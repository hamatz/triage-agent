"""Run-to-run history of the automatic kernel lookup and deterministic promotion (ADR-021 decision 2).

Every live ``--kernel-auto`` run saves a snapshot: per CVE the threat signals (KEV, EPSS, CVSS) and per
node pool which CVEs were exposed at which tier. The next run compares against it and

- promotes a CVE to tier 1 when its signals move in a way that matters:
    epss_jump      EPSS rose by at least the jump threshold since the previous run
    cvss_revision  an existing CVSS score was revised upwards into the local-privilege-escalation shape
                   (AV:L, PR:L/N, UI:N, high impact, score >= 7.0); a first score is not a revision
    manual         a person promoted it with ``--promote`` (a source URL is required)
- reports what changed per pool: newly tier 1 / tier 2, and tier 1 / 2 CVEs no longer exposed.

Promotions are sticky: once promoted, a CVE stays tier 1 while it is still exposed in any pool, so a
one-day jump is not forgotten the next day. CISA KEV listing is tier 1 by itself and is reported as a
change, not stored as a promotion.

Everything here works on the normalized results of kernel_exposure; nothing is distribution specific.
"""

import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

SCHEMA_VERSION = 1
DEFAULT_STATE_DIR = "triage-output/kernel_auto"
SNAPSHOT_FILE = "snapshot.json"
PREVIOUS_SNAPSHOT_FILE = "snapshot.previous.json"
PROMOTIONS_FILE = "promotions.json"
DEFAULT_EPSS_JUMP = 0.15
CVSS_PROMOTION_FLOOR = 7.0

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

RULE_LABELS = {
    "epss_jump": "EPSS 急上昇",
    "cvss_revision": "CVSS の引き上げ（LPE 型）",
    "manual": "手動昇格",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# -- CVSS -----------------------------------------------------------------------------------------
def parse_cvss_vector(vector: Optional[str]) -> Dict[str, str]:
    """'CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H' -> {'AV': 'L', ...}; {} when unparsable."""
    if not vector:
        return {}
    out = {}
    for part in vector.split("/"):
        key, sep, value = part.partition(":")
        if sep and key != "CVSS":
            out[key.strip().upper()] = value.strip().upper()
    return out


def is_lpe_vector(vector: Optional[str]) -> bool:
    """Local attack, little or no privilege, no user interaction, high confidentiality or integrity impact."""
    m = parse_cvss_vector(vector)
    return (
        m.get("AV") == "L"
        and m.get("PR") in ("L", "N")
        and m.get("UI") in ("N",)
        and (m.get("C") == "H" or m.get("I") == "H")
    )


# -- promotions -----------------------------------------------------------------------------------
@dataclass
class Promotion:
    cve_id: str
    rule: str                       # epss_jump | cvss_revision | manual
    detail: str
    detected_at: str
    source_url: Optional[str] = None
    new: bool = False               # detected in this run (False: carried over / standing manual promotion)

    @property
    def label(self) -> str:
        return RULE_LABELS.get(self.rule, self.rule)

    def to_json(self) -> dict:
        d = {"rule": self.rule, "detail": self.detail, "detected_at": self.detected_at}
        if self.source_url:
            d["source_url"] = self.source_url
        return d


def evaluate_promotions(
    exposed_cves: Set[str],
    kev: Set[str],
    epss: Dict[str, Optional[float]],
    cvss: Dict[str, dict],
    previous: Optional[dict],
    manual: Dict[str, dict],
    epss_jump: float = DEFAULT_EPSS_JUMP,
    now: Optional[str] = None,
) -> Dict[str, Promotion]:
    """Promotions in force for the exposed CVEs (CVEs already in KEV need none)."""
    now = now or now_iso()
    prev_signals: Dict[str, dict] = (previous or {}).get("signals", {})
    prev_promotions: Dict[str, dict] = (previous or {}).get("promotions", {})
    out: Dict[str, Promotion] = {}
    for cve in sorted(exposed_cves):
        if cve in kev:
            continue
        if cve in manual:
            m = manual[cve]
            out[cve] = Promotion(cve, "manual", m.get("reason") or "人による確認", m.get("promoted_at") or now,
                                 source_url=m.get("source_url"))
            continue
        if cve in prev_promotions:
            p = prev_promotions[cve]
            if p.get("rule") != "manual":   # a manual promotion lasts only while it is in the ledger
                out[cve] = Promotion(cve, p.get("rule", "?"), p.get("detail", ""), p.get("detected_at", ""),
                                     source_url=p.get("source_url"))
                continue
        prev = prev_signals.get(cve) or {}
        cur_epss, prev_epss = epss.get(cve), prev.get("epss")
        if cur_epss is not None and prev_epss is not None and cur_epss - prev_epss >= epss_jump:
            out[cve] = Promotion(cve, "epss_jump", f"{prev_epss:.3f} → {cur_epss:.3f}", now, new=True)
            continue
        cur_cvss, prev_cvss = cvss.get(cve) or {}, prev.get("cvss") or {}
        cur_score, prev_score = cur_cvss.get("score"), prev_cvss.get("score")
        if (
            cur_score is not None and prev_score is not None
            and float(cur_score) >= CVSS_PROMOTION_FLOOR and float(cur_score) > float(prev_score)
            and is_lpe_vector(cur_cvss.get("vector"))
            and (float(prev_score) < CVSS_PROMOTION_FLOOR or not is_lpe_vector(prev_cvss.get("vector")))
        ):
            out[cve] = Promotion(cve, "cvss_revision", f"{float(prev_score):g} → {float(cur_score):g}（{cur_cvss.get('vector')}）",
                                 now, source_url=cur_cvss.get("source_url"), new=True)
    return out


# -- run-to-run changes ---------------------------------------------------------------------------
@dataclass
class PoolChanges:
    pool_id: str
    baseline: bool                              # the previous snapshot has usable data for this pool
    previous_taken_at: Optional[str] = None
    previous_installed: Optional[str] = None
    new_tier1: List[str] = field(default_factory=list)
    new_tier2: List[str] = field(default_factory=list)
    resolved: List[str] = field(default_factory=list)   # tier 1 / 2 last time, no longer exposed
    notes: List[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new_tier1 or self.new_tier2 or self.resolved)


def compute_changes(result, previous: Optional[dict]) -> Dict[str, PoolChanges]:
    """Per pool differences between this run (KernelAutoResult) and the previous snapshot."""
    out: Dict[str, PoolChanges] = {}
    if not previous:
        return out
    prev_pools: Dict[str, dict] = previous.get("pools", {})
    taken_at = previous.get("taken_at")
    for pid, summary in result.pools.items():
        prev = prev_pools.get(pid)
        if summary.status != "ok":
            out[pid] = PoolChanges(pid, baseline=False, previous_taken_at=taken_at,
                                   notes=["今回は照会できなかったため、比較していません"])
            continue
        if not prev or prev.get("status") != "ok":
            out[pid] = PoolChanges(pid, baseline=False, previous_taken_at=taken_at,
                                   notes=["前回のデータがないため、今回が比較の基準になります"])
            continue
        tiers = prev.get("tiers", {})
        prev_t1, prev_t2, prev_t3 = (set(tiers.get(k, [])) for k in ("1", "2", "3"))
        cur = {1: set(), 2: set(), 3: set()}
        for x in summary.exposed:
            cur[x.tier].add(x.cve_id)
        changes = PoolChanges(pid, baseline=True, previous_taken_at=taken_at, previous_installed=prev.get("installed"))
        changes.new_tier1 = sorted(cur[1] - prev_t1)
        changes.new_tier2 = sorted(cur[2] - prev_t1 - prev_t2)
        changes.resolved = sorted((prev_t1 | prev_t2) - cur[1] - cur[2] - cur[3])
        if prev.get("installed") and prev.get("installed") != summary.installed:
            changes.notes.append(f"カーネルの版が変わりました（{prev.get('installed')} → {summary.installed}）")
        if previous.get("kev_available") is False and result.kev_available:
            changes.notes.append("前回は CISA KEV を取得できなかったため、新たな層1 には以前からのものが含まれます")
        if previous.get("epss_available") is False and result.epss_available:
            changes.notes.append("前回は EPSS を取得できなかったため、新たな層2 には以前からのものが含まれます")
        out[pid] = changes
    return out


# -- snapshot -------------------------------------------------------------------------------------
def build_snapshot(result, kev: Set[str], epss: Dict[str, Optional[float]], cvss: Dict[str, dict],
                   previous: Optional[dict], now: Optional[str] = None) -> dict:
    """Snapshot of this run. Signals that could not be fetched now keep their last known value, and
    pools that could not be looked up keep their previous data, so the next comparison has a baseline."""
    now = now or now_iso()
    prev_signals: Dict[str, dict] = (previous or {}).get("signals", {})
    prev_pools: Dict[str, dict] = (previous or {}).get("pools", {})
    exposed = sorted({x.cve_id for s in result.pools.values() for x in s.exposed})
    signals: Dict[str, dict] = {}
    for cve in exposed:
        rec = dict(prev_signals.get(cve) or {})
        if result.kev_available:
            rec["kev"] = cve in kev
        if result.epss_available and cve in epss:
            rec["epss"] = epss[cve]
        if getattr(result, "cvss_available", False) and cve in cvss:
            rec["cvss"] = cvss[cve]
        signals[cve] = rec
    pools: Dict[str, dict] = {}
    for pid, s in result.pools.items():
        if s.status == "ok":
            tiers = {"1": [], "2": [], "3": []}
            for x in s.exposed:
                tiers[str(x.tier)].append(x.cve_id)
            pools[pid] = {"status": "ok", "lineage": s.lineage, "installed": s.installed, "taken_at": now,
                          "tiers": {k: sorted(v) for k, v in tiers.items()}}
        elif pid in prev_pools:
            kept = dict(prev_pools[pid])
            kept["not_refreshed_reason"] = s.reason or s.status
            pools[pid] = kept
        else:
            pools[pid] = {"status": s.status, "reason": s.reason}
    info = getattr(result, "kev_catalog_info", None) or {}
    return {
        "schema": SCHEMA_VERSION,
        "taken_at": now,
        "kev_available": result.kev_available,
        "kev_catalog_version": info.get("catalogVersion"),
        "epss_available": result.epss_available,
        "cvss_available": getattr(result, "cvss_available", False),
        "signals": signals,
        "promotions": {c: p.to_json() for c, p in getattr(result, "promotions", {}).items()},
        "pools": pools,
    }


def load_snapshot(state_dir: str = DEFAULT_STATE_DIR) -> Tuple[Optional[dict], Optional[str]]:
    """(snapshot, problem). A missing snapshot is not a problem; an unreadable one is reported."""
    path = Path(state_dir) / SNAPSHOT_FILE
    if not path.exists():
        return None, None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return None, f"前回のスナップショット（{path}）を読めませんでした（{e}）。今回を基準にします"
    if not isinstance(data, dict) or data.get("schema") != SCHEMA_VERSION:
        return None, f"前回のスナップショット（{path}）の形式が違うため使いません。今回を基準にします"
    return data, None


def save_snapshot(snapshot: dict, state_dir: str = DEFAULT_STATE_DIR) -> Path:
    """Write the snapshot atomically; the one it replaces is kept as snapshot.previous.json."""
    d = Path(state_dir)
    d.mkdir(parents=True, exist_ok=True)
    path, prev = d / SNAPSHOT_FILE, d / PREVIOUS_SNAPSHOT_FILE
    tmp = d / (SNAPSHOT_FILE + ".tmp")
    tmp.write_text(json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    if path.exists():
        os.replace(path, prev)
    os.replace(tmp, path)
    return path


# -- manual promotion ledger ----------------------------------------------------------------------
def _ledger_path(state_dir: str) -> Path:
    return Path(state_dir) / PROMOTIONS_FILE


def load_manual_promotions(state_dir: str = DEFAULT_STATE_DIR) -> Dict[str, dict]:
    path = _ledger_path(state_dir)
    if not path.exists():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {p["cve_id"]: p for p in data.get("promotions", []) if isinstance(p, dict) and p.get("cve_id")}


def _write_ledger(state_dir: str, items: Dict[str, dict]) -> Path:
    path = _ledger_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    body = {
        "description": "Kernel CVEs promoted to tier 1 by a person (triage-agent --promote, ADR-021).",
        "promotions": [items[k] for k in sorted(items)],
    }
    path.write_text(json.dumps(body, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return path


def add_manual_promotion(cve_id: str, source_url: str, reason: Optional[str] = None,
                         state_dir: str = DEFAULT_STATE_DIR, now: Optional[str] = None) -> Path:
    cve = (cve_id or "").strip().upper()
    if not CVE_ID_RE.match(cve):
        raise ValueError(f"CVE ID の形式ではありません: {cve_id}")
    if not re.match(r"^https?://\S+$", (source_url or "").strip()):
        raise ValueError("昇格の根拠となる出典 URL（http:// または https://）を --promote-source で指定してください")
    items = load_manual_promotions(state_dir)
    items[cve] = {"cve_id": cve, "source_url": source_url.strip(), "reason": (reason or "").strip() or None,
                  "promoted_at": now or now_iso()}
    return _write_ledger(state_dir, items)


def remove_manual_promotion(cve_id: str, state_dir: str = DEFAULT_STATE_DIR) -> bool:
    cve = (cve_id or "").strip().upper()
    items = load_manual_promotions(state_dir)
    if cve not in items:
        return False
    del items[cve]
    _write_ledger(state_dir, items)
    return True
