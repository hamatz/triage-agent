"""OSV.dev adapter for distribution kernels (ADR-021 decision 3).

Asks OSV "which vulnerabilities affect this exact kernel package version" per node-pool kernel:

    POST /v1/querybatch  {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "linux-aws"},
                          "version": "6.8.0-1015.16"}

querybatch returns only ids and modification times, which keeps the answer small even though an old
Ubuntu / Debian kernel is affected by ~10,000 CVE records (each of which lists every kernel flavor of
every release and is large). Two record styles exist:

- per-CVE records (UBUNTU-CVE-…, DEBIAN-CVE-…): the CVE is in the id, so no download is needed to
  classify; the fixed version and severity are fetched later (``enrich``) only for tier 1 / 2.
- per-advisory records (ALSA-…, RLSA-…): few, small; downloaded immediately to read the CVEs
  (``upstream`` / ``aliases``) and the fixed version.

Downloads are cached under <cache>/osv/ (query answers for 24 h, records keyed by their modification
time), so daily runs only fetch what changed. Distributions are configured in kernel_sources.toml.
"""

import hashlib
import json
import re
import time
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from triage_agent.chain.sources.base import (
    KernelAdvisoryAdapter,
    KernelAdvisoryFix,
    PoolKernelIdentity,
    SourceResult,
    lineage_key,
)

OSV_API = "https://api.osv.dev/v1"
QUERY_TTL_SECONDS = 24 * 3600
MAX_PAGES = 50
PER_CVE_ID_RE = re.compile(r"^[A-Z]+-(CVE-\d{4}-\d{4,})$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# OSV severity entries of type 'Ubuntu' carry Ubuntu's priority; map onto the common scale.
UBUNTU_PRIORITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "negligible": "low"}


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class OsvAdapter(KernelAdvisoryAdapter):
    name = "osv"

    # -- identification --------------------------------------------------------------------------
    def ecosystem_for(self, identity: PoolKernelIdentity) -> Optional[str]:
        distro, release = identity.distro.lower(), identity.release.strip()
        templates: Dict[str, str] = self.config.get("ecosystems", {})
        tpl = templates.get(distro)
        if not tpl or not release:
            return None
        major = release.split(".")[0]
        lts = ""
        if distro == "ubuntu":
            m = re.match(r"^(\d{2})\.04$", release)
            lts = ":LTS" if m and int(m.group(1)) % 2 == 0 else ""
        return tpl.format(release=release, major=major, lts=lts)

    def package_for(self, identity: PoolKernelIdentity) -> Optional[str]:
        # OSV indexes distribution kernels by SOURCE package ('linux-aws', 'linux', 'kernel'),
        # which is what the collector reports as kernel_flavor.
        pkg = (identity.engine_flavor or "").strip()
        if not pkg or pkg in ("unknown",):
            return None
        return pkg

    def lineage_for(self, identity: PoolKernelIdentity) -> Optional[str]:
        eco, pkg, series = self.ecosystem_for(identity), self.package_for(identity), identity.series
        if not eco or not pkg or not series:
            return None
        release_key = identity.release if identity.distro.lower() == "ubuntu" else identity.release.split(".")[0]
        return lineage_key(identity.distro, release_key, pkg, series)

    @staticmethod
    def query_version(identity: PoolKernelIdentity) -> str:
        return identity.version  # package version-release as reported by dpkg / rpm (no epoch)

    # -- HTTP + cache ------------------------------------------------------------------------------
    def _http_json(self, url: str, body: Optional[dict] = None) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, headers={
            "User-Agent": "triage-agent (ADR-021 OSV adapter)",
            **({"Content-Type": "application/json"} if data else {}),
        })
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _dir(self, *parts: str) -> Path:
        d = Path(self.cache_dir, "osv", *parts)
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _query_ids(self, ecosystem: str, package: str, version: str, offline: bool) -> Tuple[List[dict], str]:
        """All (id, modified) affecting the version; cached for 24 h. Returns (vulns, retrieved_at)."""
        key = hashlib.sha256(f"{ecosystem}|{package}|{version}".encode()).hexdigest()[:24]
        path = self._dir("queries") / f"{key}.json"
        if path.exists():
            cached = json.loads(path.read_text(encoding="utf-8"))
            if offline or time.time() - path.stat().st_mtime < QUERY_TTL_SECONDS:
                return cached["vulns"], cached["retrieved_at"]
        elif offline:
            raise RuntimeError(f"{ecosystem} {package} {version}: オフラインでキャッシュがありません")
        vulns: List[dict] = []
        token = None
        for _ in range(MAX_PAGES):
            q = {"package": {"ecosystem": ecosystem, "name": package}, "version": version}
            if token:
                q["page_token"] = token
            res = (self._http_json(f"{OSV_API}/querybatch", {"queries": [q]}).get("results") or [{}])[0]
            vulns.extend({"id": v["id"], "modified": v.get("modified", "")} for v in res.get("vulns", []))
            token = res.get("next_page_token")
            if not token:
                break
        else:
            raise RuntimeError(f"{ecosystem} {package} {version}: 結果が {MAX_PAGES} ページを超えたため打ち切りました")
        retrieved_at = _now()
        path.write_text(json.dumps({"ecosystem": ecosystem, "package": package, "version": version,
                                    "retrieved_at": retrieved_at, "vulns": vulns}), encoding="utf-8")
        return vulns, retrieved_at

    def _record(self, vuln_id: str, modified: str, offline: bool) -> dict:
        safe = re.sub(r"[^A-Za-z0-9._-]", "_", vuln_id)
        path = self._dir("records") / f"{safe}.json"
        if path.exists():
            rec = json.loads(path.read_text(encoding="utf-8"))
            if offline or not modified or rec.get("modified") == modified:
                return rec
        elif offline:
            raise RuntimeError(f"{vuln_id}: オフラインでキャッシュがありません")
        rec = self._http_json(f"{OSV_API}/vulns/{vuln_id}")
        path.write_text(json.dumps(rec), encoding="utf-8")
        return rec

    # -- record parsing ----------------------------------------------------------------------------
    @staticmethod
    def cves_of(record: dict) -> List[str]:
        ids = [record.get("id", "")] + list(record.get("upstream", [])) + list(record.get("aliases", []))
        m = PER_CVE_ID_RE.match(record.get("id", ""))
        if m:
            ids.append(m.group(1))
        return sorted({i.upper() for i in ids if CVE_RE.match(i.upper())})

    @staticmethod
    def fix_of(record: dict, ecosystem: str, package: str) -> Tuple[bool, Optional[str]]:
        """(package listed, first fixed version) for this ecosystem/package; fixed None = no fix yet."""
        listed, fixes = False, []
        for aff in record.get("affected", []):
            p = aff.get("package", {})
            if p.get("ecosystem") != ecosystem or p.get("name") != package:
                continue
            listed = True
            for r in aff.get("ranges", []):
                if r.get("type") != "ECOSYSTEM":
                    continue
                fixes.extend(ev["fixed"] for ev in r.get("events", []) if "fixed" in ev)
        return listed, (fixes[0] if fixes else None)

    @staticmethod
    def severity_of(record: dict) -> str:
        for sev in record.get("severity", []):
            if sev.get("type") == "Ubuntu":
                return UBUNTU_PRIORITY.get(str(sev.get("score", "")).lower(), "unknown")
        for aff in record.get("affected", []):
            for k in ("urgency",):  # Debian
                val = str((aff.get("ecosystem_specific") or {}).get(k, "")).lower()
                if val in ("high", "medium", "low"):
                    return val
        return "unknown"

    @staticmethod
    def _normalize_fixed(fixed: Optional[str], distro: str) -> Optional[str]:
        """RPM fixed versions are expressed with an explicit epoch so the core compares them exactly."""
        if fixed is None:
            return None
        if distro in ("almalinux", "rocky") and ":" not in fixed:
            return f"0:{fixed}"
        return fixed

    # -- contract ----------------------------------------------------------------------------------
    def fetch(self, lineages: Set[str], offline: bool = False, identities=None) -> SourceResult:
        result = SourceResult(adapter=self.name, retrieved_at=_now())
        identities = identities or {}
        self._pending_index: Dict[str, Tuple[str, str, str, str]] = getattr(self, "_pending_index", {})
        for lineage in sorted(lineages):
            pools = identities.get(lineage) or []
            if not pools:
                result.errors.append(f"{lineage}: 照会に使うカーネル版がありません")
                continue
            versions = sorted({self.query_version(p) for p in pools})
            ident = pools[0]
            ecosystem, package = self.ecosystem_for(ident), self.package_for(ident)
            ok_versions = 0
            for version in versions:
                try:
                    vulns, retrieved_at = self._query_ids(ecosystem, package, version, offline)
                except Exception as e:  # noqa: BLE001 - disclosed
                    result.errors.append(f"OSV {ecosystem} {package} {version}: 照会できませんでした（{e}）")
                    continue
                ok_versions += 1
                for v in vulns:
                    vid, modified = v["id"], v.get("modified", "")
                    m = PER_CVE_ID_RE.match(vid)
                    if m:
                        # Per-CVE record: classify from the id; details later if it matters.
                        cve = m.group(1)
                        self._pending_index[f"{lineage}|{cve}"] = (vid, modified, ecosystem, package)
                        result.fixes.append(KernelAdvisoryFix(
                            cve_id=cve, lineage=lineage, fixed_evr=None, severity="unknown", advisory_ids=[vid],
                            source_url=f"https://osv.dev/vulnerability/{vid}", retrieved_at=retrieved_at,
                            affected_confirmed=True, applies_to_versions={version}, details_pending=True,
                        ))
                        continue
                    try:
                        rec = self._record(vid, modified, offline)
                    except Exception as e:  # noqa: BLE001
                        result.errors.append(f"OSV {vid}: レコードを取得できませんでした（{e}）")
                        continue
                    cves = self.cves_of(rec)
                    if not cves:
                        continue  # e.g. bug-fix-only advisories (ALBA) carry no CVE
                    _, fixed = self.fix_of(rec, ecosystem, package)
                    for cve in cves:
                        result.fixes.append(KernelAdvisoryFix(
                            cve_id=cve, lineage=lineage, fixed_evr=self._normalize_fixed(fixed, ident.distro),
                            severity=self.severity_of(rec), advisory_ids=[vid],
                            source_url=f"https://osv.dev/vulnerability/{vid}", retrieved_at=retrieved_at,
                            affected_confirmed=True, applies_to_versions={version},
                        ))
            if ok_versions == len(versions):
                result.lineages_covered.add(lineage)
        return result

    def enrich(self, fixes: List[KernelAdvisoryFix], offline: bool = False) -> List[str]:
        errors: List[str] = []
        index = getattr(self, "_pending_index", {})
        for fix in fixes:
            if not fix.details_pending:
                continue
            ref = index.get(f"{fix.lineage}|{fix.cve_id}")
            if not ref:
                errors.append(f"{fix.cve_id}: 詳細を取得するための参照がありません")
                continue
            vid, modified, ecosystem, package = ref
            try:
                rec = self._record(vid, modified, offline)
            except Exception as e:  # noqa: BLE001
                errors.append(f"OSV {vid}: 詳細（修正版・重大度）を取得できませんでした（{e}）")
                continue
            distro = fix.lineage.split(":", 1)[0]
            _, fixed = self.fix_of(rec, ecosystem, package)
            fix.fixed_evr = self._normalize_fixed(fixed, distro)
            fix.severity = self.severity_of(rec)
            fix.details_pending = False
        return errors
