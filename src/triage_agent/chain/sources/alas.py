"""Amazon Linux Security Center (ALAS) adapter (ADR-021 decision 3).

OSV has no Amazon Linux ecosystem, so this adapter reads the repositories' own advisory metadata
(`repodata/updateinfo.xml`), which is what `dnf updateinfo` uses:

    mirror.list  ->  <base>/repodata/repomd.xml  ->  updateinfo.xml.gz

Each <update> lists its CVEs (<reference type="cve">) and the exact fixed packages
(name / epoch / version / release). Kernel lines are identified by package name *and* upstream series,
because Amazon Linux 2 ships several kernel lines named 'kernel' (4.14 in core, 5.10 / 5.15 in extras),
while Amazon Linux 2023 uses distinct names ('kernel' = 6.1, 'kernel6.12', 'kernel6.18').

Livepatch packages ('kernel-livepatch-<kernel version>-<release>') are mapped to the CVEs they address.

Notes:
- Only x86_64 metadata is read; fixed versions are identical across architectures.
- ALAS severity is assigned per advisory, and a kernel advisory typically bundles dozens of CVEs, so it
  is a weak per-CVE signal. It is reported, but tier classification relies on KEV / EPSS as well.
- AWS recommends using the dnf API instead of parsing updateinfo.xml; this parser follows the
  rpm-metadata format and counts anything it cannot interpret as an error instead of dropping it.
"""

import gzip
import json
import lzma
import re
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from triage_agent.chain.sources.base import (
    SEVERITY_RANK,
    KernelAdvisoryAdapter,
    KernelAdvisoryFix,
    LivepatchFix,
    PoolKernelIdentity,
    SourceResult,
    lineage_key,
    upstream_series,
)
from triage_agent.chain.version_parser import compare_rpm_evr

REPOMD_NS = {"repo": "http://linux.duke.edu/metadata/repo"}
BASE_KERNEL_RE = re.compile(r"^kernel(\d+\.\d+)?$")           # kernel, kernel6.12, kernel6.18
LIVEPATCH_RE = re.compile(r"^kernel-livepatch-(\d[\w.]*-[\w.]+)$")
CACHE_TTL_SECONDS = 24 * 3600

SEVERITY_MAP = {"critical": "critical", "important": "high", "medium": "medium", "moderate": "medium", "low": "low"}


def _advisory_url(release: str, advisory_id: str) -> Optional[str]:
    # Documented for AL2023: dnf id 'ALAS2023-2024-581' is published as /AL2023/ALAS-2024-581.html
    if release == "2023":
        m = re.match(r"^ALAS2023-(\d{4}-\d+)$", advisory_id)
        if m:
            return f"https://alas.aws.amazon.com/AL2023/ALAS-{m.group(1)}.html"
    return None


class AlasAdapter(KernelAdvisoryAdapter):
    name = "alas"

    def lineage_for(self, identity: PoolKernelIdentity) -> Optional[str]:
        if identity.distro.lower() != "amzn" or not identity.release:
            return None
        package = identity.package
        if not package or not BASE_KERNEL_RE.match(package):
            return None
        series = identity.series
        if not series:
            return None
        return lineage_key("amzn", identity.release, package, series)

    # -- fetching ------------------------------------------------------------------------------
    def _http(self, url: str) -> bytes:
        req = urllib.request.Request(url, headers={"User-Agent": "triage-agent (ADR-021 ALAS adapter)"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return resp.read()

    def _cache_paths(self, release: str, label: str) -> Tuple[Path, Path]:
        d = Path(self.cache_dir) / "alas" / release
        return d / f"{label}.updateinfo.xml", d / f"{label}.meta.json"

    def _load_updateinfo(self, release: str, label: str, mirror_url: str, offline: bool) -> Tuple[bytes, dict]:
        data_path, meta_path = self._cache_paths(release, label)
        fresh = data_path.exists() and meta_path.exists() and (time.time() - data_path.stat().st_mtime) < CACHE_TTL_SECONDS
        if offline or fresh:
            if data_path.exists() and meta_path.exists():
                return data_path.read_bytes(), json.loads(meta_path.read_text(encoding="utf-8"))
            raise RuntimeError(f"{label}: no cached updateinfo (offline)")
        try:
            base = self._http(mirror_url).decode().split()[0].rstrip("/")
            repomd = ET.fromstring(self._http(base + "/repodata/repomd.xml"))
            href = None
            for d in repomd.findall("repo:data", REPOMD_NS):
                if d.get("type") == "updateinfo":
                    href = d.find("repo:location", REPOMD_NS).get("href")
            if not href:
                raise RuntimeError("repomd.xml has no updateinfo")
            raw = self._http(base + "/" + href)
            if href.endswith(".gz"):
                raw = gzip.decompress(raw)
            elif href.endswith(".xz"):
                raw = lzma.decompress(raw)
            elif not href.endswith(".xml"):
                raise RuntimeError(f"unsupported updateinfo compression: {href}")
            meta = {"source_url": base + "/" + href, "retrieved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
            data_path.parent.mkdir(parents=True, exist_ok=True)
            data_path.write_bytes(raw)
            meta_path.write_text(json.dumps(meta), encoding="utf-8")
            return raw, meta
        except Exception as e:  # network failure: fall back to a stale cache, disclosed by the caller
            if data_path.exists() and meta_path.exists():
                meta = json.loads(meta_path.read_text(encoding="utf-8"))
                meta["stale_reason"] = repr(e)
                return data_path.read_bytes(), meta
            raise

    def fetch(self, lineages: Set[str], offline: bool = False) -> SourceResult:
        result = SourceResult(adapter=self.name, retrieved_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
        releases = sorted({lk.split(":")[1] for lk in lineages})
        repos: Dict[str, Dict[str, str]] = self.config.get("repos", {})
        for release in releases:
            urls = repos.get(release)
            if not urls:
                result.errors.append(f"amzn {release}: このリリース向けのリポジトリが登録されていません（kernel_sources.toml）")
                continue
            for label, mirror_url in urls.items():
                try:
                    raw, meta = self._load_updateinfo(release, label, mirror_url, offline)
                except Exception as e:  # noqa: BLE001 - disclose, never drop silently
                    result.errors.append(f"amzn {release} {label}: updateinfo を取得できませんでした（{e}）")
                    continue
                if meta.get("stale_reason"):
                    result.errors.append(f"amzn {release} {label}: 取得に失敗したため前回のキャッシュを使いました（{meta['stale_reason']}）")
                self.parse_updateinfo(raw, release, meta.get("source_url", mirror_url), meta.get("retrieved_at", ""), lineages, result)
        result.lineages_covered = {f.lineage for f in result.fixes}
        return result

    # -- parsing ---------------------------------------------------------------------------------
    @staticmethod
    def parse_updateinfo(
        xml_bytes: bytes,
        release: str,
        source_url: str,
        retrieved_at: str,
        lineages: Optional[Set[str]],
        result: SourceResult,
    ) -> None:
        """Parse updateinfo.xml into result (in place). ``lineages=None`` keeps every kernel lineage."""
        try:
            root = ET.fromstring(xml_bytes)
        except ET.ParseError as e:
            result.errors.append(f"amzn {release}: updateinfo を解析できませんでした（{e}）")
            return
        # (cve, lineage) -> fix ; keep the FIRST fixed version (minimum EVR) and the HIGHEST severity
        best: Dict[Tuple[str, str], KernelAdvisoryFix] = {}
        lp_best: Dict[Tuple[str, str], LivepatchFix] = {}
        for upd in root.findall("update"):
            adv_id = (upd.findtext("id") or "").strip()
            cves = sorted({(r.get("id") or "").strip().upper() for r in upd.findall("./references/reference") if r.get("type") == "cve"})
            cves = [c for c in cves if c.startswith("CVE-")]
            if not cves:
                continue
            severity = SEVERITY_MAP.get((upd.findtext("severity") or "").strip().lower(), "unknown")
            for pkg in upd.findall("./pkglist/collection/package"):
                name = pkg.get("name") or ""
                epoch = pkg.get("epoch") or "0"
                version, rel = pkg.get("version"), pkg.get("release")
                if not version or not rel:
                    continue
                evr = f"{epoch}:{version}-{rel}"
                if BASE_KERNEL_RE.match(name):
                    series = upstream_series(version)
                    if not series:
                        result.errors.append(f"{adv_id}: 系列を特定できないパッケージ版 {name}-{version}")
                        continue
                    lk = lineage_key("amzn", release, name, series)
                    if lineages is not None and lk not in lineages:
                        continue
                    for cve in cves:
                        key = (cve, lk)
                        cur = best.get(key)
                        if cur is None:
                            best[key] = KernelAdvisoryFix(
                                cve_id=cve, lineage=lk, fixed_evr=evr, severity=severity, advisory_ids=[adv_id],
                                source_url=source_url, retrieved_at=retrieved_at, advisory_url=_advisory_url(release, adv_id),
                            )
                            continue
                        if adv_id not in cur.advisory_ids:
                            cur.advisory_ids.append(adv_id)
                        cmp = compare_rpm_evr(evr, cur.fixed_evr)
                        if cmp is not None and cmp < 0:
                            cur.fixed_evr = evr
                            cur.advisory_url = _advisory_url(release, adv_id) or cur.advisory_url
                        if SEVERITY_RANK[severity] > SEVERITY_RANK[cur.severity]:
                            cur.severity = severity
                else:
                    m = LIVEPATCH_RE.match(name)
                    if not m:
                        continue
                    target = m.group(1)
                    for cve in cves:
                        key = (cve, name)
                        cur_lp = lp_best.get(key)
                        if cur_lp is None:
                            lp_best[key] = LivepatchFix(cve_id=cve, target_kernel=target, livepatch_package=name, fixed_evr=evr)
                        else:
                            cmp = compare_rpm_evr(evr, cur_lp.fixed_evr)
                            if cmp is not None and cmp < 0:
                                cur_lp.fixed_evr = evr
        result.fixes.extend(best.values())
        result.livepatch_fixes.extend(lp_best.values())
