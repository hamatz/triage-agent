"""Threat Intelligence Feed integration for Exploit Chain Triaging.

Fetches and tracks:
1. CISA KEV (Known Exploited Vulnerabilities) Catalog
2. FIRST EPSS (Exploit Prediction Scoring System) Scores & History
3. Fail-safe tracking: network/API failures are marked as 'unverified', never assumed safe.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import urllib.error
import urllib.request

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
FIRST_EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"


@dataclass
class ThreatFeedResult:
    """Consolidated threat intelligence for a given CVE."""
    cve_id: str
    in_cisa_kev: Optional[bool] = None
    kev_date_added: Optional[str] = None
    kev_ransomware_use: Optional[str] = None
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    previous_epss_score: Optional[float] = None
    epss_delta: Optional[float] = None
    epss_sudden_jump: bool = False
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    cwe_list: List[str] = field(default_factory=list)
    summary: Optional[str] = None
    verified: bool = False
    error: Optional[str] = None


class ThreatFeedClient:
    """Client for retrieving and caching CISA KEV and FIRST EPSS threat intelligence."""

    def __init__(
        self,
        cache_dir: Optional[Path] = None,
        history_path: Optional[Path] = None,
        epss_jump_threshold: float = 0.15,
        timeout: int = 10,
    ) -> None:
        self.cache_dir = cache_dir or Path("triage-output/cache")
        self.history_path = history_path or Path("triage-output/epss_history.json")
        self.epss_jump_threshold = epss_jump_threshold
        self.timeout = timeout
        self._kev_cache: Optional[Dict[str, Dict[str, Any]]] = None

    def _ensure_dirs(self) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        if self.history_path.parent:
            self.history_path.parent.mkdir(parents=True, exist_ok=True)

    def fetch_cisa_kev_catalog(self, force_refresh: bool = False) -> Dict[str, Dict[str, Any]]:
        """Fetch the full CISA KEV catalog. Cached locally for 24h by default."""
        if self._kev_cache is not None and not force_refresh:
            return self._kev_cache

        self._ensure_dirs()
        cache_file = self.cache_dir / "cisa_kev_catalog.json"

        # Check local cache validity (24 hours)
        if not force_refresh and cache_file.exists():
            try:
                mtime = cache_file.stat().st_mtime
                if time.time() - mtime < 86400:
                    with open(cache_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self._kev_cache = self._index_kev_data(data)
                        return self._kev_cache
            except Exception as e:
                logger.warning("Failed to read KEV cache: %s", e)

        # Download from CISA
        try:
            req = urllib.request.Request(
                CISA_KEV_URL,
                headers={"User-Agent": "triage-agent/0.4.0 (Security Triaging Tool)"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    raw_data = resp.read().decode("utf-8")
                    data = json.loads(raw_data)
                    with open(cache_file, "w", encoding="utf-8") as f:
                        f.write(raw_data)
                    self._kev_cache = self._index_kev_data(data)
                    return self._kev_cache
                else:
                    raise urllib.error.HTTPError(
                        CISA_KEV_URL, resp.status, f"HTTP {resp.status}", resp.headers, None
                    )
        except Exception as e:
            logger.warning("Failed to download CISA KEV catalog: %s", e)
            # Fallback to stale cache if present
            if cache_file.exists():
                try:
                    with open(cache_file, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self._kev_cache = self._index_kev_data(data)
                        return self._kev_cache
                except Exception:
                    pass
            raise RuntimeError(f"CISA KEV catalog unavailable: {e}") from e

    def _index_kev_data(self, data: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        vulnerabilities = data.get("vulnerabilities", [])
        return {item.get("cveID", "").upper(): item for item in vulnerabilities if item.get("cveID")}

    def fetch_osv_vulnerability(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Fetch full OSV record for a vulnerability (CVE-XXXX-XXXX or GHSA-XXXX)."""
        cid = cve_id.strip()
        url = f"{OSV_VULN_URL}/{cid}"
        cache_file = self.cache_dir / f"osv_{cid}.json"
        if cache_file.exists():
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "triage-agent/0.4.0 (Security Triaging Tool)"},
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    self._ensure_dirs()
                    with open(cache_file, "w", encoding="utf-8") as f:
                        json.dump(data, f, indent=2)
                    return data
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            logger.debug("OSV query for %s returned HTTP error: %s", cid, e)
            raise RuntimeError(f"HTTP {e.code}") from e
        except Exception as e:
            logger.debug("OSV query for %s returned error: %s", cid, e)
            raise RuntimeError(str(e)) from e
        return None

    def extract_osv_fixed_ranges(self, osv_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract distro-specific package fixed versions from OSV record.
        
        Returns dict of distro keys (e.g. 'ubuntu:24.04:linux', 'ubuntu:24.04:linux-aws') to fixed version strings.
        Release-less keys (e.g. 'ubuntu') are intentionally excluded to prevent cross-release overwrites.
        """
        results: Dict[str, Any] = {}
        affected = osv_data.get("affected", [])
        for aff in affected:
            pkg = aff.get("package", {})
            eco = (pkg.get("ecosystem") or "").lower()
            name = (pkg.get("name") or "").lower()

            # Find fixed version event
            fixed_ver = None
            for r in aff.get("ranges", []):
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        fixed_ver = ev["fixed"]
                        break
                if fixed_ver:
                    break

            if not fixed_ver:
                continue

            # Parse ecosystem: e.g. "ubuntu:24.04:lts", "debian:12"
            parts = eco.split(":")
            distro_name = parts[0] if parts else eco
            release = parts[1] if len(parts) > 1 else ""

            # Key variations: only when release is known (prevent release-less key collisions)
            if release:
                results[f"{distro_name}:{release}:{name}"] = {"package": name, "fixed_version": fixed_ver}
                if name == "linux":
                    results[f"{distro_name}:{release}"] = {"package": name, "fixed_version": fixed_ver}

        return results

    def fetch_epss_scores(self, cve_ids: List[str]) -> Dict[str, Dict[str, float]]:
        """Query FIRST EPSS API for scores and percentiles.
        
        Returns dict: {CVE-ID: {"epss": 0.45, "percentile": 0.95}}
        """
        clean_ids = [c.strip().upper() for c in cve_ids if c.strip()]
        if not clean_ids:
            return {}

        results: Dict[str, Dict[str, float]] = {}
        # Batch in chunks of 50 to avoid URL length issues
        chunk_size = 50
        for i in range(0, len(clean_ids), chunk_size):
            chunk = clean_ids[i : i + chunk_size]
            url = f"{FIRST_EPSS_URL}?cve={','.join(chunk)}"
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "triage-agent/0.4.0 (Security Triaging Tool)"},
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode("utf-8"))
                        for item in data.get("data", []):
                            cid = item.get("cve", "").upper()
                            try:
                                ep = float(item.get("epss", 0.0))
                                pc = float(item.get("percentile", 0.0))
                                results[cid] = {"epss": ep, "percentile": pc}
                            except (ValueError, TypeError):
                                continue
            except Exception as e:
                logger.warning("EPSS API request failed for chunk %s: %s", chunk, e)
                # Network/API failure: Do not mock scores. Raise so caller handles fail-safe.
                raise RuntimeError(f"EPSS API query failed: {e}") from e

        return results

    def load_epss_history(self) -> Dict[str, Dict[str, Any]]:
        """Load historical EPSS records."""
        if not self.history_path.exists():
            return {}
        try:
            with open(self.history_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.warning("Failed to load EPSS history from %s: %s", self.history_path, e)
            return {}

    def save_epss_history(self, history: Dict[str, Dict[str, Any]]) -> None:
        """Save updated EPSS records."""
        self._ensure_dirs()
        try:
            with open(self.history_path, "w", encoding="utf-8") as f:
                json.dump(history, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning("Failed to save EPSS history to %s: %s", self.history_path, e)

    def analyze_cves(
        self,
        cve_ids: List[str],
        offline: bool = False,
    ) -> Dict[str, ThreatFeedResult]:
        """Consolidate threat intelligence for a list of CVE IDs.
        
        Evaluates:
        - CISA KEV membership
        - EPSS score & sudden jump against history
        - Fail-safe state (verified=False if feed unreachable)
        """
        results: Dict[str, ThreatFeedResult] = {}
        history = self.load_epss_history()
        now_iso = datetime.now(timezone.utc).isoformat()

        # Step 1: KEV lookup
        kev_catalog: Optional[Dict[str, Dict[str, Any]]] = None
        kev_error: Optional[str] = None
        if not offline:
            try:
                kev_catalog = self.fetch_cisa_kev_catalog()
            except Exception as e:
                kev_error = str(e)
        else:
            # Try offline cache
            cache_file = self.cache_dir / "cisa_kev_catalog.json"
            if cache_file.exists():
                try:
                    with open(cache_file, "r", encoding="utf-8") as f:
                        kev_catalog = self._index_kev_data(json.load(f))
                except Exception:
                    kev_error = "Offline cache unreadable"
            else:
                kev_error = "Offline mode and no local KEV cache found"

        # Step 2: EPSS lookup
        epss_data: Dict[str, Dict[str, float]] = {}
        epss_error: Optional[str] = None
        if not offline:
            try:
                epss_data = self.fetch_epss_scores(cve_ids)
            except Exception as e:
                epss_error = str(e)
        else:
            epss_error = "Offline mode: EPSS live scores unavailable"

        # Step 3: Consolidate
        history_updated = False
        for cve in cve_ids:
            cid = cve.strip().upper()
            res = ThreatFeedResult(cve_id=cid)

            # Process KEV
            if kev_catalog is not None:
                if cid in kev_catalog:
                    res.in_cisa_kev = True
                    item = kev_catalog[cid]
                    res.kev_date_added = item.get("dateAdded")
                    res.kev_ransomware_use = item.get("knownRansomwareCampaignUse")
                else:
                    res.in_cisa_kev = False
            else:
                res.error = f"KEV: {kev_error}"

            # Process EPSS & History Jump
            prev_entry = history.get(cid)
            prev_score = prev_entry.get("score") if isinstance(prev_entry, dict) else None
            res.previous_epss_score = prev_score

            if cid in epss_data:
                score = epss_data[cid]["epss"]
                percentile = epss_data[cid]["percentile"]
                res.epss_score = score
                res.epss_percentile = percentile

                if prev_score is not None:
                    delta = round(score - prev_score, 4)
                    res.epss_delta = delta
                    if delta >= self.epss_jump_threshold:
                        res.epss_sudden_jump = True
                else:
                    res.epss_delta = 0.0

                # Update history
                history[cid] = {
                    "score": score,
                    "percentile": percentile,
                    "last_updated": now_iso,
                    "previous_score": prev_score,
                }
                history_updated = True
            elif epss_error:
                err_msg = f"EPSS: {epss_error}"
                res.error = f"{res.error}; {err_msg}" if res.error else err_msg

            # Process OSV (CVSS vector, CWEs, summary)
            try:
                osv_rec = self.fetch_osv_vulnerability(cid)
                if osv_rec:
                    res.summary = osv_rec.get("summary") or osv_rec.get("details")
                    # Extract severity (CVSS vector)
                    for sev in osv_rec.get("severity", []):
                        score_str = sev.get("score")
                        if score_str and ("CVSS:" in score_str or "AV:" in score_str):
                            res.cvss_vector = score_str
                            break
                    # Extract CWEs
                    db_spec = osv_rec.get("database_specific", {})
                    cwes = db_spec.get("cwe_ids") or []
                    if isinstance(cwes, list):
                        res.cwe_list = [str(c) for c in cwes]
            except Exception as e:
                err_msg = f"OSV: 取得失敗 ({e})"
                res.error = f"{res.error}; {err_msg}" if res.error else err_msg

            # Verified status
            if res.error is None:
                res.verified = True
            else:
                res.verified = False

            results[cid] = res

        if history_updated and not offline:
            self.save_epss_history(history)

        return results
