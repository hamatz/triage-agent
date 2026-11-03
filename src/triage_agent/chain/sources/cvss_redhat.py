"""Kernel CVE data from the Red Hat Security Data API (ADR-021): CVSS for every distribution, and
Red Hat's own fix states for RHEL.

    GET https://access.redhat.com/hydra/rest/securitydata/cve.json?package=kernel&include_package_state=true
                                                                   &per_page=1000&page=N

One bulk download (cached for 24 hours) serves two users:
- RedHatCvssSource: CVSS v3 per CVE, used for ordering and promotion of automatically found CVEs.
- the RHEL adapter (sources/rhel.py): CVEs Red Hat lists as not yet fixed for a RHEL major release
  ('Affected', 'Fix deferred', 'Will not fix', 'New'), which advisory based sources cannot show.

The list covers the kernel CVEs Red Hat tracks (about 21,000 in November 2026) with Red Hat's own
CVSS v3 vector. It is fetched in bulk, so no CVE number or other information about the user's
environment is sent; only the package name in the query ('kernel').

Chosen over NVD after a comparison on 400 kernel CVEs from Amazon Linux 2023 advisories (2026-11-02):
Red Hat had a CVSS v3 vector for 94 % of them and took 14 seconds; NVD (kernel.org CNA records) had
73 % and took 31 minutes without an API key. The two sources agreed on the exact vector for only about
a third of the CVEs both had scored, so the report names the source of every score. Red Hat scores
reflect its own assessment; the signal is used to order CVEs and to detect upward revisions, not to
decide that a CVE is safe.

The registry entry ``[signals.cvss]`` in kernel_sources.toml selects this class; another provider with
the same ``lookup`` method can be registered instead.
"""

import json
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from triage_agent import user_agent

API = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
CACHE_TTL_SECONDS = 24 * 3600
CACHE_SCHEMA = 2
PER_PAGE = 1000
MAX_PAGES = 100
# Fix states meaning "the shipped package is (or may be) affected and no fix is available".
UNFIXED_STATES = ("Affected", "Fix deferred", "Will not fix", "New")
RHEL_PRODUCT_RE = re.compile(r"^Red Hat Enterprise Linux (\d+)$")
SEVERITY_MAP = {"critical": "critical", "important": "high", "moderate": "medium", "low": "low"}


class RedHatSecurityData:
    """Bulk kernel CVE list (CVSS, severity, unfixed RHEL states), cached for 24 hours."""

    name = "redhat"
    label = "Red Hat Security Data API"

    def __init__(self, config: Optional[dict] = None, cache_dir: str = "triage-output/cache", timeout: int = 60):
        self.config = config or {}
        self.cache_dir = cache_dir
        self.timeout = timeout
        self.packages: List[str] = list(self.config.get("packages") or ["kernel"])
        self.notes: List[str] = []       # disclosed by the caller (e.g. a stale cache was used)
        self.retrieved_at: Optional[str] = None

    # -- HTTP + cache -----------------------------------------------------------------------------
    def _http_json(self, url: str):
        req = urllib.request.Request(url, headers={"User-Agent": user_agent("kernel CVE data: Red Hat")})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _cache_path(self) -> Path:
        return Path(self.cache_dir) / "redhat" / "kernel_cves.json"

    def _fetch_all(self) -> Dict[str, dict]:
        records: Dict[str, dict] = {}
        for package in self.packages:
            for page in range(1, MAX_PAGES + 1):
                q = urllib.parse.urlencode({"package": package, "per_page": PER_PAGE, "page": page,
                                            "include_package_state": "true"})
                rows = self._http_json(f"{API}?{q}")
                if not isinstance(rows, list):
                    raise RuntimeError(f"想定外の応答です（page {page}）")
                for row in rows:
                    cve = str(row.get("CVE") or "").upper()
                    if not cve.startswith("CVE-"):
                        continue
                    vector, score = row.get("cvss3_scoring_vector"), row.get("cvss3_score")
                    try:
                        score = float(score) if score not in (None, "") else None
                    except (TypeError, ValueError):
                        score = None
                    unfixed = []
                    for st in row.get("package_state") or []:
                        m = RHEL_PRODUCT_RE.match(str(st.get("product_name") or ""))
                        if m and st.get("fix_state") in UNFIXED_STATES and st.get("package_name"):
                            unfixed.append([m.group(1), st["package_name"], st["fix_state"]])
                    records[cve] = {"vector": vector or None, "score": score,
                                    "severity": SEVERITY_MAP.get(str(row.get("severity") or "").lower(), "unknown"),
                                    "unfixed": unfixed}
                if len(rows) < PER_PAGE:
                    break
            else:
                raise RuntimeError(f"{package}: {MAX_PAGES} ページを超えたため打ち切りました")
        if not records:
            raise RuntimeError("1 件も取得できませんでした")
        return records

    def _load(self, offline: bool) -> Dict[str, dict]:
        path = self._cache_path()
        cached = None
        if path.exists():
            try:
                cached = json.loads(path.read_text(encoding="utf-8"))
            except Exception:  # noqa: BLE001 - a broken cache is refetched
                cached = None
        if cached is not None and (cached.get("schema") != CACHE_SCHEMA or cached.get("packages") != self.packages):
            cached = None
        fresh = cached is not None and time.time() - path.stat().st_mtime < CACHE_TTL_SECONDS
        if cached is not None and (offline or fresh):
            self.retrieved_at = cached.get("retrieved_at")
            return cached.get("records", {})
        if offline:
            raise RuntimeError("オフラインで、CVSS のキャッシュがありません")
        try:
            records = self._fetch_all()
        except Exception as e:  # noqa: BLE001
            if cached is not None:
                self.retrieved_at = cached.get("retrieved_at")
                self.notes.append(f"CVSS（{self.label}）を取得できなかったため、前回のキャッシュ（{self.retrieved_at}）を使いました（{e}）")
                return cached.get("records", {})
            raise
        self.retrieved_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"schema": CACHE_SCHEMA, "retrieved_at": self.retrieved_at,
                                    "packages": self.packages, "records": records},
                                   separators=(",", ":")), encoding="utf-8")
        return records

    def records(self, offline: bool = False) -> Dict[str, dict]:
        if not hasattr(self, "_records"):
            self._records = self._load(offline)
        return self._records

    @staticmethod
    def cve_url(cve: str) -> str:
        return f"https://access.redhat.com/security/cve/{cve.lower()}"


class RedHatCvssSource(RedHatSecurityData):
    """CVSS signal for --kernel-auto ([signals.cvss] in kernel_sources.toml)."""

    def lookup(self, cve_ids: Iterable[str], offline: bool = False) -> Dict[str, dict]:
        """{cve: {"vector", "score", "source", "source_url"}} for the CVEs this source has scored."""
        records = self.records(offline)
        out: Dict[str, dict] = {}
        for cve in cve_ids:
            rec = records.get(cve.upper())
            if not rec or not rec.get("vector") or rec.get("score") is None:
                continue
            out[cve.upper()] = {
                "vector": rec["vector"], "score": rec["score"], "source": self.name,
                "source_url": self.cve_url(cve),
            }
        return out
