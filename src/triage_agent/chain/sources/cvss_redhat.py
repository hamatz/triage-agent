"""CVSS for kernel CVEs from the Red Hat Security Data API (ADR-021, tier-2 / promotion signal).

    GET https://access.redhat.com/hydra/rest/securitydata/cve.json?package=kernel&per_page=1000&page=N

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
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, Iterable, List, Optional

API = "https://access.redhat.com/hydra/rest/securitydata/cve.json"
CACHE_TTL_SECONDS = 24 * 3600
PER_PAGE = 1000
MAX_PAGES = 100


class RedHatCvssSource:
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
        req = urllib.request.Request(url, headers={"User-Agent": "triage-agent (ADR-021 CVSS signal)"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _cache_path(self) -> Path:
        return Path(self.cache_dir) / "cvss" / "redhat_kernel.json"

    def _fetch_all(self) -> Dict[str, dict]:
        records: Dict[str, dict] = {}
        for package in self.packages:
            for page in range(1, MAX_PAGES + 1):
                q = urllib.parse.urlencode({"package": package, "per_page": PER_PAGE, "page": page})
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
                    records[cve] = {"vector": vector or None, "score": score}
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
        fresh = cached is not None and time.time() - path.stat().st_mtime < CACHE_TTL_SECONDS \
            and cached.get("packages") == self.packages
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
        path.write_text(json.dumps({"retrieved_at": self.retrieved_at, "packages": self.packages, "records": records},
                                   separators=(",", ":")), encoding="utf-8")
        return records

    # -- contract ---------------------------------------------------------------------------------
    def lookup(self, cve_ids: Iterable[str], offline: bool = False) -> Dict[str, dict]:
        """{cve: {"vector", "score", "source", "source_url"}} for the CVEs this source has scored."""
        records = self._load(offline)
        out: Dict[str, dict] = {}
        for cve in cve_ids:
            rec = records.get(cve.upper())
            if not rec or not rec.get("vector") or rec.get("score") is None:
                continue
            out[cve.upper()] = {
                "vector": rec["vector"], "score": rec["score"], "source": self.name,
                "source_url": f"https://access.redhat.com/security/cve/{cve.lower()}",
            }
        return out
