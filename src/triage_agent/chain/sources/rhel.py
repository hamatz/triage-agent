"""RHEL kernel adapter (ADR-021 stage 5).

Fixed versions come from OSV.dev's "Red Hat" ecosystem, which imports Red Hat's CSAF advisories
(RHSA / RHBA). The main stream of each major release is queried ('Red Hat:enterprise_linux:9::baseos',
package 'kernel'), exactly like the AlmaLinux / Rocky Linux records, so this adapter reuses OsvAdapter.

Red Hat also publishes per-CVE fix states. CVEs that Red Hat lists for the release's kernel as
'Affected', 'Fix deferred', 'Will not fix' or 'New' (under analysis) have no advisory yet, so OSV cannot
show them; they are added as exposed CVEs without a fixed version (reported as "修正版なし"). The states
come from the same bulk Red Hat Security Data API download as the CVSS signal.

Known limits (disclosed in docs/exploit-chain.md):
- Hosts on Extended Update Support (EUS) / Advanced Update Support streams are compared with the main
  stream. A CVE fixed only in an EUS build is reported as exposed (safe side, may over-report).
- Real-time kernels ('kernel-rt') are not covered by the baseos ecosystem; such pools are reported as
  source errors rather than as clean.
"""

from typing import Dict, List, Optional, Set

from triage_agent.chain.sources.base import KernelAdvisoryFix, PoolKernelIdentity, SourceResult
from triage_agent.chain.sources.cvss_redhat import RedHatSecurityData
from triage_agent.chain.sources.osv import OsvAdapter


class RhelAdapter(OsvAdapter):
    name = "rhel"

    def __init__(self, config: dict, cache_dir: str = "triage-output/cache", timeout: int = 60):
        super().__init__(config, cache_dir=cache_dir, timeout=timeout)
        self.redhat = RedHatSecurityData({"packages": config.get("redhat_packages") or ["kernel"]},
                                         cache_dir=cache_dir, timeout=timeout)

    @staticmethod
    def _normalize_fixed(fixed: Optional[str], distro: str) -> Optional[str]:
        if fixed is not None and ":" not in fixed:
            return f"0:{fixed}"   # RPM: express the epoch explicitly, as Red Hat does
        return fixed

    def fetch(self, lineages: Set[str], offline: bool = False, identities=None) -> SourceResult:
        result = super().fetch(lineages, offline=offline, identities=identities)
        if not lineages:
            return result
        try:
            records = self.redhat.records(offline)
        except Exception as e:  # noqa: BLE001 - disclosed; the advisory part stays usable
            result.errors.append(
                f"Red Hat Security Data API を取得できなかったため、RHEL の未修正の CVE（Affected など）と重大度を反映していません（{e}）"
            )
            return result
        result.errors.extend(self.redhat.notes)
        for fix in result.fixes:  # OSV records carry no severity for Red Hat; use Red Hat's per-CVE rating
            if fix.severity == "unknown":
                fix.severity = (records.get(fix.cve_id) or {}).get("severity", "unknown")
        identities = identities or {}
        for lineage in sorted(lineages):
            pools: List[PoolKernelIdentity] = identities.get(lineage) or []
            if not pools or lineage not in result.lineages_covered:
                continue
            major = pools[0].release.split(".")[0]
            package = self.package_for(pools[0])
            for cve, rec in sorted(records.items()):
                states = [s for m, p, s in rec.get("unfixed", []) if m == major and p == package]
                if not states:
                    continue
                result.fixes.append(KernelAdvisoryFix(
                    cve_id=cve, lineage=lineage, fixed_evr=None, severity=rec.get("severity", "unknown"),
                    advisory_ids=[f"Red Hat: {states[0]}"], source_url=self.redhat.cve_url(cve),
                    retrieved_at=self.redhat.retrieved_at or "", affected_confirmed=True,
                ))
        return result
