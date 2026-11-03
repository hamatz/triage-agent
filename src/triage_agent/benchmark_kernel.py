"""Benchmark cases for the automatic kernel lookup (ADR-021 stage 7).

Each case in ``kernel_auto_cases`` (benchmark/manifest.json) describes one node pool, what a
distribution source says about its kernel line, the threat signals, optionally the previous run, and
the expected outcome. The source is a declarative stand-in (``StaticAdapter``), so the cases check the
distribution-neutral core end to end: exposure, lineage separation, livepatch, tiers, the tier 2 cap,
promotion, coverage, and never reporting an unlooked-up pool as clean. The adapters' parsing of real
feeds is covered by the unit tests with trimmed real data.

Case fields (all optional unless noted):
  id, name, description         (required) identification
  polarity                      'positive' (something must be flagged) or 'negative' (must stay quiet)
  pool                          {distro, release, package, flavor, version, epoch, livepatch,
                                 observed_nodes, expected_nodes}
  workload_exposure             internet_facing | untrusted_code | internal_only (default untrusted_code)
  adapter                       'static' (default) | 'none' (no source for the distribution) |
                                'unreachable' (the source fails)
  fixes                         [{cve, series, package?, fixed (null = no fix yet)}]
  livepatch_fixes               [{cve, target, package, fixed}]
  kev, epss, cvss               signals now ({cve: score} / {cve: {vector, score}})
  previous                      {epss, cvss, tiers: {"1": [...], ...}} of the previous run
  target_cve                    CVE whose chain level is checked
  expected_level                chain level for target_cve, or 'NONE' (no chain item for it)
  expected_pool_status          ok | no_adapter | unidentified | source_error
  expected_promoted             CVEs that must be promoted in this run (and no others)
  expected_coverage_note        true when the pool must be flagged as partially collected
"""

from typing import Any, Dict, List, Optional, Set

from triage_agent.chain.engine import build_pool_coverage, run_exploit_chain_audit
from triage_agent.chain.kernel_exposure import run_kernel_auto
from triage_agent.chain.models import (
    EnvironmentDefinition,
    ExposureType,
    NodePoolDefinition,
    NodeTelemetry,
    WorkloadDefinition,
)
from triage_agent.chain.sources.base import (
    KernelAdvisoryAdapter,
    KernelAdvisoryFix,
    LivepatchFix,
    PoolKernelIdentity,
    SourceResult,
    lineage_key,
)

POOL_ID = "bench-pool"
NOW = "2026-11-03T00:00:00Z"
PREVIOUS_AT = "2026-11-02T00:00:00Z"


class StaticAdapter(KernelAdvisoryAdapter):
    """A source whose answer is declared by the benchmark case."""

    name = "benchmark"

    def __init__(self, case: dict, fail: bool = False):
        super().__init__({})
        self.case, self.fail = case, fail

    def lineage_for(self, identity: PoolKernelIdentity) -> Optional[str]:
        if not identity.series:
            return None
        return lineage_key(identity.distro, identity.release.split(".")[0], identity.package, identity.series)

    def fetch(self, lineages: Set[str], offline: bool = False, identities=None) -> SourceResult:
        if self.fail:
            raise RuntimeError("benchmark: source unreachable")
        pool = self.case["pool"]
        result = SourceResult(adapter=self.name, retrieved_at=NOW)
        for f in self.case.get("fixes", []):
            lk = lineage_key(pool["distro"], str(pool["release"]).split(".")[0], f.get("package", pool["package"]), f["series"])
            result.fixes.append(KernelAdvisoryFix(
                cve_id=f["cve"], lineage=lk, fixed_evr=f.get("fixed"), severity=f.get("severity", "unknown"),
                advisory_ids=[f"BENCH-{f['cve']}"], source_url="https://example.invalid/benchmark", retrieved_at=NOW,
            ))
        for lp in self.case.get("livepatch_fixes", []):
            result.livepatch_fixes.append(LivepatchFix(cve_id=lp["cve"], target_kernel=lp["target"],
                                                       livepatch_package=lp["package"], fixed_evr=lp["fixed"]))
        result.lineages_covered = {f.lineage for f in result.fixes} & set(lineages)
        return result


def _exposure(value: str) -> ExposureType:
    return {"internet_facing": ExposureType.INTERNET_FACING, "untrusted_code": ExposureType.UNTRUSTED_CODE}.get(
        (value or "").lower(), ExposureType.INTERNAL_ONLY)


def _previous_snapshot(case: dict) -> Optional[dict]:
    prev = case.get("previous")
    if prev is None:
        return None
    signals: Dict[str, dict] = {}
    for cve, score in (prev.get("epss") or {}).items():
        signals.setdefault(cve, {})["epss"] = score
    for cve, cv in (prev.get("cvss") or {}).items():
        signals.setdefault(cve, {})["cvss"] = cv
    for cve in prev.get("kev") or []:
        signals.setdefault(cve, {})["kev"] = True
    tiers = {k: list(v) for k, v in (prev.get("tiers") or {}).items()}
    return {
        "schema": 1, "taken_at": PREVIOUS_AT, "kev_available": True, "epss_available": True, "cvss_available": True,
        "signals": signals, "promotions": {},
        "pools": {POOL_ID: {"status": "ok", "installed": None, "tiers": {k: tiers.get(k, []) for k in ("1", "2", "3")}}},
    }


def run_case(case: dict) -> Dict[str, Any]:
    pool = case["pool"]
    env = EnvironmentDefinition(
        environment_name="benchmark",
        node_pools=[NodePoolDefinition(pool_id=POOL_ID, os_distribution=pool["distro"],
                                       nodes_count=pool.get("expected_nodes", pool.get("observed_nodes", 1)))],
        workloads=[WorkloadDefinition(name="bench-workload", exposure=_exposure(case.get("workload_exposure", "untrusted_code")),
                                      node_pool=POOL_ID)],
    )
    tel = {POOL_ID: NodeTelemetry(
        pool_id=POOL_ID, os_distribution=pool["distro"], os_release=str(pool["release"]),
        kernel_flavor=pool.get("flavor", pool["package"]), kernel_binary_package=pool["package"],
        kernel_package_version=pool["version"], kernel_package_epoch=pool.get("epoch"),
        livepatch_packages=pool.get("livepatch", []), observed_nodes_count=pool.get("observed_nodes", 1),
    )}
    mode = case.get("adapter", "static")
    adapters = {} if mode == "none" else {pool["distro"]: StaticAdapter(case, fail=(mode == "unreachable"))}
    epss = {c: {"epss": s, "percentile": 0.9} for c, s in (case.get("epss") or {}).items()}
    cvss = case.get("cvss")
    res = run_kernel_auto(
        env, tel, adapters,
        kev_lookup=lambda: {c: {} for c in case.get("kev", [])},
        epss_lookup=lambda ids: {c: v for c, v in epss.items() if c in ids},
        cvss_lookup=(lambda ids: {c: v for c, v in cvss.items() if c in ids}) if cvss is not None else None,
        previous_snapshot=_previous_snapshot(case),
        now=NOW,
        coverage=build_pool_coverage(env, tel),
    )
    items = run_exploit_chain_audit(environment=env, kernel_vulnerabilities=res.entries, telemetries=tel,
                                    evaluation_date="2026-11-03")
    summary = res.pools[POOL_ID]
    by_cve = {i.kernel_cve: i for i in items}

    checks: List[str] = []
    passed = True
    actual: Dict[str, Any] = {"pool_status": summary.status, "tiers": summary.tier_counts,
                              "promoted": sorted(c for c, p in res.promotions.items() if p.new)}
    if "expected_level" in case:
        item = by_cve.get(case["target_cve"])
        level = item.chain_level.value if item else "NONE"
        actual["level"] = level
        ok = level == case["expected_level"]
        passed &= ok
        checks.append(f"level {level} (expected {case['expected_level']})")
    if "expected_pool_status" in case:
        ok = summary.status == case["expected_pool_status"]
        passed &= ok
        checks.append(f"pool {summary.status} (expected {case['expected_pool_status']})")
    if "expected_promoted" in case:
        ok = actual["promoted"] == sorted(case["expected_promoted"])
        passed &= ok
        checks.append(f"promoted {actual['promoted']} (expected {sorted(case['expected_promoted'])})")
    if "expected_coverage_note" in case:
        ok = bool(summary.coverage_note) == bool(case["expected_coverage_note"])
        passed &= ok
        checks.append(f"coverage note {bool(summary.coverage_note)} (expected {case['expected_coverage_note']})")
    return {
        "id": case["id"],
        "category": "kernel_auto",
        "name": case["name"],
        "polarity": case.get("polarity", "positive"),
        "expected": {k: v for k, v in case.items() if k.startswith("expected_")},
        "actual_status": actual,
        "passed": bool(passed),
        "reasoning": "; ".join(checks),
    }


def run_kernel_auto_cases(manifest: dict) -> List[Dict[str, Any]]:
    return [run_case(case) for case in manifest.get("kernel_auto_cases", [])]
