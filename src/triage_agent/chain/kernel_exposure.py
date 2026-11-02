"""Automatic kernel advisory lookup and tier classification (ADR-021 decisions 1 and 3).

For every node pool, identify the running kernel lineage, ask the registered adapter which CVEs that
lineage has fixes for, decide which of them the pool is still exposed to, and classify them:

    tier 1  confirmed exploitation risk : listed in CISA KEV, or promoted (kernel_history: EPSS jump,
                                          upward CVSS revision, or a person's --promote)
    tier 2  suspected LPE               : EPSS >= threshold, or distribution severity 'critical'
    tier 3  other unfixed CVEs          : counted only

Tier 1 and the top tier 2 CVEs become KernelVulnerabilityEntry objects scoped to their pool, so the
existing chain engine evaluates them; tier 2 is capped at HIGH_UNVERIFIED there. CVEs that are also in
the manual ledger are skipped (the manual, sourced entry wins).

Distribution specific logic lives only in the adapters (triage_agent.chain.sources).
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set, Tuple

from triage_agent.chain.kernel_history import (
    DEFAULT_EPSS_JUMP,
    PoolChanges,
    Promotion,
    build_snapshot,
    compute_changes,
    evaluate_promotions,
)
from triage_agent.chain.models import (
    DistroAffectedRange,
    EnvironmentDefinition,
    KernelVulnerabilityEntry,
    NodeTelemetry,
)
from triage_agent.chain.sources.base import (
    SEVERITY_RANK,
    KernelAdvisoryAdapter,
    KernelAdvisoryFix,
    PoolKernelIdentity,
    SourceResult,
)
from triage_agent.chain.version_parser import compare_kernel_versions

DEFAULT_EPSS_THRESHOLD = 0.1
DEFAULT_TIER2_LIMIT = 10


@dataclass
class ExposedCve:
    cve_id: str
    tier: int
    fixed_evr: Optional[str]
    severity: str
    in_kev: bool
    epss: Optional[float]
    advisory_ids: List[str]
    source_url: str
    promotion: Optional[Promotion] = None
    cvss_score: Optional[float] = None


@dataclass
class PoolAutoSummary:
    pool_id: str
    status: str                       # ok | no_adapter | unidentified | source_error (never treated as clean)
    reason: str = ""
    adapter: Optional[str] = None
    lineage: Optional[str] = None
    installed: Optional[str] = None
    grounded_in_telemetry: bool = False
    tier_counts: Dict[int, int] = field(default_factory=lambda: {1: 0, 2: 0, 3: 0})
    livepatched: int = 0
    indeterminate: int = 0            # version comparison impossible (counted as exposed, tier as signals say)
    no_fix_available: int = 0         # exposed CVEs for which the distribution has not shipped a fix (where known)
    details_not_fetched: int = 0      # exposed CVEs whose fixed version was not downloaded (tier 3 only)
    upgrade_target: Optional[str] = None       # resolves every tier 1 and 2 CVE
    all_fixes_target: Optional[str] = None     # resolves every listed CVE
    exposed: List[ExposedCve] = field(default_factory=list)
    tier2_itemized: int = 0


@dataclass
class KernelAutoResult:
    pools: Dict[str, PoolAutoSummary] = field(default_factory=dict)
    entries: List[KernelVulnerabilityEntry] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    epss_available: bool = True
    kev_available: bool = True
    epss_threshold: float = DEFAULT_EPSS_THRESHOLD
    tier2_limit: int = DEFAULT_TIER2_LIMIT
    kev_catalog_info: Optional[Dict[str, object]] = None   # provenance of the KEV catalog used
    cvss_available: bool = False
    epss_jump: float = DEFAULT_EPSS_JUMP
    promotions: Dict[str, Promotion] = field(default_factory=dict)     # in force for exposed CVEs
    manual_promotions: Dict[str, dict] = field(default_factory=dict)   # the --promote ledger
    previous_taken_at: Optional[str] = None     # None: no previous snapshot (this run is the baseline)
    changes: Dict[str, PoolChanges] = field(default_factory=dict)
    snapshot: Optional[dict] = None             # to be saved by the caller (live runs only)

    @property
    def new_tier1_total(self) -> int:
        return sum(len(c.new_tier1) for c in self.changes.values())


def _split_epoch(version: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not version:
        return None, None
    if ":" in version:
        e, v = version.split(":", 1)
        return e, v
    return None, version


def identify_pools(
    environment: EnvironmentDefinition,
    telemetries: Optional[Dict[str, NodeTelemetry]],
) -> Dict[str, Tuple[Optional[PoolKernelIdentity], str]]:
    """Kernel identity per pool (telemetry first, environments.yaml otherwise), or a reason it is unknown."""
    telemetry_map = telemetries or {}
    out: Dict[str, Tuple[Optional[PoolKernelIdentity], str]] = {}
    for pool in environment.node_pools:
        tel = telemetry_map.get(pool.pool_id)
        if tel is not None:
            distro, release = tel.os_distribution, tel.os_release
            package = tel.kernel_binary_package or tel.kernel_flavor
            epoch, version = tel.kernel_package_epoch, tel.kernel_package_version
            engine_flavor = (tel.kernel_flavor or "unknown").strip().lower()
            lp, grounded = tuple(tel.livepatch_packages or ()), True
        else:
            distro, release = pool.os_distribution, pool.os_release
            package = pool.kernel_flavor or pool.kernel_package_name
            epoch, version = _split_epoch(pool.kernel_package_version)
            engine_flavor = (pool.kernel_flavor or "linux").strip().lower()
            lp, grounded = (), False
        missing = [n for n, v in (("ディストリ", distro), ("リリース", release), ("カーネルパッケージ", package), ("パッケージ版", version))
                   if not v or str(v).strip().lower() in ("unknown", "")]
        if missing:
            out[pool.pool_id] = (None, f"{'・'.join(missing)}が分からないため、照会できません")
            continue
        out[pool.pool_id] = (
            PoolKernelIdentity(
                pool_id=pool.pool_id, distro=str(distro).strip().lower(), release=str(release).strip(),
                package=str(package).strip(), version=str(version).strip(), epoch=(str(epoch).strip() if epoch not in (None, "") else None),
                engine_flavor=engine_flavor, livepatch_packages=lp, grounded_in_telemetry=grounded,
            ),
            "",
        )
    return out


def _is_livepatched(identity: PoolKernelIdentity, cve: str, livepatch_index: Dict[str, list]) -> bool:
    """True if an installed livepatch package for exactly this kernel build covers the CVE."""
    installed = {}
    for item in identity.livepatch_packages:
        name, _, evr = item.partition("=")
        installed[name] = evr
    for lp in livepatch_index.get(cve, []):
        if not KernelAdvisoryAdapter.livepatch_matches(lp.target_kernel, identity.version):
            continue
        have = installed.get(lp.livepatch_package)
        if not have:
            continue
        cmp = compare_kernel_versions(identity.distro, have, lp.fixed_evr)
        if cmp is not None and cmp >= 0:
            return True
    return False


def _max_version(distro: str, versions: Iterable[str]) -> Optional[str]:
    best = None
    for v in versions:
        if best is None:
            best = v
            continue
        cmp = compare_kernel_versions(distro, v, best)
        if cmp is not None and cmp > 0:
            best = v
    return best


def _engine_fixed_version(identity: PoolKernelIdentity, fixed_evr: str) -> str:
    """Express the fixed version in the same form as the installed version the engine compares.

    The engine compares against the telemetry's version-release (no epoch). The epoch is dropped only
    when it is known to be equal on both sides; otherwise it is kept so the comparison is indeterminate
    (fail-safe) rather than wrong.
    """
    f_epoch, f_rest = _split_epoch(fixed_evr)
    if f_epoch is not None and identity.epoch is not None and str(int(f_epoch)) == str(int(identity.epoch)):
        return f_rest
    return fixed_evr


def run_kernel_auto(
    environment: EnvironmentDefinition,
    telemetries: Optional[Dict[str, NodeTelemetry]],
    adapters: Dict[str, KernelAdvisoryAdapter],
    kev_lookup: Optional[Callable[[], Dict[str, dict]]],
    epss_lookup: Optional[Callable[[List[str]], Dict[str, Dict[str, float]]]],
    manual_cve_ids: Optional[Set[str]] = None,
    offline: bool = False,
    epss_threshold: float = DEFAULT_EPSS_THRESHOLD,
    tier2_limit: int = DEFAULT_TIER2_LIMIT,
    previous_snapshot: Optional[dict] = None,
    manual_promotions: Optional[Dict[str, dict]] = None,
    epss_jump: float = DEFAULT_EPSS_JUMP,
    cvss_lookup: Optional[Callable[[List[str]], Dict[str, dict]]] = None,
    now: Optional[str] = None,
) -> KernelAutoResult:
    result = KernelAutoResult(epss_threshold=epss_threshold, tier2_limit=tier2_limit, epss_jump=epss_jump)
    result.manual_promotions = {k.upper(): v for k, v in (manual_promotions or {}).items()}
    result.previous_taken_at = (previous_snapshot or {}).get("taken_at")
    manual = {c.upper() for c in (manual_cve_ids or set())}
    identities = identify_pools(environment, telemetries)

    # 1) lineage per pool and lineages to fetch per adapter
    pool_lineage: Dict[str, Tuple[PoolKernelIdentity, KernelAdvisoryAdapter, str]] = {}
    wanted: Dict[str, Set[str]] = {}
    lineage_pools: Dict[str, List[PoolKernelIdentity]] = {}
    adapter_by_name: Dict[str, KernelAdvisoryAdapter] = {}
    for pool_id, (identity, reason) in identities.items():
        if identity is None:
            result.pools[pool_id] = PoolAutoSummary(pool_id=pool_id, status="unidentified", reason=reason)
            continue
        adapter = adapters.get(identity.distro)
        if adapter is None:
            result.pools[pool_id] = PoolAutoSummary(
                pool_id=pool_id, status="no_adapter", installed=identity.evr, grounded_in_telemetry=identity.grounded_in_telemetry,
                reason=f"ディストリ {identity.distro} の照会元が未登録のため、自動照会していません（手動台帳のみで評価）",
            )
            continue
        lineage = adapter.lineage_for(identity)
        if lineage is None:
            result.pools[pool_id] = PoolAutoSummary(
                pool_id=pool_id, status="unidentified", adapter=adapter.name, installed=identity.evr,
                grounded_in_telemetry=identity.grounded_in_telemetry,
                reason=f"カーネルの系統（{identity.package} {identity.version}）を特定できないため、照会できません",
            )
            continue
        pool_lineage[pool_id] = (identity, adapter, lineage)
        wanted.setdefault(adapter.name, set()).add(lineage)
        lineage_pools.setdefault(lineage, []).append(identity)
        adapter_by_name[adapter.name] = adapter

    # 2) fetch once per adapter
    fetched: Dict[str, SourceResult] = {}
    for name, lineages in wanted.items():
        try:
            fetched[name] = adapter_by_name[name].fetch(
                lineages, offline=offline, identities={lk: lineage_pools[lk] for lk in lineages}
            )
        except Exception as e:  # noqa: BLE001 - disclosed
            fetched[name] = SourceResult(adapter=name, errors=[f"{name}: 照会に失敗しました（{e}）"])
        result.errors.extend(fetched[name].errors)

    # 3) exposure per pool
    per_pool_candidates: Dict[str, List[Tuple[KernelAdvisoryFix, bool]]] = {}
    for pool_id, (identity, adapter, lineage) in pool_lineage.items():
        src = fetched[adapter.name]
        summary = PoolAutoSummary(
            pool_id=pool_id, status="ok", adapter=adapter.name, lineage=lineage, installed=identity.evr,
            grounded_in_telemetry=identity.grounded_in_telemetry,
        )
        result.pools[pool_id] = summary
        if lineage not in src.lineages_covered:
            # Every lineage the source knows has at least one advisory. Zero means the data was not
            # obtained or the repository for this line is not registered: never report it as clean.
            summary.status = "source_error"
            summary.reason = (
                "照会元から当該系統の情報を取得できませんでした（照会不全）" if src.errors
                else "照会元に当該系統の勧告が1件もありません（リポジトリが kernel_sources.toml に未登録の可能性）"
            )
            continue
        lp_index: Dict[str, list] = {}
        for lp in src.livepatch_fixes:
            lp_index.setdefault(lp.cve_id, []).append(lp)
        # One fix per CVE: the earliest fixed version wins ("no fix" only if no record has one).
        by_cve: Dict[str, KernelAdvisoryFix] = {}
        for fix in src.fixes:
            if fix.lineage != lineage or fix.cve_id in manual:
                continue
            if fix.applies_to_versions is not None and identity.version not in fix.applies_to_versions:
                continue  # version-specific answer obtained for another pool's kernel
            cur = by_cve.get(fix.cve_id)
            if cur is None:
                by_cve[fix.cve_id] = fix
            elif fix.fixed_evr is not None and (
                cur.fixed_evr is None
                or (compare_kernel_versions(identity.distro, fix.fixed_evr, cur.fixed_evr) or 0) < 0
            ):
                by_cve[fix.cve_id] = fix
        candidates = []
        for fix in by_cve.values():
            if fix.fixed_evr is None:
                # No fixed version known: either the distribution has not fixed it yet, or the details
                # are fetched later (details_pending). Exposed either way.
                candidates.append((fix, False))
                continue
            cmp = compare_kernel_versions(identity.distro, identity.evr, fix.fixed_evr)
            if fix.affected_confirmed and (cmp is None or cmp >= 0):
                cmp = -1  # the source already answered for this exact version: trust it
            if cmp is not None and cmp >= 0:
                continue  # already fixed
            if _is_livepatched(identity, fix.cve_id, lp_index):
                summary.livepatched += 1
                continue
            if cmp is None:
                summary.indeterminate += 1
            candidates.append((fix, cmp is None))
        per_pool_candidates[pool_id] = candidates

    # 4) threat signals for every exposed CVE (one KEV catalog, batched EPSS)
    all_cves = sorted({fix.cve_id for cands in per_pool_candidates.values() for fix, _ in cands})
    kev: Dict[str, dict] = {}
    epss: Dict[str, Dict[str, float]] = {}
    if all_cves:
        try:
            kev = kev_lookup() if kev_lookup else {}
            result.kev_available = kev_lookup is not None
        except Exception as e:  # noqa: BLE001
            result.kev_available = False
            result.errors.append(f"CISA KEV を取得できませんでした（{e}）。層1の判定が不完全です")
        if epss_lookup is None or offline:
            result.epss_available = False
        else:
            try:
                epss = epss_lookup(all_cves)
            except Exception as e:  # noqa: BLE001
                result.epss_available = False
                result.errors.append(f"EPSS を取得できませんでした（{e}）。層2の判定が不完全です")
    cvss: Dict[str, dict] = {}
    if all_cves and cvss_lookup is not None and not offline:
        try:
            cvss = cvss_lookup(all_cves) or {}
            result.cvss_available = True
        except Exception as e:  # noqa: BLE001
            result.errors.append(f"CVSS を取得できませんでした（{e}）。CVSS の引き上げによる昇格を判定していません")

    # 4a) promotions (deterministic, against the previous run's snapshot)
    epss_scores = {c: (v or {}).get("epss") for c, v in epss.items()}
    result.promotions = evaluate_promotions(
        set(all_cves), set(kev), epss_scores, cvss, previous_snapshot, result.manual_promotions,
        epss_jump=epss_jump, now=now,
    )

    # 4b) fetch details (fixed version, distribution severity) only for what can reach tier 1 / 2
    def _signal_tier(fix: KernelAdvisoryFix) -> int:
        score = (epss.get(fix.cve_id) or {}).get("epss")
        if fix.cve_id in kev or fix.cve_id in result.promotions:
            return 1
        if (score is not None and score >= epss_threshold) or fix.severity == "critical":
            return 2
        return 3

    for name, src in fetched.items():
        pending = [f for f in src.fixes if f.details_pending and _signal_tier(f) in (1, 2)]
        if pending:
            result.errors.extend(adapter_by_name[name].enrich(pending, offline=offline))

    # 5) tiers, upgrade targets, entries
    for pool_id, candidates in per_pool_candidates.items():
        identity, adapter, lineage = pool_lineage[pool_id]
        summary = result.pools[pool_id]
        exposed: List[ExposedCve] = []
        for fix, _indeterminate in candidates:
            if fix.details_pending:
                summary.details_not_fetched += 1   # tier 3 per-CVE records: fixed version not downloaded
            elif fix.fixed_evr is None:
                summary.no_fix_available += 1
            in_kev = fix.cve_id in kev
            score = (epss.get(fix.cve_id) or {}).get("epss")
            promotion = result.promotions.get(fix.cve_id)
            if in_kev or promotion is not None:
                tier = 1
            elif (score is not None and score >= epss_threshold) or fix.severity == "critical":
                tier = 2
            else:
                tier = 3
            summary.tier_counts[tier] += 1
            exposed.append(ExposedCve(
                cve_id=fix.cve_id, tier=tier, fixed_evr=fix.fixed_evr, severity=fix.severity, in_kev=in_kev,
                epss=score, advisory_ids=list(fix.advisory_ids), source_url=fix.advisory_url or fix.source_url,
                promotion=promotion, cvss_score=(cvss.get(fix.cve_id) or {}).get("score"),
            ))
        exposed.sort(key=lambda x: (
            x.tier, not x.in_kev, x.promotion is None, -(x.epss or 0.0), -SEVERITY_RANK.get(x.severity, 0),
            -(x.cvss_score or 0.0), x.cve_id,
        ))
        summary.exposed = exposed
        summary.upgrade_target = _max_version(identity.distro, [x.fixed_evr for x in exposed if x.tier in (1, 2) and x.fixed_evr])
        summary.all_fixes_target = _max_version(identity.distro, [x.fixed_evr for x in exposed if x.fixed_evr])

        tier2_used = 0
        for x in exposed:
            if x.tier == 3:
                continue
            if x.tier == 2:
                if tier2_used >= tier2_limit:
                    continue
                tier2_used += 1
            fix_src = next(f for f, _ in per_pool_candidates[pool_id] if f.cve_id == x.cve_id)
            ranges = {}
            if x.fixed_evr:
                ranges = {
                    f"{identity.distro}:{identity.release.lower()}:{identity.engine_flavor}": DistroAffectedRange(
                        package=identity.package, fixed_version=_engine_fixed_version(identity, x.fixed_evr)
                    )
                }
            promoted = f"・昇格: {x.promotion.label} {x.promotion.detail}" if x.promotion else ""
            result.entries.append(KernelVulnerabilityEntry(
                cve_id=x.cve_id,
                name=f"{x.cve_id}（{adapter.name} 自動照会・層{x.tier}{promoted}{'・修正版なし' if not x.fixed_evr else ''}）",
                source_url=x.source_url,
                retrieved_at=(fix_src.retrieved_at or "")[:10],
                epss_score=x.epss,
                cisa_kev=x.in_kev,
                distro_affected_ranges=ranges,  # no range (no fix yet) => the engine reports 要確認 (exposed)
                applies_to_pools=[pool_id],
                auto_tier=x.tier,
                provenance="auto",
            ))
        summary.tier2_itemized = tier2_used

    # 6) run-to-run changes and the snapshot for the next run
    result.changes = compute_changes(result, previous_snapshot)
    if not offline:
        result.snapshot = build_snapshot(result, set(kev), epss_scores, cvss, previous_snapshot, now=now)
    return result
