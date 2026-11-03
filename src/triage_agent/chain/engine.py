"""Exploit Chain Triaging Engine (v0.4.0 / ADR-019).

Evaluates systemic co-location risks between application-layer footholds (RCEs) and
OS/Kernel-layer Privilege Escalation (LPE) vulnerabilities across shared-kernel node pools.
"""

import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from triage_agent.chain.foothold import evaluate_application_foothold
from triage_agent.chain.mitigations import evaluate_kernel_mitigation
from triage_agent.chain.models import (
    ChainAuditItem,
    ChainLevel,
    EnvironmentDefinition,
    ExposureType,
    KernelVulnerabilityEntry,
    NodePoolDefinition,
    NodeTelemetry,
    PoolCoverage,
    TelemetryLoadIssue,
    WorkloadDefinition,
)
from triage_agent.chain.version_parser import is_kernel_package_vulnerable


def _resolve_distro_range(
    distro: str,
    os_release: Optional[str],
    kernel_package: Optional[str],
    kernel_flavor: Optional[str],
    distro_affected_ranges: Dict[str, Any],
) -> Tuple[Optional[Any], str]:
    """Resolve distro-specific affected range accounting for cloud/distro flavors.
    
    Returns (DistroAffectedRange or None, match_explanation).
    Upholds 'Never declare unverified items safe': If a node runs a specialized kernel flavor
    (e.g. linux-aws) but the ledger only defines generic/unspecified, returns None to force indeterminate!
    """
    d_clean = (distro or "").strip().lower()
    rel_clean = (os_release or "").strip().lower()
    
    # Determine flavor (e.g. 'linux-aws', 'linux-gcp', 'linux-azure', 'linux')
    flavor = "linux"
    if kernel_flavor:
        flavor = kernel_flavor.strip().lower()
    elif kernel_package:
        pkg_lower = kernel_package.strip().lower()
        for f in ["aws", "azure", "gcp", "oracle", "kvm", "hwe"]:
            if f"-{f}" in pkg_lower or f"linux-{f}" in pkg_lower:
                flavor = f"linux-{f}"
                break

    # Candidate keys in order of precision:
    candidates = []
    if rel_clean:
        candidates.append(f"{d_clean}:{rel_clean}:{flavor}")
    candidates.append(f"{d_clean}:{flavor}")
    
    # Generic keys (without flavor) are ONLY allowed if node is genuinely running the standard/generic kernel
    if flavor == "linux":
        if rel_clean:
            candidates.append(f"{d_clean}:{rel_clean}")
        candidates.append(d_clean)

    for c in candidates:
        if c in distro_affected_ranges:
            return distro_affected_ranges[c], f"合致キー: {c}"

    if flavor != "linux":
        return None, f"台帳に当該カーネル系統（{d_clean}:{flavor}）の修正版情報未登録（安全側に倒し要確認）"
    return None, f"台帳にディストリビューション（{d_clean}）の修正版情報未登録"


def audit_exploit_chains(
    environment: EnvironmentDefinition,
    kernel_vulnerabilities: List[KernelVulnerabilityEntry],
    app_findings_by_workload: Dict[str, List[Dict[str, Any]]],
    telemetry_by_pool: Optional[Dict[str, NodeTelemetry]] = None,
    evaluation_date: Optional[str] = None,
) -> List[ChainAuditItem]:
    """Execute end-to-end exploit chain evaluation across all workloads and shared node pools.
    
    Upholds 'Never declare unverified items safe' and prevents lateral movement blind spots.
    """
    today_str = evaluation_date or date.today().isoformat()
    telemetry_map = telemetry_by_pool or {}
    pool_map: Dict[str, NodePoolDefinition] = {p.pool_id: p for p in environment.node_pools}
    coverage_map = build_pool_coverage(environment, telemetry_map)

    # Group workloads by node pool for blast radius calculation
    workloads_by_pool: Dict[str, List[WorkloadDefinition]] = {}
    for wl in environment.workloads:
        workloads_by_pool.setdefault(wl.node_pool, []).append(wl)

    audit_results: List[ChainAuditItem] = []

    for wl in environment.workloads:
        pool = pool_map.get(wl.node_pool)
        if not pool:
            # Fallback for undefined node pool: create safe fail-safe dummy pool
            pool = NodePoolDefinition(
                pool_id=wl.node_pool,
                os_distribution="unknown",
            )

        # Blast radius: all other workloads running in the same node pool
        co_located_workloads = [
            w.name for w in workloads_by_pool.get(wl.node_pool, [])
            if w.name != wl.name
        ]
        blast_radius_desc = [
            f"同一ノードプール（{wl.node_pool}）上の同居ワークロード: {', '.join(co_located_workloads) if co_located_workloads else 'なし（単独稼働）'}",
            "ノード root 奪取時の実被害: 同居全 Pod のメモリ・環境変数・マウントされた Secret、および kubelet 認証トークンがすべて奪取され、クラスタ全体への横展開に直結します。",
        ]

        # Evaluate application-layer footholds for this workload
        raw_app_findings = app_findings_by_workload.get(wl.name, [])
        detected_footholds: List[Dict[str, Any]] = []
        unclassifiable_high: List[Dict[str, Any]] = []

        for finding in raw_app_findings:
            if finding.get("is_unclassifiable"):
                unclassifiable_high.append({
                    "cve": finding.get("cve_id") or finding.get("cve") or "UNKNOWN",
                    "basis": finding.get("basis") or "判定不能・要確認",
                })
                continue

            cid = finding.get("cve_id") or finding.get("id") or finding.get("cve") or "UNKNOWN"
            f_res = evaluate_application_foothold(
                cve_id=cid,
                cisa_kev=finding.get("cisa_kev", False),
                cvss_vector=finding.get("cvss_vector"),
                cvss_score=finding.get("cvss_score"),
                summary_text=finding.get("summary") or finding.get("title") or finding.get("content_summary"),
                cwe_list=finding.get("cwe_list"),
            )
            if f_res.is_foothold:
                detected_footholds.append({
                    "cve": cid,
                    "basis": f_res.basis,
                })
            elif f_res.is_unclassifiable:
                unclassifiable_high.append({
                    "cve": cid,
                    "basis": f_res.basis,
                })

        has_app_foothold = len(detected_footholds) > 0
        has_unclassifiable = len(unclassifiable_high) > 0

        # Evaluate against each target kernel vulnerability
        for k_entry in kernel_vulnerabilities:
            if k_entry.applies_to_pools is not None and pool.pool_id not in k_entry.applies_to_pools:
                continue  # lineage specific automatic entry for another pool
            pool_telemetry = telemetry_map.get(pool.pool_id)
            
            # Resolve OS and kernel flavor from telemetry or pool definition
            # Fail-safe principle: If telemetry is provided for this pool, its telemetry is the ground truth.
            # If telemetry resolved version or distro as unknown/None, NEVER fall back to hand-written environments.yaml!
            if pool_telemetry:
                eff_distro = pool_telemetry.os_distribution or "unknown"
                eff_release = pool_telemetry.os_release
                eff_pkg = pool_telemetry.kernel_package_name or "linux"
                eff_flavor = pool_telemetry.kernel_flavor or "unknown"
                eff_version = pool_telemetry.kernel_package_version
                # Partial coverage (ADR-021 decision 4) is handled below: it never yields SAFE or MITIGATED.
                is_telemetry_grounded = True
            else:
                eff_distro = pool.os_distribution or "ubuntu"
                eff_release = pool.os_release
                eff_pkg = pool.kernel_package_name or "linux"
                eff_flavor = pool.kernel_flavor
                eff_version = pool.kernel_package_version
                is_telemetry_grounded = False

            range_info, match_exp = _resolve_distro_range(
                distro=eff_distro,
                os_release=eff_release,
                kernel_package=eff_pkg,
                kernel_flavor=eff_flavor,
                distro_affected_ranges=k_entry.distro_affected_ranges,
            )

            # Step 1: Kernel Vulnerability Check (Q1)
            is_vuln: Optional[bool] = None
            if range_info:
                is_vuln = is_kernel_package_vulnerable(
                    distro=eff_distro,
                    installed_version=eff_version,
                    fixed_version=range_info.fixed_version,
                )

            pool_cov = coverage_map.get(pool.pool_id)
            is_partial_telemetry = bool(pool_telemetry and pool_cov and pool_cov.is_known_incomplete)
            if is_partial_telemetry:
                grounding_note = f"・実機テレメトリは一部のノードのみ（{pool_cov.describe()}）"
            elif pool_telemetry:
                grounding_note = f"・実機テレメトリ確認済み（{pool_cov.describe() if pool_cov else '台数不明'}）"
            else:
                grounding_note = "・構成定義上（実機未確認）"

            # Fail-safe: Missing version, unknown flavor, or indeterminate comparison defaults to vulnerable!
            if is_vuln is None:
                is_vuln = True
                kernel_status = f"要確認 (該当の可能性あり⚠️: {match_exp} / 現行: {eff_version or '未確定'})"
            elif is_vuln is False and is_partial_telemetry:
                # Collected nodes are patched, but uncollected nodes may still run a vulnerable kernel.
                is_vuln = True
                kernel_status = (
                    f"要確認 (該当の可能性あり⚠️: 収集済みノードはパッケージ版 {eff_version} で修正済みですが、"
                    f"未収集のノードがあります{grounding_note})"
                )
            elif is_vuln is False:
                kernel_status = f"NO (修正済み: {k_entry.cve_id}・パッケージ版 {eff_version}・{today_str}確認・{match_exp}{grounding_note})"
            else:
                kernel_status = f"YES (脆弱性該当: {k_entry.cve_id}・パッケージ版 {eff_version} < 修正版 {range_info.fixed_version}・{match_exp}{grounding_note})"
            if k_entry.provenance == "auto":
                kernel_status += f"［自動照会・層{k_entry.auto_tier}・出典: {k_entry.source_url}］"

            if not is_vuln:
                # Kernel is definitively patched for this specific CVE
                audit_results.append(
                    ChainAuditItem(
                        workload_name=wl.name,
                        node_pool_id=wl.node_pool,
                        kernel_cve=k_entry.cve_id,
                        app_cve=detected_footholds[0]["cve"] if detected_footholds else None,
                        chain_level=ChainLevel.SAFE,
                        action_deadline="対応不要（カーネルパッチ適用確認済み）" if is_telemetry_grounded else "対応不要（構成定義上修正済み・実機確認推奨）",
                        foothold_detail=None,
                        kernel_status=kernel_status,
                        mitigation_status="緩和策不要（修正済み）",
                        blast_radius=blast_radius_desc,
                        recommendations=[
                            "現行カーネルパッケージを維持し、次期定期更新で最新状態を継続してください。"
                            if is_telemetry_grounded
                            else "構成定義上の修正版設定を確認しました。実機へのパッチ適用状態を担保するため実機テレメトリ（node-telemetry）の採取を推奨します。"
                        ],
                    )
                )
                continue

            # Step 2: Mitigation Check (Q2)
            mitigation_res = evaluate_kernel_mitigation(
                cve_id=k_entry.cve_id,
                telemetry=pool_telemetry,
            )

            is_mitigated = mitigation_res["is_mitigated"]
            if is_mitigated and is_partial_telemetry:
                # The mitigation is confirmed only on collected nodes; uncollected nodes are unknown.
                is_mitigated = False
                mitigation_res = {
                    **mitigation_res,
                    "is_mitigated": False,
                    "status": "UNVERIFIED_PARTIAL_COVERAGE",
                    "reasoning": (
                        f"収集済みのノードでは緩和策を確認できましたが、未収集のノードがあるためプール全体では未確認です"
                        f"（{pool_cov.describe()}）。全ノードのテレメトリを収集してください。"
                    ),
                }
            mitigation_status_str = f"{mitigation_res['status']}: {mitigation_res['reasoning']}"

            # Step 3: Chain Level Evaluation (Q3)
            # Check exposure type (defaulting unknown to internet_facing)
            eff_exposure = wl.exposure
            if eff_exposure == ExposureType.UNKNOWN:
                eff_exposure = ExposureType.INTERNET_FACING

            is_untrusted_code = (eff_exposure == ExposureType.UNTRUSTED_CODE)
            is_internet_facing = (eff_exposure == ExposureType.INTERNET_FACING)
            is_high_exposure = is_untrusted_code or is_internet_facing

            if is_mitigated:
                chain_lvl = ChainLevel.MITIGATED_NEEDS_PATCH
                deadline = "30日以内（通常更新枠）"
                recs = [
                    f"一時的な緩和策（{mitigation_res['reasoning']}）が有効です。",
                    "ただし根本解決ではないため、30日以内の通常メンテナンス枠でカーネルパッチを適用してください。",
                ]
            elif is_untrusted_code:
                # Untrusted code execution environment (CI runner, sandbox) is inherently a foothold!
                chain_lvl = ChainLevel.CRITICAL_CHAIN
                deadline = "48時間以内（回避策・緩和策即時適用）"
                recs = [
                    f"🚨 【最優先対応】ワークロード（{wl.name}）は信頼できないコードを実行する環境（{eff_exposure.value}）です。",
                    f"攻撃者のコード実行が前提の足場となるため、同一カーネル（{wl.node_pool}）上の未解消 LPE（{k_entry.cve_id}）によりノード root 奪取が直結します。",
                    "即座にカーネル緩和策（またはノード緊急再起動・パッチ適用）を実施してください。",
                    mitigation_res["reasoning"],
                ]
                if mitigation_res.get("side_effect_warning"):
                    recs.append(mitigation_res["side_effect_warning"])
            elif has_app_foothold and is_high_exposure:
                # Critical Exploit Chain (e.g. PHP2Shell + Fragnesia on DMZ node)
                chain_lvl = ChainLevel.CRITICAL_CHAIN
                deadline = "48時間以内（回避策・緩和策即時適用）"
                recs = [
                    f"🚨 【最優先対応】外部到達可能ワークロード（{wl.name}）で侵入足場（{detected_footholds[0]['cve']}）を検知しました。",
                    f"同一カーネル（{wl.node_pool}）上に未解消 LPE（{k_entry.cve_id}）が存在するため、コンテナ脱出・ノード root 奪取が直結します。",
                    "即座にアプリ層のパッチ/回避策、およびカーネル緩和策（またはノード緊急再起動・パッチ適用）を実施してください。",
                    mitigation_res["reasoning"],
                ]
                if mitigation_res.get("side_effect_warning"):
                    recs.append(mitigation_res["side_effect_warning"])
            elif has_unclassifiable and is_high_exposure:
                chain_lvl = ChainLevel.HIGH_UNVERIFIED
                deadline = "2週間以内（足場リスク要人手確認）"
                recs = [
                    f"外部到達可能ワークロード（{wl.name}）で高深刻度または未確定脆弱性（{unclassifiable_high[0]['cve']}）を検知しました。",
                    "足場（RCE）の可否が自動判定不能なため、人手による精査を行い、足場となりうる場合は Critical 連鎖として即座に対処してください。",
                ]
            elif is_internet_facing:
                # Internet-facing with unmitigated LPE, but no current application RCE detected
                chain_lvl = ChainLevel.HIGH_ISOLATED
                deadline = "2週間以内（横展開・侵入リスク対策）"
                recs = [
                    f"ワークロード（{wl.name}）は外部到達可能（{eff_exposure.value}）ですが、現時点でアプリ層の既知侵入足場（RCE）は未検出です。",
                    f"ただし同一ノード（{wl.node_pool}）上に未解消 LPE（{k_entry.cve_id}）が存在するため、未知のゼロデイや迂回攻撃時に即座にノード root を奪取されるリスクがあります。",
                    "2 週間以内にパッチまたは緩和策を適用してください（定期メンテ先送り禁止）。",
                ]
            else:
                # Isolated / Internal node with unmitigated LPE (Dream Lateral Movement protection)
                chain_lvl = ChainLevel.HIGH_ISOLATED
                deadline = "2週間以内（横展開リスク対策・先送り禁止）"
                recs = [
                    f"ワークロード（{wl.name}）は内部限定ですが、同一ノード（{wl.node_pool}）上に未解消 LPE（{k_entry.cve_id}）が存在します。",
                    "Dream 事例（内部管理機侵害・LDAP奪取）の教訓に基づき、横展開攻撃を防ぐため 2 週間以内にパッチまたは緩和策を適用してください（定期メンテ放置禁止）。",
                ]

            if k_entry.auto_tier == 2 and chain_lvl == ChainLevel.CRITICAL_CHAIN:
                # ADR-021 decision 1: automatically suspected LPEs are capped at HIGH_UNVERIFIED.
                # They are promoted (to tier 1) when KEV / EPSS / CVSS signals change, or by --promote.
                chain_lvl = ChainLevel.HIGH_UNVERIFIED
                deadline = "2週間以内（自動照会による LPE の疑い・人による確認）"
                recs = [
                    f"【層2・自動推定】{k_entry.cve_id} は自動照会で見つかった LPE の疑いです（KEV 未掲載）。"
                    "足場のあるワークロードと同じカーネルにあるため、人が内容を確認し、LPE と判断した場合は "
                    f"`--promote {k_entry.cve_id} --promote-source <根拠の URL>` で層1 に昇格させ、Critical として扱ってください。",
                ] + recs

            foothold_desc = None
            if detected_footholds:
                foothold_desc = f"{detected_footholds[0]['cve']} ({detected_footholds[0]['basis']})"
            elif unclassifiable_high:
                foothold_desc = f"{unclassifiable_high[0]['cve']} ({unclassifiable_high[0]['basis']})"

            audit_results.append(
                ChainAuditItem(
                    workload_name=wl.name,
                    node_pool_id=wl.node_pool,
                    kernel_cve=k_entry.cve_id,
                    app_cve=detected_footholds[0]["cve"] if detected_footholds else (unclassifiable_high[0]["cve"] if unclassifiable_high else None),
                    chain_level=chain_lvl,
                    action_deadline=deadline,
                    foothold_detail=foothold_desc,
                    kernel_status=kernel_status,
                    mitigation_status=mitigation_status_str,
                    blast_radius=blast_radius_desc,
                    recommendations=recs,
                )
            )

    return audit_results


def _parse_yaml_fallback(text: str) -> Dict[str, Any]:
    """Lightweight fallback parser for simple YAML topologies when PyYAML is not installed."""
    import re
    lines = text.splitlines()
    data: Dict[str, Any] = {}
    current_key: Optional[str] = None
    current_list: Optional[List[Any]] = None
    current_dict: Optional[Dict[str, Any]] = None

    for raw_line in lines:
        line = raw_line.split("#")[0].rstrip()
        if not line.strip():
            continue

        indent = len(line) - len(line.lstrip())
        stripped = line.strip()

        # Top-level key: value or section
        if indent == 0 and ":" in stripped:
            k, v = stripped.split(":", 1)
            k = k.strip()
            v = v.strip().strip('"\'')
            if v:
                data[k] = v
                current_key = None
            else:
                data[k] = []
                current_key = k
                current_list = data[k]
                current_dict = None
        elif current_key and current_list is not None:
            if stripped.startswith("- "):
                # Start of list item (dict)
                item_content = stripped[2:].strip()
                current_dict = {}
                current_list.append(current_dict)
                if ":" in item_content:
                    dk, dv = item_content.split(":", 1)
                    dk = dk.strip()
                    dv = dv.strip().strip('"\'')
                    if dv.startswith("[") and dv.endswith("]"):
                        # Parse inline list: ["a", "b"]
                        items = [x.strip().strip('"\'') for x in dv[1:-1].split(",") if x.strip()]
                        current_dict[dk] = items
                    elif dv in ("true", "True"):
                        current_dict[dk] = True
                    elif dv in ("false", "False"):
                        current_dict[dk] = False
                    else:
                        current_dict[dk] = dv
            elif current_dict is not None and ":" in stripped:
                dk, dv = stripped.split(":", 1)
                dk = dk.strip()
                dv = dv.strip().strip('"\'')
                if dv.startswith("[") and dv.endswith("]"):
                    items = [x.strip().strip('"\'') for x in dv[1:-1].split(",") if x.strip()]
                    current_dict[dk] = items
                elif dv in ("true", "True"):
                    current_dict[dk] = True
                elif dv in ("false", "False"):
                    current_dict[dk] = False
                else:
                    current_dict[dk] = dv

    return data


def load_environment_definition(path_or_str: str) -> EnvironmentDefinition:
    """Load EnvironmentDefinition from a YAML or JSON file with flexible schema mapping."""
    import json
    from pathlib import Path

    p = Path(path_or_str)
    if not p.exists():
        raise FileNotFoundError(f"Environment definition file not found: {p}")

    with open(p, "r", encoding="utf-8") as f:
        content = f.read()

    data: Dict[str, Any] = {}
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml
            data = yaml.safe_load(content) or {}
        except ImportError:
            data = _parse_yaml_fallback(content)
    else:
        data = json.loads(content)

    env_name = data.get("environment") or data.get("environment_name") or "default"

    # Map node_pools
    raw_pools = data.get("node_pools", [])
    node_pools: List[NodePoolDefinition] = []
    for item in raw_pools:
        pool_id = item.get("pool_id") or item.get("id") or "default-pool"
        os_dist = item.get("os_distribution") or item.get("os_distro") or "ubuntu"
        os_rel = str(item.get("os_release") or item.get("release") or "")
        # Legacy key 'kernel_package' was read as BOTH name and version. Disambiguate it:
        # a value starting with a digit is a package version (e.g. '6.8.0-40.40'), otherwise a package name.
        legacy_pkg = item.get("kernel_package")
        legacy_is_version = isinstance(legacy_pkg, str) and legacy_pkg[:1].isdigit()
        k_pkg = (
            item.get("kernel_package_name")
            or (legacy_pkg if legacy_pkg and not legacy_is_version else None)
            or "linux-image-generic"
        )
        k_flavor = item.get("kernel_flavor") or item.get("flavor")
        pkg_ver = item.get("kernel_package_version") or (legacy_pkg if legacy_is_version else None)
        if isinstance(item.get("nodes"), list):
            expected_nodes: Optional[int] = len(item["nodes"])
        elif item.get("nodes_count") is not None:
            expected_nodes = int(item["nodes_count"])
        else:
            expected_nodes = None
        node_pools.append(
            NodePoolDefinition(
                pool_id=pool_id,
                os_distribution=os_dist,
                os_release=os_rel if os_rel else None,
                kernel_package_name=k_pkg,
                kernel_flavor=k_flavor,
                kernel_package_version=pkg_ver,
                kernel_release=item.get("kernel_release"),
                livepatch_active=item.get("livepatch_active", False),
                nodes_count=expected_nodes,
            )
        )

    # Map workloads
    raw_workloads = data.get("workloads", [])
    workloads: List[WorkloadDefinition] = []
    for item in raw_workloads:
        w_name = item.get("name") or item.get("id") or "unnamed-workload"
        w_pool = item.get("node_pool") or item.get("node_pool_id") or "default-pool"
        raw_exp = str(item.get("exposure", "unknown")).lower()
        if raw_exp == "internet_facing":
            exp = ExposureType.INTERNET_FACING
        elif raw_exp == "untrusted_code":
            exp = ExposureType.UNTRUSTED_CODE
        elif raw_exp == "internal_only":
            exp = ExposureType.INTERNAL_ONLY
        else:
            exp = ExposureType.UNKNOWN

        # Merge entry_cves, entry_vulnerabilities, and components
        c_list = item.get("components", [])
        if isinstance(c_list, str):
            c_list = [c_list]
        e_cves = item.get("entry_cves", [])
        if isinstance(e_cves, str):
            e_cves = [e_cves]

        workloads.append(
            WorkloadDefinition(
                name=w_name,
                exposure=exp,
                node_pool=w_pool,
                namespace=item.get("namespace", "default"),
                components=c_list,
                entry_cves=e_cves,
                sbom_path=item.get("sbom_path"),
            )
        )

    return EnvironmentDefinition(
        environment_name=env_name,
        node_pools=node_pools,
        workloads=workloads,
    )


def _aggregate_pool_telemetries(nodes: List[NodeTelemetry]) -> NodeTelemetry:
    """Aggregate multiple node telemetries belonging to the same pool under fail-safe rules.
    
    Rules (ADR-019 / v0.4.0):
    1. Mitigations: All nodes must be mitigated for the pool to be mitigated.
       - loaded_modules: UNION of all nodes (if loaded on any node, it is loaded in pool)
       - builtin_modules: UNION of all nodes (if builtin on any node, cannot disable)
       - modprobe_disabled_modules: INTERSECTION across all nodes (only disabled if disabled on ALL nodes)
       - active_services: UNION of all nodes (if IPsec active on any node, side effect blocks mitigation)
       - xfrm_active: True if True on ANY node
       - livepatch_modules: INTERSECTION across all nodes
    2. Kernel package version:
       - Select the oldest (minimum) version across nodes using compare_kernel_versions.
    3. Distribution / Flavor:
       - If all nodes share identical distro / flavor, use it; otherwise treat as mixed/indeterminate.
    """
    if not nodes:
        raise ValueError("Nodes list cannot be empty for pool aggregation")
    if len(nodes) == 1:
        return nodes[0]

    primary = nodes[0]
    pool_id = primary.pool_id

    # 1. Distro, Release, Flavor, Package consistency
    # Fail-safe principle: If ANY node has an unknown/missing distribution or release, or if nodes have differing distributions/releases,
    # the pool must be marked "unknown" / None so it never falsely inherits a patched status.
    any_unknown_distro = any(not n.os_distribution or n.os_distribution.strip().lower() in ("unknown", "") for n in nodes)
    unique_distros = list(set(n.os_distribution.strip().lower() for n in nodes if n.os_distribution and n.os_distribution.strip().lower() not in ("unknown", "")))
    if any_unknown_distro or len(unique_distros) != 1:
        eff_distro = "unknown"
    else:
        eff_distro = unique_distros[0]

    any_unknown_release = any(not n.os_release or n.os_release.strip().lower() in ("unknown", "") for n in nodes)
    unique_releases = list(set(n.os_release.strip() for n in nodes if n.os_release and n.os_release.strip().lower() not in ("unknown", "")))
    if any_unknown_release or len(unique_releases) != 1:
        eff_release = None
    else:
        eff_release = unique_releases[0]

    any_unknown_pkg = any(not n.kernel_package_name or n.kernel_package_name.strip().lower() in ("unknown", "") for n in nodes)
    unique_pkgs = list(set(n.kernel_package_name.strip() for n in nodes if n.kernel_package_name and n.kernel_package_name.strip().lower() not in ("unknown", "")))
    if any_unknown_pkg or len(unique_pkgs) != 1:
        eff_pkg = "unknown"
    else:
        eff_pkg = unique_pkgs[0]

    any_unknown_flavor = any(not n.kernel_flavor or n.kernel_flavor.strip().lower() in ("unknown", "") for n in nodes)
    unique_flavors = list(set(n.kernel_flavor.strip() for n in nodes if n.kernel_flavor and n.kernel_flavor.strip().lower() not in ("unknown", "")))
    if any_unknown_flavor or len(unique_flavors) != 1:
        eff_flavor = "unknown"
    else:
        eff_flavor = unique_flavors[0]

    # 2. Kernel Version: Oldest across all nodes in the pool
    # Fail-safe principle: If ANY node in the pool has an unknown or missing kernel package version,
    # the pool version MUST be None ("unknown"), forcing the evaluation to fail-safe to "該当の可能性あり".
    has_unknown_version = any(not n.kernel_package_version or n.kernel_package_version.strip().lower() in ("unknown", "") for n in nodes)
    oldest_version = None
    if not has_unknown_version:
        all_versions = [n.kernel_package_version.strip() for n in nodes if n.kernel_package_version]
        if all_versions:
            from functools import cmp_to_key
            from triage_agent.chain.version_parser import compare_kernel_versions
            def _cmp(a: str, b: str) -> int:
                res = compare_kernel_versions(eff_distro, a, b)
                if res is not None:
                    return res
                return 1 if a > b else (-1 if a < b else 0)
            sorted_vers = sorted(all_versions, key=cmp_to_key(_cmp))
            oldest_version = sorted_vers[0]

    # 3. Mitigations
    # Loaded modules: UNION (any node loading esp4 means pool is unmitigated)
    all_loaded = list(set(m for n in nodes for m in (n.loaded_modules or [])))
    
    # Builtin modules: UNION
    all_builtin = list(set(m for n in nodes for m in (n.builtin_modules or [])))

    # Modprobe disabled: INTERSECTION (only disabled if all nodes disabled)
    disabled_sets = [set(m.lower() for m in (n.modprobe_disabled_modules or [])) for n in nodes]
    common_disabled = list(set.intersection(*disabled_sets)) if disabled_sets else []

    # Active services: UNION
    all_services = list(set(s for n in nodes for s in (n.active_services or [])))

    # Xfrm active: ANY
    any_xfrm = any(n.xfrm_active for n in nodes)

    # Livepatch modules: INTERSECTION
    livepatch_sets = [set(n.livepatch_modules or []) for n in nodes]
    common_livepatch = list(set.intersection(*livepatch_sets)) if livepatch_sets else []

    # Running kernel identity: only kept when every node agrees (otherwise the pool is mixed -> unknown).
    def _same(values):
        vals = [v for v in values]
        if any(v is None or str(v).strip() == "" for v in vals):
            return None
        return vals[0] if len(set(vals)) == 1 else None

    eff_epoch = _same([n.kernel_package_epoch for n in nodes])
    eff_binary = _same([n.kernel_binary_package for n in nodes])
    lp_sets = [set(n.livepatch_packages or []) for n in nodes]
    common_lp_packages = sorted(set.intersection(*lp_sets)) if lp_sets else []

    # Collection provenance: oldest timestamp wins; any unknown timestamp makes the pool's freshness unknown.
    collected = [n.oldest_collected_at for n in nodes]
    oldest_collected = None if any(c is None for c in collected) else min(collected)
    all_node_ids = [nid for n in nodes for nid in (n.node_ids or [])]
    expected_counts = [n.expected_nodes_count for n in nodes if n.expected_nodes_count is not None]

    return NodeTelemetry(
        kernel_package_epoch=eff_epoch,
        kernel_binary_package=eff_binary,
        livepatch_packages=common_lp_packages,
        node_ids=all_node_ids,
        observed_nodes_count=sum(n.observed_nodes_count for n in nodes),
        oldest_collected_at=oldest_collected,
        expected_nodes_count=max(expected_counts) if expected_counts else None,
        pool_id=pool_id,
        os_distribution=eff_distro,
        os_release=eff_release,
        kernel_package_name=eff_pkg,
        kernel_flavor=eff_flavor,
        kernel_package_version=oldest_version,
        kernel_release=primary.kernel_release,
        loaded_modules=all_loaded,
        builtin_modules=all_builtin,
        modprobe_disabled_modules=common_disabled,
        active_services=all_services,
        xfrm_active=any_xfrm,
        livepatch_modules=common_livepatch,
    )


# Placeholder node_id emitted by the v0.4 collector for every host; cannot be used to de-duplicate.
_LEGACY_ANONYMOUS_NODE_IDS = {"", "anonymized-node", "unknown-node", "unidentified-node"}
COLLECTION_MANIFEST_KIND = "collection_manifest"
DEFAULT_TELEMETRY_MAX_AGE_DAYS = 7


def _parse_iso_utc(value: Any) -> Optional[datetime]:
    """Parse an ISO 8601 timestamp (e.g. '2026-11-02T01:23:45Z') into an aware UTC datetime."""
    if not value or not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _parse_disabled_modules(modprobe_lines: List[str]) -> List[str]:
    """Extract module names disabled by modprobe config lines.

    Recognized forms (same semantics as v0.4, but no longer limited to esp4/esp6/rxrpc):
      - 'install <module> /bin/false'
      - 'blacklist <module>'
    """
    disabled: List[str] = []
    for line in modprobe_lines or []:
        tokens = str(line).split()
        if len(tokens) < 2:
            continue
        directive, module = tokens[0].lower(), tokens[1].lower()
        if directive == "blacklist" or (directive == "install" and "/bin/false" in line):
            if module not in disabled:
                disabled.append(module)
    return disabled


def load_node_telemetries_with_report(
    path_or_str: str,
    max_age_days: Optional[int] = DEFAULT_TELEMETRY_MAX_AGE_DAYS,
    now: Optional[datetime] = None,
) -> Tuple[Dict[str, NodeTelemetry], List[TelemetryLoadIssue]]:
    """Load node telemetry files (a file or a directory tree) and aggregate them per pool.

    ADR-021 decision 4 / 5:
    - Records without a pool_id are rejected (v0.4 silently fell back to node_id, which merged every
      anonymized host into one bogus pool).
    - Records older than ``max_age_days`` are excluded from the evidence (None or 0 disables the check).
    - Records with the same stable node_id are de-duplicated (the newest wins).
    - ``collection_manifest`` JSON files declare the expected node set of a pool.
    Returns (telemetry_by_pool, issues). Issues are never silently dropped.
    """
    p = Path(path_or_str)
    issues: List[TelemetryLoadIssue] = []
    if not p.exists():
        issues.append(TelemetryLoadIssue(severity="warning", source=str(p), message="テレメトリのパスが存在しません"))
        return {}, issues

    now_utc = now or datetime.now(timezone.utc)
    files = [p] if p.is_file() else sorted(p.rglob("*.json"))

    # pool_id -> node key -> (collected_at datetime or None, telemetry)
    records: Dict[str, Dict[str, Tuple[Optional[datetime], NodeTelemetry]]] = {}
    manifest_expected: Dict[str, int] = {}

    for fpath in files:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            issues.append(TelemetryLoadIssue(severity="warning", source=str(fpath), message=f"JSON として読めないため除外しました（{e}）"))
            continue
        if not isinstance(data, dict):
            issues.append(TelemetryLoadIssue(severity="warning", source=str(fpath), message="形式が不正なため除外しました（JSON オブジェクトではありません）"))
            continue

        # Collection manifest: declares which nodes the collector targeted for a pool.
        if data.get("kind") == COLLECTION_MANIFEST_KIND:
            m_pool = data.get("pool_id")
            targets = data.get("targets")
            if not m_pool or not isinstance(targets, list):
                issues.append(TelemetryLoadIssue(severity="warning", source=str(fpath), message="収集マニフェストに pool_id または targets がないため無視しました"))
                continue
            manifest_expected[m_pool] = max(manifest_expected.get(m_pool, 0), len(set(map(str, targets))))
            failed = [str(t) for t in (data.get("failed") or []) + (data.get("unreachable") or [])]
            if failed:
                issues.append(TelemetryLoadIssue(
                    severity="warning", source=str(fpath),
                    message=f"プール {m_pool}: 収集に失敗した、または届かなかったノードが {len(failed)} 台あります",
                ))
            continue

        pool_id = data.get("pool_id") or data.get("node_pool_id")
        if not pool_id:
            issues.append(TelemetryLoadIssue(
                severity="warning", source=str(fpath),
                message="pool_id がないため除外しました（収集スクリプトに -p <プールID> を指定してください）",
            ))
            continue

        collected_at = _parse_iso_utc(data.get("collected_at"))
        if collected_at is not None and max_age_days:
            age_days = (now_utc - collected_at).total_seconds() / 86400
            if age_days > max_age_days:
                issues.append(TelemetryLoadIssue(
                    severity="warning", source=str(fpath),
                    message=f"プール {pool_id}: 収集から {age_days:.1f} 日経過しており、許容日数（{max_age_days} 日）を超えるため根拠から除外しました",
                ))
                continue
        elif collected_at is None:
            issues.append(TelemetryLoadIssue(
                severity="info", source=str(fpath),
                message=f"プール {pool_id}: collected_at がないため、鮮度を確認できません",
            ))

        raw_node_id = str(data.get("node_id") or "").strip()
        is_anonymous = raw_node_id.lower() in _LEGACY_ANONYMOUS_NODE_IDS
        # Legacy anonymized records cannot be de-duplicated; key them by file so each counts once.
        node_key = f"file:{fpath}" if is_anonymous else raw_node_id

        livepatch = data.get("livepatch_modules")
        if not isinstance(livepatch, list):
            livepatch = []

        telemetry = NodeTelemetry(
            pool_id=pool_id,
            os_distribution=data.get("os_distribution") or data.get("os_distro"),
            os_release=str(data.get("os_release")) if data.get("os_release") else None,
            kernel_package_name=data.get("kernel_package_name") or data.get("package_name"),
            kernel_flavor=data.get("kernel_flavor") or data.get("flavor"),
            kernel_package_version=data.get("distro_package_version") or data.get("kernel_package_version"),
            kernel_release=data.get("kernel_release"),
            loaded_modules=data.get("loaded_modules", []),
            builtin_modules=data.get("builtin_modules", []),
            modprobe_disabled_modules=(
                data.get("modprobe_disabled_modules")
                if isinstance(data.get("modprobe_disabled_modules"), list)
                else _parse_disabled_modules(data.get("modprobe_config", []))
            ),
            active_services=data.get("active_services", []),
            xfrm_active=bool(data.get("xfrm_active", False)),
            livepatch_modules=livepatch,
            kernel_package_epoch=(str(data.get("kernel_package_epoch")).strip() or None) if data.get("kernel_package_epoch") not in (None, "") else None,
            kernel_binary_package=data.get("kernel_binary_package") or None,
            livepatch_packages=[str(x) for x in data.get("livepatch_packages", []) if x] if isinstance(data.get("livepatch_packages"), list) else [],
            node_ids=[] if is_anonymous else [raw_node_id],
            observed_nodes_count=1,
            oldest_collected_at=collected_at.strftime("%Y-%m-%dT%H:%M:%SZ") if collected_at else None,
        )

        pool_records = records.setdefault(pool_id, {})
        previous = pool_records.get(node_key)
        if previous is not None:
            prev_at = previous[0]
            issues.append(TelemetryLoadIssue(
                severity="info", source=str(fpath),
                message=f"プール {pool_id}: 同じノード（{raw_node_id}）のテレメトリが複数あるため、新しい方を採用しました",
            ))
            # Keep the newer record; on unknown timestamps keep the first one seen (deterministic by sorted path).
            if prev_at is None or collected_at is None or collected_at <= prev_at:
                continue
        pool_records[node_key] = (collected_at, telemetry)

    telemetries: Dict[str, NodeTelemetry] = {}
    for pool_id, pool_records in records.items():
        nodes = [t for _, t in pool_records.values()]
        agg = _aggregate_pool_telemetries(nodes)
        if pool_id in manifest_expected:
            agg.expected_nodes_count = manifest_expected[pool_id]
        telemetries[pool_id] = agg

    for m_pool in manifest_expected:
        if m_pool not in telemetries:
            issues.append(TelemetryLoadIssue(
                severity="warning", source=m_pool,
                message=f"プール {m_pool}: 収集マニフェストはありますが、有効なテレメトリが 1 件もありません",
            ))

    return telemetries, issues


def load_node_telemetries(
    path_or_str: str,
    max_age_days: Optional[int] = None,
) -> Dict[str, NodeTelemetry]:
    """Load NodeTelemetry objects from a JSON file or a directory of JSON files.

    Backward-compatible wrapper: freshness is not enforced unless ``max_age_days`` is given.
    Use ``load_node_telemetries_with_report`` to also receive the load issues.
    """
    telemetries, _ = load_node_telemetries_with_report(path_or_str, max_age_days=max_age_days)
    return telemetries


def build_pool_coverage(
    environment: EnvironmentDefinition,
    telemetries: Optional[Dict[str, NodeTelemetry]],
) -> Dict[str, PoolCoverage]:
    """Compute per-pool telemetry coverage (observed vs expected nodes) for every known pool."""
    telemetry_map = telemetries or {}
    pool_ids: List[str] = [p.pool_id for p in environment.node_pools]
    for wl in environment.workloads:
        if wl.node_pool not in pool_ids:
            pool_ids.append(wl.node_pool)
    known_ids = set(pool_ids)
    for tid in telemetry_map:
        if tid not in pool_ids:
            pool_ids.append(tid)

    pool_defs = {p.pool_id: p for p in environment.node_pools}
    coverage: Dict[str, PoolCoverage] = {}
    for pid in pool_ids:
        tel = telemetry_map.get(pid)
        pool_def = pool_defs.get(pid)
        if tel is not None and tel.expected_nodes_count is not None:
            expected, source = tel.expected_nodes_count, "manifest"
        elif pool_def is not None and pool_def.nodes_count is not None:
            expected, source = pool_def.nodes_count, "environments.yaml"
        else:
            expected, source = None, "unknown"
        coverage[pid] = PoolCoverage(
            pool_id=pid,
            expected_nodes=expected,
            expected_source=source,
            observed_nodes=tel.observed_nodes_count if tel else 0,
            oldest_collected_at=tel.oldest_collected_at if tel else None,
            has_telemetry=tel is not None,
            in_environment=pid in known_ids,
        )
    return coverage


def find_pool_mismatches(
    environment: EnvironmentDefinition,
    telemetries: Optional[Dict[str, NodeTelemetry]],
) -> List[TelemetryLoadIssue]:
    """Report pools present only in telemetry, and workload pools without any telemetry."""
    telemetry_ids = set((telemetries or {}).keys())
    defined_ids = {p.pool_id for p in environment.node_pools}
    workload_pools = {wl.node_pool for wl in environment.workloads}
    issues: List[TelemetryLoadIssue] = []
    for tid in sorted(telemetry_ids - defined_ids - workload_pools):
        issues.append(TelemetryLoadIssue(
            severity="warning", source=tid,
            message=f"プール {tid}: テレメトリはありますが環境定義にないため、評価に使われていません（-p の値と environments.yaml の id を確認してください）",
        ))
    if telemetry_ids:
        for pid in sorted(workload_pools - telemetry_ids):
            issues.append(TelemetryLoadIssue(
                severity="warning", source=pid,
                message=f"プール {pid}: ワークロードが配置されていますが実機テレメトリがありません（構成定義の値で評価します）",
            ))
    return issues


def _build_finding(
    raw_id: str,
    base: Optional[Dict[str, Any]] = None,
    feed_results: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Normalize finding CVE/GHSA ID and enrich with threat feed results (CISA KEV, OSV vector/CWE/summary, EPSS)."""
    base = dict(base) if base else {}
    m = re.search(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[\w-]+)\b", raw_id, re.IGNORECASE)
    cid = m.group(1).upper() if m else raw_id.strip().upper()
    f = {**base, "cve_id": cid}
    fr = (feed_results or {}).get(cid)
    if fr:
        if getattr(fr, "in_cisa_kev", None) is not None:
            f["cisa_kev"] = fr.in_cisa_kev
        if getattr(fr, "epss_score", None) is not None:
            f["epss_score"] = fr.epss_score
        f["cvss_vector"] = f.get("cvss_vector") or getattr(fr, "cvss_vector", None)
        f["cwe_list"] = f.get("cwe_list") or getattr(fr, "cwe_list", None)
        f["summary"] = getattr(fr, "summary", None) or f.get("summary")
    return f


def run_exploit_chain_audit(
    environment: EnvironmentDefinition,
    kernel_vulnerabilities: List[KernelVulnerabilityEntry],
    telemetries: Optional[Dict[str, NodeTelemetry]] = None,
    evaluation_date: Optional[str] = None,
    feed_results: Optional[Dict[str, Any]] = None,
    triage_report: Optional[Any] = None,
) -> List[ChainAuditItem]:
    """Execute end-to-end exploit chain audit with full pipeline integration.
    
    Upholds 'Never present fabricated data as truth': No hardcoded CVE lists.
    Resolves application findings from triage report notices, workload SBOMs, or explicit entries.
    """
    app_findings: Dict[str, List[Dict[str, Any]]] = {}

    # 1. Map existing findings from TriageReport (from upstream OSV / Researcher pipeline)
    pipeline_findings_by_comp: Dict[str, List[Dict[str, Any]]] = {}
    if triage_report and hasattr(triage_report, "notices"):
        for notice in triage_report.notices:
            c_name = (notice.component_name or notice.product_name or "").lower()
            for cp in notice.check_points:
                raw_target = cp.target_or_cve
                base_info = {
                    "cvss_score": float(cp.cvss) if cp.cvss and cp.cvss.replace(".", "", 1).isdigit() else None,
                    "cvss_vector": getattr(cp, "cvss_vector", None),
                    "summary": f"{notice.conclusion or ''} {cp.content_summary or ''}".strip() or None,
                    "cwe_list": getattr(cp, "cwe_list", None),
                }
                item_finding = _build_finding(raw_target, base_info, feed_results)
                pipeline_findings_by_comp.setdefault(c_name, []).append(item_finding)

    # 2. Build findings for each workload
    for wl in environment.workloads:
        findings: List[Dict[str, Any]] = []

        # A. Pull findings matched by component names from pipeline
        for comp in wl.components:
            comp_lower = comp.strip().lower()
            if comp_lower in pipeline_findings_by_comp:
                for f_item in pipeline_findings_by_comp[comp_lower]:
                    findings.append(_build_finding(f_item.get("cve_id", ""), f_item, feed_results))

        # B. Pull explicit entry CVEs
        all_entry_cves = list(wl.entry_cves)
        for c in wl.components:
            if c.upper().startswith("CVE-") or c.upper().startswith("GHSA-"):
                all_entry_cves.append(c)

        for cve in all_entry_cves:
            findings.append(_build_finding(cve, {}, feed_results))

        # C. Inspect workload SBOM if provided
        if wl.sbom_path:
            sbom_p = Path(wl.sbom_path)
            if not sbom_p.exists():
                findings.append({
                    "cve_id": "SBOM-MISSING",
                    "is_unclassifiable": True,
                    "basis": f"指定されたSBOMファイルが存在しません（{wl.sbom_path}）: 判定不能・要確認",
                })
            else:
                try:
                    with open(sbom_p, "r", encoding="utf-8") as f:
                        sbom_data = json.load(f)
                        # Read components from CycloneDX or Syft
                        comps = sbom_data.get("components") or sbom_data.get("artifacts") or []
                        for comp_item in comps:
                            cn = (comp_item.get("name") or "").lower()
                            if cn in pipeline_findings_by_comp:
                                for f_item in pipeline_findings_by_comp[cn]:
                                    findings.append(_build_finding(f_item.get("cve_id", ""), f_item, feed_results))
                except Exception as e:
                    findings.append({
                        "cve_id": "SBOM-CORRUPT",
                        "is_unclassifiable": True,
                        "basis": f"SBOMファイルの読み込みに失敗しました（{wl.sbom_path}: {e}）: 判定不能・要確認",
                    })

        app_findings[wl.name] = findings

    return audit_exploit_chains(
        environment=environment,
        kernel_vulnerabilities=kernel_vulnerabilities,
        app_findings_by_workload=app_findings,
        telemetry_by_pool=telemetries,
        evaluation_date=evaluation_date,
    )


def format_chain_audit_markdown(
    items: List[ChainAuditItem],
    environment_name: str = "Production",
    feed_results: Optional[Dict[str, Any]] = None,
    coverage: Optional[Dict[str, PoolCoverage]] = None,
    load_issues: Optional[List[TelemetryLoadIssue]] = None,
    kernel_auto: Optional[Any] = None,
) -> str:
    """Format Exploit Chain audit results into enterprise-ready Markdown report."""
    lines = [
        f"# 🚨 Exploit Chain & Linux Kernel Exposure Audit Report ({environment_name})",
        "",
        "> ℹ️ **【ADR-019 / v0.4.0 連鎖エクスプロイト判定標準】**  ",
        "> 単一のCVSS値にとらわれず、「外部露出したアプリ層の侵入足場（RCE）」×「同一共有カーネル上のOS権限昇格（LPE）」の結合リスク、",
        "> および同一ノードに同居する別マイクロサービスへの水平展開（Blast Radius）を網羅的に評価します。",
        "",
    ]

    # Disclose feed failure status ("調べなかったものを隠さない" principle)
    if feed_results:
        kev_err_count = sum(1 for fr in feed_results.values() if "KEV" in (getattr(fr, "error", "") or ""))
        osv_err_count = sum(1 for fr in feed_results.values() if "OSV" in (getattr(fr, "error", "") or ""))
        epss_err_count = sum(1 for fr in feed_results.values() if "EPSS" in (getattr(fr, "error", "") or ""))
        if kev_err_count or osv_err_count or epss_err_count:
            err_details = []
            if kev_err_count:
                err_details.append(f"KEV 取得失敗: {kev_err_count} 件")
            if osv_err_count:
                err_details.append(f"OSV 取得失敗: {osv_err_count} 件")
            if epss_err_count:
                err_details.append(f"EPSS 取得失敗: {epss_err_count} 件")
            lines.extend([
                "> ⚠️ **【フィード同期ステータス・調査不全の開示】**（「調べなかったものを隠さない」原則）  ",
                f"> 外部脅威インテリジェンスフィード照会で障害を検知しました: {', '.join(err_details)}。  ",
                "> ※ データ取得に失敗した脆弱性は安全側に倒し「足場分類不能・要人手確認」として扱っています。",
                "",
            ])

    if coverage:
        lines.extend([
            "## 🛰️ 実機テレメトリの収集状況",
            "",
            "> 期待ノード数に満たないプールでは、未収集のノードに古いカーネルが残っている可能性があるため、",
            "> 「修正済み（SAFE）」「緩和済み」と判定しません（ADR-021）。",
            "",
            "| ノードプール | 収集台数 | 期待ノード数の出典 | 最も古い収集日時 (UTC) | 状態 |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        source_label = {"manifest": "収集マニフェスト", "environments.yaml": "環境定義", "unknown": "不明"}
        for pid in sorted(coverage):
            cov = coverage[pid]
            if not cov.in_environment:
                state = "⚠️ 環境定義にないプール（評価に使われていません）"
            elif not cov.has_telemetry:
                state = "ℹ️ 実機テレメトリなし（構成定義の値で評価）"
            elif cov.is_known_incomplete:
                state = "⚠️ 一部のノードのみ（SAFE / 緩和済みを出しません）"
            elif cov.expected_nodes is None:
                state = "❓ 期待ノード数不明（環境定義に nodes を記載してください）"
            else:
                state = "✅ 全ノード収集済み"
            lines.append(
                f"| `{pid}` | {cov.describe()} | {source_label.get(cov.expected_source, cov.expected_source)} "
                f"| {cov.oldest_collected_at or '不明'} | {state} |"
            )
        lines.append("")

    warn_issues = [i for i in (load_issues or []) if i.severity == "warning"]
    if warn_issues:
        lines.extend([
            "### ⚠️ テレメトリ読み込み時の注意（除外・不一致）",
            "",
        ])
        for issue in warn_issues:
            suffix = f"（`{Path(issue.source).name}`）" if issue.source.endswith(".json") else ""
            lines.append(f"- {issue.message}{suffix}")
        lines.append("")

    if kernel_auto is not None:
        lines.extend(_format_kernel_auto_section(kernel_auto))

    lines.extend([
        "## 📊 監査サマリ・総合判定",
        "",
        "| ワークロード | ノードプール | カーネルCVE | 深刻度・連鎖判定 | 対応期限 | 影響範囲（水平展開リスク） |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ])

    for item in items:
        badge = item.chain_level.value
        if item.chain_level == ChainLevel.CRITICAL_CHAIN:
            badge = "🚨 **CRITICAL_CHAIN**"
        elif item.chain_level == ChainLevel.HIGH_ISOLATED:
            badge = "⚠️ **HIGH_ISOLATED**"
        elif item.chain_level == ChainLevel.HIGH_UNVERIFIED:
            badge = "❓ **HIGH_UNVERIFIED**"
        elif item.chain_level == ChainLevel.MITIGATED_NEEDS_PATCH:
            badge = "🛡️ **MITIGATED**"
        else:
            badge = "✅ **SAFE**"

        blast = ", ".join(item.blast_radius) if item.blast_radius else "なし"
        lines.append(
            f"| `{item.workload_name}` | `{item.node_pool_id}` | `{item.kernel_cve}` | {badge} | {item.action_deadline} | {blast} |"
        )

    lines.extend([
        "",
        "## 📝 詳細評価および推奨アクション",
        "",
    ])

    for item in items:
        lines.extend([
            f"### ワークロード: {item.workload_name} (ノード: {item.node_pool_id})",
            f"- **対象カーネル脆弱性**: `{item.kernel_cve}` ({item.kernel_status})",
            f"- **緩和策状態**: {item.mitigation_status}",
            f"- **侵入足場（RCE）評価**: {item.foothold_detail or '明示的な足場なし'}",
            f"- **対応期限**: **{item.action_deadline}**",
            f"- **同居ワークロード（影響半径）**: {', '.join(item.blast_radius) if item.blast_radius else 'なし'}",
            "",
            "**推奨アクション:**",
        ])
        for rec in item.recommendations:
            lines.append(f"- {rec}")
        lines.append("")

    return "\n".join(lines)



def _format_kernel_auto_section(ka: Any) -> List[str]:
    """Report section for the automatic kernel advisory lookup (ADR-021)."""
    status_label = {
        "ok": "✅ 照会済み",
        "no_adapter": "ℹ️ 照会元なし（手動台帳のみ）",
        "unidentified": "❓ 系統を特定できない",
        "source_error": "⚠️ 照会不全（未修正なしとは扱いません）",
    }
    lines = [
        "## 🧭 カーネル脆弱性の自動照会（横展開）",
        "",
        "> 手動台帳に載っていないカーネル脆弱性を、実機のカーネル版とディストリの勧告から引いています（ADR-021）。  ",
        f"> 層1 = CISA KEV 掲載または昇格、層2 = EPSS {ka.epss_threshold:g} 以上またはディストリ重大度 critical（LPE の疑い・上限は HIGH_UNVERIFIED）、層3 = その他（件数のみ）。",
        "",
    ]
    lines.extend(_format_kernel_history_lines(ka))
    info = getattr(ka, "kev_catalog_info", None)
    if info:
        lines.extend([
            f"> 使用した CISA KEV カタログ: 版 `{info.get('catalogVersion')}`（公開 {info.get('dateReleased')}・{info.get('count')} 件）",
            "",
        ])
    if not ka.kev_available or not ka.epss_available:
        missing = [n for n, ok in (("CISA KEV", ka.kev_available), ("EPSS", ka.epss_available)) if not ok]
        lines.extend([
            f"> ⚠️ **{'・'.join(missing)} を取得できなかったため、層の判定が不完全です。** 層3 の中に、本来は層1・2 のものが含まれている可能性があります。",
            "",
        ])
    lines.extend([
        "| ノードプール | 系統 | 現行の版 | 層1 | 層2 | 層3 | うち修正版なし | livepatch で解消 | 層1・2 を解消する版 | 状態 |",
        "| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | :--- | :--- |",
    ])
    for pid in sorted(ka.pools):
        p = ka.pools[pid]
        if p.status == "ok":
            counts = [str(p.tier_counts.get(t, 0)) for t in (1, 2, 3)]
            lp = str(p.livepatched)
            nofix = str(p.no_fix_available) + ("（層3 は未取得）" if getattr(p, "details_not_fetched", 0) else "")
            top_no_fix = any(x.tier in (1, 2) and not x.fixed_evr for x in p.exposed)
            if p.upgrade_target:
                target = f"`{p.upgrade_target}`" + ("（修正版のないものを除く）" if top_no_fix else "")
            else:
                target = "—（修正版なし）" if top_no_fix else "—（層1・2 なし）"
        else:
            counts, lp, target, nofix = ["—", "—", "—"], "—", "—", "—"
        state = status_label.get(p.status, p.status)
        if p.reason:
            state += f"：{p.reason}"
        if p.status == "ok" and not p.grounded_in_telemetry:
            state += "（構成定義上の版で照会）"
        if getattr(p, "coverage_note", None):
            state += f" ⚠️ {p.coverage_note}"
        lines.append(
            f"| `{pid}` | {f'`{p.lineage}`' if p.lineage else '—'} | {f'`{p.installed}`' if p.installed else '—'} "
            f"| {counts[0]} | {counts[1]} | {counts[2]} | {nofix} | {lp} | {target} | {state} |"
        )
    lines.append("")
    for pid in sorted(ka.pools):
        p = ka.pools[pid]
        top = [x for x in p.exposed if x.tier in (1, 2)]
        if p.status != "ok" or not top:
            continue
        shown = top[:15]
        lines.extend([
            f"### {pid}: 層1・層2 の脆弱性（{len(top)} 件中 {len(shown)} 件を表示）",
            "",
            "| CVE | 層 | KEV | EPSS | CVSS | ディストリ重大度 | 修正版 | 勧告 |",
            "| :--- | :--- | :---: | ---: | ---: | :--- | :--- | :--- |",
        ])
        for x in shown:
            epss = f"{x.epss:.3f}" if x.epss is not None else "—"
            adv = ", ".join(x.advisory_ids[:2]) + (" …" if len(x.advisory_ids) > 2 else "")
            link = f"[{adv}]({x.source_url})" if x.source_url.startswith("http") else adv
            fixed = f"`{x.fixed_evr}`" if x.fixed_evr else "**修正版なし**"
            promo = getattr(x, "promotion", None)
            tier = f"{x.tier}（昇格: {promo.label}）" if promo else str(x.tier)
            cvss = f"{x.cvss_score:g}" if getattr(x, "cvss_score", None) is not None else "—"
            lines.append(f"| `{x.cve_id}` | {tier} | {'✓' if x.in_kev else ''} | {epss} | {cvss} | {x.severity} | {fixed} | {link} |")
        if p.tier_counts.get(2, 0) > p.tier2_itemized:
            lines.append("")
            lines.append(
                f"> 層2 のうち上位 {p.tier2_itemized} 件を連鎖評価に含めています。残り {p.tier_counts[2] - p.tier2_itemized} 件も "
                f"`{p.upgrade_target}` 以上に更新すれば解消します。"
            )
        lines.append("")
    if ka.errors:
        lines.extend(["### ⚠️ 照会時の注意（調べられなかったものを隠さない）", ""])
        lines.extend(f"- {e}" for e in ka.errors)
        lines.append("")
    return lines


def _format_kernel_history_lines(ka: Any) -> List[str]:
    """Run-to-run changes and promotions (ADR-021 decision 2)."""
    lines: List[str] = []
    rules = [f"EPSS が前回から {getattr(ka, 'epss_jump', 0.15):g} 以上上昇", "人による `--promote`（出典 URL 必須）"]
    if getattr(ka, "cvss_available", False):
        rules.insert(1, "既存の CVSS が LPE 型の 7.0 以上へ引き上げ")
    if getattr(ka, "cvss_available", False):
        cvss_note = f"CVSS は {getattr(ka, 'cvss_source', None) or '登録された照会元'} の採点です（照会元により値が異なることがあります）。"
    elif getattr(ka, "cvss_source", None):
        cvss_note = f"CVSS（{ka.cvss_source}）を今回は取得できなかったため、CVSS の引き上げは判定していません。"
    else:
        cvss_note = "CVSS の照会元が登録されていないため、CVSS の引き上げは判定していません。"
    lines.append(f"> 昇格の規則: {'、'.join(rules)}。昇格したものは、露出が続く限り層1 のまま扱います。{cvss_note}")
    lines.append("")
    previous = getattr(ka, "previous_taken_at", None)
    changes = getattr(ka, "changes", {}) or {}
    if previous is None:
        lines.extend([
            "> 前回のスナップショットがないため、今回の結果が比較の基準になります。次回の実行から、変化と昇格を判定します。",
            "",
        ])
    else:
        lines.extend([f"### 前回の実行（{previous}）からの変化", ""])
        rows = []
        for pid in sorted(changes):
            c = changes[pid]
            if not c.baseline:
                rows.append(f"| `{pid}` | — | — | — | {'；'.join(c.notes)} |")
                continue
            def _ids(items, limit=5):
                if not items:
                    return "0"
                head = ", ".join(f"`{i}`" for i in items[:limit])
                return f"{len(items)}（{head}{' …' if len(items) > limit else ''}）"
            rows.append(f"| `{pid}` | {_ids(c.new_tier1)} | {_ids(c.new_tier2, 3)} | {_ids(c.resolved, 3)} | {'；'.join(c.notes) or '—'} |")
        if rows:
            lines.extend([
                "| ノードプール | 新たに層1 | 新たに層2 | 解消（層1・2） | 備考 |",
                "| :--- | :--- | :--- | :--- | :--- |",
            ])
            lines.extend(rows)
            lines.append("")
    promotions = getattr(ka, "promotions", {}) or {}
    if promotions:
        pools_by_cve: Dict[str, List[str]] = {}
        for pid, p in ka.pools.items():
            for x in p.exposed:
                pools_by_cve.setdefault(x.cve_id, []).append(pid)
        lines.extend([
            f"### 昇格して層1 として扱っている脆弱性（{len(promotions)} 件）",
            "",
            "| CVE | 規則 | 内容 | 検知 | 該当プール |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for cve in sorted(promotions, key=lambda c: (not promotions[c].new, c)):
            p = promotions[cve]
            detail = p.detail + (f"（[出典]({p.source_url})）" if p.source_url else "")
            when = (p.detected_at or "")[:10] + ("・**今回**" if p.new else "")
            lines.append(f"| `{cve}` | {p.label} | {detail} | {when} | {', '.join(f'`{x}`' for x in sorted(pools_by_cve.get(cve, [])))} |")
        lines.append("")
    manual = getattr(ka, "manual_promotions", {}) or {}
    idle = sorted(c for c in manual if c not in promotions)
    if idle:
        lines.extend([
            f"> 手動昇格の台帳にあるが、今回どのプールにも露出していないもの: {', '.join(f'`{c}`' for c in idle)}"
            "（修正済み、または KEV 掲載で層1）。不要になったら `--unpromote` で外せます。",
            "",
        ])
    return lines
