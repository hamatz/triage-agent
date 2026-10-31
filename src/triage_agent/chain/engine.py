"""Exploit Chain Triaging Engine (v0.4.0 / ADR-019).

Evaluates systemic co-location risks between application-layer footholds (RCEs) and
OS/Kernel-layer Privilege Escalation (LPE) vulnerabilities across shared-kernel node pools.
"""

from datetime import date
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
        candidates.append(f"{d_clean}:{rel_clean}")
    candidates.append(f"{d_clean}:{flavor}")
    
    # Generic keys only allowed if node is genuinely running the standard/generic kernel
    if flavor == "linux":
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
            pool_telemetry = telemetry_map.get(pool.pool_id)
            
            # Resolve OS and kernel flavor from telemetry or pool definition
            eff_distro = (pool_telemetry.os_distribution if pool_telemetry and pool_telemetry.os_distribution else pool.os_distribution) or "ubuntu"
            eff_release = pool_telemetry.os_release if pool_telemetry and pool_telemetry.os_release else pool.os_release
            eff_pkg = (pool_telemetry.kernel_package_name if pool_telemetry and pool_telemetry.kernel_package_name else pool.kernel_package_name) or "linux"
            eff_flavor = pool_telemetry.kernel_flavor if pool_telemetry and pool_telemetry.kernel_flavor else pool.kernel_flavor
            eff_version = (pool_telemetry.kernel_package_version if pool_telemetry and pool_telemetry.kernel_package_version else pool.kernel_package_version)

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

            # Fail-safe: Missing version, unknown flavor, or indeterminate comparison defaults to vulnerable!
            if is_vuln is None:
                is_vuln = True
                kernel_status = f"要確認 (該当の可能性あり⚠️: {match_exp} / 現行: {eff_version or '未確定'})"
            elif is_vuln is False:
                kernel_status = f"NO (修正済み: {k_entry.cve_id}・パッケージ版 {eff_version}・{today_str}確認・{match_exp})"
            else:
                kernel_status = f"YES (脆弱性該当: {k_entry.cve_id}・パッケージ版 {eff_version} < 修正版 {range_info.fixed_version}・{match_exp})"

            if not is_vuln:
                # Kernel is definitively patched for this specific CVE
                audit_results.append(
                    ChainAuditItem(
                        workload_name=wl.name,
                        node_pool_id=wl.node_pool,
                        kernel_cve=k_entry.cve_id,
                        app_cve=detected_footholds[0]["cve"] if detected_footholds else None,
                        chain_level=ChainLevel.SAFE,
                        action_deadline="対応不要（カーネルパッチ適用確認済み）",
                        foothold_detail=None,
                        kernel_status=kernel_status,
                        mitigation_status="緩和策不要（修正済み）",
                        blast_radius=blast_radius_desc,
                        recommendations=["現行カーネルパッケージを維持し、次期定期更新で最新状態を継続してください。"],
                    )
                )
                continue

            # Step 2: Mitigation Check (Q2)
            mitigation_res = evaluate_kernel_mitigation(
                cve_id=k_entry.cve_id,
                telemetry=pool_telemetry,
            )

            is_mitigated = mitigation_res["is_mitigated"]
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
        k_pkg = item.get("kernel_package_name") or item.get("kernel_package") or "linux-image-generic"
        k_flavor = item.get("kernel_flavor") or item.get("flavor")
        pkg_ver = item.get("kernel_package_version") or item.get("kernel_package")
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
                nodes_count=len(item.get("nodes", [])) if "nodes" in item else item.get("nodes_count", 1),
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


def load_node_telemetries(path_or_str: str) -> Dict[str, NodeTelemetry]:
    """Load NodeTelemetry objects from a JSON file or a directory of JSON files."""
    import json
    from pathlib import Path

    p = Path(path_or_str)
    if not p.exists():
        return {}

    telemetries: Dict[str, NodeTelemetry] = {}

    def _parse_telemetry_file(fpath: Path) -> Optional[NodeTelemetry]:
        try:
            with open(fpath, "r", encoding="utf-8") as f:
                data = json.load(f)
            # Handle field mapping from collect_kernel_telemetry.sh
            pool_id = data.get("pool_id") or data.get("node_pool_id") or data.get("node_id") or fpath.stem
            modprobe_cfg = data.get("modprobe_config", [])
            disabled = []
            for line in modprobe_cfg:
                if "/bin/false" in line or "blacklist" in line:
                    for mod in ["esp4", "esp6", "rxrpc"]:
                        if mod in line and mod not in disabled:
                            disabled.append(mod)

            return NodeTelemetry(
                pool_id=pool_id,
                os_distribution=data.get("os_distribution") or data.get("os_distro"),
                os_release=str(data.get("os_release")) if data.get("os_release") else None,
                kernel_package_name=data.get("kernel_package_name") or data.get("package_name"),
                kernel_flavor=data.get("kernel_flavor") or data.get("flavor"),
                kernel_package_version=data.get("distro_package_version") or data.get("kernel_package_version"),
                kernel_release=data.get("kernel_release"),
                loaded_modules=data.get("loaded_modules", []),
                builtin_modules=data.get("builtin_modules", []),
                modprobe_disabled_modules=disabled,
                active_services=data.get("active_services", []),
                xfrm_active=bool(data.get("xfrm_active", False)),
                livepatch_modules=data.get("livepatch_modules", []),
            )
        except Exception:
            return None

    if p.is_file():
        t = _parse_telemetry_file(p)
        if t:
            telemetries[t.pool_id] = t
    elif p.is_dir():
        for json_file in p.glob("*.json"):
            t = _parse_telemetry_file(json_file)
            if t:
                telemetries[t.pool_id] = t

    return telemetries


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
                item_finding = {
                    "cve_id": cp.target_or_cve,
                    "cvss_score": float(cp.cvss) if cp.cvss and cp.cvss.replace(".", "", 1).isdigit() else None,
                    "cvss_vector": getattr(cp, "cvss_vector", None),
                    "summary": f"{notice.conclusion} {cp.content_summary}",
                    "cwe_list": getattr(cp, "cwe_list", None),
                }
                pipeline_findings_by_comp.setdefault(c_name, []).append(item_finding)

    # 2. Build findings for each workload
    for wl in environment.workloads:
        findings: List[Dict[str, Any]] = []

        # A. Pull findings matched by component names from pipeline
        for comp in wl.components:
            comp_lower = comp.strip().lower()
            if comp_lower in pipeline_findings_by_comp:
                findings.extend(pipeline_findings_by_comp[comp_lower])

        # B. Pull explicit entry CVEs
        all_entry_cves = list(wl.entry_cves)
        for c in wl.components:
            if c.upper().startswith("CVE-"):
                all_entry_cves.append(c)

        for cve in all_entry_cves:
            cid = cve.strip().upper()
            f_entry: Dict[str, Any] = {
                "cve_id": cid,
                "summary": None,  # Do not invent synthetic summaries!
            }
            if feed_results and cid in feed_results:
                fr = feed_results[cid]
                if getattr(fr, "in_cisa_kev", None) is not None:
                    f_entry["cisa_kev"] = fr.in_cisa_kev
                if getattr(fr, "epss_score", None) is not None:
                    f_entry["epss_score"] = fr.epss_score
            findings.append(f_entry)

        # C. Inspect workload SBOM if provided
        if wl.sbom_path and Path(wl.sbom_path).exists():
            try:
                with open(wl.sbom_path, "r", encoding="utf-8") as f:
                    sbom_data = json.load(f)
                    # Read components from CycloneDX or Syft
                    comps = sbom_data.get("components") or sbom_data.get("artifacts") or []
                    for comp_item in comps:
                        cn = (comp_item.get("name") or "").lower()
                        if cn in pipeline_findings_by_comp:
                            findings.extend(pipeline_findings_by_comp[cn])
            except Exception:
                pass

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
) -> str:
    """Format Exploit Chain audit results into enterprise-ready Markdown report."""
    lines = [
        f"# 🚨 Exploit Chain & Linux Kernel Exposure Audit Report ({environment_name})",
        "",
        "> ℹ️ **【ADR-019 / v0.4.0 連鎖エクスプロイト判定標準】**  ",
        "> 単一のCVSS値にとらわれず、「外部露出したアプリ層の侵入足場（RCE）」×「同一共有カーネル上のOS権限昇格（LPE）」の結合リスク、",
        "> および同一ノードに同居する別マイクロサービスへの水平展開（Blast Radius）を網羅的に評価します。",
        "",
        "## 📊 監査サマリ・総合判定",
        "",
        "| ワークロード | ノードプール | カーネルCVE | 深刻度・連鎖判定 | 対応期限 | 影響範囲（水平展開リスク） |",
        "| :--- | :--- | :--- | :--- | :--- | :--- |",
    ]

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

