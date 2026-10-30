"""Core execution pipeline shared between CLI and Web GUI.

Ensures that triage investigation, target selection, researcher loops,
omission tracking, and codebase/vendor verification remain strictly identical
across both CLI and GUI interfaces.
"""

import os
from pathlib import Path
from typing import Callable, List, Optional, Set, Tuple

from triage_agent.agents.planner import run_recon_planner
from triage_agent.agents.researcher import run_researcher
from triage_agent.agents.triage import run_triage_agent
from triage_agent.config import is_llm_configured
from triage_agent.demo import generate_demo_report
from triage_agent.schemas import PreAnnouncementNotice, ReconPlan, ReconTarget, TargetResearchResult, TriageReport
from triage_agent.tools.advisory_catalog import scan_catalog_pre_announcements
from triage_agent.tools.github import is_github_auth_failed, reset_github_rate_limit
from triage_agent.tools.osv import query_osv_batch
from triage_agent.tools.sbom import load_sbom_summary
from triage_agent.verifier import CodebaseAuditReport, verify_codebase


def execute_triage_pipeline(
    sbom_path: str,
    mode: str = "live",
    max_targets: int = 10,
    code_dir: Optional[str] = None,
    audit_file_path: Optional[str] = None,
    target_environment: Optional[str] = None,
    progress_callback: Optional[Callable[[str], None]] = None,
) -> Tuple[TriageReport, Optional[CodebaseAuditReport]]:
    """Execute the full 3-phase triage pipeline and optional verification.

    Args:
        sbom_path: Path to the SBOM file (JSON).
        mode: Execution mode ('demo', 'dry-run', or 'live').
        max_targets: Maximum top priority targets to investigate.
        code_dir: Optional path to local codebase for automatic code inspection.
        audit_file_path: Optional path to audit attestation JSON file.
        target_environment: Optional environment string (e.g. 'Production') to scope sign-offs.
        progress_callback: Optional callback for status progress messages.

    Returns:
        Tuple of (TriageReport, Optional[CodebaseAuditReport])
    """
    # Reset session circuit breakers (unauthenticated 403 rate limit & 401 auth failure) for fresh run
    reset_github_rate_limit()

    def log(msg: str, percent: int = 0, phase: str = "Init", **kwargs):
        if progress_callback:
            try:
                progress_callback(msg, percent=percent, phase=phase, **kwargs)
            except TypeError:
                progress_callback(msg)

    # 1. Handle Demo mode
    if mode == "demo":
        log("展示用合成データ（DEMO-*）で即座に指示書を生成中...", percent=10, phase="Recon Planner")
        triage_report = generate_demo_report()
        log("DEMO 調査完了。発火条件指示書を構成中...", percent=70, phase="Triage Agent")
        audit_report = None
        if code_dir or audit_file_path:
            log("自社検証 / ベンダー監査判定を実行中...", percent=90, phase="Verifier")
            audit_report = verify_codebase(
                triage_report,
                code_dir_path=code_dir,
                audit_file_path=audit_file_path,
                target_environment=target_environment,
            )
        log("すべての処理が完了しました。", percent=100, phase="Complete")
        return triage_report, audit_report

    # 2. Check SBOM existence and handle typo fallback with explicit warning
    p = Path(sbom_path)
    unscanned_items: List[str] = []

    if not p.exists():
        alt_p = p.with_suffix(".json")
        if alt_p.exists():
            unscanned_items.append(
                f"⚠️ 指定されたSBOMファイル '{sbom_path}' が見つからなかったため、同名の '{alt_p}' を代替使用しました。"
            )
            sbom_path = str(alt_p)
            p = alt_p
        else:
            raise FileNotFoundError(f"SBOMファイルが見つかりません: '{sbom_path}'")

    is_dry_run = (mode == "dry-run")

    if not is_dry_run and not is_llm_configured():
        raise ValueError(
            "LLM API が設定されていません。\n"
            "ライブエージェントによる自動調査を行うには、GEMINI_API_KEY または Vertex AI を設定してください。\n"
            "オフラインでシミュレーションを実行したい場合は、Dry-Run モードを選択してください。"
        )

    # -------------------------------------------------------------
    # Phase 1: Recon Planner
    # -------------------------------------------------------------
    log("[1/3] Recon Planner: SBOM解析および巡回戦略策定中...", percent=5, phase="Recon Planner", step=1, total_steps=3)
    components = load_sbom_summary(sbom_path)
    osv_hits, osv_errors, osv_unsupported = query_osv_batch(components)
    catalog_pre_announcements, catalog_feed_errors = scan_catalog_pre_announcements(components)
    if catalog_feed_errors:
        unscanned_items.extend(catalog_feed_errors)
    if catalog_pre_announcements:
        log(f"事前予告カタログ照合: {len(catalog_pre_announcements)} 件の監視対象/予定を特定。", percent=17, phase="Recon Planner", step=1, total_steps=3)

    actual_osv_failures = [e for e in osv_errors if not ("詳細未取得" in e or "上位" in e)]
    overflow_osv_notes = [e for e in osv_errors if ("詳細未取得" in e or "上位" in e)]

    if actual_osv_failures:
        log(f"⚠️ OSV.dev 一括照会失敗 ({'; '.join(actual_osv_failures)})。フォールバック処理を継続中...", percent=15, phase="Recon Planner", step=1, total_steps=3)
        unscanned_items.append(f"OSV.dev 一括照会失敗: {'; '.join(actual_osv_failures)}")
    else:
        status_msg = f"OSV.dev 一括照会完了 ({len(osv_hits)} 件のヒット)"
        if overflow_osv_notes:
            status_msg += f" (※一部多数検出コンポーネントで件数上限適用)"
        log(f"{status_msg}。深層調査対象を選定中...", percent=15, phase="Recon Planner", step=1, total_steps=3)

    if is_dry_run:
        targets: List[ReconTarget] = []
        repo_map = {
            "urllib3": "urllib3/urllib3",
            "jsonwebtoken": "auth0/node-jsonwebtoken",
            "axios": "axios/axios",
            "log4j-core": "apache/logging-log4j2",
            "fastapi": "fastapi/fastapi",
            "express": "expressjs/express",
        }

        for c in components:
            is_hit = c.name in osv_hits
            github_repo = repo_map.get(c.name, f"{c.name}/{c.name}")
            targets.append(
                ReconTarget(
                    name=c.name,
                    version=c.version,
                    ecosystem=c.ecosystem,
                    github_repo=github_repo,
                    priority="CRITICAL" if is_hit and c.name in ["log4j-core", "urllib3", "jsonwebtoken"] else "HIGH",
                    rationale=f"Known OSV hits found ({len(osv_hits.get(c.name, []))} alerts)" if is_hit else "Core web/network component",
                    search_queries=[
                        f"{c.name} upcoming security release notice",
                        f"{c.name} {c.version} RCE vulnerability patch",
                    ],
                    github_search_keywords=["security", "cve", "patch", "rce"],
                )
            )

        targets.sort(key=lambda t: 0 if t.priority == "CRITICAL" else 1)
        recon_plan = ReconPlan(
            summary="Heuristic & OSV batch scan completed.",
            total_components_scanned=len(components),
            known_osv_hits_count=len(osv_hits),
            targets=targets[:max_targets],
        )
    else:
        recon_plan = run_recon_planner(sbom_path, osv_results=osv_hits)
        recon_plan.targets = recon_plan.targets[:max_targets]

    # Explicitly track omitted components that had actual vulnerabilities or unverified status
    # When OSV batch succeeds: components with 0 known OSV hits are clear at Level 1 (mechanical lookup).
    # Components that have OSV hits but were omitted due to max_targets pose a risk and are recorded.
    # When OSV batch failed: omitted components were NEVER verified and must be explicitly recorded.
    target_names = {t.name for t in recon_plan.targets}
    if actual_osv_failures:
        unchecked = [c.name for c in components if c.name not in target_names]
        if unchecked:
            unscanned_items.append(
                f"OSV.dev 一括照会失敗のため脆弱性未確認（{len(unchecked)} 件: {', '.join(unchecked)}）"
            )
    else:
        omitted_osv_hits = [c.name for c in components if c.name in osv_hits and c.name not in target_names]
        if omitted_osv_hits:
            unscanned_items.append(
                f"上限（--max-targets {max_targets}）により、OSV脆弱性が検知された以下のコンポーネントの深層調査を省略しました（計 {len(omitted_osv_hits)} 件: {', '.join(omitted_osv_hits)}）"
            )

    # -------------------------------------------------------------
    # Phase 2: Dynamic Researcher (Target-by-Target)
    # -------------------------------------------------------------
    total_targets = len(recon_plan.targets)
    log(f"[2/3] Researcher: {total_targets} コンポーネントの動的調査・事前予告探索中...", percent=20, phase="Researcher", step=2, total_steps=3, total_targets=total_targets)
    research_results: List[TargetResearchResult] = []
    failed_targets: Set[str] = set()

    for idx, target in enumerate(recon_plan.targets, 1):
        target_pct = int(20 + ((idx - 1) / max(total_targets, 1)) * 55)
        log(
            f"  [{idx}/{total_targets}] 調査中: {target.name} ({target.version})...",
            percent=target_pct,
            phase="Researcher",
            step=2,
            total_steps=3,
            current_target=f"{target.name} ({target.version})",
            target_index=idx,
            total_targets=total_targets,
        )
        try:
            res = run_researcher(target, dry_run=is_dry_run)
            research_results.append(res)
            if res.errors:
                failed_targets.add(target.name)
                for err in res.errors:
                    unscanned_items.append(f"{target.name}: {err}")
        except Exception as e:
            failed_targets.add(target.name)
            unscanned_items.append(f"{target.name}: 調査処理エラー ({str(e)})")

    if is_github_auth_failed():
        unscanned_items.append("GitHub API 認証エラー: 設定された GITHUB_TOKEN が無効または期限切れです（HTTP 401 Bad credentials）")

    # -------------------------------------------------------------
    # Phase 3: Triage & Action Generation
    # -------------------------------------------------------------
    log("[3/3] Triage Agent: 発火条件特定・現場即応指示書生成中...", percent=78, phase="Triage Agent", step=3, total_steps=3)
    triage_report = run_triage_agent(
        research_results=research_results,
        unscanned_components=unscanned_items,
        dry_run=is_dry_run,
    )
    triage_report.osv_unsupported_components = osv_unsupported

    # Populate pre-announcements from catalog and dynamic findings (ADR-020)
    pre_announcements_map = {
        f"{n.source_id}:{n.component_name}:{n.title}": n for n in catalog_pre_announcements
    }
    for res in research_results:
        for f in res.findings:
            if f.is_pre_announcement:
                # Key by component and finding ID/title so multiple pre-announcements for one target are preserved
                dyn_key = f"dynamic-{res.target.name}:{f.id or f.title}"
                if dyn_key not in pre_announcements_map:
                    pre_announcements_map[dyn_key] = PreAnnouncementNotice(
                        source_id=f"dynamic-{res.target.name}",
                        source_name=f"{res.target.name} 公開リポジトリ/Web検索",
                        component_name=res.target.name,
                        title=f.title,
                        expected_date=None,
                        severity_hint=f.severity,
                        summary=f.summary,
                        url=f.source_urls[0] if f.source_urls else None,
                        is_official=False,  # Web/Search signals are unconfirmed pre-announcements (ADR-020)
                        recommended_preparations=[
                            "次期パッチ公開予定の事前確認（公式チャンネルの確認）",
                            "ベンダー作業枠の事前仮押さえ",
                            "本番変更管理申請（RFC）の先行起票",
                        ],
                    )
    triage_report.pre_announcements = list(pre_announcements_map.values())

    # Informational coverage summary: record scope of deep research vs OSV lookup
    total_c = len(components)
    deep_c = len(recon_plan.targets)
    omitted_c = total_c - deep_c
    failed_c = len(failed_targets)
    success_c = max(0, deep_c - failed_c)

    # 1. Deep research summary
    if deep_c == total_c:
        if failed_c > 0:
            deep_part = (
                f"全 {total_c} コンポーネントすべてを深層調査対象として選定"
                f"（{success_c} 件完了、{failed_c} 件失敗・未調査警告あり）。"
            )
        else:
            deep_part = (
                f"全 {total_c} コンポーネントすべてを深層調査（Researcher）対象として選定・調査完了。"
            )
    else:
        if failed_c > 0:
            deep_part = (
                f"全 {total_c} コンポーネント中、優先度上位 {deep_c} 件を深層調査対象として選定"
                f"（{success_c} 件完了、{failed_c} 件失敗・未調査警告あり）。"
            )
        else:
            deep_part = (
                f"全 {total_c} コンポーネント中、優先度上位 {deep_c} 件を深層調査（Researcher）。"
            )

    # 2. Omitted components summary
    if omitted_c > 0:
        if actual_osv_failures:
            omitted_part = (
                f"残り {omitted_c} 件は OSV.dev 一括照会失敗により脆弱性未確認（Web/コミット深掘り調査も未実施、要個別調査）。"
            )
        else:
            omitted_osv_hits_c = len([c for c in components if c.name in osv_hits and c.name not in target_names])
            if omitted_osv_hits_c > 0:
                omitted_clean_c = omitted_c - omitted_osv_hits_c
                omitted_part = (
                    f"残り {omitted_c} 件中、{omitted_osv_hits_c} 件で OSV 脆弱性を検知（深層調査は上限により省略）。"
                    f"残り {omitted_clean_c} 件は OSV.dev 一括照会（脆弱性 0 件確認）のみ実施し、Web/コミット深掘り調査を省略。"
                )
            else:
                omitted_part = (
                    f"残り {omitted_c} 件は OSV.dev 一括照会（脆弱性 0 件確認）のみ実施し、Web/コミット深掘り調査を省略。"
                )
        triage_report.recon_coverage_summary = f"{deep_part} {omitted_part}"
    else:
        triage_report.recon_coverage_summary = deep_part

    if is_github_auth_failed():
        triage_report.recon_coverage_summary += " ※注意: GITHUB_TOKEN の認証に失敗しました（HTTP 401 Bad credentials: トークンが無効または期限切れ）。"

    log("指示書生成完了。検証判定を実行中...", percent=90, phase="Triage Agent", step=3, total_steps=3)

    # -------------------------------------------------------------
    # Phase 4: Codebase / Vendor Verification Audit
    # -------------------------------------------------------------
    audit_report = None
    if code_dir or audit_file_path:
        log("自社検証 / ベンダー監査判定を実行中...", percent=94, phase="Verifier", step=3, total_steps=3)
        audit_report = verify_codebase(
            triage_report,
            code_dir_path=code_dir,
            audit_file_path=audit_file_path,
            target_environment=target_environment,
        )

    log("すべての処理が完了しました。", percent=100, phase="Complete", step=3, total_steps=3)
    return triage_report, audit_report
