import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from triage_agent.agents.planner import run_recon_planner
from triage_agent.agents.researcher import run_researcher
from triage_agent.agents.triage import run_triage_agent
from triage_agent.config import get_gemini_api_key, get_model_name, is_llm_configured
from triage_agent.demo import generate_demo_report
from triage_agent.schemas import ReconPlan, ReconTarget, TargetResearchResult, TriageNotice, TriageReport

console = Console()


def format_report_markdown(report: TriageReport) -> str:
    """Format the TriageReport into the enterprise action-oriented standard."""
    lines = [
        f"# {report.report_title}",
        "",
    ]

    if report.is_dry_run:
        lines.extend([
            "> ⚠️ **【DRY-RUN / シミュレーション実行】** 本レポートはオフライン静的解析によるシミュレーション結果です。"
            "確定判定（RCE有無の精読や修正パッチバージョンの確定）はライブエージェント（GEMINI_API_KEY設定環境）で実行してください。",
            "",
        ])

    if report.recon_coverage_summary:
        lines.extend([
            f"> ℹ️ **【調査カバレッジ・深度サマリ】** {report.recon_coverage_summary}",
            "",
        ])

    if report.unscanned_or_failed_components:
        lines.extend([
            "> 🚨 **【警告: 調査不能・未調査コンポーネント】**",
            "> 以下のコンポーネントはネットワーク障害、APIエラー、または上限設定のため深層調査を完了できませんでした。",
            "> **未調査の項目を『安全・対応不要』と誤認してはなりません。**",
            "",
        ])
        for c in report.unscanned_or_failed_components:
            lines.append(f"> - ⚠️ `{c}`")
        lines.append("")

    if report.osv_unsupported_components:
        lines.extend([
            "> ℹ️ **【OSV.dev 照合対象外（ランタイム・OS共有ライブラリ等）】**",
            "> 以下のコンポーネントは言語パッケージリポジトリ（PyPI/npm等）ではなくランタイムやOS共有ライブラリ等のため、OSV一括照会から除外され、Web/LLM等による個別調査の対象となります。",
            "",
        ])
        for c in report.osv_unsupported_components:
            lines.append(f"> - ℹ️ `{c}`")
        lines.append("")

    if report.pre_announcements:
        lines.extend([
            "## 📅 事前パッチ予告・定期更新スケジュール (Early Warning Calendar)",
            "",
            "> 💡 **「突発的な緊急対応を、コントロールされた計画作業へ」**  ",
            "> 自社SBOMに該当するコンポーネントについて、CVE公表前の事前予告や次回定期更新スケジュールを検知しました。  ",
            "> iCalendar（`.ics`）ファイルを Google カレンダーや Microsoft Outlook に取り込むことで、**「輪番の事前確保」「ベンダー作業枠の仮押さえ」「本番変更管理申請（RFC）の先行起票」** をパッチ公開前に完了できます（`--calendar output.ics`）。",
            "",
            "| 対象コンポーネント | 予定日 / 時期 | 深刻度・概要 | 情報源・公式度 | 事前準備チェックリスト |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])
        for pa in report.pre_announcements:
            date_col = f"**{pa.expected_date}**" if pa.expected_date else "事前監視チャンネル"
            if pa.expected_time:
                date_col += f"<br>({pa.expected_time})"
            sev_col = f"[{pa.severity_hint or '要確認'}] {pa.title}"
            official_tag = "公式一次情報" if pa.is_official else "未確認の予兆"
            source_col = f"{pa.source_name}<br>({official_tag})"
            if pa.url:
                source_col += f"<br><{pa.url}>"
            checklist_col = "<br>".join([f"・{item}" for item in pa.recommended_preparations])
            lines.append(f"| `{pa.component_name}` | {date_col} | {sev_col} | {source_col} | {checklist_col} |")
        lines.extend(["", "---", ""])

    for notice in report.notices:
        lines.extend([
            f"## {notice.product_name}（{notice.announcement_date}）",
            f"**結論：** {notice.conclusion}",
            f"**公開日：** {notice.announcement_date}",
            f"**修正版：** {notice.fixed_versions}",
            f"**深刻度：** {notice.severity_note}",
            "",
            "| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |",
            "| :--- | :--- | :--- | :--- | :--- |",
        ])

        for cp in notice.check_points:
            target_cve = cp.target_or_cve.replace("|", "/")
            summary = cp.content_summary.replace("|", "/")
            versions = cp.affected_versions.replace("|", "/")
            yes_no = cp.check_point_yes_no.replace("|", "/")
            method = cp.verification_method.replace("|", "/")
            lines.append(f"| {target_cve} | {summary} | {versions} | {yes_no} | {method} |")

        lines.append("")
        if notice.pre_check_note:
            lines.append(f"> {notice.pre_check_note}")
            lines.append("")

        if notice.workaround:
            lines.append(f"**回避策：** {notice.workaround}")
            lines.append("")

        if notice.unconfirmed_points:
            lines.append("**未確認事項**")
            for u in notice.unconfirmed_points:
                lines.append(f"- {u}")
            lines.append("")

        if notice.sources:
            lines.append(f"**出典：** " + ", ".join([f"<{s}>" for s in notice.sources]))
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def run_chain_audit_flow(args, console: Console, triage_report: Optional[Any] = None) -> List[Any]:
    """Execute the Exploit Chain & Linux Kernel Exposure audit (v0.4.0)."""
    import re
    from triage_agent.chain.engine import (
        build_pool_coverage,
        find_pool_mismatches,
        format_chain_audit_markdown,
        load_environment_definition,
        load_node_telemetries_with_report,
        run_exploit_chain_audit,
    )
    from triage_agent.chain.feeds import ThreatFeedClient
    from triage_agent.chain.models import DistroAffectedRange, KernelVulnerabilityEntry

    console.print(
        Panel.fit(
            "[bold red]【EXPLOIT CHAIN & KERNEL EXPOSURE AUDIT / 連鎖エクスプロイト監査（v0.4.0）】[/bold red]\n"
            "「外部露出RCE足場」×「共有カーネルノード上のLPE」によるホスト権限奪取および同居マイクロサービスへの\n"
            "水平展開（Lateral Movement / Blast Radius）リスクを網羅的かつ決定論的に監査します。",
            border_style="red",
        )
    )

    env_path = args.environments
    if not env_path:
        for candidate in ["triage-output/environments.yaml", "environments.yaml", "environments.example.yaml"]:
            if Path(candidate).exists():
                env_path = candidate
                break

    if not env_path or not Path(env_path).exists():
        console.print("[bold red]❌ エラー: 環境定義ファイル（--environments）が見つかりません。environments.example.yaml を参考に作成してください。[/bold red]")
        sys.exit(1)

    console.print(f"ℹ️ 環境定義ファイルを読み込みます: [cyan]{env_path}[/cyan]")
    env_def = load_environment_definition(env_path)

    telemetries = {}
    telemetry_issues = []
    max_age = getattr(args, "telemetry_max_age", 7)
    telemetry_source = args.telemetry
    if not telemetry_source and Path("triage-output/telemetry").exists():
        telemetry_source = "triage-output/telemetry"
    if telemetry_source:
        telemetries, telemetry_issues = load_node_telemetries_with_report(
            str(telemetry_source), max_age_days=max_age if max_age and max_age > 0 else None
        )
        total_nodes = sum(t.observed_nodes_count for t in telemetries.values())
        console.print(
            f"ℹ️ 実機ノードテレメトリを読み込みました（{telemetry_source}）: "
            f"[cyan]{len(telemetries)} プール / {total_nodes} ノード[/cyan]"
        )
    telemetry_issues.extend(find_pool_mismatches(env_def, telemetries))
    for issue in telemetry_issues:
        if issue.severity == "warning":
            suffix = f"（{Path(issue.source).name}）" if issue.source.endswith(".json") else ""
            console.print(f"[bold yellow]⚠️ テレメトリ: {issue.message}{suffix}[/bold yellow]")
    pool_coverage = build_pool_coverage(env_def, telemetries)
    for cov in pool_coverage.values():
        if cov.is_known_incomplete:
            console.print(
                f"[bold yellow]⚠️ プール {cov.pool_id}: 実機テレメトリが一部のノードのみです（{cov.describe()}）。"
                f"このプールでは SAFE / 緩和済みと判定しません。[/bold yellow]"
            )

    # Build kernel vulnerability targets from external ledger or OSV feed (No synthetic hardcoded entries)
    vulnerabilities: List[KernelVulnerabilityEntry] = []
    ledger_candidates = []
    if args.chain_ledger:
        ledger_candidates.append(args.chain_ledger)
    ledger_candidates.extend(["triage-output/exploit_chain_ledger.json", "exploit_chain_ledger.json"])

    loaded_ledger_path = None
    for cand in ledger_candidates:
        if cand and Path(cand).exists():
            try:
                with open(cand, "r", encoding="utf-8") as f:
                    ledger_data = json.load(f)
                    items = ledger_data.get("vulnerabilities", []) if isinstance(ledger_data, dict) else (ledger_data if isinstance(ledger_data, list) else [])
                    skipped_missing_provenance = 0
                    for item in items:
                        if not isinstance(item, dict):
                            continue
                        cid = item.get("cve_id", "")
                        if cid == "CVE-0000-00000":
                            # Skip synthetic placeholder in example ledger
                            continue
                        source_url = item.get("source_url")
                        retrieved_at = item.get("retrieved_at")
                        if not source_url or not retrieved_at:
                            skipped_missing_provenance += 1
                            continue

                        # Convert affected_packages or distro_affected_ranges
                        aff_ranges = {}
                        raw_ranges = item.get("distro_affected_ranges") or item.get("affected_packages") or {}
                        for k, v in raw_ranges.items():
                            if isinstance(v, dict):
                                aff_ranges[k] = DistroAffectedRange(
                                    package=v.get("package", "linux"),
                                    fixed_version=v.get("fixed_version", ""),
                                )
                        vulnerabilities.append(
                            KernelVulnerabilityEntry(
                                cve_id=cid,
                                name=item.get("name") or item.get("summary") or cid,
                                source_url=source_url,
                                retrieved_at=retrieved_at,
                                epss_score=item.get("epss_score"),
                                cisa_kev=item.get("cisa_kev", False),
                                poc_available=item.get("poc_available", False),
                                distro_affected_ranges=aff_ranges,
                            )
                        )
                    if skipped_missing_provenance > 0:
                        console.print(
                            f"[bold yellow]⚠️ カーネル台帳読み込み: 出典（source_url）または取得日（retrieved_at）が未記載の "
                            f"{skipped_missing_provenance} 件を読み飛ばしました。（実測・出典付き台帳のみを採用する監査保護方針）[/bold yellow]"
                        )
                loaded_ledger_path = cand
                console.print(f"ℹ️ カーネル脆弱性台帳（{cand}）から {len(vulnerabilities)} 件を読み込みました")
                break
            except Exception as e:
                console.print(f"[bold yellow]⚠️ 外部台帳読み込み警告: {e}[/bold yellow]")

    # ADR-021: automatic kernel advisory lookup (lateral discovery of LPEs missing from the manual ledger)
    kernel_auto_result = None
    if getattr(args, "kernel_auto", False):
        from triage_agent.chain.kernel_exposure import run_kernel_auto
        from triage_agent.chain.kernel_history import load_manual_promotions, load_snapshot, save_snapshot
        from triage_agent.chain.sources import build_adapters, load_registry

        auto_feed = ThreatFeedClient(epss_jump_threshold=args.epss_threshold)
        offline = bool(args.dry_run)

        def _kev_lookup():
            return auto_feed.load_cached_kev_catalog() if offline else auto_feed.fetch_cisa_kev_catalog()

        state_dir = args.kernel_auto_state
        previous_snapshot, snapshot_problem = load_snapshot(state_dir)
        if snapshot_problem:
            console.print(f"[bold yellow]⚠️ {snapshot_problem}[/bold yellow]")
        try:
            manual_promotions = load_manual_promotions(state_dir)
        except Exception as e:  # noqa: BLE001 - a broken ledger must not silently drop promotions
            console.print(f"[bold red]❌ 手動昇格の台帳（{state_dir}/promotions.json）を読めません: {e}[/bold red]")
            sys.exit(1)

        console.print("ℹ️ カーネル脆弱性を自動照会しています（ディストリの勧告 × 実機のカーネル版）...")
        kernel_auto_result = run_kernel_auto(
            environment=env_def,
            telemetries=telemetries,
            adapters=build_adapters(load_registry(), cache_dir=str(auto_feed.cache_dir)),
            kev_lookup=_kev_lookup,
            epss_lookup=auto_feed.fetch_epss_scores,
            manual_cve_ids={v.cve_id for v in vulnerabilities},
            offline=offline,
            epss_threshold=args.kernel_auto_epss,
            tier2_limit=args.kernel_auto_tier2_limit,
            previous_snapshot=previous_snapshot,
            manual_promotions=manual_promotions,
            epss_jump=args.epss_threshold,
        )
        kernel_auto_result.kev_catalog_info = auto_feed.kev_catalog_info
        if auto_feed.kev_catalog_info:
            info = auto_feed.kev_catalog_info
            console.print(f"ℹ️ CISA KEV カタログ: 版 {info['catalogVersion']}（公開 {info['dateReleased']}・{info['count']} 件）")
        for pid, summary in sorted(kernel_auto_result.pools.items()):
            if summary.status == "ok":
                c = summary.tier_counts
                console.print(
                    f"   - {pid}: 層1 {c[1]} 件 / 層2 {c[2]} 件 / 層3 {c[3]} 件"
                    + (f"（{summary.upgrade_target} 以上で層1・2 を解消）" if summary.upgrade_target else "")
                )
            else:
                console.print(f"[yellow]   - {pid}: {summary.reason}[/yellow]")
        for err in kernel_auto_result.errors:
            console.print(f"[bold yellow]⚠️ 自動照会: {err}[/bold yellow]")
        if kernel_auto_result.previous_taken_at is None:
            console.print("ℹ️ 前回のスナップショットがないため、今回の結果を比較の基準にします（次回から変化と昇格を判定）")
        else:
            new_promos = [p for p in kernel_auto_result.promotions.values() if p.new]
            console.print(
                f"ℹ️ 前回（{kernel_auto_result.previous_taken_at}）からの変化: 新たに層1 {kernel_auto_result.new_tier1_total} 件"
                f"（うち今回の昇格 {len(new_promos)} 件）"
            )
            for p in new_promos:
                console.print(f"[bold red]   ⬆ 昇格: {p.cve_id}（{p.label}: {p.detail}）[/bold red]")
        if kernel_auto_result.snapshot is not None:
            snap_path = save_snapshot(kernel_auto_result.snapshot, state_dir)
            console.print(f"ℹ️ 次回の比較用にスナップショットを保存しました: {snap_path}")
        elif offline:
            console.print("ℹ️ オフライン実行のため、スナップショットは更新していません")
        args.kernel_auto_result = kernel_auto_result
        vulnerabilities.extend(kernel_auto_result.entries)

    if not vulnerabilities and kernel_auto_result is None:
        console.print("[yellow]ℹ️ カーネル脆弱性台帳（--chain-ledger または exploit_chain_ledger.json）に対象エントリがないため、連鎖評価をスキップします。[/yellow]")
        return []

    # If triage_report wasn't passed directly, check if a generated triage_report.json exists
    if triage_report is None:
        report_candidates = ["triage-output/triage_report.json", "triage_report.json"]
        if args.output and args.output.endswith(".json"):
            report_candidates.insert(0, args.output)
        for rc in report_candidates:
            if Path(rc).exists():
                try:
                    with open(rc, "r", encoding="utf-8") as rf:
                        triage_report = TriageReport(**json.load(rf))
                        console.print(f"ℹ️ トリアージ結果レポート（{rc}）を自動連携しました")
                        break
                except Exception:
                    pass

    # Sync with threat feeds (CISA KEV / EPSS sudden jumps)
    feed_client = ThreatFeedClient(epss_jump_threshold=args.epss_threshold)
    target_cves = [v.cve_id for v in vulnerabilities]
    # Only CVE/GHSA identifiers are sent to external feeds. Component names (which may be internal
    # package names) must never leave the machine (docs/data-handling.md, ADR-021 decision 5).
    vuln_id_pattern = re.compile(r"^(CVE-\d{4}-\d{4,7}|GHSA-[\w-]+)$", re.IGNORECASE)
    for wl in env_def.workloads:
        target_cves.extend(c for c in wl.components if vuln_id_pattern.match(c.strip()))
        target_cves.extend(c for c in wl.entry_cves if vuln_id_pattern.match(c.strip()))

    # Extract CVEs/GHSAs from triage_report notices and checkpoints using regex
    if triage_report and hasattr(triage_report, "notices"):
        for notice in triage_report.notices:
            for text in [notice.product_name, notice.component_name, notice.conclusion]:
                if text:
                    target_cves.extend(re.findall(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[\w-]+)\b", text, re.IGNORECASE))
            for cp in notice.check_points:
                for text in [cp.target_or_cve, cp.content_summary]:
                    if text:
                        target_cves.extend(re.findall(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[\w-]+)\b", text, re.IGNORECASE))

    feed_results = {}
    try:
        clean_cves = list(set([c.strip().upper() for c in target_cves if c.strip()]))
        feed_results = feed_client.analyze_cves(clean_cves, offline=args.dry_run)
        for v in vulnerabilities:
            if v.cve_id in feed_results:
                fr = feed_results[v.cve_id]
                if fr.in_cisa_kev is not None:
                    v.cisa_kev = fr.in_cisa_kev
                if fr.epss_score is not None:
                    v.epss_score = fr.epss_score
    except Exception as e:
        console.print(f"[bold yellow]⚠️ 脅威インテリジェンスフィード同期スキップ（オフライン/エラー）: {e}[/bold yellow]")

    # Disclose partial feed retrieval failures ("調べなかったものを隠さない" principle)
    if feed_results:
        kev_err_count = sum(1 for fr in feed_results.values() if "KEV" in (getattr(fr, "error", "") or ""))
        osv_err_count = sum(1 for fr in feed_results.values() if "OSV" in (getattr(fr, "error", "") or ""))
        epss_err_count = sum(1 for fr in feed_results.values() if "EPSS" in (getattr(fr, "error", "") or ""))
        if kev_err_count or osv_err_count or epss_err_count:
            err_parts = []
            if kev_err_count:
                err_parts.append(f"KEV失敗 {kev_err_count}件")
            if osv_err_count:
                err_parts.append(f"OSV失敗 {osv_err_count}件")
            if epss_err_count:
                err_parts.append(f"EPSS失敗 {epss_err_count}件")
            console.print(
                f"[bold yellow]⚠️ フィード照会不全（調査不全の開示）: {', '.join(err_parts)}"
                f"（この分は安全側に倒し判定不能として扱います）[/bold yellow]"
            )

    # Run audit
    audit_items = run_exploit_chain_audit(
        environment=env_def,
        kernel_vulnerabilities=vulnerabilities,
        telemetries=telemetries,
        feed_results=feed_results,
        triage_report=triage_report,
    )

    # Format and save report
    report_md = format_chain_audit_markdown(
        audit_items,
        environment_name=env_def.environment_name,
        feed_results=feed_results,
        coverage=pool_coverage,
        load_issues=telemetry_issues,
        kernel_auto=kernel_auto_result,
    )
    out_path = Path(args.chain_output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report_md, encoding="utf-8")
    console.print(f"[bold green]✓ 連鎖エクスプロイト監査レポートを出力しました: {out_path.resolve()}[/bold green]\n")

    # Display critical chains in console
    critical_chains = [i for i in audit_items if i.chain_level.value == "CRITICAL_CHAIN"]
    if critical_chains:
        console.print(
            Panel(
                f"[bold red]🚨 【CRITICAL ALERT: 連鎖エクスプロイト（Exploit Chain）を検知しました】[/bold red]\n"
                f"単体のCVSSスコアではMedium/Highに留まる脆弱性が、公開ワークロードのRCE足場と同一ホスト上のカーネルLPEにより\n"
                f"結合し、ホスト全体の完全掌握および同居マイクロサービスへの水平展開が可能な状態です。\n\n"
                + "\n".join([
                    f"• [bold red]ワークロード: {i.workload_name}[/bold red] (ノード: {i.node_pool_id})\n"
                    f"  - 足場RCE: {i.foothold_detail or i.app_cve or '未知/疑義'}\n"
                    f"  - 標的カーネル脆弱性: {i.kernel_cve}\n"
                    f"  - 緩和策状態: {i.mitigation_status}\n"
                    f"  - 対応期限: [bold red]{i.action_deadline}[/bold red]\n"
                    f"  - 影響範囲（水平展開）: {', '.join(i.blast_radius) if i.blast_radius else 'なし'}"
                    for i in critical_chains
                ]),
                border_style="red",
            )
        )
    else:
        console.print("[bold green]✓ Critical な連鎖エクスプロイト（RCE足場＋未緩和LPE）は検出されませんでした。[/bold green]")

    return audit_items


def _kernel_promotion_reason(args) -> Optional[str]:
    """--fail-on promoted: a kernel CVE became tier 1 since the previous --kernel-auto run."""
    ka = getattr(args, "kernel_auto_result", None)
    if ka is None or ka.previous_taken_at is None or ka.new_tier1_total == 0:
        return None
    new_promos = sorted(c for c, p in ka.promotions.items() if p.new)
    detail = f"（今回の昇格: {', '.join(new_promos)}）" if new_promos else ""
    return f"前回の実行から新たに層1 になったカーネル脆弱性が {ka.new_tier1_total} 件あります{detail}"


def main():
    parser = argparse.ArgumentParser(
        description="triage-agent: Autonomous SBOM Vulnerability Intelligence and Triage Multi-Agent System"
    )
    parser.add_argument(
        "--sbom",
        type=str,
        default="sample_sbom.json",
        help="Path to Syft CycloneDX JSON or native JSON SBOM file (default: sample_sbom.json)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Override Gemini model name (default: reads GEMINI_MODEL or gemini-3.5-flash)",
    )
    parser.add_argument(
        "--max-targets",
        type=int,
        default=10,
        help="Maximum top-priority targets to investigate dynamically (default: 10)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional path to save the generated Triage Report (Markdown format, e.g. report.md, or .json)",
    )
    parser.add_argument(
        "--verify-code",
        type=str,
        default=None,
        help="Optional path to local codebase directory. Automatically scans the code against the check points.",
    )
    parser.add_argument(
        "--verify-output",
        type=str,
        default="verification_audit_report.md",
        help="Path to save the codebase verification report (default: verification_audit_report.md)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run in dry-run mode (uses direct tools and offline simulation without calling LLM API)",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Run in explicit demonstration showcase mode using clearly identifiable synthetic DEMO-* data",
    )
    parser.add_argument(
        "--audit-file",
        type=str,
        default=None,
        help="Optional path to audit attestation JSON file (e.g. sample_audit_signoff.json)",
    )
    parser.add_argument(
        "--self-triage",
        action="store_true",
        help="Run dogfooding self-audit against triage-agent's own dependencies and source code (ADR-018)",
    )
    parser.add_argument(
        "--fail-on",
        type=str,
        default=None,
        help="Comma-separated conditions to exit with non-zero status code (e.g. 'unscanned,yes' or 'any'). "
             "Supported: unscanned (investigation failed/error), excluded (packages omitted via --exclude), "
             "yes (vulnerable code confirmed), unconfirmed (unverified external settings), critical_chain, "
             "promoted (--kernel-auto: a kernel CVE became tier 1 since the previous run), any. "
             "(Note: 'any' matches unscanned, yes, unconfirmed, and critical_chain, but does not match 'excluded' "
             "or 'promoted' unless explicitly specified).",
    )
    parser.add_argument(
        "--calendar",
        type=str,
        default=None,
        dest="calendar_output",
        help="Optional path to export iCalendar file (.ics) for security release schedules (ADR-020)",
    )
    parser.add_argument(
        "--export-checklist",
        type=str,
        default=None,
        dest="export_checklist_path",
        help="Optional path to export vendor checklist CSV for cybersecurity/vendor inquiry (ADR-019)",
    )
    parser.add_argument(
        "--export-checklist-target",
        type=str,
        default=None,
        dest="export_checklist_target",
        help="Optional target product/component filter to scope the exported checklist and prevent attack map leakage (ADR-013)",
    )
    parser.add_argument(
        "--import-checklist",
        type=str,
        default=None,
        dest="import_checklist_path",
        help="Import filled vendor checklist CSV into audit_signoff.json (ADR-019)",
    )
    parser.add_argument(
        "--environment",
        type=str,
        default=None,
        help="Target environment (e.g. 'Production', 'Staging', 'Development') to scope sign-offs (v0.3.1 / ADR-019)",
    )
    parser.add_argument(
        "--record-remediation",
        type=str,
        default=None,
        metavar="DISTRIBUTION_ID",
        help="Record T4 remediation / patch deployment completion for a distribution ID (v0.3.1 / ADR-019)",
    )
    parser.add_argument(
        "--remediated-at",
        type=str,
        default=None,
        help="Optional ISO timestamp for remediation completion (defaults to current UTC time)",
    )
    parser.add_argument(
        "--remediation-note",
        type=str,
        default=None,
        help="Optional operational note or deploy commit hash for the remediation record",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the interactive Web GUI dashboard in your browser",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run the ground-truth benchmark suite for Verifier and feeds (ADR-019 / Pillar 4)",
    )
    parser.add_argument(
        "--environments",
        type=str,
        default=None,
        help="Path to environments definition YAML for Exploit Chain Analysis (v0.4.0)",
    )
    parser.add_argument(
        "--telemetry",
        type=str,
        default=None,
        help="Path to node telemetry JSON file or directory containing telemetry files (v0.4.0)",
    )
    parser.add_argument(
        "--kernel-auto",
        action="store_true",
        help="Look up kernel advisories automatically for each node pool's running kernel (ADR-021). "
             "Uses the adapters in chain/kernel_sources.toml; with --dry-run only cached data is used.",
    )
    parser.add_argument(
        "--kernel-auto-epss",
        type=float,
        default=0.1,
        help="EPSS score at or above which an automatically found kernel CVE is tier 2 (default: 0.1)",
    )
    parser.add_argument(
        "--kernel-auto-tier2-limit",
        type=int,
        default=10,
        help="Maximum tier 2 CVEs per pool included in the chain evaluation (default: 10; the rest are counted)",
    )
    parser.add_argument(
        "--kernel-auto-state",
        type=str,
        default="triage-output/kernel_auto",
        help="Directory for the --kernel-auto snapshot (run-to-run comparison) and the manual promotion ledger "
             "(default: triage-output/kernel_auto). Keep it between scheduled runs (ADR-021).",
    )
    parser.add_argument(
        "--promote",
        type=str,
        default=None,
        metavar="CVE_ID",
        help="Promote a kernel CVE found by --kernel-auto to tier 1 (treated like a KEV-listed LPE). "
             "Requires --promote-source (ADR-021).",
    )
    parser.add_argument(
        "--promote-source",
        type=str,
        default=None,
        help="Source URL that justifies --promote (e.g. a PoC write-up or a vendor advisory)",
    )
    parser.add_argument(
        "--promote-reason",
        type=str,
        default=None,
        help="Short reason recorded with --promote",
    )
    parser.add_argument(
        "--unpromote",
        type=str,
        default=None,
        metavar="CVE_ID",
        help="Remove a CVE from the manual promotion ledger",
    )
    parser.add_argument(
        "--telemetry-max-age",
        type=int,
        default=7,
        help="Telemetry older than this many days is excluded from the evidence (default: 7, 0 disables) (ADR-021)",
    )
    parser.add_argument(
        "--chain-audit",
        action="store_true",
        help="Execute Exploit Chain & Linux Kernel Exposure audit (v0.4.0)",
    )
    parser.add_argument(
        "--chain-output",
        type=str,
        default="chain_audit_report.md",
        help="Path to save the Exploit Chain audit report (default: chain_audit_report.md)",
    )
    parser.add_argument(
        "--chain-ledger",
        type=str,
        default=None,
        help="Optional path to custom kernel vulnerability ledger JSON",
    )
    parser.add_argument(
        "--epss-threshold",
        type=float,
        default=0.15,
        help="EPSS sudden jump delta threshold (default: 0.15)",
    )
    parser.add_argument(
        "--exclude",
        type=str,
        default=None,
        help="カンマ区切りの除外 glob パターン（例: '@company/*,internal-*'）。指定されたパッケージは脆弱性照会やAI推論から除外されます。",
    )

    args = parser.parse_args()

    # Run benchmark suite if requested
    if args.benchmark:
        from triage_agent.benchmark import main as benchmark_main
        benchmark_main()
        return

    # Launch GUI dashboard if requested
    if args.gui:
        from triage_agent.web_ui import run_gui
        run_gui()
        return

    # Standalone vendor checklist import (ADR-019)
    if args.import_checklist_path:
        from triage_agent.tools.vendor_workflow import import_vendor_checklist
        count, audit_p, summary = import_vendor_checklist(args.import_checklist_path, args.audit_file)
        held_note = f" (※根拠・確認者未記入による保留: {summary['no_held_count']} 件)" if summary.get("no_held_count") else ""
        conflict_note = f" (⚠️社内YESとの競合検知: {summary['conflict_count']} 件)" if summary.get("conflict_count") else ""
        console.print(f"[bold green]✓ ベンダー回答をインポートしました ({count} 件{held_note}{conflict_note}): {audit_p.resolve()}[/bold green]")
        if args.verify_code is None and not args.self_triage and args.sbom == "sample_sbom.json" and not args.output:
            # Standalone import completed
            return

    # Standalone record remediation completion (v0.3.1 / ADR-019)
    if args.record_remediation:
        from triage_agent.tools.vendor_workflow import record_remediation_completed
        try:
            res = record_remediation_completed(
                distribution_id=args.record_remediation,
                remediated_at=args.remediated_at,
                note=args.remediation_note,
            )
            saved_str = f" (短縮時間: {res.get('lead_time_saved_hours')} 時間)" if res.get("lead_time_saved_hours") is not None else ""
            console.print(
                Panel.fit(
                    f"[bold green]✓ T4 対応完了（Remediation Completed）を記録しました[/bold green]\n"
                    f"配布ID: [bold]{res['distribution_id']}[/bold]\n"
                    f"完了時刻 (T4): [cyan]{res['remediated_at']}[/cyan]\n"
                    f"総リードタイム: [yellow]{res.get('total_lead_time_hours')} 時間[/yellow]{saved_str}\n"
                    f"ステータス: [bold green]{res.get('status')}[/bold green]\n"
                    f"備考: {res.get('remediation_note') or 'なし'}",
                    border_style="green",
                )
            )
        except Exception as e:
            console.print(f"[bold red]❌ T4 記録エラー:[/bold red] {e}")
            sys.exit(1)
        return

    # Manual promotion ledger for --kernel-auto (ADR-021 decision 2)
    if args.promote or args.unpromote:
        from triage_agent.chain.kernel_history import add_manual_promotion, remove_manual_promotion
        try:
            if args.promote:
                path = add_manual_promotion(args.promote, args.promote_source, args.promote_reason, state_dir=args.kernel_auto_state)
                console.print(f"[bold green]✓ {args.promote.upper()} を層1 に昇格させました（台帳: {path}）。次の --kernel-auto 実行から反映されます。[/bold green]")
            if args.unpromote:
                if remove_manual_promotion(args.unpromote, state_dir=args.kernel_auto_state):
                    console.print(f"[bold green]✓ {args.unpromote.upper()} を手動昇格の台帳から外しました。[/bold green]")
                else:
                    console.print(f"[yellow]ℹ️ {args.unpromote.upper()} は手動昇格の台帳にありません。[/yellow]")
        except ValueError as e:
            console.print(f"[bold red]❌ {e}[/bold red]")
            sys.exit(1)
        if not args.chain_audit and args.verify_code is None and not args.self_triage and args.sbom == "sample_sbom.json" and not args.output:
            return

    # Standalone Exploit Chain audit (v0.4.0)
    chain_audit_items = None
    if args.chain_audit:
        chain_audit_items = run_chain_audit_flow(args, console)
        # If running purely for chain audit (default SBOM without explicit scan options)
        if args.verify_code is None and not args.self_triage and args.sbom == "sample_sbom.json" and not args.output:
            if args.fail_on:
                triggers = [t.strip().lower() for t in args.fail_on.split(",") if t.strip()]
                has_critical_chain = any(i.chain_level.value == "CRITICAL_CHAIN" for i in chain_audit_items)
                if ("chain" in triggers or "critical_chain" in triggers or "any" in triggers) and has_critical_chain:
                    console.print(
                        Panel(
                            "[bold red]❌ 【CI/CD ガードレール違反: --fail-on 条件発火 (Critical Exploit Chain 検知)】[/bold red]\n"
                            "未緩和のカーネルLPEと外部露出RCE足場による連鎖エクスプロイトが検知されたため、終了コード 2 で停止します。",
                            border_style="red",
                        )
                    )
                    sys.exit(2)
                promoted_reason = _kernel_promotion_reason(args) if "promoted" in triggers else None
                if promoted_reason:
                    console.print(
                        Panel(
                            "[bold red]❌ 【CI/CD ガードレール違反: --fail-on 条件発火 (promoted)】[/bold red]\n" + promoted_reason,
                            border_style="red",
                        )
                    )
                    sys.exit(2)
            return

    mode = "demo" if args.demo else ("dry-run" if args.dry_run else "live")

    sbom_path = args.sbom
    verify_code = args.verify_code

    if args.self_triage:
        console.print(
            Panel.fit(
                "[bold cyan]【SELF-TRIAGE / ソフトウェア自己診断モード（ADR-018）】[/bold cyan]\n"
                "triage-agent 自身の依存関係SBOMを動的生成し、自社コードベース（src/triage_agent）を走査して自己診断を実行します。\n"
                "「3つの鮮度」（システム・SBOM・ツール）を継続担保するためのドッグフーディング機能です。",
                border_style="cyan",
            )
        )
        if args.sbom == "sample_sbom.json":
            from triage_agent.tools.sbom import generate_self_sbom
            self_sbom_file = Path("self_sbom.json")
            generate_self_sbom(output_path=self_sbom_file, include_transitive=True)
            sbom_path = str(self_sbom_file)
        else:
            sbom_path = args.sbom

        if verify_code is None:
            verify_code = "src/triage_agent"

    if mode == "demo":
        console.print(
            Panel.fit(
                "[bold yellow]【DEMO SHOWCASE モード】[/bold yellow]\n"
                "明示的な展示用合成データ（DEMO-* プレフィックス）を使用して指示書を生成します。\n"
                "実際の外部ネットワーク調査や推論は行いません。",
                border_style="yellow",
            )
        )
    elif mode == "live" and not is_llm_configured():
        console.print(
            "[bold red]❌ エラー: LLM API が設定されていません。[/bold red]\n"
            "ライブエージェントによる自動調査・推論を行うには、以下のいずれかを設定してください：\n"
            "  1. Google AI Studio: .env または環境変数に GEMINI_API_KEY を設定\n"
            "  2. Google Cloud Vertex AI: GOOGLE_GENAI_USE_VERTEXAI=true および GCP プロジェクト/認証を設定\n\n"
            "オフラインでシミュレーションを実行したい場合は、明示的に [bold cyan]--dry-run[/bold cyan] フラグを付与してください。\n"
            "例: python -m triage_agent.cli --sbom sample_sbom.json --dry-run"
        )
        sys.exit(1)
    else:
        console.print(
            Panel.fit(
                f"[bold cyan]triage-agent[/bold cyan] : Autonomous SBOM Vulnerability Intelligence\n"
                f"[dim]Model: {get_model_name()} | SBOM: {sbom_path} | Verify: {verify_code or 'None'} | Mode: {'Dry-Run (Simulation)' if mode == 'dry-run' else 'Live Agent'}[/dim]",
                border_style="cyan",
            )
        )

    max_targets = args.max_targets
    if args.self_triage and args.max_targets == 10:
        # Cover all triage-agent internal dependencies fully without artificial omission
        max_targets = 50

    from triage_agent.pipeline import execute_triage_pipeline

    exclude_patterns = [p.strip() for p in args.exclude.split(",") if p.strip()] if getattr(args, "exclude", None) else None

    try:
        triage_report, audit_report = execute_triage_pipeline(
            sbom_path=sbom_path,
            mode=mode,
            max_targets=max_targets,
            code_dir=verify_code,
            audit_file_path=args.audit_file,
            target_environment=args.environment,
            progress_callback=lambda msg: console.print(f"[dim]{msg}[/dim]"),
            exclude_patterns=exclude_patterns,
        )
    except Exception as e:
        console.print(f"[bold red]❌ パイプライン実行エラー:[/bold red] {e}")
        sys.exit(1)

    console.print()

    # Display Report in Terminal
    if triage_report.is_dry_run:
        console.print(
            Panel(
                "[bold yellow]⚠️ 【DRY-RUN / シミュレーション実行】[/bold yellow]\n"
                "本レポートはオフライン静的解析によるシミュレーション結果です。\n"
                "RCE有無の精読や修正パッチバージョンの確定判断は、ライブエージェント（GEMINI_API_KEY設定環境）で実行してください。",
                border_style="yellow",
            )
        )

    if triage_report.unscanned_or_failed_components:
        console.print(
            Panel(
                "[bold red]🚨 【警告: 調査不能・未調査コンポーネント】[/bold red]\n"
                + "\n".join([f"• {u}" for u in triage_report.unscanned_or_failed_components])
                + "\n\n[dim]未調査のコンポーネントを安全と誤認してはなりません。[/dim]",
                border_style="red",
            )
        )

    if triage_report.recon_coverage_summary:
        console.print(
            Panel(
                f"[bold blue]ℹ️ 【調査カバレッジ・深度サマリ】[/bold blue]\n{triage_report.recon_coverage_summary}",
                border_style="blue",
            )
        )

    if getattr(triage_report, "excluded_components", None):
        is_ci = bool(os.getenv("CI") or os.getenv("GITHUB_ACTIONS"))
        if is_ci:
            content = (
                f"プライバシーおよびCIログ漏洩防止のため、パッケージ名は非表示とし件数のみ開示します。\n"
                f"（合計: {len(triage_report.excluded_components)} 件を外部API照会およびLLM推論から除外）"
            )
        else:
            names_preview = "\n".join([f"• {u}" for u in triage_report.excluded_components[:10]])
            if len(triage_report.excluded_components) > 10:
                names_preview += f"\n• ... ほか {len(triage_report.excluded_components) - 10} 件"
            content = (
                f"{names_preview}\n\n"
                f"[dim]プライバシー保護のため、外部API照会およびLLM推論から除外されました（CI環境では件数のみ開示されます）。[/dim]"
            )
        console.print(
            Panel(
                f"[bold cyan]🛡️ 【--exclude による除外コンポーネント（計 {len(triage_report.excluded_components)} 件）】[/bold cyan]\n"
                + content,
                border_style="cyan",
            )
        )

    if triage_report.osv_unsupported_components:
        console.print(
            Panel(
                "[bold blue]ℹ️ 【OSV.dev 照合対象外（ランタイム・OS共有ライブラリ）】[/bold blue]\n"
                + "\n".join([f"• {u}" for u in triage_report.osv_unsupported_components])
                + "\n\n[dim]言語パッケージ外のためOSV一括照会から除外され、Web/LLM調査対象となります。[/dim]",
                border_style="blue",
            )
        )

    if triage_report.pre_announcements:
        cal_table = Table(show_lines=True, header_style="bold green")
        cal_table.add_column("対象", style="bold")
        cal_table.add_column("予定日 / 時期", style="bold yellow")
        cal_table.add_column("予告概要", style="dim")
        cal_table.add_column("情報源 (公式度)", style="cyan")
        cal_table.add_column("事前準備チェックリスト", style="green")

        for pa in triage_report.pre_announcements:
            d_str = pa.expected_date or "事前監視チャンネル"
            if pa.expected_time:
                d_str += f"\n({pa.expected_time})"
            tag = "公式一次情報" if pa.is_official else "未確認の予兆"
            cl_str = "\n".join([f"• {item}" for item in pa.recommended_preparations])
            cal_table.add_row(
                pa.component_name,
                d_str,
                f"[{pa.severity_hint or '要確認'}]\n{pa.title}",
                f"{pa.source_name}\n({tag})",
                cl_str,
            )

        console.print(
            Panel(
                cal_table,
                title="[bold green]📅 【事前パッチ予告・定期更新スケジュール (Early Warning Calendar)】[/bold green]",
                subtitle="[dim]突発的な緊急対応を、コントロールされた計画作業へ (iCalendar出力: --calendar <path.ics>)[/dim]",
                border_style="green",
            )
        )

    for notice in triage_report.notices:
        console.print(
            Panel(
                f"[bold yellow]結論：[/bold yellow]{notice.conclusion}\n"
                f"[bold]公開日：[/bold]{notice.announcement_date} | [bold]修正版：[/bold]{notice.fixed_versions}\n"
                f"[bold]深刻度：[/bold]{notice.severity_note}\n\n"
                f"[dim]{notice.pre_check_note}[/dim]",
                title=f"[bold cyan]▼ {notice.product_name}[/bold cyan]",
                border_style="cyan",
            )
        )

        table = Table(show_lines=True, header_style="bold magenta")
        table.add_column("対象 / CVE (CVSS)", style="bold")
        table.add_column("内容", style="dim")
        table.add_column("影響バージョン", style="yellow")
        table.add_column("確認ポイント（Yes/No）", style="bold red")
        table.add_column("確認方法", style="green")

        for cp in notice.check_points:
            table.add_row(
                cp.target_or_cve,
                cp.content_summary,
                cp.affected_versions,
                cp.check_point_yes_no,
                cp.verification_method,
            )

        console.print(table)
        if notice.workaround:
            console.print(f"[bold cyan]回避策：[/bold cyan]{notice.workaround}")
        if notice.unconfirmed_points:
            console.print("[bold dim]未確認事項：[/bold dim]" + " / ".join(notice.unconfirmed_points))
        console.print()

    # Optional file output
    if args.output:
        out_path = Path(args.output)
        if args.output.endswith(".json"):
            out_path.write_text(triage_report.model_dump_json(indent=2), encoding="utf-8")
        else:
            md_content = format_report_markdown(triage_report)
            out_path.write_text(md_content, encoding="utf-8")
        console.print(f"[bold green]✓ 現場即応トリアージ指示書を出力しました: {out_path.resolve()}[/bold green]\n")

    # Optional iCalendar file output (ADR-020)
    if args.calendar_output:
        from triage_agent.tools.calendar import export_icalendar_file
        cal_path = export_icalendar_file(triage_report.pre_announcements, args.calendar_output)
        console.print(f"[bold green]✓ カレンダー予定表（iCalendar .ics）を出力しました: {cal_path.resolve()}[/bold green]\n")

    # Optional vendor checklist CSV export (ADR-019)
    if args.export_checklist_path:
        from triage_agent.tools.vendor_workflow import export_checklist_csv
        if not args.export_checklist_target:
            console.print(
                "[yellow]ℹ️ 絞り込み対象（--export-checklist-target）が未指定のため、全コンポーネントの確認ポイントを出力します"
                "（社外委託先配布時の共有範囲・攻撃地図化にご注意ください）。[/yellow]"
            )
        _, csv_path, dist_id = export_checklist_csv(
            triage_report,
            output_path=args.export_checklist_path,
            target_product=args.export_checklist_target,
        )
        console.print(f"[bold green]✓ ベンダー照会用早見表（CSV, {dist_id}）を出力しました: {csv_path.resolve()}[/bold green]\n")

    # Optional automated codebase or vendor verification output
    if audit_report:
        from triage_agent.verifier import format_verification_markdown
        audit_file = Path(args.verify_output)
        audit_file.write_text(format_verification_markdown(audit_report), encoding="utf-8")
        console.print(f"[bold green]✓ 検証結果レポートを出力しました: {audit_file.resolve()}[/bold green]\n")

    # Optional exploit chain audit execution if configured
    if args.chain_audit and chain_audit_items is None:
        chain_audit_items = run_chain_audit_flow(args, console)

    # Enforce non-zero exit codes if --fail-on conditions are met
    if args.fail_on:
        triggers = [t.strip().lower() for t in args.fail_on.split(",") if t.strip()]
        triggered_reasons = []

        has_unscanned = bool(triage_report.unscanned_or_failed_components)
        has_excluded = bool(getattr(triage_report, "excluded_components", None))
        has_yes = False
        has_unconfirmed = False
        has_critical_chain = False

        if chain_audit_items:
            has_critical_chain = any(i.chain_level.value == "CRITICAL_CHAIN" for i in chain_audit_items)

        if audit_report:
            for nr in audit_report.notice_results:
                for cr in nr.results:
                    status = cr.status.upper()
                    if "YES" in status:
                        has_yes = True
                    elif "未検出" in status or "要確認" in status:
                        has_unconfirmed = True

        if ("unscanned" in triggers or "any" in triggers) and has_unscanned:
            triggered_reasons.append(
                f"調査不能・未調査コンポーネントが {len(triage_report.unscanned_or_failed_components)} 件存在します"
            )

        if "excluded" in triggers and has_excluded:
            triggered_reasons.append(
                f"--exclude により除外されたコンポーネントが {len(triage_report.excluded_components)} 件存在します"
            )

        if ("yes" in triggers or "any" in triggers) and has_yes:
            triggered_reasons.append("ソースコード内から脆弱性発火条件（YES判定）が検出されました")

        if ("unconfirmed" in triggers or "any" in triggers) and has_unconfirmed:
            triggered_reasons.append("外部設定・既定値の要確認項目（未サインオフ）が存在します")

        if ("chain" in triggers or "critical_chain" in triggers or "any" in triggers) and has_critical_chain:
            triggered_reasons.append("未緩和のカーネルLPEと外部露出RCE足場による連鎖エクスプロイト（Critical Exploit Chain）が検知されました")

        if "promoted" in triggers:
            promoted_reason = _kernel_promotion_reason(args)
            if promoted_reason:
                triggered_reasons.append(promoted_reason)

        if triggered_reasons:
            console.print(
                Panel(
                    "[bold red]❌ 【CI/CD ガードレール違反: --fail-on 条件発火】[/bold red]\n"
                    + "\n".join([f"• {r}" for r in triggered_reasons])
                    + "\n\n[dim]パイプラインのサイレント成功を防ぐため、非ゼロの終了コード（exit 2）で停止します。[/dim]",
                    border_style="red",
                )
            )
            sys.exit(2)


if __name__ == "__main__":
    main()
