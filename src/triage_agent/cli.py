import argparse
import json
import os
import sys
from pathlib import Path
from typing import List

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
             "Supported: unscanned (uninvestigated components/errors), yes (vulnerable code confirmed), "
             "unconfirmed (unverified external settings), any.",
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
        "--gui",
        action="store_true",
        help="Launch the interactive Web GUI dashboard in your browser",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run the ground-truth benchmark suite for Verifier and feeds (ADR-019 / Pillar 4)",
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

    try:
        triage_report, audit_report = execute_triage_pipeline(
            sbom_path=sbom_path,
            mode=mode,
            max_targets=max_targets,
            code_dir=verify_code,
            audit_file_path=args.audit_file,
            progress_callback=lambda msg: console.print(f"[dim]{msg}[/dim]"),
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

    # Enforce non-zero exit codes if --fail-on conditions are met
    if args.fail_on:
        triggers = [t.strip().lower() for t in args.fail_on.split(",") if t.strip()]
        triggered_reasons = []

        has_unscanned = bool(triage_report.unscanned_or_failed_components)
        has_yes = False
        has_unconfirmed = False

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

        if ("yes" in triggers or "any" in triggers) and has_yes:
            triggered_reasons.append("ソースコード内から脆弱性発火条件（YES判定）が検出されました")

        if ("unconfirmed" in triggers or "any" in triggers) and has_unconfirmed:
            triggered_reasons.append("外部設定・既定値の要確認項目（未サインオフ）が存在します")

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
