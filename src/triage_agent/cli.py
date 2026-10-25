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
        help="Override Gemini model name (default: reads GEMINI_MODEL or gemini-2.5-flash)",
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
        "--gui",
        action="store_true",
        help="Launch the interactive Web GUI dashboard in your browser",
    )

    args = parser.parse_args()

    # Launch GUI dashboard if requested
    if args.gui:
        from triage_agent.web_ui import run_gui
        run_gui()
        return

    # Dynamic model override
    if args.model:
        os.environ["GEMINI_MODEL"] = args.model

    mode = "demo" if args.demo else ("dry-run" if args.dry_run else "live")

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
                f"[dim]Model: {get_model_name()} | SBOM: {args.sbom} | Mode: {'Dry-Run (Simulation)' if mode == 'dry-run' else 'Live Agent'}[/dim]",
                border_style="cyan",
            )
        )

    from triage_agent.pipeline import execute_triage_pipeline

    try:
        triage_report, audit_report = execute_triage_pipeline(
            sbom_path=args.sbom,
            mode=mode,
            max_targets=args.max_targets,
            code_dir=args.verify_code,
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

    # Optional automated codebase or vendor verification output
    if audit_report:
        from triage_agent.verifier import format_verification_markdown
        audit_file = Path(args.verify_output)
        audit_file.write_text(format_verification_markdown(audit_report), encoding="utf-8")
        console.print(f"[bold green]✓ 検証結果レポートを出力しました: {audit_file.resolve()}[/bold green]\n")


if __name__ == "__main__":
    main()
