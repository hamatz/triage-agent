"""Command line interface for triage-verifier."""

import argparse
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from triage_agent.schemas import TriageReport
from triage_agent.verifier.engine import verify_codebase
from triage_agent.verifier.report import format_verification_markdown

console = Console()


def main():
    parser = argparse.ArgumentParser(
        description="triage-agent verifier: Automatically verify codebase against Triage Report check points"
    )
    parser.add_argument(
        "--report",
        type=str,
        default="triage_report.json",
        help="Path to TriageReport JSON file (generated with triage-agent --output triage_report.json)",
    )
    parser.add_argument(
        "--code-dir",
        type=str,
        default=".",
        help="Path to the source code repository directory to inspect (default: current directory)",
    )
    parser.add_argument(
        "--audit-file",
        type=str,
        default=None,
        help="Optional path to human audit sign-off file (e.g. audit_signoff.json) to record verified safe settings",
    )
    parser.add_argument(
        "--environment",
        type=str,
        default=None,
        help="Target environment (e.g. 'Production', 'Staging', 'Development') to enforce sign-off scope",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="verification_audit_report.md",
        help="Path to save the verification markdown report (default: verification_audit_report.md)",
    )

    args = parser.parse_args()

    report_path = Path(args.report)
    if not report_path.exists():
        console.print(f"[bold red]Error:[/bold red] Triage report JSON not found at '{args.report}'.")
        console.print("[dim]Hint: First run: python -m triage_agent.cli --output triage_report.json[/dim]")
        return

    try:
        report = TriageReport.model_validate_json(report_path.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[bold red]Failed to parse triage report:[/bold red] {e}")
        return

    console.print(
        Panel.fit(
            f"[bold cyan]triage-verifier[/bold cyan] : 自社コードベース脆弱性発火条件・自動検証ツール\n"
            f"[dim]Report: {args.report} | Target Codebase: {Path(args.code_dir).resolve()}[/dim]",
            border_style="cyan",
        )
    )

    audit_report = verify_codebase(
        report,
        args.code_dir,
        audit_file_path=args.audit_file,
        target_environment=args.environment,
    )

    # Console display with corrected color logic (Fixed '要手動確認' being green)
    if audit_report.overall_status.startswith("YES"):
        status_color = "red"
    elif "確認" in audit_report.overall_status or "未検出" in audit_report.overall_status:
        status_color = "yellow"
    else:
        status_color = "green"

    console.print(
        Panel(
            f"[bold]総合判定:[/bold] [{status_color}]{audit_report.overall_status}[/{status_color}]\n"
            f"総項目: {audit_report.summary_counts['total_checks']} 件 | "
            f"[bold red]YES (該当・要対応): {audit_report.summary_counts['yes_count']} 件[/bold red] | "
            f"[bold yellow]要確認 (外部設定/手動確認): {audit_report.summary_counts['unverified_count']} 件[/bold yellow] | "
            f"[bold green]NO (確認済・安全): {audit_report.summary_counts['safe_count']} 件[/bold green]",
            title="[bold]自社コードベース検証結果サマリ[/bold]",
            border_style=status_color,
        )
    )

    for n_res in audit_report.notice_results:
        table = Table(title=f"▼ {n_res.notice.product_name}", show_lines=True)
        table.add_column("対象 / CVE", style="bold")
        table.add_column("確認ポイント（Yes/No）")
        table.add_column("自社判定", style="bold")
        table.add_column("検出コード / 判定根拠", style="dim")

        for c_res in n_res.results:
            # Color logic: NO (safe/signoff) is green even if it contains "確認"; YES is red; unverified is yellow
            if c_res.status.startswith("YES"):
                c_color = "bold red"
            elif c_res.status.startswith("NO"):
                c_color = "bold green"
            elif "確認" in c_res.status or "未検出" in c_res.status:
                c_color = "bold yellow"
            else:
                c_color = "bold white"

            table.add_row(
                c_res.check_point.target_or_cve,
                c_res.check_point.check_point_yes_no,
                f"[{c_color}]{c_res.status}[/]",
                c_res.reasoning if not c_res.matches else f"{len(c_res.matches)}箇所検出: {c_res.matches[0].file_path}:{c_res.matches[0].line_number}",
            )
        console.print(table)
        console.print()

    # Save output
    out_path = Path(args.output)
    md_content = format_verification_markdown(audit_report)
    out_path.write_text(md_content, encoding="utf-8")
    console.print(f"[bold green]✓ 自社検証結果レポートを出力しました: {out_path.resolve()}[/bold green]\n")


if __name__ == "__main__":
    main()
