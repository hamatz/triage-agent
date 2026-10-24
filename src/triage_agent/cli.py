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
from triage_agent.config import get_gemini_api_key, get_model_name
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

    args = parser.parse_args()

    # Dynamic model override
    if args.model:
        os.environ["GEMINI_MODEL"] = args.model

    api_key = get_gemini_api_key()
    is_dry_run = args.dry_run

    # CRITICAL: Prevent silent failure fallback!
    if not is_dry_run and not api_key:
        console.print(
            "[bold red]❌ エラー: GEMINI_API_KEY が設定されていません。[/bold red]\n"
            "ライブエージェントによる自動調査・推論を行うには、.env または環境変数に GEMINI_API_KEY を設定してください。\n"
            "オフラインでシミュレーションを実行したい場合は、明示的に [bold cyan]--dry-run[/bold cyan] フラグを付与してください。\n"
            "例: python -m triage_agent.cli --sbom sample_sbom.json --dry-run"
        )
        sys.exit(1)

    console.print(
        Panel.fit(
            f"[bold cyan]triage-agent[/bold cyan] : Autonomous SBOM Vulnerability Intelligence\n"
            f"[dim]Model: {get_model_name()} | SBOM: {args.sbom} | Mode: {'Dry-Run (Simulation)' if is_dry_run else 'Live Agent'}[/dim]",
            border_style="cyan",
        )
    )

    unscanned_items: List[str] = []

    # -------------------------------------------------------------
    # Phase 1: Recon Planner
    # -------------------------------------------------------------
    console.print("[bold green]▶ [1/3] Recon Planner: SBOM解析および巡回戦略策定中...[/bold green]")
    try:
        from triage_agent.tools.sbom import load_sbom_summary
        from triage_agent.tools.osv import query_osv_batch

        components = load_sbom_summary(args.sbom)
        osv_hits, osv_errors = query_osv_batch(components)

        if osv_errors:
            console.print(f"[bold red]⚠️ OSV.dev 一括照会エラー:[/bold red] {'; '.join(osv_errors)}")
            unscanned_items.append(f"OSV.dev 一括照会失敗: {'; '.join(osv_errors)}")

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
                targets.append(
                    ReconTarget(
                        name=c.name,
                        version=c.version,
                        ecosystem=c.ecosystem,
                        github_repo=repo_map.get(c.name, f"{c.name}/{c.name}"),
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
                targets=targets[:args.max_targets],
            )
        else:
            recon_plan = run_recon_planner(args.sbom, osv_results=osv_hits)
            recon_plan.targets = recon_plan.targets[:args.max_targets]

    except Exception as e:
        console.print(f"[bold red]Recon Planner Error:[/bold red] {e}")
        sys.exit(1)

    # Note any components beyond max_targets
    if len(components) > len(recon_plan.targets):
        remaining_count = len(components) - len(recon_plan.targets)
        unscanned_items.append(
            f"上限（--max-targets {args.max_targets}）により深層調査を省略したコンポーネント（計 {remaining_count} 件）"
        )

    plan_table = Table(title="Recon Planner - 選定された深層調査ターゲット", show_lines=True)
    plan_table.add_column("Priority", style="bold red")
    plan_table.add_column("Component", style="cyan")
    plan_table.add_column("Version", style="magenta")
    plan_table.add_column("GitHub Repo", style="green")
    plan_table.add_column("Rationale")

    for t in recon_plan.targets:
        plan_table.add_row(t.priority, t.name, t.version, t.github_repo or "-", t.rationale)

    console.print(plan_table)
    console.print(f"[dim]スキャン対象: 全 {len(components)} 件中、上位 {len(recon_plan.targets)} 件を深層調査。[/dim]\n")

    # -------------------------------------------------------------
    # Phase 2: Dynamic Researcher (Target-by-Target)
    # -------------------------------------------------------------
    console.print(f"[bold green]▶ [2/3] Researcher: {len(recon_plan.targets)} コンポーネントの動的調査・事前予告探索中...[/bold green]")
    research_results: List[TargetResearchResult] = []

    for idx, target in enumerate(recon_plan.targets, 1):
        console.print(f"  [{idx}/{len(recon_plan.targets)}] 調査中: [cyan]{target.name}[/cyan] ({target.version})...")
        try:
            res = run_researcher(target, dry_run=is_dry_run)
            research_results.append(res)
            console.print(f"    ✓ 発見シグナル数: [bold yellow]{len(res.findings)}[/bold yellow] 件")
            for f in res.findings:
                pre_flag = "[bold magenta][PRE-ANNOUNCEMENT][/bold magenta] " if f.is_pre_announcement else ""
                console.print(f"      - {pre_flag}[bold]{f.id}[/bold]: {f.title[:70]}...")
        except Exception as e:
            console.print(f"    [red]調査失敗 ({target.name}):[/red] {e}")
            unscanned_items.append(f"{target.name}: 調査処理エラー ({str(e)})")

    console.print()

    # -------------------------------------------------------------
    # Phase 3: Triage & Action Generation
    # -------------------------------------------------------------
    console.print("[bold green]▶ [3/3] Triage Agent: 発火条件特定・現場即応指示書生成中...[/bold green]")
    try:
        triage_report = run_triage_agent(
            research_results=research_results,
            unscanned_components=unscanned_items,
            dry_run=is_dry_run,
        )
    except Exception as e:
        console.print(f"[bold red]Triage Agent Error:[/bold red] {e}")
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

    # Optional automated codebase verification
    if args.verify_code:
        from triage_agent.verifier import format_verification_markdown, verify_codebase
        console.print(f"[bold cyan]▶ 自社コードベース自動検証を実行中: {args.verify_code}...[/bold cyan]")
        audit_report = verify_codebase(triage_report, args.verify_code)
        audit_file = Path(args.verify_output)
        audit_file.write_text(format_verification_markdown(audit_report), encoding="utf-8")
        console.print(f"[bold green]✓ 自社検証結果レポートを出力しました: {audit_file.resolve()}[/bold green]\n")


if __name__ == "__main__":
    main()
