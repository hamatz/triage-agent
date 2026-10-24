import argparse
import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport

console = Console()

# Standard file extensions to scan in codebases
TARGET_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".xml", ".yaml", ".yml", ".json", ".ini", ".conf", ".toml", ".env",
    ".properties", ".gradle", ".dockerfile", "Dockerfile"
}

IGNORE_DIRS = {
    ".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__",
    ".idea", ".vscode", "target", ".next", ".nuxt"
}


class MatchSnippet(BaseModel):
    file_path: str
    line_number: int
    line_content: str


class CheckVerificationResult(BaseModel):
    check_point: CheckPointItem
    status: str = Field(description="'YES (要対応)', 'NO (安全)', or '要手動確認'")
    matches: List[MatchSnippet] = Field(default_factory=list)
    reasoning: str


class NoticeVerificationResult(BaseModel):
    notice: TriageNotice
    overall_status: str = Field(description="'YES (要対応)' or 'NO (安全)'")
    action_deadline_advice: str
    results: List[CheckVerificationResult] = Field(default_factory=list)


class CodebaseAuditReport(BaseModel):
    code_dir: str
    overall_status: str
    summary_counts: Dict[str, int]
    notice_results: List[NoticeVerificationResult] = Field(default_factory=list)


def extract_keywords_from_method(text: str) -> List[str]:
    """Extract code tokens, XML tags, function calls, or config keys from verification method text."""
    # Look for tokens in quotes, backticks, or tokens with parentheses / dots / brackets
    patterns = set()

    # Backtick tokens: `stream(` -> stream(
    for token in re.findall(r"`([^`]+)`", text):
        cleaned = token.strip()
        if len(cleaned) >= 3:
            patterns.add(cleaned)

    # XML tags like <Connector or <async-supported
    for tag in re.findall(r"<([a-zA-Z0-9_\-]+)", text):
        patterns.add(f"<{tag}")

    # Specific common keywords
    for kw in ["stream(", "read_chunked(", "HTTPS_PROXY", "ProxyManager", "jwt.verify", "serialize_handler", "upload_progress"]:
        if kw.lower() in text.lower():
            patterns.add(kw)

    return list(patterns)


def scan_directory_for_patterns(code_dir: Path, patterns: List[str], max_matches: int = 5) -> List[MatchSnippet]:
    """Scan code directory for occurrences of patterns, returning line snippets."""
    if not patterns:
        return []

    matches: List[MatchSnippet] = []

    for root, dirs, files in os.walk(code_dir):
        # Filter out ignored directories
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]

        for fname in files:
            fpath = Path(root) / fname
            suffix = fpath.suffix.lower()

            if suffix in TARGET_EXTENSIONS or fname in TARGET_EXTENSIONS:
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        for line_no, line in enumerate(f, 1):
                            line_str = line.strip()
                            if not line_str or line_str.startswith("#") or line_str.startswith("//"):
                                continue

                            for p in patterns:
                                if p in line:
                                    rel_path = str(fpath.relative_to(code_dir))
                                    matches.append(
                                        MatchSnippet(
                                            file_path=rel_path,
                                            line_number=line_no,
                                            line_content=line_str[:120],
                                        )
                                    )
                                    if len(matches) >= max_matches:
                                        return matches
                except Exception:
                    continue

    return matches


def verify_codebase(report: TriageReport, code_dir_path: str) -> CodebaseAuditReport:
    """Run automated code inspection against a local codebase based on TriageReport check points."""
    code_dir = Path(code_dir_path).resolve()
    if not code_dir.exists():
        raise FileNotFoundError(f"Codebase directory not found: {code_dir_path}")

    notice_results: List[NoticeVerificationResult] = []
    total_yes = 0
    total_no = 0

    for notice in report.notices:
        check_results: List[CheckVerificationResult] = []
        any_yes = False

        for cp in notice.check_points:
            patterns = extract_keywords_from_method(f"{cp.check_point_yes_no} {cp.verification_method}")
            matches = scan_directory_for_patterns(code_dir, patterns)

            if matches:
                status = "YES (要対応)"
                any_yes = True
                total_yes += 1
                reason = f"自社コード内で発火キーワード（{', '.join(patterns)}）の利用を {len(matches)} 箇所検知"
            else:
                status = "NO (安全)"
                total_no += 1
                reason = f"該当設定・API呼び出し（{', '.join(patterns) if patterns else '対象設定'}）はコード内に見つかりません"

            check_results.append(
                CheckVerificationResult(
                    check_point=cp,
                    status=status,
                    matches=matches,
                    reasoning=reason,
                )
            )

        if any_yes:
            overall_status = "YES (要対応)"
            deadline_advice = "【緊急対応要】自社コード内に発火条件を検知したため、外部公開システムは7日以内（または指示書記載の期限）に設定変更またはパッチを適用してください。"
        else:
            overall_status = "NO (安全)"
            deadline_advice = "【通常リリース可】自社コード内で発火設定は検出されませんでした。通常リリース（30日以内）での更新対応で問題ありません。"

        notice_results.append(
            NoticeVerificationResult(
                notice=notice,
                overall_status=overall_status,
                action_deadline_advice=deadline_advice,
                results=check_results,
            )
        )

    overall_codebase_status = "YES (要対応)" if total_yes > 0 else "NO (安全)"

    return CodebaseAuditReport(
        code_dir=str(code_dir),
        overall_status=overall_codebase_status,
        summary_counts={"total_checks": total_yes + total_no, "yes_count": total_yes, "no_count": total_no},
        notice_results=notice_results,
    )


def format_verification_markdown(audit: CodebaseAuditReport) -> str:
    """Format the CodebaseAuditReport into an executive and technical Markdown report."""
    lines = [
        "# 自社コードベース脆弱性発火条件・検証結果レポート",
        "",
        f"**対象コードベース:** `{audit.code_dir}`",
        f"**総合判定:** `{'【要対応あり (ACTION REQUIRED)】' if audit.overall_status.startswith('YES') else '【安全・通常対応可 (SAFE)】'}`",
        "",
        "## 1. 検証サマリ",
        f"- **総検査項目数:** {audit.summary_counts.get('total_checks', 0)} 件",
        f"- **判定: YES (発火条件該当・要対応):** {audit.summary_counts.get('yes_count', 0)} 件",
        f"- **判定: NO (該当なし・安全):** {audit.summary_counts.get('no_count', 0)} 件",
        "",
        "---",
        "",
        "## 2. プロダクト別詳細検証結果",
    ]

    for n_res in audit.notice_results:
        notice = n_res.notice
        lines.extend([
            f"### {notice.product_name}",
            f"**自社判定結果:** `{n_res.overall_status}`",
            f"**対応方針:** {n_res.action_deadline_advice}",
            "",
            "| 対象 / CVE (CVSS) | 確認ポイント（Yes/No） | 自社判定 | 検出コード / 判定根拠 |",
            "| :--- | :--- | :--- | :--- |",
        ])

        for c_res in n_res.results:
            cp = c_res.check_point
            target_cve = cp.target_or_cve.replace("|", "/")
            yes_no_q = cp.check_point_yes_no.replace("|", "/")
            status = c_res.status

            if c_res.matches:
                match_desc = "<br>".join(
                    [f"• `{m.file_path}:{m.line_number}`: `{m.line_content}`" for m in c_res.matches]
                )
            else:
                match_desc = f"{c_res.reasoning}"

            lines.append(f"| {target_cve} | {yes_no_q} | **{status}** | {match_desc} |")

        lines.append("")
        if notice.workaround and n_res.overall_status.startswith("YES"):
            lines.append(f"> **推奨回避策:** {notice.workaround}")
            lines.append("")

        lines.append("---")
        lines.append("")

    return "\n".join(lines)


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

    audit_report = verify_codebase(report, args.code_dir)

    # Console display
    status_color = "red" if audit_report.overall_status.startswith("YES") else "green"
    console.print(
        Panel(
            f"[bold]総合判定:[/bold] [{status_color}]{audit_report.overall_status}[/{status_color}]\n"
            f"総項目: {audit_report.summary_counts['total_checks']} 件 | "
            f"[bold red]YES (要対応): {audit_report.summary_counts['yes_count']} 件[/bold red] | "
            f"[bold green]NO (安全): {audit_report.summary_counts['no_count']} 件[/bold green]",
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
            table.add_row(
                c_res.check_point.target_or_cve,
                c_res.check_point.check_point_yes_no,
                f"[{'bold red' if c_res.status.startswith('YES') else 'bold green'}]{c_res.status}[/]",
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
