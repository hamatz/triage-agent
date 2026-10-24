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
    status: str = Field(description="'YES (該当・要対応)', 'コード内未検出 (外部設定/既定値の要確認)', or '要手動確認'")
    matches: List[MatchSnippet] = Field(default_factory=list)
    reasoning: str
    external_check_advice: Optional[str] = Field(
        default=None,
        description="Advice on external config files (e.g. php.ini, server.xml, env vars, K8s manifests)"
    )


class NoticeVerificationResult(BaseModel):
    notice: TriageNotice
    overall_status: str = Field(description="'YES (該当・要対応)', '要確認 (外部設定・環境設定の確認要)', or 'NO (安全)'")
    action_deadline_advice: str
    results: List[CheckVerificationResult] = Field(default_factory=list)


class CodebaseAuditReport(BaseModel):
    code_dir: str
    overall_status: str
    summary_counts: Dict[str, int]
    notice_results: List[NoticeVerificationResult] = Field(default_factory=list)


def extract_keywords_from_method(text: str) -> List[str]:
    """Extract code tokens, XML tags, function calls, or config keys from verification method text."""
    patterns = set()

    # Backtick tokens: `stream(` -> stream(
    for token in re.findall(r"`([^`]+)`", text):
        cleaned = token.strip()
        if len(cleaned) >= 3:
            patterns.add(cleaned)

    # XML tags like <Connector or <UpgradeProtocol
    for tag in re.findall(r"<([a-zA-Z0-9_\-]+)", text):
        patterns.add(f"<{tag}")

    # Specific common keywords
    for kw in [
        "stream(", "read_chunked(", "HTTPS_PROXY", "ProxyManager",
        "jwt.verify", "serialize_handler", "upload_progress",
        "Http2Protocol", "asyncSupported", "startAsync()", "JNDIRealm"
    ]:
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
    """Run automated code inspection against a local codebase based on TriageReport check points.
    
    Adheres to the core enterprise security principle:
    '不明・未検出は安全ではなく該当あり（要確認）として扱う。確実な否定証拠がない限り安全と断定しない。'
    """
    code_dir = Path(code_dir_path).resolve()
    if not code_dir.exists():
        raise FileNotFoundError(f"Codebase directory not found: {code_dir_path}")

    notice_results: List[NoticeVerificationResult] = []
    total_yes = 0
    total_unverified = 0
    total_safe = 0

    for notice in report.notices:
        check_results: List[CheckVerificationResult] = []
        has_yes = False
        has_unverified = False

        for cp in notice.check_points:
            patterns = extract_keywords_from_method(f"{cp.check_point_yes_no} {cp.verification_method}")
            
            # If no pattern could be extracted, it requires manual inspection
            if not patterns:
                status = "要手動確認 (キーワード抽出不能)"
                has_unverified = True
                total_unverified += 1
                reason = "確認方法が自然言語またはインフラ依存のため、自動検索キーワードを抽出できませんでした。手動での確認が必要です。"
                advice = cp.verification_method
                matches = []
            else:
                matches = scan_directory_for_patterns(code_dir, patterns)
                if matches:
                    status = "YES (該当・要対応)"
                    has_yes = True
                    total_yes += 1
                    reason = f"自社リポジトリ内で発火キーワード（{', '.join(patterns)}）の利用を {len(matches)} 箇所検出しました。"
                    advice = f"該当箇所（{matches[0].file_path}:{matches[0].line_number} 等）の設定および呼び出し引数を修正してください。"
                else:
                    # In enterprise security, not finding in code does NOT mean safe!
                    # It could be default-enabled (e.g. upload_progress) or in external configs (php.ini, server.xml, K8s, env)
                    status = "コード内未検出 (外部設定/既定値の要確認)"
                    has_unverified = True
                    total_unverified += 1
                    reason = (
                        f"リポジトリ内のコードでは '{', '.join(patterns)}' は未検出でした。"
                        "ただし、ミドルウェアの既定値（デフォルト有効）や、外部設定ファイル"
                        "（php.ini, server.xml, 環境変数, コンテナマニフェスト等）で有効化されている可能性があります。"
                    )
                    advice = f"外部設定（{cp.verification_method[:80]}...）の有無を確認してください。"

            check_results.append(
                CheckVerificationResult(
                    check_point=cp,
                    status=status,
                    matches=matches,
                    reasoning=reason,
                    external_check_advice=advice,
                )
            )

        # Determine overall product status adhering to: "不明は該当あり（要確認）"
        if has_yes:
            overall_status = "YES (該当・要対応)"
            deadline_advice = (
                "【緊急対応要】自社コード内に発火条件を検知しました。"
                "外部公開システムは指示書記載の期限（Critical: 48時間以内、High: 7日以内）に設定変更またはパッチを適用してください。"
            )
        elif has_unverified:
            overall_status = "要確認 (外部設定・環境設定の確認要)"
            deadline_advice = (
                "【要確認（不明は該当あり扱い）】ソースコード内では未検出ですが、外部設定（php.ini, server.xml, 環境変数等）"
                "または既定値で有効になっている可能性があります。外部設定の確認が完了するまでは『要対応』として扱ってください。"
            )
        else:
            overall_status = "NO (安全)"
            deadline_advice = "【通常リリース可】自社環境において非該当であることが確認されました。"

        notice_results.append(
            NoticeVerificationResult(
                notice=notice,
                overall_status=overall_status,
                action_deadline_advice=deadline_advice,
                results=check_results,
            )
        )

    # Determine overall codebase status
    if total_yes > 0:
        overall_codebase_status = "YES (該当あり・緊急対応要)"
    elif total_unverified > 0:
        overall_codebase_status = "要確認 (外部設定・環境設定の確認要)"
    else:
        overall_codebase_status = "NO (安全・通常対応可)"

    return CodebaseAuditReport(
        code_dir=str(code_dir),
        overall_status=overall_codebase_status,
        summary_counts={
            "total_checks": total_yes + total_unverified + total_safe,
            "yes_count": total_yes,
            "unverified_count": total_unverified,
            "safe_count": total_safe,
        },
        notice_results=notice_results,
    )


def format_verification_markdown(audit: CodebaseAuditReport) -> str:
    """Format the CodebaseAuditReport into an executive and technical Markdown report."""
    lines = [
        "# 自社コードベース脆弱性発火条件・検証結果レポート",
        "",
        f"**対象コードベース:** `{audit.code_dir}`",
        f"**総合判定:** `{audit.overall_status}`",
        "",
        "> ⚠️ **【重要判定基準】** 本検証は自社リポジトリ内のソースコード走査結果です。"
        "『コード内未検出』であっても、ミドルウェアの既定有効値や外部設定（php.ini, server.xml, 環境変数, K8s設定等）"
        "に依存する場合は【不明＝該当あり（要確認）】として扱います。否定の確証がない限り『安全』と断定しないでください。",
        "",
        "## 1. 検証サマリ",
        f"- **総検査項目数:** {audit.summary_counts.get('total_checks', 0)} 件",
        f"- **判定: YES (自社コード内該当・要対応):** {audit.summary_counts.get('yes_count', 0)} 件",
        f"- **判定: コード内未検出 (外部設定/既定値の要確認):** {audit.summary_counts.get('unverified_count', 0)} 件",
        f"- **判定: NO (完全非該当・安全確証):** {audit.summary_counts.get('safe_count', 0)} 件",
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
            "| 対象 / CVE (CVSS) | 確認ポイント（Yes/No） | 自社判定 | 検出コード / 判定根拠 / 外部確認事項 |",
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
                if c_res.external_check_advice:
                    match_desc += f"<br>👉 **確認すべき外部設定:** {c_res.external_check_advice}"

            lines.append(f"| {target_cve} | {yes_no_q} | **{status}** | {match_desc} |")

        lines.append("")
        if notice.workaround and (n_res.overall_status.startswith("YES") or "要確認" in n_res.overall_status):
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
    if audit_report.overall_status.startswith("YES"):
        status_color = "red"
    elif "要確認" in audit_report.overall_status:
        status_color = "yellow"
    else:
        status_color = "green"

    console.print(
        Panel(
            f"[bold]総合判定:[/bold] [{status_color}]{audit_report.overall_status}[/{status_color}]\n"
            f"総項目: {audit_report.summary_counts['total_checks']} 件 | "
            f"[bold red]YES (該当・要対応): {audit_report.summary_counts['yes_count']} 件[/bold red] | "
            f"[bold yellow]コード内未検出 (外部設定/既定値の要確認): {audit_report.summary_counts['unverified_count']} 件[/bold yellow] | "
            f"[bold green]NO (安全確証): {audit_report.summary_counts['safe_count']} 件[/bold green]",
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
            if c_res.status.startswith("YES"):
                c_color = "bold red"
            elif "要確認" in c_res.status or "未検出" in c_res.status:
                c_color = "bold yellow"
            else:
                c_color = "bold green"

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
