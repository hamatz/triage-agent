import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional
from pydantic import BaseModel, Field

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from triage_agent.rules import TRIAGE_RULES
from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport

console = Console()

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


class AuditAttestation(BaseModel):
    check_point_id: Optional[str] = Field(
        default=None,
        description="Deterministic unique ID of the check point (e.g. 'urllib3-cve-2026-97688-a1b2c3d4'). Primary key.",
    )
    notice_hash: Optional[str] = Field(
        default=None,
        description="Notice content hash fingerprint. If check points are added/changed in edition 2, automatically invalidates outdated sign-offs.",
    )
    cve_id: Optional[str] = Field(
        default=None,
        description="Exact CVE or GHSA ID (e.g. 'CVE-2026-11149'). Used in combination with check_point_yes_no.",
    )
    check_point_yes_no: Optional[str] = Field(
        default=None,
        description="Exact question text of the check point (e.g. 'HTTPS_PROXY 環境変数を利用しているか').",
    )
    report_version: Optional[str] = Field(
        default=None,
        description="Target report version (e.g. '1.0'). If mismatched with current report version, sign-off is invalidated.",
    )
    target_or_cve: Optional[str] = Field(
        default=None,
        description="Legacy field for backward compatibility. Must match CVE ID strictly if used.",
    )
    matches_hash: Optional[str] = Field(
        default=None,
        description="Fingerprint hash of detected code snippet matches at sign-off time. Invalidates sign-off if code changes.",
    )
    status: str = Field(default="NO (手動確認済み・非該当)")
    reviewer: str = Field(description="Name/ID of the security reviewer or engineer")
    date: str = Field(description="Date of attestation (e.g. '2026-10-25')")
    evidence: str = Field(description="Audit justification, config proof, or architecture rationale")


class AttestationFile(BaseModel):
    attestations: List[AuditAttestation] = Field(default_factory=list)


def compute_matches_hash(matches: List[MatchSnippet]) -> Optional[str]:
    """Compute deterministic fingerprint of code matches for drift detection."""
    if not matches:
        return None
    normalized_items = [
        f"{m.file_path}:{' '.join(m.line_content.split())}"
        for m in sorted(matches, key=lambda x: (x.file_path, x.line_number))
    ]
    raw = "\n".join(normalized_items)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def normalize_text(text: str) -> str:
    """Normalize whitespace and lowercase for reliable exact matching."""
    return re.sub(r"\s+", " ", text.strip().lower())


def extract_cve_id(text: str) -> Optional[str]:
    """Extract standard CVE or GHSA identifier from text."""
    m = re.search(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9\-]+)\b", text, re.IGNORECASE)
    return m.group(1).upper() if m else None


class CheckVerificationResult(BaseModel):
    check_point: CheckPointItem
    status: str = Field(description="'YES (該当・要対応)', 'コード内未検出 (外部設定/既定値の要確認)', '要手動確認', or 'NO (手動確認済み・非該当)'")
    matches: List[MatchSnippet] = Field(default_factory=list)
    matches_hash: Optional[str] = Field(default=None, description="Current fingerprint hash of code matches")
    reasoning: str
    external_check_advice: Optional[str] = Field(
        default=None,
        description="Advice on external config files (e.g. php.ini, server.xml, env vars, K8s manifests)"
    )
    attestation: Optional[AuditAttestation] = Field(
        default=None,
        description="Human audit sign-off if confirmed offline"
    )


class NoticeVerificationResult(BaseModel):
    notice: TriageNotice
    overall_status: str = Field(description="'YES (該当・要対応)', '要確認 (外部設定・環境設定の確認要)', or 'NO (安全・確認済み)'")
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

    for token in re.findall(r"`([^`]+)`", text):
        cleaned = token.strip()
        if len(cleaned) >= 3:
            patterns.add(cleaned)

    for tag in re.findall(r"<([a-zA-Z0-9_\-]+)", text):
        patterns.add(f"<{tag}")

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


def load_audit_attestations(audit_file_path: Optional[str]) -> List[AuditAttestation]:
    """Load human attestation sign-off records if provided."""
    if not audit_file_path:
        return []
    path = Path(audit_file_path)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [AuditAttestation.model_validate(item) for item in data]
        if isinstance(data, dict) and "attestations" in data:
            return [AuditAttestation.model_validate(item) for item in data["attestations"]]
    except Exception as e:
        console.print(f"[yellow]Warning: Failed to load audit file {audit_file_path}: {e}[/yellow]")
    return []


def verify_codebase(
    report: TriageReport,
    code_dir_path: Optional[str] = None,
    audit_file_path: Optional[str] = None
) -> CodebaseAuditReport:
    """Run automated code inspection or vendor attestation check based on TriageReport check points.
    
    Supports audit attestation files (e.g. audit_signoff.json) to record human and vendor sign-offs.
    If code_dir_path is None or empty, operates in vendor/manual audit mode without scanning local files.
    """
    code_dir = None
    if code_dir_path and code_dir_path.strip():
        p = Path(code_dir_path).resolve()
        if p.exists():
            code_dir = p
        else:
            raise FileNotFoundError(f"Codebase directory not found: {code_dir_path}")

    attestations = load_audit_attestations(audit_file_path)

    notice_results: List[NoticeVerificationResult] = []
    total_yes = 0
    total_unverified = 0
    total_safe = 0

    report_ver = getattr(report, "report_version", None)

    for notice in report.notices:
        check_results: List[CheckVerificationResult] = []
        has_yes = False
        has_unverified = False

        # Count occurrences of CVEs in this notice to detect ambiguity
        cve_counts: Dict[str, int] = {}
        for cp in notice.check_points:
            cve = extract_cve_id(cp.target_or_cve)
            if cve:
                cve_counts[cve] = cve_counts.get(cve, 0) + 1

        for cp in notice.check_points:
            cp_cve = extract_cve_id(cp.target_or_cve)
            matched_attestation = None

            # 1. Match human audit attestations strictly
            for att in attestations:
                # Check candidate match first
                is_candidate = False
                if att.check_point_id and cp.check_point_id:
                    if att.check_point_id.strip() == cp.check_point_id.strip():
                        is_candidate = True
                elif att.cve_id and att.check_point_yes_no:
                    if cp_cve and att.cve_id.upper() == cp_cve and \
                       normalize_text(att.check_point_yes_no) == normalize_text(cp.check_point_yes_no):
                        is_candidate = True
                elif att.target_or_cve:
                    att_cve = extract_cve_id(att.target_or_cve)
                    if att_cve and cp_cve and att_cve == cp_cve:
                        if cve_counts.get(cp_cve, 0) > 1:
                            console.print(
                                f"[yellow]⚠ 警告: {cp_cve} には複数の確認ポイントが存在するため、"
                                f"target_or_cve 単体での曖昧なサインオフを拒否しました。"
                                f"安全のため check_point_id または check_point_yes_no を指定してください。[/yellow]"
                            )
                        else:
                            is_candidate = True

                if not is_candidate:
                    continue

                # Verify report version compatibility
                if att.report_version and report_ver and att.report_version != report_ver:
                    console.print(
                        f"[yellow]⚠ 警告: サインオフの対象版（v{att.report_version}）が現在のレポート版（v{report_ver}）と不一致のため、"
                        f"サインオフを適用せず再確認対象とします（対象: {att.check_point_id or att.cve_id or att.target_or_cve}）。[/yellow]"
                    )
                    continue

                # Verify notice fingerprint hash compatibility
                if att.notice_hash and notice.notice_hash and att.notice_hash != notice.notice_hash:
                    console.print(
                        f"[yellow]⚠ 警告: {notice.product_name} の確認ポイント構成（版）が変更されたため、"
                        f"古いサインオフ（hash {att.notice_hash}）を適用せず再確認対象とします（対象: {att.check_point_id or att.cve_id or att.target_or_cve}）。[/yellow]"
                    )
                    continue

                matched_attestation = att
                break

            # Run code scan if code directory is provided
            code_matches: List[MatchLocation] = []
            scan_patterns: List[str] = []
            if code_dir is not None:
                scan_patterns = extract_keywords_from_method(f"{cp.check_point_yes_no} {cp.verification_method}")
                if scan_patterns:
                    code_matches = scan_directory_for_patterns(code_dir, scan_patterns)

            current_matches_hash = compute_matches_hash(code_matches)

            if matched_attestation:
                # Validate attestation status safely: only "NO..." without code drift counts as safe!
                att_status = matched_attestation.status.strip()
                matches = code_matches
                advice = None

                if att_status.upper().startswith("NO"):
                    if code_matches:
                        if matched_attestation.matches_hash and matched_attestation.matches_hash == current_matches_hash:
                            # False positive safely confirmed: code matches match exactly what reviewer approved
                            status = "NO (コード確認済み・非該当)"
                            total_safe += 1
                            reason = (
                                f"【手動監査済・該当コード確認済】{matched_attestation.reviewer}（{matched_attestation.date}）により"
                                f"該当コード箇所（{len(code_matches)}件）は確認済み・非該当と判断されています: {matched_attestation.evidence}"
                            )
                        elif matched_attestation.matches_hash and matched_attestation.matches_hash != current_matches_hash:
                            # Code drift detected! Matches have changed since sign-off
                            status = "要再確認 (コード変更検知・サインオフ要更新⚠️)"
                            has_unverified = True
                            total_unverified += 1
                            reason = (
                                f"【コード変更検知⚠️】サインオフ時点とコード検出内容が変化しました。"
                                f"{matched_attestation.reviewer}（{matched_attestation.date}）のサインオフを自動失効し再確認対象とします。"
                                f"（現在 {len(code_matches)} 箇所検出: {code_matches[0].file_path}:{code_matches[0].line_number} 等）"
                            )
                            advice = f"変更されたコード箇所（{code_matches[0].file_path}:{code_matches[0].line_number} 等）を確認し、サインオフを更新してください。"
                        else:
                            # Attestation has no matches_hash (e.g. signed off assuming 0 matches, but matches exist)
                            status = "要再確認 (サインオフ済・コード該当あり⚠️)"
                            has_unverified = True
                            total_unverified += 1
                            reason = (
                                f"【要再確認・コード該当あり⚠️】{matched_attestation.reviewer}（{matched_attestation.date}）による非該当サインオフ（{matched_attestation.evidence}）がありますが、"
                                f"コード走査により該当キーワード（{', '.join(scan_patterns)}）が {len(code_matches)} 箇所検出されました（{code_matches[0].file_path}:{code_matches[0].line_number} 等）。"
                                f"コード変更または例外的な許容根拠の再確認が必要です。"
                            )
                            advice = f"該当箇所（{code_matches[0].file_path}:{code_matches[0].line_number} 等）の設定を確認し、必要に応じてサインオフの更新または修正を行ってください。"
                    else:
                        status = matched_attestation.status
                        total_safe += 1
                        reason = f"【安全確認済（サインオフ記録）】{matched_attestation.reviewer}（{matched_attestation.date}）: {matched_attestation.evidence}"
                elif att_status.upper().startswith("YES"):
                    status = matched_attestation.status
                    has_yes = True
                    total_yes += 1
                    reason = f"【該当あり（サインオフ記録）】{matched_attestation.reviewer}（{matched_attestation.date}）: {matched_attestation.evidence}"
                else:
                    status = matched_attestation.status
                    has_unverified = True
                    total_unverified += 1
                    reason = f"【要確認（サインオフ記録）】{matched_attestation.reviewer}（{matched_attestation.date}）: {matched_attestation.evidence}"
            else:
                if code_dir is None:
                    status = "要手動確認 (ベンダー照会要)"
                    has_unverified = True
                    total_unverified += 1
                    reason = "自社コードベース対象外（外注・ベンダー委託）。ベンダーへの照会および手動確認・回答記録が必要です。"
                    advice = cp.verification_method
                    matches = []
                else:
                    if not scan_patterns:
                        status = "要手動確認 (キーワード抽出不能)"
                        has_unverified = True
                        total_unverified += 1
                        reason = "確認方法が自然言語またはインフラ依存のため、自動検索キーワードを抽出できませんでした。手動での確認が必要です。"
                        advice = cp.verification_method
                        matches = []
                    else:
                        matches = code_matches
                        if matches:
                            status = "YES (該当・要対応)"
                            has_yes = True
                            total_yes += 1
                            reason = f"自社リポジトリ内で発火キーワード（{', '.join(scan_patterns)}）の利用を {len(matches)} 箇所検出しました。"
                            advice = f"該当箇所（{matches[0].file_path}:{matches[0].line_number} 等）の設定および呼び出し引数を修正してください。"
                        else:
                            status = "コード内未検出 (外部設定/既定値の要確認)"
                            has_unverified = True
                            total_unverified += 1
                            reason = (
                                f"リポジトリ内のコードでは '{', '.join(scan_patterns)}' は未検出でした。"
                                "ただし、ミドルウェアの既定値（デフォルト有効）や外部設定"
                                "（php.ini, server.xml, 環境変数, コンテナマニフェスト等）で有効化されている可能性があります。"
                            )
                            advice = f"外部設定（{cp.verification_method[:80]}...）の有無を確認してください。"

            check_results.append(
                CheckVerificationResult(
                    check_point=cp,
                    status=status,
                    matches=matches,
                    matches_hash=current_matches_hash,
                    reasoning=reason,
                    external_check_advice=advice,
                    attestation=matched_attestation,
                )
            )

        if has_yes:
            overall_status = "YES (該当・要対応)"
            deadline_advice = (
                f"【緊急対応要】自社コード内に発火条件を検知しました。"
                f"外部公開システムはルールに従い（Critical: {TRIAGE_RULES['CRITICAL_DEADLINE']}、High: {TRIAGE_RULES['HIGH_DEADLINE']}）に修正または回避策を適用してください。"
            )
        elif has_unverified:
            overall_status = "要確認 (外部設定・環境設定の確認要)"
            deadline_advice = (
                "【要確認（不明は該当あり扱い）】ソースコード内では未検出ですが、外部設定（php.ini, server.xml, 環境変数等）"
                "または既定値で有効になっている可能性があります。外部設定の確認または監査サインオフが完了するまでは『要対応』として扱ってください。"
            )
        else:
            overall_status = "NO (安全・確認済み)"
            deadline_advice = f"【通常リリース可】自社環境において非該当・確認済みであることが検証されました。{TRIAGE_RULES['NORMAL_DEADLINE']}での更新対応で問題ありません。"

        notice_results.append(
            NoticeVerificationResult(
                notice=notice,
                overall_status=overall_status,
                action_deadline_advice=deadline_advice,
                results=check_results,
            )
        )

    if total_yes > 0:
        overall_codebase_status = "YES (該当あり・緊急対応要)"
    elif total_unverified > 0:
        overall_codebase_status = "要確認 (ベンダー照会・回答待ち)" if code_dir is None else "要確認 (外部設定・環境設定の確認要)"
    else:
        overall_codebase_status = "NO (安全・ベンダー確認済み)" if code_dir is None else "NO (安全・確認済み)"

    return CodebaseAuditReport(
        code_dir=str(code_dir) if code_dir else "なし (外注・ベンダー委託システム / 手動監査)",
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
        "に依存する場合は【不明＝該当あり（要確認）】として扱います。否定の確証または監査サインオフがない限り『安全』と断定しないでください。",
        "",
        "## 1. 検証サマリ",
        f"- **総検査項目数:** {audit.summary_counts.get('total_checks', 0)} 件",
        f"- **判定: YES (自社コード内該当・要対応):** {audit.summary_counts.get('yes_count', 0)} 件",
        f"- **判定: コード内未検出 (外部設定/既定値の要確認):** {audit.summary_counts.get('unverified_count', 0)} 件",
        f"- **判定: NO (非該当・手動監査サインオフ済):** {audit.summary_counts.get('safe_count', 0)} 件",
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
                if c_res.attestation:
                    match_desc = (
                        f"⚠️ **サインオフ（{c_res.attestation.reviewer}）:** {c_res.attestation.evidence}<br>"
                        f"📍 **コード内検出箇所（要照合）:**<br>" + match_desc
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
        "--audit-file",
        type=str,
        default=None,
        help="Optional path to human audit sign-off file (e.g. audit_signoff.json) to record verified safe settings",
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

    audit_report = verify_codebase(report, args.code_dir, audit_file_path=args.audit_file)

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
