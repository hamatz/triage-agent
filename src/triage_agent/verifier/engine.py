"""Core codebase verification engine that cross-references scan results and attestations."""

from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console

from triage_agent.rules import TRIAGE_RULES
from triage_agent.schemas import TriageReport
from triage_agent.verifier.attestation import (
    compute_matches_hash,
    extract_cve_id,
    load_audit_attestations,
    normalize_text,
)
from triage_agent.verifier.models import (
    CheckVerificationResult,
    CodebaseAuditReport,
    MatchSnippet,
    NoticeVerificationResult,
)
from triage_agent.verifier.scanner import (
    extract_keywords_from_method,
    scan_directory_for_patterns,
)

console = Console()


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
            code_matches: List[MatchSnippet] = []
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
                    if has_unverified is False:
                        pass
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
                            prod_matches = [m for m in matches if not m.is_test]
                            test_matches = [m for m in matches if m.is_test]

                            if prod_matches:
                                status = "YES (本番コード内検出・要実地確認)"
                                has_yes = True
                                total_yes += 1
                                test_note = f"（他にテストコード内: {len(test_matches)} 件）" if test_matches else ""
                                reason = (
                                    f"自社リポジトリ内の本番コードで発火関連キーワード（{', '.join(scan_patterns)}）の呼び出しを "
                                    f"{len(prod_matches)} 箇所検出しました{test_note}。現場で実際の引数・オプション設定の実地確認が必要です。"
                                )
                                advice = (
                                    f"本番コード検出箇所（{prod_matches[0].file_path}:{prod_matches[0].line_number} 等）を確認し、"
                                    f"発火条件に合致する場合は修正・パッチ適用、影響を受けない設計の場合はサインオフ（誤検知・許容）を記録してください。"
                                )
                            else:
                                status = "YES (テストコード内のみ検出・本番未検出)"
                                has_yes = True
                                total_yes += 1
                                reason = (
                                    f"自社リポジトリ内のテスト・モックコード（{', '.join([m.file_path for m in test_matches[:3]])} 等）で "
                                    f"{len(test_matches)} 箇所検出されましたが、本番コード内での呼び出しは未検出です。"
                                    f"本番ビルドに含まれないテスト専用ファイルであることを確認の上、サインオフ（許容）の記録を推奨します。"
                                )
                                advice = f"テストコード検出箇所（{test_matches[0].file_path}:{test_matches[0].line_number} 等）を確認し、本番影響がなければサインオフを登録してください。"
                        else:
                            status = "コード内未検出 (外部設定・既定値の要確認)"
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
            overall_status = "YES (発火関連コード検出・要実地確認)"
            deadline_advice = (
                f"【要実地確認】自社コード内に発火関連キーワードを検知しました。"
                f"発火条件に合致する場合は運用ルール（Critical: {TRIAGE_RULES['CRITICAL_DEADLINE']}、High: {TRIAGE_RULES['HIGH_DEADLINE']}）に従い修正または回避策を適用、"
                f"影響を受けない設計やテストコード等の場合はサインオフを記録してください。"
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
        overall_codebase_status = "YES (発火関連コード検出・要実地確認)"
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
