"""Markdown report formatter for codebase verification audit results."""

from triage_agent.verifier.models import CodebaseAuditReport


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
        f"- **判定: YES (発火関連コード検出・要実地確認):** {audit.summary_counts.get('yes_count', 0)} 件",
        f"- **判定: コード内未検出 (外部設定・既定値の要確認):** {audit.summary_counts.get('unverified_count', 0)} 件",
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
                    [
                        f"• `{'[TEST] ' if m.is_test else ''}{m.file_path}:{m.line_number}`: `{m.line_content[:100]}`"
                        for m in c_res.matches[:5]
                    ]
                )
                if len(c_res.matches) > 5:
                    match_desc += f"<br>• ...他 {len(c_res.matches) - 5} 箇所"
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
