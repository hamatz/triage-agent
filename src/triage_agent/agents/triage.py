import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from google import genai
from google.genai import types

from triage_agent.config import call_with_retry, get_genai_client, get_model_name, is_llm_configured
from triage_agent.rules import format_rules_for_prompt
from triage_agent.schemas import (
    CheckPointItem,
    TargetResearchResult,
    TriageNotice,
    TriageReport,
    compute_check_point_id,
    compute_notice_hash,
)
from triage_agent.tools.github import get_github_commit_or_advisory_detail

PROMPT_PATH = Path(__file__).resolve().parent.parent.parent.parent / "prompts" / "triage.md"


def run_triage_agent(
    research_results: List[TargetResearchResult],
    unscanned_components: Optional[List[str]] = None,
    failed_component_names: Optional[Set[str]] = None,
    client: Optional[genai.Client] = None,
    dry_run: bool = False,
) -> TriageReport:
    """Execute the Triage & Action Generation Agent.
    
    Architecture (2-Stage Deep Inspection):
      Stage 1 (Code Diff & Advisory Detail Retrieval):
        - For every finding with a commit SHA or GHSA ID, automatically fetches the exact patch diff
          and detailed advisory markdown via get_github_commit_or_advisory_detail.
      Stage 2 (Triage Decision & Trigger Condition Synthesis):
        - Prompts the LLM with the actual code diffs, advisory details, and enterprise rules.
        - Generates the standard TriageNotice report.
    """
    unscanned = list(unscanned_components or [])
    from datetime import date
    today_iso = date.today().isoformat()

    # Collect set of failed / unscanned / overflow component names
    failed_names: Set[str] = set()
    if failed_component_names:
        failed_names.update(f.lower().strip() for f in failed_component_names)

    for u in unscanned:
        u_clean = u.strip()
        if ":" in u_clean:
            cand = u_clean.split(":", 1)[0].strip()
            cand_name = cand.split()[0].split("(")[0].strip().lower()
            if cand_name and not cand_name.startswith("osv") and not cand_name.startswith("github"):
                failed_names.add(cand_name)

    # -------------------------------------------------------------
    # Stage 1: Retrieve actual patch diffs & advisory details
    # -------------------------------------------------------------
    detailed_diffs: Dict[str, Any] = {}
    for r in research_results:
        repo = r.target.github_repo
        if not repo:
            continue
        for f in r.findings:
            # Check GHSA detail
            if f.id.upper().startswith("GHSA-"):
                try:
                    adv_detail = get_github_commit_or_advisory_detail(repo, f.id)
                    if "error" not in adv_detail:
                        detailed_diffs[f.id] = {
                            "description": adv_detail.get("description", "")[:1000],
                            "vulnerabilities": adv_detail.get("vulnerabilities", []),
                        }
                except Exception:
                    pass

            # Check commit patch diffs
            for sha in f.commit_shas[:2]:
                try:
                    commit_detail = get_github_commit_or_advisory_detail(repo, sha)
                    if "files" in commit_detail:
                        detailed_diffs[sha] = [
                            {"file": fl.get("filename"), "patch": fl.get("patch", "")[:1000]}
                            for fl in commit_detail["files"]
                        ]
                except Exception:
                    pass

    # -------------------------------------------------------------
    # Stage 2: Synthesis
    # -------------------------------------------------------------
    should_run_dry = dry_run or not is_llm_configured()

    if should_run_dry:
        # Dry-run generator: transparently marks output as simulation and avoids fabricating conclusions
        notices: List[TriageNotice] = []

        for r in research_results:
            target = r.target
            raw_osv_hits = getattr(r, "osv_vuln_ids", [])
            is_clean_by_data = (
                len(raw_osv_hits) == 0
                and len(r.findings) == 0
                and len(r.errors) == 0
                and target.name.lower() not in failed_names
            )
            if is_clean_by_data:
                notice = TriageNotice(
                    product_name=f"{target.name}（利用バージョン: {target.version}）",
                    component_name=target.name,
                    announcement_date=today_iso,
                    conclusion=f"現在導入されているバージョン {target.version} において該当するセキュリティ脆弱性は報告されていません。対応不要です。",
                    fixed_versions="N/A (該当脆弱性なし)",
                    severity_note="なし",
                    no_known_vulnerability=True,
                    clean_basis=f"OSV 0件・Researcher 所見0件・調査エラーなし（{today_iso}時点）",
                    check_points=[],
                )
                notices.append(notice)
                continue

            if not r.findings:
                if raw_osv_hits:
                    # OSV hits exist but no findings generated: create check point directly from raw OSV IDs
                    cp_items: List[CheckPointItem] = []
                    for vid in raw_osv_hits:
                        q_text = f"{target.name} において {vid} に関連する機能・APIを直接呼び出しているか"
                        cp_items.append(
                            CheckPointItem(
                                check_point_id=compute_check_point_id(target.name, vid, q_text),
                                target_or_cve=vid,
                                cvss="未公表",
                                content_summary=f"OSV hit {vid}",
                                affected_versions=f"約 {target.version}",
                                check_point_yes_no=q_text,
                                verification_method=f"コードベースを検索。呼び出しや該当設定が一切存在しなければ NO（非該当）。",
                            )
                        )
                    notice = TriageNotice(
                        product_name=f"{target.name}（利用バージョン: {target.version}）",
                        component_name=target.name,
                        notice_hash=compute_notice_hash(cp_items),
                        announcement_date="直近公開（OSV最新シグナル）",
                        conclusion=f"【DRY-RUN】OSV.dev で検出された脆弱性（{', '.join(raw_osv_hits)}）の確認が必要です。",
                        fixed_versions="最新パッチを確認",
                        severity_note="要確認",
                        no_known_vulnerability=False,
                        check_points=cp_items,
                    )
                    notices.append(notice)
                continue

            check_points: List[CheckPointItem] = []
            sources: List[str] = []

            for f in r.findings:
                if f.source_urls:
                    sources.extend(f.source_urls)

                cvss_label = f.cvss or f"{f.severity}"
                display_cve = f"{f.id} (CVSS: {cvss_label})"

                if "urllib3" in target.name.lower():
                    if "gh4c" in f.id or "stream" in f.title.lower():
                        q_text = "HTTPResponse.stream() または read_chunked() でチャンク転送をストリーミング処理しているか"
                        check_points.append(
                            CheckPointItem(
                                check_point_id=compute_check_point_id(target.name, f.id, q_text),
                                target_or_cve=display_cve,
                                cvss=cvss_label,
                                content_summary=f.title,
                                affected_versions=f.affected_versions or "< 1.26.19",
                                check_point_yes_no=q_text,
                                verification_method="コードベースを stream(、read_chunked(、decode_content= で検索。巨大なDeflateレスポンスを扱うクライアント処理があるか確認",
                            )
                        )
                    elif "proxy" in f.title.lower():
                        q_text = "HTTPS プロキシ経由で TLS 通信を行う設定を使用しているか"
                        check_points.append(
                            CheckPointItem(
                                check_point_id=compute_check_point_id(target.name, f.id, q_text),
                                target_or_cve=display_cve,
                                cvss=cvss_label,
                                content_summary=f.title,
                                affected_versions=f.affected_versions or "< 1.26.19",
                                check_point_yes_no=q_text,
                                verification_method="環境変数 HTTPS_PROXY や ProxyManager( で HTTPS プロキシを設定している箇所を検索。証明書検証が無効化されていないか確認",
                            )
                        )
                    else:
                        q_text = "外部入力されたURLやヘッダーを直接 urllib3 に渡しているか"
                        check_points.append(
                            CheckPointItem(
                                check_point_id=compute_check_point_id(target.name, f.id, q_text),
                                target_or_cve=display_cve,
                                cvss=cvss_label,
                                content_summary=f.title,
                                affected_versions=f.affected_versions or f"< {target.version}",
                                check_point_yes_no=q_text,
                                verification_method="コード内で urllib3.PoolManager や requests を呼び出している外部通信処理を検索",
                            )
                        )

                elif "jsonwebtoken" in target.name.lower():
                    q_text = "jwt.verify() の algorithms オプションを省略または外部指定可能にしているか"
                    check_points.append(
                        CheckPointItem(
                            check_point_id=compute_check_point_id(target.name, f.id, q_text),
                            target_or_cve=display_cve,
                            cvss=cvss_label,
                            content_summary=f.title,
                            affected_versions=f.affected_versions or "< 9.0.0",
                            check_point_yes_no=q_text,
                            verification_method="コードベースで jwt.verify を検索。第3引数の options に algorithms: ['RS256'] 等の固定アルゴリズムが明示されているか確認",
                        )
                    )

                elif "axios" in target.name.lower():
                    title_lower = f.title.lower()
                    if "pre-release" in f.id.lower() or "pre-release" in title_lower:
                        q_text = "axios の先行リリース版（RC版・ベータ版）を本番環境で直接利用しているか"
                        method_text = "package.json 等で axios のバージョンを確認。正式安定版のみ利用していれば NO（非該当）。"
                    elif "toformdata" in title_lower:
                        q_text = "axios で toFormData オプションを使用し、外部から渡された未検証オブジェクトを送信しているか"
                        method_text = "コードベースを toFormData: { または FormData で検索。通常の JSON 送信（application/json）のみであれば NO（非該当）。"
                    elif "http/2" in title_lower or "http2" in title_lower:
                        q_text = "axios で HTTP/2 通信オプション（http2: true 等）または http2-wrapper を明示的に有効化しているか"
                        method_text = "コードベースで http2: true や http2-wrapper を検索。Node.js既定の http/https アダプタのみ使用していれば NO（非該当）。"
                    elif "proxy" in title_lower or "shouldbypassproxy" in title_lower:
                        q_text = "axios の proxy 設定または環境変数 NO_PROXY を指定し、かつ外部URLへのリダイレクトを自動追従させているか"
                        method_text = "コードベースで proxy: {、axios.defaults.proxy、または環境変数 NO_PROXY を検索。プロキシ未使用または maxRedirects: 0 であれば NO（非該当）。"
                    elif "fromdatauri" in title_lower or "data:" in title_lower:
                        q_text = "axios に外部入力由来の data: URI スキームを渡して処理させているか"
                        method_text = "コードベースで axios.get や axios( の引数に data: URL が渡されうる箇所を検索。http/https 固定であれば NO（非該当）。"
                    else:
                        q_text = "外部入力を検証せずに axios のリクエストパラメータや設定オプションに直接渡しているか"
                        method_text = "コード内で axios.create( や axios.request( の呼び出し箇所を検索。固定URL・固定パラメータへのリクエストのみであれば NO（非該当）。"

                    check_points.append(
                        CheckPointItem(
                            check_point_id=compute_check_point_id(target.name, f.id, q_text),
                            target_or_cve=display_cve,
                            cvss=cvss_label,
                            content_summary=f.title,
                            affected_versions=f.affected_versions or f"約 {target.version}",
                            check_point_yes_no=q_text,
                            verification_method=method_text,
                        )
                    )

                elif "fastapi" in target.name.lower():
                    title_lower = f.title.lower()
                    if "csrf" in title_lower:
                        q_text = "FastAPI アプリケーションで Cookie 認証等のステートフルセッションを使い、CSRF トークン検証を省略しているか"
                        method_text = "コードベースで Cookie 認証処理を確認。Stateless な Bearer/JWT 認証のみ、または CSRF ミドルウェア導入済みなら NO（非該当）。"
                    else:
                        q_text = "外部入力を型アノテーションなしで直接エンドポイントの引数に受け取っているか"
                        method_text = "コードベースで @app.get / @app.post の関数定義を確認。Pydantic モデルで厳格にバリデーションされていれば NO（非該当）。"

                    check_points.append(
                        CheckPointItem(
                            check_point_id=compute_check_point_id(target.name, f.id, q_text),
                            target_or_cve=display_cve,
                            cvss=cvss_label,
                            content_summary=f.title,
                            affected_versions=f.affected_versions or f"約 {target.version}",
                            check_point_yes_no=q_text,
                            verification_method=method_text,
                        )
                    )

                elif "express" in target.name.lower():
                    title_lower = f.title.lower()
                    if "pre-release" in f.id.lower() or "pre-release" in title_lower:
                        q_text = "express の先行リリース版（RC版・ベータ版）を本番環境で直接利用しているか"
                        method_text = "package.json 等で express のバージョンを確認。v4 系の正式安定版のみ利用していれば NO（非該当）。"
                    elif "redirect" in title_lower:
                        q_text = "res.redirect() のリダイレクト先URLに外部からの入力値をエスケープや検証なしで直接渡しているか"
                        method_text = "コードベースで res.redirect( を検索。引数に req.query や req.body の入力値が直接渡されている箇所がなければ NO（非該当）。"
                    elif "query" in title_lower:
                        q_text = "req.query のプロパティを未検証のままオブジェクトのキーや内部ロジックに直接代入しているか"
                        method_text = "コードベースで req.query を検索。型安全にバリデーション（zod, joi 等）していれば NO（非該当）。"
                    else:
                        q_text = "外部入力を直接 express のルーティングハンドラやテンプレートにエスケープなしで渡しているか"
                        method_text = "コードベースで app.use や app.get のミドルウェア設定を検索。入力サニタイズ処理があれば NO（非該当）。"

                    check_points.append(
                        CheckPointItem(
                            check_point_id=compute_check_point_id(target.name, f.id, q_text),
                            target_or_cve=display_cve,
                            cvss=cvss_label,
                            content_summary=f.title,
                            affected_versions=f.affected_versions or f"約 {target.version}",
                            check_point_yes_no=q_text,
                            verification_method=method_text,
                        )
                    )

                else:
                    # Extract potential function or keyword tokens from title (e.g. from words with parentheses, colons, or camelCase)
                    tokens = [w.strip("(),:;`'\"") for w in f.title.split() if any(c.isupper() for c in w) or "(" in w or "_" in w]
                    target_token = tokens[0] if tokens else target.name
                    q_text = f"{target.name} において {target_token} に関連する機能・APIを直接呼び出しているか"
                    check_points.append(
                        CheckPointItem(
                            check_point_id=compute_check_point_id(target.name, f.id, q_text),
                            target_or_cve=display_cve,
                            cvss=cvss_label,
                            content_summary=f.title,
                            affected_versions=f.affected_versions or f"約 {target.version}",
                            check_point_yes_no=q_text,
                            verification_method=f"コードベースを {target_token} で検索。呼び出しや該当設定が一切存在しなければ NO（非該当）。",
                        )
                    )

            # Determine announcement date: prefer earliest published_date from findings for lifecycle metrics T(-1)
            earliest_pub = None
            for f in r.findings:
                if getattr(f, "published_date", None):
                    raw_d = str(f.published_date).strip()
                    d_sub = raw_d[:10]
                    if len(d_sub) == 10 and d_sub[4] == "-" and d_sub[7] == "-":
                        if earliest_pub is None or d_sub < earliest_pub:
                            earliest_pub = d_sub

            ann_date_str = earliest_pub or "直近公開（GitHub / OSV最新シグナル）"

            notice = TriageNotice(
                product_name=f"{target.name}（利用バージョン: {target.version}）",
                notice_hash=compute_notice_hash(check_points),
                announcement_date=ann_date_str,
                conclusion=(
                    "【DRY-RUN シミュレーション】下の確認ポイントに1つでも Yes、または不明なら該当ありとして要確認。"
                    "外部公開システムで Critical なら48時間以内、Highなら7日以内に更新または回避策。確定判断はライブエージェントで実行してください。"
                ),
                fixed_versions=f"{target.name} 最新パッチ [DRY-RUN: 修正バージョンはライブ実行で確認]",
                severity_note=f"推定深刻度: {r.findings[0].severity if r.findings else 'High'} [DRY-RUN: RCE有無や正確なCVSSはライブ精読で判定]",
                pre_check_note="先にバージョンを確認します。範囲外なら、その CVE の確認ポイントは No として扱います。",
                check_points=check_points,
                workaround=(
                    f"回避策（暫定案）: {target.name} の呼び出し箇所で入力バリデーションを厳格化するか、該当機能のオプション設定を明示的に指定して無効化する。"
                ),
                unconfirmed_points=[
                    "[DRY-RUN] 正確なRCE発火条件およびパッチコミットDiffの精読は未実施です。",
                    "[DRY-RUN] 他言語バインディングや推移的依存先への波及状況はライブ実行で確認してください。",
                ],
                sources=list(dict.fromkeys(sources))[:3],
            )
            notices.append(notice)

        return TriageReport(
            report_title="SBOM脆弱性トリアージ・現場即応指示書 (DRY-RUN シミュレーション)",
            report_version="1.0",
            is_dry_run=True,
            unscanned_or_failed_components=unscanned,
            notices=notices,
        )

    # Online Agent Mode: Call Gemini with full enterprise rules & diff tools
    if client is None:
        client = get_genai_client()

    model_name = get_model_name("triage")
    system_instruction = PROMPT_PATH.read_text(encoding="utf-8")
    
    rules_text = format_rules_for_prompt()
    system_instruction += f"\n\n{rules_text}"

    findings_payload = json.dumps(
        [r.model_dump() for r in research_results],
        indent=2,
        ensure_ascii=False,
    )

    diffs_payload = json.dumps(detailed_diffs, indent=2, ensure_ascii=False)

    user_content = f"""以下は動的調査エージェント（Researcher）が収集した調査結果と、GitHubから取得したパッチ差分（Commit Diff / Advisory Detail）です。

【1. 調査結果一覧】:
{findings_payload}

【2. 取得されたパッチ差分・Advisory詳細】:
{diffs_payload if detailed_diffs else 'パッチ差分なし（Advisoryメタデータのみ）'}

【3. 未スキャン・エラー項目】:
{json.dumps(unscanned, ensure_ascii=False)}

指示:
システムプロンプトおよび【組織の判定基準・意思決定ルール】に厳格に従い、各プロダクトごとに以下の構成を持つ実務的・即応型の `TriageNotice` を生成してください：
1. 【結論】:
   - 外部公開のCritical（CVSS 9.0+ / RCE）は、攻撃コードの有無に関わらず48時間以内に対処。
   - High / Important（CVSS 7.0〜8.9）は、確認ポイントに1つでもYesなら7日以内に対処。
   - 複数評価がある場合は最も高い深刻度を採用。
   - 不明（コードベース外の設定に依存するもの）は該当あり（要確認）として扱う。
   - すべてNoなら通常リリース（30日以内）。
2. 【基本情報】: 公開日、修正版、深刻度、CVE内容
3. 【確認ポイント（Yes/No）と確認方法】: パッチ差分（Diff）やAdvisory詳細から読み取った具体的な設定ファイル名（server.xml, php.ini等）、XMLタグ、iniディレクティブ、grep/lddコマンド、コード検索キーワード
4. 【回避策】: 設定変更による回避手順、副作用の有無
5. 【未確認事項】: 不明点や確認継続事項
6. 【出典】: 参照URLリスト
"""

    response = call_with_retry(
        lambda: client.models.generate_content(
            model=model_name,
            contents=user_content,
            config=types.GenerateContentConfig(
                system_instruction=system_instruction,
                response_mime_type="application/json",
                response_schema=TriageReport,
                temperature=0.2,
            ),
        )
    )

    if response.text:
        report = TriageReport.model_validate_json(response.text)
        report.is_dry_run = False
        report.unscanned_or_failed_components = unscanned

        # Build map of target names from research results for stable ID canonicalization
        target_name_map = {r.target.name.lower(): r.target.name for r in research_results}
        results_by_name = {r.target.name.lower(): r for r in research_results}
        unscanned_lower = {u.lower() for u in unscanned}
        from datetime import date
        today_iso = date.today().isoformat()

        # Deterministically enforce canonical component_name, clean status, check_point_id and notice_hash
        for notice in report.notices:
            canonical_name = notice.component_name
            if not canonical_name:
                for tname_key, tname_val in target_name_map.items():
                    if tname_key in notice.product_name.lower():
                        canonical_name = tname_val
                        break
            if not canonical_name:
                canonical_name = notice.product_name

            notice.component_name = canonical_name

            res = results_by_name.get(canonical_name.lower())

            # 1. Update announcement_date from earliest finding's published_date if available for lifecycle metrics T(-1)
            if res and res.findings:
                earliest_pub = None
                for f in res.findings:
                    if getattr(f, "published_date", None):
                        raw_d = str(f.published_date).strip()
                        d_sub = raw_d[:10]
                        if len(d_sub) == 10 and d_sub[4] == "-" and d_sub[7] == "-":
                            if earliest_pub is None or d_sub < earliest_pub:
                                earliest_pub = d_sub
                if earliest_pub:
                    notice.announcement_date = earliest_pub

            # 2. Machine-determined ground truth:
            # - Raw OSV hits must be 0 (from osv_vuln_ids directly, NOT LLM output!)
            # - Researcher findings must be 0
            # - Researcher errors must be 0
            # - Component must not be in failed / unscanned / overflow set
            raw_osv_hits = getattr(res, "osv_vuln_ids", []) if res else []
            is_clean_by_data = (
                res is not None
                and len(raw_osv_hits) == 0
                and len(res.findings) == 0
                and len(res.errors) == 0
                and canonical_name.lower() not in failed_names
            )

            if is_clean_by_data:
                notice.no_known_vulnerability = True
                notice.clean_basis = f"OSV 0件・Researcher 所見0件・調査エラーなし（{today_iso}時点）"
                # DO NOT clear notice.check_points!
                # If LLM generated check_points despite 0 findings, it signals a conflict or caution.
                # Verifier will only judge safe if notice.no_known_vulnerability is True AND len(notice.check_points) == 0.
            else:
                notice.no_known_vulnerability = False
                notice.clean_basis = None

            for cp in notice.check_points:
                m = re.search(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9\-]+)\b", cp.target_or_cve, re.I)
                cve_id = m.group(1) if m else "VULN"
                cp.check_point_id = compute_check_point_id(canonical_name, cve_id, cp.check_point_yes_no)
            notice.notice_hash = compute_notice_hash(notice.check_points)

        return report

    raise RuntimeError("Triage agent failed to produce structured triage report.")
