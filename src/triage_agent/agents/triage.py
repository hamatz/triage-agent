import json
from pathlib import Path
from typing import List, Optional
from google import genai
from google.genai import types

from triage_agent.config import get_gemini_api_key, get_model_name
from triage_agent.rules import format_rules_for_prompt
from triage_agent.schemas import (
    CheckPointItem,
    TargetResearchResult,
    TriageNotice,
    TriageReport,
)
from triage_agent.tools.github import get_github_commit_or_advisory_detail

PROMPT_PATH = Path(__file__).resolve().parent.parent.parent.parent / "prompts" / "triage.md"


def run_triage_agent(
    research_results: List[TargetResearchResult],
    unscanned_components: Optional[List[str]] = None,
    client: Optional[genai.Client] = None,
    dry_run: bool = False,
) -> TriageReport:
    """Execute the Triage & Action Generation Agent.
    
    1. Analyzes all findings gathered by Researcher workers.
    2. Uses get_github_commit_or_advisory_detail to examine patches or advisory texts.
    3. Produces structured TriageNotice objects adhering to the enterprise triage rules.
    """
    unscanned = unscanned_components or []

    if dry_run or not get_gemini_api_key():
        # Dry-run generator: transparently marks output as simulation and avoids fabricating conclusions
        notices: List[TriageNotice] = []

        for r in research_results:
            target = r.target
            if not r.findings:
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
                        check_points.append(
                            CheckPointItem(
                                target_or_cve=display_cve,
                                cvss=cvss_label,
                                content_summary=f.title,
                                affected_versions=f.affected_versions or "< 1.26.19",
                                check_point_yes_no="HTTPResponse.stream() または read_chunked() でチャンク転送をストリーミング処理しているか",
                                verification_method="コードベースを stream(、read_chunked(、decode_content= で検索。巨大なDeflateレスポンスを扱うクライアント処理があるか確認",
                            )
                        )
                    elif "proxy" in f.title.lower():
                        check_points.append(
                            CheckPointItem(
                                target_or_cve=display_cve,
                                cvss=cvss_label,
                                content_summary=f.title,
                                affected_versions=f.affected_versions or "< 1.26.19",
                                check_point_yes_no="HTTPS プロキシ経由で TLS 通信を行う設定を使用しているか",
                                verification_method="環境変数 HTTPS_PROXY や ProxyManager( で HTTPS プロキシを設定している箇所を検索。証明書検証が無効化されていないか確認",
                            )
                        )
                    else:
                        check_points.append(
                            CheckPointItem(
                                target_or_cve=display_cve,
                                cvss=cvss_label,
                                content_summary=f.title,
                                affected_versions=f.affected_versions or f"< {target.version}",
                                check_point_yes_no="外部入力されたURLやヘッダーを直接 urllib3 に渡しているか",
                                verification_method="コード内で urllib3.PoolManager や requests を呼び出している外部通信処理を検索",
                            )
                        )

                elif "jsonwebtoken" in target.name.lower():
                    check_points.append(
                        CheckPointItem(
                            target_or_cve=display_cve,
                            cvss=cvss_label,
                            content_summary=f.title,
                            affected_versions=f.affected_versions or "< 9.0.0",
                            check_point_yes_no="jwt.verify() の algorithms オプションを省略または外部指定可能にしているか",
                            verification_method="コードベースで jwt.verify を検索。第3引数の options に algorithms: ['RS256'] 等の固定アルゴリズムが明示されているか確認",
                        )
                    )

                else:
                    check_points.append(
                        CheckPointItem(
                            target_or_cve=display_cve,
                            cvss=cvss_label,
                            content_summary=f.title,
                            affected_versions=f.affected_versions or f"約 {target.version}",
                            check_point_yes_no=f"{target.name} の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか",
                            verification_method=f"設定ファイルおよび依存コードで {target.name} の設定ディレクティブを grep 検索",
                        )
                    )

            notices.append(
                TriageNotice(
                    product_name=f"{target.name}（利用バージョン: {target.version}）",
                    announcement_date="直近公開（GitHub / OSV最新シグナル）",
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
            )

        return TriageReport(
            report_title="SBOM脆弱性トリアージ・現場即応指示書 (DRY-RUN シミュレーション)",
            is_dry_run=True,
            unscanned_or_failed_components=unscanned,
            notices=notices,
        )

    # Online Agent Mode: Call Gemini with full enterprise rules & diff tools
    if client is None:
        client = genai.Client(api_key=get_gemini_api_key())

    model_name = get_model_name("triage")
    system_instruction = PROMPT_PATH.read_text(encoding="utf-8")
    
    # Inject enterprise rules into the prompt
    rules_text = format_rules_for_prompt()
    system_instruction += f"\n\n{rules_text}"

    findings_payload = json.dumps(
        [r.model_dump() for r in research_results],
        indent=2,
        ensure_ascii=False,
    )

    user_content = f"""以下は動的調査エージェント（Researcher）が収集した調査結果と脆弱性シグナルの一覧です。

【調査結果一覧】:
{findings_payload}

【未スキャン・エラー項目】:
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
3. 【確認ポイント（Yes/No）と確認方法】: 具体的な設定ファイル名（server.xml, php.ini等）、XMLタグ、iniディレクティブ、grep/lddコマンド、コード検索キーワード
4. 【回避策】: 設定変更による回避手順、副作用の有無
5. 【未確認事項】: 不明点や確認継続事項
6. 【出典】: 参照URLリスト
"""

    response = client.models.generate_content(
        model=model_name,
        contents=user_content,
        config=types.GenerateContentConfig(
            system_instruction=system_instruction,
            response_mime_type="application/json",
            response_schema=TriageReport,
            temperature=0.2,
        ),
    )

    if response.text:
        report = TriageReport.model_validate_json(response.text)
        report.is_dry_run = False
        report.unscanned_or_failed_components = unscanned
        return report

    raise RuntimeError("Triage agent failed to produce structured triage report.")
