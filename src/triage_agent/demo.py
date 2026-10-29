"""Explicit demo showcase generator for triage-agent.

Ensures synthetic demonstration data is completely separated from production code
and clearly identifiable via 'DEMO-' prefixed IDs and explicit warnings.
"""

from typing import List
from triage_agent.schemas import (
    CheckPointItem,
    PreAnnouncementNotice,
    TriageNotice,
    TriageReport,
    compute_check_point_id,
    compute_notice_hash,
)


def generate_demo_report() -> TriageReport:
    """Generate a clean, self-contained demonstration report with clear DEMO prefixes."""
    notices: List[TriageNotice] = []

    # Demo Notice 1: Apache Tomcat
    cp1_text = "AJP コネクタを有効にしているか"
    cp2_text = "HTTP/2 を有効にしていて、かつ非同期サーブレットを使っているか"
    cp3_text = "JNDIRealm (LDAP連携) を使い、GSSAPI 以外の SASL 方式で認証しているか"

    tomcat_cps = [
        CheckPointItem(
            check_point_id=compute_check_point_id("tomcat", "DEMO-CVE-2026-0001", cp1_text),
            target_or_cve="DEMO-CVE-2026-0001 (CVSS: 7.5 High)",
            cvss="7.5 (High)",
            content_summary="AJP でレスポンスの一部が次のリクエストに混ざる。別の利用者へ情報が漏れるおそれ",
            affected_versions="11.0.0-M25〜11.0.26 (10.1系は対象外)",
            check_point_yes_no=cp1_text,
            verification_method="server.xml にコメントアウトされていない <Connector protocol=\"AJP/1.3\" ...> があるか。前段に Apache httpd（mod_proxy_ajp 等）を置いている構成は要注意",
        ),
        CheckPointItem(
            check_point_id=compute_check_point_id("tomcat", "DEMO-CVE-2026-0002", cp2_text),
            target_or_cve="DEMO-CVE-2026-0002 (CVSS: 7.5 High)",
            cvss="7.5 (High)",
            content_summary="HTTP/2 で非同期処理中にエラーが起きると、利用者間でリクエストやレスポンスが入れ替わる",
            affected_versions="11.0.22〜11.0.26、10.1.55〜10.1.60",
            check_point_yes_no=cp2_text,
            verification_method="server.xml の Connector 内に <UpgradeProtocol className=\"org.apache.coyote.http2.Http2Protocol\"/> があるか。アプリに asyncSupported=true、startAsync() があるか",
        ),
        CheckPointItem(
            check_point_id=compute_check_point_id("tomcat", "DEMO-CVE-2026-0003", cp3_text),
            target_or_cve="DEMO-CVE-2026-0003 (CVSS: 8.1 High)",
            cvss="8.1 (High)",
            content_summary="JNDIRealm で、正しいパスワードなしに認証を通られる",
            affected_versions="11.0.0-M1〜11.0.26、10.1.0-M1〜10.1.60",
            check_point_yes_no=cp3_text,
            verification_method="server.xml や context.xml に <Realm className=\"org.apache.catalina.realm.JNDIRealm\" ...> の定義があり、かつ DIGEST-MD5 や CRAM-MD5 等の SASL を使っているか",
        ),
    ]

    notices.append(
        TriageNotice(
            product_name="DEMO: Apache Tomcat (展示用サンプル)",
            notice_hash=compute_notice_hash(tomcat_cps),
            announcement_date="2026年10月20日公開 (展示用)",
            conclusion="【デモ表示】下の確認ポイントに1つでも Yes なら外部公開システムは7日以内に更新。すべて No なら通常リリース（30日以内）。RCEは含まれません。",
            fixed_versions="11.0.27、10.1.61 (9.0系は未確認)",
            severity_note="Important × 3 (Apache Tomcat の表記)。CVSS は 7.5〜8.1",
            pre_check_note="先にバージョンを確認します。範囲外なら、その CVE の確認ポイントは No として扱います。",
            check_points=tomcat_cps,
            workaround="AJP を使っていなければコネクタの定義ごと削除またはコメントアウト。HTTP/2 は一時的に無効化。",
            unconfirmed_points=[
                "9.0 系の影響有無は未確認",
                "Tomcat Native / APR コネクタ併用時の詳細挙動",
            ],
            sources=["https://tomcat.apache.org/security.html (デモ参考)"],
        )
    )

    # Demo Notice 2: jsonwebtoken
    jwt_q = "jwt.verify() の algorithms オプションを省略または外部指定可能にしているか"
    jwt_cps = [
        CheckPointItem(
            check_point_id=compute_check_point_id("jsonwebtoken", "DEMO-CVE-2026-0004", jwt_q),
            target_or_cve="DEMO-CVE-2026-0004 (CVSS: 7.5 High)",
            cvss="7.5 (High)",
            content_summary="algorithms オプション未指定によるアルゴリズム検証回避",
            affected_versions="< 9.0.0",
            check_point_yes_no=jwt_q,
            verification_method="コードベースで jwt.verify を検索。第3引数の options に algorithms: ['RS256'] 等の固定アルゴリズムが明示されているか確認",
        )
    ]
    notices.append(
        TriageNotice(
            product_name="DEMO: auth0/node-jsonwebtoken (展示用サンプル)",
            notice_hash=compute_notice_hash(jwt_cps),
            announcement_date="直近公開 (展示用)",
            conclusion="【デモ表示】確認ポイントに Yes なら7日以内に修正。Noなら通常リリース（30日以内）。",
            fixed_versions="9.0.0",
            severity_note="High (CVSS 7.5)",
            check_points=jwt_cps,
            workaround="jwt.verify 呼び出し時に第3引数でアルゴリズムを明示的にホワイトリスト固定する。",
            unconfirmed_points=["推移的依存パッケージでの利用状況"],
            sources=["https://github.com/auth0/node-jsonwebtoken/security (デモ参考)"],
        )
    )

    return TriageReport(
        report_title="SBOM脆弱性トリアージ・現場即応指示書 (【DEMO】機能展示用データ)",
        report_version="1.0",
        is_dry_run=True,
        unscanned_or_failed_components=[
            "[DEMO NOTICE] 本レポートは --demo フラグにより生成された合成データです。実環境の調査結果ではありません。"
        ],
        notices=notices,
        pre_announcements=[
            PreAnnouncementNotice(
                source_id="demo-nodejs-security",
                source_name="Node.js Security Releases (展示用サンプル)",
                component_name="nodejs",
                title="Node.js 次期セキュリティリリース事前予告 (展示用)",
                expected_date="2026-11-03",
                expected_time="17:00 UTC (予定)",
                severity_hint="High",
                summary="【デモ表示】Node.js 20系および22系を対象としたセキュリティアップデートの事前予告。最高深刻度はHigh。",
                url="https://nodejs.org/en/blog/vulnerability/ (デモ参考)",
                is_official=True,
                recommended_preparations=[
                    "11月3日夜〜4日朝の輪番要員の手配・代休事前調整",
                    "フロントエンド/Node.js基盤担当ベンダーの作業枠仮押さえ",
                    "本番変更管理申請（RFC）の先行起票",
                ],
            ),
            PreAnnouncementNotice(
                source_id="demo-oracle-cpu",
                source_name="Oracle Critical Patch Update (展示用サンプル)",
                component_name="com.oracle:ojdbc8",
                title="Oracle CPU 次期定期セキュリティアップデート (展示用)",
                expected_date="2027-01-19",
                expected_time="20:00 UTC (予定)",
                severity_hint="定期セキュリティアップデート",
                summary="【デモ表示】四半期包括セキュリティパッチ (Oracle CPU)。Java/JDBCドライバ関連の修正見込み。",
                url="https://www.oracle.com/security-alerts/ (デモ参考)",
                is_official=True,
                recommended_preparations=[
                    "四半期パッチ適用枠の事前確保（第3火曜日翌日以降）",
                    "DBAおよびJava基盤担当ベンダーの作業枠仮押さえ",
                    "本番変更管理申請（RFC）の先行起票",
                ],
            ),
        ],
    )
