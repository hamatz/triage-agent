# 事前予告カレンダー (Early Warning Calendar)

従来の脆弱性管理は「CVE が公表された直後」から始まります。しかし、金曜夕方や連休前夜に Critical CVE が公表されると、担当者の確保や変更管理申請が間に合わずパニックに陥ります。

事前予告カレンダー（`.ics`）を自社の Google カレンダーや Outlook、またはチーム共有カレンダーに取り込むことで、**CVE が発行される前に以下の先回りアクションを完了** できます：

1. **オンコール・当番エンジニアの事前確保**:
   「来週火曜日に Node.js の High 深刻度セキュリティリリースがある」ことが分かっていれば、リリースの数日前に夜間・翌朝の対応担当者をアサインしておけます。
2. **委託先ベンダーへの事前アラート（作業枠の仮押さえ）**:
   「○月○日に基盤ライブラリのパッチが出る見込みのため、翌営業日の適用テスト枠を空けておいてほしい」と事前に合意でき、当日の連絡の滞留や追加コストを防ぎます。
3. **本番変更管理申請（RFC: Request for Change）の先行起票**:
   厳格な金融システム等では本番適用の数日前までに変更申請の提出が必要です。「○月○日に予定されているセキュリティ修正の適用準備」として事前にドラフト申請を通しておくことで、パッチ公開後のリードタイムを最小化できます。

---

## 1. カレンダー生成コマンド

```bash
# SBOM 照会と同時に事前予告カレンダーを生成
python -m triage_agent.cli --sbom my_sbom.json \
  --output triage-output/triage_report.json \
  --calendar triage-output/upcoming_patches.ics
```

---

## 2. 公式事前予告ソースの対応状況

| 監視対象 | 手法 | 内容 |
| :--- | :--- | :--- |
| **Node.js** | RSS フィード自動巡回 | 公式ブログから予告日・影響バージョン・深刻度を抽出 |
| **Apache Tomcat** | Atom フィード自動巡回 | セキュリティリリース予告の抽出 |
| **Oracle CPU** | 公式スケジュール自動算出 | 毎年 1月・4月・7月・10月の第3火曜日 |
| **Microsoft Patch Tuesday** | 公式スケジュール自動算出 | 毎月 第2火曜日 |
| **PostgreSQL** | 公式スケジュール自動算出 | 毎年 2月・5月・8月・11月の第2木曜日 |
| **OpenSSL, Go, Python 等** | 一次情報源リンク提供 | 監視窓口の提示 |

---

## 3. 機密保護・社内情報の漏洩防止設計（ADR-013）

生成される `.ics` ファイルは共有カレンダーや外部 SaaS（Google Calendar / Outlook）に取り込まれることを想定しています。そのため、カレンダーのタイトルや本文には **自社の内部パッケージ名、独自サービス名、および具体的なインベントリ情報は載せず、対象件数のみを記載** します：

- **予定タイトル**: `【事前予告 [High]】Node.js Security Releases (対象 2 件)`
- **予定説明**: 内部パッケージ名は伏せられ、`【該当コンポーネント】2 件 (詳細は社内トリアージレポートを参照)` と記載。

---

## 4. 監視対象プロジェクトの追加方法 (`advisory_sources.toml`)

事前予告を拾うロジックはコードではなく宣言的な TOML データ（[`advisory_sources.toml`](../src/triage_agent/data/advisory_sources.toml)）として分離されています。社内で利用している OSS や独自ベンダーがある場合、このファイルに項目を追加するだけでカレンダー連携の対象を自由に拡張できます：

```toml
[[sources]]
id = "my-framework"
name = "My Framework Security Releases"
ecosystem = "npm"
package_patterns = ["my-framework"]
purl_patterns = ["pkg:npm/my-framework*"]
url = "https://example.com/security/blog/"
feed_url = "https://example.com/security/feed.xml"
type = "rss_feed"
is_official = true
cadence_hint = "事前予告は通常、リリースの数日前に公開されます。"
keywords = ["security release", "vulnerabilities", "upcoming"]
default_preparations = [
    "当該日の輪番要員の手配",
    "ベンダー作業枠の事前仮押さえ"
]
```

> 💡 **定期日程（fixed_schedule）の追加ルール:**  
> 定期日程は一行の書き間違いで毎月誤った確定予定を出してしまうリスクがあるため、公式ドキュメントで日程算出規則が明記されているもののみ登録可能です。TOML 内での `schedule_source_url`（公式根拠 URL）の記載を必須とし、推測や慣行に基づく日程は受け付けません。
