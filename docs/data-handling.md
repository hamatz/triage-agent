# データ送信とプライバシー・外部通信仕様 (Data Handling & Privacy)

企業のセキュリティ担当部門や情報管理部門が本ツールの導入を審査・判断できるよう、**「どの処理で、何が、どこへ送られるのか」「何が絶対に送られないのか」「送信範囲をどう制御できるか」** を透明かつ正確に開示します。

---

## 1. 外部通信とデータ送信の一覧

本ツールが実行時に行う外部通信は、以下の5系統のみです。

| 通信先 | 運営主体 | 送信されるデータ | 取得されるデータ | 目的 | 通信を無効化・制御する手段 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **OSV.dev API**<br>(`api.osv.dev`) | Google / Open Source Security Foundation (OpenSSF) | パッケージ名、バージョン番号（例: `lodash@4.17.20`） | 該当パッケージの既知脆弱性一覧、CVE ID、CVSS、修正バージョン | SBOM に含まれるコンポーネントの既知脆弱性を高速・一括検索 | `--exclude` で内製パッケージを除外<br>`--demo`（完全オフライン） |
| **Google Gemini API / Vertex AI** | Google LLC / Google Cloud | コンポーネント名、バージョン番号、脆弱性の要約テキスト、プロンプト | LLM による推論結果（Yes/No確認ポイント、発火条件、推奨アクションの下書き） | パッチ差分やアドバイザリに基づく発火条件の自然言語分析 | `--dry-run`（LLM 呼び出しを完全停止し静的照会・ルールベース推論のみ実施）<br>または Vertex AI 経由（企業向け Google Cloud 契約）の利用 |
| **事前予告フィード (RSS/Atom)** | 各 OSS プロジェクト（Node.js, Apache 等の公開 Web サーバー） | なし（HTTP GET 要求のみ） | 公開されているブログ記事やリリースページの本文・公開予定日 | パッチ公開前の事前予告カレンダー（`.ics`）や注意喚起の生成 | `--demo`（完全オフライン）<br>※フィード巡回は Recon 偵察フェーズで実行され、`--calendar` は .ics ファイルの書き出し先を指定します |
| **GitHub API / Web 検索** | GitHub Inc. / Google Search | 調査対象の OSS リポジトリ名、CVE 番号（公開情報のみ） | 公開コミットログ、公開 Issue / PR、公式リリースノート | 脆弱性の修正コミット差分（Diff）や詳細な発火条件の補足 | Web 検索（Google Search）は `--dry-run` で停止。<br>GitHub API は `--dry-run` でも通信します（停止は `--demo` のみ。未認証時はレートリミット自動保護） |
| **CISA KEV / FIRST EPSS API** | 米国 CISA / FIRST.org | CVE 番号（例: `CVE-2026-109618`） | 実侵害悪用フラグ（True/False）、EPSS 悪用予測スコア | 連鎖エクスプロイト判定における侵入足場（RCE）の客観的評価 | オフライン/dry-run実行時はローカルキャッシュ（`triage-output/cache/`）のみ参照 |

---

## 2. 絶対に外部へ送信されないもの（ローカル完結）

以下の情報は、**いかなる外部 API や LLM サービスにも一切送信されず、手元のローカルマシン内（Python プロセス）でのみ処理されます**：

1. **自社ソースコードおよび設定ファイル (`server.xml`, `php.ini`, `nginx.conf` 等)**:
   - `triage-verifier` は、Python の AST（抽象構文木）解析（docstring やコメントの除外を含む）および各言語・設定ファイルのコメント行や文字列リテラルを識別する構文走査（Pattern-based Scanner）エンジンによって手元で走査を実行します。
   - 自社のコード行、ファイルパス、設定値の本文が外部サーバーへ送信されることは一切ありません。
2. **監査サインオフの記録 (`audit_signoff.json`)**:
   - 誰が、いつ、どの環境（本番/検証）で、どのような証跡（Evidence）を見て非該当と判断したかという社内ガバナンス記録は、ローカルまたは自社の Git / CI 内にのみ保存されます。
3. **インフラ環境構成 (`environments.yaml`) と実機テレメトリ (`telemetry.json`)**:
   - ワークロードの外部公開度、ノードプールの所属、OS カーネル版番号、読み込み済みモジュール（`/proc/modules`）、稼働ネットワークサービス（IPsec/CNI）などのホスト構成情報は、**100% 手元の CPU で決定論的に突き合わせ評価** されます。
   - ホスト名収集は既定で匿名化（`anonymized-node`）されており、社外の通信にノード構成が漏れることはありません。
4. **自社独自の内製パッケージ名**:
   - 事前予告カレンダー（`upcoming_patches.ics`）には、情報漏洩・攻撃地図化を防ぐため内部パッケージ名は記載されず、対象件数サマリ（例: `対象 2 件`）のみが出力されます。
   - さらに、CLI 実行時に `--exclude` オプション（例: `--exclude "@mycompany/*,internal-*"`）を指定することで、自社内製パッケージを SBOM 読み込み段階で安全に除外でき、OSV.dev 照会や LLM への送信対象から完全に除外できます。

---

## 3. 送信範囲を制御・限定するための選択肢

企業のセキュリティポリシーに応じて、以下の3つの運用選択肢があります：

### 選択肢 A: Vertex AI（Google Cloud 企業契約）を利用する
商用 Gemini API ではなく、自社が契約する Google Cloud の Vertex AI をバックエンドとして利用可能です。

- **データ学習への不使用保証**: Google Cloud 利用規約（Terms of Service）に基づき、送信したプロンプトやデータがモデルの再学習に利用されることはありません。（※無料枠の Google AI Studio / Gemini API ではデータが製品改善に利用される可能性があるため、機密保持が求められる企業環境では有料枠または Vertex AI の利用を推奨します）。
- **リージョン指定（データ常駐）**: `asia-northeast1`（東京）など、日本国内リージョンを指定してデータを国内に留めることが可能です。環境変数 `GOOGLE_CLOUD_LOCATION`（または `GOOGLE_CLOUD_REGION`）で設定します。

```bash
# .env で Vertex AI を有効化
GOOGLE_GENAI_USE_VERTEXAI="true"
GOOGLE_CLOUD_PROJECT="your-gcp-project-id"
GOOGLE_CLOUD_LOCATION="asia-northeast1"
```

### 選択肢 B: LLM を使わず「照会＋カレンダー」のみ手元で動かす（`--dry-run`）
API キーを設定せず、または `--dry-run` を指定することで、**LLM へのプロンプト送信および Google Search を完全に遮断** できます。
この場合でも、OSV.dev による確定脆弱性の一括照会、公開 GitHub リポジトリのセキュリティアドバイザリ照会、および事前予告カレンダー（`.ics`）の生成は問題なく動作します。

```bash
# LLM への推論を行わず、静的解析・照会のみ実行
python -m triage_agent.cli --sbom my_sbom.json --dry-run --calendar upcoming.ics
```

### 選択肢 C: 完全オフライン・外部通信ゼロで試す（`--demo`）
`--demo` フラグを付与した場合、外部ネットワークへの通信（OSV, Gemini, RSS, GitHub, KEV/EPSS）をすべて遮断し、同梱の合成データのみを用いて手元で動作を検証できます。

```bash
python -m triage_agent.cli --demo
```

---

## 4. 企業内審査（社内セキュリティ部門向け Q&A）

### Q1. SBOM を外部に渡すこと自体がリスクになりませんか？
**A:** SBOM（ソフトウェア部品表）には自社が使用している OSS の名称とバージョンが含まれます。本ツールでは、OSV.dev および Gemini API にコンポーネント名とバージョンが送信されます。自社の独自リポジトリ名や内製プライベートパッケージについては、`--exclude` オプション（例: `--exclude "@mycompany/*,internal-*"`）でスキャン対象から除外するか、Vertex AI（学習不使用契約）経由での実行を推奨します。

### Q2. ソースコードを預けている受託開発ベンダーや顧客に対して説明が必要ですか？
**A:** 本ツールのコード走査エンジン（`triage-verifier`）は**完全にローカル環境（自社マシンまたは自社 CI ランナー）の Python プロセス内のみで動作**し、ソースコードや設定ファイルを外部のクラウドや AI に送信することは一切ありません。そのため、「顧客のコードを外部 AI に送信していない」と明確に説明できます。

### Q3. 生成されたレポートは外部に漏洩しませんか？
**A:** 出力ファイル（`triage_report.json`, `verification_audit_report.md`, `chain_audit_report.md`, `vendor_checklist.csv` 等）は、すべて手元のローカルディレクトリ（`triage-output/`）に保存されます。これらは攻撃者にとっての「脆弱性地図」になり得るため、既定で `.gitignore` の対象となっており、外部に自動公開されることはありません。
