# 開発ロードマップ & タスクリスト (todo.md)

本ドキュメントは、`triage-agent` の今後の機能拡張、改善予定、およびバックログを管理します。
特に、**Engineering Enablement（専門家の手作業をソフトウェア化し、組織全体の脆弱性即応能力を高める構想）** の実現に向けた実務的・組織的ロードマップを定義しています。

---

## 0. 実装済み（Completed / v0.1）

- [x] **SBOM（Syft CycloneDX / JSON）からの自律巡回戦略策定（Recon Planner）**
- [x] **OSV.dev バッチ照会と GitHub API / Google Search Grounding の2段階動的調査（Researcher）**
- [x] **現場即応指示書生成（Triage Agent: 結論・期限・Yes/No確認ポイント・具体的確認方法・CVSS）**
- [x] **自社コードベース自動検証CLI（triage-verifier）と3値判定（YES/外部設定要確認/手動確認）**
- [x] **手動監査サインオフ突合の防衛的設計（check_point_id主キー完全一致・版突合・安全側判定）**
- [x] **Google Cloud Vertex AI（非学習・エンタープライズガバナンス）完全サポート**
- [x] **調査不能・未調査コンポーネント（GitHub 403レートリミット等）の漏れなき警告集約**
- [x] **ゼロ依存・Zero-CDN Web GUI Studio（DAWNデザイン・オフライン企業内稼働）**
- [x] **Web GUIにおける徹底防御（Content-Type/CSRF・Host/DNSリバインディング・ディレクトリトラバーサル・XSS遮断）**
- [x] **外注・ベンダー委託システム向けの手動/ベンダー回答サインオフ（YES/NO/要確認の記録・更新）**
- [x] **コードドリフト自動検知（matches_hash フィンガープリント照合による改変時の自動失効・誤検知の正当承認）**

---

## 1. v0.2 実装完了（Completed: v0.2.0〜v0.2.5）

- [x] **肥大化ファイルのモジュール分割リファクタリング（v0.2.5対応完了）**
  - **Web UI の関心事分離 (`triage_agent.ui`):** 1,970行あった `web_ui.py` から HTML (`templates/index.html`)、CSS (`static/style.css`)、JavaScript (`static/app.js`) を独立ファイルとして分離。Python文字列内エスケープ事故（`\n`展開や構文エラー）を根本根絶し、エディタリンター・構文検査に対応。
  - **Verifier の責務別パッケージ化 (`triage_agent.verifier`):** 800行のモノリシックだった `verifier.py` を、データモデル (`models.py`)、AST構文解析・コード走査 (`scanner.py`)、サインオフ突合・ドリフト検知 (`attestation.py`)、検証エンジン (`engine.py`)、Markdown生成 (`report.py`)、CLI (`cli.py`) に分割。各ファイルを 50〜300 行程度に整理し、保守性・テスタビリティを大幅向上。
- [x] **Web UI におけるレポート保存（Export）と以前のレポート読込・継続編集（Import / Resume）機能（v0.2.5対応完了）**
  - Web UI（DAWN Studio）から、生成された指示書（Markdown / JSON）および検証結果レポート（Markdown）を安全なファイルパスへ直接保存。
  - **堅牢なファイル上書き防止（ADR-013）:** 保存先を専用ディレクトリ `triage-output/` 配下に限定し、拡張子も `.md`, `.json` のホワイトリストに制限。ソースコード（`src/`）や機密設定ファイルへの任意上書き攻撃を完全に排除。
  - **厳格なセキュリティレスポンスヘッダーの導入:** `Content-Security-Policy (script-src 'self', style-src 'self' 'unsafe-inline')`、`X-Content-Type-Options: nosniff`、`X-Frame-Options: DENY`（クリックジャッキング対策）をすべての HTTP レスポンスに適用。インラインイベントハンドラ（`onsubmit` 等）を完全排除。
  - ブラウザからの直接ダウンロード（Markdown / JSON）ボタンをアクションバーに配備。
  - 過去に保存した `triage_report.json` をモーダルから即座に読み込み、外部API照会を行わずにUIを瞬時に復元。サインオフの追加やコードベース検証の再実行（継続編集）が可能に。
- [x] **調査カバレッジ・深度サマリ（Recon Coverage Summary）の明示（v0.2.5対応完了）**
  - 上限（`--max-targets`）により深層調査を省略したコンポーネント（OSVヒット0件）について、「全 ◯ 件中、上位 ◯ 件を深層調査。残り ◯ 件はOSV照合（0件）のみ実施」という情報サマリ（Info）をレポートおよび画面に明記。
  - CIの `--fail-on`（未調査・失敗コンポーネント）には影響を与えず、読む人が調査範囲（OSV照合のみでWeb/コミット深掘りは省略されたこと）を誤解しない透明性を確保。
- [x] **Self-Triage における件数上限（`--max-targets`）自動最適化と未調査誤認アラートの解消（v0.2.5対応完了）**
  - `--self-triage` 指定時は `--max-targets` の既定値を内部全依存関係を走査可能な 50 に自動引き上げ。
  - OSV照会で脆弱性ヒットが0件だった健全なコンポーネントが「調査省略」として未調査警告（UNSCANNED WARNING）に誤分類される問題を解消。Level 1（機械的チェック）クリアとして正しく集計。
  - 依存ライブラリ名のパース処理におけるカッコ付きバージョン指定（例: `markdown-it-py (>=2.2.0)`）への完全対応。
- [x] **SPDX JSON 形式（ISO/IEC 5962）へのネイティブ対応拡充（v0.2対応完了 / ADR-017）**
  - CycloneDX JSON に加え、SPDX 2.2 / 2.3 / 3.0 JSON 形式（`spdxVersion`/`packages`/`externalRefs`）の直接パースに対応。
  - Trivy、Docker Scout、cnspec 等の出力もそのまま受け入れ可能になり、SBOM 2大国際標準を完全網羅。
- [x] **Web GUI リアルタイムプログレスバー & 進捗ストリーミング（v0.2対応完了 / ADR-016）**
  - Python標準ライブラリの `http.server` で Server-Sent Events (SSE) `/api/run-stream` を実装。
  - DAWN デザインに調和したグラデーションプログレスバー、パーセンテージ（0〜100%）、3段階 Phase インジケーター（Recon Planner → Researcher → Triage Agent）、リアルタイムの調査対象ライブラリ名表示を実装し、調査待機時間のストレスを大幅に軽減。
- [x] **GitHub Token 完全撤廃と OSV-Scanner / OSV.dev への脆弱性調査一本化（Tokenless Architecture / ADR-014対応完了）**
  - GITHUB_TOKEN の設定・管理を不要にし、PAT漏洩や権限昇格リスクをアーキテクチャから根本排除。
  - 完全無料・認証不要・オープンな OSV.dev (OSV-Scanner バックエンド) をプライマリに採用し、CVE alias、CVSS score、影響・修正バージョン、修正コミット/アドバイザリ参照URLを高精度取得。
  - GitHub API レート制限（403）に起因する不要な未調査警告（UNSCANNED WARNING）を解消し、未認証環境でも即座に高品質なトリアージを実行可能に。
- [x] **ランタイム環境の Python 3.11+ / 3.12 移行（v0.2対応完了 / ADR-015）**
  - Python 3.9 EOL に伴うサポート終了警告を解消し、Faster CPython による AST 解析・JSON パースを大幅高速化。
- [x] **Verifier判定文言の精緻化（v0.2対応完了）**
  - 単なるキーワード照合結果を断定的な「該当・要対応」と決めつけず、画面およびレポート上で `YES (本番コード内検出・要実地確認)` / `YES (テストコード内のみ検出・本番未検出)` と客観的に明示。
  - 理由欄にもテストコードや到達不能パスの可能性を明記し、発火時は修正、影響を受けない場合はサインオフ（誤検知・許容）を促す誠実なガイダンスへ刷新。AST/到達可能性解析による完全証明との境界線を明確化。
- [x] **テストコード自動認識・スコープ分離（v0.2対応完了）**
  - `test/`, `spec/`, `__tests__/`, `*test*.js`, `test_*.py` などのテスト・モックファイルを自動判定し、本番コードとテストコードを分離。
  - テストコード内にしか該当コードがない場合は `YES (テストコード内のみ検出・本番未検出)` と判定し、現場の不毛な誤検知アラート疲弊を防止。
- [x] **Python AST（抽象構文木）解析エンジンの導入（v0.2対応完了）**
  - Pythonファイル走査において、標準 `ast` モジュールによる構文木解析を導入。docstring やコメント内の文字列を完全無視し、実際の関数呼び出し（`Call`）やキーワード引数（`keywords`）のみを高精度検出。
  - C/JS/TS系言語における `/* ... */` ブロックコメントの自動スキップにも対応。
- [x] **Self-Triage（ドッグフーディング自己診断）と「3つの鮮度」運用原則の実装（v0.2対応完了 / ADR-018）**
  - `triage-agent` 自身の依存関係から CycloneDX 1.4 JSON SBOM を動的に生成する自己SBOM生成エンジン（標準ライブラリ `importlib.metadata` + `tomllib`）を実装。
  - `--self-triage` オプションおよび `scripts/self_triage.sh` により、triage-agent 自身のコードベース（`src/triage_agent`）を自ら走査して脆弱性を診断するドッグフーディング機構を実現。
  - 週次定期実行を行う GitHub Actions ワークフロー（`.github/workflows/self-triage.yml`）を配置し、外部API仕様変化やモデルの風化を自動検知。
  - 「システムの鮮度（定期更新）」「SBOMの鮮度（CI自動生成）」「ツールの鮮度（ドッグフーディング）」の3つの鮮度を開発・運用の恒久原則として確立。

---

## 2. v0.3.0 実地試行（PoC）即応マイルストーン（ADR-019 / ADR-020）

実地試行（PoC）で評価される「公開から配布までの時間短縮」「ベンダーとの往復回数削減」を直接達成し、さらに「緊急対応を予定された作業に変える（パッチカレンダー）」という本ツールの真のコア価値を確立するための実務最優先マイルストーンです。

### 柱 1: 事前予告カタログとカレンダー連携（Early Warning Calendar / ADR-020）
- [x] **事前予告データカタログ（`advisory_sources.toml`）の設計・初期データ整備（v0.3対応完了）**
  - 公式一次情報源（URL、RSSフィード、メーリングリスト、固定リリース日程、UTC時刻）を宣言的データとして外部化：
    - Node.js（公式ブログ RSS フィード: `https://nodejs.org/en/feed/vulnerability.xml`）
    - OpenSSL（メーリングリスト事前予告、最高深刻度事前通知）
    - Go（golang-announce メーリングリスト）
    - Tomcat（announce メーリングリストおよび RSS/API）
    - Oracle Critical Patch Update（四半期固定日程・第3火曜日ルール・21:00 UTC / 翌水曜 06:00 JST）
    - Microsoft Patch Tuesday（毎月第2火曜日ルール・18:00 UTC / 翌水曜 03:00 JST）
    - Python（python-announce-list メーリングリスト）
    - Django（毎月第1月曜日・固定リリースルール・14:00 UTC / 翌火曜 23:00 JST）
    - PostgreSQL（四半期固定日程・2/5/8/11月第2木曜日ルール・13:00 UTC / 翌金曜 22:00 JST）
    - Apache HTTP Server / Nginx（`category = "primary_advisory"` 公式一次アドバイザリ参照枠）
  - スキーマに `category`（`pre_announcement` vs `primary_advisory`）を導入し、事後アドバイザリ情報源が事前予告カレンダーを日付なしノイズで汚染しないよう防護。
  - Spring Boot同梱の `tomcat-embed-core` 等に対応するため、`purl_patterns`（`pkg:maven/org.apache.tomcat*/*` 等）や `group:name` マッチングを実装。
  - 利用者がPRで監視対象を追加・共有できるオープンコミュニティ資産（堀）として `src/triage_agent/data/advisory_sources.toml` を設計。
- [x] **2段階定点巡回エンジン（Researcher）の実装（v0.3対応完了）**
  - **1段目:** `advisory_sources.toml` に基づく公式一次ソースの決定論的フェッチ・RSSフィード巡回・次回予定日自動算出（APIキー不要・結果固定・高速）。
  - **巡回失敗の明示:** フィード取得エラーやタイムアウトが発生した場合は握り潰さず、レポートの `unscanned_or_failed_components` に未調査警告として明示（「調べなかったものを隠さない」「作った内容を本物に見せない」原則の厳格適用）。
  - **2段目:** 検出された事前予告を自社SBOMコンポーネントと照合し、推奨初動チェックリスト（輪番確保、変更管理RFC起票、ベンダー仮枠押さえ）を生成。
  - **フォールバック:** カタログ未登録パッケージ向けに Google Search Grounding を補助網として維持。
- [x] **公式一次情報と「未確認の予兆」の明示的区別（v0.3対応完了）**
  - 公式一次ソースからの「確定予告」（`is_official=True`）と、Web検索・LLM調査等からの「未確認の予兆」（`is_official=False`）を厳格に分離。
  - 同一コンポーネントに複数の予兆がある場合にも破棄せず全件を保持。
- [x] **iCalendar（`.ics`）エクスポートの実用化・機密保護（v0.3対応完了）**
  - **決定論的 UID:** 再インポート時に予定が重複せず、上書き更新されるUID算出。
  - **情報源 × 予定日の集約:** Patch Tuesday に複数パッケージが該当しても 1 件のイベント枠に集約（タイトルに対象件数を表示）。
  - **UTC 時刻化（日米時差対応）:** 終日指定ではなく `DTSTART:...Z` の UTC 時刻枠を出力し、カレンダーアプリが日本時間（水曜深夜〜早朝）で自動正しく配置。
  - **機密性保護（ADR-013）:** 外部カレンダーサービスの DESCRIPTION に自社全パッケージ一覧を丸出しにせず、件数とトリアージレポート参照にとどめて攻撃地図化を防止。
  - **RFC 5545 準拠:** 75オクテット Line Folding（`\r\n `）およびエスケープ処理（`\,`, `\;`, `\\`, `\n`）。
  - CLI オプション `--calendar output.ics` および Web UI アクションバーへの「📅 予定表ダウンロード」ボタン・モーダルUI追加。

### 柱 2: Verifier の実戦的拡張（設定ファイル ＋ 主要3言語 / ADR-019）
- [x] **設定ファイル検証エンジン（XML / INI / Conf / Properties）の導入（v0.3対応完了）**
  - Tomcat `server.xml`（AJPコネクタの有無・secretRequired/secret/requiredSecret保護状態）、PHP `php.ini`（`session.upload_progress.enabled`）、Nginx設定ファイル（`http2 on` / `http2 off`）のセマンティック自動検証（`src/triage_agent/verifier/config_scanner.py`）。
  - **複数設定ファイルの全走査と集約:** 最初に見つかった1ファイルで早まった判定を下さず、`conf.d/*.conf` や環境ごとの複数設定ファイルを網羅。1つでも脆弱な設定があれば YES、すべて明示的に無効化されている場合のみ NO、未記載または解析不能なら外部設定要確認。
  - **PHP conf.d 階層上書き評価（後勝ち）:** `php.ini` に続いて `conf.d/*.ini` をアルファベット順に評価し、後のファイルによる設定上書きを正確に反映。PHP-FPMプール設定（`www.conf`）や `.user.ini`、`.htaccess` の存在も検知して未解析時は安全側に「外部設定要確認」へ倒す。
  - **「分からないものを安全と言わない」の徹底:** Nginx で http2 設定が未記載の場合、include や外部LB/CDN終端の可能性があるため安易に NO とせず「外部設定要確認」に倒す。PHP配布用テンプレート（`php.ini-production` 等）は実設定の証拠とせずスキップ。
  - **構造化された検証マッピング（`config_check`）:** 単なる文字列の部分一致（server.xml や http2 の単語だけ）での誤爆を防ぎ、確認ポイントに `Literal["tomcat_ajp", "nginx_http2", "php_upload_progress"]` の厳格な型付き明示フィールドを導入。プロンプトにも付与基準を明記し、推測でディスパッチされた場合は根拠欄に明記。
  - **構文解析エラーの明示:** XMLのパース失敗（`&nbsp;` 等）を黙って握りつぶさず、「構文解析エラーのため要確認」として出力。
  - **コメント除去の堅牢化:** XMLコメント（1行内の複数 `<!-- ... -->` および複数行）、INIコメント（`;`）、Confコメント（`#`）を完全除去し、コメントアウトされた設定による誤検知を根絶。
  - **Tomcat AJP 行番号精緻化:** 複数行にまたがる `<Connector ... protocol="AJP/1.3"` タグブロックの開始行を正確に特定。
- [x] **主要3言語（JavaScript/TypeScript, Java, PHP）の構文走査強化（v0.3対応完了）**
  - Cスタイル言語（JS/TS, Java, Go, PHP等）における `/* ... */` ブロックコメント、`//` 行コメントの完全除外。
  - 設定ファイル名（`server.xml`, `php.ini`, `nginx.conf` 等）自体の言及によるコード検索誤マッチを除外するトークンフィルタを導入。
  - テストコード自動分離（`__tests__`, `*Test.java`, `*.test.js`, `tests/` 等）の厳格適用。
- [x] **「客観的3状態（YES/外部設定要確認/手動確認要）」の維持（v0.3対応完了）**
  - 到達可能性解析（Taint解析）への安易な深入りを避け、「分からないものを安全と言わない」の原則を堅持。

### 柱 3: ベンダー往復のワークフロー支援（Excel / CSV 連携 ＆ 往復履歴 / ADR-019）
- [x] **早見表の CSV（.csv）帳票エクスポート機能（v0.3対応完了）**
  - トリアージ指示書から、サイバーセキュリティ部・情シス・委託先との標準プロトコルである UTF-8 BOM付き CSV 早見表をワンクリック出力（Excelでの文字化け完全防止）。
  - **CSVインジェクション（数式実行）防護:** セル先頭が `=`, `+`, `-`, `@` で始まる場合にシングルクォート `'` を付与してExcelマクロ・数式実行を無害化。
  - **対象製品/システムでのスコープ絞り込み（ADR-013）:** 委託先ごとに他社システムの攻撃地図が漏洩しないよう、`--export-checklist-target` や Web UI から特定製品のみを切り出して出力可能。
  - **案件ごとの配布ID（DistributionID）発行:** 出力時に `DIST-YYYYMMDD-XXXX` を発行し、CSVヘッダーとメトリクスにバインド。
- [x] **ベンダー回答のインポート ＆ サインオフ自動確定（履歴化）（v0.3対応完了）**
  - 記入済み CSV を一括取り込み、`audit_signoff.json` に反映（`src/triage_agent/tools/vendor_workflow.py`）。
  - **厳格な完全一致判定（「安全」の過大評価防止）:** 前方一致や部分一致を排し、`NO` / `非該当` / `該当なし` などの完全一致のみを対象化。`Not sure`, `No idea`, `NOT CHECKED YET`, `安全かどうか未確認` などの曖昧な回答はすべて「要確認」に倒す。
  - **根拠と確認者の捏造撤廃:** NO 回答であっても根拠または確認者が未記入の場合は「要確認（根拠・確認者未記入）」として保留（手動確認対象）。
  - **既存サインオフの消失・破壊防止:** 既存 JSON の破損時はフェイルファストで処理中断。社内 YES に対するベンダー NO 回答は「要再確認（社内YESとベンダーNOの競合⚠️）」として検知し、安易な上書きを阻止。社内YES維持時もベンダーの実際の回答を根拠欄に正確に併記。
  - **出力ディレクトリ（triage-output/）移行時のシームレス統合:** GUI取り込み時に `triage-output/` にまだファイルが存在しない場合、元のワークスペース（ルート）のサインオフを読み込んでからベンダー回答と合流させて出力し、社内サインオフのサイレント消失を根絶。移行通知もレスポンスに明示。
  - **Web UI におけるパストラバーサル防護:** `/api/import-checklist` で保存先を `.json` に限定し、安全なパス解決を強制。
- [x] **案件（配布ID）単位の試行メトリクス自動計測ログ（v0.3対応完了）**
  - 配布IDごとに「配布時刻」「回答受領時刻」「往復回数」「ターンアラウンド所要時間（hours）」を記録（`triage-output/workflow_metrics.json`）し、複数案件が並行しても2月の成果報告用エビデンスを正確に個別集計。

### 柱 4: 品質担保のための正解付きミニ評価セット（Benchmark Suite / ADR-019）
- [x] **実事例ミニリポジトリの作成 (`benchmark/`）（v0.3対応完了）**
  - 直近の実事例（Node/jsonwebtoken, Tomcat/AJP Ghostcat, PHP/session upload progress, Nginx/HTTP2Shell Rapid Reset）を標準化された正解ラベル（`expected: "YES" | "NOT_YES" | "UNVERIFIED"`）付きの最小再現ファイルおよびグランドトゥルースマニフェスト（`benchmark/manifest.json`）として整備。
  - コメントアウトや明示的無効化設定を含むネガティブケース（`benchmark/cases_negative/`）も完備。
  - 柱2・柱1で見逃しを防いだ難関エッジケース（`benchmark/cases_hard/`: Case A conf.d包含, Case C2 複数server.xml, Case G PHP上書き, Case D 質問誤爆防止, Case E 構文エラー安全退避）および事前予告フィード実例（`benchmark/feeds/`）を正式データセット化。
- [x] **見逃し（False Negative）・誤検知（False Positive）の自動検知テスト（v0.3対応完了）**
  - Verifier の言語・設定追加時に、過去の正解判定が壊れていないかを自動判定するベンチマークスイート（`tests/test_benchmark_suite.py`）を実装。全ケース100%パスを検証。
- [x] **「数字で語れる」ベンチマーク集計ランナーの実装（v0.3対応完了）**
  - `python -m triage_agent.benchmark` および CLI `--benchmark` により、即座に2月報告用サマリ（例: `陽性 8件中 8件検出（見逃し 0）／陰性 9件中 誤検知 0／要確認 2件 (総合正解率: 100.0%)`）を出力。
  - 判定の内訳および推移追跡用メトリクスを `triage-output/benchmark_results.json` に自動出力。

---

## 3. Engineering Enablement 推進に向けた戦略的ロードマップ (v0.4〜v1.0)

Engineering Enablement（専門家依存の解消と組織的な即応）を実現するため、単なる機能追加にとどまらず、全社運用に耐えうるガバナンスと知識蓄積を強化します。

### 進化像の5つの柱

| 柱 | ① スコープ階層化 | ② 判定精緻化 | ③ システム知識化 | ④ MTTR/ROI可視化 | ⑤ 成果物機密管理 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **英名** | Clarity of Scope | Contextual Attestation | Architectural Knowledge Base | Lifecycle Metrics & MTTR | Confidentiality & Data Minimization |
| **主要テーマ** | 機械照合・AI深層調査・未調査の3層分離 | 環境・構成版・有効期限付きサインオフ | システム恒久事実の辞書化と再利用 | 各フェーズ所要時間と削減効果の定量化 | 「攻撃地図化」の防止・最小特権・TTLパージ |

### ① 調査範囲の3層階層化と全社スキャン基盤連携（Clarity of Coverage & Scope）
- [ ] **3層ステータスモデルの導入**
  - 「調査で安全と判明した」と「調査リソース上限やAPIエラーで未調査」の混同を完全に防ぐステータス設計：
    1. `Layer 1: 機械的照合済`（OSV等のデータベース照合が完了したコンポーネント）
    2. `Layer 2: AI深層調査済`（Triage Agent がパッチDiffや発火条件まで精読したコンポーネント）
    3. `Layer 3: 調査対象外 / 調査不能`（深掘り上限到達、レート制限、外部エラー等）
- [ ] **全社資産管理・脆弱性基盤（Dependency-Track 等）との役割分担・連携**
  - 全社何百システム・数万コンポーネントの機械的網羅スキャンは Dependency-Track などの基盤に委ね、triage-agent は「緊急度・優先度の高い脆弱性の深層調査・指示書化・現場トリアージ」を担う専門レイヤーとして接続。

### ② サインオフのコンテキスト紐付け ＆ OS/カーネル層の攻撃連鎖トリアージ（Contextual Attestation & Exploit Chain Triaging）

> **背景（実事例）:** PHP2Shell（CVE-2026-109618 / 109619、2026-10-21 修正）で侵入し、5か月前に PoC 付きで公表済みだった Fragnesia（CVE-2026-46300、カーネル LPE）で root を奪取する連鎖により、境界ファイアウォール等 25 台が侵害された（Dream 報告、2026-10-26）。
> 「ローカル限定だから低優先」と後回しにされた LPE が、新しい RCE の出現で一気に致命傷になる。
> 本項の目的は、カーネル CVE の網羅ではなく、**アプリ層と OS 層の優先度の隙間を埋めること**にある。

#### ②-1 土台：環境・バージョン・有効期限（TTL）付きサインオフ（v0.3.1先行対応完了）
- [x] **サインオフにコンテキスト属性を付与:**
  - **対象環境:** `Production` / `Staging` / `Development`（ホスト群・クラスタ単位）
  - **有効期限（TTL）:** `valid_until: "YYYY-MM-DD"`。期限切れで Verifier が自動的に「要再確認（サインオフ期限切れ⚠️）」へ倒す安全設計。
  - **根拠の種類を区別して記録:**
    - `iac_config`（構成コード・マニフェスト）／`live_telemetry`（実機スクリプト観測）／`vendor_attestation`（ベンダー回答・配布ID）

#### ②-2 中核：未解消のローカル権限昇格（LPE）台帳 ＆ 連鎖評価（v0.4.0対応完了）
- [x] **LPE 台帳（Exploit Chain Ledger）:**
  - 環境ごとに「未パッチかつ緩和策未確認の LPE／コンテナ脱出」を保持（`environments.yaml` および `kernel_ledger.json`）。
  - **対象の絞り込み:** 非特権ユーザーからの root 昇格、コンテナ脱出（Fragnesia: CVE-2026-46300 等）。
  - **優先度の材料:** PoC 公開の有無、CISA KEV 掲載の有無、EPSS スパイク値。
- [x] **連鎖評価（新規 RCE 発生時の突合）:**
  - 新しい RCE の予告・公表時に、同一ノードプール・カーネル環境上の LPE 台帳を突合。
  - **単純ルールで判定:** 「外部から到達可能な RCE（または信頼できないコード実行環境・CIランナー）」＋「未解消 LPE」が同一環境 → **最優先（Critical Exploit Chain、48時間以内）**。
  - **Fail-Safe の徹底:** KEV 取得失敗時やベクトル未確定時は「要確認（足場判定不能）」へ倒し、未知のゼロデイに備え内部限定ノードでも2週間の期限を設定。
- [x] **SLA への反映（運用ルール）:**
  - 外部公開の入口を持つホストでは、PoC 公開済み LPE を「ローカル限定」を理由に低優先としない。

#### ②-3 情報収集：カーネル／OS 層の公表を即座に台帳へ（v0.4.0対応完了）
- [x] カーネルは事前予告文化がないため、公表即台帳化・評価セット化として扱う。
- [x] **監視ソース（CISA KEV, EPSS API, OSV.dev, Distro Trackers）:**
  - オフライン時はローカルキャッシュ（`triage-output/cache/`）を参照し、取得失敗時は安全側に要確認へ倒す。
- [x] **ディストリビューション系統（Flavor）の完全分離:**
  - `ubuntu:24.04` の一般カーネル版で AWS 向けカーネル（`6.8.0-1015-aws` / `linux-aws`）が誤認バイパスされないよう、フレーバー完全一致または未確定（要確認）へ倒す分離ロジックを実装。
  - dpkg バージョン比較規則（`~`、エポック、文字順序）および RPM バージョン分割規則の完全準拠。

#### ②-4 Researcher / Mitigations：緩和策の構造化検証と副作用検知（v0.4.0対応完了）
- [x] **緩和策レジストリ（`kernel_mitigations.toml`）:**
  - 発火条件（必要なモジュール: `esp4`, `esp6`, `rxrpc`）および無効化手法（`modprobe_disabled_modules`）。
  - **緩和策の副作用検知:** IPsec（strongSwan）や AFS などの稼働サービスを検知し、モジュール無効化による業務停止副作用がある場合は即座に `CANNOT_MITIGATE`（緩和不可・パッチ必須）と判定。
- [x] **架空パラメータ混入防止（Grounding Guardrail）:**
  - 出典URLと根拠を明記。

#### ②-5 実機テレメトリ（`/proc`）と安全なノード集約（v0.4.0対応完了）
- [x] **実機ノード情報（NodeTelemetry）の収集と決定論的評価:**
  - `/proc/modules`（ロード済み）、`modules.builtin`（組み込みモジュール）、`/etc/modprobe.d/`（無効化設定）、稼働サービスを JSON 経由で取得。
  - 組み込みモジュール（`=y`）は modprobe で無効化できないため、即座に未緩和と判定。
- [x] **同一ノードプール内の複数ノード集約（Fail-Safe Aggregation）:**
  - 読み込み順序に依存しない集約エンジン：
    - `loaded_modules`: 全ノードの和集合（UNION）（1台でも残っていれば未緩和）
    - `modprobe_disabled_modules`: 全ノードの積集合（INTERSECTION）（全台無効化のみ有効）
    - `xfrm_active`: いずれかのノードで有効（ANY）
    - `kernel_package_version`: 全ノード中最も古い版番号を採用。
    - **版番号・OS不明時の安全側倒し:** 1台でも版番号やOSが不明なノードがあればプール全体も「不明」とし、「要確認（該当の可能性あり⚠️）」へ倒す。
    - **実機テレメトリの正本性担保:** 実機テレメトリがあるプールでは、手書きの `environments.yaml` にフォールバックせず実機状態のみを根拠とする。実機なしの手書き判定時は「構成定義上（実機未確認）」と明記。

#### ②-6 データ送信・プライバシー開示と内製パッケージ秘匿（v0.4.0対応完了）
- [x] **外部通信とデータ送信仕様の完全開示（`docs/data-handling.md`）:**
  - 外部通信先5系統（OSV, Gemini/Vertex, RSS, GitHub, KEV/EPSS）の送信データと目的、完全ローカル完結データ（コード、環境構成、サインオフ）を明記。
  - Google Cloud Vertex AI の `GOOGLE_CLOUD_LOCATION`（東京 asia-northeast1）および利用規約（学習不使用）への対応。
- [x] **内製パッケージの秘匿除外（`--exclude`）:**
  - CycloneDX の `group` 分割記法や URL エンコードされた PURL（`%40`）にも対応した glob パターン除外。
  - 意図的な除外（`excluded_components`）と調査エラー（`unscanned_or_failed_components`）を分離し、`--fail-on unscanned` との両立を実現。
  - CI環境（`CI=true`）ではログへの社内パッケージ名露出を防止（件数のみ出力）。

#### ②-7 評価セット（v0.4.0対応完了）
- [x] `benchmark/` に Fragnesia + PHP2Shell 連鎖、CIランナー足場連鎖、IPsec副作用阻害、版番号不明フェイルセーフケースを追加し、全28ケース100%合格（見逃しゼロ）を達成。

---

## 4. v0.5.0 実地試行（PoC）即応マイルストーン（System Profile / Container Boundary / Trial Report）

実地試行（PoC）で評価される **「ベンダー往復回数の削減」「対応所要時間の短縮」を直接数値で証明する** ための最優先マイルストーンです。

### 柱 A: System Profile（組織知化）：4つの安全歯止め付き設計
脆弱性ごとの一過性のサインオフにとどまらず、ベンダーやエンジニアから得られた「システムの構成事実」を蓄積し、次回以降の重複照会を劇的に削減します。

- [ ] **期限 & 確かめ方付き構成事実データモデル (`system_profile.yaml`)**:
  - 「恒久」と呼ばず、必ず有効期限と検証方法を付与。
  - **機械検証可能事実（`php.ini`、`server.xml`、`nginx.conf` 等）**:
    - プロファイルは前回ベースラインとして扱い、実行ごとに Verifier で必ず再走査（コード変更があれば即座に検知）。
  - **非機械的事実（「SGでLDAPを外部遮断」「専用閉域網運用」等）**:
    - 対象環境（`environment`）、有効期限（`valid_until`）、根拠の種類（`evidence_type: iac_config | live_telemetry | vendor_attestation`）を必須化。期限切れは自動で「要再確認（プロファイル期限切れ⚠️）」へ倒す。
  - **判定文言の明示**:
    - `NO (構成プロファイル・2026-10-15 確認・期限 2027-10-15・ec-sales-core)` のように時点・期限・システムIDを明記。
- [ ] **`config_check` 構造化キー完全一致ディスパッチ（LLM推測禁止）**:
  - 自然言語による曖昧な対応付けを禁止し、v0.3.0 で整備した `config_check`（`tomcat_ajp`, `nginx_http2`, `php_upload_progress` 等）の構造化キー完全一致でのみ自動解決。
  - 一致しない確認ポイントは安全側に倒して通常照会。
- [ ] **ベンダー CSV の「確認のみ（事前回答入り）」出力**:
  - プロファイル合致項目を CSV から消さず、変化検知のために行を保持。
  - 回答欄に `【事前確認済】無効 (前回: 2026-10-15確認済)。変更がなければ空欄のまま返送してください` を記載し、ベンダーの手間を実質ゼロ化。
  - 往復回数計測で「確認のみで済んだ行」を分離集計し、2月の経営報告で「照会の ◯ 割が確認のみ（ゼロ工数）で完了した」と数値化。
- [ ] **サインオフからの候補書き出し & 人手承認フロー (`--export-profile-candidates`)**:
  - `audit_signoff.json` から候補を抽出し、`status: pending_review` で出力。
  - 人間（アーキテクト）が内容を確認し承認（`status: approved`、承認者名、承認日付）したものだけを `system_profile.yaml` に組み込み。

### 柱 B: コンテナ境界走査（危険を上げる方向・Critical昇格のみ）
Kubernetes マニフェスト（Pod/Deployment）や Compose の設定を走査し、攻撃連鎖（Chain Audit）に結合します。

- [ ] **コンテナ境界破断フラグの走査と Critical 昇格**:
  - `securityContext.privileged: true`
  - 危険ケーパビリティ（`CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_DAC_OVERRIDE` 等）
  - `hostPID: true`, `hostNetwork: true`, `hostIPC: true`
  - `allowPrivilegeEscalation: true` かつ root 実行
  - 検出時はアプリRCEとカーネルLPEの連鎖を即座に **Critical Exploit Chain（48時間以内即時対処）へ昇格**。
- [ ] **安易な緩和の禁止 & 証跡の区別**:
  - `restricted` な Pod であっても期限緩和（48h→2週）は禁止（カーネルLPEは通常システムコール経由で届くため）。
  - マニフェスト走査は `iac_config`（構成コード上）として扱い、実機 Pod 稼働テレメトリ（`kubectl get pod -o json`）と明確に区別。

### 柱 C: 試行レポート機能（経営報告直結の可視化）
試行評価・役員報告でそのまま使える定量レポートを出力します。

- [ ] **総括指標（KPI）集計エンジン**:
  - T(-1)〜T4 の MTTR リードタイム短縮実績（基準値 74.9 時間との比較、短縮時間・短縮率）。
  - 配布IDごとの往復回数および「確認のみ化率（%）」。
  - 夜間・休日（Off-Hours）緊急招集の削減件数。
- [ ] **Markdown 試行総括レポート (`triage-output/trial_summary_report.md`)**:
  - スライドや社内 Wiki に直接貼り付け可能な Markdown 表形式。
- [ ] **Web GUI (DAWN Studio) 試行サマリカード**:
  - ダッシュボード上部に重要 KPI（短縮時間、確認のみ化率、事前予告件数）をカード表示。

### 柱 D: 実地試行現場フィードバック吸収枠（2〜3割）
- [ ] 現場やベンダーからの「この確認ポイントが伝わらなかった」「この設定記述に対応してほしい」という声に応じた `config_check` 語彙の追加・微調整枠の確保。

### 柱 E: 攻撃連鎖評価の運用手順化とカーネル脆弱性の自動照会（ADR-021）
v0.4.0 の連鎖評価を、複数マシンからの収集を前提とした運用に耐える形にし、手動台帳に載っていないカーネル LPE も横展開で見つけられるようにします。特定のクラウドやディストリを前提にしない（ディストリ中立）ことを原則とします。

- [x] **① 収集カバレッジ・鮮度・プール不一致の検出と付随修正**
  - 期待ノード数に満たないプールでは SAFE / 緩和済みを出さない。`--telemetry-max-age`、`pool_id` 必須、安定した匿名ノード ID、`collection_manifest.json` の読み込み。
- [x] **② 手順書の書き直しと収集マニフェストの補助スクリプト**
  - `docs/exploit-chain.md` を 6 段構成に再編。ssh / kubectl / AWS SSM 向けの補助スクリプト（`scripts/collect/`）。
- [ ] **③ 照会元アダプタの共通契約、OSV と ALAS、3 層分類、プールごとの「この版まで上げれば解消」表示**
  - [x] 事前検証（2026-11-02）: ALAS は AL2023（本体・livepatch）と AL2（本体・Extras 5.10/5.15）の `updateinfo.xml` から CVE・修正版・重大度を取得可能。OSV は Ubuntu/Debian で約 1 万件（大半が修正版なし）、Alma/Rocky は勧告単位で約 100 件。
  - [x] 共通契約（`chain/sources/base.py`）、宣言的な登録表（`chain/kernel_sources.toml`）、ALAS アダプタ、3 層分類、`--kernel-auto`、livepatch による解消の判定。
  - [x] OSV アダプタ（Ubuntu / Debian / Alma / Rocky）。件数は ID で数え、層 1・2 のものだけ詳細を取得。照会結果は 24 時間、レコードは更新日時でキャッシュ。
  - [ ] 層 2 の CVSS シグナル（ALAS には CVE 単位の CVSS がないため、別の情報源で補う）。昇格の規則（`cvss_lookup`）は実装済みで、照会元の接続待ち。候補は NVD API（中立だが分析待ちが多く、無認証は 30 秒に 5 件）と Red Hat Security Data API（カーネルの CVE をほぼすべて採点・一括取得可）。事前検証で網羅率を比べて決める。
- [x] **④ スナップショットと昇格ルール、`--fail-on promoted`、`--promote`**
  - `chain/kernel_history.py`。EPSS 急上昇・CVSS の引き上げ（照会元の接続待ち）・手動昇格（`promotions.json`、出典 URL 必須）。昇格は露出が続く限り維持。レポートに「前回の実行からの変化」と昇格の一覧。
- [ ] **⑤ RHEL 対応**（OSV の `Red Hat` ecosystem で足りるか、CSAF/VEX が要るかの検証から）
- [ ] **⑥ ディストリ対応表の公開とアダプタ寄稿の手引き**
- [ ] **⑦ ベンチマークへの追加**（層の昇格、収集の欠けたプール、系統違い、livepatch、照会元の無いディストリ）

### ④ 対応ライフサイクルの時間測定とROI可視化（Lifecycle Metrics / MTTR / v0.3.1先行対応完了）
- [x] **ライフサイクル・タイムスタンプ自動記録（`src/triage_agent/tools/lifecycle_metrics.py`）**
  - **公表起点 T(-1) からの総リードタイム測定:**
    - `T(-1) (Announce)`: アドバイザリ公表・事前予告日時（時計の起点をツール起動ではなく公表に置く）
    - `T0 (Detect)`: SBOM生成・初回スキャン
    - `T1 (Triage)`: 指示書（早見表）生成完了
    - `T2 (Dispatch)`: チーム/ベンダーへの照会依頼発行（配布ID発行）
    - `T3 (Attest)`: 回答受領 / コード・設定検証完了（サインオフ完了）
    - `T4 (Remediate)`: パッチ・回避策実機適用完了
  - **夜間・休日（Off-Hours）対応の自動判定:**
    - 平日 09:00〜18:00 JST 以外の時間帯に発生したイベントを自動検知・集計し、「夜間・休日緊急招集の削減効果」を数値化。
  - **実測ベースライン比較（「作った内容を本物に見せない」徹底）:**
    - 過去の直近実事例（Node.js, PHP, Tomcat 等）の公表〜完了時刻を出典URL付きで記録した基準データ（平均 74.9 時間）を同梱し、総リードタイム削減効果を自動算出。
    - 「総リードタイム」と「作業工数」を分離して記録。

### ⑤ 成果物の機密性管理と「攻撃地図化」の防止（Confidentiality & Data Minimization）
- [ ] **CLI・GUIの既定出力先ディレクトリ集約（セキュア・バイ・デフォルト）**
  - ファイル名のパターン除外（`*report*.json` 等）のみに依存すると、`systemA-2026-10-25.json` や `out.md` のような任意のファイル名が指定された際に除外漏れが生じる限界がある。
  - そのため、CLI（`--output`, `--verify-output`）および Web GUI の出力先デフォルトを、`.gitignore` で完全遮断された専用ディレクトリ（`triage-output/` または `reports/`）配下に自動設定し、ユーザーがパスを意識せずとも誤コミットが発生しない構造的防護（Secure by Default）を適用。
- [ ] **成果物のデータ最小化と保管期限（TTLパージ）**
  - 未対応の間は詳細なコード該当行・コンテキストを保持するが、対応完了・パッチ適用後は詳細行情報をパージし、「誰がいつどのような根拠で対応したか」という監査証跡の最小メタデータのみを長期保管。
- [ ] **配布範囲の最小化（システム別レポート分割・テナント分離）**
  - 全社一覧やフラッシュレポートの一斉同報を避け、ベンダーや各開発部門には「自システムに直接関連する確認ポイントのみ」を切り分けて配布するスコープ制御。
- [ ] **48時間ルールによる「地図の賞味期限短縮」**
  - 脆弱性の攻撃地図としての価値を無効化する最も本質的な防御として、発火条件特定から48時間以内の初動対応完了を促すライフサイクル運用。

---

## 5. 技術的深化ロードマップ（Technical Deep Dive）

- [ ] **AST（抽象構文木）を利用した高精度コード検査の拡充**
  - Python標準 `ast`（Call/Attribute/Keyword解析）およびブロックコメント除外は実装完了。
  - 次期フェーズとして、JavaScript/TypeScript (`tree-sitter` 等) による多言語AST解析や引数オブジェクトのディープ解析を拡充。
- [ ] **推移的依存の到達可能性（Reachability Analysis）エンジン統合**
  - 静的コールグラフ解析を行い、推移的依存ライブラリの危険関数が自社コードのエントリポイントから実際に呼び出されうるか（Call Graph Reachability）を検証。
- [ ] **セキュアなCI/CDパイプライン連携（GitHub Actions / GitLab CI）**
  - PR作成時やコンテナビルド時に自動で `syft` -> `triage-agent` -> `verifier` を実行。
  - **※ セキュリティ・機密性への配慮:** PRコメントや公開ビルドログには、具体的な脆弱コード行番号や攻撃地図を平文で露出させず、合否サマリ（Pass/Fail・件数）のみを通知。詳細レポートはアクセス権限が制御された閉じたストレージに期限付きで保管する設計とする。
- [ ] **自動修正PR（Auto-Remediation PR）生成**
  - `verifier` で発火コード（例: `jwt.verify(token, secret)`）が特定された場合、LLMが自動で修正差分（例: `jwt.verify(token, secret, { algorithms: ['RS256'] })`）を生成し、テスト実行の上で修正Pull Requestを下書き作成する機能。
- [ ] **通知インテグレーション（Slack / Teams / Jira）**
  - 自社判定が「YES (要対応)」になった際、Slackチャンネルに警報メンションを飛ばし、自動でJiraチケットを起票するWebhookアダプタ。

---

## 6. マルチSBOM・部門横断ポートフォリオ管理構想（別リポジトリ予定: `triage-hub`）

本リポジトリ（`triage-agent`）は「単一システム・単一SBOMに対する深層トリアージとコード検証エンジン」としての責務に集中し、複数のSBOMや部署内全システムの状況を束ねて統合トラックする機能は、将来的に別リポジトリ（集中管理ダッシュボード）として疎結合に切り出す構想です。

```
[ システムA (内製) ] ──> triage-agent (CI/CD) ──┐
[ システムB (内製) ] ──> triage-agent (CI/CD) ──┼──> [ GCS / S3 / API ]
[ システムC (外注) ] ──> triage-agent (手動/Web)─┘           │
                                                          ▼
                                                ┌──────────────────────────┐
                                                │  triage-hub (別リポジトリ) │
                                                │  部門横断ポートフォリオUI.   │
                                                └──────────────────────────┘
```

### システム境界と役割分担
- **`triage-agent`（本リポジトリ / 実行エンジン）:**
  - 各システムのCI/CDや現場環境で動作。
  - 個別SBOMの解析、LLMによる発火条件調査、コード走査、監査サインオフの収集。
  - 成果物としてポータブルかつ構造化された `triage_report.json` や `audit_signoff.json` を出力。
- **`triage-hub`（別リポジトリ構想 / 集中管理ポータル）:**
  - 各システムから出力されたレポートを集約し、部門管理者・セキュリティ統括向けに可視化：
    - **全社横断CVE影響検索:** 「CVE-2026-XXXX の影響を受ける部内システムはどれか？各システムのサインオフ進捗は？」を一発検索。
    - **システム別セキュリティ健康度マトリクス:** 内製・ベンダー委託を含む全システムのトリアージ状況（要対応 / 要確認 / 安全確認済）を一覧表示。
    - **SLA超過アラート & リマインド:** 未対応のまま放置されている脆弱性や、期限が近い要対応項目の自動エスカレーション。

### 集約ポータルのセキュリティ設計（攻撃地図集中リスクの排除）
全システムの未対応脆弱性が単一のHubに集約されると、万が一の漏洩時における被害が全社規模の致命的な攻撃地図（クラウンジュエル）と化します。これを防ぐため、以下の原則を厳格に適用します：
1. **Zero-Detail Federation（生データ不保持のサマリ連携）:**
   - `triage-hub` が収集・保存するのは「CVE ID、影響判定（YES / NO / 要確認）、SLA期限、システム識別子」といった**高位のメタデータ（件数・ステータス）のみ**とします。
   - 具体的なソースコードの該当ファイルパスやコード行、コンテキストスニペット等の生データはHubへ送信・集約せず、各システム管轄のセキュアストレージ内に分散保持させます。
2. **全社横断CVE影響検索のアクセス制御と監査ログ（Audit Logging）:**
   - 「全社でどのシステムがこの脆弱性を踏んでいるか」の逆引き検索は、攻撃者視点では最優先の標的選定マップとなるため、厳格なRBAC（ロールベースアクセス制御）による特権制限を課します。
   - 誰がいつどのCVEの影響範囲を横断検索・閲覧したかを追跡する改竄不能な監査ログの記録を必須とします。

---

## 7. 中長期検討課題（Backlog）

- [ ] **GitHub Enterprise / GitLab 対応**
  - 社内閉域網で稼働している GitHub Enterprise Server や GitLab のリポジトリ・Advisory APIへの接続オプション追加。
