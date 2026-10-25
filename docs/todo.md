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

## 1. 近日対応予定（Near-term / Quick Wins: v0.2）

- [ ] **SPDX JSON形式へのネイティブ対応拡充**
  - 現在は CycloneDX JSON および Syft native JSON が中心。SPDX 2.3 / 3.0 JSON形式の直接読み込みパーサーを追加。
- [ ] **GitHub Enterprise / GitLab 対応**
  - 社内閉域網で稼働している GitHub Enterprise Server や GitLab のリポジトリ・Advisory APIへの接続オプション追加。
- [ ] **Verifier判定文言の精緻化**
  - 現行のキーワード照合による判定を、画面およびレポート上で `YES (発火関連コード検出・要確認)` と明示し、AST/到達可能性解析による完全証明との区別を明確化。

---

## 2. Engineering Enablement 推進に向けた戦略的ロードマップ (v0.3〜v1.0)

Engineering Enablement（専門家依存の解消と組織的な即応）を実現するため、単なる機能追加にとどまらず、全社運用に耐えうるガバナンスと知識蓄積を強化します。

### 進化像の4つの柱

| 柱 | ① スコープ階層化 | ② 判定精緻化 | ③ システム知識化 | ④ MTTR/ROI可視化 |
| :--- | :--- | :--- | :--- | :--- |
| **英名** | Clarity of Scope & Integration | Contextual Attestation & TTL | Architectural Knowledge Base | Lifecycle Metrics & MTTR |
| **主要テーマ** | 機械照合・AI深層調査・未調査の3層分離 | 環境・構成版・有効期限付きサインオフ | システム恒久事実の辞書化と再利用 | 各フェーズ所要時間と削減効果の定量化 |

### ① 調査範囲の3層階層化と全社スキャン基盤連携（Clarity of Coverage & Scope）
- [ ] **3層ステータスモデルの導入**
  - 「調査で安全と判明した」と「調査リソース上限やAPIエラーで未調査」の混同を完全に防ぐステータス設計：
    1. `Layer 1: 機械的照合済`（OSV等のデータベース照合が完了したコンポーネント）
    2. `Layer 2: AI深層調査済`（Triage Agent がパッチDiffや発火条件まで精読したコンポーネント）
    3. `Layer 3: 調査対象外 / 調査不能`（深掘り上限到達、レート制限、外部エラー等）
- [ ] **全社資産管理・脆弱性基盤（Dependency-Track 等）との役割分担・連携**
  - 全社何百システム・数万コンポーネントの機械的網羅スキャンは Dependency-Track などの基盤に委ね、triage-agent は「緊急度・優先度の高い脆弱性の深層調査・指示書化・現場トリアージ」を担う専門レイヤーとして接続。

### ② サインオフのコンテキスト紐付け（Contextual Attestation & TTL）
- [ ] **環境・バージョン・有効期限（TTL）付きサインオフ**
  - 手動/ベンダーサインオフに対し、以下のコンテキスト情報を付与可能にする：
    - **対象環境:** `Production` / `Staging` / `Development`
    - **構成バージョン:** リリースバージョン番号、コンテナタグ、または Git コミットSHA
    - **有効期限（TTL）:** 「次回メジャーリリースまで」「2026-12-31まで」等を設定し、期限切れ時に自動で再確認を喚起。

### ③ ベンダー・現場回答の「組織知（System Architectural Profile）」化
- [ ] **システム構成プロファイル（System Profile）機能**
  - 脆弱性ごとの一過性のサインオフにとどまらず、ベンダーやエンジニアから得られた「システムの恒久的構成事実」をシステム辞書として蓄積：
    - 例: 「販売管理システムAでは、AJPコネクタは永続的に無効化済み（HTTPリバースプロキシ直結）」
    - 例: 「バッチ基盤BのLog4jは、オフラインのローカルログ集計でのみ使用（JNDI/LDAP接続不可）」
- [ ] **次回以降の類似脆弱性への自動照合（問い合わせ削減）**
  - 次回、同一ミドルウェアで類似の脆弱性が出た際、ゼロからベンダーに再問い合わせせず、蓄積されたプロファイルから「該当システムは設定無効化済み」と即座に自動解決・スキップする仕組み。

### ④ 対応ライフサイクルの時間測定とROI可視化（Lifecycle Metrics / MTTR）
- [ ] **ライフサイクル・タイムスタンプ自動記録**
  - 脆弱性対応の各フェーズの所要時間を追跡：
    - `T0 (Detect)`: SBOM生成・脆弱性検知
    - `T1 (Triage)`: AI指示書（早見表）生成完了
    - `T2 (Dispatch)`: 開発チーム / ベンダーへの照会依頼発行
    - `T3 (Attest)`: 回答受領 / コード検証完了
    - `T4 (Remediate)`: パッチ適用 / 回避策実施完了
- [ ] **MTTR（平均対応時間）短縮・削減工数の定量ダッシュボード**
  - 「従来の手作業トリアージ（平均5営業日）」 vs 「triage-agent 導入後（平均数時間）」の削減効果を可視化し、経営層やIT部門リーダーへのROI報告を自動化。

---

## 3. 技術的深化ロードマップ（Technical Deep Dive）

- [ ] **AST（抽象構文木）を利用した高精度コード検査**
  - `verifier.py` において、現在の正規表現・コンテキスト走査に加え、Python (`ast`) や JavaScript/TypeScript (`tree-sitter`) の構文解析による引数レベルの検証。
- [ ] **推移的依存の到達可能性（Reachability Analysis）エンジン統合**
  - 静的コールグラフ解析を行い、推移的依存ライブラリの危険関数が自社コードのエントリポイントから実際に呼び出されうるか（Call Graph Reachability）を検証。
- [ ] **CI/CD パイプライン連携（GitHub Actions / GitLab CI）**
  - PR作成時やコンテナビルド時に自動で `syft` -> `triage-agent` -> `verifier` を実行し、PRコメントにトリアージ結果とYes/No自動判定を書き込むActionの提供。
- [ ] **自動修正PR（Auto-Remediation PR）生成**
  - `verifier` で発火コード（例: `jwt.verify(token, secret)`）が特定された場合、LLMが自動で修正差分（例: `jwt.verify(token, secret, { algorithms: ['RS256'] })`）を生成し、テスト実行の上で修正Pull Requestを下書き作成する機能。
- [ ] **通知インテグレーション（Slack / Teams / Jira）**
  - 自社判定が「YES (要対応)」になった際、Slackチャンネルに警報メンションを飛ばし、自動でJiraチケットを起票するWebhookアダプタ。
