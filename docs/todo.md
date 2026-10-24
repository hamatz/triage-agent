# 開発ロードマップ & タスクリスト (todo.md)

本ドキュメントは、`triage-agent` の今後の機能拡張、改善予定、およびバックログを管理します。

---

## 1. 近日対応予定（Near-term / Quick Wins）

- [ ] **SPDX JSON形式へのネイティブ対応拡充**
  - 現在は CycloneDX JSON および Syft native JSON が中心。SPDX 2.3 / 3.0 JSON形式の直接読み込みパーサーを追加。
- [ ] **GitHub Enterprise / GitLab 対応**
  - 社内閉域網で稼働している GitHub Enterprise Server や GitLab のリポジトリ・Advisory APIへの接続オプション追加。
- [ ] **AST（抽象構文木）を利用した高精度コード検査**
  - `verifier.py` において、現在の正規表現・トークンマッチングに加え、Python (`ast`) や JavaScript/TypeScript (`tree-sitter` / `esprima`) の構文解析による引数レベルの検証（例: `jwt.verify(token, secret)` の第3引数欠落をASTで完全判定）。

---

## 2. 中期ロードマップ（Mid-term）

- [ ] **CI/CD パイプライン連携（GitHub Actions / GitLab CI）**
  - PR作成時やコンテナビルド時に自動で `syft` -> `triage-agent` -> `verifier` を実行し、PRコメントにトリアージ結果とYes/No自動判定を書き込むActionの提供。
- [ ] **通知インテグレーション（Slack / Teams / Jira）**
  - CVSS 7.0以上（High/Critical）または RCE 疑いの脆弱性で自社判定が「YES (要対応)」になった際、Slackチャンネルに警報メンションを飛ばし、自動でJiraチケットを起票するWebhookアダプタ。
- [ ] **過去トリアージ結果のローカルキャッシュ（DB/ファイル）**
  - 同一コンポーネント・バージョンの重複調査を避け、前回調査日からの差分（New Advisory）のみを効率的に深層調査するキャッシュ層。

---

## 3. 長期構想（Long-term）

- [ ] **自動修正PR（Auto-Remediation PR）生成**
  - `verifier` で発火コード（例: `jwt.verify(token, secret)`）が特定された場合、LLMが自動で修正差分（例: `jwt.verify(token, secret, { algorithms: ['RS256'] })`）を生成し、テスト実行の上で修正Pull Requestを下書き作成する機能。
- [ ] **推移的依存の到達可能性（Reachability Analysis）エンジン統合**
  - 静的コールグラフ解析を行い、推移的依存ライブラリの危険関数が自社コードのエントリポイントから実際に呼び出されうるか（Call Graph Reachability）を検証。
