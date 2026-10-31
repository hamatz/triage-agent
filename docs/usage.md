# CLI & Web GUI 利用ガイド (Usage Guide)

triage-agent の CLI オプション、Syft による SBOM 生成、および Web GUI ダッシュボードの利用方法です。

---

## 1. Syft による SBOM 生成

> 💡 **推奨スキャン手法（コンテナイメージ単位）:**  
> `syft scan dir:.` でソースコードディレクトリのみをスキャンした場合、**Node.js 本体、PHP ランタイム、OS 共有ライブラリ（OpenSSL, Brotli 等）** といった基盤層が SBOM に含まれません（基盤脆弱性の見落としリスク）。  
> 本番環境にデプロイするコンテナイメージ全体をスキャンすることを強く推奨します。

```bash
# 【推奨】コンテナイメージ全体をスキャン (CycloneDX JSON)
syft scan docker:my-org/my-app:latest -o cyclonedx-json > my_sbom.json

# または SPDX JSON (ISO/IEC 5962 国際標準形式)
syft scan docker:my-org/my-app:latest -o spdx-json > my_spdx_sbom.json

# 【簡易】ソースコードディレクトリのみのスキャン (言語ライブラリのみ)
syft scan dir:. -o cyclonedx-json > my_sbom.json
```

---

## 2. CLI コマンドリファレンス

### 基本実行
```bash
# 基本実行: Markdown 指示書を出力
python -m triage_agent.cli --sbom my_sbom.json --output triage-output/triage_report.md

# 機械可読な JSON 形式で出力（verifier や後続ツール連携用）
python -m triage_agent.cli --sbom my_sbom.json --output triage-output/triage_report.json

# 事前予告カレンダー（iCalendar / .ics）を同時生成
python -m triage_agent.cli --sbom my_sbom.json \
  --output triage-output/triage_report.json \
  --calendar triage-output/upcoming_patches.ics
```

### モデル・実行制御オプション
```bash
# 一時的にモデルを変更して実行
python -m triage_agent.cli --sbom my_sbom.json --model gemini-2.5-pro

# 並列調査ワーカー数の指定
python -m triage_agent.cli --sbom my_sbom.json --workers 4

# オフライン（シミュレーション）実行
python -m triage_agent.cli --sbom my_sbom.json --dry-run

# 社内内製パッケージを外部照会・推論から除外
python -m triage_agent.cli --sbom my_sbom.json --exclude "@mycompany/*,internal-*"
```

### ベンダー往復・エクスポート/インポート
```bash
# 担当製品に絞ってベンダー向けチェックリスト（CSV）を書き出す
python -m triage_agent.cli --sbom my_sbom.json \
  --export-checklist triage-output/vendor_check.csv \
  --export-checklist-target "Apache Tomcat"

# ベンダー回答（CSV）を取り込み、サインオフを自動生成
python -m triage_agent.cli --import-checklist vendor_answered.csv \
  --audit-file triage-output/audit_signoff.json

# パッチ適用完了の記録
python -m triage_agent.cli --record-remediation DIST-xxxxxxxx-xxxxxx \
  --remediated-at 2026-12-02T10:30:00+09:00
```

### 自社コードベース同時自動検証
```bash
# トリアージと同時に自社コード・設定を自動検証
python -m triage_agent.cli --sbom my_sbom.json --verify-code /path/to/my-repo
```

### CI/CD ガードレール停止オプション
```bash
# 調査不能コンポーネント、または脆弱性該当（YES）がある場合に非ゼロ終了 (exit 2)
python -m triage_agent.cli --sbom my_sbom.json --fail-on unscanned,yes
```

---

## 3. Web GUI ダッシュボード (DAWN Studio)

ブラウザ上で対話的にトリアージ指示書を閲覧し、自社コードベース検証やサインオフ登録を行える軽量・セキュア Web GUI です。

```bash
# Web GUI ダッシュボードの起動（ブラウザで http://127.0.0.1:8080 が開きます）
python -m triage_agent.cli --gui
# または
python -m triage_agent.web_ui
```

### セキュリティ & UX 特徴
- **Zero CDN & 完全オフライン動作**: 外部 CDN スクリプト（Tailwind や Font Awesome）への依存を排除。イントラネット・金融機関閉域網でも崩れず安全に動作します。
- **CSRF 防護 & パストラバーサル防止**: 動的 CSRF トークン検証、Origin 検証、作業ディレクトリ制限を徹底。
- **リアルタイム進捗ストリーミング**: Server-Sent Events (SSE) による軽量プログレス表示。
