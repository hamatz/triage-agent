# セットアップと環境設定ガイド (Setup Guide)

triage-agent のセットアップ、API キー設定、モデル切り替え、およびトークンレス構成に関する詳細ガイドです。

---

## 1. 必要要件 (Requirements)

- **Python**: 3.11 以上
- **LLM API**: Google Gemini API Key（または Vertex AI / ADC）
- **GitHub Token**: **不要（Tokenless）**
  - OSV.dev をプライマリ脆弱性データベースとして利用するため、GitHub PAT（Personal Access Token）の管理や漏洩リスクなしで動作します。

---

## 2. インストール手順

```bash
# 仮想環境の作成と有効化
python3 -m venv .venv
source .venv/bin/activate

# 依存パッケージのインストール（開発モード）
pip install -e .
```

---

## 3. 環境設定ファイル (`.env`)

プロジェクトルートの `.env.example` をコピーして `.env` を作成します：

```bash
cp .env.example .env
```

### 設定項目一覧

```bash
# 必須: Google Gemini API キー
GEMINI_API_KEY="your-gemini-api-key"

# ベースモデル（既定値: 高速・安定・最新の gemini-3.5-flash 推奨）
GEMINI_MODEL="gemini-3.5-flash"

# （任意）役割ごとにモデルを分けたい場合のみ設定
# GEMINI_MODEL_PLANNER="gemini-2.5-pro"
# GEMINI_MODEL_RESEARCHER="gemini-3.5-flash"
# GEMINI_MODEL_TRIAGE="gemini-2.5-pro"

# （任意）GitHub Token
# 通常は未設定で問題ありません。OSV.dev により完全トークンレスで動作します。
# GITHUB_TOKEN=""
```

> ⚠️ **GITHUB_TOKEN を設定する場合の注意:**  
> 明示的に `GITHUB_TOKEN` を設定した場合、トークンが無効または期限切れ（HTTP 401 Bad credentials）であるときは、設定ミスを見逃さないよう「未調査コンポーネント」として警告され、`--fail-on unscanned` により CI が安全に停止します。

---

## 4. 動作確認（5分クイックスタート・API キー不要）

API キーを設定する前でも、`--demo` フラグを使用することで合成データによる即時動作確認が可能です：

```bash
python -m triage_agent.cli --demo \
  --output triage-output/demo_report.json \
  --calendar triage-output/demo_calendar.ics \
  --export-checklist triage-output/demo_checklist.csv
```
