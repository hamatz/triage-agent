# システムアーキテクチャ設計書 (architecture.md)

本ドキュメントは、`triage-agent` の全体構造、エージェント協調モデル、データフロー、ツールセット、およびモデル構成方針について定義します。

---

## 1. 全体アーキテクチャ概要

本システムは、自社のソフトウェア部品表（SBOM）を起点として、既知の脆弱性（CVE）だけでなく **「パッチのリリース予告」「直近のセキュリティ修正コミット」** を能動的に収集し、**「自社の具体的設定で発火するか」** を解明して即応指示書を出力するマルチエージェントシステムです。

### アーキテクチャ原則
1. **Agent-Native & Minimal Framework:** 複雑なグラフオーケストレータを自作せず、Gemini公式 `google-genai` SDKのFunction CallingとStructured Outputsを中心とした直線的パイプライン構成。
2. **型安全なエージェント間引き継ぎ（Schema Handoff）:** Pydanticモデルを共通言語として各エージェント間でデータをバトンタッチ。
3. **ベンダー問い合わせと自社内製検証の分離・両立:** 
   - 外部委託向けには「Yes/No確認票付きの問い合わせ指示書」を生成。
   - 内製コード向けには「自社リポジトリ自動走査ツール（verifier）」で即座に判定。

---

## 2. マルチエージェントトポロジー

```mermaid
flowchart TD
    SBOM["入力: SBOM (Syft CycloneDX JSON)"] --> RP

    subgraph Phase1["Phase 1: Recon Planner（戦略立案）"]
        RP["Recon Planner"]
        T_SBOM["load_sbom_summary"]
        T_OSV["query_osv_batch (OSV一括照会)"]
        RP <--> T_SBOM
        RP <--> T_OSV
    end

    RP -->|"ReconPlan (JSON)"| Dispatcher["ディスパッチャ"]

    subgraph Phase2["Phase 2: Researcher（動的調査ワーカー）"]
        Dispatcher --> R1["Researcher Worker #1"]
        Dispatcher --> R2["Researcher Worker #2"]
        T_WEB["fetch_webpage_text / google_search"]
        T_GH["search_github_security_signals"]
        R1 <--> T_WEB
        R1 <--> T_GH
        R2 <--> T_WEB
        R2 <--> T_GH
    end

    R1 -->|"TargetResearchResult"| TR
    R2 -->|"TargetResearchResult"| TR

    subgraph Phase3["Phase 3: Triage Agent（トリアージ＆指示書生成）"]
        TR["Triage Agent"]
        T_DIFF["get_github_commit_or_advisory_detail"]
        TR <--> T_DIFF
    end

    TR --> OutMD["triage_report.md (現場指示書)"]
    TR --> OutJSON["triage_report.json (構造化データ)"]

    subgraph Phase4["Phase 4: Codebase Verifier（自社検証補助CLI）"]
        OutJSON --> VER["triage-verifier (verifier.py)"]
        SRC["自社ソースコード\n(demo_app/ など)"] --> VER
        VER --> AuditReport["verification_audit_report.md\n(自社検証結果レポート)"]
    end
```

---

## 3. 各エージェントの責務と入出力

| エージェント | 責務 | 入力 | 出力スキーマ | 主なツール |
| :--- | :--- | :--- | :--- | :--- |
| **Recon Planner** | SBOMを全件走査し、OSV一括照会結果と外部露出度から調査優先度（CRITICAL/HIGH）と検索クエリリストを策定 | SBOM JSON, 自社特性（任意） | `ReconPlan` | `load_sbom_summary`<br>`query_osv_batch` |
| **Researcher** | 特定されたターゲットごとに、GitHub Advisories、直近Release/RC、修正コミット、Google検索でシグナルを探索 | `ReconTarget` | `TargetResearchResult`<br>（`ResearchFinding` リスト） | `search_github_security_signals`<br>`fetch_webpage_text`<br>`google_search` |
| **Triage Agent** | 収集したシグナルとパッチ差分（Diff）を精読し、発火する具体的設定値・API利用条件を特定。現場指示書を生成 | `List[TargetResearchResult]` | `TriageReport`<br>（`TriageNotice` リスト） | `get_github_commit_or_advisory_detail` |
| **Verifier (補助CLI)** | 指示書の確認ポイントに基づき、自社コードベース内を走査してYes/Noの自社判定レポートを自動生成 | `TriageReport (JSON)`<br>自社コードディレクトリ | `CodebaseAuditReport` | `extract_keywords_from_method`<br>`scan_directory_for_patterns` |

---

## 4. ツールセット設計（APIキー・レートリミット対策）

1. **OSV.dev API (`query_osv_batch`):**
   - 無料・認証不要。数千件のパッケージを一括で1リクエスト（`POST /v1/querybatch`）で照会可能。
2. **GitHub API (`search_github_security_signals`, `get_github_commit_or_advisory_detail`):**
   - トークン未設定時は公開IPレートリミット（60回/時）、`GITHUB_TOKEN` 設定時は 5,000回/時。
   - Advisories, Releases, Commits, Diffを一元取得。
3. **Gemini Google Search Grounding (`google_search`):**
   - Gemini APIネイティブのグラウンディング機能。追加のSerpAPI / Tavily等の有料APIキーを不要とし、低コストで事前予告ニュースやブログを検索。

---

## 5. モデル設定とプロンプト分離

- **環境変数外出し:**
  - `GEMINI_MODEL`: デフォルトモデル名（`.env` で設定可能、例: `gemini-2.5-flash`）。
  - `GEMINI_MODEL_PLANNER`, `GEMINI_MODEL_TRIAGE` などの役割別オーバーライドにも対応。
- **プロンプトファイルの分離:**
  - プロンプトはPythonコード内に埋め込まず、`prompts/*.md` にMarkdownとして独立管理。
  - 出力フォーマットは自然言語プロンプトではなく、SDKの `response_schema`（Pydantic）によって100%保証。

---

## 6. 自社コードベース自動検証エンジン (triage-verifier)

`triage-verifier`（[`src/triage_agent/verifier.py`](../src/triage_agent/verifier.py)）は、生成されたトリアージ指示書（`triage_report.json`）を入力として、自社管理下のソースコードリポジトリを自動走査し、**「自社で本当に発火条件を踏んでいるか」** を判定する補助CLIツールです。

```mermaid
flowchart LR
    Report["triage_report.json\n(確認ポイント・確認方法)"] --> Extractor["1. キーワード・パターン自動抽出\n(extract_keywords_from_method)"]
    Extractor --> Scanner["2. マルチ言語コード走査\n(scan_directory_for_patterns)"]
    Repo["自社リポジトリ\n(Python, JS/TS, Java, XML, ini等)"] --> Scanner
    Scanner --> Evaluator["3. 判定ロジック\n(Yes: 要対応 / No: 安全)"]
    Evaluator --> Output["verification_audit_report.md\n(該当行スニペット・根拠付き)"]
```

### 動作ステップ
1. **パターン抽出（`extract_keywords_from_method`）:**
   - 指示書の `check_point_yes_no` および `verification_method` に含まれるコードトークン（バッククォート囲み、関数呼び出し `stream(`, `jwt.verify`、XMLタグ `<Connector`, `<async-supported`、ini設定 `serialize_handler` 等）を自動抽出。
2. **高速マルチ言語走査（`scan_directory_for_patterns`）:**
   - `.git`, `node_modules`, `.venv`, `dist` 等の非対象ディレクトリを除外し、主要ソースファイル（`.py`, `.js`, `.ts`, `.java`, `.xml`, `.ini`, `.conf` 等）を行単位で走査。
3. **判定と根拠のバインド（`verify_codebase`）:**
   - 発火パターンが検出された場合: `YES (要対応)` と判定し、該当ファイルパス・行番号・コードスニペットを記録。
   - 検出されなかった場合: `NO (安全)` と判定し、「自社コード内では使用されていないため次回定例リリース（30日以内）で可」と結論。
4. **自社検証レポート生成（`format_verification_markdown`）:**
   - 総合判定、項目別判定、検出箇所、推奨回避策を網羅した Markdown レポートを出力。
