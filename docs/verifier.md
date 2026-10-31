# 自社コード＆設定ファイル自動検証 (Verifier)

`triage-verifier` は、トリアージ指示書（`triage_report.json`）に記載された「確認ポイント（Yes/No）」に基づき、自社リポジトリ内のソースコードおよびミドルウェア設定ファイルを走査し、客観的な判定レポートを出力する検証エンジンです。

---

## 1. コマンドライン実行

```bash
# 基本実行: 自社コードベースを自動検証
python -m triage_agent.verifier \
  --report triage-output/triage_report.json \
  --code-dir /path/to/my-repo \
  --output triage-output/verification_audit_report.md

# 人手によるサインオフ（インフラ・設定確認済み）を反映
python -m triage_agent.verifier \
  --report triage-output/triage_report.json \
  --code-dir /path/to/my-repo \
  --audit-file triage-output/audit_signoff.json
```

---

## 2. 判定の3状態

Verifier は以下の客観的な3状態で結果を出力します：

| 判定ステータス | 意味 | アクション |
| :--- | :--- | :--- |
| **YES (要対応)** | 自社コードまたは有効な設定内で発火条件を検出 | 7日以内の修正・パッチ適用を推奨 |
| **コード内未検出 (外部設定要確認)** | ソースコード内には該当キーワードなし。ただしミドルウェアのデフォルト値やインフラ設定に依存 | SRE・インフラ担当者による手動確認 & サインオフ作成が必要 |
| **NO (手動確認済み / 安全)** | 根拠と確認者が記録されたサインオフが存在、または設定の無効化を確認 | 対応不要（通常運用維持） |

---

## 3. 設定ファイル（Config Scanner）の走査対象

現場で発火可否を分けるのは、コードそのものより設定ファイルです。`config_scanner.py` は以下を直接走査します：

1. **Apache Tomcat (`conf/server.xml`)**:
   - AJP コネクタの有効化（Ghostcat CVE-2020-1938）
   - HTTP/2 プロトコルと非同期サーブレットの組み合わせ
2. **PHP (`php.ini` および `.user.ini`)**:
   - `session.upload_progress.enabled` の有効化（LFI to RCE ベクトル）
   - コメントアウト行（`;`）および複数設定ファイルの上書き順序を考慮
3. **Nginx (`nginx.conf`)**:
   - `http2 on;` ディレクティブの有効化（Rapid Reset CVE-2023-44487）
   - `#` コメントアウト行の除外

---

## 4. AST 構文木解析とテストコード分離

- **AST (Abstract Syntax Tree) 走査**:
  単純な文字列 grep ではなく構文木を解析し、コメント行や文字列リテラル内の誤検知を防止。
- **テストコード・モックの自動分離**:
  `tests/`, `test/`, `spec/`, `__tests__/` 配下のファイルやテスト関数内で使用されている危険な設定は本番影響なしとして区別します。
