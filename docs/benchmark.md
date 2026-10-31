# グラウンドトゥルース評価セット (Benchmark Suite)

triage-agent は、**「見逃し（False Negative）ゼロ」「誤検知（False Positive）ゼロ」** を定量検証するため、過去の実インシデントや難関エッジケースを収録したグラウンドトゥルース評価セット（ADR-019 柱4）を標準搭載しています。

---

## 1. 評価セットの実行

```bash
# 評価セットの実行と集計
python -m triage_agent.benchmark
# または CLI オプション
python -m triage_agent.cli --benchmark
```

### 出力例
```text
======================================================================
triage-agent Verifier & Feed Benchmark Suite (ADR-019 / Pillar 4)
======================================================================
陽性 19件中 19件検出（見逃し 0）／陰性 9件中 誤検知 0／要確認 2件
総合正解率: 100.0% (28/28 ケース合格)
詳細結果保存先: triage-output/benchmark_results.json
======================================================================
✅ 全ベンチマークケース合格（リグレッションなし）
```

---

## 2. 収録ケースの内訳

1. **コード・設定ファイル走査ケース (`benchmark/cases/`)**:
   - `node_jwt`: JWT verify のアルゴリズム制限漏れ（本番コード `src/` とテスト `tests/` の分離）
   - `tomcat_ajp`: Tomcat AJP コネクタの有効化（Ghostcat）
   - `php_session`: PHP `session.upload_progress.enabled` の有効化
   - `http2_shell`: Nginx HTTP/2 Rapid Reset 有効化
2. **陰性（安全）ケース (`benchmark/cases_negative/`)**:
   - コメントアウトされた設定、明示的に `Off` されたディレクティブが誤って YES と判定されないことの検証
3. **難関ケース (`benchmark/cases_hard/`)**:
   - 複数設定ファイルによる上書き（`.user.ini` による `php.ini` の上書き）
   - 構文エラーを含む設定ファイルに対するフォールバック
4. **事前予告フィード実例 (`benchmark/feeds/`)**:
   - Node.js および Tomcat の過去の予告フィードからの正確な予定日・深刻度抽出
5. **連鎖エクスプロイト＆カーネル露出ケース (`chain_cases`)**:
   - PHP2Shell + Fragnesia による Critical 連鎖検知
   - CI ランナー環境（`untrusted_code`）におけるアプリ CVE 0件での Critical 発火
   - AWS 向けカーネル（`linux-aws`）のフレーバー分離と安全倒し（要確認）
   - 不在 SBOM（`SBOM-MISSING`）に対する要確認（`HIGH_UNVERIFIED`）倒し
   - トリアージ結果・SBOM 経路からの KEV 連鎖検知
