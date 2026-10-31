# ベンダー連携ワークフローと対応時間計測 (Vendor Workflow & Metrics)

ソースコードを自社で保有せず、開発・保守を委託している外注システムでは、**「ベンダーに何を、どう聞けばよいか」「戻ってきた回答をどう記録・集計するか」** が課題になります。

triage-agent は、確認ポイントを Excel で開ける CSV として書き出し、回答を取り込んでタイムスタンプ付きのサインオフに変換するワークフローを備えています。

---

## 1. ベンダー向けチェックリストのエクスポート

```bash
# 担当製品に絞って CSV を書き出す（UTF-8 BOM 付き・Excel で文字化けせず開けます）
python -m triage_agent.cli --sbom my_sbom.json \
  --export-checklist triage-output/vendor_checklist.csv \
  --export-checklist-target "Apache Tomcat"
```

### 出力される CSV の項目
1. **配布 ID (`distribution_id`)**: 回答照合用の追跡 ID
2. **対象コンポーネント**: 例: `Apache Tomcat`
3. **対象 CVE**: 例: `CVE-2020-1938`
4. **確認ポイント (Yes/No)**: 例: `AJP コネクタを有効にしているか`
5. **確認方法 (Verification Method)**: 例: `server.xml の Connector 設定を確認`
6. **ベンダー回答 (`vendor_answer`)**: `YES (該当)` / `NO (非該当)`
7. **確認根拠 (`evidence`)**: 設定ファイル抜粋や確認ログ
8. **確認者 (`reviewer`)**: 担当エンジニア名
9. **確認日 (`reviewed_at`)**: ISO 8601 タイムスタンプ

---

## 2. ベンダー回答のインポートと自動サインオフ

ベンダーから戻ってきた記入済み CSV をインポートします：

```bash
python -m triage_agent.cli --import-checklist vendor_checklist_answered.csv \
  --audit-file triage-output/audit_signoff.json
```

### 回答の判定規則（安全保護原則）
- **非該当 (NO)**: 回答が `NO` かつ「確認根拠（evidence）」と「確認者」が記載されている場合のみ、監査済みの安全（NO）としてサインオフを確定します。
- **要確認**: 回答が空欄、曖昧、または根拠がない場合は、安全側に倒して「要確認」としてサインオフを保留します。
- **該当あり (YES)**: パッチ適用または回避策が必要な要対応項目として記録します。

---

## 3. 対応時間の記録とメトリクス集計

公表から、照会、ベンダー回答、パッチ適用完了までのリードタイムと、夜間・休日の対応件数を記録します：

```bash
# パッチ適用の完了を記録
python -m triage_agent.cli --record-remediation DIST-xxxxxxxx-xxxxxx \
  --remediated-at 2026-12-02T10:30:00+09:00
```

### 計測されるメトリクス (`triage-output/workflow_metrics.json`)
- **配布までの時間 (Lead Time to Distribution)**: 公表からベンダーへチェックリストを送付するまでの時間
- **回答までの時間 (Lead Time to Response)**: 送付からベンダーが回答するまでの時間
- **完了までの時間 (Lead Time to Remediation)**: パッチ適用が完了するまでの総所要時間
- **往復回数 (Turnaround Count)**: 差し戻しや再確認の回数
- **夜間・休日操作件数**: 担当者の突発対応負荷の可視化

> 💡 **基準値（`baselines.json`）の保護方針:**  
> 過去の対応時間との比較を行う場合、利用者が用意した「出典（source: チケット番号や URL）付きの実測値」のみを基準値として採用します。根拠のない数字や仮の値は読み飛ばされます。
