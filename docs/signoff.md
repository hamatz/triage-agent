# 監査サインオフと正本管理運用 (Sign-off & Governance)

セキュリティ現場において、**「コード内でキーワードが見つからないこと」は決して「安全（非該当）」を意味しません。**  
ミドルウェアのデフォルト設定（例: PHP の `session.upload_progress.enabled`）や、環境変数、インフラ側の設定（K8s マニフェストや ConfigMap）に依存する脆弱性は、コード走査だけでは安全を証明できないためです。

本システムでは、未検出を安易に安全と言わず、**「人間のエンジニア/SREがインフラ設定や既定値を確認し、根拠を残して承認（サインオフ）して初めて安全（NO）とする」** ガバナンスワークフローを実装しています。

---

## 1. 2段階運用：AI 下書きと正本管理

LLM による文章生成は、実行ごとに言い回しが微妙に変わる可能性があります。毎回レポートをゼロから再生成して検証を回すと、質問文の微細な変化によって ID が変わり、以前作成したサインオフが当たらなくなってエンジニアが疲弊します。

そのため、実務では **「AI は版の下書きを作り、確定・配布された版を正本とする」** 2段階運用を推奨します。

```text
[SBOM] ──> (triage-agent) ──> triage_v1.0_draft.json (AI下書き)
                                     │
                             [人の確認・微修正]
                                     ↓
                         triage_v1.0_official.json (第1版 正本として保存)
                                     │
           ┌─────────────────────────┴─────────────────────────┐
           ↓                                                   ↓
   【外注委託システム】                                 【内製システム】
ベンダーへ指示書送付                               triage-verifier で自動走査 & 
(Yesなら7日以内/Noなら30日)                        正本に対してサインオフを突合・確定
```

1. **AI は「版の下書き（Draft）」を作成**:
   `python -m triage_agent.cli --sbom my_sbom.json --output reports/triage_v1.0_draft.json`
2. **人間がレビューして「第1版の正本（Official Baseline）」として確定・保存**:
   内容を確定し、`reports/triage_v1.0_official.json` として Git リポジトリ等に保存。
3. **自社検証・サインオフ照合は「正本」に対して実行**:
   `python -m triage_agent.verifier --report reports/triage_v1.0_official.json --code-dir . --audit-file audit_signoff.json`
4. **新情報・新バージョン公開時**:
   新版（第2版）を作成。内容に変更があった脆弱性のみ `notice_hash` により自動で再確認（黄色）を促します。

---

## 2. サインオフ JSON フォーマット (`audit_signoff.json`)

サインオフファイルには、誰が、いつ、どの環境に対して、何の証拠（Evidence）を元に判断したかを記録します：

```json
{
  "attestations": [
    {
      "check_point_id": "tomcat-demo-cve-2026-0001-338803ee",
      "target_or_cve": "CVE-2020-1938",
      "component_name": "tomcat-catalina",
      "status": "NO",
      "environment": "production",
      "report_version": "v1.0",
      "reviewer": "sre-lead@example.com",
      "reviewed_at": "2026-10-31T09:00:00Z",
      "evidence": "K8s ConfigMap (server.xml) 内で AJP コネクタが完全削除されていることを確認済み",
      "ticket_id": "SEC-4092"
    }
  ]
}
```

---

## 3. ドリフト検知・保護規則

サインオフが安易に形骸化しないよう、以下の安全保護が作動します：

1. **レポート版の不一致警告**: サインオフ対象の版（例: `v2.0`）が現在のレポート版（`v1.0`）と異なる場合、自動適用されず再確認対象となります。
2. **構成・ハッシュ変更検知**: 確認ポイントの文面や質問構成が変更された場合、古いサインオフを無効化し、差分確認を促します。
3. **環境限定サインオフ**: `--environment staging` のサインオフが本番（`production`）に誤適用されるのを防止します。
