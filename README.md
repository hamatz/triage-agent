# triage-agent

ソースコードが手元になくても、SBOM から「誰に、何を、Yes/No で聞けばいいか」を作り、パッチの日を前もって予定に入れる。委託開発の多い IT 部門のための、脆弱性トリアージ OSS です。

> **In English:** triage-agent turns an SBOM into concrete yes/no check points you can hand to vendors, puts upcoming security release dates on your calendar, and flags dangerous combinations of remote footholds and unpatched kernel privilege escalations. It never tells you something is safe when it doesn't know.

[![Unit & Benchmark Tests](https://github.com/hamatz/triage-agent/actions/workflows/test.yml/badge.svg)](https://github.com/hamatz/triage-agent/actions/workflows/test.yml)
[![Self-Triage](https://github.com/hamatz/triage-agent/actions/workflows/self-triage.yml/badge.svg)](https://github.com/hamatz/triage-agent/actions/workflows/self-triage.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

紹介記事：[v0.1「脆弱性は金曜の夜にも公開される。月曜日まで待っていて、本当に大丈夫なのか?」](https://zenn.dev/hamatz/articles/0d183807564605) ／ v0.4.0　[金曜の夜の脆弱性、コードが手元になくても月曜まで無為に過ごさないために —— triage-agent v0.4.0
](https://zenn.dev/hamatz/articles/2b113d9c15f459)

---

## こんなときに

- **金曜の夕方に Critical な脆弱性が公表された。** でもコードはベンダーの手元にあり、「影響を確認してください」と頼んで待つしかない
- **来週セキュリティリリースがあると分かっていれば、** 輪番も、ベンダーの作業枠も、本番変更の申請も先に準備できたのに
- **「ローカルからしか使えない」と後回しにしたカーネルの脆弱性が、** 新しく出た RCE と組み合わさって root まで取られた

triage-agent は、こうした「情報が手元にない」「確かめる手段がない」ことによる待ち時間を減らすための道具です。

---

## 5分で試す（API キー不要）

```bash
git clone https://github.com/hamatz/triage-agent.git
cd triage-agent
pip install -e .
python -m triage_agent.cli --demo \
  --output triage-output/demo.json \
  --calendar triage-output/demo.ics \
  --export-checklist triage-output/demo.csv
```

`--demo` は、`DEMO-` で始まる展示用の合成データを使います。外部への通信も AI の推論も行いません。出力には「合成データであり、実環境の調査結果ではない」ことが明示されます。

### デモで手に入るもの

#### 1. ベンダーにそのまま渡せる確認ポイント（`demo.csv`、Excel で開けます）

| 対象 | CVE | 確認ポイント (Yes/No) | 確認方法 | ベンダー回答 |
| :--- | :--- | :--- | :--- | :--- |
| DEMO: Apache Tomcat | DEMO-CVE-2026-0001 | AJP コネクタを有効にしているか | `server.xml` にコメントアウトされていない `<Connector protocol="AJP/1.3" ...>` があるか | （記入欄） |
| DEMO: Apache Tomcat | DEMO-CVE-2026-0002 | HTTP/2 を有効にしていて、かつ非同期サーブレットを使っているか | `server.xml` の `Http2Protocol` と、アプリの `asyncSupported=true` を確認 | （記入欄） |

#### 2. カレンダーに取り込めるパッチ予定（`demo.ics`）
Node.js の事前予告や Oracle Critical Patch Update の日程が、時刻付きの予定として入ります。米国の火曜の公開は日本では水曜の未明になるため、カレンダー上でもそのとおりに表示されます。

#### 3. 「分からないもの」を隠さないレポート（`demo.json` と画面表示）
調査できなかったコンポーネントは「未調査」として必ず警告されます。

#### 4. Web GUI ダッシュボード
ブラウザ上で視覚的にトリアージ指示書や確認ポイントを一覧できます：

![Web GUI](./docs/img/ss1.png)

---

## できること

| あなたが得られること | triage-agent がしていること |
| :--- | :--- |
| **コードがなくても、何を確かめればいいかが分かる** | SBOM（CycloneDX / SPDX）を OSV.dev と照合し、公式アドバイザリや修正コミットを調べ、Yes/No で答えられる確認ポイントの下書きを作ります |
| **コードがあれば、答えの一部が自動で埋まる** | コードと設定ファイル（Tomcat の `server.xml`、`php.ini` とその上書き、Nginx の HTTP/2）を走査します。コメントやテストコードは区別します |
| **ベンダーと同じ表で話せる** | 確認ポイントを、担当製品に絞った CSV で書き出します。戻ってきた回答は、根拠と確認者がそろったものだけを「非該当」として記録し、曖昧な回答は「要確認」にします。過去の回答は履歴に残ります |
| **パッチの日が、前もって予定表に入る** | Node.js と Tomcat の公式フィードを巡回し、Oracle CPU・Microsoft Patch Tuesday・PostgreSQL の定期日程を計算して、iCalendar（`.ics`）で書き出します |
| **対応にかかった時間を、数字で説明できる** | 公表から、照会、回答、パッチ適用完了までの時刻と、夜間・休日の対応操作の件数を記録します。比較の基準値は、利用者が用意した出典付きの実測値だけを使います |
| **「ローカルだから後回し」の危険な組み合わせが見える（v0.4.0）** | 外部公開のワークロードの侵入足場（RCE など）と、同じカーネルを共有するノードの未解消の権限昇格（LPE）を突き合わせ、Critical（48時間以内）として知らせます |

---

## このツールが守っている約束

- **分からないものを安全と言わない。** 調査に失敗したもの、設定が見つからないもの、回答が曖昧なものは、すべて「要確認」になります
- **失敗を黙って成功にしない。** 調べられなかったものは「未調査」として残り、CI で処理を止めることもできます
- **作った内容を本物に見せない。** 根拠のない数字、出典のない緩和策、仮の基準値は使いません。デモのデータはデモだと分かる形でしか出しません
- **判断は人が持つ。** AI が作るのは確認ポイントの下書きまでです。「非該当」を決めるのは、根拠を添えた人のサインオフです

そのため「要確認」は多めに出ます。これは意図した動作です。

---

## できないこと

- **安全の証明はしません。** 到達可能性の解析（そのコードに本当に到達するかの証明）は行いません
- **事前予告の自動巡回は、Node.js と Tomcat だけです。** OpenSSL・Go・Python・Django・Nginx・Apache HTTP Server は監視先の案内のみです（[一覧はデータとして追加できます](docs/early-warning-calendar.md)）
- **SBOM に載っていないものは見えません。** ソースディレクトリだけを読んだ SBOM には、Node.js 本体や PHP などの実行環境が入りません。コンテナイメージ単位の SBOM を推奨します
- **カーネルの修正版の情報は手入力です。** 攻撃連鎖の評価で使う修正版は、公式アドバイザリをもとに出典付きで台帳に入れます
- **既存の脆弱性管理製品の置き換えではありません。** 既知の脆弱性との照合や継続監視は既存製品が強い領域です。triage-agent はその前（予告）と後（確認ポイント、往復の記録、攻撃連鎖の評価）を担います
- **本格的な調査には Gemini の API が必要です。** 外部の AI や API に情報を渡してよいかは、各社のルールを確認してください（どの処理で何が送信され、何が送られないかの詳細は [docs/data-handling.md](docs/data-handling.md) を参照してください。Vertex AI 契約や LLM 不使用モードの選択肢もあります）

---

## 本番で使う

### 1. 準備
Python 3.11 以上が必要です。

```bash
pip install -e .
echo 'GEMINI_API_KEY="your-gemini-api-key"' > .env
```

GitHub のトークンは不要です（OSV.dev で動作します）。モデルの切り替えなどは [docs/setup.md](docs/setup.md) を参照してください。

### 2. SBOM を作って調べる
```bash
# 推奨：コンテナイメージ全体から SBOM を作る（実行環境も含まれます）
syft scan docker:my-org/my-app:latest -o cyclonedx-json > my_sbom.json

# トリアージ指示書とカレンダーを生成
python -m triage_agent.cli --sbom my_sbom.json \
  --output triage-output/triage_report.json \
  --calendar triage-output/patch_calendar.ics
```
ベンダーから受け取った SBOM でも動きます。

### 3. ベンダーと往復する
```bash
# 担当製品に絞って書き出す
python -m triage_agent.cli --sbom my_sbom.json \
  --export-checklist triage-output/vendor_a.csv \
  --export-checklist-target "Apache Tomcat"

# 戻ってきた回答を取り込む
python -m triage_agent.cli --import-checklist vendor_a_answered.csv \
  --audit-file triage-output/audit_signoff.json

# パッチ適用の完了を記録する（配布 ID は CSV に入っています）
python -m triage_agent.cli --record-remediation DIST-xxxxxxxx-xxxxxx \
  --remediated-at 2026-12-02T10:30:00+09:00
```

### 4. 攻撃連鎖を評価する（v0.4.0）
```bash
# 各ノード上で実行（読み取りのみ。ホスト名は --include-hostname を付けたときだけ記録）
sh scripts/collect_kernel_telemetry.sh -p dmz-pool -o triage-output/telemetry/node01.json

# 監査を実行
python -m triage_agent.cli --chain-audit \
  --environments environments.example.yaml \
  --chain-ledger exploit_chain_ledger.example.json \
  --telemetry triage-output/telemetry/ \
  --chain-output triage-output/chain_audit_report.md
```
環境定義と台帳の見本は [`environments.example.yaml`](environments.example.yaml) と [`exploit_chain_ledger.example.json`](exploit_chain_ledger.example.json) です。詳しくは [docs/exploit-chain.md](docs/exploit-chain.md) を参照してください。

### 5. CI に組み込む
```bash
# 未調査や該当ありがあれば非ゼロで終了
python -m triage_agent.cli --sbom my_sbom.json --fail-on unscanned,yes

# 攻撃連鎖（Critical）があれば非ゼロで終了
python -m triage_agent.cli --chain-audit --environments triage-output/environments.yaml --fail-on critical_chain
```
GitHub Actions の例は [`.github/workflows/self-triage.yml`](.github/workflows/self-triage.yml) にあります（triage-agent 自身を毎回診断しています）。

---

## 画面で使う

```bash
python -m triage_agent.web_ui
```

自分の PC の中（`127.0.0.1:8080`）だけで動く画面がブラウザで開きます。

---

## 出力物の扱いに注意してください

triage-agent の出力（レポート、環境定義、CSV、ノード情報）は、**「自社のどこに、何があり、どこが弱いか」の一覧、つまり攻撃者にとっての地図** です。

- 出力は `triage-output/` に置いてください（`.gitignore` の対象です）
- 公開リポジトリの CI ログには、件数だけを出すようにしています
- ベンダーに渡す CSV は、担当製品に絞って書き出してください
- カレンダーの予定には、社内のパッケージ名を載せていません。ただし情報源の名前（Oracle CPU など）から技術スタックの大枠は推測できるので、共有範囲に注意してください

どの処理で何が送信され、何が手元に留まるかの詳細は、[docs/data-handling.md](docs/data-handling.md) に一覧で開示しています。

---

## 詳しく知りたい方へ

| 内容 | ドキュメント |
| :--- | :--- |
| **外部通信とデータ送信仕様（どこへ何が送られ、何が送られないか）** | [docs/data-handling.md](docs/data-handling.md) |
| **仕組みと構成（エージェントの役割、データの流れ）** | [docs/architecture.md](docs/architecture.md) |
| **CLI のすべてのオプション、SBOM の作り方** | [docs/usage.md](docs/usage.md) |
| **インストール、環境設定（.env）、モデル選択** | [docs/setup.md](docs/setup.md) |
| **コードと設定ファイルの検証（Verifier）** | [docs/verifier.md](docs/verifier.md) |
| **サインオフの形式と運用、正本の管理** | [docs/signoff.md](docs/signoff.md) |
| **事前予告カレンダーと監視先の追加方法** | [docs/early-warning-calendar.md](docs/early-warning-calendar.md) |
| **攻撃連鎖の評価（環境定義、台帳、ノード情報）** | [docs/exploit-chain.md](docs/exploit-chain.md) |
| **ベンダーとの往復と、対応時間の計測** | [docs/vendor-workflow.md](docs/vendor-workflow.md) |
| **評価セット（見逃しと誤検知の測定）** | [docs/benchmark.md](docs/benchmark.md) |
| **自己診断（Self-Triage）** | [docs/self-triage.md](docs/self-triage.md) |
| **設計判断の記録（ADR）** | [docs/decision.md](docs/decision.md) |
| **今後の予定** | [docs/todo.md](docs/todo.md) |

---

## ご協力のお誘い

特に歓迎しているのは、コードよりも現場の知識です：

- **「この OSS は、ここで予告を出している」**: [`advisory_sources.toml`](src/triage_agent/data/advisory_sources.toml) に監視先を追加する Pull Request。公式の情報源に限り、定期日程の場合は根拠となる公式ページの URL を添えてください
- **「この確認ポイントはベンダーに伝わらなかった」**: 確認ポイントの書き方の改善提案を Issue でお寄せください
- **見逃しや誤検知のケース**: 評価セット（`benchmark/`）に追加できる再現ケース

---

## ライセンス

[Apache License 2.0](LICENSE)。企業での利用、改変、組み込みを歓迎します。
