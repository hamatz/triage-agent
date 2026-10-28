# 脆弱性トリアージおよびインシデント即応アクション指示票（サンプル）

## log4j-core（2021年12月10日公開）
**結論：** 下の確認ポイントに1つでも Yes（特にJNDIルックアップ機能の利用または外部入力のログ出力）があれば、CVSS 10.0 (Critical) かつ RCE リスクが存在するため、外部公開システムは【48時間以内】に更新または回避策を実施してください。すべて No の場合でも本バージョンはEOL（サポート終了）のため30日以内に最新版へ更新してください。
**公開日：** 2021年12月10日公開
**修正版：** 2.17.1 (Java 8向け), 2.12.3 (Java 7向け), 2.3.2 (Java 6向け) または 現行安定版 2.25.5 / 2.26.1 以上
**深刻度：** Critical (CVSS 10.0), RCEリスクあり

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| CVE-2021-44228 (CVSS 10.0 Critical) | ログ出力処理におけるJNDIルックアップ評価の不備により、リモートサーバーからの任意コード実行（RCE）が可能となる脆弱性（Log4Shell）。 | >= 2.0-beta9, <= 2.14.1 | ログ出力の引数にHTTPリクエストヘッダーやユーザー入力などの外部入力を渡しており、かつJNDIルックアップ機能が有効化されているか | ソースコード内で logger.info(…), logger.error(…) 等の呼び出し部を検索し、外部入力をログ出力しているか確認。また JVM 起動オプションに -Dlog4j2.formatMsgNoLookups=true が指定されていない、または環境変数 LOG4J_FORMAT_MSG_NO_LOOKUPS=true が未設定の場合は YES（該当）。設定済みなら NO（非該当）。 |
| CVE-2021-45046 (CVSS 9.0 Critical) | Thread Context Map (MDC) を使用する特定のパターンレイアウト構成においてルックアップ評価が行われ、RCEやDoSを引き起こす脆弱性。 | >= 2.0-beta9, <= 2.15.0 | log4j2.xml 等の設定ファイルで Thread Context Map パターン（%X, %mdc, %MDC）を使用しているか | 設定ファイル（log4j2.xml, log4j2.properties）内で %X, %mdc, %MDC の記述を検索。記述が存在し、かつMDCに外部入力値を設定している場合は YES（該当）。使用していなければ NO（非該当）。 |
| CVE-2021-45105 (CVSS 7.5 High) | Context Map ルックアップなどのネストされたルックアップ評価処理において無限再帰が発生し、StackOverflowErrorによるDoSを引き起こす脆弱性。 | >= 2.0-alpha1, <= 2.16.0 | 設定ファイルで ${ctx:loginId} などのコンテキストマップルックアップパターンを使用しているか | 設定ファイル内で ${ctx: を検索。記述が存在する場合は YES（該当）。存在しなければ NO（非該当）。 |

> log4j-core 2.0-beta9 〜 2.14.1 を使用している場合に対象

**回避策：** 1. JVM起動オプションに `-Dlog4j2.formatMsgNoLookups=true` を追加するか、環境変数 `LOG4J_FORMAT_MSG_NO_LOOKUPS=true` を設定する。
2. クラスパスから `org/apache/logging/log4j/core/lookup/JndiLookup.class` を削除する (`zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`)。
副作用: JNDIを用いたログメッセージの動的参照機能が利用できなくなりますが、通常のアプリケーション運用への影響は軽微です。

**未確認事項**
- アプリケーションが依存するサードパーティ製ライブラリ内部での Log4j2 の抱え込み利用状況

**出典：** <https://logging.apache.org/log4j/2.x/security.html>, <https://www.cisa.gov/uscert/apache-log4j-vulnerability-guidance>

---

## jsonwebtoken（2022年12月21日公開）
**結論：** 下の確認ポイントに1つでも Yes の場合は、認証バイパスや鍵検証不備のリスクがあるため、外部公開システムは【7日以内】に更新またはコード修正を行ってください。すべて No の場合は通常リリース（30日以内）で構いません。
**公開日：** 2022年12月21日公開
**修正版：** 9.0.0 以上
**深刻度：** High 相当 (CVSS 7.5 相当), 認証バイパス・署名検証回避リスクあり

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| CVE-2022-23540 (CVSS 7.5 High相当) | jwt.verify() において algorithms オプションが未指定の場合に 'none' アルゴリズム等の未署名トークンを受け入れてしまい、署名検証をバイパスされる脆弱性。 | <= 8.5.1 | jwt.verify() 呼び出し時の第3引数 options で algorithms（許容アルゴリズムリスト）の指定を省略しているか | コードベースで jwt.verify を検索。呼び出し箇所の第3引数 options に algorithms: ['RS256'] や ['HS256'] などの配列が明示的に指定されていない場合は YES（該当）。常に明示指定されている場合は NO（非該当）。 |
| CVE-2022-23541 (CVSS 7.5 High相当) | 動的鍵取得コールバック（getKey関数等）使用時に鍵タイプ検証が不十分なため、RSA非対称鍵トークンをHMAC対称鍵として偽造されるキーコンフュージョン脆弱性。 | <= 8.5.1 | jwt.verify() の第2引数（secretOrPublicKey）に getKey などの動的鍵取得関数を渡し、その中でアルゴリズムと鍵タイプの整合性チェックを怠っているか | コード内で jwt.verify の第2引数に関数を渡している箇所を検索。関数内で header.alg や 鍵の型（asymmetricKeyType）を検証せずに鍵を返している場合は YES（該当）。 |
| CVE-2022-23539 (CVSS 7.5 High相当) | jwt.verify() の secretOrPublicKey 引数に文字列ではなく型未検証のオブジェクトが渡された場合、悪意ある toString() 定義により任意のコード実行やプロトタイプ汚染が引き起こされる脆弱性。 | <= 8.5.1 | secretOrPublicKey に外部からのリクエストボディや未検証のオブジェクトが直接渡される実装になっているか | jwt.verify(token, secret, ...) の secret 部分の型チェック（typeof secret === 'string' や Buffer チェック）が行われているか確認。外部入力をそのまま渡している場合は YES（該当）。環境変数や固定文字列のみの場合は NO（非該当）。 |

> jsonwebtoken <= 8.5.1 を使用している場合に対象

**回避策：** 1. `jwt.verify(token, secret, { algorithms: ['HS256'] })` のように、必ず第3引数の `algorithms` に使用するアルゴリズムを明示的に指定する。
2. `secretOrPublicKey` に渡す値が `string` または `Buffer` であることを事前に型チェックする。
副作用: 許容リストに含まれないアルゴリズムで署名された不正なトークンが拒否されます（意図通りの動作）。

**未確認事項**
- v9.0.0 へのアップデートに伴う Breaking Changes（Node.js 古いバージョンのサポート切り捨て、2048bit未満のRSA鍵拒否など）の影響範囲

**出典：** <https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-qwph-4952-7xr6>, <https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959>

---

## express（2024年9月公開）
**結論：** 下の確認ポイントに1つでも Yes の場合は、依存ライブラリ qs の脆弱性やオープンリダイレクトのリスクがあるため、外部公開システムは【7日以内】に 4.22.2 以上へ更新してください。すべて No の場合は通常リリース（30日以内）で構いません。
**公開日：** 2024年9月公開
**修正版：** 4.22.2 以上 (または 4.20.0 以上)
**深刻度：** High 相当 (依存関係 qs の CVE-2026-82417 / CVE-2026-82562 含む)

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| CVE-2026-82417 / CVE-2026-82562 (CVSS 7.5 High相当) | Express が内部で依存するクエリパースライブラリ qs に存在する脆弱性。ネストされたクエリパラメータのパース処理における欠陥。 | < 4.22.x (qs < 6.16.0) | req.query によるクエリパラメータのパース処理を使用しているか | Express アプリケーションでデフォルトのクエリパーサー（Extended query parser）を使用し、req.query を参照しているコードが存在すれば YES（該当）。`app.set('query parser', false)` 等で無効化していなければ該当します。 |
| CVE-2024-43796 (CVSS 5.0 Medium) | res.redirect() におけるエスケープ不備により、ユーザー検証のない入力が渡された場合に XSS やオープンリダイレクトが発生する脆弱性。 | < 4.20.0 | res.redirect() の引数にユーザーからの入力（req.query.url や req.body.redirectTo 等）を直接渡しているか | コードベースで `res.redirect(` を検索。引数にユーザー入力を直接指定し、かつドメインやスキームの検証を行っていない箇所があれば YES（該当）。 |

> express < 4.20.0 (特に 4.17.1) を使用している場合に対象

**回避策：** 1. `package.json` の overrides / resolutions フィールド等を用いて、依存ライブラリ `qs` のバージョンを `6.16.0` 以上に強制固定する。
2. `res.redirect()` に渡す URL について、相対パス限定にするか許可リスト方式で検証する。
副作用: qs のバージョン固定によるクエリパース挙動の軽微な変化の可能性があります。

**未確認事項**
- アプリケーションが独自にクエリパーサーを上書き設定している場合の qs への依存度

**出典：** <https://github.com/expressjs/express/security/advisories/GHSA-qw6h-vgh9-j6wx>, <https://github.com/expressjs/express/commit/3b7e39fe74371ddabc77fed736dd22aa71c14f5c>

---

## axios（2025年2月 / 2026年公開）
**結論：** 下の確認ポイントに1つでも Yes（特にプロキシ設定やプロキシバイパス処理、data: URIの処理など）がある場合は、ReDoS や SSRF、認証ヘッダー漏洩のリスクがあるため、外部公開システムは【7日以内】に更新してください。すべて No なら通常リリース（30日以内）で構いません。
**公開日：** 2025年2月 / 2026年公開
**修正版：** 1.19.0 以上 (または 0.34.0 以上)
**深刻度：** High (CVSS 8.2), ReDoS / SSRF / ヘッダー漏洩リスクあり

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| GHSA-mghh-pgcx-3jjj (CVSS 8.2 High) | shouldBypassProxy のホスト正規化処理における ReDoS 脆弱性。未認証のリダイレクト Location ヘッダー経由でイベントループを停止させられる。 | < 0.34.0 / < 1.19.0 | HTTP/HTTPS プロキシ設定（proxy オプションまたは HTTP_PROXY / HTTPS_PROXY / NO_PROXY 環境変数）を有効にして外部リクエストを行っているか | axios.create() や axios() の呼び出しで `proxy:` 設定を使用しているか、または環境変数 `NO_PROXY` / `HTTPS_PROXY` が設定されている環境で動作しているか確認。該当する場合は YES（該当）。 |
| GHSA-c29m-xwm3-cm6r (CVSS 8.2 High) | fromDataURI における data: スキーム URL のパース処理に ReDoS 脆弱性が存在し、Node.js のイベントループを停止（DoS）させることができる。 | < 0.34.0 / < 1.19.0 | 外部から与えられた `data:` 形式の URI 文字列を axios でリクエスト処理しているか | コードベースで axios(url) の url パラメータに `data:` スキームのデータが渡る可能性があるか検索。渡る可能性がある場合は YES（該当）。 |
| CVE-2025-27152 (CVSS 7.5 High) | 絶対URLの取り扱いおよび NO_PROXY 環境変数の正規化処理における不備により、プロキシ検証をバイパスして SSRF が実行可能となる脆弱性。 | < 0.31.0 / < 1.15.0 | ユーザー入力の URL に対して NO_PROXY 設定環境下で axios リクエストを送信しているか | ユーザー入力由来の URL（絶対URL）を axios.get(inputUrl) 等でリクエストしており、かつ NO_PROXY を利用している構成であれば YES（該当）。 |

> axios < 0.34.0 または < 1.19.0 (特に 0.21.1) を使用している場合に対象

**回避策：** 1. 信頼できない外部サイトへの自動リダイレクトを無効化する (`maxRedirects: 0`)。
2. ユーザー入力の URL を axios に渡す前に厳格に検証し、`data:` スキームを拒否する。
副作用: リダイレクト追跡機能が停止するため、必要なリダイレクト処理は手動で実装する必要があります。

**未確認事項**
- 0.x 系から 1.x 系へのメジャーアップデートに伴う破壊的変更（Headers オブジェクトの扱い等）の適用影響

**出典：** <https://github.com/axios/axios/security/advisories/GHSA-mghh-pgcx-3jjj>, <https://github.com/axios/axios/security/advisories/GHSA-c29m-xwm3-cm6r>

---

## urllib3（2026年公開）
**結論：** 下の確認ポイントに1つでも Yes（特に streaming API、read_chunked()、ProxyManager の利用）がある場合は、メモリ枯渇 DoS やヘッダー漏洩のリスクがあるため、外部公開システムは【7日以内】に更新してください。すべて No なら通常リリース（30日以内）で構いません。
**公開日：** 2026年公開
**修正版：** 1.26.19 以上 (1.x branch) または 2.8.0 以上
**深刻度：** High (CVSS 8.9), メモリ枯渇 DoS / 無限ループ / 認証情報漏洩リスクあり

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| CVE-2026-97689 (CVSS 8.9 High) | HTTPResponse.read_chunked() および stream() において chunk-size 行の長制限がないため、悪意あるサーバーからの応答により過度なメモリを消費させられる脆弱性。 | >= 1.10.3, < 2.8.0 | レスポンス取得時に HTTPResponse.read_chunked() または HTTPResponse.stream() を使用しているか | コードベースで `.read_chunked(` または `.stream(` を検索。外部・非信頼サーバーへのリクエストでこれらを使用している場合は YES（該当）。 |
| CVE-2026-44432 (CVSS 8.9 High) | ストリーミング API で preload_content=False を使用した際、リダイレクト応答の展開処理が制限前に全読込され、展開爆弾（Decompression Bomb）によるリソース枯渇が発生する脆弱性。 | >= 1.22, < 2.6.3 | リクエスト送信時に `preload_content=False` オプションを指定してストリーミング処理を行っているか | コードベースで `preload_content=False` を検索。指定が存在し、外部 URL へのリクエストを行っている場合は YES（該当）。 |
| CVE-2026-44431 (CVSS 8.2 High) | 低レベルプロキシインターフェース使用時、クロスオリジンリダイレクトにおいて機密ヘッダーが誤って保持・送信されてしまう脆弱性。 | >= 1.23, < 2.7.0 | ProxyManager 等で `assert_same_host=False` を指定したプロキシリダイレクトを行っているか | コードベースで `ProxyManager` や `connection_from_url` を検索し、`assert_same_host=False` パラメータが渡されているか確認。渡されている場合は YES（該当）。 |

> urllib3 1.26.18 を使用している場合に対象

**回避策：** 1. 信頼できない先へのリクエストで `preload_content=False` を使う場合、リダイレクト追跡を無効化する (`redirect=False`)。
2. 応答ヘッダーの Content-Encoding による自動解凍に頼らず、受信サイズの上限をチェックする。
副作用: リダイレクトの手動処理が必要になります。

**未確認事項**
- 1.x 系の最終メンテナンススケジュールおよび 2.x 系列へのアップグレードによる互換性影響

**出典：** <https://github.com/urllib3/urllib3/security/advisories/GHSA-vxq7-64xx-v4gw>, <https://github.com/urllib3/urllib3/security/advisories/GHSA-mf9v-mfxr-j63j>

---

## fastapi（2021年公開 (旧脆弱性)）
**結論：** 現在使用中のバージョン 0.95.0 に影響する緊急の脆弱性やパッチ予告は検出されませんでした。確認ポイントはすべて No となるため、対応は【通常リリース（30日以内）】での定例アップデートで問題ありません。
**公開日：** 2021年公開 (旧脆弱性)
**修正版：** 0.65.2 以上 (利用中の 0.95.0 で修正済み)
**深刻度：** 該当なし (過去の CVE-2021-32677 は 0.65.2 で修正済み)

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| CVE-2021-32677 (CVSS 5.3 Medium) | FastAPI 0.65.2 未満における CSRF 脆弱性。現行の 0.95.0 では既に修正されています。 | < 0.65.2 | FastAPI のバージョンが 0.65.2 未満であるか | `pip show fastapi` または `poetry show fastapi` を実行し、バージョンを確認。0.95.0 のため結果は NO（非該当）。 |

> fastapi < 0.65.2 のみ対象（現在 0.95.0 利用中のため非該当）

**出典：** <https://github.com/fastapi/fastapi/security/advisories/GHSA-8h2j-cgx8-6xv7>

---
