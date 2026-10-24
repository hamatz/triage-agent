# SBOM脆弱性トリアージ・現場即応指示書 (DRY-RUN シミュレーション)

> ⚠️ **【DRY-RUN / シミュレーション実行】** 本レポートはオフライン静的解析によるシミュレーション結果です。確定判定（RCE有無の精読や修正パッチバージョンの確定）はライブエージェント（GEMINI_API_KEY設定環境）で実行してください。

## urllib3（利用バージョン: 1.26.18）（直近公開（GitHub / OSV最新シグナル））
**結論：** 【DRY-RUN シミュレーション】下の確認ポイントに1つでも Yes、または不明なら該当ありとして要確認。外部公開システムで Critical なら48時間以内、Highなら7日以内に更新または回避策。確定判断はライブエージェントで実行してください。
**公開日：** 直近公開（GitHub / OSV最新シグナル）
**修正版：** urllib3 最新パッチ [DRY-RUN: 修正バージョンはライブ実行で確認]
**深刻度：** 推定深刻度: Medium [DRY-RUN: RCE有無や正確なCVSSはライブ精読で判定]

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| CVE-2026-97688 (CVSS: Medium) | Chunked Deflate streaming can enter an infinite loop | Affects versions around 1.26.18 | HTTPResponse.stream() または read_chunked() でチャンク転送をストリーミング処理しているか | コードベースを stream(、read_chunked(、decode_content= で検索。巨大なDeflateレスポンスを扱うクライアント処理があるか確認 |
| CVE-2026-97689 (CVSS: High) | HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory | Affects versions around 1.26.18 | HTTPResponse.stream() または read_chunked() でチャンク転送をストリーミング処理しているか | コードベースを stream(、read_chunked(、decode_content= で検索。巨大なDeflateレスポンスを扱うクライアント処理があるか確認 |
| CVE-2026-97687 (CVSS: High) | HTTPS proxy TLS configuration may be ignored or overridden | Affects versions around 1.26.18 | HTTPS プロキシ経由で TLS 通信を行う設定を使用しているか | 環境変数 HTTPS_PROXY や ProxyManager( で HTTPS プロキシを設定している箇所を検索。証明書検証が無効化されていないか確認 |
| CVE-2026-44432 (CVSS: High) | Decompression-bomb safeguards bypassed in parts of the streaming API | Affects versions around 1.26.18 | HTTPResponse.stream() または read_chunked() でチャンク転送をストリーミング処理しているか | コードベースを stream(、read_chunked(、decode_content= で検索。巨大なDeflateレスポンスを扱うクライアント処理があるか確認 |
| CVE-2026-44431 (CVSS: High) | Sensitive headers forwarded across origins in proxied low-level redirects | Affects versions around 1.26.18 | 外部入力されたURLやヘッダーを直接 urllib3 に渡しているか | コード内で urllib3.PoolManager や requests を呼び出している外部通信処理を検索 |

> 先にバージョンを確認します。範囲外なら、その CVE の確認ポイントは No として扱います。

**回避策：** 回避策（暫定案）: urllib3 の呼び出し箇所で入力バリデーションを厳格化するか、該当機能のオプション設定を明示的に指定して無効化する。

**未確認事項**
- [DRY-RUN] 正確なRCE発火条件およびパッチコミットDiffの精読は未実施です。
- [DRY-RUN] 他言語バインディングや推移的依存先への波及状況はライブ実行で確認してください。

**出典：** <https://github.com/urllib3/urllib3/security/advisories/GHSA-gh4c-6fx4-qh6g>, <https://github.com/urllib3/urllib3/security/advisories/GHSA-vxq7-64xx-v4gw>, <https://github.com/urllib3/urllib3/security/advisories/GHSA-8988-9cw3-xx77>

---

## jsonwebtoken（利用バージョン: 8.5.1）（直近公開（GitHub / OSV最新シグナル））
**結論：** 【DRY-RUN シミュレーション】下の確認ポイントに1つでも Yes、または不明なら該当ありとして要確認。外部公開システムで Critical なら48時間以内、Highなら7日以内に更新または回避策。確定判断はライブエージェントで実行してください。
**公開日：** 直近公開（GitHub / OSV最新シグナル）
**修正版：** jsonwebtoken 最新パッチ [DRY-RUN: 修正バージョンはライブ実行で確認]
**深刻度：** 推定深刻度: Medium [DRY-RUN: RCE有無や正確なCVSSはライブ精読で判定]

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| GHSA-27h2-hvpr-p74q (CVSS: Medium) | Insecure input validation in jwt.verify function | Affects versions around 8.5.1 | jwt.verify() の algorithms オプションを省略または外部指定可能にしているか | コードベースで jwt.verify を検索。第3引数の options に algorithms: ['RS256'] 等の固定アルゴリズムが明示されているか確認 |
| CVE-2022-23540 (CVSS: Medium) | Insecure default algorithm in jwt.verify() could lead to signature validation bypass | Affects versions around 8.5.1 | jwt.verify() の algorithms オプションを省略または外部指定可能にしているか | コードベースで jwt.verify を検索。第3引数の options に algorithms: ['RS256'] 等の固定アルゴリズムが明示されているか確認 |
| CVE-2022-23541 (CVSS: Medium) | Insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC | Affects versions around 8.5.1 | jwt.verify() の algorithms オプションを省略または外部指定可能にしているか | コードベースで jwt.verify を検索。第3引数の options に algorithms: ['RS256'] 等の固定アルゴリズムが明示されているか確認 |
| CVE-2022-23539 (CVSS: Medium) | Unrestricted key type could lead to legacy keys usage  | Affects versions around 8.5.1 | jwt.verify() の algorithms オプションを省略または外部指定可能にしているか | コードベースで jwt.verify を検索。第3引数の options に algorithms: ['RS256'] 等の固定アルゴリズムが明示されているか確認 |

> 先にバージョンを確認します。範囲外なら、その CVE の確認ポイントは No として扱います。

**回避策：** 回避策（暫定案）: jsonwebtoken の呼び出し箇所で入力バリデーションを厳格化するか、該当機能のオプション設定を明示的に指定して無効化する。

**未確認事項**
- [DRY-RUN] 正確なRCE発火条件およびパッチコミットDiffの精読は未実施です。
- [DRY-RUN] 他言語バインディングや推移的依存先への波及状況はライブ実行で確認してください。

**出典：** <https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-27h2-hvpr-p74q>, <https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-qwph-4952-7xr6>, <https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959>

---

## axios（利用バージョン: 0.21.1）（直近公開（GitHub / OSV最新シグナル））
**結論：** 【DRY-RUN シミュレーション】下の確認ポイントに1つでも Yes、または不明なら該当ありとして要確認。外部公開システムで Critical なら48時間以内、Highなら7日以内に更新または回避策。確定判断はライブエージェントで実行してください。
**公開日：** 直近公開（GitHub / OSV最新シグナル）
**修正版：** axios 最新パッチ [DRY-RUN: 修正バージョンはライブ実行で確認]
**深刻度：** 推定深刻度: High [DRY-RUN: RCE有無や正確なCVSSはライブ精読で判定]

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| CVE-2026-101901 (CVSS: High) | Denial of Service  via Unhandled 'error' Event in HTTP/2 ClientHttp2Session Initialization | Affects versions around 0.21.1 | axios の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで axios の設定ディレクティブを grep 検索 |
| CVE-2026-101898 (CVSS: High) | HTTP/2 adapter bypasses configured DNS lookup and proxy controls | Affects versions around 0.21.1 | axios の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで axios の設定ディレクティブを grep 検索 |
| CVE-2026-101909 (CVSS: High) | Prototype Pollution Gadget in axios toFormData Options | Affects versions around 0.21.1 | axios の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで axios の設定ディレクティブを grep 検索 |
| CVE-2026-101906 (CVSS: High) | ReDoS (O(N²)) in shouldBypassProxy host normalization, reachable via untrusted redirect Location | Affects versions around 0.21.1 | axios の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで axios の設定ディレクティブを grep 検索 |
| CVE-2026-101903 (CVSS: High) | ReDoS in fromDataURI data: URL parser freezes the Node event loop (DoS) | Affects versions around 0.21.1 | axios の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで axios の設定ディレクティブを grep 検索 |
| PRE-RELEASE-v1.19.0 (CVSS: 未公表 (Pre-release)) | Pre-release / Security Notice: v1.19.0 | Targeting fixes around 0.21.1 | axios の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで axios の設定ディレクティブを grep 検索 |
| PRE-RELEASE-v1.18.0 (CVSS: 未公表 (Pre-release)) | Pre-release / Security Notice: v1.18.0 | Targeting fixes around 0.21.1 | axios の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで axios の設定ディレクティブを grep 検索 |

> 先にバージョンを確認します。範囲外なら、その CVE の確認ポイントは No として扱います。

**回避策：** 回避策（暫定案）: axios の呼び出し箇所で入力バリデーションを厳格化するか、該当機能のオプション設定を明示的に指定して無効化する。

**未確認事項**
- [DRY-RUN] 正確なRCE発火条件およびパッチコミットDiffの精読は未実施です。
- [DRY-RUN] 他言語バインディングや推移的依存先への波及状況はライブ実行で確認してください。

**出典：** <https://github.com/axios/axios/security/advisories/GHSA-542g-h47m-68v8>, <https://github.com/axios/axios/security/advisories/GHSA-3pq3-5fj3-cg6v>, <https://github.com/axios/axios/security/advisories/GHSA-x97p-jq2g-jp4f>

---

## fastapi（利用バージョン: 0.95.0）（直近公開（GitHub / OSV最新シグナル））
**結論：** 【DRY-RUN シミュレーション】下の確認ポイントに1つでも Yes、または不明なら該当ありとして要確認。外部公開システムで Critical なら48時間以内、Highなら7日以内に更新または回避策。確定判断はライブエージェントで実行してください。
**公開日：** 直近公開（GitHub / OSV最新シグナル）
**修正版：** fastapi 最新パッチ [DRY-RUN: 修正バージョンはライブ実行で確認]
**深刻度：** 推定深刻度: Medium [DRY-RUN: RCE有無や正確なCVSSはライブ精読で判定]

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| CVE-2021-32677 (CVSS: 5.3 (Medium)) | Cross-Site Request Forgery (CSRF) in FastAPI | Affects versions around 0.95.0 | fastapi の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで fastapi の設定ディレクティブを grep 検索 |

> 先にバージョンを確認します。範囲外なら、その CVE の確認ポイントは No として扱います。

**回避策：** 回避策（暫定案）: fastapi の呼び出し箇所で入力バリデーションを厳格化するか、該当機能のオプション設定を明示的に指定して無効化する。

**未確認事項**
- [DRY-RUN] 正確なRCE発火条件およびパッチコミットDiffの精読は未実施です。
- [DRY-RUN] 他言語バインディングや推移的依存先への波及状況はライブ実行で確認してください。

**出典：** <https://github.com/fastapi/fastapi/security/advisories/GHSA-8h2j-cgx8-6xv7>

---

## express（利用バージョン: 4.17.1）（直近公開（GitHub / OSV最新シグナル））
**結論：** 【DRY-RUN シミュレーション】下の確認ポイントに1つでも Yes、または不明なら該当ありとして要確認。外部公開システムで Critical なら48時間以内、Highなら7日以内に更新または回避策。確定判断はライブエージェントで実行してください。
**公開日：** 直近公開（GitHub / OSV最新シグナル）
**修正版：** express 最新パッチ [DRY-RUN: 修正バージョンはライブ実行で確認]
**深刻度：** 推定深刻度: Low [DRY-RUN: RCE有無や正確なCVSSはライブ精読で判定]

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| CVE-2024-51999 (CVSS: Low) | REJECTED (not a vulnerability): improperly controlled modification of query properties in express | Affects versions around 4.17.1 | express の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで express の設定ディレクティブを grep 検索 |
| CVE-2024-43796 (CVSS: 5.0 (Medium)) | express vulnerable to XSS via response.redirect() | Affects versions around 4.17.1 | express の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで express の設定ディレクティブを grep 検索 |
| CVE-2024-29041 (CVSS: 6.1 (Medium)) | Express.js Open Redirect in malformed URLs | Affects versions around 4.17.1 | express の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで express の設定ディレクティブを grep 検索 |
| PRE-RELEASE-v5.2.1 (CVSS: 未公表 (Pre-release)) | Pre-release / Security Notice: v5.2.1 | Targeting fixes around 4.17.1 | express の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで express の設定ディレクティブを grep 検索 |
| PRE-RELEASE-v5.2.0 (CVSS: 未公表 (Pre-release)) | Pre-release / Security Notice: v5.2.0 | Targeting fixes around 4.17.1 | express の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで express の設定ディレクティブを grep 検索 |
| PRE-RELEASE-v4.22.1 (CVSS: 未公表 (Pre-release)) | Pre-release / Security Notice: v4.22.1 | Targeting fixes around 4.17.1 | express の特定脆弱機能（外部入力受付・非同期処理）を有効にしているか | 設定ファイルおよび依存コードで express の設定ディレクティブを grep 検索 |

> 先にバージョンを確認します。範囲外なら、その CVE の確認ポイントは No として扱います。

**回避策：** 回避策（暫定案）: express の呼び出し箇所で入力バリデーションを厳格化するか、該当機能のオプション設定を明示的に指定して無効化する。

**未確認事項**
- [DRY-RUN] 正確なRCE発火条件およびパッチコミットDiffの精読は未実施です。
- [DRY-RUN] 他言語バインディングや推移的依存先への波及状況はライブ実行で確認してください。

**出典：** <https://github.com/expressjs/express/security/advisories/GHSA-pj86-cfqh-vqx6>, <https://github.com/expressjs/express/security/advisories/GHSA-qw6h-vgh9-j6wx>, <https://github.com/expressjs/express/security/advisories/GHSA-rv95-896h-c2vc>

---
