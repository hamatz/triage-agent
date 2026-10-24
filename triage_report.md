# SBOM脆弱性トリアージ・現場即応指示書

## urllib3（利用バージョン: 1.26.18）（直近公開（GitHub / OSV最新シグナル））
**結論：** 下の確認ポイントに1つでも Yes で、かつ CVSS 7.0（High）以上の場合は、外部公開のシステムは7日以内に更新または回避策を適用します。CVSS 6.9 以下のものや、すべて No なら通常リリース（30日以内）で構いません。
**公開日：** 直近公開（GitHub / OSV最新シグナル）
**修正版：** urllib3 次期最新パッチリリース
**深刻度：** High 相当。RCE の直接の報告なし（Dos / 情報漏洩リスク）

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| CVE-2026-97688 (CVSS: 未公表 (Medium)) | Chunked Deflate streaming can enter an infinite loop | Affects versions around 1.26.18 | HTTPResponse.stream() または read_chunked() でチャンク転送をストリーミング処理しているか | コードベースを stream(、read_chunked(、decode_content= で検索。巨大なDeflateレスポンスを扱うクライアント処理があるか確認 |
| CVE-2026-97689 (CVSS: 未公表 (High)) | HTTPResponse.stream()/read_chunked() buffers an unbounded chunk-size line into memory | Affects versions around 1.26.18 | HTTPResponse.stream() または read_chunked() でチャンク転送をストリーミング処理しているか | コードベースを stream(、read_chunked(、decode_content= で検索。巨大なDeflateレスポンスを扱うクライアント処理があるか確認 |
| CVE-2026-97687 (CVSS: 未公表 (High)) | HTTPS proxy TLS configuration may be ignored or overridden | Affects versions around 1.26.18 | HTTPS プロキシ経由で TLS 通信を行う設定を使用しているか | 環境変数 HTTPS_PROXY や ProxyManager( で HTTPS プロキシを設定している箇所を検索。証明書検証が無効化されていないか確認 |

> 先にバージョンを確認します。範囲外なら、その CVE の確認ポイントは No として扱います。

**回避策：** urllib3 の呼び出し箇所で入力バリデーションを厳格化するか、該当機能のオプション設定を明示的に指定して無効化する。

**未確認事項**
- 他言語バインディングや推移的依存先への波及状況
- 最新パッチ適用時の後方互換性（メジャーバージョンアップ要否）

**出典：** <https://github.com/urllib3/urllib3/security/advisories/GHSA-gh4c-6fx4-qh6g>, <https://github.com/urllib3/urllib3/security/advisories/GHSA-vxq7-64xx-v4gw>, <https://github.com/urllib3/urllib3/security/advisories/GHSA-8988-9cw3-xx77>

---

## jsonwebtoken（利用バージョン: 8.5.1）（直近公開（GitHub / OSV最新シグナル））
**結論：** 下の確認ポイントに1つでも Yes で、かつ CVSS 7.0（High）以上の場合は、外部公開のシステムは7日以内に更新または回避策を適用します。CVSS 6.9 以下のものや、すべて No なら通常リリース（30日以内）で構いません。
**公開日：** 直近公開（GitHub / OSV最新シグナル）
**修正版：** jsonwebtoken 次期最新パッチリリース
**深刻度：** High 相当。RCE の直接の報告なし（Dos / 情報漏洩リスク）

| 対象 / CVE (CVSS) | 内容 | 影響バージョン | 確認ポイント（Yes/No） | 確認方法 |
| :--- | :--- | :--- | :--- | :--- |
| GHSA-27h2-hvpr-p74q (CVSS: 未公表 (Medium)) | Insecure input validation in jwt.verify function | Affects versions around 8.5.1 | jwt.verify() の algorithms オプションを省略または外部指定可能にしているか | コードベースで jwt.verify を検索。第3引数の options に algorithms: ['RS256'] 等の固定アルゴリズムが明示されているか確認 |
| CVE-2022-23540 (CVSS: 未公表 (Medium)) | Insecure default algorithm in jwt.verify() could lead to signature validation bypass | Affects versions around 8.5.1 | jwt.verify() の algorithms オプションを省略または外部指定可能にしているか | コードベースで jwt.verify を検索。第3引数の options に algorithms: ['RS256'] 等の固定アルゴリズムが明示されているか確認 |
| CVE-2022-23541 (CVSS: 未公表 (Medium)) | Insecure implementation of key retrieval function could lead to Forgeable Public/Private Tokens from RSA to HMAC | Affects versions around 8.5.1 | jwt.verify() の algorithms オプションを省略または外部指定可能にしているか | コードベースで jwt.verify を検索。第3引数の options に algorithms: ['RS256'] 等の固定アルゴリズムが明示されているか確認 |

> 先にバージョンを確認します。範囲外なら、その CVE の確認ポイントは No として扱います。

**回避策：** jsonwebtoken の呼び出し箇所で入力バリデーションを厳格化するか、該当機能のオプション設定を明示的に指定して無効化する。

**未確認事項**
- 他言語バインディングや推移的依存先への波及状況
- 最新パッチ適用時の後方互換性（メジャーバージョンアップ要否）

**出典：** <https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-27h2-hvpr-p74q>, <https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-qwph-4952-7xr6>, <https://github.com/auth0/node-jsonwebtoken/security/advisories/GHSA-hjrf-2m68-5959>

---
