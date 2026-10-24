# 自社コードベース脆弱性発火条件・検証結果レポート

**対象コードベース:** `/Users/hamatsumakoto/Documents/develop/triage-agent/demo_app`
**総合判定:** `【要対応あり (ACTION REQUIRED)】`

## 1. 検証サマリ
- **総検査項目数:** 6 件
- **判定: YES (発火条件該当・要対応):** 3 件
- **判定: NO (該当なし・安全):** 3 件

---

## 2. プロダクト別詳細検証結果
### urllib3（利用バージョン: 1.26.18）
**自社判定結果:** `NO (安全)`
**対応方針:** 【通常リリース可】自社コード内で発火設定は検出されませんでした。通常リリース（30日以内）での更新対応で問題ありません。

| 対象 / CVE (CVSS) | 確認ポイント（Yes/No） | 自社判定 | 検出コード / 判定根拠 |
| :--- | :--- | :--- | :--- |
| CVE-2026-97688 (CVSS: 未公表 (Medium)) | HTTPResponse.stream() または read_chunked() でチャンク転送をストリーミング処理しているか | **NO (安全)** | 該当設定・API呼び出し（stream(, read_chunked(）はコード内に見つかりません |
| CVE-2026-97689 (CVSS: 未公表 (High)) | HTTPResponse.stream() または read_chunked() でチャンク転送をストリーミング処理しているか | **NO (安全)** | 該当設定・API呼び出し（stream(, read_chunked(）はコード内に見つかりません |
| CVE-2026-97687 (CVSS: 未公表 (High)) | HTTPS プロキシ経由で TLS 通信を行う設定を使用しているか | **NO (安全)** | 該当設定・API呼び出し（HTTPS_PROXY, ProxyManager）はコード内に見つかりません |

---

### jsonwebtoken（利用バージョン: 8.5.1）
**自社判定結果:** `YES (要対応)`
**対応方針:** 【緊急対応要】自社コード内に発火条件を検知したため、外部公開システムは7日以内（または指示書記載の期限）に設定変更またはパッチを適用してください。

| 対象 / CVE (CVSS) | 確認ポイント（Yes/No） | 自社判定 | 検出コード / 判定根拠 |
| :--- | :--- | :--- | :--- |
| GHSA-27h2-hvpr-p74q (CVSS: 未公表 (Medium)) | jwt.verify() の algorithms オプションを省略または外部指定可能にしているか | **YES (要対応)** | • `server.js:6`: `return jwt.verify(token, "secret-key");` |
| CVE-2022-23540 (CVSS: 未公表 (Medium)) | jwt.verify() の algorithms オプションを省略または外部指定可能にしているか | **YES (要対応)** | • `server.js:6`: `return jwt.verify(token, "secret-key");` |
| CVE-2022-23541 (CVSS: 未公表 (Medium)) | jwt.verify() の algorithms オプションを省略または外部指定可能にしているか | **YES (要対応)** | • `server.js:6`: `return jwt.verify(token, "secret-key");` |

> **推奨回避策:** jsonwebtoken の呼び出し箇所で入力バリデーションを厳格化するか、該当機能のオプション設定を明示的に指定して無効化する。

---
