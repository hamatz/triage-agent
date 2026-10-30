"""Tests for Clean / Non-vulnerable Components in Verifier (ADR-019).

Ensures that packages with no vulnerabilities (e.g. google-auth concluding '対応不要'
or severity 'なし') are never falsely downgraded to '要確認 (外部設定・環境設定の確認要)'.
"""

import tempfile
import unittest
from pathlib import Path

from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport
from triage_agent.verifier.engine import verify_codebase


class TestCleanComponentVerification(unittest.TestCase):
    """Test suite ensuring clean components are recognized as safe (NO) without alarm fatigue."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.code_dir = Path(self.tmp_dir.name)
        (self.code_dir / "main.py").write_text("import os\nprint('hello')", encoding="utf-8")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_clean_component_with_no_checkpoints(self):
        """A notice concluding no vulnerabilities with empty check_points must be NO (安全)."""
        report = TriageReport(
            report_title="Test Clean Audit",
            scan_target="self-audit",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="google-auth（利用バージョン: 2.62.0）",
                    announcement_date="2026-10-27",
                    conclusion="現在導入されているバージョン 2.62.0 において該当するセキュリティ脆弱性は報告されていません。対応不要です。",
                    fixed_versions="N/A (該当脆弱性なし)",
                    severity_note="なし",
                    check_points=[],
                )
            ],
        )

        res = verify_codebase(report, code_dir_path=str(self.code_dir))
        self.assertEqual(res.overall_status, "NO (安全・確認済み)")
        self.assertEqual(res.summary_counts["unverified_count"], 0)
        self.assertEqual(res.summary_counts["safe_count"], 1)

        nr = res.notice_results[0]
        self.assertIn("NO", nr.overall_status)
        self.assertIn("該当脆弱性なし", nr.overall_status)

    def test_clean_component_with_informational_checkpoint(self):
        """Even if LLM generates an informational check_point for a clean notice, Verifier must NOT report 要確認."""
        report = TriageReport(
            report_title="Test Clean Audit with CP",
            scan_target="self-audit",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="google-auth（利用バージョン: 2.62.0）",
                    announcement_date="2026-10-27",
                    conclusion="現在導入されているバージョン 2.62.0 において該当するセキュリティ脆弱性は報告されていません。対応不要です。",
                    fixed_versions="N/A (該当脆弱性なし)",
                    severity_note="なし",
                    check_points=[
                        CheckPointItem(
                            target_or_cve="N/A (該当脆弱性なし)",
                            cvss="なし",
                            content_summary="一般的なセキュリティ注意点",
                            affected_versions="なし",
                            check_point_yes_no="サービスアカウントキーを適切に管理しているか",
                            verification_method="コードベースで service_account を検索",
                            check_point_id="google-auth-safe-1",
                        )
                    ],
                )
            ],
        )

        res = verify_codebase(report, code_dir_path=str(self.code_dir))
        self.assertEqual(res.overall_status, "NO (安全・確認済み)")
        self.assertEqual(res.summary_counts["unverified_count"], 0)
        self.assertEqual(res.summary_counts["safe_count"], 1)

        nr = res.notice_results[0]
        self.assertIn("NO", nr.overall_status)
        self.assertIn("該当脆弱性なし", nr.overall_status)

        cr = nr.results[0]
        self.assertIn("NO", cr.status)
        self.assertNotIn("コード内未検出 (外部設定・既定値の要確認)", cr.status)


if __name__ == "__main__":
    unittest.main()
