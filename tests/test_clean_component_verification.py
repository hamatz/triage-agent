"""Tests for Clean / Non-vulnerable Components and Deterministic Verification Safety (ADR-019 / v0.3.1).

Ensures:
1. Packages with confirmed clean status (no_known_vulnerability=True, empty check_points)
   are recognized as NO without false alarm fatigue.
2. Natural language phrases with negation (e.g. '対応不要とは言えません') or unrated
   CVEs (CVSS: N/A) are NEVER falsely marked safe.
3. T4 remediation persistence in workflow_metrics.json.
"""

import json
import tempfile
import unittest
from pathlib import Path

from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport
from triage_agent.tools.vendor_workflow import (
    record_remediation_completed,
    record_workflow_event,
)
from triage_agent.verifier.engine import verify_codebase


class TestCleanComponentVerification(unittest.TestCase):
    """Test suite ensuring clean components are recognized safely and LLM text is never used to falsify safety."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.code_dir = Path(self.tmp_dir.name)
        (self.code_dir / "main.py").write_text("import os\nprint('hello')", encoding="utf-8")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_clean_component_with_deterministic_flag(self):
        """A notice with no_known_vulnerability=True and empty check_points must be safely NO."""
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
                    no_known_vulnerability=True,
                    clean_basis="OSV.dev 0件照合済み・2026-10-27時点",
                    check_points=[],
                )
            ],
        )

        res = verify_codebase(report, code_dir_path=str(self.code_dir))
        self.assertEqual(res.overall_status, "NO (安全・確認済み)")
        self.assertEqual(res.summary_counts["unverified_count"], 0)
        self.assertEqual(res.summary_counts["safe_count"], 1)

        nr = res.notice_results[0]
        self.assertIn("NO (既知の脆弱性なし", nr.overall_status)
        self.assertIn("OSV.dev 0件照合済み", nr.overall_status)

    def test_negated_phrase_must_not_become_safe(self):
        """A notice containing '対応不要とは言えません' must NOT be judged as safe!"""
        report = TriageReport(
            report_title="Test Negation Safety",
            scan_target="test-repo",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="nodejs（利用バージョン: 20.18.0）",
                    announcement_date="2026-10-21",
                    conclusion="WAF で遮断できない場合は対応不要とは言えません。至急更新してください。",
                    fixed_versions="20.18.1",
                    severity_note="Critical (CVSS 9.8)",
                    no_known_vulnerability=False,
                    check_points=[
                        CheckPointItem(
                            check_point_id="node-brotli-cp1",
                            target_or_cve="CVE-2026-111497 (CVSS 9.8)",
                            cvss="9.8 (Critical)",
                            content_summary="Brotli decompression RCE",
                            affected_versions="< 20.18.1",
                            check_point_yes_no="zlib / brotli 関連APIを利用しているか",
                            verification_method="コードベースで brotliDecompress を検索",
                        )
                    ],
                )
            ],
        )

        res = verify_codebase(report, code_dir_path=str(self.code_dir))
        # Code does not contain brotliDecompress, but it's an unverified external/env check
        self.assertNotEqual(res.overall_status, "NO (安全・確認済み)")
        self.assertIn("要確認", res.overall_status)
        self.assertEqual(res.summary_counts["safe_count"], 0)
        self.assertEqual(res.summary_counts["unverified_count"], 1)

    def test_unrated_new_cve_with_na_cvss_must_not_become_safe(self):
        """Newly released RCE with CVSS: N/A must NOT be judged safe."""
        report = TriageReport(
            report_title="Test Unrated CVE Safety",
            scan_target="test-repo",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="critical-pkg（利用バージョン: 1.0.0）",
                    announcement_date="2026-10-28",
                    conclusion="新着のゼロデイ脆弱性です。至急対応してください。",
                    fixed_versions="1.0.1",
                    severity_note="N/A",  # Unrated
                    no_known_vulnerability=False,
                    check_points=[
                        CheckPointItem(
                            check_point_id="crit-cp1",
                            target_or_cve="CVE-2026-999999 (CVSS N/A)",
                            cvss="N/A",
                            content_summary="Zero-day RCE",
                            affected_versions="1.0.0",
                            check_point_yes_no="該当APIを呼び出しているか",
                            verification_method="コードベースで vulnerable_endpoint を検索",
                        )
                    ],
                )
            ],
        )

        res = verify_codebase(report, code_dir_path=str(self.code_dir))
        self.assertNotEqual(res.overall_status, "NO (安全・確認済み)")
        self.assertIn("要確認", res.overall_status)
        self.assertEqual(res.summary_counts["unverified_count"], 1)

    def test_remediation_t4_persistence(self):
        """Verify that record_remediation_completed persists remediated_at and status: remediated to disk."""
        metrics_file = self.code_dir / "workflow_metrics.json"

        # 1. Simulate export event
        dist_id = "DIST-TEST-001"
        record_workflow_event("vendor_checklist_exported", {
            "distribution_id": dist_id,
            "target_product": "test-product",
            "check_points_count": 2,
            "announced_at": "2026-10-20T10:00:00Z",
        }, metrics_file=str(metrics_file))

        # 2. Simulate import event
        record_workflow_event("vendor_checklist_imported", {
            "distribution_id": dist_id,
            "file_path": "checklist.csv",
        }, metrics_file=str(metrics_file))

        # 3. Record remediation completed (T4)
        t4_ts = "2026-10-22T15:00:00Z"
        res = record_remediation_completed(
            distribution_id=dist_id,
            remediated_at=t4_ts,
            note="Deploy commit abcdef1",
            metrics_file=str(metrics_file),
        )

        self.assertEqual(res["remediated_at"], t4_ts)
        self.assertEqual(res["status"], "remediated")
        self.assertEqual(res["remediation_note"], "Deploy commit abcdef1")

        # 4. Verify disk content directly
        disk_data = json.loads(metrics_file.read_text(encoding="utf-8"))
        saved_entry = disk_data["distributions"][dist_id]
        self.assertEqual(saved_entry["remediated_at"], t4_ts)
        self.assertEqual(saved_entry["status"], "remediated")
        self.assertEqual(saved_entry["remediation_note"], "Deploy commit abcdef1")
        self.assertIsNotNone(saved_entry.get("total_lead_time_hours"))


if __name__ == "__main__":
    unittest.main()
