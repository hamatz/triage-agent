import json
import tempfile
import unittest
from pathlib import Path

from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport
from triage_agent.verifier import verify_codebase


class TestAttestationSafety(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        # Construct a dummy report with similar CVE numbers and version 1.0
        self.report = TriageReport(
            report_title="Test Report",
            report_version="1.0",
            is_dry_run=True,
            notices=[
                TriageNotice(
                    product_name="test-product",
                    announcement_date="2026-10-25",
                    conclusion="Test conclusion",
                    fixed_versions="2.0.0",
                    severity_note="High",
                    pre_check_note="Test note",
                    check_points=[
                        # Target CVE
                        CheckPointItem(
                            check_point_id="test-cve-11149-cp1",
                            target_or_cve="CVE-2026-11149 (CVSS: 7.5 High)",
                            cvss="7.5 (High)",
                            content_summary="Original CVE",
                            affected_versions="< 1.0",
                            check_point_yes_no="設定Aを有効にしているか",
                            verification_method="search pattern A",
                        ),
                        # Longer CVE with prefix matching
                        CheckPointItem(
                            check_point_id="test-cve-111497-cp1",
                            target_or_cve="CVE-2026-111497 (CVSS: 9.8 Critical)",
                            cvss="9.8 (Critical)",
                            content_summary="Different longer CVE",
                            affected_versions="< 1.0",
                            check_point_yes_no="設定Bを有効にしているか",
                            verification_method="search pattern B",
                        ),
                    ]
                )
            ]
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_prefix_cve_isolation(self):
        """Partial match should NOT match CVE-2026-111497 when signoff is for CVE-2026-11149."""
        audit_data_1 = {
            "attestations": [
                {
                    "cve_id": "CVE-2026-11149",
                    "check_point_yes_no": "設定Aを有効にしているか",
                    "report_version": "1.0",
                    "status": "NO (手動確認済み・非該当)",
                    "reviewer": "Alice",
                    "date": "2026-10-25",
                    "evidence": "Config verified safe."
                }
            ]
        }
        f1 = self.tmppath / "test_audit_1.json"
        f1.write_text(json.dumps(audit_data_1), encoding="utf-8")

        res1 = verify_codebase(self.report, "demo_app", str(f1))
        results1 = res1.notice_results[0].results
        self.assertEqual(results1[0].status, "NO (手動確認済み・非該当)", "CP1 should match")
        self.assertTrue(
            "未検出" in results1[1].status or "要手動確認" in results1[1].status,
            "CP2 must NOT match CVE-2026-11149!"
        )

    def test_mismatched_report_version_invalidation(self):
        """Mismatched report_version should be invalidated."""
        audit_data_2 = {
            "attestations": [
                {
                    "check_point_id": "test-cve-11149-cp1",
                    "report_version": "2.0",  # Mismatch! Report is 1.0
                    "status": "NO (手動確認済み・非該当)",
                    "reviewer": "Bob",
                    "date": "2026-10-25",
                    "evidence": "Outdated sign-off."
                }
            ]
        }
        f2 = self.tmppath / "test_audit_2.json"
        f2.write_text(json.dumps(audit_data_2), encoding="utf-8")

        res2 = verify_codebase(self.report, "demo_app", str(f2))
        results2 = res2.notice_results[0].results
        self.assertTrue(
            "未検出" in results2[0].status or "要手動確認" in results2[0].status,
            "Mismatched version must not be accepted as safe!"
        )

    def test_yes_signoff_not_counted_as_safe(self):
        """Sign-off with status YES should NOT count as safe."""
        audit_data_3 = {
            "attestations": [
                {
                    "check_point_id": "test-cve-11149-cp1",
                    "report_version": "1.0",
                    "status": "YES (該当している)",
                    "reviewer": "Charlie",
                    "date": "2026-10-25",
                    "evidence": "Found in production environment."
                }
            ]
        }
        f3 = self.tmppath / "test_audit_3.json"
        f3.write_text(json.dumps(audit_data_3), encoding="utf-8")

        res3 = verify_codebase(self.report, "demo_app", str(f3))
        self.assertEqual(res3.summary_counts["safe_count"], 0, "status YES must not be safe_count")
        self.assertTrue(res3.overall_status.startswith("YES"), "overall_status must be YES")


if __name__ == "__main__":
    unittest.main()
