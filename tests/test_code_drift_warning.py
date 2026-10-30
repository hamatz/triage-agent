import json
import unittest
from pathlib import Path
from triage_agent.schemas import TriageReport, TriageNotice, CheckPointItem
from triage_agent.verifier import verify_codebase, compute_matches_hash

class TestCodeDriftWarning(unittest.TestCase):
    def setUp(self):
        self.report = TriageReport(
            report_title="Drift Test Report",
            report_version="1.0",
            is_dry_run=True,
            notices=[
                TriageNotice(
                    product_name="jsonwebtoken",
                    announcement_date="2026-10-25",
                    conclusion="Algorithm confusion vulnerability",
                    fixed_versions="9.0.0",
                    severity_note="High",
                    pre_check_note="Test note",
                    check_points=[
                        CheckPointItem(
                            check_point_id="jwt-cp1",
                            target_or_cve="CVE-2022-23529 (CVSS: 7.5 High)",
                            cvss="7.5 (High)",
                            content_summary="Insecure verify call",
                            affected_versions="< 9.0.0",
                            check_point_yes_no="jwt.verify をアルゴリズム未指定で呼び出しているか",
                            verification_method="コード内で jwt.verify を検索し、algorithms 引数があるか確認",
                        )
                    ]
                )
            ]
        )

    def test_signed_off_no_without_matches_hash_flags_unverified(self):
        """Ensure sign-off without hash flags '要再確認' (Point 1: never starts with NO)."""
        audit_file = Path("test_drift_audit_1.json")
        try:
            audit_file.write_text(json.dumps({
                "attestations": [
                    {
                        "check_point_id": "jwt-cp1",
                        "status": "NO (手動確認済み・非該当)",
                        "reviewer": "Security Team",
                        "date": "2026-10-25",
                        "evidence": "Past review claimed safe."
                    }
                ]
            }), encoding="utf-8")

            res = verify_codebase(self.report, "demo_app", str(audit_file))
            cp_result = res.notice_results[0].results[0]

            self.assertGreater(len(cp_result.matches), 0)
            # Point 1: Must start with 要再確認, NEVER with NO
            self.assertTrue(cp_result.status.startswith("要再確認"))
            self.assertFalse(cp_result.status.startswith("NO"))
            self.assertIn("コード該当あり⚠️", cp_result.status)

            self.assertEqual(res.summary_counts["unverified_count"], 1)
            self.assertEqual(res.summary_counts["safe_count"], 0)

        finally:
            if audit_file.exists():
                audit_file.unlink()

    def test_matches_hash_allows_false_positive_signoff(self):
        """Ensure matching matches_hash accepts false positive sign-off as safe NO (Point 2)."""
        # First scan without audit to get current matches_hash
        init_res = verify_codebase(self.report, "demo_app", None)
        curr_hash = init_res.notice_results[0].results[0].matches_hash
        self.assertIsNotNone(curr_hash)

        audit_file = Path("test_drift_audit_2.json")
        try:
            audit_file.write_text(json.dumps({
                "attestations": [
                    {
                        "check_point_id": "jwt-cp1",
                        "matches_hash": curr_hash,
                        "status": "NO (手動確認済み・非該当)",
                        "reviewer": "Lead Architect",
                        "date": "2026-10-25",
                        "evidence": "Inspected server.js: algorithm RS256 is explicitly passed."
                    }
                ]
            }), encoding="utf-8")

            res = verify_codebase(self.report, "demo_app", str(audit_file))
            cp_result = res.notice_results[0].results[0]

            # Matching hash recognizes the inspected false positive -> NO (safe)
            self.assertTrue(cp_result.status.startswith("NO"))
            self.assertIn("コード確認済み", cp_result.status)
            self.assertEqual(res.summary_counts["safe_count"], 1)
            self.assertEqual(res.summary_counts["unverified_count"], 0)

        finally:
            if audit_file.exists():
                audit_file.unlink()

    def test_matches_hash_invalidates_when_code_changes(self):
        """Ensure mismatched matches_hash (code altered) automatically invalidates sign-off (Point 2)."""
        audit_file = Path("test_drift_audit_3.json")
        try:
            audit_file.write_text(json.dumps({
                "attestations": [
                    {
                        "check_point_id": "jwt-cp1",
                        "matches_hash": "outdated1234",  # Different hash
                        "status": "NO (手動確認済み・非該当)",
                        "reviewer": "Old Reviewer",
                        "date": "2026-01-01",
                        "evidence": "Old evidence before code change."
                    }
                ]
            }), encoding="utf-8")

            res = verify_codebase(self.report, "demo_app", str(audit_file))
            cp_result = res.notice_results[0].results[0]

            # Mismatched hash triggers code drift warning
            self.assertTrue(cp_result.status.startswith("要再確認"))
            self.assertFalse(cp_result.status.startswith("NO"))
            self.assertIn("コード変更検知", cp_result.status)
            self.assertEqual(res.summary_counts["unverified_count"], 1)
            self.assertEqual(res.summary_counts["safe_count"], 0)

        finally:
            if audit_file.exists():
                audit_file.unlink()

if __name__ == "__main__":
    unittest.main()
