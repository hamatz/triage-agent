import json
import shutil
import tempfile
import unittest
from pathlib import Path

from triage_agent.schemas import TriageReport, TriageNotice, CheckPointItem
from triage_agent.verifier import verify_codebase

class TestAdversarialCodeDrift(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())
        self.report = TriageReport(
            report_title="Adversarial Test Report",
            report_version="1.0",
            is_dry_run=True,
            notices=[
                TriageNotice(
                    product_name="jsonwebtoken",
                    announcement_date="2026-10-25",
                    conclusion="Algorithm confusion",
                    fixed_versions="9.0.0",
                    severity_note="High",
                    pre_check_note="Test note",
                    check_points=[
                        CheckPointItem(
                            check_point_id="jwt-cp1",
                            target_or_cve="CVE-2022-23529",
                            cvss="7.5 (High)",
                            content_summary="Verify call",
                            affected_versions="< 9.0.0",
                            check_point_yes_no="jwt.verify を呼び出しているか",
                            verification_method="search jwt.verify",
                        )
                    ]
                )
            ]
        )

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_case2_multiline_call_drift(self):
        """Case 2: Deleting algorithms on subsequent line must trigger drift invalidation."""
        # Initial multi-line safe code
        app_file = self.tmp_dir / "server.js"
        app_file.write_text(
            "const jwt = require('jsonwebtoken');\n"
            "jwt.verify(token, key, {\n"
            "  algorithms: ['RS256']\n"
            "});\n",
            encoding="utf-8"
        )

        # Baseline scan to obtain matches_hash
        init_res = verify_codebase(self.report, str(self.tmp_dir), None)
        orig_hash = init_res.notice_results[0].results[0].matches_hash

        # Audit file recording orig_hash
        audit_file = self.tmp_dir / "audit.json"
        audit_file.write_text(json.dumps({
            "attestations": [{
                "check_point_id": "jwt-cp1",
                "matches_hash": orig_hash,
                "status": "NO (手動確認済み・非該当)",
                "reviewer": "Alice",
                "date": "2026-10-25",
                "evidence": "Multi-line options verified."
            }]
        }), encoding="utf-8")

        # Verify initial sign-off works
        res1 = verify_codebase(self.report, str(self.tmp_dir), str(audit_file))
        self.assertTrue(res1.notice_results[0].results[0].status.startswith("NO"))

        # Adversarial change: remove 'algorithms' from line 3!
        app_file.write_text(
            "const jwt = require('jsonwebtoken');\n"
            "jwt.verify(token, key, {\n"
            "});\n",
            encoding="utf-8"
        )

        res2 = verify_codebase(self.report, str(self.tmp_dir), str(audit_file))
        cp_res2 = res2.notice_results[0].results[0]
        # Must detect drift!
        self.assertTrue(cp_res2.status.startswith("要再確認"))
        self.assertIn("コード変更検知", cp_res2.status)

    def test_case3_long_line_drift_beyond_120_chars(self):
        """Case 3: Deleting algorithms beyond 120th character on a single line must trigger drift."""
        padding = " " * 130
        app_file = self.tmp_dir / "server.js"
        app_file.write_text(
            f"jwt.verify(token, key, /* {padding} */ {{ algorithms: ['RS256'] }});\n",
            encoding="utf-8"
        )

        init_res = verify_codebase(self.report, str(self.tmp_dir), None)
        orig_hash = init_res.notice_results[0].results[0].matches_hash

        audit_file = self.tmp_dir / "audit.json"
        audit_file.write_text(json.dumps({
            "attestations": [{
                "check_point_id": "jwt-cp1",
                "matches_hash": orig_hash,
                "status": "NO (手動確認済み・非該当)",
                "reviewer": "Bob",
                "date": "2026-10-25",
                "evidence": "Long line options verified."
            }]
        }), encoding="utf-8")

        # Initial verified
        res1 = verify_codebase(self.report, str(self.tmp_dir), str(audit_file))
        self.assertTrue(res1.notice_results[0].results[0].status.startswith("NO"))

        # Adversarial change: remove algorithms beyond 120th char!
        app_file.write_text(
            f"jwt.verify(token, key, /* {padding} */ {{ }});\n",
            encoding="utf-8"
        )

        res2 = verify_codebase(self.report, str(self.tmp_dir), str(audit_file))
        cp_res2 = res2.notice_results[0].results[0]
        self.assertTrue(cp_res2.status.startswith("要再確認"))
        self.assertIn("コード変更検知", cp_res2.status)

    def test_case4_more_than_5_matches_in_subfolders(self):
        """Case 4: When 5 matches exist in root, adding a 6th match in subfolder must trigger drift."""
        # Create 5 matches in root
        app_file = self.tmp_dir / "server.js"
        app_file.write_text(
            "\n".join([f"jwt.verify(token{i}, key, {{ algorithms: ['RS256'] }});" for i in range(5)]),
            encoding="utf-8"
        )

        init_res = verify_codebase(self.report, str(self.tmp_dir), None)
        orig_hash = init_res.notice_results[0].results[0].matches_hash

        audit_file = self.tmp_dir / "audit.json"
        audit_file.write_text(json.dumps({
            "attestations": [{
                "check_point_id": "jwt-cp1",
                "matches_hash": orig_hash,
                "status": "NO (手動確認済み・非該当)",
                "reviewer": "Charlie",
                "date": "2026-10-25",
                "evidence": "All 5 matches verified."
            }]
        }), encoding="utf-8")

        res1 = verify_codebase(self.report, str(self.tmp_dir), str(audit_file))
        self.assertTrue(res1.notice_results[0].results[0].status.startswith("NO"))

        # Adversarial change: Add 6th dangerous match in a deep subfolder!
        sub_dir = self.tmp_dir / "src" / "api" / "v2"
        sub_dir.mkdir(parents=True)
        sub_file = sub_dir / "auth.js"
        sub_file.write_text("jwt.verify(badToken, badKey);\n", encoding="utf-8")

        res2 = verify_codebase(self.report, str(self.tmp_dir), str(audit_file))
        cp_res2 = res2.notice_results[0].results[0]
        self.assertTrue(cp_res2.status.startswith("要再確認"))
        self.assertIn("コード変更検知", cp_res2.status)
        self.assertEqual(len(cp_res2.matches), 6)

if __name__ == "__main__":
    unittest.main()
