import tempfile
import unittest
from pathlib import Path

from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport
from triage_agent.verifier import is_test_path, verify_codebase


class TestAstAndTestSeparation(unittest.TestCase):
    def test_is_test_path(self):
        self.assertTrue(is_test_path("test/unit/auth_test.js"))
        self.assertTrue(is_test_path("tests/test_server.py"))
        self.assertTrue(is_test_path("src/__tests__/login.test.ts"))
        self.assertTrue(is_test_path("spec/controllers/auth_spec.rb"))
        self.assertTrue(is_test_path("mocks/api_mock.py"))
        self.assertFalse(is_test_path("src/controllers/auth.py"))
        self.assertFalse(is_test_path("server.js"))
        self.assertFalse(is_test_path("app/main.py"))

    def test_python_ast_ignores_comments_and_docstrings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            # Create a Python file where jwt.verify only appears in a docstring or comment
            py_file = tmppath / "service.py"
            py_file.write_text(
                '"""\nHere is an example:\njwt.verify(token, "secret")\n"""\n'
                "# Another comment mentioning jwt.verify\n"
                "def hello():\n"
                "    return 'ok'\n",
                encoding="utf-8",
            )

            report = TriageReport(
                report_title="Test",
                report_version="1.0",
                notices=[
                    TriageNotice(
                        product_name="jsonwebtoken",
                        notice_hash="abc",
                        announcement_date="2026-10-25",
                        conclusion="Check",
                        fixed_versions="9.0.0",
                        severity_note="High",
                        check_points=[
                            CheckPointItem(
                                check_point_id="cp1",
                                target_or_cve="CVE-2026-0001",
                                cvss="7.5",
                                content_summary="JWT check",
                                affected_versions="< 9.0.0",
                                check_point_yes_no="jwt.verify を利用しているか",
                                verification_method="コードベースで jwt.verify を検索",
                            )
                        ],
                    )
                ],
            )

            res = verify_codebase(report, str(tmppath))
            # AST should correctly identify 0 actual call sites!
            cp_res = res.notice_results[0].results[0]
            self.assertEqual(len(cp_res.matches), 0)
            self.assertEqual(cp_res.status, "コード内未検出 (外部設定・既定値の要確認)")

    def test_distinguishes_prod_vs_test_matches(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)
            # Create test-only file
            test_dir = tmppath / "tests"
            test_dir.mkdir()
            (test_dir / "auth.test.js").write_text(
                'const jwt = require("jsonwebtoken");\njwt.verify(mockToken, "test-secret");\n',
                encoding="utf-8",
            )

            report = TriageReport(
                report_title="Test",
                report_version="1.0",
                notices=[
                    TriageNotice(
                        product_name="jsonwebtoken",
                        notice_hash="abc",
                        announcement_date="2026-10-25",
                        conclusion="Check",
                        fixed_versions="9.0.0",
                        severity_note="High",
                        check_points=[
                            CheckPointItem(
                                check_point_id="cp1",
                                target_or_cve="CVE-2026-0001",
                                cvss="7.5",
                                content_summary="JWT check",
                                affected_versions="< 9.0.0",
                                check_point_yes_no="jwt.verify を利用しているか",
                                verification_method="コードベースで jwt.verify を検索",
                            )
                        ],
                    )
                ],
            )

            # Case A: Only in tests
            res_test = verify_codebase(report, str(tmppath))
            cp_test = res_test.notice_results[0].results[0]
            self.assertEqual(len(cp_test.matches), 1)
            self.assertTrue(cp_test.matches[0].is_test)
            self.assertEqual(cp_test.status, "YES (テストコード内のみ検出・本番未検出)")

            # Case B: Add production file
            (tmppath / "server.js").write_text(
                'const jwt = require("jsonwebtoken");\njwt.verify(realToken, "prod-secret");\n',
                encoding="utf-8",
            )
            res_prod = verify_codebase(report, str(tmppath))
            cp_prod = res_prod.notice_results[0].results[0]
            self.assertEqual(len(cp_prod.matches), 2)
            self.assertEqual(cp_prod.status, "YES (本番コード内検出・要実地確認)")


if __name__ == "__main__":
    unittest.main()
