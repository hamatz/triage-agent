"""Automated regression and benchmark suite test for Verifier engine (Pillar 4 / ADR-019)."""

import json
import unittest
from pathlib import Path
from triage_agent.verifier.engine import verify_codebase
from triage_agent.verifier.models import CodebaseAuditReport, CheckVerificationResult
from triage_agent.schemas import TriageReport, TriageNotice, CheckPointItem

def _find_benchmark_dir() -> Path:
    # 1. Standard tests directory inside repository: tests/ -> root / benchmark
    p1 = Path(__file__).resolve().parent.parent / "benchmark"
    if p1.exists():
        return p1
    # 2. Inside scratch directory: scratch/ -> conversation / brain / ... / benchmark
    p2 = Path(__file__).resolve().parent.parent.parent.parent / "benchmark"
    if p2.exists():
        return p2
    # 3. Current working directory fallback
    cwd_benchmark = Path.cwd() / "benchmark"
    if cwd_benchmark.exists():
        return cwd_benchmark
    raise FileNotFoundError("Could not find 'benchmark' directory in repository tree.")

BENCHMARK_DIR = _find_benchmark_dir()


class TestBenchmarkSuite(unittest.TestCase):
    """Test the benchmark ground truth cases against the Verifier engine."""

    @classmethod
    def setUpClass(cls):
        manifest_path = BENCHMARK_DIR / "manifest.json"
        with open(manifest_path, "r", encoding="utf-8") as f:
            cls.manifest = json.load(f)

    def test_benchmark_manifest_structure(self):
        """Manifest must contain required cases with valid fields."""
        self.assertIn("cases", self.manifest)
        self.assertGreaterEqual(len(self.manifest["cases"]), 4)
        for case in self.manifest["cases"]:
            self.assertIn("id", case)
            self.assertIn("target_dir", case)
            self.assertIn("expected", case)

    def test_benchmark_runner_full_suite(self):
        """Benchmark runner module must execute cleanly with 100% accuracy and produce headline summary."""
        from triage_agent.benchmark import run_benchmark_suite
        summary = run_benchmark_suite(benchmark_dir=BENCHMARK_DIR)
        self.assertEqual(summary["failed_cases"], 0)
        self.assertEqual(summary["accuracy_rate"], 100.0)
        self.assertGreaterEqual(summary["total_cases"], 17)
        self.assertIn("陽性", summary["headline"])
        self.assertIn("陰性", summary["headline"])

    def test_case_node_jwt(self):
        """Node.js jsonwebtoken case: calls in src/ must trigger YES, tests/ ignored."""
        case = next(c for c in self.manifest["cases"] if c["id"] == "node_jwt_insecure_verify")
        code_dir = BENCHMARK_DIR / case["target_dir"]

        dummy_report = TriageReport(
            report_title="Benchmark JWT Test",
            scan_target="test-node-jwt",
            total_dependencies=2,
            notices=[
                TriageNotice(
                    product_name="jsonwebtoken",
                    component_name="jsonwebtoken",
                    announcement_date="2026-10-25",
                    conclusion="Algorithm confusion vulnerability. Check if algorithms are specified.",
                    fixed_versions="9.0.0",
                    severity_note="Critical (CVSS 9.8)",
                    check_points=[
                        CheckPointItem(
                            target_or_cve="CVE-2022-23529 (CVSS 9.8 Critical)",
                            cvss="9.8 (Critical)",
                            content_summary="Algorithm confusion vulnerability in jwt.verify",
                            affected_versions="<= 8.5.1",
                            check_point_yes_no="verify 呼び出しで algorithms が制限されているか",
                            verification_method="`jwt.verify` の呼び出し箇所で第三引数 options.algorithms が指定されているか確認",
                        )
                    ],
                )
            ],
        )

        res = verify_codebase(dummy_report, code_dir_path=str(code_dir), audit_file_path=None)
        self.assertEqual(len(res.notice_results), 1)
        notice_res = res.notice_results[0]
        self.assertEqual(len(notice_res.results), 1)
        cp_res = notice_res.results[0]

        # In current scanner, `verify` or `jwt.verify` matches src/auth.js
        self.assertIn("YES", cp_res.status)
        self.assertIn("本番コード内検出", cp_res.status)
        # Check that match includes src/auth.js and not tests/auth.test.js as primary prod match
        prod_matches = [m for m in cp_res.matches if not m.is_test]
        test_matches = [m for m in cp_res.matches if m.is_test]
        self.assertTrue(any("src/auth.js" in m.file_path for m in prod_matches))
        self.assertTrue(any("tests/auth.test.js" in m.file_path for m in test_matches))

    def test_case_tomcat_ajp(self):
        """Tomcat AJP case: server.xml has active AJP/1.3 connector, should detect YES."""
        case = next(c for c in self.manifest["cases"] if c["id"] == "tomcat_ajp_ghostcat")
        code_dir = BENCHMARK_DIR / case["target_dir"]

        dummy_report = TriageReport(
            report_title="Benchmark Tomcat Test",
            scan_target="test-tomcat",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="Apache Tomcat",
                    component_name="tomcat-catalina",
                    announcement_date="2020-02-20",
                    conclusion="AJP connector vulnerability (Ghostcat). Check if AJP connector is enabled.",
                    fixed_versions="9.0.31, 8.5.51",
                    severity_note="Critical (CVSS 9.8)",
                    check_points=[
                        CheckPointItem(
                            target_or_cve="CVE-2020-1938 (CVSS 9.8 Critical)",
                            cvss="9.8 (Critical)",
                            content_summary="Ghostcat vulnerability via unauthenticated AJP protocol access",
                            affected_versions="< 9.0.31",
                            check_point_yes_no="AJP コネクタを有効にしているか",
                            verification_method="`server.xml` で `<Connector protocol=\"AJP/1.3\"` が有効か確認",
                        )
                    ],
                )
            ],
        )

        res = verify_codebase(dummy_report, code_dir_path=str(code_dir))
        self.assertEqual(len(res.notice_results), 1)
        cp_res = res.notice_results[0].results[0]
        self.assertIn("YES", cp_res.status)
        self.assertTrue(any("conf/server.xml" in m.file_path for m in cp_res.matches))

    def test_case_php_session(self):
        """PHP session case: php.ini has session.upload_progress.enabled = On."""
        case = next(c for c in self.manifest["cases"] if c["id"] == "php_session_upload_progress")
        code_dir = BENCHMARK_DIR / case["target_dir"]

        dummy_report = TriageReport(
            report_title="Benchmark PHP Test",
            scan_target="test-php",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="PHP",
                    component_name="php",
                    announcement_date="2019-10-24",
                    conclusion="Session upload progress remote code execution.",
                    fixed_versions="7.3.11, 7.2.24",
                    severity_note="High (CVSS 8.1)",
                    check_points=[
                        CheckPointItem(
                            target_or_cve="CVE-2019-11043 (CVSS 8.1 High)",
                            cvss="8.1 (High)",
                            content_summary="PHP-FPM remote code execution via session upload progress",
                            affected_versions="< 7.3.11",
                            check_point_yes_no="session.upload_progress.enabled が有効か",
                            verification_method="`php.ini` の `session.upload_progress.enabled` を確認",
                        )
                    ],
                )
            ],
        )

        res = verify_codebase(dummy_report, code_dir_path=str(code_dir))
        self.assertEqual(len(res.notice_results), 1)
        cp_res = res.notice_results[0].results[0]
        self.assertIn("YES", cp_res.status)
        self.assertTrue(any("conf/php.ini" in m.file_path for m in cp_res.matches))

    def test_case_http2_shell(self):
        """HTTP/2 case: nginx.conf has http2 on."""
        case = next(c for c in self.manifest["cases"] if c["id"] == "http2_shell_rapid_reset")
        code_dir = BENCHMARK_DIR / case["target_dir"]

        dummy_report = TriageReport(
            report_title="Benchmark Nginx HTTP2 Test",
            scan_target="test-nginx",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="nginx",
                    component_name="nginx",
                    announcement_date="2023-10-10",
                    conclusion="HTTP/2 Rapid Reset attack.",
                    fixed_versions="1.25.3",
                    severity_note="High (CVSS 7.5)",
                    check_points=[
                        CheckPointItem(
                            target_or_cve="CVE-2023-44487 (CVSS 7.5 High)",
                            cvss="7.5 (High)",
                            content_summary="DDoS via HTTP/2 stream reset frames",
                            affected_versions="all with HTTP/2 enabled",
                            check_point_yes_no="HTTP/2 を有効にしているか",
                            verification_method="`nginx.conf` で `http2 on;` または `listen ... http2;` を確認",
                        )
                    ],
                )
            ],
        )

        res = verify_codebase(dummy_report, code_dir_path=str(code_dir))
        self.assertEqual(len(res.notice_results), 1)
        cp_res = res.notice_results[0].results[0]
        self.assertIn("YES", cp_res.status)
        self.assertTrue(any("conf/nginx.conf" in m.file_path for m in cp_res.matches))

    def test_negative_cases_must_not_report_yes(self):
        """Negative (safe/disabled) fixtures must not be falsely flagged as YES."""
        # 1. Negative Tomcat AJP (commented out)
        safe_tomcat_dir = BENCHMARK_DIR / "cases_negative/tomcat_ajp_safe"
        tomcat_report = TriageReport(
            report_title="Benchmark Tomcat Test",
            scan_target="test-tomcat-safe",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="Apache Tomcat",
                    component_name="tomcat-catalina",
                    announcement_date="2020-02-20",
                    conclusion="AJP connector check.",
                    fixed_versions="9.0.31",
                    severity_note="Critical (CVSS 9.8)",
                    check_points=[
                        CheckPointItem(
                            target_or_cve="CVE-2020-1938",
                            cvss="9.8",
                            content_summary="Ghostcat AJP check",
                            affected_versions="< 9.0.31",
                            check_point_yes_no="AJP コネクタを有効にしているか",
                            verification_method="`server.xml` で `<Connector protocol=\"AJP/1.3\"` が有効か確認",
                        )
                    ],
                )
            ],
        )
        res_tomcat = verify_codebase(tomcat_report, code_dir_path=str(safe_tomcat_dir))
        cp_tomcat = res_tomcat.notice_results[0].results[0]
        # Should NOT be YES!
        self.assertNotIn("YES", cp_tomcat.status, f"Commented-out AJP was wrongly flagged as YES: {cp_tomcat.reasoning}")

        # 2. Negative PHP session (disabled: session.upload_progress.enabled = Off)
        safe_php_dir = BENCHMARK_DIR / "cases_negative/php_session_safe"
        php_report = TriageReport(
            report_title="Benchmark PHP Test",
            scan_target="test-php-safe",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="PHP",
                    component_name="php",
                    announcement_date="2019-10-24",
                    conclusion="Session upload progress check.",
                    fixed_versions="7.3.11",
                    severity_note="High",
                    check_points=[
                        CheckPointItem(
                            target_or_cve="CVE-2019-11043",
                            cvss="8.1",
                            content_summary="Session upload progress",
                            affected_versions="< 7.3.11",
                            check_point_yes_no="session.upload_progress.enabled が有効か",
                            verification_method="`php.ini` の `session.upload_progress.enabled` を確認",
                        )
                    ],
                )
            ],
        )
        res_php = verify_codebase(php_report, code_dir_path=str(safe_php_dir))
        cp_php = res_php.notice_results[0].results[0]
        # Should NOT be YES!
        self.assertNotIn("YES", cp_php.status, f"Disabled session.upload_progress was wrongly flagged as YES: {cp_php.reasoning}")

        # 3. Negative Nginx HTTP/2 (disabled: http2 off; # http2 on;)
        safe_nginx_dir = BENCHMARK_DIR / "cases_negative/http2_safe"
        nginx_report = TriageReport(
            report_title="Benchmark Nginx HTTP2 Test",
            scan_target="test-nginx-safe",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="nginx",
                    component_name="nginx",
                    announcement_date="2023-10-10",
                    conclusion="HTTP/2 check.",
                    fixed_versions="1.25.3",
                    severity_note="High",
                    check_points=[
                        CheckPointItem(
                            target_or_cve="CVE-2023-44487",
                            cvss="7.5",
                            content_summary="HTTP/2 check",
                            affected_versions="all",
                            check_point_yes_no="HTTP/2 を有効にしているか",
                            verification_method="`nginx.conf` で `http2 on;` または `listen ... http2;` を確認",
                        )
                    ],
                )
            ],
        )
        res_nginx = verify_codebase(nginx_report, code_dir_path=str(safe_nginx_dir))
        cp_nginx = res_nginx.notice_results[0].results[0]
        # Should NOT be YES!
        self.assertNotIn("YES", cp_nginx.status, f"Disabled http2 was wrongly flagged as YES: {cp_nginx.reasoning}")


if __name__ == "__main__":
    unittest.main()
