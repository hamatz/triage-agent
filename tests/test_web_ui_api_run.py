import unittest
import json
from io import BytesIO
from triage_agent.web_ui import TriageDashboardHandler, SERVER_CSRF_TOKEN

class TestWebUiApiRun(unittest.TestCase):
    def test_mock_api_run_demo(self):
        class MockServer:
            server_port = 8080

        class DummyHandler(TriageDashboardHandler):
            def __init__(self, path, body, headers=None):
                self.path = path
                self.rfile = BytesIO(body)
                self.wfile = BytesIO()
                self.headers = dict(headers or {})
                self.headers["Content-Length"] = str(len(body))
                self.server = MockServer()
                self._headers_sent = []
                self.status_code = None

            def send_response(self, code, message=None):
                self.status_code = code

            def send_header(self, keyword, value):
                self._headers_sent.append((keyword, value))

            def end_headers(self):
                pass

        payload = json.dumps({
            "mode": "demo",
            "sbom": "sample_sbom.json",
            "code_dir": "demo_app",
            "audit_file": "sample_audit_signoff.json"
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:8080",
            "Host": "127.0.0.1:8080",
            "X-CSRF-Token": SERVER_CSRF_TOKEN,
        }

        handler = DummyHandler("/api/run", payload, headers=headers)
        handler.do_POST()
        self.assertEqual(handler.status_code, 200)
        res_data = json.loads(handler.wfile.getvalue().decode("utf-8"))
        self.assertIn("report", res_data)
        self.assertIn("audit", res_data)
        self.assertGreater(len(res_data["report"]["notices"]), 0)

    def test_save_and_load_report(self):
        class MockServer:
            server_port = 8080

        class DummyHandler(TriageDashboardHandler):
            def __init__(self, path, body, headers=None):
                self.path = path
                self.rfile = BytesIO(body)
                self.wfile = BytesIO()
                self.headers = dict(headers or {})
                self.headers["Content-Length"] = str(len(body))
                self.server = MockServer()
                self._headers_sent = []
                self.status_code = None

            def send_response(self, code, message=None):
                self.status_code = code

            def send_header(self, keyword, value):
                self._headers_sent.append((keyword, value))

            def end_headers(self):
                pass

        # 1. Run demo first to get sample report & audit
        run_payload = json.dumps({"mode": "demo"}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:8080",
            "Host": "127.0.0.1:8080",
            "X-CSRF-Token": SERVER_CSRF_TOKEN,
        }
        h_run = DummyHandler("/api/run", run_payload, headers=headers)
        h_run.do_POST()
        run_res = json.loads(h_run.wfile.getvalue().decode("utf-8"))
        report_data = run_res["report"]
        audit_data = run_res["audit"]

        # 2. Test /api/save-report
        tmp_md = "test_output_report.md"
        tmp_json = "test_output_report.json"
        tmp_audit = "test_output_audit.md"
        save_payload = json.dumps({
            "report": report_data,
            "audit": audit_data,
            "output_md": tmp_md,
            "output_json": tmp_json,
            "verify_output": tmp_audit,
        }).encode("utf-8")

        h_save = DummyHandler("/api/save-report", save_payload, headers=headers)
        h_save.do_POST()
        self.assertEqual(h_save.status_code, 200)
        save_res = json.loads(h_save.wfile.getvalue().decode("utf-8"))
        self.assertTrue(save_res["success"])
        self.assertTrue(any(tmp_md in f for f in save_res["saved_files"]))
        self.assertTrue(any(tmp_json in f for f in save_res["saved_files"]))
        self.assertIn("md_content", save_res)
        self.assertIn("audit_content", save_res)

        # 3. Test /api/load-report
        load_payload = json.dumps({
            "report_path": tmp_json,
            "code_dir": "demo_app",
            "audit_file": "sample_audit_signoff.json"
        }).encode("utf-8")

        h_load = DummyHandler("/api/load-report", load_payload, headers=headers)
        h_load.do_POST()
        self.assertEqual(h_load.status_code, 200)
        load_res = json.loads(h_load.wfile.getvalue().decode("utf-8"))
        self.assertTrue(load_res["success"])
        self.assertIn("report", load_res)
        self.assertEqual(len(load_res["report"]["notices"]), len(report_data["notices"]))
        self.assertIn("audit", load_res)

        # 4. Test security protections: arbitrary source code overwrite attempt must fail
        malicious_payload = json.dumps({
            "report": report_data,
            "output_md": "src/triage_agent/__init__.py",
        }).encode("utf-8")
        h_malicious = DummyHandler("/api/save-report", malicious_payload, headers=headers)
        h_malicious.do_POST()
        self.assertEqual(h_malicious.status_code, 500)
        mal_res = json.loads(h_malicious.wfile.getvalue().decode("utf-8"))
        self.assertFalse(mal_res["success"])
        self.assertIn("許可されていない拡張子", mal_res["error"])

        # Cleanup generated test files
        import os
        from pathlib import Path
        for f in (tmp_md, tmp_json, tmp_audit):
            if os.path.exists(f):
                os.remove(f)
            out_f = Path("triage-output") / f
            if out_f.exists():
                out_f.unlink()

    def test_get_routing_with_query_params(self):
        class MockServer:
            server_port = 8080

        class DummyHandler(TriageDashboardHandler):
            def __init__(self, path, headers=None):
                self.path = path
                self.request_version = "HTTP/1.1"
                self._headers_buffer = []
                self.rfile = BytesIO(b"")
                self.wfile = BytesIO()
                self.headers = dict(headers or {})
                self.server = MockServer()
                self._headers_sent = []
                self.status_code = None

            def send_response(self, code, message=None):
                self.status_code = code

            def send_header(self, keyword, value):
                self._headers_sent.append((keyword, value))

            def end_headers(self):
                pass

        headers = {
            "Host": "127.0.0.1:8080",
        }
        # Standard root
        h1 = DummyHandler("/", headers=headers)
        h1.do_GET()
        self.assertEqual(h1.status_code, 200)

        # Root with query params (e.g. from accidental form submission)
        h2 = DummyHandler("/?mode=demo&sbom=sample_sbom.json", headers=headers)
        h2.do_GET()
        self.assertEqual(h2.status_code, 200)

        # /api/status with query params
        h3 = DummyHandler("/api/status?check=1", headers=headers)
        h3.do_GET()
        self.assertEqual(h3.status_code, 200)

        # Static assets delivery
        h_css = DummyHandler("/static/style.css", headers=headers)
        h_css.do_GET()
        self.assertEqual(h_css.status_code, 200)
        self.assertIn("text/css", dict(h_css._headers_sent).get("Content-Type", ""))
        self.assertIn(b"--accent-gold", h_css.wfile.getvalue())

        h_js = DummyHandler("/static/app.js", headers=headers)
        h_js.do_GET()
        self.assertEqual(h_js.status_code, 200)
        self.assertIn("text/javascript", dict(h_js._headers_sent).get("Content-Type", ""))
        self.assertIn(b"renderReport", h_js.wfile.getvalue())

    def test_meta_tag_csrf_token_injected_in_get(self):
        class MockServer:
            server_port = 8080

        class DummyHandler(TriageDashboardHandler):
            def __init__(self, path, headers=None):
                self.path = path
                self.request_version = "HTTP/1.1"
                self._headers_buffer = []
                self.rfile = BytesIO(b"")
                self.wfile = BytesIO()
                self.headers = dict(headers or {})
                self.server = MockServer()
                self._headers_sent = []
                self.status_code = None

            def send_response(self, code, message=None):
                self.status_code = code

            def send_header(self, keyword, value):
                self._headers_sent.append((keyword, value))

        h = DummyHandler("/", headers={"Host": "127.0.0.1:8080"})
        h.do_GET()
        self.assertEqual(h.status_code, 200)
        html = h.wfile.getvalue().decode("utf-8")
        self.assertIn(f'<meta name="csrf-token" content="{SERVER_CSRF_TOKEN}">', html)
        self.assertNotIn('<script>window.CSRF_TOKEN', html)

    def test_security_headers_present(self):
        class MockServer:
            server_port = 8080

        class DummyHandler(TriageDashboardHandler):
            def __init__(self, path, headers=None):
                self.path = path
                self.request_version = "HTTP/1.1"
                self._headers_buffer = []
                self.rfile = BytesIO(b"")
                self.wfile = BytesIO()
                self.headers = dict(headers or {})
                self.server = MockServer()
                self._headers_sent = []
                self.status_code = None

            def send_response(self, code, message=None):
                self.status_code = code

            def send_header(self, keyword, value):
                self._headers_sent.append((keyword, value))

        h = DummyHandler("/", headers={"Host": "127.0.0.1:8080"})
        h.do_GET()
        header_keys = [k for k, _ in h._headers_sent]
        self.assertIn("Content-Security-Policy", header_keys)
        self.assertIn("X-Content-Type-Options", header_keys)
        self.assertIn("X-Frame-Options", header_keys)

        # Check values
        headers_dict = dict(h._headers_sent)
        self.assertEqual(headers_dict["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers_dict["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", headers_dict["Content-Security-Policy"])
        self.assertIn("frame-ancestors 'none'", headers_dict["Content-Security-Policy"])

    def test_status_endpoint_does_not_contain_csrf_token(self):
        class MockServer:
            server_port = 8080

        class DummyHandler(TriageDashboardHandler):
            def __init__(self, path, headers=None):
                self.path = path
                self.request_version = "HTTP/1.1"
                self._headers_buffer = []
                self.rfile = BytesIO(b"")
                self.wfile = BytesIO()
                self.headers = dict(headers or {})
                self.server = MockServer()
                self._headers_sent = []
                self.status_code = None

            def send_response(self, code, message=None):
                self.status_code = code

            def send_header(self, keyword, value):
                self._headers_sent.append((keyword, value))

        h = DummyHandler("/api/status", headers={"Host": "127.0.0.1:8080"})
        h.do_GET()
        self.assertEqual(h.status_code, 200)
        res_data = json.loads(h.wfile.getvalue().decode("utf-8"))
        self.assertNotIn("csrf_token", res_data, "CSRF token must not be leaked via /api/status")

    def test_api_import_checklist_integration(self):
        class MockServer:
            server_port = 8080

        class DummyHandler(TriageDashboardHandler):
            def __init__(self, path, body, headers=None):
                self.path = path
                self.rfile = BytesIO(body)
                self.wfile = BytesIO()
                self.headers = dict(headers or {})
                self.headers["Content-Length"] = str(len(body))
                self.server = MockServer()
                self._headers_sent = []
                self.status_code = None

            def send_response(self, code, message=None):
                self.status_code = code

            def send_header(self, keyword, value):
                self._headers_sent.append((keyword, value))

            def end_headers(self):
                pass

        from triage_agent.ui.server import resolve_safe_output_path

        audit_filename = "test_e2e_import_signoff.json"
        dest_audit_path = resolve_safe_output_path(audit_filename, allowed_extensions=(".json",))
        if dest_audit_path.exists():
            dest_audit_path.unlink()

        csv_content = (
            "\ufeffDistributionID,No,CheckPointID,対象製品/ライブラリ,CVE/対象識別子,深刻度/CVSS,確認ポイント (Yes/No),確認方法 (設定・コード・コマンド),ベンダー回答 (YES/NO/要確認),確認根拠/設定箇所,確認者 (会社名・氏名),確認日 (YYYY-MM-DD)\n"
            "DIST-20261025-ABCD,1,cp-tomcat-01,Apache Tomcat,CVE-2020-1938,9.8 Critical,AJP コネクタ無効化,server.xml,NO,無効化確認済み,SRE山田,2026-10-25\n"
            "DIST-20261025-ABCD,2,cp-php-02,PHP Runtime,CVE-2026-0002,7.5 High,セッション設定,php.ini,NO,,,2026-10-25\n"
        )

        headers = {
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:8080",
            "Host": "127.0.0.1:8080",
            "X-CSRF-Token": SERVER_CSRF_TOKEN,
        }

        payload = json.dumps({
            "csv_content": csv_content,
            "audit_file": audit_filename,
        }).encode("utf-8")

        handler = DummyHandler("/api/import-checklist", payload, headers=headers)
        handler.do_POST()

        self.assertEqual(handler.status_code, 200)
        res_data = json.loads(handler.wfile.getvalue().decode("utf-8"))
        self.assertTrue(res_data["success"])
        self.assertEqual(res_data["imported_count"], 2)
        # cp-php-02 had NO without reviewer/evidence, so no_held_count must be 1
        self.assertEqual(res_data["no_held_count"], 1)
        self.assertEqual(res_data["distribution_id"], "DIST-20261025-ABCD")

        # Verify output file was created and contains valid JSON
        self.assertTrue(dest_audit_path.exists())
        saved_audit = json.loads(dest_audit_path.read_text(encoding="utf-8"))
        self.assertIn("attestations", saved_audit)
        self.assertEqual(len(saved_audit["attestations"]), 2)

        # Cleanup
        if dest_audit_path.exists():
            dest_audit_path.unlink()

    def test_api_import_checklist_seamless_migration_from_root(self):
        """Opus Review Point 1: When triage-output/ doesn't have the audit file yet,

        importing vendor checklist must load and merge from root workspace audit file,
        preserving internal signoffs without silent data loss.
        """
        class MockServer:
            server_port = 8080

        class DummyHandler(TriageDashboardHandler):
            def __init__(self, path, body, headers=None):
                self.path = path
                self.rfile = BytesIO(body)
                self.wfile = BytesIO()
                self.headers = dict(headers or {})
                self.headers["Content-Length"] = str(len(body))
                self.server = MockServer()
                self._headers_sent = []
                self.status_code = None

            def send_response(self, code, message=None):
                self.status_code = code

            def send_header(self, keyword, value):
                self._headers_sent.append((keyword, value))

            def end_headers(self):
                pass

        from triage_agent.ui.server import resolve_safe_output_path
        from pathlib import Path

        root_audit_file = Path("test_migration_sample_audit.json")
        root_audit_file.write_text(
            json.dumps({
                "attestations": [
                    {
                        "check_point_id": "cp-internal",
                        "status": "NO (手動確認済み)",
                        "reviewer": "社内田中",
                        "date": "2026-10-25",
                        "evidence": "社内確認済み",
                    }
                ]
            }),
            encoding="utf-8"
        )

        dest_audit_path = resolve_safe_output_path("test_migration_sample_audit.json", allowed_extensions=(".json",))
        if dest_audit_path.exists():
            dest_audit_path.unlink()

        csv_content = (
            "\ufeffDistributionID,No,CheckPointID,対象製品/ライブラリ,CVE/対象識別子,深刻度/CVSS,確認ポイント (Yes/No),確認方法 (設定・コード・コマンド),ベンダー回答 (YES/NO/要確認),確認根拠/設定箇所,確認者 (会社名・氏名),確認日 (YYYY-MM-DD)\n"
            "DIST-20261025-MIGR,1,cp-vendor,Apache Tomcat,CVE-2020-1938,9.8 Critical,AJP コネクタ無効化,server.xml,NO,無効化確認済み,SRE山田,2026-10-25\n"
        )

        headers = {
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:8080",
            "Host": "127.0.0.1:8080",
            "X-CSRF-Token": SERVER_CSRF_TOKEN,
        }

        payload = json.dumps({
            "csv_content": csv_content,
            "audit_file": "test_migration_sample_audit.json",
        }).encode("utf-8")

        handler = DummyHandler("/api/import-checklist", payload, headers=headers)
        handler.do_POST()

        self.assertEqual(handler.status_code, 200)
        res_data = json.loads(handler.wfile.getvalue().decode("utf-8"))
        self.assertTrue(res_data["success"])
        # Check migration warning/notice
        warnings = res_data.get("warnings", [])
        self.assertTrue(any("移行・統合しました" in w for w in warnings))

        # Check destination file contains BOTH cp-internal and cp-vendor!
        self.assertTrue(dest_audit_path.exists())
        saved_audit = json.loads(dest_audit_path.read_text(encoding="utf-8"))
        cp_ids = [item.get("check_point_id") for item in saved_audit.get("attestations", [])]
        self.assertIn("cp-internal", cp_ids, "Internal root signoff must NOT be lost!")
        self.assertIn("cp-vendor", cp_ids, "Vendor signoff must be merged!")

        # Cleanup
        if root_audit_file.exists():
            root_audit_file.unlink()
        if dest_audit_path.exists():
            dest_audit_path.unlink()

    def test_resolve_safe_output_path_supports_subdirectories(self):
        from triage_agent.ui.server import resolve_safe_output_path, DEFAULT_OUTPUT_DIR
        import shutil

        sub_path = "subdir_test/nested/report.md"
        resolved = resolve_safe_output_path(sub_path)
        self.assertTrue(resolved.is_relative_to(DEFAULT_OUTPUT_DIR))
        self.assertTrue(resolved.parent.exists(), "Intermediate directory must be automatically created")
        # Cleanup
        if (DEFAULT_OUTPUT_DIR / "subdir_test").exists():
            shutil.rmtree(DEFAULT_OUTPUT_DIR / "subdir_test")


if __name__ == "__main__":
    unittest.main()
