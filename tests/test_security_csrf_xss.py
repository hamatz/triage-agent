import json
import unittest
from io import BytesIO
from pathlib import Path

from triage_agent.web_ui import (
    SERVER_CSRF_TOKEN,
    TriageDashboardHandler,
    HTML_PAGE,
    resolve_safe_path,
)
from triage_agent.pipeline import execute_triage_pipeline


class MockServer:
    server_port = 8080


class DummyHandler(TriageDashboardHandler):
    def __init__(self, path, body=b"", headers=None):
        self.path = path
        self.rfile = BytesIO(body)
        self.wfile = BytesIO()
        self.headers = headers or {}
        self.headers.setdefault("Content-Length", str(len(body)))
        self.server = MockServer()
        self._headers_sent = []
        self.status_code = None

    def send_response(self, code, message=None):
        self.status_code = code

    def send_header(self, keyword, value):
        self._headers_sent.append((keyword, value))

    def end_headers(self):
        pass


class TestSecurityAndFixes(unittest.TestCase):
    def test_zero_cdn_dependencies(self):
        """Ensure no external CDN script or stylesheet links remain in HTML_PAGE."""
        self.assertNotIn("cdn.tailwindcss.com", HTML_PAGE)
        self.assertNotIn("cdnjs.cloudflare.com", HTML_PAGE)
        self.assertNotIn("<script src=\"http", HTML_PAGE)
        self.assertNotIn("<link rel=\"stylesheet\" href=\"http", HTML_PAGE)

    def test_no_inline_xss_in_signoff_modal(self):
        """Ensure no inline string interpolation inside onclick attributes."""
        self.assertNotIn("onclick=\"openSignoffModal", HTML_PAGE)
        self.assertIn("btn-open-signoff", HTML_PAGE)
        self.assertIn("data-cp-id", HTML_PAGE)
        self.assertIn("data-question", HTML_PAGE)

    def test_meta_tag_csrf_token_present_and_no_inline_scripts(self):
        """Ensure CSRF token is exposed via secure meta tag and no inline script blocks exist (CSP compliant)."""
        from triage_agent.ui.server import load_ui_template
        template = load_ui_template()
        self.assertIn('<meta name="csrf-token" content="__CSRF_TOKEN__">', template)
        self.assertIn('<meta name="default-reviewer" content="__DEFAULT_REVIEWER__">', template)
        # Ensure no inline script tags exist in index.html (only external /static/app.js)
        self.assertNotIn('<script>', template.lower())

    def test_safe_path_resolution(self):
        """Ensure directory traversal and paths outside cwd are blocked."""
        cwd = Path.cwd().resolve()
        # Normal relative path within cwd is allowed
        p = resolve_safe_path("sample_sbom.json", base_dir=cwd)
        self.assertEqual(p, cwd / "sample_sbom.json")

        # Traversal outside cwd is rejected
        with self.assertRaises(PermissionError):
            resolve_safe_path("../../etc/passwd", base_dir=cwd)

        with self.assertRaises(PermissionError):
            resolve_safe_path("/etc/hosts", base_dir=cwd)

    def test_csrf_content_type_enforcement(self):
        """Ensure non-application/json requests (like browser text/plain simple requests) are rejected."""
        body = json.dumps({"audit_file": "sample_audit_signoff.json"}).encode("utf-8")
        h = DummyHandler(
            "/api/create-signoff",
            body=body,
            headers={"Content-Type": "text/plain", "Origin": "https://evil.example"},
        )
        h.do_POST()
        self.assertEqual(h.status_code, 415)

    def test_csrf_origin_enforcement(self):
        """Ensure external Origin headers are blocked with 403."""
        body = json.dumps({"audit_file": "sample_audit_signoff.json"}).encode("utf-8")
        h = DummyHandler(
            "/api/create-signoff",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Origin": "https://evil.example",
                "Host": "127.0.0.1:8080",
                "X-CSRF-Token": SERVER_CSRF_TOKEN,
            },
        )
        h.do_POST()
        self.assertEqual(h.status_code, 403)
        res = json.loads(h.wfile.getvalue().decode("utf-8"))
        self.assertIn("アクセス拒否", res["error"])

    def test_csrf_token_enforcement(self):
        """Ensure missing or invalid CSRF tokens are rejected with 403."""
        body = json.dumps({"audit_file": "sample_audit_signoff.json"}).encode("utf-8")
        h = DummyHandler(
            "/api/create-signoff",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Origin": "http://127.0.0.1:8080",
                "Host": "127.0.0.1:8080",
                "X-CSRF-Token": "bad-token-12345",
            },
        )
        h.do_POST()
        self.assertEqual(h.status_code, 403)

    def test_valid_post_with_csrf_token(self):
        """Ensure valid request with matching CSRF token and Origin passes."""
        body = json.dumps({
            "mode": "demo",
            "sbom": "sample_sbom.json",
            "code_dir": "",
            "audit_file": "sample_audit_signoff.json",
        }).encode("utf-8")
        h = DummyHandler(
            "/api/run",
            body=body,
            headers={
                "Content-Type": "application/json",
                "Origin": "http://127.0.0.1:8080",
                "Host": "127.0.0.1:8080",
                "X-CSRF-Token": SERVER_CSRF_TOKEN,
            },
        )
        h.do_POST()
        self.assertEqual(h.status_code, 200)
        res = json.loads(h.wfile.getvalue().decode("utf-8"))
        self.assertIn("report", res)
        self.assertIn("audit", res)

    def test_vendor_mode_without_codebase(self):
        """Ensure vendor departments without code can inspect checkpoints and record sign-offs."""
        triage_report, audit_report = execute_triage_pipeline(
            sbom_path="sample_sbom.json",
            mode="demo",
            code_dir=None,
            audit_file_path="sample_audit_signoff.json",
        )
        self.assertIsNotNone(audit_report)
        self.assertIn("外注・ベンダー委託", audit_report.code_dir)
        # Checkpoint statuses should have either attested status or '要手動確認 (ベンダー照会要)'
        statuses = [
            cp_res.status
            for n in audit_report.notice_results
            for cp_res in n.results
        ]
        self.assertTrue(any("ベンダー" in s or "手動" in s for s in statuses))

    def test_get_host_validation_blocks_dns_rebinding(self):
        """Ensure GET requests with spoofed or external Host header are rejected with 403."""
        h = DummyHandler(
            "/api/status",
            headers={"Host": "evil.example"}
        )
        h.do_GET()
        self.assertEqual(h.status_code, 403)
        res = json.loads(h.wfile.getvalue().decode("utf-8"))
        self.assertIn("アクセス拒否", res["error"])

        # Also verify GET / (HTML page) blocks spoofed Host
        h_root = DummyHandler(
            "/",
            headers={"Host": "evil.example"}
        )
        h_root.do_GET()
        self.assertEqual(h_root.status_code, 403)

    def test_get_valid_host_allowed(self):
        """Ensure GET requests with valid local Host headers succeed with 200."""
        h = DummyHandler(
            "/api/status",
            headers={"Host": "127.0.0.1:8080"}
        )
        h.do_GET()
        self.assertEqual(h.status_code, 200)
        res = json.loads(h.wfile.getvalue().decode("utf-8"))
        self.assertIn("is_llm_configured", res)

    def test_source_links_xss_sanitization(self):
        """Ensure sources are strictly escaped and javascript: URIs are blocked from href."""
        self.assertNotIn('<a href="${s}"', HTML_PAGE)
        self.assertIn("formatSourceLink", HTML_PAGE)
        self.assertIn("https?:\\/\\/", HTML_PAGE)

    def test_signoff_options_allow_vendor_and_yes(self):
        """Ensure signoff modal options include vendor YES and unverified choices."""
        self.assertIn("YES (ベンダー回答・該当あり)", HTML_PAGE)
        self.assertIn("要確認 (ベンダー回答待ち・調査中)", HTML_PAGE)
        self.assertIn("NO (ベンダー確認済み・非該当)", HTML_PAGE)
        # Verify signoff button is not hidden for YES items
        self.assertNotIn("canSignoff = !statusText.startsWith('YES')", HTML_PAGE)


if __name__ == "__main__":
    unittest.main()
