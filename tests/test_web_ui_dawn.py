import unittest
import json
from io import BytesIO
from triage_agent.web_ui import TriageDashboardHandler, HTML_PAGE

class TestWebUiDawn(unittest.TestCase):
    def test_html_contains_dawn_elements(self):
        # Check DAWN design tokens
        self.assertIn("#f6f1e8", HTML_PAGE)
        self.assertIn("--serif", HTML_PAGE)
        self.assertIn("--accent-gold", HTML_PAGE)
        self.assertIn("generating-ring", HTML_PAGE)
        self.assertIn("triage-form", HTML_PAGE)
        self.assertIn("sbom-path", HTML_PAGE)
        self.assertIn("code-dir", HTML_PAGE)
        self.assertIn("audit-file", HTML_PAGE)
        self.assertIn("loading-spinner", HTML_PAGE)
        self.assertIn("verification-panel", HTML_PAGE)
        self.assertIn("unscanned-panel", HTML_PAGE)
        self.assertIn("notices-container", HTML_PAGE)
        self.assertIn("signoff-modal", HTML_PAGE)

    def test_mock_get_routes(self):
        class MockServer:
            pass

        class DummyHandler(TriageDashboardHandler):
            def __init__(self, path):
                self.path = path
                self.rfile = BytesIO()
                self.wfile = BytesIO()
                self.headers = {"Host": "127.0.0.1:8080"}
                self.server = MockServer()
                self.server.server_port = 8080
                self._headers_sent = []
                self.status_code = None

            def send_response(self, code, message=None):
                self.status_code = code

            def send_header(self, keyword, value):
                self._headers_sent.append((keyword, value))

            def end_headers(self):
                pass

        # Test GET /
        h_root = DummyHandler("/")
        h_root.do_GET()
        self.assertEqual(h_root.status_code, 200)
        output = h_root.wfile.getvalue().decode("utf-8")
        self.assertIn("triage-agent", output)
        self.assertIn("DAWN", output)

        # Test GET /api/status
        h_status = DummyHandler("/api/status")
        h_status.do_GET()
        self.assertEqual(h_status.status_code, 200)
        status_data = json.loads(h_status.wfile.getvalue().decode("utf-8"))
        self.assertIn("is_llm_configured", status_data)

if __name__ == "__main__":
    unittest.main()
