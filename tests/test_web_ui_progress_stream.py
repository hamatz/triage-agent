import unittest
import json
from io import BytesIO
from triage_agent.web_ui import TriageDashboardHandler, SERVER_CSRF_TOKEN


class MockServer:
    server_port = 8080


class DummyHandler(TriageDashboardHandler):
    def __init__(self, path, body, headers=None):
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


class TestWebUIProgressStream(unittest.TestCase):
    def test_run_stream_sse_flow(self):
        """Test /api/run-stream sends progress events and completes with report."""
        payload = json.dumps({
            "mode": "demo",
            "sbom": "sample_sbom.json",
            "code_dir": "demo_app",
            "audit_file": "sample_audit_signoff.json",
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:8080",
            "Host": "127.0.0.1:8080",
            "X-CSRF-Token": SERVER_CSRF_TOKEN,
        }

        handler = DummyHandler("/api/run-stream", payload, headers=headers)
        handler.do_POST()

        self.assertEqual(handler.status_code, 200)
        self.assertIn(("Content-Type", "text/event-stream; charset=utf-8"), handler._headers_sent)

        # Parse SSE data events
        output_str = handler.wfile.getvalue().decode("utf-8")
        events = []
        for line in output_str.split("\n\n"):
            line = line.strip()
            if line.startswith("data: "):
                events.append(json.loads(line[6:]))

        self.assertGreater(len(events), 0, "Should receive SSE data events")

        # Verify progress events
        progress_events = [e for e in events if e.get("type") == "progress"]
        self.assertGreater(len(progress_events), 0)
        for pe in progress_events:
            self.assertIn("percent", pe)
            self.assertIn("phase", pe)

        # Verify complete event
        complete_events = [e for e in events if e.get("type") == "complete"]
        self.assertEqual(len(complete_events), 1)
        self.assertIn("report", complete_events[0])
        self.assertIsNotNone(complete_events[0]["report"])

    def test_run_stream_csrf_rejected(self):
        """Test /api/run-stream rejects invalid CSRF token."""
        payload = json.dumps({"mode": "demo"}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:8080",
            "Host": "127.0.0.1:8080",
            "X-CSRF-Token": "INVALID_TOKEN",
        }

        handler = DummyHandler("/api/run-stream", payload, headers=headers)
        handler.do_POST()

        self.assertEqual(handler.status_code, 403)
        res_data = json.loads(handler.wfile.getvalue().decode("utf-8"))
        self.assertIn("error", res_data)


if __name__ == "__main__":
    unittest.main()
