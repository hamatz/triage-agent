"""Web UI (local mode) endpoints for the kernel inquiry (ADR-022 / ADR-023).

Runs offline in a temporary working directory with the trimmed ALAS fixtures and a SYNTHETIC KEV catalog.
"""

import base64
import csv
import io
import json
import os
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_kernel_auto import _seed_alas_cache  # noqa: E402
from test_kernel_inquiry import KEV, OLD, UBUNTU  # noqa: E402

from triage_agent.chain import kernel_inquiry as ki  # noqa: E402
from triage_agent.web_ui import SERVER_CSRF_TOKEN, TriageDashboardHandler  # noqa: E402

HEADERS = {"Content-Type": "application/json", "Origin": "http://127.0.0.1:8080", "Host": "127.0.0.1:8080",
           "X-CSRF-Token": SERVER_CSRF_TOKEN}


class _Server:
    server_port = 8080


class _Handler(TriageDashboardHandler):
    def __init__(self, path, payload):
        body = json.dumps(payload).encode("utf-8")
        self.path = path
        self.rfile = BytesIO(body)
        self.wfile = BytesIO()
        self.headers = dict(HEADERS, **{"Content-Length": str(len(body))})
        self.server = _Server()
        self.status_code = None

    def send_response(self, code, message=None):
        self.status_code = code

    def send_header(self, keyword, value):
        pass

    def end_headers(self):
        pass


def _post(path, payload):
    h = _Handler(path, payload)
    h.do_POST()
    return h.status_code, json.loads(h.wfile.getvalue().decode("utf-8"))


def _form(rows, encoding="utf-8-sig") -> bytes:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=ki.REQUEST_HEADERS)
    w.writeheader()
    for no, label, line, count in rows:
        w.writerow({h: "" for h in ki.REQUEST_HEADERS} | {"DistributionID": "DIST-20261112-abcdef", "No": no,
                                                        "サーバー群（呼び名・任意）": label,
                                                        "コマンドの出力（1 行をそのまま貼り付け）": line, "台数": count})
    return buf.getvalue().encode(encoding)


class TestKernelInquiryEndpoints(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        cache = Path("triage-output/cache")
        _seed_alas_cache(cache)
        (cache / "cisa_kev_catalog.json").write_text(json.dumps({
            "title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.11.12",
            "dateReleased": "2026-11-12T00:00:00Z", "count": len(KEV), "vulnerabilities": list(KEV.values())}), encoding="utf-8")

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def test_request_returns_form_and_message_without_writing_files(self):
        code, data = _post("/api/kernel-inquiry/request", {"target": "受注システム"})
        self.assertEqual(code, 200, data)
        self.assertTrue(data["csv"].startswith("﻿"))
        self.assertIn(ki.COLLECT_COMMAND, data["message"])
        self.assertTrue(data["filename"].endswith(".csv"))
        self.assertFalse(list(Path("triage-output").glob("kernel_inquiry_*")))

    def test_answers_saved_by_japanese_excel_are_read(self):
        content = _form([("1", "Web", OLD, "4"), ("2", "Ubuntu 群", UBUNTU, "2")], encoding="cp932")
        code, data = _post("/api/kernel-inquiry/answers", {
            "target": "受注システム", "filename": "back.csv", "offline": True,
            "content_b64": base64.b64encode(content).decode()})
        self.assertEqual(code, 200, data)
        by_label = {g["label"]: g for g in data["groups"]}
        self.assertEqual(by_label["Web"]["status"], "remaining")
        self.assertEqual(by_label["Web"]["target"], "6.1.189-236.399.amzn2023")
        self.assertEqual(by_label["Ubuntu 群"]["status"], "unknown")
        self.assertIn("6.1.189-236.399.amzn2023 以上に更新", data["message"])
        self.assertIn("判定できませんでした", data["message"])
        self.assertTrue(data["errors"])
        self.assertEqual(data["kev_version"], "2026.11.12")

    def test_answers_rejects_other_files(self):
        code, data = _post("/api/kernel-inquiry/answers", {
            "filename": "x.csv", "offline": True, "content_b64": base64.b64encode(b"a,b\n1,2\n").decode()})
        self.assertEqual(code, 400)
        self.assertIn("記入表ではありません", data["error"])
        code, data = _post("/api/kernel-inquiry/answers", {"filename": "x.csv", "content_b64": "%%%"})
        self.assertEqual(code, 400)

    def test_answers_without_any_line_is_an_error(self):
        code, data = _post("/api/kernel-inquiry/answers", {
            "filename": "x.csv", "offline": True, "content_b64": base64.b64encode(_form([])).decode()})
        self.assertEqual(code, 400)
        self.assertIn("1 行もありません", data["error"])

    def test_page_has_navigation_and_kernel_screen(self):
        from triage_agent.web_ui import HTML_PAGE
        for marker in ('id="view-home"', 'id="view-kernel"', 'id="view-sbom"', "ki-btn-request", "ki-btn-answers",
                       "/api/kernel-inquiry/answers"):
            self.assertIn(marker, HTML_PAGE)
        # Values from the server or the uploaded file are never inserted as HTML.
        views_js = (Path(__file__).resolve().parents[1] / "src/triage_agent/ui/static/views.js").read_text(encoding="utf-8")
        self.assertNotRegex(views_js, r"\.(innerHTML|outerHTML)\b|insertAdjacentHTML|document\.write")


class TestLocalModeBinding(unittest.TestCase):
    def test_local_mode_refuses_to_listen_beyond_this_computer(self):
        from triage_agent.ui.server import run_gui
        with self.assertRaises(SystemExit):
            run_gui(host="0.0.0.0", port=0, open_browser=False)


if __name__ == "__main__":
    unittest.main()
