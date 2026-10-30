"""Unit tests for Vendor Workflow and Metrics (Pillar 3 / ADR-019)."""

import csv
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport
from triage_agent.tools.vendor_workflow import (
    CHECKLIST_HEADERS,
    export_checklist_csv,
    get_workflow_metrics,
    import_vendor_checklist,
    record_workflow_event,
)


class TestVendorWorkflow(unittest.TestCase):
    """Test checklist CSV export, vendor import, and workflow metrics."""

    def setUp(self):
        self.notice = TriageNotice(
            product_name="Apache Tomcat",
            component_name="tomcat-catalina",
            announcement_date="2020-02-20",
            conclusion="Ghostcat vulnerability.",
            fixed_versions="9.0.31",
            severity_note="Critical (CVSS 9.8)",
            check_points=[
                CheckPointItem(
                    check_point_id="tomcat-ghostcat-cp1",
                    target_or_cve="CVE-2020-1938 (CVSS 9.8 Critical)",
                    cvss="9.8 (Critical)",
                    content_summary="AJP unauthenticated read/inclusion",
                    affected_versions="< 9.0.31",
                    check_point_yes_no="AJP コネクタを有効にしているか",
                    verification_method="server.xml を確認",
                )
            ],
        )
        self.report = TriageReport(
            report_title="Vendor Workflow Test",
            scan_target="test-system",
            total_dependencies=1,
            notices=[self.notice],
        )

    def test_export_checklist_csv(self):
        """export_checklist_csv must generate UTF-8 BOM CSV with proper columns and rows."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tf:
            tf_path = tf.name

        try:
            csv_text, out_p = export_checklist_csv(self.report, tf_path)
            self.assertTrue(out_p.exists())
            raw_bytes = out_p.read_bytes()
            # UTF-8 BOM starts with 0xEF 0xBB 0xBF
            self.assertTrue(raw_bytes.startswith(b"\xef\xbb\xbf"))

            # Parse CSV content
            reader = list(csv.DictReader(io.StringIO(raw_bytes.decode("utf-8-sig"))))
            self.assertEqual(len(reader), 1)
            row = reader[0]
            self.assertEqual(row["CheckPointID"], "tomcat-ghostcat-cp1")
            self.assertEqual(row["対象製品/ライブラリ"], "Apache Tomcat")
            self.assertEqual(row["確認ポイント (Yes/No)"], "AJP コネクタを有効にしているか")
            self.assertEqual(row["ベンダー回答 (YES/NO/要確認)"], "")
        finally:
            if os.path.exists(tf_path):
                os.remove(tf_path)

    def test_import_vendor_checklist(self):
        """import_vendor_checklist must parse vendor answers and update audit_signoff.json."""
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w", encoding="utf-8-sig") as tf_csv:
            writer = csv.DictWriter(tf_csv, fieldnames=CHECKLIST_HEADERS)
            writer.writeheader()
            writer.writerow({
                "No": "1",
                "CheckPointID": "tomcat-ghostcat-cp1",
                "対象製品/ライブラリ": "Apache Tomcat",
                "CVE/対象識別子": "CVE-2020-1938",
                "深刻度/CVSS": "9.8 (Critical)",
                "確認ポイント (Yes/No)": "AJP コネクタを有効にしているか",
                "確認方法 (設定・コード・コマンド)": "server.xml を確認",
                "ベンダー回答 (YES/NO/要確認)": "NO (非該当・無効化確認済み)",
                "確認根拠/設定箇所": "本番環境ではHTTPコネクタのみ使用しAJPコネクタはコメントアウト済み",
                "確認者 (会社名・氏名)": "株式会社委託システムズ 担当 山田",
                "確認日 (YYYY-MM-DD)": "2026-10-29",
            })
            csv_path = tf_csv.name

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf_json:
            audit_json_path = tf_json.name

        try:
            count, target_p = import_vendor_checklist(csv_path, audit_json_path)
            self.assertEqual(count, 1)

            data = json.loads(target_p.read_text(encoding="utf-8"))
            self.assertIn("attestations", data)
            self.assertEqual(len(data["attestations"]), 1)
            att = data["attestations"][0]
            self.assertEqual(att["check_point_id"], "tomcat-ghostcat-cp1")
            self.assertEqual(att["status"], "NO (ベンダー回答・非該当)")
            self.assertEqual(att["reviewer"], "株式会社委託システムズ 担当 山田")
            self.assertIn("AJPコネクタはコメントアウト済み", att["evidence"])
        finally:
            if os.path.exists(csv_path):
                os.remove(csv_path)
            if os.path.exists(audit_json_path):
                os.remove(audit_json_path)

    def test_workflow_metrics_recording(self):
        """Workflow events must be recorded and aggregated into summary metrics."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf_metric:
            metric_file = tf_metric.name

        try:
            record_workflow_event("vendor_checklist_exported", {"file": "test.csv"}, metrics_file=metric_file)
            record_workflow_event("vendor_checklist_imported", {"imported": 1}, metrics_file=metric_file)

            metrics = get_workflow_metrics(metric_file)
            self.assertEqual(metrics["total_exports"], 1)
            self.assertEqual(metrics["total_imports"], 1)
            self.assertEqual(metrics["roundtrip_count"], 1)
            self.assertIsNotNone(metrics["turnaround_hours"])
        finally:
            if os.path.exists(metric_file):
                os.remove(metric_file)


if __name__ == "__main__":
    unittest.main()
