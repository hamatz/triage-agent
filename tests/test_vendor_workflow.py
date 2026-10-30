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
    sanitize_csv_cell,
)


class TestVendorWorkflow(unittest.TestCase):
    """Test checklist CSV export, vendor import, and workflow metrics."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

        self.notice_tomcat = TriageNotice(
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

        self.notice_php = TriageNotice(
            product_name="PHP Runtime",
            component_name="php",
            announcement_date="2019-10-24",
            conclusion="PHP session upload progress RCE.",
            fixed_versions="7.3.11",
            severity_note="Critical",
            check_points=[
                CheckPointItem(
                    check_point_id="php-upload-cp1",
                    target_or_cve="CVE-2019-11043",
                    cvss="9.8",
                    content_summary="Upload progress session rce",
                    affected_versions="< 7.3.11",
                    check_point_yes_no="session.upload_progress.enabled が有効か",
                    verification_method="php.ini を確認",
                )
            ],
        )

        self.report = TriageReport(
            report_title="Vendor Workflow Test",
            scan_target="test-system",
            total_dependencies=2,
            notices=[self.notice_tomcat, self.notice_php],
        )

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_export_checklist_csv_and_formula_sanitization(self):
        """CSV export must include DistributionID, UTF-8 BOM, and sanitize potential Excel formulas."""
        # Add a check point starting with = and -
        injection_notice = TriageNotice(
            product_name="Injection Test",
            component_name="test-inj",
            announcement_date="2026-10-30",
            conclusion="Test",
            fixed_versions="1.0",
            severity_note="Low",
            check_points=[
                CheckPointItem(
                    check_point_id="=cmd|' /C calc'!A0",
                    target_or_cve="+1234567890",
                    content_summary="@SUM(1,2)",
                    affected_versions="< 1.0",
                    check_point_yes_no="-危险指令",
                    verification_method="echo test",
                )
            ]
        )
        report_with_inj = TriageReport(
            report_title="Inj Test",
            scan_target="inj",
            total_dependencies=1,
            notices=[injection_notice]
        )

        csv_path = self.tmppath / "out_inj.csv"
        csv_text, out_p, dist_id = export_checklist_csv(report_with_inj, str(csv_path))

        self.assertTrue(out_p.exists())
        self.assertTrue(dist_id.startswith("DIST-"))
        raw_bytes = out_p.read_bytes()
        self.assertTrue(raw_bytes.startswith(b"\xef\xbb\xbf"), "Must have UTF-8 BOM")

        # Parse CSV content
        reader = list(csv.DictReader(io.StringIO(raw_bytes.decode("utf-8-sig"))))
        self.assertEqual(len(reader), 1)
        row = reader[0]
        self.assertEqual(row["DistributionID"], dist_id)
        # Verify formula characters are escaped with leading single quote '
        self.assertTrue(row["CheckPointID"].startswith("'="))
        self.assertTrue(row["CVE/対象識別子"].startswith("'+"))
        self.assertTrue(row["確認ポイント (Yes/No)"].startswith("'-"))

    def test_export_checklist_scoped_by_product(self):
        """Exporting with target_product filter must only export matching product check points."""
        csv_path = self.tmppath / "out_scoped.csv"
        csv_text, out_p, dist_id = export_checklist_csv(self.report, str(csv_path), target_product="Tomcat")

        reader = list(csv.DictReader(io.StringIO(csv_path.read_text(encoding="utf-8-sig"))))
        self.assertEqual(len(reader), 1)
        self.assertEqual(reader[0]["対象製品/ライブラリ"], "Apache Tomcat")
        self.assertNotIn("PHP", csv_text)

    def test_import_opus_review_answer_patterns(self):
        """Test import against all Opus review patterns (NO, Not sure, NOT CHECKED YET, No idea, etc.)."""
        test_patterns = [
            ("NO", "SRE山田", "server.xml確認済み", "NO (ベンダー回答・非該当)"),
            ("非該当", "SRE山田", "設定なし", "NO (ベンダー回答・非該当)"),
            ("該当なし", "SRE山田", "無効化済み", "NO (ベンダー回答・非該当)"),
            ("YES", "SRE山田", "本番で有効", "YES (ベンダー回答・該当あり)"),
            ("Not sure", "SRE山田", "不明", "要確認 (ベンダー回答: Not sure)"),
            ("NOT CHECKED YET", "SRE山田", "未調査", "要確認 (ベンダー回答: NOT CHECKED YET)"),
            ("No idea", "SRE山田", "調査中", "要確認 (ベンダー回答: No idea)"),
            ("安全かどうか未確認", "SRE山田", "来週確認", "要確認 (ベンダー回答: 安全かどうか未確認)"),
            ("わからない", "SRE山田", "未定", "要確認 (ベンダー回答: わからない)"),
        ]

        csv_path = self.tmppath / "answers_test.csv"
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CHECKLIST_HEADERS)
            writer.writeheader()
            for idx, (ans, reviewer, evidence, _) in enumerate(test_patterns, 1):
                writer.writerow({
                    "DistributionID": "DIST-TEST-001",
                    "No": str(idx),
                    "CheckPointID": f"cp-{idx}",
                    "対象製品/ライブラリ": "TestProduct",
                    "CVE/対象識別子": f"CVE-2026-000{idx}",
                    "深刻度/CVSS": "High",
                    "確認ポイント (Yes/No)": f"Question {idx}",
                    "確認方法 (設定・コード・コマンド)": "Check code",
                    "ベンダー回答 (YES/NO/要確認)": ans,
                    "確認根拠/設定箇所": evidence,
                    "確認者 (会社名・氏名)": reviewer,
                    "確認日 (YYYY-MM-DD)": "2026-10-30",
                })

        audit_path = self.tmppath / "audit_result.json"
        count, target_p, summary = import_vendor_checklist(str(csv_path), str(audit_path))
        self.assertEqual(count, len(test_patterns))

        data = json.loads(audit_path.read_text(encoding="utf-8"))
        attestations = {a["check_point_id"]: a for a in data["attestations"]}

        for idx, (ans, reviewer, evidence, expected_status) in enumerate(test_patterns, 1):
            cp_key = f"cp-{idx}"
            self.assertIn(cp_key, attestations)
            actual_status = attestations[cp_key]["status"]
            self.assertEqual(
                actual_status,
                expected_status,
                f"Answer '{ans}' should resolve to '{expected_status}', got '{actual_status}'"
            )

    def test_no_answer_without_reviewer_or_evidence_is_held(self):
        """NO answer without reviewer or evidence must NOT be declared safe; must be held as 要確認."""
        csv_path = self.tmppath / "no_missing_fields.csv"
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CHECKLIST_HEADERS)
            writer.writeheader()
            # 1. Missing reviewer
            writer.writerow({
                "DistributionID": "DIST-TEST-002",
                "No": "1",
                "CheckPointID": "cp-no-reviewer",
                "ベンダー回答 (YES/NO/要確認)": "NO",
                "確認根拠/設定箇所": "本番設定ファイルで確認済み",
                "確認者 (会社名・氏名)": "",
            })
            # 2. Missing evidence
            writer.writerow({
                "DistributionID": "DIST-TEST-002",
                "No": "2",
                "CheckPointID": "cp-no-evidence",
                "ベンダー回答 (YES/NO/要確認)": "NO",
                "確認根拠/設定箇所": "",
                "確認者 (会社名・氏名)": "山田太郎",
            })

        audit_path = self.tmppath / "audit_held.json"
        count, _, summary = import_vendor_checklist(str(csv_path), str(audit_path))
        self.assertEqual(summary["no_held_count"], 2)

        data = json.loads(audit_path.read_text(encoding="utf-8"))
        att_map = {a["check_point_id"]: a for a in data["attestations"]}

        self.assertIn("要確認", att_map["cp-no-reviewer"]["status"])
        self.assertIn("確認者未記入", att_map["cp-no-reviewer"]["status"])

        self.assertIn("要確認", att_map["cp-no-evidence"]["status"])
        self.assertIn("根拠未記入", att_map["cp-no-evidence"]["status"])

    def test_corrupted_audit_file_aborts_import_to_protect_data(self):
        """If existing audit file is corrupted, import must abort with ValueError to prevent data loss."""
        corrupted_path = self.tmppath / "corrupted_audit.json"
        corrupted_path.write_text("{ incomplete json ...", encoding="utf-8")

        csv_path = self.tmppath / "valid.csv"
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CHECKLIST_HEADERS)
            writer.writeheader()
            writer.writerow({
                "CheckPointID": "cp-test",
                "ベンダー回答 (YES/NO/要確認)": "NO",
                "確認根拠/設定箇所": "verified",
                "確認者 (会社名・氏名)": "Alice",
            })

        with self.assertRaises(ValueError) as ctx:
            import_vendor_checklist(str(csv_path), str(corrupted_path))
        self.assertIn("解析に失敗しました", str(ctx.exception))
        # Ensure file content was not overwritten
        self.assertEqual(corrupted_path.read_text(encoding="utf-8"), "{ incomplete json ...")

    def test_internal_yes_and_vendor_no_conflict_detection(self):
        """Internal YES must not be silently overwritten by vendor NO; must flag as conflict."""
        audit_path = self.tmppath / "existing_yes_audit.json"
        existing_data = {
            "attestations": [
                {
                    "check_point_id": "cp-critical-1",
                    "status": "YES (本番コード内検出・要実地確認)",
                    "reviewer": "社内セキュリティチーム",
                    "date": "2026-10-25",
                    "evidence": "server.js:45 で jwt.verify() の algorithms 未指定を検出"
                }
            ]
        }
        audit_path.write_text(json.dumps(existing_data), encoding="utf-8")

        csv_path = self.tmppath / "vendor_claims_no.csv"
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CHECKLIST_HEADERS)
            writer.writeheader()
            writer.writerow({
                "CheckPointID": "cp-critical-1",
                "ベンダー回答 (YES/NO/要確認)": "NO",
                "確認根拠/設定箇所": "特に問題ないと思います",
                "確認者 (会社名・氏名)": "ベンダー窓口",
            })

        count, _, summary = import_vendor_checklist(str(csv_path), str(audit_path))
        self.assertEqual(summary["conflict_count"], 1)

        data = json.loads(audit_path.read_text(encoding="utf-8"))
        att = data["attestations"][0]
        self.assertTrue(att["status"].startswith("要再確認 (社内YESとベンダーNOの競合⚠️)"))
        self.assertIn("競合検知", att["evidence"])

    def test_internal_yes_preserved_and_shows_actual_vendor_answer(self):
        """Opus Review Point 2: When internal YES is preserved against vendor 'わからない'/Not sure,

        evidence text must display the vendor's actual answer, not the overwritten YES status.
        """
        audit_path = self.tmppath / "existing_yes_audit_unknown.json"
        existing_data = {
            "attestations": [
                {
                    "check_point_id": "cp-yes-preserve",
                    "status": "YES (本番コード内検出・要実地確認)",
                    "reviewer": "社内セキュリティチーム",
                    "date": "2026-10-25",
                    "evidence": "server.js:45 で脆弱コードを検出",
                }
            ]
        }
        audit_path.write_text(json.dumps(existing_data), encoding="utf-8")

        csv_path = self.tmppath / "vendor_claims_unknown.csv"
        with open(csv_path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=CHECKLIST_HEADERS)
            writer.writeheader()
            writer.writerow({
                "CheckPointID": "cp-yes-preserve",
                "ベンダー回答 (YES/NO/要確認)": "わからない",
                "確認根拠/設定箇所": "担当者不在",
                "確認者 (会社名・氏名)": "B社 担当者",
            })

        count, _, summary = import_vendor_checklist(str(csv_path), str(audit_path))
        data = json.loads(audit_path.read_text(encoding="utf-8"))
        att = data["attestations"][0]

        # Status must remain YES
        self.assertEqual(att["status"], "YES (本番コード内検出・要実地確認)")
        # Evidence must show the actual vendor answer ("わからない"), NOT "YES"
        self.assertIn("※ベンダー回答: 要確認 (ベンダー回答: わからない)", att["evidence"])
        self.assertIn("B社 担当者", att["evidence"])
        self.assertNotIn("※ベンダー回答: YES", att["evidence"])

    def test_distribution_id_metrics_tracking(self):
        """Workflow metrics must accurately record turnaround time and roundtrip per DistributionID."""
        metrics_file = self.tmppath / "workflow_metrics.json"

        # 1. Export checklist
        _, _, dist_id = export_checklist_csv(self.report, output_path=str(self.tmppath / "dist.csv"))

        # 2. Record export event to custom test metrics file
        record_workflow_event("vendor_checklist_exported", {
            "distribution_id": dist_id,
            "target_product": "Apache Tomcat",
            "check_points_count": 2,
        }, metrics_file=str(metrics_file))

        # 3. Record import event to custom test metrics file
        record_workflow_event("vendor_checklist_imported", {
            "distribution_id": dist_id,
            "imported_count": 2,
        }, metrics_file=str(metrics_file))

        metrics = get_workflow_metrics(str(metrics_file))
        self.assertEqual(metrics["total_exports"], 1)
        self.assertEqual(metrics["total_imports"], 1)
        self.assertIn(dist_id, metrics["distributions"])
        dist_record = metrics["distributions"][dist_id]
        self.assertEqual(dist_record["status"], "imported")
        self.assertIsNotNone(dist_record["turnaround_hours"])


if __name__ == "__main__":
    unittest.main()
