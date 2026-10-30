"""Tests for Clean / Non-vulnerable Components and Deterministic Verification Safety (ADR-019 / v0.3.1).

Ensures:
1. Packages with confirmed clean status (no_known_vulnerability=True, empty check_points)
   are recognized as NO without false alarm fatigue.
2. Natural language phrases with negation (e.g. '対応不要とは言えません') or unrated
   CVEs (CVSS: N/A) are NEVER falsely marked safe.
3. T4 remediation persistence in workflow_metrics.json.
"""

import json
import tempfile
import unittest
from pathlib import Path

from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport
from triage_agent.tools.vendor_workflow import (
    record_remediation_completed,
    record_workflow_event,
)
from triage_agent.verifier.engine import verify_codebase


class TestCleanComponentVerification(unittest.TestCase):
    """Test suite ensuring clean components are recognized safely and LLM text is never used to falsify safety."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.code_dir = Path(self.tmp_dir.name)
        (self.code_dir / "main.py").write_text("import os\nprint('hello')", encoding="utf-8")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_clean_component_with_deterministic_flag(self):
        """A notice with no_known_vulnerability=True and empty check_points must be safely NO."""
        report = TriageReport(
            report_title="Test Clean Audit",
            scan_target="self-audit",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="google-auth（利用バージョン: 2.62.0）",
                    announcement_date="2026-10-27",
                    conclusion="現在導入されているバージョン 2.62.0 において該当するセキュリティ脆弱性は報告されていません。対応不要です。",
                    fixed_versions="N/A (該当脆弱性なし)",
                    severity_note="なし",
                    no_known_vulnerability=True,
                    clean_basis="OSV.dev 0件照合済み・2026-10-27時点",
                    check_points=[],
                )
            ],
        )

        res = verify_codebase(report, code_dir_path=str(self.code_dir))
        self.assertEqual(res.overall_status, "NO (安全・確認済み)")
        self.assertEqual(res.summary_counts["unverified_count"], 0)
        self.assertEqual(res.summary_counts["safe_count"], 1)

        nr = res.notice_results[0]
        self.assertIn("NO (既知の脆弱性なし", nr.overall_status)
        self.assertIn("OSV.dev 0件照合済み", nr.overall_status)

    def test_negated_phrase_must_not_become_safe(self):
        """A notice containing '対応不要とは言えません' must NOT be judged as safe!"""
        report = TriageReport(
            report_title="Test Negation Safety",
            scan_target="test-repo",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="nodejs（利用バージョン: 20.18.0）",
                    announcement_date="2026-10-21",
                    conclusion="WAF で遮断できない場合は対応不要とは言えません。至急更新してください。",
                    fixed_versions="20.18.1",
                    severity_note="Critical (CVSS 9.8)",
                    no_known_vulnerability=False,
                    check_points=[
                        CheckPointItem(
                            check_point_id="node-brotli-cp1",
                            target_or_cve="CVE-2026-111497 (CVSS 9.8)",
                            cvss="9.8 (Critical)",
                            content_summary="Brotli decompression RCE",
                            affected_versions="< 20.18.1",
                            check_point_yes_no="zlib / brotli 関連APIを利用しているか",
                            verification_method="コードベースで brotliDecompress を検索",
                        )
                    ],
                )
            ],
        )

        res = verify_codebase(report, code_dir_path=str(self.code_dir))
        # Code does not contain brotliDecompress, but it's an unverified external/env check
        self.assertNotEqual(res.overall_status, "NO (安全・確認済み)")
        self.assertIn("要確認", res.overall_status)
        self.assertEqual(res.summary_counts["safe_count"], 0)
        self.assertEqual(res.summary_counts["unverified_count"], 1)

    def test_unrated_new_cve_with_na_cvss_must_not_become_safe(self):
        """Newly released RCE with CVSS: N/A must NOT be judged safe."""
        report = TriageReport(
            report_title="Test Unrated CVE Safety",
            scan_target="test-repo",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="critical-pkg（利用バージョン: 1.0.0）",
                    announcement_date="2026-10-28",
                    conclusion="新着のゼロデイ脆弱性です。至急対応してください。",
                    fixed_versions="1.0.1",
                    severity_note="N/A",  # Unrated
                    no_known_vulnerability=False,
                    check_points=[
                        CheckPointItem(
                            check_point_id="crit-cp1",
                            target_or_cve="CVE-2026-999999 (CVSS N/A)",
                            cvss="N/A",
                            content_summary="Zero-day RCE",
                            affected_versions="1.0.0",
                            check_point_yes_no="該当APIを呼び出しているか",
                            verification_method="コードベースで vulnerable_endpoint を検索",
                        )
                    ],
                )
            ],
        )

        res = verify_codebase(report, code_dir_path=str(self.code_dir))
        self.assertNotEqual(res.overall_status, "NO (安全・確認済み)")
        self.assertIn("要確認", res.overall_status)
        self.assertEqual(res.summary_counts["unverified_count"], 1)

    def test_remediation_t4_persistence(self):
        """Verify that record_remediation_completed persists remediated_at and status: remediated to disk."""
        metrics_file = self.code_dir / "workflow_metrics.json"

        # 1. Simulate export event
        dist_id = "DIST-TEST-001"
        record_workflow_event("vendor_checklist_exported", {
            "distribution_id": dist_id,
            "target_product": "test-product",
            "check_points_count": 2,
            "announced_at": "2026-10-20T10:00:00Z",
        }, metrics_file=str(metrics_file))

        # 2. Simulate import event
        record_workflow_event("vendor_checklist_imported", {
            "distribution_id": dist_id,
            "file_path": "checklist.csv",
        }, metrics_file=str(metrics_file))

        # 3. Record remediation completed (T4)
        t4_ts = "2026-10-22T15:00:00Z"
        res = record_remediation_completed(
            distribution_id=dist_id,
            remediated_at=t4_ts,
            note="Deploy commit abcdef1",
            metrics_file=str(metrics_file),
        )

        self.assertEqual(res["remediated_at"], t4_ts)
        self.assertEqual(res["status"], "remediated")
        self.assertEqual(res["remediation_note"], "Deploy commit abcdef1")

        # 4. Verify disk content directly
        disk_data = json.loads(metrics_file.read_text(encoding="utf-8"))
        saved_entry = disk_data["distributions"][dist_id]
        self.assertEqual(saved_entry["remediated_at"], t4_ts)
        self.assertEqual(saved_entry["status"], "remediated")
        self.assertEqual(saved_entry["remediation_note"], "Deploy commit abcdef1")
        self.assertIsNotNone(saved_entry.get("total_lead_time_hours"))

    def test_osv_hit_with_llm_findings_omission_must_not_become_safe(self):
        """Opus issue 1 reproduction: OSV has hit, but LLM omitted findings.

        Must NOT set no_known_vulnerability=True, and MUST NOT erase check_points!
        """
        from triage_agent.agents.triage import run_triage_agent
        from triage_agent.schemas import ReconTarget, TargetResearchResult

        # Simulate axios: OSV has CVE-2026-50001, but findings is empty (LLM omitted it)
        research_result = TargetResearchResult(
            target=ReconTarget(
                name="axios",
                version="1.7.2",
                ecosystem="npm",
                priority="HIGH",
                rationale="Test",
            ),
            findings=[],  # LLM omitted findings
            osv_vuln_ids=["CVE-2026-50001"],  # Ground-truth raw OSV hit
            recon_notes="Clean notes",
            errors=[],
        )

        # In dry_run mode
        report = run_triage_agent(
            research_results=[research_result],
            dry_run=True,
        )

        self.assertEqual(len(report.notices), 1)
        notice = report.notices[0]
        # Flag must NOT be True!
        self.assertFalse(notice.no_known_vulnerability)
        # Checkpoint must NOT be deleted!
        self.assertGreater(len(notice.check_points), 0)
        self.assertIn("CVE-2026-50001", notice.check_points[0].target_or_cve)

        # Verifier must report 要確認, NEVER NO
        audit_res = verify_codebase(report, code_dir_path=str(self.code_dir))
        self.assertNotEqual(audit_res.overall_status, "NO (安全・確認済み)")
        self.assertIn("要確認", audit_res.overall_status)

    def test_unscanned_prefix_matching(self):
        """Opus issue 2 reproduction: unscanned component list with descriptive message.

        e.g. 'axios: 上位10件のみ詳細取得' must prevent axios from becoming no_known_vulnerability=True!
        """
        from triage_agent.agents.triage import run_triage_agent
        from triage_agent.schemas import ReconTarget, TargetResearchResult

        # Clean findings and clean osv_vuln_ids, BUT listed in unscanned items
        research_result = TargetResearchResult(
            target=ReconTarget(
                name="axios",
                version="1.7.2",
                ecosystem="npm",
                priority="HIGH",
                rationale="Test",
            ),
            findings=[],
            osv_vuln_ids=[],
            recon_notes="Partial scan",
            errors=[],
        )

        report = run_triage_agent(
            research_results=[research_result],
            unscanned_components=["axios: 上位10件のみ詳細取得（残り未取得）"],
            dry_run=True,
        )

        notice = report.notices[0] if report.notices else None
        if notice:
            self.assertFalse(notice.no_known_vulnerability)

    def test_export_checklist_scoped_announcement_date(self):
        """Opus issue 3 reproduction: export checklist scoped to target must use target's announcement date.

        When report contains nodejs (announced 2026-10-21) and axios (announced 2026-10-28),
        exporting with target_product='axios' must record announced_at='2026-10-28', NOT 2026-10-21!
        """
        from triage_agent.tools.vendor_workflow import export_checklist_csv

        metrics_file = self.code_dir / "workflow_metrics_scoped.json"
        report = TriageReport(
            report_title="Scoped Export Test",
            scan_target="test-repo",
            total_dependencies=2,
            notices=[
                TriageNotice(
                    product_name="nodejs",
                    component_name="nodejs",
                    announcement_date="2026-10-21",
                    conclusion="Node.js critical RCE",
                    fixed_versions="20.18.1",
                    severity_note="Critical",
                    check_points=[
                        CheckPointItem(
                            check_point_id="node-cp1",
                            target_or_cve="CVE-2026-111497",
                            cvss="9.8",
                            content_summary="Brotli",
                            affected_versions="< 20.18.1",
                            check_point_yes_no="brotli API を使用しているか",
                            verification_method="brotliDecompress を検索",
                        )
                    ],
                ),
                TriageNotice(
                    product_name="axios",
                    component_name="axios",
                    announcement_date="2026-10-28",
                    conclusion="Axios issue",
                    fixed_versions="1.7.3",
                    severity_note="Medium",
                    check_points=[
                        CheckPointItem(
                            check_point_id="axios-cp1",
                            target_or_cve="CVE-2026-50001",
                            cvss="5.3",
                            content_summary="Axios SSRF",
                            affected_versions="< 1.7.3",
                            check_point_yes_no="proxy 設定を使用しているか",
                            verification_method="proxy を検索",
                        )
                    ],
                ),
            ],
        )

        csv_file = self.code_dir / "axios_checklist.csv"
        _, _, dist_id = export_checklist_csv(
            report,
            output_path=str(csv_file),
            target_product="axios",
        )

        # Inspect generated workflow metric
        from triage_agent.tools.vendor_workflow import get_workflow_metrics
        # Metrics file is triage-output/workflow_metrics.json by default in export_checklist_csv
        metrics = get_workflow_metrics()
        dist_entry = metrics.get("distributions", {}).get(dist_id)
        self.assertIsNotNone(dist_entry)
        self.assertEqual(dist_entry["announced_at"], "2026-10-28")
        self.assertNotEqual(dist_entry["announced_at"], "2026-10-21")

    def test_uninvestigated_component_with_no_checkpoints_must_not_become_safe(self):
        """Case D (Opus latest review): An unverified / failed notice with empty check_points

        Must NEVER become safe (NO). It must be flagged as 要確認 (安全の根拠なし⚠️)!
        """
        report = TriageReport(
            report_title="Case D: Failed Investigation Test",
            scan_target="test-repo",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="failed-pkg（利用バージョン: 1.0.0）",
                    component_name="failed-pkg",
                    announcement_date="2026-10-31",
                    conclusion="調査エージェントが API 429 エラーで失敗したため、詳細を調査できませんでした。",
                    fixed_versions="未確認",
                    severity_note="要確認",
                    no_known_vulnerability=False,  # NOT confirmed clean!
                    check_points=[],  # LLM didn't create fake check points
                )
            ],
        )

        res = verify_codebase(report, code_dir_path=str(self.code_dir))
        # Must NOT be safe!
        self.assertNotEqual(res.overall_status, "NO (安全・確認済み)")
        self.assertIn("要確認", res.overall_status)
        self.assertEqual(res.summary_counts["safe_count"], 0)
        self.assertEqual(res.summary_counts["unverified_count"], 1)

        nr = res.notice_results[0]
        self.assertIn("要確認", nr.overall_status)
        self.assertIn("安全の根拠なし", nr.overall_status)


if __name__ == "__main__":
    unittest.main()
