"""Tests for Contextual Attestation, Environment Scope, and TTL Expiration (v0.3.1 / ADR-019)."""

import json
from pathlib import Path
import tempfile
import unittest

from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport
from triage_agent.verifier.engine import verify_codebase
from triage_agent.verifier.models import AuditAttestation


class TestContextualAttestation(unittest.TestCase):
    """Test suite for contextual sign-off: environment filtering, evidence_type, and strict valid_until validation."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.code_dir = Path(self.tmp_dir.name)
        (self.code_dir / "index.js").write_text("console.log('clean app');", encoding="utf-8")

        self.report = TriageReport(
            report_title="Test Contextual Audit",
            scan_target="test-app",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="test-lib",
                    component_name="test-lib",
                    announcement_date="2026-10-25",
                    conclusion="Test conclusion",
                    fixed_versions="2.0.0",
                    severity_note="High",
                    check_points=[
                        CheckPointItem(
                            target_or_cve="CVE-2026-9999",
                            cvss="8.5",
                            content_summary="Test check",
                            affected_versions="< 2.0.0",
                            check_point_yes_no="Vulnerable feature enabled",
                            verification_method="Check configuration",
                            check_point_id="test-cp-ctx-1",
                        )
                    ],
                )
            ],
        )

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_attestation_ttl_not_expired(self):
        """A valid_until date in the future (e.g. 2099-12-31) must preserve NO (safe)."""
        audit_file = self.code_dir / "audit_valid.json"
        att = AuditAttestation(
            check_point_id="test-cp-ctx-1",
            status="NO (手動確認済み・非該当)",
            reviewer="SecOps Team",
            date="2026-10-25",
            evidence="Feature disabled in config",
            environment="Production",
            evidence_type="live_telemetry",
            valid_until="2099-12-31",
        )
        audit_file.write_text(json.dumps([att.model_dump()]), encoding="utf-8")

        res = verify_codebase(
            self.report,
            code_dir_path=str(self.code_dir),
            audit_file_path=str(audit_file),
            target_environment="Production",
        )
        cp_res = res.notice_results[0].results[0]

        self.assertIn("NO", cp_res.status)
        self.assertIn("安全確認済", cp_res.reasoning)
        self.assertEqual(cp_res.attestation.environment, "Production")
        self.assertEqual(cp_res.attestation.evidence_type, "live_telemetry")

    def test_attestation_ttl_expired_invalidation(self):
        """A valid_until date in the past (e.g. 2020-01-01) must automatically invalidate sign-off to 要再確認."""
        audit_file = self.code_dir / "audit_expired.json"
        att = AuditAttestation(
            check_point_id="test-cp-ctx-1",
            status="NO (手動確認済み・非該当)",
            reviewer="SecOps Team",
            date="2019-12-01",
            evidence="Old config verification",
            environment="Production",
            valid_until="2020-01-01",
        )
        audit_file.write_text(json.dumps([att.model_dump()]), encoding="utf-8")

        res = verify_codebase(self.report, code_dir_path=str(self.code_dir), audit_file_path=str(audit_file))
        cp_res = res.notice_results[0].results[0]

        self.assertIn("要再確認", cp_res.status)
        self.assertIn("サインオフ期限切れ", cp_res.status)
        self.assertIn("2020-01-01", cp_res.reasoning)

    def test_attestation_invalid_date_format_invalidation(self):
        """Unparseable valid_until formats (slash, text, next_major_release) must invalidate to 要再確認."""
        for bad_date in ["2026/01/31", "31 Jan 2026", "next_major_release", "unknown"]:
            audit_file = self.code_dir / f"audit_bad_{hash(bad_date)}.json"
            att = AuditAttestation(
                check_point_id="test-cp-ctx-1",
                status="NO (手動確認済み・非該当)",
                reviewer="SecOps Team",
                date="2026-10-25",
                evidence="Unclear format",
                valid_until=bad_date,
            )
            audit_file.write_text(json.dumps([att.model_dump()]), encoding="utf-8")

            res = verify_codebase(self.report, code_dir_path=str(self.code_dir), audit_file_path=str(audit_file))
            cp_res = res.notice_results[0].results[0]

            self.assertIn("要再確認", cp_res.status, f"Failed for bad format: {bad_date}")
            self.assertIn("形式不正", cp_res.status, f"Failed for bad format: {bad_date}")
            self.assertIn("分からないものを安全と言わない", cp_res.reasoning)

    def test_environment_mismatch_invalidation(self):
        """A sign-off designated for Staging must NOT be applied when verifying Production."""
        audit_file = self.code_dir / "audit_staging.json"
        att = AuditAttestation(
            check_point_id="test-cp-ctx-1",
            status="NO (手動確認済み・非該当)",
            reviewer="Dev Team",
            date="2026-10-25",
            evidence="Disabled in staging manifest",
            environment="Staging",
            valid_until="2099-12-31",
        )
        audit_file.write_text(json.dumps([att.model_dump()]), encoding="utf-8")

        res = verify_codebase(
            self.report,
            code_dir_path=str(self.code_dir),
            audit_file_path=str(audit_file),
            target_environment="Production",
        )
        cp_res = res.notice_results[0].results[0]

        self.assertIn("要再確認", cp_res.status)
        self.assertIn("環境不一致", cp_res.status)
        self.assertIn("Staging", cp_res.reasoning)
        self.assertIn("Production", cp_res.reasoning)

    def test_evidence_type_iac_config_label(self):
        """evidence_type == 'iac_config' must be clearly distinguished as 'NO (構成コード上・実機未確認)'."""
        audit_file = self.code_dir / "audit_iac.json"
        att = AuditAttestation(
            check_point_id="test-cp-ctx-1",
            status="NO (手動確認済み・非該当)",
            reviewer="DevOps Team",
            date="2026-10-25",
            evidence="K8s manifest has secure setting",
            environment="Production",
            evidence_type="iac_config",
            valid_until="2099-12-31",
        )
        audit_file.write_text(json.dumps([att.model_dump()]), encoding="utf-8")

        res = verify_codebase(
            self.report,
            code_dir_path=str(self.code_dir),
            audit_file_path=str(audit_file),
            target_environment="Production",
        )
        cp_res = res.notice_results[0].results[0]

        self.assertEqual(cp_res.status, "NO (構成コード上・実機未確認)")
        self.assertIn("構成コード上・実機未確認", cp_res.reasoning)


if __name__ == "__main__":
    unittest.main()
