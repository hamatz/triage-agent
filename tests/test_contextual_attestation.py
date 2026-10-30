"""Tests for Contextual Attestation and TTL Expiration (v0.3.1 / ADR-019)."""

import json
from pathlib import Path
import tempfile
import unittest

from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport
from triage_agent.verifier.engine import verify_codebase
from triage_agent.verifier.models import AuditAttestation


class TestContextualAttestation(unittest.TestCase):
    """Test suite for contextual sign-off: environment, evidence_type, and valid_until TTL expiration."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.code_dir = Path(self.tmp_dir.name)
        # Create a clean dummy codebase with no vulnerability
        (self.code_dir / "index.js").write_text("console.log('clean app');", encoding="utf-8")

        self.report = TriageReport(
            report_title="Test TTL Audit",
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
                            check_point_id="test-cp-ttl-1",
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
            check_point_id="test-cp-ttl-1",
            status="NO (手動確認済み・非該当)",
            reviewer="SecOps Team",
            date="2026-10-25",
            evidence="Feature disabled in config",
            environment="Production",
            evidence_type="iac_config",
            valid_until="2099-12-31",
        )
        audit_file.write_text(json.dumps([att.model_dump()]), encoding="utf-8")

        res = verify_codebase(self.report, code_dir_path=str(self.code_dir), audit_file_path=str(audit_file))
        cp_res = res.notice_results[0].results[0]

        self.assertIn("NO", cp_res.status)
        self.assertIn("安全確認済", cp_res.reasoning)
        self.assertEqual(cp_res.attestation.environment, "Production")
        self.assertEqual(cp_res.attestation.evidence_type, "iac_config")

    def test_attestation_ttl_expired_invalidation(self):
        """A valid_until date in the past (e.g. 2020-01-01) must automatically invalidate sign-off to 要再確認."""
        audit_file = self.code_dir / "audit_expired.json"
        att = AuditAttestation(
            check_point_id="test-cp-ttl-1",
            status="NO (手動確認済み・非該当)",
            reviewer="SecOps Team",
            date="2019-12-01",
            evidence="Old config verification",
            environment="Production",
            evidence_type="iac_config",
            valid_until="2020-01-01",
        )
        audit_file.write_text(json.dumps([att.model_dump()]), encoding="utf-8")

        res = verify_codebase(self.report, code_dir_path=str(self.code_dir), audit_file_path=str(audit_file))
        cp_res = res.notice_results[0].results[0]

        self.assertIn("要再確認", cp_res.status)
        self.assertIn("サインオフ期限切れ", cp_res.status)
        self.assertIn("2020-01-01", cp_res.reasoning)
        self.assertIn("自動失効", cp_res.reasoning)


if __name__ == "__main__":
    unittest.main()
