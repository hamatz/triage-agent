import json
import tempfile
import unittest
from pathlib import Path

from triage_agent.schemas import (
    CheckPointItem,
    TriageNotice,
    TriageReport,
    compute_check_point_id,
    compute_notice_hash,
)
from triage_agent.verifier import verify_codebase


class TestDeterministicIdAndFingerprint(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.tmppath = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_deterministic_id_regardless_of_order(self):
        """Test deterministic ID calculation is order-independent across editions."""
        q1 = "HTTP/2 を有効にしているか"
        q2 = "AJP コネクタを有効にしているか"

        cp1_id_order1 = compute_check_point_id("tomcat", "CVE-2026-0001", q1)
        cp2_id_order1 = compute_check_point_id("tomcat", "CVE-2026-0002", q2)

        # In edition 2, order is swapped
        cp2_id_order2 = compute_check_point_id("tomcat", "CVE-2026-0002", q2)
        cp1_id_order2 = compute_check_point_id("tomcat", "CVE-2026-0001", q1)

        self.assertEqual(cp1_id_order1, cp1_id_order2, "ID for q1 must be identical across editions!")
        self.assertEqual(cp2_id_order1, cp2_id_order2, "ID for q2 must be identical across editions!")

    def test_notice_fingerprint_hash_invalidation(self):
        """Test Notice Fingerprint Hash changes and invalidates outdated attestations automatically."""
        q1 = "HTTP/2 を有効にしているか"
        q2 = "AJP コネクタを有効にしているか"

        cp1_id = compute_check_point_id("tomcat", "CVE-2026-0001", q1)
        cp2_id = compute_check_point_id("tomcat", "CVE-2026-0002", q2)

        cps_v1 = [
            CheckPointItem(
                check_point_id=cp1_id,
                target_or_cve="CVE-2026-0001",
                cvss="7.5",
                content_summary="Vulnerability 1",
                affected_versions="< 11.0",
                check_point_yes_no=q1,
                verification_method="search http2",
            ),
            CheckPointItem(
                check_point_id=cp2_id,
                target_or_cve="CVE-2026-0002",
                cvss="7.5",
                content_summary="Vulnerability 2",
                affected_versions="< 11.0",
                check_point_yes_no=q2,
                verification_method="search ajp",
            ),
        ]
        hash_v1 = compute_notice_hash(cps_v1)

        # Edition 2 adds a 3rd check point (e.g. JNDIRealm)
        q3 = "JNDIRealm を使っているか"
        cp3_id = compute_check_point_id("tomcat", "CVE-2026-0003", q3)
        cps_v2 = cps_v1 + [
            CheckPointItem(
                check_point_id=cp3_id,
                target_or_cve="CVE-2026-0003",
                cvss="8.1",
                content_summary="Vulnerability 3",
                affected_versions="< 11.0",
                check_point_yes_no=q3,
                verification_method="search jndirealm",
            )
        ]
        hash_v2 = compute_notice_hash(cps_v2)

        self.assertNotEqual(hash_v1, hash_v2, "Notice hash must change when check points change!")

        # Test Verifier Invalidation using notice_hash
        report_v2 = TriageReport(
            report_title="Report v2",
            report_version="1.0",
            notices=[
                TriageNotice(
                    product_name="tomcat",
                    notice_hash=hash_v2,
                    announcement_date="2026-10-25",
                    conclusion="Conclusion",
                    fixed_versions="11.0.27",
                    severity_note="High",
                    check_points=cps_v2,
                )
            ]
        )

        # Outdated sign-off containing hash_v1
        audit_data = {
            "attestations": [
                {
                    "check_point_id": cp1_id,
                    "notice_hash": hash_v1,  # Outdated fingerprint from edition 1!
                    "status": "NO (手動確認済み・非該当)",
                    "reviewer": "Alice",
                    "date": "2026-10-25",
                    "evidence": "Signed off on edition 1"
                }
            ]
        }
        audit_path = self.tmppath / "test_outdated_audit.json"
        audit_path.write_text(json.dumps(audit_data), encoding="utf-8")

        res = verify_codebase(report_v2, "demo_app", str(audit_path))
        cp1_status = res.notice_results[0].results[0].status
        self.assertTrue(
            "未検出" in cp1_status or "要手動確認" in cp1_status,
            "Must be invalidated when notice_hash mismatches!"
        )


if __name__ == "__main__":
    unittest.main()
