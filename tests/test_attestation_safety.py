import json
from pathlib import Path
from triage_agent.schemas import TriageReport, TriageNotice, CheckPointItem
from triage_agent.verifier import verify_codebase

def test_attestation_safety():
    # Construct a dummy report with similar CVE numbers and version 1.0
    report = TriageReport(
        report_title="Test Report",
        report_version="1.0",
        is_dry_run=True,
        notices=[
            TriageNotice(
                product_name="test-product",
                announcement_date="2026-10-25",
                conclusion="Test conclusion",
                fixed_versions="2.0.0",
                severity_note="High",
                pre_check_note="Test note",
                check_points=[
                    # Target CVE
                    CheckPointItem(
                        check_point_id="test-cve-11149-cp1",
                        target_or_cve="CVE-2026-11149 (CVSS: 7.5 High)",
                        cvss="7.5 (High)",
                        content_summary="Original CVE",
                        affected_versions="< 1.0",
                        check_point_yes_no="設定Aを有効にしているか",
                        verification_method="search pattern A",
                    ),
                    # Longer CVE with prefix matching
                    CheckPointItem(
                        check_point_id="test-cve-111497-cp1",
                        target_or_cve="CVE-2026-111497 (CVSS: 9.8 Critical)",
                        cvss="9.8 (Critical)",
                        content_summary="Different longer CVE",
                        affected_versions="< 1.0",
                        check_point_yes_no="設定Bを有効にしているか",
                        verification_method="search pattern B",
                    ),
                ]
            )
        ]
    )

    # Test 1: Partial match should NOT match CVE-2026-111497 when signoff is for CVE-2026-11149
    audit_data_1 = {
        "attestations": [
            {
                "cve_id": "CVE-2026-11149",
                "check_point_yes_no": "設定Aを有効にしているか",
                "report_version": "1.0",
                "status": "NO (手動確認済み・非該当)",
                "reviewer": "Alice",
                "date": "2026-10-25",
                "evidence": "Config verified safe."
            }
        ]
    }
    Path("test_audit_1.json").write_text(json.dumps(audit_data_1))

    res1 = verify_codebase(report, "demo_app", "test_audit_1.json")
    results1 = res1.notice_results[0].results
    print("Test 1 - Check Point 1 status:", results1[0].status)
    print("Test 1 - Check Point 2 status:", results1[1].status)
    assert results1[0].status == "NO (手動確認済み・非該当)", "CP1 should match"
    assert "未検出" in results1[1].status or "要手動確認" in results1[1].status, "CP2 must NOT match CVE-2026-11149!"

    # Test 2: Mismatched report_version should be invalidated
    audit_data_2 = {
        "attestations": [
            {
                "check_point_id": "test-cve-11149-cp1",
                "report_version": "2.0",  # Mismatch! Report is 1.0
                "status": "NO (手動確認済み・非該当)",
                "reviewer": "Bob",
                "date": "2026-10-25",
                "evidence": "Outdated sign-off."
            }
        ]
    }
    Path("test_audit_2.json").write_text(json.dumps(audit_data_2))
    res2 = verify_codebase(report, "demo_app", "test_audit_2.json")
    results2 = res2.notice_results[0].results
    print("Test 2 - Check Point 1 status (mismatched version):", results2[0].status)
    assert "未検出" in results2[0].status or "要手動確認" in results2[0].status, "Mismatched version must not be accepted as safe!"

    # Test 3: Sign-off with status YES should NOT count as safe
    audit_data_3 = {
        "attestations": [
            {
                "check_point_id": "test-cve-11149-cp1",
                "report_version": "1.0",
                "status": "YES (該当している)",
                "reviewer": "Charlie",
                "date": "2026-10-25",
                "evidence": "Found in production environment."
            }
        ]
    }
    Path("test_audit_3.json").write_text(json.dumps(audit_data_3))
    res3 = verify_codebase(report, "demo_app", "test_audit_3.json")
    print("Test 3 - Overall status:", res3.overall_status)
    print("Test 3 - Safe count:", res3.summary_counts["safe_count"])
    assert res3.summary_counts["safe_count"] == 0, "status YES must not be safe_count"
    assert res3.overall_status.startswith("YES"), "overall_status must be YES"

    # Clean up test files
    Path("test_audit_1.json").unlink(missing_ok=True)
    Path("test_audit_2.json").unlink(missing_ok=True)
    Path("test_audit_3.json").unlink(missing_ok=True)

    print("\n>>> ALL SAFETY TESTS PASSED SUCCESSFULLY! <<<")

if __name__ == "__main__":
    test_attestation_safety()
