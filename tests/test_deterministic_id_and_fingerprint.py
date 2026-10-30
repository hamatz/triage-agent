import json
from pathlib import Path
from triage_agent.schemas import (
    CheckPointItem,
    TriageNotice,
    TriageReport,
    compute_check_point_id,
    compute_notice_hash,
)
from triage_agent.verifier import verify_codebase

def test_deterministic_id_and_fingerprint():
    # 1. Test deterministic ID regardless of order
    q1 = "HTTP/2 を有効にしているか"
    q2 = "AJP コネクタを有効にしているか"

    cp1_id_order1 = compute_check_point_id("tomcat", "CVE-2026-0001", q1)
    cp2_id_order1 = compute_check_point_id("tomcat", "CVE-2026-0002", q2)

    # In edition 2, order is swapped
    cp2_id_order2 = compute_check_point_id("tomcat", "CVE-2026-0002", q2)
    cp1_id_order2 = compute_check_point_id("tomcat", "CVE-2026-0001", q1)

    assert cp1_id_order1 == cp1_id_order2, "ID for q1 must be identical across editions!"
    assert cp2_id_order1 == cp2_id_order2, "ID for q2 must be identical across editions!"
    print("✓ Test 1: Order-independent deterministic ID verified:", cp1_id_order1)

    # 2. Test Notice Fingerprint Hash (automatic invalidation on edition changes)
    cps_v1 = [
        CheckPointItem(
            check_point_id=cp1_id_order1,
            target_or_cve="CVE-2026-0001",
            cvss="7.5",
            content_summary="Vulnerability 1",
            affected_versions="< 11.0",
            check_point_yes_no=q1,
            verification_method="search http2",
        ),
        CheckPointItem(
            check_point_id=cp2_id_order1,
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

    assert hash_v1 != hash_v2, "Notice hash must change when check points change!"
    print(f"✓ Test 2: Notice fingerprint changes automatically (v1: {hash_v1} -> v2: {hash_v2})")

    # 3. Test Verifier Invalidation using notice_hash
    report_v2 = TriageReport(
        report_title="Report v2",
        report_version="1.0", # Note: even if manual report_version is NOT bumped!
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
                "check_point_id": cp1_id_order1,
                "notice_hash": hash_v1, # Outdated fingerprint from edition 1!
                "status": "NO (手動確認済み・非該当)",
                "reviewer": "Alice",
                "date": "2026-10-25",
                "evidence": "Signed off on edition 1"
            }
        ]
    }
    audit_path = Path("test_outdated_audit.json")
    audit_path.write_text(json.dumps(audit_data))

    res = verify_codebase(report_v2, "demo_app", str(audit_path))
    audit_path.unlink(missing_ok=True)

    # cp1 must NOT be accepted as safe because notice_hash mismatched!
    cp1_status = res.notice_results[0].results[0].status
    print("Status of cp1 with outdated notice_hash:", cp1_status)
    assert "未検出" in cp1_status or "要手動確認" in cp1_status, "Must be invalidated when notice_hash mismatches!"

    print("\n>>> ALL DETERMINISTIC ID & FINGERPRINT TESTS PASSED! <<<")

if __name__ == "__main__":
    test_deterministic_id_and_fingerprint()
