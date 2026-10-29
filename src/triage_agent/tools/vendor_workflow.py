"""Vendor collaboration workflow: CSV/Excel checklist export, import, and round-trip metrics (ADR-019).

Facilitates bidirectional communication between cybersecurity teams, IT ops, and external software vendors.
Tracks time metrics (distribution, turnaround, roundtrips) to demonstrate quantifiable PoC value.
"""

import csv
import io
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from triage_agent.schemas import TriageReport
from triage_agent.verifier.models import AttestationFile, AuditAttestation


CHECKLIST_HEADERS = [
    "No",
    "CheckPointID",
    "対象製品/ライブラリ",
    "CVE/対象識別子",
    "深刻度/CVSS",
    "確認ポイント (Yes/No)",
    "確認方法 (設定・コード・コマンド)",
    "ベンダー回答 (YES/NO/要確認)",
    "確認根拠/設定箇所",
    "確認者 (会社名・氏名)",
    "確認日 (YYYY-MM-DD)",
]


def export_checklist_csv(
    report: TriageReport,
    output_path: Optional[str] = None
) -> Tuple[str, Path]:
    """Export the triage report quick-check table into a structured CSV for vendor inquiry."""
    rows = []
    idx = 1

    for notice in report.notices:
        prod_name = notice.product_name or notice.component_name or "Unknown"
        for cp in notice.check_points:
            cp_id = cp.check_point_id or f"{notice.component_name or 'target'}-{idx}"
            rows.append({
                "No": str(idx),
                "CheckPointID": cp_id,
                "対象製品/ライブラリ": prod_name,
                "CVE/対象識別子": cp.target_or_cve,
                "深刻度/CVSS": cp.cvss or notice.severity_note or "",
                "確認ポイント (Yes/No)": cp.check_point_yes_no,
                "確認方法 (設定・コード・コマンド)": cp.verification_method,
                "ベンダー回答 (YES/NO/要確認)": "",  # To be filled by vendor
                "確認根拠/設定箇所": "",             # To be filled by vendor
                "確認者 (会社名・氏名)": "",         # To be filled by vendor
                "確認日 (YYYY-MM-DD)": "",          # To be filled by vendor
            })
            idx += 1

    # Output CSV string
    output_io = io.StringIO()
    # Write UTF-8 BOM so Excel opens it with Japanese correctly without garbled text
    output_io.write("\ufeff")
    writer = csv.DictWriter(output_io, fieldnames=CHECKLIST_HEADERS)
    writer.writeheader()
    writer.writerows(rows)
    csv_text = output_io.getvalue()

    if output_path is None:
        safe_name = (report.scan_target or "triage").replace("/", "_").replace("\\", "_")
        target_path = Path("triage-output") / f"{safe_name}_vendor_checklist.csv"
    else:
        target_path = Path(output_path).resolve()

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(csv_text, encoding="utf-8")

    # Record distribution metric
    record_workflow_event("vendor_checklist_exported", {
        "file_path": str(target_path),
        "check_points_count": len(rows),
        "report_title": report.report_title,
    })

    return csv_text, target_path


def import_vendor_checklist(
    csv_path: str,
    audit_file_path: Optional[str] = None
) -> Tuple[int, Path]:
    """Parse vendor filled CSV and update audit_signoff.json with attestations."""
    p = Path(csv_path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Checklist CSV not found: {csv_path}")

    # Read with utf-8-sig to automatically handle BOM if present
    content = p.read_text(encoding="utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))

    new_attestations: List[AuditAttestation] = []
    today_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    for row in reader:
        ans = (row.get("ベンダー回答 (YES/NO/要確認)") or "").strip()
        if not ans:
            continue

        cp_id = (row.get("CheckPointID") or "").strip()
        cve_id = (row.get("CVE/対象識別子") or "").strip()
        reviewer = (row.get("確認者 (会社名・氏名)") or "委託先ベンダー").strip()
        evidence = (row.get("確認根拠/設定箇所") or "ベンダー回答CSVによる確認").strip()
        date_val = (row.get("確認日 (YYYY-MM-DD)") or today_str).strip()

        # Normalize status
        ans_upper = ans.upper()
        if ans_upper.startswith("NO") or "安全" in ans or "非該当" in ans:
            status = "NO (ベンダー回答・非該当)"
        elif ans_upper.startswith("YES") or "該当" in ans:
            status = "YES (ベンダー回答・該当あり)"
        else:
            status = f"要確認 (ベンダー回答: {ans})"

        att = AuditAttestation(
            check_point_id=cp_id or None,
            cve_id=cve_id or None,
            status=status,
            reviewer=reviewer,
            date=date_val,
            evidence=evidence,
        )
        new_attestations.append(att)

    if not new_attestations:
        target_audit_path = Path(audit_file_path) if audit_file_path else Path("audit_signoff.json")
        return 0, target_audit_path

    # Merge into target audit file
    target_audit_path = Path(audit_file_path).resolve() if audit_file_path else Path("audit_signoff.json").resolve()
    existing_attestations = []

    if target_audit_path.exists():
        try:
            data = json.loads(target_audit_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "attestations" in data:
                existing_attestations = [AuditAttestation(**item) for item in data["attestations"]]
            elif isinstance(data, list):
                existing_attestations = [AuditAttestation(**item) for item in data]
        except Exception:
            existing_attestations = []

    # Map existing by check_point_id or cve_id to update without duplicating
    merged: Dict[str, AuditAttestation] = {}
    for att in existing_attestations:
        key = att.check_point_id or att.cve_id or att.target_or_cve or str(id(att))
        merged[key] = att

    for att in new_attestations:
        key = att.check_point_id or att.cve_id or att.target_or_cve or str(id(att))
        merged[key] = att

    updated_file = AttestationFile(attestations=list(merged.values()))
    target_audit_path.parent.mkdir(parents=True, exist_ok=True)
    target_audit_path.write_text(
        json.dumps(updated_file.model_dump(), indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    # Record workflow round-trip metric
    record_workflow_event("vendor_checklist_imported", {
        "file_path": str(p),
        "imported_count": len(new_attestations),
        "total_attestations": len(merged),
    })

    return len(new_attestations), target_audit_path


def record_workflow_event(event_type: str, details: Dict[str, Any], metrics_file: str = "triage-output/workflow_metrics.json") -> None:
    """Record timestamped workflow events to measure PoC turnaround metrics (ADR-019)."""
    p = Path(metrics_file).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)

    metrics = {
        "version": "1.0",
        "events": [],
        "summary": {
            "total_exports": 0,
            "total_imports": 0,
            "roundtrip_count": 0,
            "first_export_time": None,
            "last_import_time": None,
            "turnaround_hours": None,
        }
    }

    if p.exists():
        try:
            loaded = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and "events" in loaded:
                metrics = loaded
        except Exception:
            pass

    event_record = {
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details,
    }
    metrics["events"].append(event_record)

    # Update summary
    exports = [e for e in metrics["events"] if e["event_type"] == "vendor_checklist_exported"]
    imports = [e for e in metrics["events"] if e["event_type"] == "vendor_checklist_imported"]

    metrics["summary"]["total_exports"] = len(exports)
    metrics["summary"]["total_imports"] = len(imports)
    metrics["summary"]["roundtrip_count"] = min(len(exports), len(imports))

    if exports:
        metrics["summary"]["first_export_time"] = exports[0]["timestamp"]
    if imports:
        metrics["summary"]["last_import_time"] = imports[-1]["timestamp"]

    if exports and imports:
        try:
            t0 = datetime.fromisoformat(exports[0]["timestamp"])
            t1 = datetime.fromisoformat(imports[-1]["timestamp"])
            delta_seconds = (t1 - t0).total_seconds()
            metrics["summary"]["turnaround_hours"] = round(delta_seconds / 3600.0, 2)
        except Exception:
            pass

    p.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")


def get_workflow_metrics(metrics_file: str = "triage-output/workflow_metrics.json") -> Dict[str, Any]:
    """Retrieve current workflow metrics summary."""
    p = Path(metrics_file).resolve()
    if not p.exists():
        return {
            "total_exports": 0,
            "total_imports": 0,
            "roundtrip_count": 0,
            "turnaround_hours": None
        }
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data.get("summary", {})
    except Exception:
        return {}
