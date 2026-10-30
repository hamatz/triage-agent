"""Vendor collaboration workflow: CSV/Excel checklist export, import, and round-trip metrics (ADR-019).

Facilitates bidirectional communication between cybersecurity teams, IT ops, and external software vendors.
Protects against formula injection, ensures strict answer validation, prevents attestation loss,
preserves internal YES findings against vendor downgrades, and tracks quantifiable PoC metrics per distribution ID.
"""

import csv
import io
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from triage_agent.schemas import TriageReport
from triage_agent.verifier.models import AttestationFile, AuditAttestation

CHECKLIST_HEADERS = [
    "DistributionID",
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

# Strict answer sets to prevent ambiguous prefix/substring matching
ALLOWED_NO_ANSWERS: Set[str] = {
    "NO", "非該当", "該当なし", "SAFE", "FALSE", "0", "安全", "対象外"
}

ALLOWED_YES_ANSWERS: Set[str] = {
    "YES", "該当", "該当あり", "VULNERABLE", "TRUE", "1", "要対応"
}


def sanitize_csv_cell(val: Any) -> str:
    """Sanitize cell value to prevent CSV Formula Injection in Microsoft Excel."""
    s = str(val) if val is not None else ""
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


def generate_distribution_id(report_title: str) -> str:
    """Generate a unique tracking distribution ID for each vendor checklist export."""
    now_tag = datetime.now(timezone.utc).strftime("%Y%m%d")
    rnd = secrets.token_hex(3)
    return f"DIST-{now_tag}-{rnd}"


def export_checklist_csv(
    report: TriageReport,
    output_path: Optional[str] = None,
    target_product: Optional[str] = None,
    target_component: Optional[str] = None,
) -> Tuple[str, Path, str]:
    """Export the triage report quick-check table into a structured CSV for vendor inquiry.
    
    Supports target-specific scoping to prevent leaking full system attack maps (ADR-013).
    Escapes formula injection characters. Emits a unique DistributionID for lifecycle tracking.
    
    Returns:
        Tuple of (csv_text, target_path, distribution_id)
    """
    distribution_id = generate_distribution_id(report.report_title)
    rows = []
    idx = 1

    target_prod_lower = target_product.strip().lower() if target_product else None
    target_comp_lower = target_component.strip().lower() if target_component else None

    for notice in report.notices:
        prod_name = notice.product_name or notice.component_name or "Unknown"
        comp_name = notice.component_name or ""

        # Exact matching for scoping to prevent leaking other vendors' components (e.g. 'node' shouldn't match 'node-forge')
        if target_prod_lower:
            prod_clean = prod_name.lower().strip()
            prod_words = [w.strip() for w in prod_clean.split()]
            if target_prod_lower != prod_clean and target_prod_lower not in prod_words:
                continue
        if target_comp_lower and target_comp_lower != comp_name.lower().strip():
            continue

        for cp in notice.check_points:
            cp_id = cp.check_point_id or f"{notice.component_name or 'target'}-{idx}"
            rows.append({
                "DistributionID": distribution_id,
                "No": str(idx),
                "CheckPointID": sanitize_csv_cell(cp_id),
                "対象製品/ライブラリ": sanitize_csv_cell(prod_name),
                "CVE/対象識別子": sanitize_csv_cell(cp.target_or_cve),
                "深刻度/CVSS": sanitize_csv_cell(cp.cvss or notice.severity_note or ""),
                "確認ポイント (Yes/No)": sanitize_csv_cell(cp.check_point_yes_no),
                "確認方法 (設定・コード・コマンド)": sanitize_csv_cell(cp.verification_method),
                "ベンダー回答 (YES/NO/要確認)": "",  # To be filled by vendor
                "確認根拠/設定箇所": "",             # To be filled by vendor
                "確認者 (会社名・氏名)": "",         # To be filled by vendor
                "確認日 (YYYY-MM-DD)": "",          # To be filled by vendor
            })
            idx += 1

    # Output CSV string with UTF-8 BOM
    output_io = io.StringIO()
    output_io.write("\ufeff")
    writer = csv.DictWriter(output_io, fieldnames=CHECKLIST_HEADERS)
    writer.writeheader()
    writer.writerows(rows)
    csv_text = output_io.getvalue()

    if output_path is None:
        scope_tag = f"_{target_prod_lower}" if target_prod_lower else ""
        safe_name = (report.scan_target or "triage").replace("/", "_").replace("\\", "_")
        target_path = Path("triage-output") / f"{safe_name}{scope_tag}_vendor_checklist.csv"
    else:
        target_path = Path(output_path).resolve()

    target_path.parent.mkdir(parents=True, exist_ok=True)
    target_path.write_text(csv_text, encoding="utf-8")

    # Record distribution metric
    ann_date = None
    for n in report.notices:
        if n.announcement_date:
            ann_date = n.announcement_date
            break

    record_workflow_event("vendor_checklist_exported", {
        "distribution_id": distribution_id,
        "file_path": str(target_path),
        "target_product": target_product,
        "check_points_count": len(rows),
        "report_title": report.report_title,
        "announced_at": ann_date,
    })

    return csv_text, target_path, distribution_id


def import_vendor_checklist(
    csv_path: str,
    audit_file_path: Optional[str] = None,
    source_audit_path: Optional[str] = None,
) -> Tuple[int, Path, Dict[str, Any]]:
    """Parse vendor filled CSV and update audit_signoff.json with attestations.
    
    Strictly validates responses:
    - Only exact matches in ALLOWED_NO_ANSWERS count as NO, and ONLY IF both reviewer and evidence are present.
    - Ambiguous phrases ('Not sure', 'No idea', 'NOT CHECKED YET', '安全かどうか未確認') become '要確認'.
    - Existing attestations are never silently deleted on parse failure (fails fast to protect data).
    - Internal YES cannot be silently overwritten by vendor NO (flags conflict) or downgraded by '要確認' (preserves YES).
    - Maintains a full audit history trail across round-trips.
    - When writing to triage-output/ for the first time, seamlessly migrates and merges from existing root audit sign-off.
    """
    p = Path(csv_path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Checklist CSV not found: {csv_path}")

    content = p.read_text(encoding="utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))

    new_attestations: List[AuditAttestation] = []
    distribution_ids: Set[str] = set()
    warnings: List[str] = []
    no_held_count = 0  # Count of NO answers demoted to '要確認' due to missing reviewer/evidence

    import_timestamp = datetime.now(timezone.utc).isoformat()

    for row in reader:
        ans_raw = (row.get("ベンダー回答 (YES/NO/要確認)") or "").strip()
        dist_id = (row.get("DistributionID") or "").strip()
        if dist_id:
            distribution_ids.add(dist_id)

        if not ans_raw:
            continue

        cp_id = (row.get("CheckPointID") or "").strip().lstrip("'")
        cve_id = (row.get("CVE/対象識別子") or "").strip().lstrip("'")
        reviewer = (row.get("確認者 (会社名・氏名)") or "").strip()
        evidence = (row.get("確認根拠/設定箇所") or "").strip()
        date_val = (row.get("確認日 (YYYY-MM-DD)") or "").strip()

        # Strict exact match evaluation
        ans_clean = ans_raw.upper()
        if ans_clean in ALLOWED_NO_ANSWERS:
            # NO requires BOTH reviewer and evidence to prevent unverified attestations
            if reviewer and evidence:
                status = "NO (ベンダー回答・非該当)"
            else:
                missing_parts = []
                if not reviewer:
                    missing_parts.append("確認者未記入")
                if not evidence:
                    missing_parts.append("根拠未記入")
                status = f"要確認 (ベンダーNO回答保留: {', '.join(missing_parts)})"
                no_held_count += 1
        elif ans_clean in ALLOWED_YES_ANSWERS:
            status = "YES (ベンダー回答・該当あり)"
        else:
            status = f"要確認 (ベンダー回答: {ans_raw})"

        att = AuditAttestation(
            check_point_id=cp_id or None,
            cve_id=cve_id or None,
            status=status,
            reviewer=reviewer or "未記入",
            date=date_val or import_timestamp[:10],
            evidence=evidence or "未記入",
            history=[],
        )
        new_attestations.append(att)

    target_audit_path = Path(audit_file_path).resolve() if audit_file_path else Path("audit_signoff.json").resolve()

    if len(distribution_ids) > 1:
        warnings.append(f"単一CSV内に複数の配布IDが混在しています: {', '.join(sorted(distribution_ids))}")

    # Determine which file to load existing attestations from.
    # If target (e.g. in triage-output/) doesn't exist yet, look for source_audit_path or root workspace file.
    read_path: Optional[Path] = None
    migrated_notice: Optional[str] = None

    if target_audit_path.exists():
        read_path = target_audit_path
    elif source_audit_path and Path(source_audit_path).resolve().exists():
        read_path = Path(source_audit_path).resolve()
        migrated_notice = f"既存のサインオフ '{read_path.name}' を読み込み、{target_audit_path.parent.name}/{target_audit_path.name} に移行・統合しました。"
    else:
        root_candidate = (Path.cwd() / target_audit_path.name).resolve()
        if root_candidate != target_audit_path and root_candidate.exists():
            read_path = root_candidate
            migrated_notice = f"既存のサインオフ '{root_candidate.name}' を読み込み、{target_audit_path.parent.name}/{target_audit_path.name} に移行・統合しました。"

    if migrated_notice:
        warnings.append(migrated_notice)

    if not new_attestations:
        return 0, target_audit_path, {
            "imported_count": 0,
            "no_held_count": 0,
            "conflict_count": 0,
            "warnings": warnings,
        }

    # Load existing audit file safely. Fail-fast if file exists but is corrupted.
    existing_attestations: List[AuditAttestation] = []
    if read_path and read_path.exists():
        raw_text = read_path.read_text(encoding="utf-8")
        if raw_text.strip():
            try:
                data = json.loads(raw_text)
                if isinstance(data, dict) and "attestations" in data:
                    existing_attestations = [AuditAttestation(**item) for item in data["attestations"]]
                elif isinstance(data, list):
                    existing_attestations = [AuditAttestation(**item) for item in data]
                else:
                    raise ValueError("Unexpected JSON format in audit signoff file")
            except Exception as e:
                # Do NOT silently drop or overwrite corrupted existing attestations!
                raise ValueError(
                    f"既存の監査サインオフファイル '{read_path}' の解析に失敗しました ({e})。"
                    f"既存データの消失・破壊を防ぐため、取り込み処理を中止します。"
                ) from e

    # Merge while guarding against conflict and preserving internal findings
    conflict_count = 0
    merged: Dict[str, AuditAttestation] = {}
    for att in existing_attestations:
        key = att.check_point_id or att.cve_id or att.target_or_cve or str(id(att))
        merged[key] = att

    for att in new_attestations:
        key = att.check_point_id or att.cve_id or att.target_or_cve or str(id(att))
        existing_item = merged.get(key)

        if existing_item:
            existing_status = existing_item.status.upper()
            new_status = att.status.upper()

            # Record prior attestation snapshot in history
            hist = list(existing_item.history or [])
            hist.append({
                "recorded_at": import_timestamp,
                "status": existing_item.status,
                "reviewer": existing_item.reviewer,
                "date": existing_item.date,
                "evidence": existing_item.evidence,
            })
            att.history = hist

            # Guard 1: If internal audit already identified YES, vendor NO must not silently overwrite it!
            if "YES" in existing_status and "NO" in new_status:
                conflict_count += 1
                att.status = "要再確認 (社内YESとベンダーNOの競合⚠️)"
                att.evidence = (
                    f"【競合検知】社内判断（{existing_item.status}: {existing_item.evidence}）に対し、"
                    f"ベンダーより非該当回答（{att.evidence}）を受領しました。人手による精査が必要です。"
                )
            # Guard 2: If internal audit already identified YES, vendor '要確認' (unknown/not checked) must NOT downgrade YES!
            elif "YES" in existing_status and "YES" not in new_status:
                vendor_status = att.status
                att.status = existing_item.status
                att.evidence = (
                    f"{existing_item.evidence} "
                    f"（※ベンダー回答: {vendor_status} / {att.reviewer}: {att.evidence} - 社内該当確認済のためYES維持）"
                )

        merged[key] = att

    updated_file = AttestationFile(attestations=list(merged.values()))
    target_audit_path.parent.mkdir(parents=True, exist_ok=True)
    target_audit_path.write_text(
        json.dumps(updated_file.model_dump(), indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    primary_dist_id = sorted(distribution_ids)[0] if distribution_ids else None

    # Record workflow round-trip metric
    record_workflow_event("vendor_checklist_imported", {
        "distribution_id": primary_dist_id,
        "file_path": str(p),
        "imported_count": len(new_attestations),
        "no_held_count": no_held_count,
        "conflict_count": conflict_count,
        "warnings": warnings,
        "total_attestations": len(merged),
    })

    summary_info = {
        "imported_count": len(new_attestations),
        "no_held_count": no_held_count,
        "conflict_count": conflict_count,
        "distribution_id": primary_dist_id,
        "warnings": warnings,
    }

    return len(new_attestations), target_audit_path, summary_info


def record_workflow_event(event_type: str, details: Dict[str, Any], metrics_file: str = "triage-output/workflow_metrics.json") -> None:
    """Record lifecycle metrics event to track timeline T(-1) to T(4), turnaround, and off-hours (v0.3.1)."""
    from triage_agent.tools.lifecycle_metrics import calculate_case_metrics, is_off_hours_jst

    p = Path(metrics_file).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)

    metrics: Dict[str, Any] = {
        "version": "1.2",
        "events": [],
        "distributions": {},
        "summary": {
            "total_exports": 0,
            "total_imports": 0,
            "total_distributions": 0,
            "total_off_hours_events": 0,
            "average_turnaround_hours": None,
            "average_announce_to_dispatch_hours": None,
        }
    }

    if p.exists():
        try:
            loaded = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and "events" in loaded:
                metrics = loaded
                if "distributions" not in metrics:
                    metrics["distributions"] = {}
                if "summary" not in metrics:
                    metrics["summary"] = {}
        except Exception:
            pass

    now_dt = datetime.now(timezone.utc)
    event_record = {
        "event_type": event_type,
        "timestamp": now_dt.isoformat(),
        "is_off_hours": is_off_hours_jst(now_dt),
        "details": details,
    }
    metrics["events"].append(event_record)

    # Update distribution-specific tracking
    dist_id = details.get("distribution_id")
    if dist_id:
        if dist_id not in metrics["distributions"]:
            metrics["distributions"][dist_id] = {
                "distribution_id": dist_id,
                "announced_at": details.get("announced_at"),
                "exported_at": None,
                "target_product": details.get("target_product"),
                "check_points_count": details.get("check_points_count", 0),
                "imported_at": None,
                "import_count": 0,
                "lead_time_announce_to_dispatch_hours": None,
                "turnaround_hours": None,
                "total_lead_time_hours": None,
                "lead_time_saved_hours": None,
                "status": "exported",
            }

        dist_entry = metrics["distributions"][dist_id]
        if details.get("announced_at") and not dist_entry.get("announced_at"):
            dist_entry["announced_at"] = details.get("announced_at")

        if event_type == "vendor_checklist_exported":
            dist_entry["exported_at"] = event_record["timestamp"]
            dist_entry["check_points_count"] = details.get("check_points_count", dist_entry["check_points_count"])
            dist_entry["target_product"] = details.get("target_product", dist_entry["target_product"])
        elif event_type == "vendor_checklist_imported":
            dist_entry["imported_at"] = event_record["timestamp"]
            dist_entry["import_count"] = dist_entry.get("import_count", 0) + 1
            dist_entry["status"] = "imported"

        # Calculate metrics using lifecycle_metrics engine
        case_calc = calculate_case_metrics(
            t_minus_1_announced=dist_entry.get("announced_at"),
            t2_dispatched=dist_entry.get("exported_at"),
            t3_attested=dist_entry.get("imported_at"),
        )
        dist_entry["lead_time_announce_to_dispatch_hours"] = case_calc["lead_time_announce_to_dispatch_hours"]
        dist_entry["turnaround_hours"] = case_calc["turnaround_dispatch_to_attest_hours"]
        dist_entry["total_lead_time_hours"] = case_calc["total_lead_time_hours"]
        dist_entry["lead_time_saved_hours"] = case_calc["lead_time_saved_hours"]

    # Global summary
    exports = [e for e in metrics["events"] if e.get("event_type") == "vendor_checklist_exported"]
    imports = [e for e in metrics["events"] if e.get("event_type") == "vendor_checklist_imported"]
    off_hours = [e for e in metrics["events"] if e.get("is_off_hours")]

    turnarounds = [
        d["turnaround_hours"] for d in metrics["distributions"].values()
        if d.get("turnaround_hours") is not None
    ]
    dispatch_leads = [
        d["lead_time_announce_to_dispatch_hours"] for d in metrics["distributions"].values()
        if d.get("lead_time_announce_to_dispatch_hours") is not None
    ]

    metrics["summary"]["total_exports"] = len(exports)
    metrics["summary"]["total_imports"] = len(imports)
    metrics["summary"]["total_distributions"] = len(metrics["distributions"])
    metrics["summary"]["total_off_hours_events"] = len(off_hours)
    metrics["summary"]["average_turnaround_hours"] = (
        round(sum(turnarounds) / len(turnarounds), 2) if turnarounds else None
    )
    metrics["summary"]["average_announce_to_dispatch_hours"] = (
        round(sum(dispatch_leads) / len(dispatch_leads), 2) if dispatch_leads else None
    )

    p.write_text(json.dumps(metrics, indent=2, ensure_ascii=False), encoding="utf-8")


def get_workflow_metrics(metrics_file: str = "triage-output/workflow_metrics.json") -> Dict[str, Any]:
    """Retrieve current workflow metrics summary and distribution breakdowns."""
    p = Path(metrics_file).resolve()
    if not p.exists():
        return {
            "total_exports": 0,
            "total_imports": 0,
            "total_distributions": 0,
            "distributions": {},
        }
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        summary = data.get("summary", {})
        summary["distributions"] = data.get("distributions", {})
        return summary
    except Exception:
        return {}


def record_remediation_completed(
    distribution_id: str,
    remediated_at: Optional[str] = None,
    note: Optional[str] = None,
    metrics_file: str = "triage-output/workflow_metrics.json",
) -> Dict[str, Any]:
    """Manually record T4 remediation / patch deployment completion timestamp for a distribution ID (ADR-019 / v0.3.1)."""
    from triage_agent.tools.lifecycle_metrics import calculate_case_metrics, load_user_baselines

    p = Path(metrics_file).resolve()
    if not p.exists():
        raise FileNotFoundError(f"Workflow metrics file not found: {metrics_file}")

    data = json.loads(p.read_text(encoding="utf-8"))
    dists = data.get("distributions", {})
    if distribution_id not in dists:
        raise KeyError(f"Distribution ID '{distribution_id}' not found in workflow metrics.")

    dist_entry = dists[distribution_id]
    ts = remediated_at or datetime.now(timezone.utc).isoformat()
    dist_entry["remediated_at"] = ts
    dist_entry["remediation_note"] = note
    dist_entry["status"] = "remediated"

    # Recalculate metrics with T4 and user baselines
    user_baselines = load_user_baselines()
    case_calc = calculate_case_metrics(
        t_minus_1_announced=dist_entry.get("announced_at"),
        t2_dispatched=dist_entry.get("exported_at"),
        t3_attested=dist_entry.get("imported_at"),
        t4_remediated=ts,
        user_baselines=user_baselines,
    )
    dist_entry["total_lead_time_hours"] = case_calc["total_lead_time_hours"]
    dist_entry["lead_time_saved_hours"] = case_calc["lead_time_saved_hours"]

    # Record event in workflow metrics
    record_workflow_event("remediation_completed", {
        "distribution_id": distribution_id,
        "remediated_at": ts,
        "note": note,
    }, metrics_file=metrics_file)

    return dist_entry
