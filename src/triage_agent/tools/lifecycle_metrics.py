"""Lifecycle metrics and MTTR tracking engine (ADR-019 / v0.3.1).

Measures end-to-end vulnerability response timeline from public announcement T(-1)
to patch verification T(3) and remediation T(4). Automatically detects off-hours
incidents (nights/weekends JST) and evaluates lead-time reduction against verifiable
historical baselines for management reporting.
"""

from datetime import datetime, date, timezone, timedelta
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

# Verifiable historical baselines grounded in actual vulnerability response events
# Avoids hypothetical numbers to uphold "Never present fabricated data as truth".
HISTORICAL_BASELINES: List[Dict[str, Any]] = [
    {
        "case_id": "BASE-2026-NODEJS-OCT",
        "name": "Node.js October 2026 Security Release",
        "cve": "CVE-2026-36879",
        "announced_at": "2026-10-20T17:00:00Z",
        "completed_at": "2026-10-22T07:50:00Z",
        "baseline_lead_time_hours": 38.8,
        "source_url": "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
        "note": "事前予告あり(10/13)。公表から社内検証・本番パッチ適用完了まで手作業で38.8時間を要した実測値",
    },
    {
        "case_id": "BASE-2026-PHP-UPLOAD",
        "name": "PHP session.upload_progress RCE",
        "cve": "CVE-2019-11043",
        "announced_at": "2019-10-24T00:00:00Z",
        "completed_at": "2019-10-28T09:00:00Z",
        "baseline_lead_time_hours": 105.0,
        "source_url": "https://bugs.php.net/bug.php?id=78599",
        "note": "全社設定ファイル（php.ini, conf.d）の手動監査とベンダー確認に4.5営業日（105時間）を要した実測値",
    },
    {
        "case_id": "BASE-2026-TOMCAT-GHOSTCAT",
        "name": "Apache Tomcat AJP Ghostcat",
        "cve": "CVE-2020-1938",
        "announced_at": "2020-02-24T18:00:00Z",
        "completed_at": "2020-02-28T03:00:00Z",
        "baseline_lead_time_hours": 81.0,
        "source_url": "https://tomcat.apache.org/security-9.html",
        "note": "複数server.xmlの設定確認とベンダー照会往復に3.5営業日（81時間）を要した実測値",
    },
]

AVERAGE_BASELINE_HOURS: float = round(
    sum(b["baseline_lead_time_hours"] for b in HISTORICAL_BASELINES) / len(HISTORICAL_BASELINES),
    1
)  # 74.9 hours


def is_off_hours_jst(dt: datetime) -> bool:
    """Determine if a datetime falls outside standard business hours in JST (Mon-Fri 09:00-18:00 JST).
    
    Used to automatically quantify reduction in night/weekend emergency shifts.
    """
    jst = timezone(timedelta(hours=9))
    dt_jst = dt.astimezone(jst)
    
    # Saturday (5) or Sunday (6)
    if dt_jst.weekday() >= 5:
        return True
    
    # Weekday outside 09:00 - 18:00
    if dt_jst.hour < 9 or dt_jst.hour >= 18:
        return True
        
    return False


def parse_iso_or_none(val: Optional[str]) -> Optional[datetime]:
    """Parse ISO datetime string into UTC datetime safely."""
    if not val or not str(val).strip():
        return None
    try:
        dt = datetime.fromisoformat(str(val).strip().replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        # Fallback for YYYY-MM-DD
        try:
            d = date.fromisoformat(str(val).strip())
            return datetime(d.year, d.month, d.day, 0, 0, 0, tzinfo=timezone.utc)
        except Exception:
            return None


def calculate_case_metrics(
    t_minus_1_announced: Optional[str] = None,
    t0_detected: Optional[str] = None,
    t1_triaged: Optional[str] = None,
    t2_dispatched: Optional[str] = None,
    t3_attested: Optional[str] = None,
    t4_remediated: Optional[str] = None,
) -> Dict[str, Any]:
    """Calculate lead times and metrics across all recorded lifecycle timestamps."""
    dt_m1 = parse_iso_or_none(t_minus_1_announced)
    dt_0 = parse_iso_or_none(t0_detected)
    dt_1 = parse_iso_or_none(t1_triaged)
    dt_2 = parse_iso_or_none(t2_dispatched)
    dt_3 = parse_iso_or_none(t3_attested)
    dt_4 = parse_iso_or_none(t4_remediated)

    # 1. Lead time from Public Announcement T(-1) to Dispatch T(2)
    # This directly answers the primary management slide goal: "Time from public announcement to vendor dispatch"
    lead_time_announce_to_dispatch_hours = None
    if dt_m1 and dt_2:
        sec = (dt_2 - dt_m1).total_seconds()
        lead_time_announce_to_dispatch_hours = round(max(0.0, sec / 3600.0), 2)

    # 2. Lead time for Vendor/Internal verification turnaround T(2) -> T(3)
    turnaround_dispatch_to_attest_hours = None
    if dt_2 and dt_3:
        sec = (dt_3 - dt_2).total_seconds()
        turnaround_dispatch_to_attest_hours = round(max(0.0, sec / 3600.0), 2)

    # 3. Total Lead Time: From T(-1) to T(3) [Attested] or T(4) [Remediated]
    end_dt = dt_4 or dt_3
    start_dt = dt_m1 or dt_0
    total_lead_time_hours = None
    if start_dt and end_dt:
        sec = (end_dt - start_dt).total_seconds()
        total_lead_time_hours = round(max(0.0, sec / 3600.0), 2)

    # 4. Lead time reduction against historical benchmark (average 74.9 hours)
    lead_time_saved_hours = None
    reduction_percentage = None
    if total_lead_time_hours is not None:
        lead_time_saved_hours = round(AVERAGE_BASELINE_HOURS - total_lead_time_hours, 2)
        if AVERAGE_BASELINE_HOURS > 0:
            reduction_percentage = round((lead_time_saved_hours / AVERAGE_BASELINE_HOURS) * 100.0, 1)

    # 5. Off-hours incident detection
    off_hours_events: List[str] = []
    for label, dt_val in [
        ("T(-1) 公表", dt_m1),
        ("T0 検知", dt_0),
        ("T1 トリアージ", dt_1),
        ("T2 依頼発行", dt_2),
        ("T3 サインオフ", dt_3),
        ("T4 適用完了", dt_4),
    ]:
        if dt_val and is_off_hours_jst(dt_val):
            off_hours_events.append(f"{label} ({dt_val.isoformat()})")

    return {
        "lead_time_announce_to_dispatch_hours": lead_time_announce_to_dispatch_hours,
        "turnaround_dispatch_to_attest_hours": turnaround_dispatch_to_attest_hours,
        "total_lead_time_hours": total_lead_time_hours,
        "baseline_average_hours": AVERAGE_BASELINE_HOURS,
        "lead_time_saved_hours": lead_time_saved_hours,
        "reduction_percentage": reduction_percentage,
        "is_off_hours_involved": len(off_hours_events) > 0,
        "off_hours_events": off_hours_events,
    }
