"""Lifecycle metrics and MTTR tracking engine (ADR-019 / v0.3.1).

Measures end-to-end vulnerability response timeline from public announcement T(-1)
to patch verification T(3) and manual remediation confirmation T(4).
Automatically tracks off-hours operational events (nights/weekends JST).
Evaluates lead-time reduction strictly against user-provided verifiable baselines.
"""

from datetime import datetime, date, timezone, timedelta
import json
from pathlib import Path
from typing import Any, Dict, List, Optional


def load_user_baselines(baselines_path: Optional[str] = "triage-output/baselines.json") -> List[Dict[str, Any]]:
    """Load user-supplied verifiable historical baselines from local storage.
    
    Upholds 'Never present fabricated data as truth'. Does not hardcode internal corporate metrics into OSS.
    Returns empty list if file does not exist or has no entries.
    """
    if not baselines_path:
        return []
    p = Path(baselines_path).resolve()
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and "baselines" in data:
            return data["baselines"]
    except Exception:
        pass
    return []


def is_off_hours_jst(dt: datetime) -> bool:
    """Determine if a datetime falls outside standard business hours in JST (Mon-Fri 09:00-18:00 JST).
    
    Used to automatically quantify reduction in night/weekend emergency operational operations.
    Note: Tracks tool operation timestamps, not human labor shifts.
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
    user_baselines: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Calculate lead times and metrics across all recorded lifecycle timestamps.
    
    Strictly avoids computing time-saved percentages unless user-supplied baselines are present.
    """
    dt_m1 = parse_iso_or_none(t_minus_1_announced)
    dt_0 = parse_iso_or_none(t0_detected)
    dt_1 = parse_iso_or_none(t1_triaged)
    dt_2 = parse_iso_or_none(t2_dispatched)
    dt_3 = parse_iso_or_none(t3_attested)
    dt_4 = parse_iso_or_none(t4_remediated)

    # 1. Lead time from Public Announcement T(-1) to Dispatch T(2)
    # Directly answers the management slide metric: "Time from announcement to dispatch"
    lead_time_announce_to_dispatch_hours = None
    if dt_m1 and dt_2:
        sec = (dt_2 - dt_m1).total_seconds()
        lead_time_announce_to_dispatch_hours = round(max(0.0, sec / 3600.0), 2)

    # 2. Lead time for Vendor/Internal verification turnaround T(2) -> T(3)
    turnaround_dispatch_to_attest_hours = None
    if dt_2 and dt_3:
        sec = (dt_3 - dt_2).total_seconds()
        turnaround_dispatch_to_attest_hours = round(max(0.0, sec / 3600.0), 2)

    # 3. Total Lead Time: From T(-1) to T(4) [Remediated] or T(3) [Attested]
    end_dt = dt_4 or dt_3
    start_dt = dt_m1 or dt_0
    total_lead_time_hours = None
    if start_dt and end_dt:
        sec = (end_dt - start_dt).total_seconds()
        total_lead_time_hours = round(max(0.0, sec / 3600.0), 2)

    # 4. Lead time reduction against user-supplied baselines only
    baseline_avg_hours = None
    baseline_count = 0
    lead_time_saved_hours = None
    reduction_percentage = None

    if user_baselines:
        valid_lead_times = [
            float(b["baseline_lead_time_hours"])
            for b in user_baselines
            if "baseline_lead_time_hours" in b and float(b["baseline_lead_time_hours"]) > 0
        ]
        if valid_lead_times:
            baseline_count = len(valid_lead_times)
            baseline_avg_hours = round(sum(valid_lead_times) / baseline_count, 1)
            if total_lead_time_hours is not None:
                lead_time_saved_hours = round(baseline_avg_hours - total_lead_time_hours, 2)
                reduction_percentage = round((lead_time_saved_hours / baseline_avg_hours) * 100.0, 1)

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
        "baseline_average_hours": baseline_avg_hours,
        "baseline_count": baseline_count,
        "lead_time_saved_hours": lead_time_saved_hours,
        "reduction_percentage": reduction_percentage,
        "is_off_hours_involved": len(off_hours_events) > 0,
        "off_hours_events": off_hours_events,
    }
