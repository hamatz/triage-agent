"""iCalendar (RFC 5545) generator for security release pre-announcements (ADR-020).

Enables SREs, developers, and security leads to import upcoming security releases
directly into Google Calendar, Microsoft Outlook, or Apple Calendar.
"""

from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional
import uuid

from triage_agent.schemas import PreAnnouncementNotice


def _format_date_for_ics(date_str: str) -> str:
    """Format YYYY-MM-DD into YYYYMMDD."""
    return date_str.replace("-", "").strip()


def generate_icalendar(
    pre_announcements: List[PreAnnouncementNotice],
    calendar_name: str = "セキュリティパッチ予定表 (triage-agent)",
) -> str:
    """Generate an RFC 5545 compliant iCalendar string (.ics) from pre-announcements."""
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//triage-agent//Pre-announcements Calendar 1.0//JA",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        f"X-WR-CALNAME:{calendar_name}",
    ]

    now_utc = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    for notice in pre_announcements:
        if not notice.expected_date:
            continue

        raw_date = notice.expected_date.strip()
        clean_date = _format_date_for_ics(raw_date)

        # Calculate next day for all-day DTEND
        try:
            d = datetime.strptime(raw_date, "%Y-%m-%d").date()
            next_day = (d + timedelta(days=1)).strftime("%Y%m%d")
        except ValueError:
            next_day = clean_date

        uid = f"{notice.source_id}-{clean_date}-{uuid.uuid4().hex[:8]}@triage-agent"
        status_tag = "公式一次情報" if notice.is_official else "未確認の予兆"
        sev_tag = f" [{notice.severity_hint}]" if notice.severity_hint else ""
        summary = f"【事前予告{sev_tag}】{notice.component_name}: {notice.title}"

        # Construct description with checklist
        checklist = "\\n".join([f"・[ ] {item}" for item in notice.recommended_preparations])
        desc_parts = [
            f"【対象コンポーネント】{notice.component_name}",
            f"【情報源】{notice.source_name} ({status_tag})",
            f"【概要】{notice.summary}",
        ]
        if notice.url:
            desc_parts.append(f"【参照URL】{notice.url}")
        if checklist:
            desc_parts.append(f"\\n【事前準備チェックリスト】\\n{checklist}")

        description = "\\n".join(desc_parts).replace("\r", "")

        lines.extend([
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"DTSTAMP:{now_utc}",
            f"DTSTART;VALUE=DATE:{clean_date}",
            f"DTEND;VALUE=DATE:{next_day}",
            f"SUMMARY:{summary}",
            f"DESCRIPTION:{description}",
        ])
        if notice.url:
            lines.append(f"URL:{notice.url}")
        lines.extend([
            "STATUS:CONFIRMED",
            "TRANSP:TRANSPARENT",
            "END:VEVENT",
        ])

    lines.append("END:VCALENDAR")
    lines.append("")  # trailing newline
    return "\r\n".join(lines)


def export_icalendar_file(
    pre_announcements: List[PreAnnouncementNotice],
    output_path: str | Path,
    calendar_name: str = "セキュリティパッチ予定表 (triage-agent)",
) -> Path:
    """Save the generated iCalendar to a .ics file."""
    p = Path(output_path).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    ics_text = generate_icalendar(pre_announcements, calendar_name=calendar_name)
    p.write_bytes(ics_text.encode("utf-8", errors="replace"))
    return p
