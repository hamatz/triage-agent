"""RFC 5545 compliant iCalendar (.ics) export engine for security patch schedules (ADR-020).

Enables security teams to export upcoming patch release schedules (Oracle CPU, Microsoft Patch Tuesday,
Node.js security releases, etc.) into Google Calendar, Microsoft Outlook, or Apple Calendar.

Strictly adheres to:
- Deterministic UID generation (re-importing overwrites instead of duplicating).
- Aggregation by Source × Date (prevents 30 identical events for multiple packages on Patch Tuesday).
- UTC timestamped events with timezone conversion (accounts for US-Japan date offset; e.g. Tuesday US morning = Wednesday early morning JST).
- RFC 5545 Section 3.1 line folding (max 75 octets) and Section 3.3.11 text escaping.
- Confidentiality & Data Minimization (ADR-013: prevents leaking entire SBOM component list into external calendar services).
"""

from datetime import datetime, timedelta, timezone
import hashlib
from pathlib import Path
import re
from typing import Dict, List, Optional, Tuple

from triage_agent.schemas import PreAnnouncementNotice


def escape_rfc5545_text(text: str) -> str:
    """Escape text characters according to RFC 5545 Section 3.3.11.
    
    Backslashes, semicolons, commas, and newlines must be escaped.
    """
    if not text:
        return ""
    # Replace backslash first
    res = text.replace("\\", "\\\\")
    res = res.replace(";", "\\;")
    res = res.replace(",", "\\,")
    res = res.replace("\r\n", "\\n").replace("\r", "\\n").replace("\n", "\\n")
    return res


def fold_line_rfc5545(line: str, max_octets: int = 75) -> str:
    """Fold lines longer than 75 octets with CRLF followed by a single space (RFC 5545 Section 3.1)."""
    encoded = line.encode("utf-8")
    if len(encoded) <= max_octets:
        return line

    chunks: List[bytes] = []
    current_chunk = bytearray()
    current_limit = max_octets

    # Iterate by unicode characters to avoid breaking multibyte UTF-8 characters across folds
    for char in line:
        char_bytes = char.encode("utf-8")
        if len(current_chunk) + len(char_bytes) > current_limit:
            chunks.append(bytes(current_chunk))
            current_chunk = bytearray()
            # Folded line starts with space (1 octet), so remaining limit is max_octets - 1
            current_limit = max_octets - 1
        current_chunk.extend(char_bytes)

    if current_chunk:
        chunks.append(bytes(current_chunk))

    # Join chunks with \r\n followed by a single space
    return "\r\n ".join(chunk.decode("utf-8") for chunk in chunks)


def parse_event_start_end_utc(
    expected_date_str: str,
    expected_time_str: Optional[str] = None
) -> Tuple[str, str]:
    """Parse expected date (YYYY-MM-DD) and optional UTC time (e.g. '18:00 UTC')
    into DTSTART and DTEND in RFC 5545 format (YYYYMMDDTHHMMSSZ).
    
    If no time is given, defaults to 18:00 UTC (start of US morning / Japan midnight).
    Default event duration is 2 hours (e.g. 18:00Z to 20:00Z).
    """
    date_parts = [int(p) for p in expected_date_str.split("-")]
    year, month, day = date_parts[0], date_parts[1], date_parts[2]

    hour, minute = 18, 0
    if expected_time_str:
        # Extract HH:MM
        t_match = re.search(r"(\d{1,2}):(\d{2})", expected_time_str)
        if t_match:
            hour = int(t_match.group(1))
            minute = int(t_match.group(2))

    start_dt = datetime(year, month, day, hour, minute, tzinfo=timezone.utc)
    end_dt = start_dt + timedelta(hours=2)

    start_str = start_dt.strftime("%Y%m%dT%H%M%SZ")
    end_str = end_dt.strftime("%Y%m%dT%H%M%SZ")
    return start_str, end_str


def generate_icalendar(
    pre_announcements: List[PreAnnouncementNotice],
    calendar_name: str = "セキュリティパッチ予定表 (triage-agent)"
) -> str:
    """Generate RFC 5545 compliant iCalendar (.ics) string.
    
    Aggregates notices by (source_id, expected_date) to prevent event duplication
    when multiple packages match the same release cycle.
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # Group notices by (source_id, expected_date)
    grouped: Dict[Tuple[str, str], List[PreAnnouncementNotice]] = {}
    for notice in pre_announcements:
        if not notice.expected_date:
            continue
        key = (notice.source_id, notice.expected_date)
        grouped.setdefault(key, []).append(notice)

    lines: List[str] = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//triage-agent//Pre-announcements Calendar 1.0//JA",
        "CALSCALE:GREGORIAN",
        "METHOD:PUBLISH",
        f"X-WR-CALNAME:{escape_rfc5545_text(calendar_name)}",
    ]

    for (source_id, date_str), notices in sorted(grouped.items(), key=lambda x: x[0][1]):
        primary = notices[0]
        comp_count = len(notices)
        components_label = f" (対象 {comp_count} 件)"

        # Severity
        sev = primary.severity_hint or "要確認"
        summary_text = f"【事前予告 [{sev}]】{primary.source_name}{components_label}"

        # Deterministic UID based solely on source_id and date (stable across SBOM component count changes)
        raw_uid_key = f"{source_id}-{date_str}"
        uid_hash = hashlib.sha256(raw_uid_key.encode("utf-8")).hexdigest()[:12]
        clean_date_str = date_str.replace("-", "")
        uid = f"{source_id}-{clean_date_str}-{uid_hash}@triage-agent"

        # Time range in UTC
        dtstart, dtend = parse_event_start_end_utc(date_str, primary.expected_time)

        # Operational preparations checklist (deduplicated)
        preps_set = []
        for n in notices:
            for p in n.recommended_preparations:
                if p not in preps_set:
                    preps_set.append(p)

        prep_lines = "\n".join([f"・[ ] {p}" for p in preps_set])

        # Data Minimization (ADR-013):
        # Do not leak full sensitive SBOM package names into external shared calendar descriptions.
        # State count and point to internal triage report.
        official_str = "公式一次情報" if primary.is_official else "未確認の予兆"
        desc_parts = [
            f"【情報源】{primary.source_name} ({official_str})",
            f"【該当コンポーネント】{comp_count} 件 (詳細は社内トリアージレポートを参照)",
        ]
        if primary.title:
            desc_parts.append(f"【予告タイトル】{primary.title}")
        if primary.expected_time:
            desc_parts.append(f"【予定時刻】{primary.expected_time} (※日本時間では翌未明〜早朝)")
        else:
            desc_parts.append("【予定時刻】時刻未定 (※海外プロジェクトの場合、日本時間では翌未明〜早朝の公開が通例です)")
        if primary.url:
            desc_parts.append(f"【公式URL】{primary.url}")
        if prep_lines:
            desc_parts.append(f"\n【事前準備チェックリスト】\n{prep_lines}")

        description_text = escape_rfc5545_text("\n".join(desc_parts))

        event_status = "CONFIRMED" if primary.is_official else "TENTATIVE"

        event_lines = [
            "BEGIN:VEVENT",
            f"UID:{uid}",
            f"DTSTAMP:{now_utc}",
            f"DTSTART:{dtstart}",
            f"DTEND:{dtend}",
            f"SUMMARY:{escape_rfc5545_text(summary_text)}",
            f"DESCRIPTION:{description_text}",
        ]
        if primary.url:
            # RFC 5545 Section 3.8.4.6: URL property is a URI and must not be backslash-escaped
            event_lines.append(f"URL:{primary.url.strip()}")

        event_lines.extend([
            f"STATUS:{event_status}",
            "TRANSP:TRANSPARENT",
            "END:VEVENT",
        ])

        lines.extend(event_lines)

    lines.append("END:VCALENDAR")

    # Apply RFC 5545 line folding (max 75 octets) to every line
    folded_lines = [fold_line_rfc5545(line) for line in lines]
    return "\r\n".join(folded_lines) + "\r\n"


def export_icalendar_file(
    pre_announcements: List[PreAnnouncementNotice],
    output_path: str | Path,
    calendar_name: str = "セキュリティパッチ予定表 (triage-agent)"
) -> Path:
    """Save the generated iCalendar to a .ics file using binary encoding with CRLF."""
    p = Path(output_path).resolve()
    p.parent.mkdir(parents=True, exist_ok=True)
    ics_text = generate_icalendar(pre_announcements, calendar_name=calendar_name)
    p.write_bytes(ics_text.encode("utf-8", errors="replace"))
    return p
