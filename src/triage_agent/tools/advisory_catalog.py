"""Community-driven Advisory and Pre-announcement Catalog Engine (ADR-020).

Provides deterministic 1st-stage matching against official primary security release
schedules and announce channels (Node.js blog, OpenSSL announce, Tomcat, Oracle CPU,
Microsoft Patch Tuesday, etc.) before or alongside live dynamic LLM research.
"""

from datetime import date, datetime, timedelta
import fnmatch
from importlib import resources
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import tomllib

from triage_agent.schemas import ComponentInfo, PreAnnouncementNotice


def load_advisory_catalog(custom_path: Optional[str | Path] = None) -> List[Dict[str, Any]]:
    """Load advisory sources from bundled package data (advisory_sources.toml)
    or a custom user-defined path.
    """
    if custom_path:
        p = Path(custom_path)
        if not p.exists():
            raise FileNotFoundError(f"カスタム予兆カタログが見つかりません: {custom_path}")
        content = p.read_text(encoding="utf-8")
        if p.suffix.lower() == ".json":
            data = json.loads(content)
            return data.get("sources", data) if isinstance(data, dict) else data
        else:
            data = tomllib.loads(content)
            return data.get("sources", [])

    # Load from package data
    try:
        ref = resources.files("triage_agent.data").joinpath("advisory_sources.toml")
        if ref.is_file():
            content = ref.read_text(encoding="utf-8")
            data = tomllib.loads(content)
            return data.get("sources", [])
    except Exception:
        pass

    # Fallback to relative file
    local_p = Path(__file__).parent.parent / "data" / "advisory_sources.toml"
    if local_p.exists():
        data = tomllib.loads(local_p.read_text(encoding="utf-8"))
        return data.get("sources", [])

    return []


def _get_nth_weekday_of_month(year: int, month: int, target_weekday: int, n: int) -> date:
    """Get the n-th target weekday (0=Monday, 1=Tuesday, ...) of the given year/month."""
    d1 = date(year, month, 1)
    offset = (target_weekday - d1.weekday()) % 7
    day = 1 + offset + (n - 1) * 7
    return date(year, month, day)


def compute_next_scheduled_date(
    schedule_rule: str,
    schedule_months: List[int],
    reference_date: Optional[date] = None,
) -> date:
    """Compute the next upcoming scheduled release date based on rules
    (e.g. 'third_tuesday' for Oracle CPU, 'second_tuesday' for Patch Tuesday).
    """
    if reference_date is None:
        reference_date = date.today()

    n = 2 if schedule_rule == "second_tuesday" else 3 if schedule_rule == "third_tuesday" else 2

    # Check candidates for current year and next year
    current_year = reference_date.year
    for yr in [current_year, current_year + 1]:
        for mo in sorted(schedule_months):
            candidate = _get_nth_weekday_of_month(yr, mo, target_weekday=1, n=n)
            if candidate >= reference_date:
                return candidate

    return reference_date + timedelta(days=30)


def match_component_to_sources(
    component: ComponentInfo,
    catalog: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Match a single SBOM component against catalog package patterns and ecosystems."""
    matched = []
    comp_name_lower = component.name.lower()

    for src in catalog:
        patterns = src.get("package_patterns", [])
        is_pattern_hit = False
        for pat in patterns:
            pat_lower = pat.lower()
            if "*" in pat_lower:
                if fnmatch.fnmatch(comp_name_lower, pat_lower):
                    is_pattern_hit = True
                    break
            else:
                if comp_name_lower == pat_lower:
                    is_pattern_hit = True
                    break

        if is_pattern_hit:
            matched.append(src)

    return matched


def scan_catalog_pre_announcements(
    components: List[ComponentInfo],
    custom_catalog_path: Optional[str | Path] = None,
    reference_date: Optional[date] = None,
) -> List[PreAnnouncementNotice]:
    """1st-stage deterministic reconnaissance of pre-announcements and scheduled releases.
    
    Returns a deduplicated list of PreAnnouncementNotice objects matching the given SBOM.
    """
    catalog = load_advisory_catalog(custom_path=custom_catalog_path)
    if not catalog:
        return []

    notices: List[PreAnnouncementNotice] = []
    seen_keys = set()

    for comp in components:
        matched_sources = match_component_to_sources(comp, catalog)
        for src in matched_sources:
            src_id = src.get("id", "unknown-source")
            key = f"{src_id}:{comp.name}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            src_type = src.get("type", "blog_html")
            is_official = src.get("is_official", True)
            preparations = list(src.get("default_preparations", []))

            if src_type == "fixed_schedule":
                rule = src.get("schedule_rule", "second_tuesday")
                months = src.get("schedule_months", list(range(1, 13)))
                next_date = compute_next_scheduled_date(rule, months, reference_date=reference_date)
                date_str = next_date.strftime("%Y-%m-%d")

                notices.append(
                    PreAnnouncementNotice(
                        source_id=src_id,
                        source_name=src.get("name", src_id),
                        component_name=comp.name,
                        title=f"{src.get('name')} 次期パッチ公開予定 ({date_str})",
                        expected_date=date_str,
                        expected_time="17:00 UTC (予定)",
                        severity_hint="定期セキュリティアップデート",
                        summary=f"{comp.name} 該当: {src.get('cadence_hint', '')} 次回予定日は {date_str} です。",
                        url=src.get("url"),
                        is_official=is_official,
                        recommended_preparations=preparations,
                    )
                )
            else:
                # Blog / Mailing list pre-announcement channel
                cadence = src.get("cadence_hint", "公式セキュリティ事前予告チャンネルです。")
                notices.append(
                    PreAnnouncementNotice(
                        source_id=src_id,
                        source_name=src.get("name", src_id),
                        component_name=comp.name,
                        title=f"{src.get('name')} 事前予告監視チャンネル",
                        expected_date=None,  # Will be populated if specific release date is detected by dynamic scan
                        severity_hint="要事前監視",
                        summary=f"{comp.name} 該当: {cadence} 監視URL: {src.get('url', '')}",
                        url=src.get("url"),
                        is_official=is_official,
                        recommended_preparations=preparations,
                    )
                )

    return notices
