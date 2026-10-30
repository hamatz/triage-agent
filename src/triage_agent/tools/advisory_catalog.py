"""Community-driven Advisory and Pre-announcement Catalog Engine (ADR-020).

Provides deterministic 1st-stage matching against official primary security release
schedules and announce channels (Node.js blog RSS, OpenSSL, Tomcat, Oracle CPU,
Microsoft Patch Tuesday, etc.) before or alongside live dynamic LLM research.

Strictly adheres to:
- "Never call unverified items safe" (record feed fetch errors as unscanned/failed warnings).
- Purl / group:name / wildcard matching (supports embedded libraries like tomcat-embed-core).
"""

from datetime import date, datetime, timedelta, timezone
import fnmatch
from importlib import resources
import json
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
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


SCHEDULE_RULE_MAP: Dict[str, Tuple[int, int]] = {
    # rule_name: (target_weekday [0=Mon, 1=Tue, 2=Wed, 3=Thu, 4=Fri, 5=Sat, 6=Sun], nth_occurrence)
    "first_monday": (0, 1),
    "second_monday": (0, 2),
    "first_tuesday": (1, 1),
    "second_tuesday": (1, 2),
    "third_tuesday": (1, 3),
    "fourth_tuesday": (1, 4),
    "first_thursday": (3, 1),
    "second_thursday": (3, 2),
    "third_thursday": (3, 3),
}


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
    (e.g. 'third_tuesday' for Oracle CPU, 'second_tuesday' for Patch Tuesday,
    'first_monday' for Django, 'second_thursday' for PostgreSQL).
    """
    if reference_date is None:
        reference_date = date.today()

    if schedule_rule in SCHEDULE_RULE_MAP:
        target_weekday, n = SCHEDULE_RULE_MAP[schedule_rule]
    else:
        # Fallback for legacy or unrecognized rules
        target_weekday = 1
        n = 3 if "third" in schedule_rule else 2

    # Check candidates for current year and next year
    current_year = reference_date.year
    for yr in [current_year, current_year + 1]:
        for mo in sorted(schedule_months):
            candidate = _get_nth_weekday_of_month(yr, mo, target_weekday=target_weekday, n=n)
            if candidate >= reference_date:
                return candidate

    return reference_date + timedelta(days=30)


def match_component_to_sources(
    component: Any,
    catalog: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Match a single SBOM component against catalog package patterns, purl patterns, and ecosystems."""
    matched = []
    comp_name_lower = getattr(component, "name", "").lower()
    comp_group_lower = (getattr(component, "group", None) or "").lower()
    comp_purl_lower = (getattr(component, "purl", None) or "").lower()

    # Candidate strings to match against patterns
    candidate_tokens = [comp_name_lower]
    if comp_group_lower:
        candidate_tokens.append(f"{comp_group_lower}:{comp_name_lower}")
        candidate_tokens.append(f"{comp_group_lower}/{comp_name_lower}")

    for src in catalog:
        is_hit = False

        # 1. PURL pattern match
        purl_patterns = src.get("purl_patterns", [])
        if comp_purl_lower:
            for pat in purl_patterns:
                if fnmatch.fnmatch(comp_purl_lower, pat.lower()):
                    is_hit = True
                    break

        # 2. Package name / group patterns
        if not is_hit:
            pkg_patterns = src.get("package_patterns", [])
            for pat in pkg_patterns:
                pat_lower = pat.lower()
                for token in candidate_tokens:
                    if "*" in pat_lower:
                        if fnmatch.fnmatch(token, pat_lower):
                            is_hit = True
                            break
                    else:
                        if token == pat_lower:
                            is_hit = True
                            break
                if is_hit:
                    break

        if is_hit:
            matched.append(src)

    return matched


def extract_iso_date_from_text(text: str) -> Optional[str]:
    """Attempt to extract an upcoming ISO release date (YYYY-MM-DD) from feed title or summary.
    
    Supports:
    - YYYY-MM-DD (e.g. 2026-11-10)
    - [Weekday,] Month DD, YYYY (e.g. Tuesday, November 10, 2026)
    - [Weekday,] DD Month YYYY (e.g. 10 November 2026, 10th Nov 2026)
    """
    # 1. Look for YYYY-MM-DD
    iso_match = re.search(r"\b(20\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01]))\b", text)
    if iso_match:
        return iso_match.group(1)

    months = {
        "jan": "01", "january": "01", "feb": "02", "february": "02",
        "mar": "03", "march": "03", "apr": "04", "april": "04",
        "may": "05", "jun": "06", "june": "06", "jul": "07", "july": "07",
        "aug": "08", "august": "08", "sep": "09", "september": "09",
        "oct": "10", "october": "10", "nov": "11", "november": "11",
        "dec": "12", "december": "12"
    }

    # 2. Look for [Weekday,] Month DD, YYYY (e.g. Tuesday, November 10, 2026 or Nov 10, 2026)
    m_re = re.search(
        r"(?:(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s+)?\b([A-Za-z]+)\s+([0-3]?\d)(?:st|nd|rd|th)?,?\s+(20\d{2})\b",
        text,
        re.IGNORECASE
    )
    if m_re:
        m_name = m_re.group(1).lower()
        if m_name in months:
            m_num = months[m_name]
            day_num = f"{int(m_re.group(2)):02d}"
            return f"{m_re.group(3)}-{m_num}-{day_num}"

    # 3. Look for [Weekday,] DD Month YYYY (e.g. 10 November 2026 or 10th Nov 2026)
    m_re_dmy = re.search(
        r"(?:(?:mon|tue|wed|thu|fri|sat|sun)[a-z]*,?\s+)?\b([0-3]?\d)(?:st|nd|rd|th)?\s+([A-Za-z]+),?\s+(20\d{2})\b",
        text,
        re.IGNORECASE
    )
    if m_re_dmy:
        m_name = m_re_dmy.group(2).lower()
        if m_name in months:
            m_num = months[m_name]
            day_num = f"{int(m_re_dmy.group(1)):02d}"
            return f"{m_re_dmy.group(3)}-{m_num}-{day_num}"

    return None


def _find_child_elem(parent: ET.Element, tags: List[str]) -> Optional[ET.Element]:
    """Find the first matching child element checking tags sequentially without relying on bool(elem)."""
    for tag in tags:
        elem = parent.find(tag)
        if elem is not None:
            return elem
    return None


def extract_severity_hint_from_text(text: str) -> str:
    """Extract severity hint (Critical, High, Medium, Low) using word boundaries to prevent matching 'highlights' or 'following'."""
    lower = text.lower()
    if re.search(r"\bcritical\b", lower):
        return "Critical"
    elif re.search(r"\bhigh\b", lower):
        return "High"
    elif re.search(r"\b(medium|moderate)\b", lower):
        return "Medium"
    elif re.search(r"\blow\b", lower):
        return "Low"
    return "未公表"


def fetch_advisory_feed(
    source: Dict[str, Any],
    timeout_sec: float = 3.0,
    reference_date: Optional[date] = None,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Fetch and parse RSS/Atom feed for upcoming pre-announcements.
    
    Identifies pre-announcements by presence of security keywords and future dates (>= reference_date).
    Past dates are strictly skipped to prevent showing completed historical releases as active notices.
    """
    feed_url = source.get("feed_url")
    if not feed_url:
        return None, None

    if reference_date is None:
        reference_date = date.today()

    req = urllib.request.Request(
        feed_url,
        headers={"User-Agent": "triage-agent-feed-monitor/1.0 (+https://github.com/triage-agent)"}
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
            content = resp.read()
    except Exception as e:
        return None, f"{source.get('name', 'Feed')} 巡回失敗 ({type(e).__name__}: {e})"

    try:
        root = ET.fromstring(content)

        # Search <channel><item> (RSS 2.0) or <entry> (Atom)
        entries = root.findall(".//item") or root.findall(".//{http://www.w3.org/2005/Atom}entry") or root.findall(".//entry")

        keywords = [k.lower() for k in source.get("keywords", ["security", "release"])]
        pre_announcement_signals = [
            "upcoming", "pre-announcement", "advance notice", "scheduled for",
            "will be released", "will release", "target date", "planned release",
            "security release pre", "forthcoming"
        ]

        undated_candidate = None

        for entry in entries:
            title_elem = _find_child_elem(entry, ["title", "{http://www.w3.org/2005/Atom}title"])
            title = (title_elem.text or "").strip() if title_elem is not None else ""

            link_elem = _find_child_elem(entry, ["link", "{http://www.w3.org/2005/Atom}link"])
            link = ""
            if link_elem is not None:
                link = link_elem.get("href") or (link_elem.text or "").strip()

            desc_elem = _find_child_elem(
                entry,
                ["description", "summary", "{http://www.w3.org/2005/Atom}summary", "content", "{http://www.w3.org/2005/Atom}content"]
            )
            summary = (desc_elem.text or "").strip() if desc_elem is not None else ""

            combined_text = f"{title} {summary}".lower()

            # Must be security-related
            if not any(k in combined_text for k in keywords):
                continue

            detected_date_str = extract_iso_date_from_text(f"{title} {summary}")

            if detected_date_str:
                try:
                    d = date.fromisoformat(detected_date_str)
                    if d < reference_date:
                        # Past release or historical pre-announcement: skip completely
                        continue
                    else:
                        # Genuine future pre-announcement detected!
                        sev = extract_severity_hint_from_text(f"{title} {summary}")
                        return {
                            "title": title,
                            "url": link or source.get("url"),
                            "summary": summary[:300] if summary else f"{source.get('name')} 事前予告フィード検知",
                            "expected_date": detected_date_str,
                            "severity_hint": sev,
                        }, None
                except Exception:
                    continue
            else:
                # No date in text: retain as undated candidate only if explicit pre-announcement signal is present
                if any(sig in combined_text for sig in pre_announcement_signals):
                    # Check article publication freshness: must not be older than 14 days
                    pub_elem = _find_child_elem(
                        entry,
                        ["pubdate", "pubDate", "updated", "{http://www.w3.org/2005/Atom}updated"]
                    )
                    pub_text = (pub_elem.text or "").strip() if pub_elem is not None else ""
                    if pub_text:
                        pub_date_str = extract_iso_date_from_text(pub_text)
                        if pub_date_str:
                            try:
                                pub_d = date.fromisoformat(pub_date_str)
                                if pub_d < (reference_date - timedelta(days=14)):
                                    # Stale undated announcement published >14 days ago: skip
                                    continue
                            except Exception:
                                pass

                    if undated_candidate is None:
                        sev = extract_severity_hint_from_text(f"{title} {summary}")
                        undated_candidate = {
                            "title": title,
                            "url": link or source.get("url"),
                            "summary": summary[:300] if summary else f"{source.get('name')} 事前予告フィード検知",
                            "expected_date": None,
                            "severity_hint": sev,
                        }

        if undated_candidate:
            return undated_candidate, None

    except Exception as e:
        return None, f"{source.get('name', 'Feed')} フィード解析エラー: {e}"

    return None, None


def scan_catalog_pre_announcements(
    components: List[ComponentInfo],
    custom_catalog_path: Optional[str | Path] = None,
    reference_date: Optional[date] = None,
    fetch_feeds: bool = True,
    feed_fetcher: Optional[Any] = None,  # Injectable fetcher for unit testing
) -> Tuple[List[PreAnnouncementNotice], List[str]]:
    """1st-stage deterministic reconnaissance of pre-announcements and scheduled releases.
    
    Returns:
        Tuple of (List of PreAnnouncementNotice, List of feed fetch error strings)
    """
    catalog = load_advisory_catalog(custom_path=custom_catalog_path)
    if not catalog:
        return [], []

    notices: List[PreAnnouncementNotice] = []
    feed_errors: List[str] = []
    seen_keys = set()
    feed_cache: Dict[str, Tuple[Optional[Dict[str, Any]], Optional[str]]] = {}

    for comp in components:
        matched_sources = match_component_to_sources(comp, catalog)
        for src in matched_sources:
            # If source is explicitly marked as primary_advisory (post-release advisory reference),
            # skip from pre-announcement calendar to avoid polluting the schedule with undated entries.
            if src.get("category") == "primary_advisory":
                continue

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
                scheduled_time = src.get("schedule_time_utc", "18:00 UTC")

                notices.append(
                    PreAnnouncementNotice(
                        source_id=src_id,
                        source_name=src.get("name", src_id),
                        component_name=comp.name,
                        title=f"{src.get('name')} 次期パッチ公開予定 ({date_str})",
                        expected_date=date_str,
                        expected_time=scheduled_time,
                        severity_hint="定期セキュリティアップデート",
                        summary=f"{comp.name} 該当: {src.get('cadence_hint', '')} 次回予定日時は {date_str} {scheduled_time} です。",
                        url=src.get("url"),
                        is_official=is_official,
                        recommended_preparations=preparations,
                    )
                )
            elif src_type == "rss_feed" and fetch_feeds:
                # Check feed cache or fetch
                if src_id not in feed_cache:
                    if feed_fetcher:
                        feed_cache[src_id] = feed_fetcher(src)
                    else:
                        feed_cache[src_id] = fetch_advisory_feed(src, reference_date=reference_date)

                feed_result, feed_err = feed_cache[src_id]
                if feed_err and feed_err not in feed_errors:
                    feed_errors.append(feed_err)

                if feed_result:
                    sev = feed_result.get("severity_hint") or "要確認"
                    exp_date = feed_result.get("expected_date")
                    notices.append(
                        PreAnnouncementNotice(
                            source_id=src_id,
                            source_name=src.get("name", src_id),
                            component_name=comp.name,
                            title=feed_result.get("title") or f"{src.get('name')} 事前リリース予告",
                            expected_date=exp_date,
                            expected_time=feed_result.get("expected_time"),
                            severity_hint=sev,
                            summary=f"{comp.name} 該当: {feed_result.get('summary', '')}",
                            url=feed_result.get("url") or src.get("url"),
                            is_official=is_official,
                            recommended_preparations=preparations,
                        )
                    )
                else:
                    # Feed had no active announcements or fetch failed: provide monitoring channel entry
                    cadence = src.get("cadence_hint", "公式セキュリティ事前予告チャンネルです。")
                    notices.append(
                        PreAnnouncementNotice(
                            source_id=src_id,
                            source_name=src.get("name", src_id),
                            component_name=comp.name,
                            title=f"{src.get('name')} 事前予告監視チャンネル",
                            expected_date=None,
                            severity_hint="要事前監視",
                            summary=f"{comp.name} 該当: {cadence} 監視URL: {src.get('url', '')}",
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
                        expected_date=None,
                        severity_hint="要事前監視",
                        summary=f"{comp.name} 該当: {cadence} 監視URL: {src.get('url', '')}",
                        url=src.get("url"),
                        is_official=is_official,
                        recommended_preparations=preparations,
                    )
                )

    return notices, feed_errors


def get_primary_advisories_for_components(
    components: List[ComponentInfo],
    custom_catalog_path: Optional[str | Path] = None,
) -> List[Dict[str, Any]]:
    """Retrieve official primary advisory reference channels for matched components."""
    catalog = load_advisory_catalog(custom_path=custom_catalog_path)
    advisories = []
    seen = set()
    for comp in components:
        matched = match_component_to_sources(comp, catalog)
        for src in matched:
            if src.get("category") == "primary_advisory":
                src_id = src.get("id", "unknown")
                key = f"{src_id}:{comp.name}"
                if key not in seen:
                    seen.add(key)
                    advisories.append({
                        "source_id": src_id,
                        "source_name": src.get("name", src_id),
                        "component_name": comp.name,
                        "url": src.get("url"),
                        "cadence_hint": src.get("cadence_hint", ""),
                        "default_preparations": src.get("default_preparations", []),
                    })
    return advisories
