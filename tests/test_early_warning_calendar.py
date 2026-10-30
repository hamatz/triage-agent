import datetime
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from triage_agent.schemas import ComponentInfo, PreAnnouncementNotice, ReconTarget, ResearchFinding, TargetResearchResult, TriageReport
from triage_agent.tools.advisory_catalog import (
    compute_next_scheduled_date,
    extract_iso_date_from_text,
    extract_severity_hint_from_text,
    fetch_advisory_feed,
    load_advisory_catalog,
    match_component_to_sources,
    scan_catalog_pre_announcements,
)
from triage_agent.tools.calendar import (
    escape_rfc5545_text,
    export_icalendar_file,
    fold_line_rfc5545,
    generate_icalendar,
    parse_event_start_end_utc,
)
from triage_agent.cli import format_report_markdown
from triage_agent.pipeline import execute_triage_pipeline


# -------------------------------------------------------------
# Opus Review 5 Test Patterns for Feed Pre-Announcement Parser
# -------------------------------------------------------------

# Pattern 1: Historical completed release article (July 2025)
FEED_PATTERN_1_PAST_COMPLETED = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Node.js Blog</title>
    <item>
      <title>Tuesday, July 15, 2025 Security Releases</title>
      <link>https://nodejs.org/en/blog/vulnerability/july-2025-security-releases</link>
      <description>The Node.js project has released updates for all active release lines.</description>
      <pubDate>Tue, 15 Jul 2025 17:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

# Pattern 2: Actual Node.js pre-announcement format with "will release... on or shortly after Tuesday, November 10, 2026"
FEED_PATTERN_2_NODEJS_REAL_UPCOMING = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Node.js Blog</title>
    <item>
      <title>Tuesday, November 10, 2026 Security Releases</title>
      <link>https://nodejs.org/en/blog/vulnerability/november-2026-security-releases</link>
      <description>The Node.js project will release new versions of the 20.x and 22.x releases on or shortly after Tuesday, November 10, 2026.</description>
      <pubDate>Thu, 05 Nov 2026 15:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

# Pattern 3: Old pre-announcement with "Upcoming..." text but past date (July 2025)
FEED_PATTERN_3_HISTORICAL_UPCOMING = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Node.js Blog</title>
    <item>
      <title>Upcoming Security Releases — July 2025</title>
      <link>https://nodejs.org/en/blog/vulnerability/upcoming-july-2025</link>
      <description>The following releases will be available on July 15, 2025.</description>
      <pubDate>Tue, 08 Jul 2025 10:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

# Pattern 4: Old pre-announcement first, followed by real upcoming pre-announcement
FEED_PATTERN_4_OLD_THEN_REAL = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Node.js Blog</title>
    <item>
      <title>Upcoming Security Releases — July 2025</title>
      <link>https://nodejs.org/en/blog/vulnerability/upcoming-july-2025</link>
      <description>Historical notice for July 15, 2025.</description>
      <pubDate>Tue, 08 Jul 2025 10:00:00 GMT</pubDate>
    </item>
    <item>
      <title>Tuesday, November 10, 2026 Security Releases</title>
      <link>https://nodejs.org/en/blog/vulnerability/november-2026-security-releases</link>
      <description>The Node.js project will release new versions of the 20.x release on or shortly after Tuesday, November 10, 2026.</description>
      <pubDate>Thu, 05 Nov 2026 15:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""

# Pattern 5: Real upcoming pre-announcement containing phrase "the following highlights"
FEED_PATTERN_5_HIGHLIGHTS_WORD_BOUNDARY = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Node.js Blog</title>
    <item>
      <title>Tuesday, November 10, 2026 Security Releases</title>
      <link>https://nodejs.org/en/blog/vulnerability/november-2026-security-releases</link>
      <description>Please see the following highlights of the upcoming release scheduled for November 10, 2026.</description>
      <pubDate>Thu, 05 Nov 2026 15:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""


class TestEarlyWarningCalendar(unittest.TestCase):
    def setUp(self):
        self.ref_date = datetime.date(2026, 10, 29)
        self.sample_src = {
            "id": "nodejs-security",
            "name": "Node.js Security Releases",
            "feed_url": "https://nodejs.org/feed.xml",
            "url": "https://nodejs.org/en/blog/vulnerability/",
            "keywords": ["security", "release"],
        }

    def test_opus_pattern_1_past_release_does_not_show_as_pre_announcement(self):
        """Pattern 1: 2025-07 completed release must NOT be returned as an upcoming pre-announcement."""
        with patch("urllib.request.urlopen") as mock_url:
            mock_url.return_value.__enter__.return_value.read.return_value = FEED_PATTERN_1_PAST_COMPLETED.encode("utf-8")
            res, err = fetch_advisory_feed(self.sample_src, reference_date=self.ref_date)

        self.assertIsNone(err)
        self.assertIsNone(res, "Past completed release must not trigger pre-announcement")

    def test_opus_pattern_2_nodejs_real_upcoming_format_detected(self):
        """Pattern 2: Real Node.js pre-announcement with 'will release... on or shortly after Tuesday, Nov 10, 2026' must be detected."""
        with patch("urllib.request.urlopen") as mock_url:
            mock_url.return_value.__enter__.return_value.read.return_value = FEED_PATTERN_2_NODEJS_REAL_UPCOMING.encode("utf-8")
            res, err = fetch_advisory_feed(self.sample_src, reference_date=self.ref_date)

        self.assertIsNone(err)
        self.assertIsNotNone(res, "Real Node.js upcoming pre-announcement must be detected")
        self.assertEqual(res["expected_date"], "2026-11-10")
        self.assertEqual(res["severity_hint"], "未公表", "If severity not explicitly in text, must be 未公表")

    def test_opus_pattern_3_historical_upcoming_does_not_show_as_active_notice(self):
        """Pattern 3: Pre-announcement with 'Upcoming' in title but past date (2025-07) must be ignored."""
        with patch("urllib.request.urlopen") as mock_url:
            mock_url.return_value.__enter__.return_value.read.return_value = FEED_PATTERN_3_HISTORICAL_UPCOMING.encode("utf-8")
            res, err = fetch_advisory_feed(self.sample_src, reference_date=self.ref_date)

        self.assertIsNone(err)
        self.assertIsNone(res, "Past upcoming announcement with historical date must not be returned")

    def test_opus_pattern_4_old_item_followed_by_real_item_returns_real_item(self):
        """Pattern 4: Parser must not stop on 1st old item; must continue loop and return the genuine upcoming notice."""
        with patch("urllib.request.urlopen") as mock_url:
            mock_url.return_value.__enter__.return_value.read.return_value = FEED_PATTERN_4_OLD_THEN_REAL.encode("utf-8")
            res, err = fetch_advisory_feed(self.sample_src, reference_date=self.ref_date)

        self.assertIsNone(err)
        self.assertIsNotNone(res)
        self.assertEqual(res["expected_date"], "2026-11-10", "Must find the 2nd valid future item")

    def test_opus_pattern_5_highlights_and_following_do_not_falsely_trigger_high_or_low(self):
        """Pattern 5: 'the following highlights' must NOT match 'High' or 'Low' via substring match."""
        with patch("urllib.request.urlopen") as mock_url:
            mock_url.return_value.__enter__.return_value.read.return_value = FEED_PATTERN_5_HIGHLIGHTS_WORD_BOUNDARY.encode("utf-8")
            res, err = fetch_advisory_feed(self.sample_src, reference_date=self.ref_date)

        self.assertIsNone(err)
        self.assertIsNotNone(res)
        self.assertEqual(res["severity_hint"], "未公表", "'highlights' must not trigger High, 'following' must not trigger Low")

    def test_confidentiality_no_component_leak_in_summary_or_description(self):
        """Opus Review Point 4: Component names like System.Text.Json must NEVER leak into calendar SUMMARY or DESCRIPTION."""
        notice = PreAnnouncementNotice(
            source_id="ms-patch-tuesday",
            source_name="Microsoft Patch Tuesday",
            component_name="System.Text.Json",
            title="Microsoft Patch Tuesday Update",
            expected_date="2026-11-10",
            expected_time="18:00 UTC",
            severity_hint="Critical",
            summary="System.Text.Json 該当: 月次セキュリティ更新プログラム",
            is_official=True,
            recommended_preparations=["輪番要員の確保", "RFC起票"],
        )

        ics = generate_icalendar([notice])
        unfolded = re.sub(r"\r\n ", "", ics)

        # Raw component name must not exist in VEVENT
        self.assertNotIn("System.Text.Json", unfolded, "System.Text.Json must not appear anywhere in calendar export")
        self.assertIn("SUMMARY:【事前予告 [Critical]】Microsoft Patch Tuesday (対象 1 件)", unfolded)
        self.assertIn("【該当コンポーネント】1 件 (詳細は社内トリアージレポートを参照)", unfolded)

    def test_deterministic_uid_stable_across_component_count_changes(self):
        """Opus Review Point: UID must be derived from (source_id + date) ONLY so it remains identical when SBOM changes."""
        notice_1 = PreAnnouncementNotice(
            source_id="ms-patch-tuesday",
            source_name="Microsoft Patch Tuesday",
            component_name="System.Text.Json",
            title="Notice",
            expected_date="2026-11-10",
            expected_time="18:00 UTC",
            severity_hint="Critical",
            summary="Updates",
            is_official=True,
        )
        notice_2 = PreAnnouncementNotice(
            source_id="ms-patch-tuesday",
            source_name="Microsoft Patch Tuesday",
            component_name="Microsoft.Extensions.Logging",
            title="Notice 2",
            expected_date="2026-11-10",
            expected_time="18:00 UTC",
            severity_hint="Critical",
            summary="Updates",
            is_official=True,
        )

        ics_with_1 = generate_icalendar([notice_1])
        ics_with_2 = generate_icalendar([notice_1, notice_2])

        uid1 = [l for l in ics_with_1.splitlines() if l.startswith("UID:")][0]
        uid2 = [l for l in ics_with_2.splitlines() if l.startswith("UID:")][0]

        self.assertEqual(uid1, uid2, "UID must stay stable across SBOM updates")

    def test_status_confirmed_vs_tentative(self):
        """Official sources must be STATUS:CONFIRMED, unconfirmed rumors must be STATUS:TENTATIVE."""
        official_notice = PreAnnouncementNotice(
            source_id="ms-patch-tuesday",
            source_name="Microsoft Patch Tuesday",
            component_name="pkg-a",
            title="Official",
            expected_date="2026-11-10",
            expected_time="18:00 UTC",
            is_official=True,
            summary="Official announcement",
        )
        unofficial_notice = PreAnnouncementNotice(
            source_id="web-rumor",
            source_name="Web Rumor Channel",
            component_name="pkg-b",
            title="Rumor",
            expected_date="2026-11-12",
            is_official=False,
            summary="Unconfirmed rumor",
        )

        ics_off = generate_icalendar([official_notice])
        self.assertIn("STATUS:CONFIRMED", ics_off)

        ics_unoff = generate_icalendar([unofficial_notice])
        self.assertIn("STATUS:TENTATIVE", ics_unoff)

    def test_url_is_not_backslash_escaped(self):
        """URL property must NOT escape commas/semicolons with backslashes."""
        notice = PreAnnouncementNotice(
            source_id="src-1",
            source_name="Test Source",
            component_name="pkg-a",
            title="Test",
            expected_date="2026-11-10",
            url="https://example.com/query?a=1,2;b=3",
            summary="URL test",
        )
        ics = generate_icalendar([notice])
        self.assertIn("URL:https://example.com/query?a=1,2;b=3", ics)
        self.assertNotIn("URL:https://example.com/query?a=1\\,2\\;b=3", ics)

    def test_opus_additional_case_undated_stale_upcoming_article_skipped(self):
        """Case 6: Undated upcoming announcement published >14 days ago must be skipped as stale."""
        stale_xml = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>Stale Feed</title>
    <item>
      <title>Upcoming Security Release planned</title>
      <link>https://example.com/stale</link>
      <description>We will release soon.</description>
      <pubDate>Mon, 01 Jun 2026 10:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""
        with patch("urllib.request.urlopen") as mock_url:
            mock_url.return_value.__enter__.return_value.read.return_value = stale_xml.encode("utf-8")
            res, err = fetch_advisory_feed(self.sample_src, reference_date=self.ref_date)

        self.assertIsNone(err)
        self.assertIsNone(res, "Undated announcement published >14 days ago must be discarded as stale")

    def test_opus_additional_case_forthcoming_and_dmy_format(self):
        """Case 7: 'Forthcoming' signal and '10 November 2026' (DD Month YYYY) format must be parsed."""
        openssl_xml = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0">
  <channel>
    <title>OpenSSL Feed</title>
    <item>
      <title>Forthcoming Security Release</title>
      <link>https://example.com/openssl/notice</link>
      <description>The OpenSSL project announces a forthcoming security release on 10 November 2026. The highest severity is High.</description>
      <pubDate>Thu, 05 Nov 2026 12:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>
"""
        with patch("urllib.request.urlopen") as mock_url:
            mock_url.return_value.__enter__.return_value.read.return_value = openssl_xml.encode("utf-8")
            res, err = fetch_advisory_feed(self.sample_src, reference_date=self.ref_date)

        self.assertIsNone(err)
        self.assertIsNotNone(res)
        self.assertEqual(res["expected_date"], "2026-11-10")
        self.assertEqual(res["severity_hint"], "High")

    def test_opus_additional_case_future_year_2030s(self):
        """Case 8: Years in 2030s (e.g. 2035) must be supported by 20\\d{2} regex."""
        d1 = extract_iso_date_from_text("Security Release on 15 January 2035")
        self.assertEqual(d1, "2035-01-15")
        d2 = extract_iso_date_from_text("Security Release on 2032-04-18")
        self.assertEqual(d2, "2032-04-18")

    def test_component_matching_purl_group_and_embedded_tomcat(self):
        """Package matching must match embedded Tomcat (tomcat-embed-core) and purl prefixes."""
        catalog = load_advisory_catalog()

        comp_embedded = ComponentInfo(
            name="tomcat-embed-core",
            group="org.apache.tomcat.embed",
            version="10.1.18",
            ecosystem="Maven",
            purl="pkg:maven/org.apache.tomcat.embed/tomcat-embed-core@10.1.18"
        )
        matched_embedded = match_component_to_sources(comp_embedded, catalog)
        self.assertTrue(any(s["id"] == "tomcat-announce" for s in matched_embedded))

    def test_schedule_calculation_fixed_tuesdays(self):
        """Fixed schedule rules (Patch Tuesday, Oracle CPU) must calculate exact future dates."""
        patch_tuesday = compute_next_scheduled_date(
            schedule_rule="second_tuesday",
            schedule_months=list(range(1, 13)),
            reference_date=self.ref_date,
        )
        self.assertEqual(patch_tuesday, datetime.date(2026, 11, 10))

        oracle_cpu = compute_next_scheduled_date(
            schedule_rule="third_tuesday",
            schedule_months=[1, 4, 7, 10],
            reference_date=self.ref_date,
        )
        self.assertEqual(oracle_cpu, datetime.date(2027, 1, 19))

    def test_rfc5545_line_folding_and_escaping(self):
        """RFC 5545 lines over 75 octets must fold with CRLF + space, and text characters must be escaped."""
        long_line = "DESCRIPTION:" + "非常に長い日本語のトリアージ事前準備チェックリスト説明文テキスト" * 5
        folded = fold_line_rfc5545(long_line, max_octets=75)
        for segment in folded.split("\r\n "):
            self.assertLessEqual(len(segment.encode("utf-8")), 75)

        raw = "Line1\nLine2; with, commas and \\ backslashes"
        escaped = escape_rfc5545_text(raw)
        self.assertEqual(escaped, "Line1\\nLine2\\; with\\, commas and \\\\ backslashes")


if __name__ == "__main__":
    unittest.main()
