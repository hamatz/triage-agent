"""Tests for the CVSS signal source of --kernel-auto (Red Hat Security Data API, ADR-021).

The HTTP layer is replaced by a fake, so no network access is needed. Rows mimic the shape of
cve.json (CVE, severity, cvss3_scoring_vector, cvss3_score as a string).
"""

import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from triage_agent.chain.kernel_history import evaluate_promotions
from triage_agent.chain.sources import build_cvss_source, load_signal_registry
from triage_agent.chain.sources import cvss_redhat
from triage_agent.chain.sources.cvss_redhat import RedHatCvssSource

LPE = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
DOS = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"


class FakeRedHat(RedHatCvssSource):
    def __init__(self, rows, cache_dir, fail=False):
        super().__init__({"packages": ["kernel"]}, cache_dir=cache_dir)
        self.rows, self.fail, self.urls = rows, fail, []

    def _http_json(self, url):
        self.urls.append(url)
        if self.fail:
            raise RuntimeError("network down")
        page = int(url.rsplit("page=", 1)[1])
        size = cvss_redhat.PER_PAGE
        return self.rows[(page - 1) * size: page * size]


ROWS = [
    {"CVE": "CVE-2026-0001", "severity": "important", "cvss3_scoring_vector": LPE, "cvss3_score": "7.8"},
    {"CVE": "CVE-2026-0002", "severity": "moderate", "cvss3_scoring_vector": DOS, "cvss3_score": "5.5"},
    {"CVE": "CVE-2026-0003", "severity": "low", "cvss3_scoring_vector": None, "cvss3_score": None},
    {"CVE": "CVE-2026-0004", "severity": "important", "cvss3_scoring_vector": LPE, "cvss3_score": "7.0"},
    {"CVE": "CVE-2026-0005", "severity": "moderate", "cvss3_scoring_vector": DOS, "cvss3_score": "4.4"},
]


class TestRedHatCvssSource(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cache = self._tmp.name
        patcher = mock.patch.object(cvss_redhat, "PER_PAGE", 2)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self._tmp.cleanup()

    def test_pages_until_short_page_and_returns_scored_only(self):
        src = FakeRedHat(ROWS, self.cache)
        got = src.lookup(["cve-2026-0001", "CVE-2026-0003", "CVE-2026-0005", "CVE-2099-9999"])
        self.assertEqual(len(src.urls), 3)  # 2 + 2 + 1 rows
        self.assertTrue(all("package=kernel" in u for u in src.urls))
        self.assertTrue(all("CVE-" not in u for u in src.urls))  # no CVE numbers are sent
        self.assertEqual(set(got), {"CVE-2026-0001", "CVE-2026-0005"})
        self.assertEqual(got["CVE-2026-0001"]["score"], 7.8)
        self.assertEqual(got["CVE-2026-0001"]["source"], "redhat")
        self.assertEqual(got["CVE-2026-0001"]["source_url"], "https://access.redhat.com/security/cve/cve-2026-0001")

    def test_cache_is_reused_for_24_hours(self):
        FakeRedHat(ROWS, self.cache).lookup(["CVE-2026-0001"])
        again = FakeRedHat(ROWS, self.cache)
        self.assertIn("CVE-2026-0001", again.lookup(["CVE-2026-0001"]))
        self.assertEqual(again.urls, [])
        # Older than 24 hours: fetched again.
        path = Path(self.cache) / "cvss" / "redhat_kernel.json"
        old = time.time() - 25 * 3600
        os.utime(path, (old, old))
        third = FakeRedHat(ROWS, self.cache)
        third.lookup(["CVE-2026-0001"])
        self.assertEqual(len(third.urls), 3)

    def test_offline_without_cache_raises_and_failure_falls_back_to_stale_cache(self):
        with self.assertRaises(RuntimeError):
            FakeRedHat(ROWS, self.cache).lookup(["CVE-2026-0001"], offline=True)
        with self.assertRaises(RuntimeError):
            FakeRedHat(ROWS, self.cache, fail=True).lookup(["CVE-2026-0001"])
        FakeRedHat(ROWS, self.cache).lookup(["CVE-2026-0001"])
        path = Path(self.cache) / "cvss" / "redhat_kernel.json"
        old = time.time() - 25 * 3600
        os.utime(path, (old, old))
        down = FakeRedHat(ROWS, self.cache, fail=True)
        self.assertIn("CVE-2026-0001", down.lookup(["CVE-2026-0001"]))
        self.assertTrue(any("前回のキャッシュ" in n for n in down.notes))

    def test_registry_selects_red_hat(self):
        src = build_cvss_source(load_signal_registry(), cache_dir=self.cache)
        self.assertIsInstance(src, RedHatCvssSource)
        self.assertIsNone(build_cvss_source({}, cache_dir=self.cache))


class TestCvssSourceChange(unittest.TestCase):
    def test_switching_source_is_not_a_revision(self):
        prev = {"signals": {"CVE-A": {"cvss": {"vector": DOS, "score": 5.5, "source": "nvd"}}}}
        cur = {"CVE-A": {"vector": LPE, "score": 7.8, "source": "redhat"}}
        self.assertEqual(evaluate_promotions({"CVE-A"}, set(), {}, cur, prev, {}), {})
        cur["CVE-A"]["source"] = "nvd"
        self.assertIn("CVE-A", evaluate_promotions({"CVE-A"}, set(), {}, cur, prev, {}))


if __name__ == "__main__":
    unittest.main()
