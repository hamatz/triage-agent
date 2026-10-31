"""Unit tests for Threat Feed Integration (CISA KEV & FIRST EPSS)."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import urllib.error

from triage_agent.chain.feeds import ThreatFeedClient, ThreatFeedResult


class TestThreatFeedClient(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_dir = Path(self.temp_dir.name) / "cache"
        self.history_path = Path(self.temp_dir.name) / "epss_history.json"
        self.client = ThreatFeedClient(
            cache_dir=self.cache_dir,
            history_path=self.history_path,
            epss_jump_threshold=0.15,
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    @patch("urllib.request.urlopen")
    def test_cisa_kev_fetch_and_cache(self, mock_urlopen):
        sample_kev = {
            "title": "CISA KEV Catalog",
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-109618",
                    "vendorProject": "PHP",
                    "product": "PHP",
                    "vulnerabilityName": "PHP RCE Vulnerability",
                    "dateAdded": "2026-10-24",
                    "knownRansomwareCampaignUse": "Known",
                }
            ],
        }
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(sample_kev).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        # First fetch
        catalog = self.client.fetch_cisa_kev_catalog()
        self.assertIn("CVE-2026-109618", catalog)
        self.assertEqual(catalog["CVE-2026-109618"]["dateAdded"], "2026-10-24")

        # Check cached file was created
        cache_file = self.cache_dir / "cisa_kev_catalog.json"
        self.assertTrue(cache_file.exists())

        # Second fetch should use memory or disk without calling urlopen again
        mock_urlopen.reset_mock()
        catalog2 = self.client.fetch_cisa_kev_catalog()
        self.assertIn("CVE-2026-109618", catalog2)
        mock_urlopen.assert_not_called()

    @patch("urllib.request.urlopen")
    def test_epss_fetch_and_jump_detection(self, mock_urlopen):
        # Pre-populate history with an earlier score
        initial_history = {
            "CVE-2026-46300": {
                "score": 0.05,
                "percentile": 0.20,
                "last_updated": "2026-10-20T00:00:00Z",
            }
        }
        with open(self.history_path, "w", encoding="utf-8") as f:
            json.dump(initial_history, f)

        # Mock EPSS API response: score jumped from 0.05 to 0.42 (+0.37 delta >= 0.15 threshold)
        sample_epss = {
            "status": "OK",
            "data": [
                {
                    "cve": "CVE-2026-46300",
                    "epss": "0.42000",
                    "percentile": "0.93000",
                }
            ],
        }
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = json.dumps(sample_epss).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        # Mock KEV catalog fetch to avoid external call
        self.client._kev_cache = {}

        results = self.client.analyze_cves(["CVE-2026-46300"])
        res = results["CVE-2026-46300"]
        self.assertEqual(res.epss_score, 0.42)
        self.assertEqual(res.previous_epss_score, 0.05)
        self.assertEqual(res.epss_delta, 0.37)
        self.assertTrue(res.epss_sudden_jump)
        self.assertTrue(res.verified)

        # Verify history was updated
        updated_history = self.client.load_epss_history()
        self.assertEqual(updated_history["CVE-2026-46300"]["score"], 0.42)
        self.assertEqual(updated_history["CVE-2026-46300"]["previous_score"], 0.05)

    @patch("urllib.request.urlopen")
    def test_fail_safe_on_api_error(self, mock_urlopen):
        # Simulate network error
        mock_urlopen.side_effect = urllib.error.URLError("Network unreachable")

        results = self.client.analyze_cves(["CVE-2026-99999"])
        res = results["CVE-2026-99999"]
        self.assertFalse(res.verified)
        self.assertIsNotNone(res.error)
        self.assertIn("unavailable", res.error)
        self.assertIsNone(res.in_cisa_kev)
        self.assertIsNone(res.epss_score)


if __name__ == "__main__":
    unittest.main()
