import unittest
import os
from unittest.mock import patch, MagicMock
from triage_agent.schemas import ReconTarget, TargetResearchResult, ComponentInfo
from triage_agent.tools.osv import (
    query_osv_single,
    query_osv_batch,
    get_osv_vulnerability_detail,
    _osv_detail_cache,
)
from triage_agent.agents.researcher import run_researcher


class TestTokenlessOSVResearcher(unittest.TestCase):
    def setUp(self):
        _osv_detail_cache.clear()

    def test_osv_query_batch_hydrates_stub_and_skips_withdrawn(self):
        """Test query_osv_batch automatically hydrates minimal stub IDs via get_osv_vulnerability_detail,
        and skips withdrawn vulnerabilities (google/osv.dev#466)."""
        stub_batch_response = {
            "results": [
                {
                    "vulns": [
                        {"id": "GHSA-valid-1", "modified": "2026-01-01T00:00:00Z"},
                        {"id": "GHSA-retracted-2", "modified": "2026-01-02T00:00:00Z"},
                    ]
                }
            ]
        }

        detailed_valid = {
            "id": "GHSA-valid-1",
            "aliases": ["CVE-2026-11111"],
            "summary": "Active RCE Vulnerability",
            "details": "Triggered under condition X",
            "severity": [{"type": "CVSS_V3", "score": "9.8"}],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [{"introduced": "0"}, {"fixed": "2.0.0"}],
                        }
                    ]
                }
            ],
            "references": [{"type": "WEB", "url": "https://example.com/advisory"}],
        }

        detailed_withdrawn = {
            "id": "GHSA-retracted-2",
            "aliases": ["CVE-2022-23529"],
            "withdrawn": "2023-01-15T12:00:00Z",
            "summary": "Retracted vulnerability",
        }

        def mock_get_detail(vid, client=None):
            if vid == "GHSA-valid-1":
                return detailed_valid
            elif vid == "GHSA-retracted-2":
                return detailed_withdrawn
            return None

        with patch("httpx.Client.post") as mock_post, \
             patch("triage_agent.tools.osv.get_osv_vulnerability_detail", side_effect=mock_get_detail):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = stub_batch_response
            mock_post.return_value = mock_resp

            vulns, errors = query_osv_single("test-lib", "1.0.0", "PyPI")
            self.assertEqual(len(errors), 0)
            # The withdrawn vulnerability should be skipped!
            self.assertEqual(len(vulns), 1)
            v = vulns[0]
            self.assertEqual(v["id"], "GHSA-valid-1")
            self.assertEqual(v["cve_id"], "CVE-2026-11111")
            self.assertEqual(v["score"], "9.8")
            self.assertIn("2.0.0", v["fixed_versions"])

    def test_osv_query_batch_overflow_stubs_preserved_and_warned(self):
        """When component has more vulns than max_vulns_per_component,
        overflow records must NOT be silently dropped, and an explicit warning must be raised."""
        stub_batch_response = {
            "results": [
                {
                    "vulns": [
                        {"id": f"GHSA-vuln-{i}", "modified": "2026-01-01T00:00:00Z"}
                        for i in range(1, 6)  # 5 vulns
                    ]
                }
            ]
        }

        with patch("httpx.Client.post") as mock_post, \
             patch("triage_agent.tools.osv.get_osv_vulnerability_detail", return_value={"summary": "Detailed info"}):
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = stub_batch_response
            mock_post.return_value = mock_resp

            comp = ComponentInfo(name="overflow-lib", version="1.0.0", ecosystem="npm")
            res_dict, errors, _ = query_osv_batch([comp], max_vulns_per_component=2)

            vulns = res_dict["overflow-lib"]
            # All 5 vulnerabilities must be preserved in results!
            self.assertEqual(len(vulns), 5)
            # First 2 are detailed
            self.assertFalse(vulns[0]["is_detail_truncated"])
            self.assertFalse(vulns[1]["is_detail_truncated"])
            # Remaining 3 are marked truncated
            self.assertTrue(vulns[2]["is_detail_truncated"])
            self.assertTrue(vulns[3]["is_detail_truncated"])
            self.assertTrue(vulns[4]["is_detail_truncated"])

            # Explicit warning must be emitted in errors
            self.assertEqual(len(errors), 1)
            self.assertIn("詳細未取得", errors[0])
            self.assertIn("overflow-lib", errors[0])

    def test_get_osv_detail_does_not_cache_failure(self):
        """Failed lookups must not be cached as None so transient network errors can retry."""
        with patch("httpx.Client.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 503  # Service unavailable
            mock_get.return_value = mock_resp

            res = get_osv_vulnerability_detail("GHSA-fail-retry")
            self.assertIsNone(res)
            self.assertNotIn("GHSA-fail-retry", _osv_detail_cache)

            # Subsequent successful call should be cached
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"id": "GHSA-fail-retry", "summary": "Recovered!"}
            res2 = get_osv_vulnerability_detail("GHSA-fail-retry")
            self.assertIsNotNone(res2)
            self.assertEqual(res2["summary"], "Recovered!")
            self.assertIn("GHSA-fail-retry", _osv_detail_cache)

    def test_researcher_graceful_on_github_rate_limit(self):
        """When GitHub API returns 403 (unauthenticated rate limit), but OSV.dev succeeds,
        researcher should NOT flag component as unscanned/error."""
        target = ReconTarget(
            name="demo-pkg",
            version="1.0.0",
            ecosystem="PyPI",
            purl="pkg:pypi/demo-pkg@1.0.0",
            priority="HIGH",
            rationale="High usage library",
            github_repo="demo-owner/demo-pkg",
            github_search_keywords=["security", "rce"],
            search_queries=["demo-pkg security announcement"],
        )

        mock_osv_vulns = [
            {
                "id": "GHSA-test-mock",
                "cve_id": "CVE-2026-88888",
                "summary": "RCE vulnerability in demo-pkg",
                "details": "Full vulnerability details from OSV.dev",
                "score": "9.8",
                "fixed_versions": ["1.0.1"],
                "references": ["https://osv.dev/vulnerability/GHSA-test-mock"],
            }
        ]

        mock_gh_signals = {
            "repo": "demo-owner/demo-pkg",
            "security_advisories": [],
            "recent_releases": [],
            "relevant_commits": [],
            "errors": ["GitHub Advisories API (demo-owner/demo-pkg): HTTP 403 - API rate limit exceeded"],
        }

        with patch("triage_agent.agents.researcher.query_osv_single", return_value=(mock_osv_vulns, [])), \
             patch("triage_agent.agents.researcher.search_github_security_signals", return_value=mock_gh_signals), \
             patch("triage_agent.agents.researcher.get_github_token", return_value=None):

            res = run_researcher(target=target, dry_run=True)
            self.assertIsInstance(res, TargetResearchResult)
            self.assertEqual(len(res.errors), 0, f"Errors should be empty but found: {res.errors}")
            self.assertEqual(len(res.findings), 1)
            finding = res.findings[0]
            self.assertEqual(finding.id, "CVE-2026-88888")
            self.assertEqual(finding.severity, "CRITICAL")
            self.assertEqual(finding.cvss, "9.8")
            self.assertIn("Fixed: 1.0.1", finding.affected_versions)


if __name__ == "__main__":
    unittest.main()
