import unittest
from unittest.mock import MagicMock, patch

from triage_agent.schemas import ReconTarget, ReconPlan, TargetResearchResult, ResearchFinding
from triage_agent.agents.researcher import run_researcher
from triage_agent.pipeline import execute_triage_pipeline


class TestOsvOverflowAndGitHubRateLimit(unittest.TestCase):
    def test_osv_overflow_treated_as_success_and_gh_403_non_blocking(self):
        """When OSV detects >10 vulns (overflow note emitted) and GitHub returns 403 rate limit,
        research must succeed and not mark the component as failed/unscanned."""
        mock_vulns = [{"id": f"GHSA-test-{i}", "summary": "test"} for i in range(15)]
        mock_osv_errors = ["overflow-pkg: OSV.dev で検出された全 15 件中、上位 10 件の詳細を取得。残り 5 件は詳細未取得（要個別確認: GHSA-test-10 等計 5 件）"]
        
        mock_gh_signals = {
            "security_advisories": [],
            "recent_releases": [],
            "relevant_commits": [],
            "errors": ["GitHub Advisories API: HTTP 403 - Rate limit exceeded"]
        }

        target = ReconTarget(
            name="overflow-pkg",
            version="1.0.0",
            ecosystem="PyPI",
            github_repo="test-org/overflow-pkg",
            priority="HIGH",
            rationale="Test target",
            search_strategy="Standard",
            github_search_keywords=["security"],
        )

        with patch("triage_agent.agents.researcher.query_osv_single", return_value=(mock_vulns, mock_osv_errors)), \
             patch("triage_agent.agents.researcher.search_github_security_signals", return_value=mock_gh_signals), \
             patch("triage_agent.agents.researcher.get_github_token", return_value=None):
            
            res = run_researcher(target, dry_run=True)
            
            # The component MUST NOT be marked as failed / error!
            self.assertEqual(res.errors, [], "Errors must be empty since primary OSV succeeded and GH 403 is non-blocking in tokenless mode")
            # Recon notes should report finding the 15 signals
            self.assertIn("15 signal(s)", res.recon_notes)

    def test_osv_403_forbidden_is_recorded_as_fatal_unscanned_error(self):
        """If OSV query fails with HTTP 403 Forbidden, it MUST be recorded in unscanned_or_failed_components."""
        mock_target = ReconTarget(
            name="test-osv-fail",
            version="1.0.0",
            ecosystem="npm",
            priority="HIGH",
            rationale="Test",
            search_strategy="Standard",
        )
        fake_result = TargetResearchResult(
            target=mock_target,
            findings=[],
            recon_notes="OSV failed",
            errors=["OSV.dev query failed: HTTP 403 Forbidden"]
        )

        with patch("pathlib.Path.exists", return_value=True), \
             patch("triage_agent.pipeline.load_sbom_summary", return_value=[mock_target]), \
             patch("triage_agent.pipeline.query_osv_batch", return_value=({mock_target.name: []}, [], [])), \
             patch("triage_agent.pipeline.run_recon_planner", return_value=ReconPlan(
                 summary="Test summary",
                 total_components_scanned=1,
                 known_osv_hits_count=1,
                 targets=[mock_target],
             )), \
             patch("triage_agent.pipeline.run_researcher", return_value=fake_result):

            report, _ = execute_triage_pipeline(
                sbom_path="dummy.json",
                mode="dry-run",
            )

            # unscanned_or_failed_components MUST contain the OSV 403 Forbidden failure!
            self.assertTrue(any("test-osv-fail" in item and "403" in item for item in report.unscanned_or_failed_components))
            # Coverage summary must report failure, not "調査完了"
            self.assertIn("失敗・未調査警告あり", report.recon_coverage_summary)
            self.assertNotIn("調査完了", report.recon_coverage_summary)

    def test_vertex_403_or_gemini_429_is_recorded_as_fatal_unscanned_error(self):
        """If Gemini/Vertex AI fails with 403 PERMISSION_DENIED or 429 RESOURCE_EXHAUSTED,
        it MUST be captured in unscanned_or_failed_components and coverage summary updated."""
        mock_target = ReconTarget(
            name="gemini-fail-pkg",
            version="2.0.0",
            ecosystem="PyPI",
            priority="CRITICAL",
            rationale="Test LLM failure",
            search_strategy="Standard",
        )

        with patch("pathlib.Path.exists", return_value=True), \
             patch("triage_agent.pipeline.load_sbom_summary", return_value=[mock_target]), \
             patch("triage_agent.pipeline.query_osv_batch", return_value=({mock_target.name: []}, [], [])), \
             patch("triage_agent.pipeline.run_recon_planner", return_value=ReconPlan(
                 summary="Test summary",
                 total_components_scanned=1,
                 known_osv_hits_count=1,
                 targets=[mock_target],
             )), \
             patch("triage_agent.pipeline.run_researcher", side_effect=RuntimeError("429 RESOURCE_EXHAUSTED: rate limit exceeded")):

            report, _ = execute_triage_pipeline(
                sbom_path="dummy.json",
                mode="dry-run",
            )

            # unscanned_or_failed_components MUST contain the 429 error!
            self.assertTrue(any("gemini-fail-pkg" in item and "429" in item for item in report.unscanned_or_failed_components))
            self.assertIn("1 件失敗・未調査警告あり", report.recon_coverage_summary)

    def test_case_c_osv_batch_failed_with_max_targets(self):
        """Case C: When OSV batch query completely fails (503/network) and max_targets is limited,
        omitted components must NOT be claimed as '0 件確認' (clean), and must be listed in unscanned."""
        components = [
            ReconTarget(name=f"pkg-{i}", version="1.0.0", ecosystem="PyPI", priority="HIGH", rationale="Test", search_strategy="Standard")
            for i in range(6)
        ]
        deep_targets = components[:2]

        # OSV batch query failed completely
        with patch("pathlib.Path.exists", return_value=True), \
             patch("triage_agent.pipeline.load_sbom_summary", return_value=components), \
             patch("triage_agent.pipeline.query_osv_batch", return_value=({}, ["OSV.dev API HTTP 503 Service Unavailable"], [])), \
             patch("triage_agent.pipeline.run_recon_planner", return_value=ReconPlan(
                 summary="Test summary",
                 total_components_scanned=6,
                 known_osv_hits_count=0,
                 targets=deep_targets,
             )), \
             patch("triage_agent.pipeline.run_researcher", return_value=TargetResearchResult(
                 target=deep_targets[0], findings=[], recon_notes="ok", errors=[]
             )):

            report, _ = execute_triage_pipeline(
                sbom_path="dummy.json",
                mode="dry-run",
                max_targets=2,
            )

            # Must NOT claim '0 件確認' for the omitted 4 components
            self.assertNotIn("0 件確認", report.recon_coverage_summary)
            self.assertIn("OSV.dev 一括照会失敗により脆弱性未確認", report.recon_coverage_summary)
            # unscanned_or_failed_components must list the 4 unchecked components
            self.assertTrue(any("OSV.dev 一括照会失敗のため脆弱性未確認（4 件" in item for item in report.unscanned_or_failed_components))

    def test_case_d_component_name_with_colon_counting(self):
        """Case D: When a component name contains a colon (e.g. Maven 'org.apache.tomcat:tomcat-catalina')
        and fails, failed_c must correctly count it without breaking from string splitting."""
        mock_target = ReconTarget(
            name="org.apache.tomcat:tomcat-catalina",
            version="10.1.0",
            ecosystem="Maven",
            priority="CRITICAL",
            rationale="Test colon target",
            search_strategy="Standard",
        )

        with patch("pathlib.Path.exists", return_value=True), \
             patch("triage_agent.pipeline.load_sbom_summary", return_value=[mock_target]), \
             patch("triage_agent.pipeline.query_osv_batch", return_value=({mock_target.name: []}, [], [])), \
             patch("triage_agent.pipeline.run_recon_planner", return_value=ReconPlan(
                 summary="Test summary",
                 total_components_scanned=1,
                 known_osv_hits_count=1,
                 targets=[mock_target],
             )), \
             patch("triage_agent.pipeline.run_researcher", side_effect=RuntimeError("429 RESOURCE_EXHAUSTED")):

            report, _ = execute_triage_pipeline(
                sbom_path="dummy.json",
                mode="dry-run",
            )

            self.assertIn("1 件失敗・未調査警告あり", report.recon_coverage_summary)
            self.assertNotIn("調査完了", report.recon_coverage_summary)
            self.assertTrue(any("org.apache.tomcat:tomcat-catalina" in item for item in report.unscanned_or_failed_components))

    def test_github_401_bad_credentials_warned(self):
        """When a GITHUB_TOKEN is configured but fails with HTTP 401 Bad credentials,
        it must be surfaced in unscanned_or_failed_components and recon_coverage_summary."""
        from triage_agent.tools.github import reset_github_rate_limit, search_github_security_signals
        reset_github_rate_limit()

        mock_target = ReconTarget(
            name="urllib3",
            version="1.26.18",
            ecosystem="PyPI",
            priority="HIGH",
            rationale="Test 401",
            search_strategy="Standard",
        )

        # Mock search_github_security_signals returning 401
        with patch("pathlib.Path.exists", return_value=True), \
             patch("triage_agent.pipeline.load_sbom_summary", return_value=[mock_target]), \
             patch("triage_agent.pipeline.query_osv_batch", return_value=({mock_target.name: []}, [], [])), \
             patch("triage_agent.agents.researcher.query_osv_single", return_value=([], [])), \
             patch("triage_agent.pipeline.run_recon_planner", return_value=ReconPlan(
                 summary="Test summary",
                 total_components_scanned=1,
                 known_osv_hits_count=0,
                 targets=[mock_target],
             )), \
             patch("triage_agent.tools.github.get_github_token", return_value="ghp_invalid_or_expired_token"), \
             patch("httpx.Client.get") as mock_get:

            mock_resp = MagicMock()
            mock_resp.status_code = 401
            mock_resp.text = '{"message": "Bad credentials"}'
            mock_get.return_value = mock_resp

            report, _ = execute_triage_pipeline(
                sbom_path="dummy.json",
                mode="dry-run",
            )

            self.assertIn("HTTP 401 Bad credentials", report.recon_coverage_summary)
            self.assertTrue(any("GitHub API 認証エラー" in item for item in report.unscanned_or_failed_components))

    def test_case_g_circuit_breaker_resets_on_subsequent_run(self):
        """Case G: In long-running processes (e.g. GUI server), circuit breaker flags
        (_GITHUB_AUTH_FAILED and _RATE_LIMIT_EXCEEDED) must be reset at the start of each run."""
        mock_target = ReconTarget(
            name="urllib3",
            version="1.26.18",
            ecosystem="PyPI",
            priority="HIGH",
            rationale="Test Reset",
            search_strategy="Standard",
        )

        with patch("pathlib.Path.exists", return_value=True), \
             patch("triage_agent.pipeline.load_sbom_summary", return_value=[mock_target]), \
             patch("triage_agent.pipeline.query_osv_batch", return_value=({mock_target.name: []}, [], [])), \
             patch("triage_agent.agents.researcher.query_osv_single", return_value=([], [])), \
             patch("triage_agent.pipeline.run_recon_planner", return_value=ReconPlan(
                 summary="Test summary",
                 total_components_scanned=1,
                 known_osv_hits_count=0,
                 targets=[mock_target],
             )):

            # Run 1: Encounter 401 Bad credentials
            with patch("triage_agent.tools.github.get_github_token", return_value="ghp_bad_token"), \
                 patch("httpx.Client.get") as mock_get_401:
                mock_resp = MagicMock()
                mock_resp.status_code = 401
                mock_resp.text = '{"message": "Bad credentials"}'
                mock_get_401.return_value = mock_resp

                report1, _ = execute_triage_pipeline(
                    sbom_path="dummy.json",
                    mode="dry-run",
                )
                self.assertIn("HTTP 401 Bad credentials", report1.recon_coverage_summary)

            # Run 2: Token is fixed / removed, GitHub returns 200 OK
            with patch("triage_agent.tools.github.get_github_token", return_value=None), \
                 patch("httpx.Client.get") as mock_get_200:
                mock_resp_ok = MagicMock()
                mock_resp_ok.status_code = 200
                mock_resp_ok.json.return_value = []
                mock_get_200.return_value = mock_resp_ok

                report2, _ = execute_triage_pipeline(
                    sbom_path="dummy.json",
                    mode="dry-run",
                )

                # report2 MUST NOT retain the 401 notice from run 1
                self.assertNotIn("HTTP 401 Bad credentials", report2.recon_coverage_summary)
                self.assertFalse(any("GitHub API 認証エラー" in item for item in report2.unscanned_or_failed_components))
                # Summary should indicate full scan completion
                self.assertIn("調査完了", report2.recon_coverage_summary)


if __name__ == "__main__":
    unittest.main()
