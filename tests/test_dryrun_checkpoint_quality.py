import unittest
from triage_agent.agents.triage import run_triage_agent
from triage_agent.schemas import (
    ReconTarget,
    ResearchFinding,
    TargetResearchResult,
)


class TestDryrunCheckpointQuality(unittest.TestCase):
    def test_axios_check_points_are_concrete_and_not_generic(self):
        target = ReconTarget(name="axios", version="0.21.1", ecosystem="npm", priority="HIGH", rationale="Test")
        findings = [
            ResearchFinding(
                id="CVE-2026-101909",
                title="Prototype Pollution Gadget in axios toFormData Options",
                severity="High",
                cvss="8.3 (High)",
                affected_versions="< 1.7.4",
                applies_to_current_version=True,
                summary="Prototype pollution via toFormData",
            ),
            ResearchFinding(
                id="CVE-2026-101901",
                title="Denial of Service via Unhandled error Event in HTTP/2 ClientHttp2Session Initialization",
                severity="High",
                cvss="8.2 (High)",
                affected_versions="< 1.7.0",
                applies_to_current_version=True,
                summary="DoS via HTTP/2",
            ),
            ResearchFinding(
                id="CVE-2026-101906",
                title="ReDoS in shouldBypassProxy host normalization, reachable via untrusted redirect",
                severity="High",
                cvss="8.2 (High)",
                affected_versions="< 1.7.0",
                applies_to_current_version=True,
                summary="ReDoS in proxy bypass",
            ),
        ]
        research_result = TargetResearchResult(
            target=target,
            findings=findings,
            recon_notes="Test notes",
            errors=[],
        )

        report = run_triage_agent([research_result], dry_run=True)
        self.assertEqual(len(report.notices), 1)
        notice = report.notices[0]
        self.assertEqual(len(notice.check_points), 3)

        for cp in notice.check_points:
            # Must NOT contain forbidden generic templates
            self.assertNotIn("特定脆弱機能", cp.check_point_yes_no)
            self.assertNotIn("設定ディレクティブを grep 検索", cp.verification_method)

            # Must contain concrete tokens and clear YES/NO conditions
            if "toFormData" in cp.content_summary:
                self.assertIn("toFormData", cp.check_point_yes_no)
                self.assertIn("toFormData", cp.verification_method)
                self.assertIn("NO", cp.verification_method)
            elif "HTTP/2" in cp.content_summary:
                self.assertIn("HTTP/2", cp.check_point_yes_no)
                self.assertIn("http2", cp.verification_method)
                self.assertIn("NO", cp.verification_method)
            elif "shouldBypassProxy" in cp.content_summary:
                self.assertIn("proxy", cp.check_point_yes_no)
                self.assertIn("proxy", cp.verification_method)
                self.assertIn("NO", cp.verification_method)


if __name__ == "__main__":
    unittest.main()
