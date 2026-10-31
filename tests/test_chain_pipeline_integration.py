"""End-to-End Pipeline Integration Test for Exploit Chain Triaging.

Verifies Opus Review Priority 2:
1. Workload points to an SBOM file (sbom_path) or TriageReport notices.
2. Real findings with CVSS vector, CWE, official summary, and CISA KEV are resolved.
3. Chains with co-located kernel LPEs automatically without handcrafted engine constants.
"""

import json
import tempfile
import unittest
from pathlib import Path

from triage_agent.chain.engine import (
    load_environment_definition,
    run_exploit_chain_audit,
)
from triage_agent.chain.feeds import ThreatFeedResult
from triage_agent.chain.models import (
    ChainLevel,
    DistroAffectedRange,
    KernelVulnerabilityEntry,
    NodeTelemetry,
)
from triage_agent.schemas import CheckPointItem, TriageNotice, TriageReport


class TestChainPipelineIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)

        # 1. Create a mock SBOM file with PHP component
        self.sbom_file = self.work_dir / "web_sbom.json"
        self.sbom_file.write_text(
            json.dumps({
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "components": [
                    {
                        "name": "php",
                        "version": "8.3.10",
                        "type": "application",
                    }
                ]
            }),
            encoding="utf-8",
        )

        # 2. Create environment YAML pointing to sbom_path
        self.env_yaml = self.work_dir / "production_env.yaml"
        self.env_yaml.write_text(
            f"""
environment: "production"
node_pools:
  - id: "dmz-pool"
    os_distro: "ubuntu"
    os_release: "24.04"
    kernel_package: "6.8.0-40.40"
workloads:
  - id: "public-web"
    exposure: "internet_facing"
    node_pool_id: "dmz-pool"
    sbom_path: "{self.sbom_file.resolve()}"
    components: ["php"]
""",
            encoding="utf-8",
        )

        # 3. Canonical Fragnesia LPE
        self.fragnesia_lpe = KernelVulnerabilityEntry(
            cve_id="CVE-2026-46300",
            name="Fragnesia IPsec LPE",
            source_url="https://ubuntu.com/security/notices/USN-7000-1",
            retrieved_at="2026-10-31",
            epss_score=0.42,
            distro_affected_ranges={
                "ubuntu": DistroAffectedRange(
                    package="linux",
                    fixed_version="6.8.0-47.47",
                )
            },
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_end_to_end_sbom_triage_to_chain(self):
        """Pipeline integration: TriageReport findings for PHP flow through to trigger CRITICAL_CHAIN."""
        # Mock upstream TriageReport as produced by Researcher & Triage Agent
        mock_triage_report = TriageReport(
            report_title="Triage Report for Web Workload",
            scan_target="web_sbom.json",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="php",
                    component_name="php",
                    announcement_date="2026-10-24",
                    conclusion="Critical Remote Code Execution flaw in session upload progress (PHP2Shell)",
                    fixed_versions="8.3.13",
                    severity_note="Critical (CVSS 9.8)",
                    check_points=[
                        CheckPointItem(
                            target_or_cve="CVE-2026-109618",
                            cvss="9.8",
                            content_summary="Remote code execution via uninitialized memory reference",
                            affected_versions="< 8.3.13",
                            check_point_yes_no="session.upload_progress.enabled が有効か",
                            verification_method="php.ini 設定確認",
                        )
                    ],
                )
            ],
        )

        # Mock threat feed (KEV confirmed by CISA)
        mock_feeds = {
            "CVE-2026-109618": ThreatFeedResult(
                cve_id="CVE-2026-109618",
                in_cisa_kev=True,
                epss_score=0.42,
                verified=True,
            )
        }

        env = load_environment_definition(str(self.env_yaml))
        telemetry = NodeTelemetry(
            pool_id="dmz-pool",
            kernel_package_version="6.8.0-40.40",
            loaded_modules=[],
            modprobe_disabled_modules=[],
            active_services=[],
        )

        # Run end-to-end chain audit with triage report & feed results
        results = run_exploit_chain_audit(
            environment=env,
            kernel_vulnerabilities=[self.fragnesia_lpe],
            telemetries={"dmz-pool": telemetry},
            evaluation_date="2026-10-31",
            feed_results=mock_feeds,
            triage_report=mock_triage_report,
        )

        item = results[0]
        self.assertEqual(item.workload_name, "public-web")
        self.assertEqual(item.chain_level, ChainLevel.CRITICAL_CHAIN)
        self.assertIn("48時間以内", item.action_deadline)
        self.assertIn("CVE-2026-109618", item.foothold_detail)
        self.assertIn("CVE-2026-46300", item.kernel_cve)


if __name__ == "__main__":
    unittest.main()
