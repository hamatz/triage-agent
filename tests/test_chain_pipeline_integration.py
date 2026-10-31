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

    def test_aws_kernel_flavor_indeterminate_fail_safe(self):
        """Review Point: Ubuntu AWS kernel 6.8.0-1015.16 must NOT match generic Ubuntu fixed version 6.8.0-47.47 and declare SAFE."""
        env_aws_yaml = self.work_dir / "aws_env.yaml"
        env_aws_yaml.write_text(
            f"""
environment: "aws-production"
node_pools:
  - id: "aws-dmz-pool"
    os_distro: "ubuntu"
    os_release: "24.04"
    kernel_package: "linux-aws"
    kernel_flavor: "linux-aws"
    kernel_package_version: "6.8.0-1015.16"
workloads:
  - id: "web-aws"
    exposure: "internet_facing"
    node_pool_id: "aws-dmz-pool"
    sbom_path: "{self.sbom_file.resolve()}"
    components: ["php"]
""",
            encoding="utf-8",
        )
        env = load_environment_definition(str(env_aws_yaml))
        telemetry = NodeTelemetry(
            pool_id="aws-dmz-pool",
            os_distribution="ubuntu",
            os_release="24.04",
            kernel_package_name="linux-aws",
            kernel_flavor="linux-aws",
            kernel_package_version="6.8.0-1015.16",
            loaded_modules=["esp4"],
            modprobe_disabled_modules=[],
            active_services=[],
        )
        mock_triage_report = TriageReport(
            report_title="Triage Report for Web AWS Workload",
            scan_target="web_sbom.json",
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="php",
                    component_name="php",
                    announcement_date="2026-10-24",
                    conclusion="Critical RCE (PHP2Shell)",
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
        mock_feeds = {
            "CVE-2026-109618": ThreatFeedResult(
                cve_id="CVE-2026-109618",
                in_cisa_kev=True,
                epss_score=0.42,
                verified=True,
            )
        }

        results = run_exploit_chain_audit(
            environment=env,
            kernel_vulnerabilities=[self.fragnesia_lpe],
            telemetries={"aws-dmz-pool": telemetry},
            evaluation_date="2026-10-31",
            feed_results=mock_feeds,
            triage_report=mock_triage_report,
        )

        item = results[0]
        self.assertEqual(item.workload_name, "web-aws")
        # Must NOT be evaluated as SAFE! Because AWS flavor has no fixed version in ledger, it defaults to indeterminate (該当の可能性あり⚠️)
        self.assertNotEqual(item.chain_level, ChainLevel.SAFE)
        self.assertIn("要確認", item.kernel_status)
        self.assertIn("該当の可能性あり⚠️", item.kernel_status)
        # Combined with confirmed app foothold (PHP2Shell in KEV) on internet-facing workload:
        self.assertEqual(item.chain_level, ChainLevel.CRITICAL_CHAIN)

    def test_missing_sbom_failsafe(self):
        """Review Point: Workload with missing sbom_path must evaluate to HIGH_UNVERIFIED (not silently treated as clean/SAFE)."""
        env_missing_sbom_yaml = self.work_dir / "missing_sbom_env.yaml"
        env_missing_sbom_yaml.write_text(
            """
environment: "production"
node_pools:
  - id: "dmz-pool"
    os_distro: "ubuntu"
    os_release: "24.04"
    kernel_package: "6.8.0-40.40"
workloads:
  - id: "web-missing-sbom"
    exposure: "internet_facing"
    node_pool_id: "dmz-pool"
    sbom_path: "/nonexistent/path/to/missing_sbom.json"
""",
            encoding="utf-8",
        )
        env = load_environment_definition(str(env_missing_sbom_yaml))
        telemetry = NodeTelemetry(
            pool_id="dmz-pool",
            kernel_package_version="6.8.0-40.40",
            loaded_modules=["esp4"],
            modprobe_disabled_modules=[],
            active_services=[],
        )

        results = run_exploit_chain_audit(
            environment=env,
            kernel_vulnerabilities=[self.fragnesia_lpe],
            telemetries={"dmz-pool": telemetry},
            evaluation_date="2026-10-31",
        )

        item = results[0]
        self.assertEqual(item.workload_name, "web-missing-sbom")
        self.assertEqual(item.chain_level, ChainLevel.HIGH_UNVERIFIED)
        self.assertIn("SBOM-MISSING", item.foothold_detail)
        self.assertIn("人手確認", item.action_deadline)

    def test_corrupt_sbom_failsafe(self):
        """Review Point: Workload with corrupt/invalid JSON sbom_path must evaluate to HIGH_UNVERIFIED."""
        corrupt_sbom = self.work_dir / "corrupt_sbom.json"
        corrupt_sbom.write_text("{invalid_json: true,", encoding="utf-8")

        env_corrupt_yaml = self.work_dir / "corrupt_sbom_env.yaml"
        env_corrupt_yaml.write_text(
            f"""
environment: "production"
node_pools:
  - id: "dmz-pool"
    os_distro: "ubuntu"
    os_release: "24.04"
    kernel_package: "6.8.0-40.40"
workloads:
  - id: "web-corrupt-sbom"
    exposure: "internet_facing"
    node_pool_id: "dmz-pool"
    sbom_path: "{corrupt_sbom.resolve()}"
""",
            encoding="utf-8",
        )
        env = load_environment_definition(str(env_corrupt_yaml))
        telemetry = NodeTelemetry(
            pool_id="dmz-pool",
            kernel_package_version="6.8.0-40.40",
            loaded_modules=["esp4"],
            modprobe_disabled_modules=[],
            active_services=[],
        )

        results = run_exploit_chain_audit(
            environment=env,
            kernel_vulnerabilities=[self.fragnesia_lpe],
            telemetries={"dmz-pool": telemetry},
            evaluation_date="2026-10-31",
        )

        item = results[0]
        self.assertEqual(item.workload_name, "web-corrupt-sbom")
        self.assertEqual(item.chain_level, ChainLevel.HIGH_UNVERIFIED)
        self.assertIn("SBOM-CORRUPT", item.foothold_detail)

    def test_triage_report_path_three_feed_states(self):
        """Review Point: Workload with SBOM + TriageReport (unnormalized CVE and no vector)

        Tests the 3 feed states:
        1. KEV = True -> CRITICAL_CHAIN
        2. KEV 取得失敗 (in_cisa_kev=None, error recorded) -> HIGH_UNVERIFIED (要確認)
        3. フィードなし (feed_results empty) -> HIGH_UNVERIFIED (要確認)
        """
        env = load_environment_definition(str(self.env_yaml))
        telemetry = NodeTelemetry(
            pool_id="dmz-pool",
            kernel_package_version="6.8.0-40.40",
            loaded_modules=["esp4"],
            modprobe_disabled_modules=[],
            active_services=[],
        )
        triage_report = TriageReport(
            report_title="Triage Report for Web Workload",
            scan_target=str(self.sbom_file),
            total_dependencies=1,
            notices=[
                TriageNotice(
                    product_name="php",
                    component_name="php",
                    announcement_date="2026-10-24",
                    conclusion="PHP session upload uninitialized pointer flaw",
                    fixed_versions="8.3.13",
                    severity_note="Critical (CVSS 9.2)",
                    check_points=[
                        CheckPointItem(
                            target_or_cve="CVE-2026-109618 (CVSS 9.2 Critical)",
                            cvss="9.2",
                            content_summary="Uninitialized memory reference in session upload progress",
                            affected_versions="< 8.3.13",
                            check_point_yes_no="session.upload_progress.enabled が有効か",
                            verification_method="php.ini 設定確認",
                        )
                    ],
                )
            ],
        )

        # State 1: KEV = True -> CRITICAL_CHAIN
        feeds_kev_true = {
            "CVE-2026-109618": ThreatFeedResult(
                cve_id="CVE-2026-109618",
                in_cisa_kev=True,
                epss_score=0.42,
                verified=True,
            )
        }
        res_1 = run_exploit_chain_audit(
            environment=env,
            kernel_vulnerabilities=[self.fragnesia_lpe],
            telemetries={"dmz-pool": telemetry},
            feed_results=feeds_kev_true,
            triage_report=triage_report,
        )
        self.assertEqual(res_1[0].chain_level, ChainLevel.CRITICAL_CHAIN)
        self.assertIn("48時間以内", res_1[0].action_deadline)
        self.assertIn("CVE-2026-109618", res_1[0].foothold_detail)

        # State 2: KEV 取得失敗 (in_cisa_kev=None) -> HIGH_UNVERIFIED
        feeds_kev_failed = {
            "CVE-2026-109618": ThreatFeedResult(
                cve_id="CVE-2026-109618",
                in_cisa_kev=None,
                error="CISA KEV: Network unreachable",
                verified=False,
            )
        }
        res_2 = run_exploit_chain_audit(
            environment=env,
            kernel_vulnerabilities=[self.fragnesia_lpe],
            telemetries={"dmz-pool": telemetry},
            feed_results=feeds_kev_failed,
            triage_report=triage_report,
        )
        self.assertEqual(res_2[0].chain_level, ChainLevel.HIGH_UNVERIFIED)
        self.assertIn("2週間以内", res_2[0].action_deadline)

        # State 3: フィードなし (feed_results={}) -> HIGH_UNVERIFIED
        res_3 = run_exploit_chain_audit(
            environment=env,
            kernel_vulnerabilities=[self.fragnesia_lpe],
            telemetries={"dmz-pool": telemetry},
            feed_results={},
            triage_report=triage_report,
        )
        self.assertEqual(res_3[0].chain_level, ChainLevel.HIGH_UNVERIFIED)
        self.assertIn("2週間以内", res_3[0].action_deadline)



if __name__ == "__main__":
    unittest.main()
