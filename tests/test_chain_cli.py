"""Integration tests for CLI Exploit Chain and Linux Kernel Exposure Audit (v0.4.0)."""

import json
import tempfile
import unittest
from pathlib import Path

from triage_agent.chain.engine import (
    load_environment_definition,
    load_node_telemetries,
    run_exploit_chain_audit,
)
from triage_agent.chain.models import (
    ChainLevel,
    DistroAffectedRange,
    KernelVulnerabilityEntry,
)


class TestChainCLIIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.work_dir = Path(self.temp_dir.name)

        # Create a test environment definition
        self.env_yaml = self.work_dir / "test_env.yaml"
        self.env_yaml.write_text(
            """
environment: "staging"
node_pools:
  - id: "pool-edge"
    os_distro: "ubuntu"
    kernel_package: "6.8.0-40.40"
workloads:
  - id: "public-php-app"
    exposure: "internet_facing"
    node_pool_id: "pool-edge"
    components: ["CVE-2026-109618"]
  - id: "internal-db"
    exposure: "internal_only"
    node_pool_id: "pool-edge"
    components: []
""",
            encoding="utf-8",
        )

        # Create test telemetry with all 3 modules disabled but IPsec service active (Conflict!)
        self.telemetry_json = self.work_dir / "telemetry_edge.json"
        self.telemetry_json.write_text(
            json.dumps({
                "node_id": "pool-edge",
                "distro_package_version": "6.8.0-40.40",
                "loaded_modules": [],
                "builtin_modules": [],
                "modprobe_config": [
                    "install esp4 /bin/false",
                    "install esp6 /bin/false",
                    "install rxrpc /bin/false"
                ],
                "active_services": ["ipsec"],
                "livepatch_active": False
            }),
            encoding="utf-8",
        )

        # Prepare local KEV cache so ThreatFeedClient can resolve in offline / dry-run mode
        cache_dir = Path("triage-output/cache")
        cache_dir.mkdir(parents=True, exist_ok=True)
        self.kev_cache_file = cache_dir / "cisa_kev_catalog.json"
        self.kev_cache_file.write_text(
            json.dumps({
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2026-109618",
                        "vendorProject": "PHP",
                        "product": "PHP",
                        "vulnerabilityName": "PHP2Shell RCE",
                        "dateAdded": "2026-10-24"
                    }
                ]
            }),
            encoding="utf-8",
        )

        # Create test chain ledger
        self.ledger_json = self.work_dir / "test_ledger.json"
        self.ledger_json.write_text(
            json.dumps([
                {
                    "cve_id": "CVE-2026-46300",
                    "name": "Fragnesia IPsec LPE",
                    "source_url": "https://ubuntu.com/security/notices/USN-7000-1",
                    "retrieved_at": "2026-10-31",
                    "epss_score": 0.42,
                    "cisa_kev": True,
                    "distro_affected_ranges": {
                        "ubuntu": {
                            "package": "linux",
                            "fixed_version": "6.8.0-47.47"
                        }
                    }
                }
            ]),
            encoding="utf-8",
        )

        self.fragnesia_cve = KernelVulnerabilityEntry(
            cve_id="CVE-2026-46300",
            name="Fragnesia IPsec LPE",
            source_url="https://ubuntu.com/security/notices/USN-7000-1",
            retrieved_at="2026-10-31",
            epss_score=0.42,
            cisa_kev=True,
            poc_available=True,
            poc_evidence="Public PoC attributed in BleepingComputer",
            distro_affected_ranges={
                "ubuntu": DistroAffectedRange(
                    package="linux",
                    fixed_version="6.8.0-47.47",
                )
            },
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_load_environment_and_telemetry(self):
        env = load_environment_definition(str(self.env_yaml))
        self.assertEqual(env.environment_name, "staging")
        self.assertEqual(len(env.node_pools), 1)
        self.assertEqual(env.node_pools[0].pool_id, "pool-edge")
        self.assertEqual(len(env.workloads), 2)

        telemetries = load_node_telemetries(str(self.telemetry_json))
        self.assertIn("pool-edge", telemetries)
        self.assertIn("esp4", telemetries["pool-edge"].modprobe_disabled_modules)
        self.assertIn("ipsec", telemetries["pool-edge"].active_services)

    def test_critical_chain_with_side_effect_conflict(self):
        from triage_agent.chain.feeds import ThreatFeedClient
        feed_client = ThreatFeedClient()
        feed_results = feed_client.analyze_cves(["CVE-2026-109618"], offline=True)

        env = load_environment_definition(str(self.env_yaml))
        telemetries = load_node_telemetries(str(self.telemetry_json))

        # Run chain audit with feed results
        items = run_exploit_chain_audit(
            environment=env,
            kernel_vulnerabilities=[self.fragnesia_cve],
            telemetries=telemetries,
            feed_results=feed_results,
        )

        # public-php-app should trigger CRITICAL_CHAIN because:
        # 1. It is internet_facing
        # 2. It has CVE-2026-109618 (PHP2Shell, CISA KEV listed)
        # 3. Kernel on pool-edge is vulnerable (6.8.0-40.40 < 6.8.0-47.47)
        # 4. Mitigation is BLOCKED_BY_SIDE_EFFECT due to active ipsec service
        php_item = next(i for i in items if i.workload_name == "public-php-app")
        self.assertEqual(php_item.chain_level, ChainLevel.CRITICAL_CHAIN)
        self.assertIn("48時間以内", php_item.action_deadline)
        self.assertIn("internal-db", php_item.blast_radius[0])

        # Verify side effect conflict is recorded in recommendations
        conflict_rec = any("ipsec" in rec.lower() or "副作用" in rec for rec in php_item.recommendations)
        self.assertTrue(conflict_rec)

    def test_cli_fail_on_critical_chain(self):
        """CLI must exit with code 2 when --fail-on critical_chain or chain is triggered."""
        import subprocess
        import sys
        cmd = [
            sys.executable,
            "-m",
            "triage_agent.cli",
            "--chain-audit",
            "--environments",
            str(self.env_yaml),
            "--telemetry",
            str(self.telemetry_json),
            "--chain-ledger",
            str(self.ledger_json),
            "--fail-on",
            "critical_chain",
            "--dry-run",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("CRITICAL ALERT", proc.stdout)
        self.assertIn("CI/CD ガードレール違反", proc.stdout)

    def test_feed_failure_disclosure_in_report(self):
        """Review Point: Disclose feed fetch failures in markdown report header."""
        from triage_agent.chain.engine import format_chain_audit_markdown
        from triage_agent.chain.feeds import ThreatFeedResult

        mock_feed_with_errors = {
            "CVE-2026-11111": ThreatFeedResult(
                cve_id="CVE-2026-11111",
                in_cisa_kev=None,
                error="CISA KEV: Network unreachable",
                verified=False,
            ),
            "CVE-2026-22222": ThreatFeedResult(
                cve_id="CVE-2026-22222",
                in_cisa_kev=False,
                error="OSV: 取得失敗 (Connection timed out)",
                verified=False,
            ),
        }
        report_md = format_chain_audit_markdown(
            items=[],
            environment_name="staging",
            feed_results=mock_feed_with_errors,
        )
        self.assertIn("フィード同期ステータス・調査不全の開示", report_md)
        self.assertIn("KEV 取得失敗: 1 件", report_md)
        self.assertIn("OSV 取得失敗: 1 件", report_md)
        self.assertIn("調べなかったものを隠さない", report_md)


if __name__ == "__main__":
    unittest.main()
