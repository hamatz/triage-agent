import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from triage_agent.chain.engine import (
    _aggregate_pool_telemetries,
    load_node_telemetries,
)
from triage_agent.chain.mitigations import evaluate_kernel_mitigation
from triage_agent.chain.models import NodeTelemetry
from triage_agent.pipeline import execute_triage_pipeline
from triage_agent.tools.sbom import _is_excluded, load_sbom_summary


class TestNodePoolAggregation(unittest.TestCase):
    """Verify that multiple nodes in the same node pool aggregate fail-safely."""

    def setUp(self):
        self.cve_id = "CVE-2026-46300"

    def test_pool_aggregation_unmitigated_node_wins_regardless_of_order(self):
        """If one node has esp4 loaded and another is completely mitigated, the pool is unmitigated."""
        unmitigated_node = NodeTelemetry(
            node_id="node-unmitigated",
            pool_id="dmz-pool",
            kernel_release="6.8.0-1015-aws",
            os_distribution="ubuntu",
            os_release="24.04",
            kernel_package_name="linux-aws",
            kernel_package_version="6.8.0-1015.16",
            loaded_modules=["esp4"],
            builtin_modules=[],
            modprobe_disabled_modules=[],
            active_services=[],
            xfrm_active=False,
        )

        mitigated_node = NodeTelemetry(
            node_id="node-mitigated",
            pool_id="dmz-pool",
            kernel_release="6.8.0-1015-aws",
            os_distribution="ubuntu",
            os_release="24.04",
            kernel_package_name="linux-aws",
            kernel_package_version="6.8.0-1015.16",
            loaded_modules=[],
            builtin_modules=[],
            modprobe_disabled_modules=["esp4", "esp6", "rxrpc"],
            active_services=[],
            xfrm_active=False,
        )

        # Order 1: unmitigated first, then mitigated
        agg1 = _aggregate_pool_telemetries([unmitigated_node, mitigated_node])
        status1 = evaluate_kernel_mitigation(self.cve_id, agg1)
        self.assertFalse(status1["is_mitigated"], "Pool must NOT be mitigated if any node has loaded module")
        self.assertIn("esp4", status1["reasoning"])

        # Order 2: mitigated first, then unmitigated
        agg2 = _aggregate_pool_telemetries([mitigated_node, unmitigated_node])
        status2 = evaluate_kernel_mitigation(self.cve_id, agg2)
        self.assertFalse(status2["is_mitigated"], "Pool must NOT be mitigated if any node has loaded module (order 2)")
        self.assertIn("esp4", status2["reasoning"])

    def test_pool_aggregation_all_nodes_mitigated(self):
        """If all nodes in the pool have unloaded and blacklisted modules, the pool is mitigated."""
        node1 = NodeTelemetry(
            node_id="node-01",
            pool_id="prod-pool",
            kernel_release="6.8.0-1015-aws",
            os_distribution="ubuntu",
            os_release="24.04",
            kernel_package_name="linux-aws",
            kernel_package_version="6.8.0-1015.16",
            loaded_modules=[],
            builtin_modules=[],
            modprobe_disabled_modules=["esp4", "esp6", "rxrpc"],
            active_services=[],
            xfrm_active=False,
        )
        node2 = NodeTelemetry(
            node_id="node-02",
            pool_id="prod-pool",
            kernel_release="6.8.0-1015-aws",
            os_distribution="ubuntu",
            os_release="24.04",
            kernel_package_name="linux-aws",
            kernel_package_version="6.8.0-1015.16",
            loaded_modules=[],
            builtin_modules=[],
            modprobe_disabled_modules=["esp4", "esp6", "rxrpc"],
            active_services=[],
            xfrm_active=False,
        )
        agg = _aggregate_pool_telemetries([node1, node2])
        status = evaluate_kernel_mitigation(self.cve_id, agg)
        self.assertTrue(status["is_mitigated"])
        self.assertEqual(status["status"], "MITIGATED")

    def test_pool_aggregation_xfrm_active_on_any_node(self):
        """If IPsec/xfrm is active on any node, mitigation is blocked on the pool."""
        node1 = NodeTelemetry(
            node_id="node-01",
            pool_id="vpn-pool",
            kernel_release="6.8.0-1015-aws",
            os_distribution="ubuntu",
            os_release="24.04",
            kernel_package_name="linux-aws",
            kernel_package_version="6.8.0-1015.16",
            loaded_modules=[],
            builtin_modules=[],
            modprobe_disabled_modules=["esp4", "esp6", "rxrpc"],
            active_services=[],
            xfrm_active=False,
        )
        node2 = NodeTelemetry(
            node_id="node-02",
            pool_id="vpn-pool",
            kernel_release="6.8.0-1015-aws",
            os_distribution="ubuntu",
            os_release="24.04",
            kernel_package_name="linux-aws",
            kernel_package_version="6.8.0-1015.16",
            loaded_modules=[],
            builtin_modules=[],
            modprobe_disabled_modules=["esp4", "esp6", "rxrpc"],
            active_services=["strongswan"],
            xfrm_active=True,
        )
        agg = _aggregate_pool_telemetries([node1, node2])
        status = evaluate_kernel_mitigation(self.cve_id, agg)
        self.assertFalse(status["is_mitigated"])
        self.assertEqual(status["status"], "BLOCKED_BY_SIDE_EFFECT")

    def test_load_node_telemetries_directory_aggregates_same_pool(self):
        """load_node_telemetries should group files in directory by pool_id and aggregate."""
        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir)
            t1 = {
                "node_id": "worker-01",
                "pool_id": "app-pool",
                "kernel_release": "6.8.0-1015-aws",
                "os_distribution": "ubuntu",
                "os_release": "24.04",
                "kernel_package_name": "linux-aws",
                "kernel_package_version": "6.8.0-1015.16",
                "loaded_modules": ["esp4"],
                "builtin_modules": [],
                "modprobe_disabled_modules": [],
                "active_services": [],
                "xfrm_active": False,
            }
            t2 = {
                "node_id": "worker-02",
                "pool_id": "app-pool",
                "kernel_release": "6.8.0-1015-aws",
                "os_distribution": "ubuntu",
                "os_release": "24.04",
                "kernel_package_name": "linux-aws",
                "kernel_package_version": "6.8.0-1015.16",
                "loaded_modules": [],
                "builtin_modules": [],
                "modprobe_disabled_modules": ["esp4", "esp6", "rxrpc"],
                "active_services": [],
                "xfrm_active": False,
            }
            (p / "node1.json").write_text(json.dumps(t1))
            (p / "node2.json").write_text(json.dumps(t2))

            telemetries = load_node_telemetries(str(p))
            self.assertIn("app-pool", telemetries)
            agg = telemetries["app-pool"]
            self.assertIn("esp4", agg.loaded_modules)
            self.assertEqual(agg.modprobe_disabled_modules, [])


class TestExcludePatterns(unittest.TestCase):
    """Verify internal package privacy via --exclude patterns."""

    def test_is_excluded_helper(self):
        patterns = ["@mycompany/*", "internal-*", "secret-lib"]
        self.assertTrue(_is_excluded("@mycompany/auth-service", "pkg:npm/%40mycompany/auth-service@1.0.0", patterns))
        self.assertTrue(_is_excluded("internal-db-connector", None, patterns))
        self.assertTrue(_is_excluded("secret-lib", None, patterns))
        self.assertFalse(_is_excluded("lodash", "pkg:npm/lodash@4.17.21", patterns))
        self.assertFalse(_is_excluded("express", None, patterns))

    def test_load_sbom_summary_filters_excluded_packages(self):
        cyclonedx_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
                {"name": "@mycompany/billing", "version": "1.0.0", "purl": "pkg:npm/%40mycompany/billing@1.0.0"},
                {"name": "internal-utils", "version": "2.1.0"},
            ],
        }
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(cyclonedx_sbom, f)
            temp_path = f.name

        try:
            components = load_sbom_summary(temp_path, exclude_patterns=["@mycompany/*", "internal-*"])
            comp_names = [c.name for c in components]
            self.assertEqual(comp_names, ["express"])
            self.assertEqual(len(components), 1)
        finally:
            Path(temp_path).unlink(missing_ok=True)


class TestNetworkIsolation(unittest.TestCase):
    """Verify that --demo and --dry-run strictly prevent unexpected external network calls."""

    @patch("urllib.request.urlopen")
    def test_demo_mode_zero_network_calls(self, mock_urlopen):
        """In demo mode, execute_triage_pipeline must make 0 external HTTP requests."""
        mock_urlopen.side_effect = AssertionError("Network call occurred in demo mode!")

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({"bomFormat": "CycloneDX", "specVersion": "1.4", "components": []}, f)
            temp_path = f.name

        try:
            triage_report, _ = execute_triage_pipeline(
                sbom_path=temp_path,
                mode="demo",
            )
            self.assertIsNotNone(triage_report)
            mock_urlopen.assert_not_called()
        finally:
            Path(temp_path).unlink(missing_ok=True)

    @patch("triage_agent.agents.researcher.run_researcher")
    @patch("triage_agent.config.get_genai_client")
    def test_dry_run_zero_gemini_calls(self, mock_client, mock_researcher):
        """In dry-run mode, Gemini API client and Researcher LLM loops must not be invoked."""
        mock_client.side_effect = AssertionError("Gemini client invoked in dry-run mode!")
        mock_researcher.return_value = MagicMock(research_summary="Dry run summary")

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump({
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "components": [{"name": "lodash", "version": "4.17.20"}]
            }, f)
            temp_path = f.name

        try:
            with patch("triage_agent.tools.osv.query_osv_batch") as mock_osv:
                mock_osv.return_value = {}
                triage_report, _ = execute_triage_pipeline(
                    sbom_path=temp_path,
                    mode="dry-run",
                )
                self.assertTrue(triage_report.is_dry_run)
                mock_client.assert_not_called()
        finally:
            Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
