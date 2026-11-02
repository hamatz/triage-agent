"""Tests for telemetry coverage, freshness and pool consistency (ADR-021 decisions 4 and 5).

Covers the multi-machine collection scenario:
1. A pool is only "confirmed by live telemetry" when every expected node was collected.
   Partial coverage must never produce SAFE or MITIGATED.
2. Stale telemetry is excluded from the evidence.
3. Records without pool_id are rejected instead of being merged into a bogus pool.
4. Duplicate records of the same node are de-duplicated (newest wins).
5. Collection manifests declare the expected node set (distro / platform neutral JSON).
6. Pools present only in telemetry, or only in the environment definition, are reported.
"""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from triage_agent.chain.engine import (
    _parse_disabled_modules,
    audit_exploit_chains,
    build_pool_coverage,
    find_pool_mismatches,
    format_chain_audit_markdown,
    load_environment_definition,
    load_node_telemetries_with_report,
)
from triage_agent.chain.models import (
    ChainLevel,
    DistroAffectedRange,
    EnvironmentDefinition,
    ExposureType,
    KernelVulnerabilityEntry,
    NodePoolDefinition,
    WorkloadDefinition,
)

NOW = datetime(2026, 11, 2, 0, 0, 0, tzinfo=timezone.utc)
FRESH = "2026-11-01T00:00:00Z"
STALE = "2026-10-01T00:00:00Z"

LPE = KernelVulnerabilityEntry(
    cve_id="CVE-2026-46300",
    name="Fragnesia",
    source_url="https://example.com/advisory",
    retrieved_at="2026-10-31",
    distro_affected_ranges={
        "ubuntu": DistroAffectedRange(package="linux", fixed_version="6.8.0-47.47"),
    },
)


def _node(pool_id, node_id, version="6.8.0-47.47", collected_at=FRESH, disabled=None, **extra):
    data = {
        "node_id": node_id,
        "pool_id": pool_id,
        "collected_at": collected_at,
        "os_distribution": "ubuntu",
        "os_release": "24.04",
        "kernel_package_name": "linux-image-6.8.0-47-generic",
        "kernel_flavor": "linux",
        "distro_package_version": version,
        "loaded_modules": [],
        "builtin_modules": [],
        "modprobe_config": [f"install {m} /bin/false" for m in (disabled or [])],
        "active_services": [],
        "xfrm_active": False,
    }
    data.update(extra)
    return data


def _env(nodes_count=None):
    return EnvironmentDefinition(
        environment_name="test",
        node_pools=[
            NodePoolDefinition(
                pool_id="pool-a",
                os_distribution="ubuntu",
                os_release="24.04",
                kernel_flavor="linux",
                kernel_package_version="6.8.0-47.47",
                nodes_count=nodes_count,
            )
        ],
        workloads=[
            WorkloadDefinition(name="web", exposure=ExposureType.INTERNET_FACING, node_pool="pool-a"),
        ],
    )


class TelemetryDirTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()

    def write(self, rel, data):
        path = self.dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def load(self, max_age_days=7):
        return load_node_telemetries_with_report(str(self.dir), max_age_days=max_age_days, now=NOW)


class TestTelemetryLoading(TelemetryDirTestCase):
    def test_record_without_pool_id_is_rejected(self):
        data = _node("pool-a", "anonymized-node")
        del data["pool_id"]
        self.write("n1.json", data)
        telemetries, issues = self.load()
        self.assertEqual(telemetries, {})
        self.assertTrue(any("pool_id がない" in i.message for i in issues))

    def test_stale_record_is_excluded(self):
        self.write("pool-a/n1.json", _node("pool-a", "n1", collected_at=FRESH))
        self.write("pool-a/n2.json", _node("pool-a", "n2", collected_at=STALE))
        telemetries, issues = self.load(max_age_days=7)
        self.assertEqual(telemetries["pool-a"].observed_nodes_count, 1)
        self.assertTrue(any("根拠から除外" in i.message for i in issues))

    def test_freshness_check_can_be_disabled(self):
        self.write("pool-a/n2.json", _node("pool-a", "n2", collected_at=STALE))
        telemetries, _ = self.load(max_age_days=None)
        self.assertEqual(telemetries["pool-a"].observed_nodes_count, 1)

    def test_missing_collected_at_is_reported_not_excluded(self):
        data = _node("pool-a", "n1")
        del data["collected_at"]
        self.write("n1.json", data)
        telemetries, issues = self.load()
        self.assertIn("pool-a", telemetries)
        self.assertIsNone(telemetries["pool-a"].oldest_collected_at)
        self.assertTrue(any(i.severity == "info" and "collected_at" in i.message for i in issues))

    def test_duplicate_node_keeps_newest_record(self):
        self.write("a.json", _node("pool-a", "n1", version="6.8.0-40.40", collected_at="2026-10-30T00:00:00Z"))
        self.write("b.json", _node("pool-a", "n1", version="6.8.0-47.47", collected_at=FRESH))
        telemetries, _ = self.load()
        pool = telemetries["pool-a"]
        self.assertEqual(pool.observed_nodes_count, 1)
        self.assertEqual(pool.kernel_package_version, "6.8.0-47.47")

    def test_legacy_anonymized_records_each_count_once(self):
        self.write("a.json", _node("pool-a", "anonymized-node"))
        self.write("b.json", _node("pool-a", "anonymized-node"))
        telemetries, _ = self.load()
        self.assertEqual(telemetries["pool-a"].observed_nodes_count, 2)

    def test_manifest_declares_expected_nodes(self):
        self.write("pool-a/n1.json", _node("pool-a", "n1"))
        self.write("pool-a/collection_manifest.json", {
            "kind": "collection_manifest",
            "pool_id": "pool-a",
            "targets": ["n1", "n2", "n3"],
            "succeeded": ["n1"],
            "failed": ["n2"],
            "unreachable": ["n3"],
        })
        telemetries, issues = self.load()
        self.assertEqual(telemetries["pool-a"].expected_nodes_count, 3)
        self.assertTrue(any("届かなかった" in i.message for i in issues))
        coverage = build_pool_coverage(_env(nodes_count=1), telemetries)
        # The manifest overrides environments.yaml.
        self.assertEqual(coverage["pool-a"].expected_nodes, 3)
        self.assertEqual(coverage["pool-a"].expected_source, "manifest")
        self.assertTrue(coverage["pool-a"].is_known_incomplete)

    def test_disabled_modules_are_not_limited_to_fragnesia(self):
        disabled = _parse_disabled_modules([
            "install algif_aead /bin/false",
            "blacklist nf_tables",
            "install esp4 /sbin/modprobe --ignore-install esp4",
        ])
        self.assertEqual(disabled, ["algif_aead", "nf_tables"])


class TestCoverageAwareVerdict(TelemetryDirTestCase):
    def audit(self, env, telemetries):
        return audit_exploit_chains(
            environment=env,
            kernel_vulnerabilities=[LPE],
            app_findings_by_workload={},
            telemetry_by_pool=telemetries,
            evaluation_date="2026-11-02",
        )

    def test_complete_coverage_of_patched_pool_is_safe(self):
        self.write("n1.json", _node("pool-a", "n1"))
        self.write("n2.json", _node("pool-a", "n2"))
        telemetries, _ = self.load()
        items = self.audit(_env(nodes_count=2), telemetries)
        self.assertEqual(items[0].chain_level, ChainLevel.SAFE)
        self.assertIn("2/2 台", items[0].kernel_status)

    def test_partial_coverage_of_patched_pool_is_not_safe(self):
        self.write("n1.json", _node("pool-a", "n1"))
        telemetries, _ = self.load()
        items = self.audit(_env(nodes_count=3), telemetries)
        self.assertNotEqual(items[0].chain_level, ChainLevel.SAFE)
        self.assertIn("要確認", items[0].kernel_status)
        self.assertIn("1/3 台", items[0].kernel_status)

    def test_partial_coverage_never_reports_mitigated(self):
        self.write("n1.json", _node("pool-a", "n1", version="6.8.0-40.40", disabled=["esp4", "esp6", "rxrpc"]))
        telemetries, _ = self.load()
        items = self.audit(_env(nodes_count=2), telemetries)
        self.assertNotEqual(items[0].chain_level, ChainLevel.MITIGATED_NEEDS_PATCH)
        self.assertIn("UNVERIFIED_PARTIAL_COVERAGE", items[0].mitigation_status)

    def test_complete_coverage_keeps_mitigation(self):
        self.write("n1.json", _node("pool-a", "n1", version="6.8.0-40.40", disabled=["esp4", "esp6", "rxrpc"]))
        telemetries, _ = self.load()
        items = self.audit(_env(nodes_count=1), telemetries)
        self.assertEqual(items[0].chain_level, ChainLevel.MITIGATED_NEEDS_PATCH)

    def test_unknown_expected_count_is_disclosed(self):
        self.write("n1.json", _node("pool-a", "n1"))
        telemetries, _ = self.load()
        items = self.audit(_env(nodes_count=None), telemetries)
        self.assertEqual(items[0].chain_level, ChainLevel.SAFE)
        self.assertIn("期待ノード数不明", items[0].kernel_status)


class TestPoolConsistencyAndReport(TelemetryDirTestCase):
    def test_pool_mismatches_are_reported_both_ways(self):
        self.write("n1.json", _node("pool-typo", "n1"))
        telemetries, _ = self.load()
        issues = find_pool_mismatches(_env(nodes_count=1), telemetries)
        messages = " ".join(i.message for i in issues)
        self.assertIn("pool-typo", messages)
        self.assertIn("環境定義にない", messages)
        coverage = build_pool_coverage(_env(nodes_count=1), telemetries)
        self.assertFalse(coverage["pool-typo"].in_environment)
        self.assertTrue(coverage["pool-a"].in_environment)
        self.assertIn("pool-a", messages)
        self.assertIn("実機テレメトリがありません", messages)

    def test_report_contains_coverage_section(self):
        self.write("n1.json", _node("pool-a", "n1"))
        telemetries, issues = self.load()
        env = _env(nodes_count=2)
        report = format_chain_audit_markdown(
            items=[],
            environment_name="test",
            coverage=build_pool_coverage(env, telemetries),
            load_issues=issues,
        )
        self.assertIn("実機テレメトリの収集状況", report)
        self.assertIn("1/2 台", report)
        self.assertIn("一部のノードのみ", report)


class TestEnvironmentDefinitionParsing(unittest.TestCase):
    def _load(self, yaml_text):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "env.yaml"
            p.write_text(yaml_text, encoding="utf-8")
            return load_environment_definition(str(p))

    def test_legacy_kernel_package_version_is_not_used_as_name(self):
        env = self._load(
            'node_pools:\n  - id: "p"\n    os_distro: "ubuntu"\n    kernel_package: "6.8.0-40.40"\n'
        )
        pool = env.node_pools[0]
        self.assertEqual(pool.kernel_package_version, "6.8.0-40.40")
        self.assertNotEqual(pool.kernel_package_name, "6.8.0-40.40")

    def test_expected_nodes_from_nodes_list_or_unknown(self):
        env = self._load(
            'node_pools:\n'
            '  - id: "listed"\n    nodes: ["a", "b", "c"]\n'
            '  - id: "counted"\n    nodes_count: 5\n'
            '  - id: "unspecified"\n'
            ''
        )
        counts = {p.pool_id: p.nodes_count for p in env.node_pools}
        self.assertEqual(counts, {"listed": 3, "counted": 5, "unspecified": None})


if __name__ == "__main__":
    unittest.main()
