"""Tests for the automatic kernel advisory lookup (ADR-021 stage 3).

The ALAS fixtures are trimmed real Amazon Linux advisories plus a few SYNTHETIC entries (marked in the
fixture files). Feeds (KEV / EPSS) are injected, so no network access is needed.
"""

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from triage_agent.chain.engine import format_chain_audit_markdown, run_exploit_chain_audit
from triage_agent.chain.kernel_exposure import run_kernel_auto
from triage_agent.chain.models import (
    ChainLevel,
    EnvironmentDefinition,
    ExposureType,
    NodePoolDefinition,
    NodeTelemetry,
    WorkloadDefinition,
)
from triage_agent.chain.sources import build_adapters, load_registry
from triage_agent.chain.sources.alas import AlasAdapter
from triage_agent.chain.sources.base import PoolKernelIdentity, SourceResult
from triage_agent.chain.version_parser import compare_rpm_evr, is_kernel_package_vulnerable

REPO = Path(__file__).resolve().parents[1]
FIXTURES = REPO / "tests" / "fixtures"
AL2023_XML = (FIXTURES / "alas_al2023_updateinfo.xml").read_bytes()
AL2_XML = (FIXTURES / "alas_al2_kernel510_updateinfo.xml").read_bytes()


def _parse(xml, release):
    r = SourceResult(adapter="alas")
    AlasAdapter.parse_updateinfo(xml, release, "https://example.invalid/updateinfo.xml", "2026-11-02T00:00:00Z", None, r)
    return r


def _seed_alas_cache(cache_dir: Path):
    """Put the fixtures where the adapter caches updateinfo, so fetch(offline=True) works."""
    empty = b"<updates/>"
    for release, label, xml in (
        ("2023", "core", AL2023_XML), ("2023", "kernel-livepatch", empty),
        ("2", "core", AL2_XML), ("2", "extras-kernel-5-10", empty), ("2", "extras-kernel-5-15", empty),
    ):
        d = cache_dir / "alas" / release
        d.mkdir(parents=True, exist_ok=True)
        (d / f"{label}.updateinfo.xml").write_bytes(xml)
        (d / f"{label}.meta.json").write_text(json.dumps({
            "source_url": f"https://cdn.amazonlinux.com/test/{release}/{label}/repodata/updateinfo.xml.gz",
            "retrieved_at": "2026-11-02T00:00:00Z",
        }), encoding="utf-8")


def _tel(pool, distro, release, binary, flavor, version, epoch="1", livepatch=()):
    return NodeTelemetry(
        pool_id=pool, os_distribution=distro, os_release=release, kernel_package_name=f"{binary}-{version}",
        kernel_flavor=flavor, kernel_package_version=version, kernel_package_epoch=epoch,
        kernel_binary_package=binary, livepatch_packages=list(livepatch),
    )


class TestVersionComparison(unittest.TestCase):
    def test_epoch_aware_rpm_comparison(self):
        self.assertEqual(compare_rpm_evr("1:6.1.189-236.399.amzn2023", "1:6.1.189-236.400.amzn2023"), -1)
        self.assertEqual(compare_rpm_evr("2:1.0-1", "1:9.9-9"), 1)
        # Only one side has an epoch: indeterminate, never guessed.
        self.assertIsNone(compare_rpm_evr("6.1.189-236.400.amzn2023", "1:6.1.189-236.399.amzn2023"))

    def test_amazon_linux_is_compared_with_rpm_rules(self):
        self.assertTrue(is_kernel_package_vulnerable("amzn", "6.1.100-1.amzn2023", "6.1.189-236.399.amzn2023"))
        self.assertFalse(is_kernel_package_vulnerable("amzn", "6.1.189-236.400.amzn2023", "6.1.189-236.399.amzn2023"))


class TestAlasParsing(unittest.TestCase):
    def test_lineages_fixed_versions_and_severity(self):
        r = _parse(AL2023_XML, "2023")
        fixes = {(f.lineage, f.cve_id): f for f in r.fixes}
        # The earliest fix wins; the highest severity across advisories is kept.
        f = fixes[("amzn:2023:kernel@6.1", "CVE-2026-68161")]
        self.assertEqual(f.fixed_evr, "1:6.1.180-230.100.amzn2023")
        self.assertEqual(f.severity, "high")
        self.assertEqual(sorted(f.advisory_ids), ["ALAS2023-2026-3336", "ALAS2023-2026-9001"])
        self.assertEqual(f.advisory_url, "https://alas.aws.amazon.com/AL2023/ALAS-2026-9001.html")
        # Distinct package names are distinct lineages.
        self.assertEqual(fixes[("amzn:2023:kernel6.12@6.12", "CVE-2026-90001")].severity, "critical")
        # Sub-packages such as kernel-headers do not create lineages.
        self.assertFalse(any("headers" in lk for lk, _ in fixes))
        self.assertEqual(r.errors, [])

    def test_livepatch_packages_map_to_cves(self):
        r = _parse(AL2023_XML, "2023")
        self.assertEqual(len(r.livepatch_fixes), 1)
        lp = r.livepatch_fixes[0]
        self.assertEqual((lp.cve_id, lp.target_kernel, lp.fixed_evr), ("CVE-2026-80521", "6.12.94-123.192", "1:1.0-6.amzn2023"))

    def test_same_package_name_different_series_are_separate_lineages(self):
        r = _parse(AL2_XML, "2")
        by_lineage = {f.lineage: f.fixed_evr for f in r.fixes}
        self.assertEqual(by_lineage, {
            "amzn:2:kernel@5.10": "0:5.10.271-272.1121.amzn2",
            "amzn:2:kernel@4.14": "0:4.14.360-300.500.amzn2",
        })

    def test_malformed_metadata_is_reported(self):
        r = _parse(b"<updates><update>", "2023")
        self.assertTrue(r.errors)

    def test_lineage_for_requires_exact_kernel_package(self):
        a = AlasAdapter({})
        ident = PoolKernelIdentity("p", "amzn", "2023", "kernel6.12", "6.12.94-123.192.amzn2023", "1")
        self.assertEqual(a.lineage_for(ident), "amzn:2023:kernel6.12@6.12")
        self.assertIsNone(a.lineage_for(PoolKernelIdentity("p", "amzn", "2023", "kernel-core", "6.1.1-1", "1")))
        self.assertIsNone(a.lineage_for(PoolKernelIdentity("p", "rhel", "9", "kernel", "5.14.0-1", "0")))

    def test_registry_maps_amazon_linux_to_alas(self):
        adapters = build_adapters(load_registry())
        self.assertIsInstance(adapters["amzn"], AlasAdapter)
        self.assertIn("2023", adapters["amzn"].config["repos"])


class KernelAutoTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self._tmp.name) / "cache"
        _seed_alas_cache(self.cache)
        self.adapters = build_adapters(load_registry(), cache_dir=str(self.cache))
        self.kev = {"CVE-2026-72402": {}}
        self.epss = {"CVE-2026-74289": {"epss": 0.5, "percentile": 0.99}, "CVE-2026-98432": {"epss": 0.01, "percentile": 0.5}}

    def tearDown(self):
        self._tmp.cleanup()

    def env(self, *pools, workloads=()):
        return EnvironmentDefinition(
            environment_name="t",
            node_pools=[NodePoolDefinition(pool_id=p, os_distribution="unknown", nodes_count=1) for p in pools],
            workloads=list(workloads),
        )

    def run_auto(self, env, tel, **kw):
        kw.setdefault("kev_lookup", lambda: self.kev)
        kw.setdefault("epss_lookup", lambda ids: {k: v for k, v in self.epss.items() if k in ids})
        return run_kernel_auto(env, tel, self.adapters, offline=False, **kw)


class TestKernelAutoClassification(KernelAutoTestCase):
    def test_tiers_and_upgrade_target(self):
        tel = {"al23": _tel("al23", "amzn", "2023", "kernel", "kernel", "6.1.180-230.100.amzn2023")}
        res = self.run_auto(self.env("al23"), tel)
        p = res.pools["al23"]
        self.assertEqual(p.status, "ok")
        self.assertEqual(p.lineage, "amzn:2023:kernel@6.1")
        # 68161 is fixed at exactly the installed build; the four others are exposed.
        self.assertEqual(p.tier_counts, {1: 1, 2: 1, 3: 2})
        self.assertEqual([x.cve_id for x in p.exposed[:2]], ["CVE-2026-72402", "CVE-2026-74289"])
        self.assertEqual(p.upgrade_target, "1:6.1.189-236.399.amzn2023")
        self.assertEqual(p.all_fixes_target, "1:6.1.189-236.400.amzn2023")
        # Tier 1 and 2 become pool-scoped entries; the engine compares without epoch (equal epochs).
        by_cve = {e.cve_id: e for e in res.entries}
        self.assertEqual(set(by_cve), {"CVE-2026-72402", "CVE-2026-74289"})
        e = by_cve["CVE-2026-74289"]
        self.assertEqual((e.auto_tier, e.provenance, e.applies_to_pools), (2, "auto", ["al23"]))
        self.assertEqual(e.distro_affected_ranges["amzn:2023:kernel"].fixed_version, "6.1.189-236.399.amzn2023")

    def test_livepatch_resolves_cve_and_critical_is_tier2(self):
        tel = {"k612": _tel("k612", "amzn", "2023", "kernel6.12", "kernel6.12", "6.12.94-123.192.amzn2023",
                             livepatch=["kernel-livepatch-6.12.94-123.192=1:1.0-6.amzn2023"])}
        p = self.run_auto(self.env("k612"), tel).pools["k612"]
        self.assertEqual(p.livepatched, 1)
        self.assertEqual([(x.cve_id, x.tier) for x in p.exposed], [("CVE-2026-90001", 2)])

    def test_older_livepatch_build_does_not_count(self):
        tel = {"k612": _tel("k612", "amzn", "2023", "kernel6.12", "kernel6.12", "6.12.94-123.192.amzn2023",
                             livepatch=["kernel-livepatch-6.12.94-123.192=1:1.0-5.amzn2023"])}
        p = self.run_auto(self.env("k612"), tel).pools["k612"]
        self.assertEqual(p.livepatched, 0)

    def test_al2_lines_named_kernel_use_their_own_fix(self):
        tel = {"al2": _tel("al2", "amzn", "2", "kernel", "kernel", "5.10.200-100.1.amzn2", epoch="0")}
        res = self.run_auto(self.env("al2"), tel)
        p = res.pools["al2"]
        self.assertEqual(p.lineage, "amzn:2:kernel@5.10")
        self.assertEqual(p.all_fixes_target, "0:5.10.271-272.1121.amzn2")

    def test_unknown_epoch_is_indeterminate_not_fixed(self):
        tel = {"al23": _tel("al23", "amzn", "2023", "kernel", "kernel", "6.1.999-1.amzn2023", epoch=None)}
        p = self.run_auto(self.env("al23"), tel).pools["al23"]
        self.assertEqual(p.indeterminate, 5)
        self.assertEqual(sum(p.tier_counts.values()), 5)

    def test_pools_without_adapter_or_identity_are_disclosed(self):
        tel = {
            "ubu": _tel("ubu", "ubuntu", "24.04", "linux-image-generic", "linux", "6.8.0-40.40", epoch=None),
            "noversion": NodeTelemetry(pool_id="noversion", os_distribution="amzn", os_release="2023"),
            "k618": _tel("k618", "amzn", "2023", "kernel6.18", "kernel6.18", "6.18.20-41.237.amzn2023"),
        }
        res = self.run_auto(self.env("ubu", "noversion", "k618"), tel)
        self.assertEqual(res.pools["ubu"].status, "no_adapter")
        self.assertEqual(res.pools["noversion"].status, "unidentified")
        # No advisory for this line in the data: never reported as clean.
        self.assertEqual(res.pools["k618"].status, "source_error")
        self.assertEqual(res.entries, [])

    def test_manual_ledger_cves_are_skipped(self):
        tel = {"al23": _tel("al23", "amzn", "2023", "kernel", "kernel", "6.1.180-230.100.amzn2023")}
        res = self.run_auto(self.env("al23"), tel, manual_cve_ids={"CVE-2026-72402"})
        self.assertNotIn("CVE-2026-72402", [x.cve_id for x in res.pools["al23"].exposed])

    def test_epss_failure_is_disclosed(self):
        def boom(_ids):
            raise RuntimeError("EPSS down")
        tel = {"al23": _tel("al23", "amzn", "2023", "kernel", "kernel", "6.1.180-230.100.amzn2023")}
        res = self.run_auto(self.env("al23"), tel, epss_lookup=boom)
        self.assertFalse(res.epss_available)
        self.assertTrue(any("EPSS" in e for e in res.errors))
        self.assertEqual(res.pools["al23"].tier_counts[2], 0)

    def test_tier2_limit(self):
        self.epss = {c: {"epss": 0.9, "percentile": 0.99} for c in ("CVE-2026-68289", "CVE-2026-74289", "CVE-2026-98432")}
        tel = {"al23": _tel("al23", "amzn", "2023", "kernel", "kernel", "6.1.180-230.100.amzn2023")}
        res = self.run_auto(self.env("al23"), tel, tier2_limit=1)
        p = res.pools["al23"]
        self.assertEqual((p.tier_counts[2], p.tier2_itemized), (3, 1))
        self.assertEqual(sum(1 for e in res.entries if e.auto_tier == 2), 1)


class TestKernelAutoChainEvaluation(KernelAutoTestCase):
    def test_tier1_critical_tier2_capped_and_pool_scoped(self):
        workloads = [
            WorkloadDefinition(name="ci", exposure=ExposureType.UNTRUSTED_CODE, node_pool="al23"),
            WorkloadDefinition(name="other", exposure=ExposureType.UNTRUSTED_CODE, node_pool="other"),
        ]
        env = self.env("al23", "other", workloads=workloads)
        tel = {
            "al23": _tel("al23", "amzn", "2023", "kernel", "kernel", "6.1.180-230.100.amzn2023"),
            "other": _tel("other", "amzn", "2023", "kernel", "kernel", "6.1.189-236.400.amzn2023"),
        }
        auto = self.run_auto(env, tel)
        items = run_exploit_chain_audit(environment=env, kernel_vulnerabilities=auto.entries, telemetries=tel)
        levels = {(i.workload_name, i.kernel_cve): i.chain_level for i in items}
        self.assertEqual(levels[("ci", "CVE-2026-72402")], ChainLevel.CRITICAL_CHAIN)
        self.assertEqual(levels[("ci", "CVE-2026-74289")], ChainLevel.HIGH_UNVERIFIED)
        # Entries are scoped to their pool: the up-to-date pool gets no rows for them.
        self.assertFalse(any(w == "other" for w, _ in levels))
        report = format_chain_audit_markdown(items, "t", kernel_auto=auto)
        self.assertIn("カーネル脆弱性の自動照会", report)
        self.assertIn("1:6.1.189-236.399.amzn2023", report)
        self.assertIn("自動照会・層2", report)


class TestCollectorRpmIdentity(unittest.TestCase):
    """The collector reports epoch, binary package and livepatch packages on RPM systems."""

    def test_rpm_fields(self):
        with tempfile.TemporaryDirectory() as d:
            bin_dir = Path(d) / "bin"
            bin_dir.mkdir()
            for tool in ("sh", "awk", "sed", "grep", "tr", "date", "uname", "hostname", "cat", "sort",
                         "cut", "ls", "sha256sum", "head", "tail", "mkdir", "dirname", "printf"):
                src = shutil.which(tool)
                if src:
                    os.symlink(src, bin_dir / tool)
            rpm = bin_dir / "rpm"
            rpm.write_text(textwrap_rpm(), encoding="utf-8")
            rpm.chmod(rpm.stat().st_mode | stat.S_IXUSR)
            proc = subprocess.run(
                [shutil.which("sh"), str(REPO / "scripts" / "collect_kernel_telemetry.sh"), "-p", "pool-al"],
                env={"PATH": str(bin_dir)}, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(data["kernel_package_epoch"], "1")
            self.assertEqual(data["kernel_binary_package"], "kernel6.12")
            self.assertEqual(data["distro_package_version"], "6.12.94-123.192.amzn2023")
            self.assertEqual(data["kernel_flavor"], "kernel6.12")
            self.assertEqual(data["livepatch_packages"], ["kernel-livepatch-6.12.94-123.192=1:1.0-6.amzn2023"])


def textwrap_rpm() -> str:
    py = sys.executable
    return f"""#!{py}
import sys
a = sys.argv[1:]
qf = a[a.index('--qf') + 1] if '--qf' in a else None
if a[:1] == ['-qa']:
    print('kernel-livepatch-6.12.94-123.192=1:1.0-6.amzn2023')
elif qf is None:
    print('kernel6.12-6.12.94-123.192.amzn2023.x86_64')
else:
    vals = {{'%{{VERSION}}-%{{RELEASE}}': '6.12.94-123.192.amzn2023', '%{{SOURCERPM}}': 'kernel6.12-6.12.94-123.192.amzn2023.src.rpm',
            '%{{EPOCHNUM}}': '1', '%{{NAME}}': 'kernel6.12'}}
    sys.stdout.write(vals.get(qf, ''))
"""


class TestCliKernelAuto(unittest.TestCase):
    def test_dry_run_uses_cached_advisories(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            cache = work / "triage-output" / "cache"
            _seed_alas_cache(cache)
            (cache / "cisa_kev_catalog.json").write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2026-72402"}]}), encoding="utf-8")
            (work / "env.yaml").write_text(
                'environment: "t"\nnode_pools:\n  - id: "al23"\n    nodes_count: 1\nworkloads:\n'
                '  - id: "ci"\n    exposure: "untrusted_code"\n    node_pool_id: "al23"\n',
                encoding="utf-8",
            )
            tel_dir = work / "tel"
            tel_dir.mkdir()
            (tel_dir / "n1.json").write_text(json.dumps({
                "node_id": "node-1", "pool_id": "al23", "os_distribution": "amzn", "os_release": "2023",
                "kernel_flavor": "kernel", "kernel_binary_package": "kernel", "kernel_package_epoch": "1",
                "distro_package_version": "6.1.180-230.100.amzn2023",
            }), encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, "-m", "triage_agent.cli", "--chain-audit", "--environments", "env.yaml",
                 "--telemetry", "tel", "--telemetry-max-age", "0", "--kernel-auto", "--dry-run",
                 "--chain-output", "report.md", "--fail-on", "critical_chain"],
                cwd=work, capture_output=True, text=True, timeout=120,
                env={**os.environ, "PYTHONPATH": str(REPO / "src")},
            )
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            report = (work / "report.md").read_text(encoding="utf-8")
            self.assertIn("カーネル脆弱性の自動照会", report)
            self.assertIn("CVE-2026-72402", report)
            # Offline: EPSS is not queried, and the report says the tiering is incomplete.
            self.assertIn("EPSS を取得できなかったため", report)
            self.assertNotIn("updateinfo を取得できませんでした", report)


if __name__ == "__main__":
    unittest.main()
