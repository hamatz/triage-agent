"""Tests for the OSV kernel advisory adapter (ADR-021 stage 3).

OSV is replaced by an in-memory fake that answers querybatch / vulns requests with records shaped like
the real ones observed on 2026-11-02 (per-CVE UBUNTU-/DEBIAN- records, per-advisory RLSA- records).
"""

import json
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
from triage_agent.chain.sources.base import PoolKernelIdentity
from triage_agent.chain.sources.osv import OsvAdapter


def _ubuntu_record(cve, fixed=None, priority="high", package="linux-aws", ecosystem="Ubuntu:24.04:LTS"):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {
        "id": f"UBUNTU-{cve}", "modified": "2026-10-30T00:00:00Z", "upstream": [cve],
        "severity": [{"type": "Ubuntu", "score": priority}, {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            # other releases / flavors are listed too in real records
            {"package": {"name": package, "ecosystem": "Ubuntu:Pro:14.04:LTS"}, "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]},
            {"package": {"name": package, "ecosystem": ecosystem}, "ranges": [{"type": "ECOSYSTEM", "events": events}]},
        ],
    }


ROCKY_RECORD = {
    "id": "RLSA-2024:2758", "modified": "2026-02-05T15:15:08Z",
    "upstream": ["CVE-2023-6240", "CVE-2024-25742", "CVE-2024-25743"],
    "affected": [{"package": {"name": "kernel", "ecosystem": "Rocky Linux:9"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "0:5.14.0-427.16.1.el9_4"}]}]}],
}
ALMA_BUGFIX = {  # bug-fix-only advisory: no CVE, must be ignored
    "id": "ALBA-2026:39332", "modified": "2026-07-25T10:00:04Z",
    "affected": [{"package": {"name": "kernel", "ecosystem": "AlmaLinux:9"},
                  "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.14.0-687.26.1.el9_8"}]}]}],
}


class FakeOsv:
    """Answers OsvAdapter._http_json; records every call."""

    def __init__(self, answers, records, page_size=2):
        self.answers = answers          # (ecosystem, package, version) -> [ids]
        self.records = records          # id -> record
        self.page_size = page_size
        self.calls = []

    def __call__(self, url, body=None):
        self.calls.append(url)
        if url.endswith("/querybatch"):
            q = body["queries"][0]
            ids = self.answers.get((q["package"]["ecosystem"], q["package"]["name"], q["version"]), [])
            start = int(q.get("page_token") or 0)
            page = ids[start:start + self.page_size]
            res = {"vulns": [{"id": i, "modified": self.records.get(i, {}).get("modified", "m")} for i in page]}
            if start + self.page_size < len(ids):
                res["next_page_token"] = str(start + self.page_size)
            return {"results": [res]}
        vid = url.rsplit("/", 1)[1]
        return self.records[vid]

    def record_fetches(self):
        return sorted(u.rsplit("/", 1)[1] for u in self.calls if "/vulns/" in u)


class OsvTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self._tmp.name) / "cache"
        self.adapters = build_adapters(load_registry(), cache_dir=str(self.cache))
        self.osv: OsvAdapter = self.adapters["ubuntu"]
        records = {
            "UBUNTU-CVE-2024-1086": _ubuntu_record("CVE-2024-1086", fixed="6.8.0-1021.23"),
            "UBUNTU-CVE-2026-1111": _ubuntu_record("CVE-2026-1111", fixed=None, priority="medium"),
            "UBUNTU-CVE-2026-2222": _ubuntu_record("CVE-2026-2222", fixed="6.8.0-1030.31", priority="low"),
            "RLSA-2024:2758": ROCKY_RECORD,
            "ALBA-2026:39332": ALMA_BUGFIX,
        }
        answers = {
            ("Ubuntu:24.04:LTS", "linux-aws", "6.8.0-1015.16"): ["UBUNTU-CVE-2024-1086", "UBUNTU-CVE-2026-1111", "UBUNTU-CVE-2026-2222"],
            ("Ubuntu:24.04:LTS", "linux-aws", "6.8.0-1025.26"): ["UBUNTU-CVE-2026-1111", "UBUNTU-CVE-2026-2222"],
            ("Rocky Linux:9", "kernel", "5.14.0-427.13.1.el9_4"): ["RLSA-2024:2758"],
            ("AlmaLinux:9", "kernel", "5.14.0-427.13.1.el9_4"): ["ALBA-2026:39332"],
        }
        self.fake = FakeOsv(answers, records)
        self.osv._http_json = self.fake
        self.kev = {"CVE-2024-1086": {}}
        self.epss = {"CVE-2026-1111": {"epss": 0.4, "percentile": 0.99}}

    def tearDown(self):
        self._tmp.cleanup()

    def run_auto(self, tel, offline=False, workloads=()):
        env = EnvironmentDefinition(
            environment_name="t",
            node_pools=[NodePoolDefinition(pool_id=p, os_distribution="unknown", nodes_count=1) for p in tel],
            workloads=list(workloads),
        )
        res = run_kernel_auto(
            env, tel, self.adapters, kev_lookup=lambda: self.kev,
            epss_lookup=lambda ids: {k: v for k, v in self.epss.items() if k in ids}, offline=offline,
        )
        return env, res


def _deb(pool, version, flavor="linux-aws", distro="ubuntu", release="24.04"):
    return NodeTelemetry(pool_id=pool, os_distribution=distro, os_release=release, kernel_flavor=flavor,
                         kernel_package_name=f"linux-image-{version}", kernel_package_version=version)


def _rpm(pool, distro, release="9.4", version="5.14.0-427.13.1.el9_4"):
    return NodeTelemetry(pool_id=pool, os_distribution=distro, os_release=release, kernel_flavor="kernel",
                         kernel_binary_package="kernel-core", kernel_package_version=version, kernel_package_epoch="0")


class TestOsvIdentification(OsvTestCase):
    def test_ecosystem_names(self):
        def eco(distro, release, flavor="linux"):
            return self.osv.ecosystem_for(PoolKernelIdentity("p", distro, release, flavor, "1.0-1", engine_flavor=flavor))
        self.assertEqual(eco("ubuntu", "24.04"), "Ubuntu:24.04:LTS")
        self.assertEqual(eco("ubuntu", "24.10"), "Ubuntu:24.10")
        self.assertEqual(eco("ubuntu", "23.04"), "Ubuntu:23.04")
        self.assertEqual(eco("debian", "12.7"), "Debian:12")
        self.assertEqual(eco("almalinux", "9.4", "kernel"), "AlmaLinux:9")
        self.assertEqual(eco("rocky", "9.4", "kernel"), "Rocky Linux:9")

    def test_source_package_is_used_not_binary(self):
        ident = PoolKernelIdentity("p", "rocky", "9.4", "kernel-core", "5.14.0-427.13.1.el9_4", "0", engine_flavor="kernel")
        self.assertEqual(self.osv.lineage_for(ident), "rocky:9:kernel@5.14")


class TestOsvLookup(OsvTestCase):
    def test_tiers_enrichment_and_downloads(self):
        _, res = self.run_auto({"ubu": _deb("ubu", "6.8.0-1015.16")})
        p = res.pools["ubu"]
        self.assertEqual(p.status, "ok")
        self.assertEqual(p.lineage, "ubuntu:24.04:linux-aws@6.8")
        self.assertEqual(p.tier_counts, {1: 1, 2: 1, 3: 1})
        # Only tier 1 / 2 per-CVE records are downloaded; tier 3 is classified from its id.
        self.assertEqual(self.fake.record_fetches(), ["UBUNTU-CVE-2024-1086", "UBUNTU-CVE-2026-1111"])
        self.assertEqual(p.details_not_fetched, 1)
        by = {x.cve_id: x for x in p.exposed}
        self.assertEqual((by["CVE-2024-1086"].fixed_evr, by["CVE-2024-1086"].severity), ("6.8.0-1021.23", "high"))
        self.assertIsNone(by["CVE-2026-1111"].fixed_evr)          # Ubuntu has not fixed it
        self.assertEqual(p.no_fix_available, 1)
        self.assertEqual(p.upgrade_target, "6.8.0-1021.23")

    def test_pagination_and_cache(self):
        self.run_auto({"ubu": _deb("ubu", "6.8.0-1015.16")})
        n_calls = len(self.fake.calls)
        self.assertGreaterEqual(sum(1 for u in self.fake.calls if u.endswith("/querybatch")), 2)
        # A second run within the TTL is served entirely from the cache.
        self.run_auto({"ubu": _deb("ubu", "6.8.0-1015.16")})
        self.assertEqual(len(self.fake.calls), n_calls)

    def test_offline_without_cache_is_a_source_error(self):
        _, res = self.run_auto({"ubu": _deb("ubu", "6.8.0-1015.16")}, offline=True)
        self.assertEqual(res.pools["ubu"].status, "source_error")
        self.assertEqual(self.fake.calls, [])

    def test_answers_are_scoped_to_each_pools_version(self):
        _, res = self.run_auto({"old": _deb("old", "6.8.0-1015.16"), "new": _deb("new", "6.8.0-1025.26")})
        self.assertIn("CVE-2024-1086", [x.cve_id for x in res.pools["old"].exposed])
        self.assertNotIn("CVE-2024-1086", [x.cve_id for x in res.pools["new"].exposed])

    def test_rpm_advisory_records(self):
        _, res = self.run_auto({"rocky": _rpm("rocky", "rocky"), "alma": _rpm("alma", "almalinux")})
        r = res.pools["rocky"]
        self.assertEqual(sorted(x.cve_id for x in r.exposed), ["CVE-2023-6240", "CVE-2024-25742", "CVE-2024-25743"])
        self.assertTrue(all(x.fixed_evr == "0:5.14.0-427.16.1.el9_4" for x in r.exposed))
        # Bug-fix-only advisories carry no CVE and are ignored.
        self.assertEqual(sum(res.pools["alma"].tier_counts.values()), 0)
        self.assertEqual(res.pools["alma"].status, "ok")

    def test_chain_evaluation_and_report(self):
        workloads = [WorkloadDefinition(name="web", exposure=ExposureType.INTERNET_FACING, node_pool="ubu")]
        tel = {"ubu": _deb("ubu", "6.8.0-1015.16")}
        env, res = self.run_auto(tel, workloads=workloads)
        items = run_exploit_chain_audit(environment=env, kernel_vulnerabilities=res.entries, telemetries=tel)
        by = {i.kernel_cve: i for i in items}
        self.assertEqual(by["CVE-2024-1086"].chain_level, ChainLevel.HIGH_ISOLATED)   # no app foothold
        self.assertIn("YES", by["CVE-2024-1086"].kernel_status)
        # A tier 2 CVE without a fix stays exposed (要確認), never SAFE.
        self.assertNotEqual(by["CVE-2026-1111"].chain_level, ChainLevel.SAFE)
        self.assertIn("要確認", by["CVE-2026-1111"].kernel_status)
        report = format_chain_audit_markdown(items, "t", kernel_auto=res)
        self.assertIn("**修正版なし**", report)
        self.assertIn("（修正版のないものを除く）", report)
        self.assertIn("https://osv.dev/vulnerability/UBUNTU-CVE-2024-1086", report)


if __name__ == "__main__":
    unittest.main()
