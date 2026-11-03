"""Tests for the RHEL kernel adapter (ADR-021 stage 5).

OSV (Red Hat ecosystem) and the Red Hat Security Data API are replaced by fakes whose records follow
the shapes observed on 2026-11-03: RHSA / RHBA records list each binary package of an advisory under
'Red Hat:enterprise_linux:<major>::<repo>' with epoch-qualified fixed versions, and cve.json rows carry
'package_state' entries per product.
"""

import tempfile
import unittest
import urllib.parse
from pathlib import Path

from triage_agent.chain.engine import format_chain_audit_markdown
from triage_agent.chain.kernel_exposure import run_kernel_auto
from triage_agent.chain.models import EnvironmentDefinition, NodePoolDefinition, NodeTelemetry
from triage_agent.chain.sources import build_adapters, load_registry
from triage_agent.chain.sources import cvss_redhat
from triage_agent.chain.sources.base import PoolKernelIdentity
from triage_agent.chain.sources.rhel import RhelAdapter

ECO9 = "Red Hat:enterprise_linux:9::baseos"
HOST = "5.14.0-427.13.1.el9_4"


def _rh_record(rid, cves, fixed, ecosystem=ECO9):
    return {
        "id": rid, "modified": "2026-10-01T00:00:00Z", "upstream": cves,
        "affected": [
            {"package": {"name": "kernel-debug-devel", "ecosystem": ecosystem.replace("baseos", "appstream")},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]},
            {"package": {"name": "kernel", "ecosystem": ecosystem},
             "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]},
        ],
    }


RECORDS = {
    "RHSA-2024:5363": _rh_record("RHSA-2024:5363", ["CVE-2024-1086", "CVE-2026-0101"], "0:5.14.0-427.31.1.el9_4"),
    "RHBA-2024:3983": _rh_record("RHBA-2024:3983", ["CVE-2024-26664"], "0:5.14.0-427.22.1.el9_4"),
}


def _state(major, state, package="kernel"):
    return {"product_name": f"Red Hat Enterprise Linux {major}", "fix_state": state, "package_name": package,
            "cpe": f"cpe:/o:redhat:enterprise_linux:{major}"}


RH_ROWS = [
    {"CVE": "CVE-2024-1086", "severity": "important", "cvss3_scoring_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
     "cvss3_score": "7.8", "package_state": [_state(6, "Not affected")]},
    {"CVE": "CVE-2026-0101", "severity": "critical", "cvss3_scoring_vector": None, "cvss3_score": None, "package_state": []},
    {"CVE": "CVE-2026-0202", "severity": "moderate", "cvss3_scoring_vector": None, "cvss3_score": None,
     "package_state": [_state(9, "Affected"), _state(8, "Not affected")]},
    {"CVE": "CVE-2026-0303", "severity": "low", "cvss3_scoring_vector": None, "cvss3_score": None,
     "package_state": [_state(9, "Will not fix"), _state(9, "Affected", package="kernel-rt")]},
    {"CVE": "CVE-2026-0404", "severity": "moderate", "cvss3_scoring_vector": None, "cvss3_score": None,
     "package_state": [_state(8, "Affected"), _state(9, "Not affected")]},
    {"CVE": "CVE-2026-0505", "severity": "moderate", "cvss3_scoring_vector": None, "cvss3_score": None,
     "package_state": [_state("9.4 Extended Update Support".replace(" ", "_"), "Affected")]},  # not a plain major
]


class FakeOsv:
    def __init__(self):
        self.calls = []

    def __call__(self, url, body=None):
        self.calls.append(url)
        if url.endswith("/querybatch"):
            q = body["queries"][0]
            known = (q["package"]["ecosystem"], q["package"]["name"]) == (ECO9, "kernel")
            ids = list(RECORDS) if known and q["version"] in (HOST, "0") else []   # '0': is the package known at all?
            return {"results": [{"vulns": [{"id": i, "modified": RECORDS[i]["modified"]} for i in ids]}]}
        return RECORDS[urllib.parse.unquote(url.rsplit("/", 1)[1])]


def _tel(pool, version=HOST, release="9.4", flavor="kernel"):
    return NodeTelemetry(pool_id=pool, os_distribution="rhel", os_release=release, kernel_flavor=flavor,
                         kernel_binary_package="kernel-core", kernel_package_version=version, kernel_package_epoch="0")


class RhelTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.cache = Path(self._tmp.name) / "cache"
        self.adapters = build_adapters(load_registry(), cache_dir=str(self.cache))
        self.rhel: RhelAdapter = self.adapters["rhel"]
        self.osv = FakeOsv()
        self.rhel._http_json = self.osv
        self.rh_fail = False

        def rh_http(url):
            if self.rh_fail:
                raise RuntimeError("Red Hat API down")
            page = int(urllib.parse.parse_qs(urllib.parse.urlparse(url).query)["page"][0])
            return RH_ROWS if page == 1 else []
        self.rhel.redhat._http_json = rh_http

    def tearDown(self):
        self._tmp.cleanup()

    def run_auto(self, tel, offline=False, kev=None):
        env = EnvironmentDefinition(environment_name="t", node_pools=[
            NodePoolDefinition(pool_id=p, os_distribution="rhel", nodes_count=1) for p in tel])
        return run_kernel_auto(env, tel, self.adapters, kev_lookup=lambda: kev or {}, epss_lookup=lambda ids: {},
                               offline=offline)


class TestRhelIdentification(RhelTestCase):
    def test_registry_ecosystem_and_lineage(self):
        self.assertIsInstance(self.rhel, RhelAdapter)
        ident = PoolKernelIdentity("p", "rhel", "9.4", "kernel-core", HOST, "0", engine_flavor="kernel")
        self.assertEqual(self.rhel.ecosystem_for(ident), ECO9)
        self.assertEqual(self.rhel.lineage_for(ident), "rhel:9:kernel@5.14")


class TestRhelLookup(RhelTestCase):
    def test_advisories_plus_unfixed_states(self):
        res = self.run_auto({"r9": _tel("r9")}, kev={"CVE-2024-1086": {}})
        p = res.pools["r9"]
        self.assertEqual(p.status, "ok", p.reason)
        by = {x.cve_id: x for x in p.exposed}
        # From OSV: fixed in later builds of the same stream.
        self.assertEqual(by["CVE-2024-1086"].fixed_evr, "0:5.14.0-427.31.1.el9_4")
        self.assertEqual(by["CVE-2024-1086"].tier, 1)
        self.assertEqual(by["CVE-2024-26664"].fixed_evr, "0:5.14.0-427.22.1.el9_4")
        # Red Hat's own per-CVE rating fills the severity (critical -> tier 2).
        self.assertEqual((by["CVE-2026-0101"].severity, by["CVE-2026-0101"].tier), ("critical", 2))
        # Unfixed for RHEL 9 'kernel' only: Affected and Will not fix; not RHEL 8, not kernel-rt, not EUS rows.
        self.assertEqual(by["CVE-2026-0202"].fixed_evr, None)
        self.assertEqual(by["CVE-2026-0202"].advisory_ids, ["Red Hat: Affected"])
        self.assertEqual(by["CVE-2026-0303"].advisory_ids, ["Red Hat: Will not fix"])
        self.assertNotIn("CVE-2026-0404", by)
        self.assertNotIn("CVE-2026-0505", by)
        self.assertEqual(p.no_fix_available, 2)
        self.assertEqual(p.upgrade_target, "0:5.14.0-427.31.1.el9_4")

    def test_already_fixed_host_sees_only_unfixed(self):
        res = self.run_auto({"r9": _tel("r9", version="5.14.0-503.11.1.el9_5")})
        p = res.pools["r9"]
        self.assertEqual(p.status, "ok", p.reason)
        self.assertEqual(sorted(x.cve_id for x in p.exposed), ["CVE-2026-0202", "CVE-2026-0303"])

    def test_red_hat_api_failure_is_disclosed_and_advisories_still_used(self):
        self.rh_fail = True
        res = self.run_auto({"r9": _tel("r9")})
        p = res.pools["r9"]
        self.assertEqual(p.status, "ok")
        self.assertIn("CVE-2024-1086", [x.cve_id for x in p.exposed])
        self.assertNotIn("CVE-2026-0202", [x.cve_id for x in p.exposed])
        self.assertTrue(any("RHEL の未修正の CVE" in e for e in res.errors))

    def test_rt_kernel_is_not_reported_clean(self):
        # OSV answers an unknown package with an empty list; that must not read as "nothing to fix".
        res = self.run_auto({"rt": _tel("rt", version="5.14.0-427.13.1.el9_4", flavor="kernel-rt")})
        self.assertEqual(res.pools["rt"].status, "source_error")
        self.assertTrue(any("パッケージ kernel-rt の記録がありません" in e for e in res.errors))

    def test_report_shows_red_hat_state(self):
        res = self.run_auto({"r9": _tel("r9")}, kev={"CVE-2024-1086": {}})
        report = format_chain_audit_markdown([], environment_name="t", kernel_auto=res)
        self.assertIn("`rhel:9:kernel@5.14`", report)
        self.assertIn("https://osv.dev/vulnerability/RHSA-2024:5363", report)


class TestCvssCacheSharedWithRhel(RhelTestCase):
    def test_one_download_serves_both(self):
        self.run_auto({"r9": _tel("r9")})
        src = cvss_redhat.RedHatCvssSource({"packages": ["kernel"]}, cache_dir=str(self.cache))
        src._http_json = lambda url: self.fail("should use the cache")
        self.assertEqual(src.lookup(["CVE-2024-1086"])["CVE-2024-1086"]["score"], 7.8)


if __name__ == "__main__":
    unittest.main()
