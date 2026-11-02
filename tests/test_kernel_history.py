"""Tests for run-to-run snapshots and deterministic promotion of kernel CVEs (ADR-021 stage 4).

Uses the same ALAS fixtures as test_kernel_auto. For the installed build 6.1.180-230.100.amzn2023 the
exposed CVEs are: 72402 (KEV -> tier 1), 74289 (EPSS 0.5 -> tier 2), 98432 and 68289 (tier 3).
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from triage_agent.chain.engine import format_chain_audit_markdown
from triage_agent.chain.kernel_history import (
    add_manual_promotion,
    evaluate_promotions,
    is_lpe_vector,
    load_manual_promotions,
    load_snapshot,
    remove_manual_promotion,
    save_snapshot,
)
from test_kernel_auto import REPO, KernelAutoTestCase, _seed_alas_cache, _tel

T0, T1, T2 = "2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z", "2026-11-03T00:00:00Z"
OLD = "6.1.180-230.100.amzn2023"
NEW = "6.1.189-236.399.amzn2023"
LPE_78 = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
DOS_55 = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"


class HistoryTestCase(KernelAutoTestCase):
    def tel(self, version=OLD):
        return {"al23": _tel("al23", "amzn", "2023", "kernel", "kernel", version)}

    def run_at(self, now, previous=None, version=OLD, **kw):
        return self.run_auto(self.env("al23"), self.tel(version), previous_snapshot=previous, now=now, **kw)


class TestFirstRunIsBaseline(HistoryTestCase):
    def test_snapshot_without_previous(self):
        res = self.run_at(T0)
        self.assertIsNone(res.previous_taken_at)
        self.assertEqual(res.changes, {})
        self.assertEqual(res.promotions, {})
        snap = res.snapshot
        self.assertEqual(snap["taken_at"], T0)
        self.assertEqual(snap["pools"]["al23"]["tiers"], {
            "1": ["CVE-2026-72402"], "2": ["CVE-2026-74289"], "3": ["CVE-2026-68289", "CVE-2026-98432"],
        })
        self.assertTrue(snap["signals"]["CVE-2026-72402"]["kev"])
        self.assertEqual(snap["signals"]["CVE-2026-98432"]["epss"], 0.01)

    def test_offline_run_builds_no_snapshot(self):
        from triage_agent.chain.kernel_exposure import run_kernel_auto
        res = run_kernel_auto(self.env("al23"), self.tel(), self.adapters, kev_lookup=lambda: self.kev,
                              epss_lookup=None, offline=True)
        self.assertIsNone(res.snapshot)


class TestEpssJumpPromotion(HistoryTestCase):
    def test_jump_promotes_and_stays_promoted_while_exposed(self):
        base = self.run_at(T0).snapshot
        self.epss["CVE-2026-98432"] = {"epss": 0.30, "percentile": 0.97}
        res = self.run_at(T1, base)
        promo = res.promotions["CVE-2026-98432"]
        self.assertEqual((promo.rule, promo.new, promo.detail), ("epss_jump", True, "0.010 → 0.300"))
        p = res.pools["al23"]
        self.assertEqual(p.tier_counts, {1: 2, 2: 1, 3: 1})
        self.assertEqual(res.changes["al23"].new_tier1, ["CVE-2026-98432"])
        self.assertEqual(res.new_tier1_total, 1)
        entry = next(e for e in res.entries if e.cve_id == "CVE-2026-98432")
        self.assertEqual(entry.auto_tier, 1)  # not capped at HIGH_UNVERIFIED
        self.assertIn("昇格: EPSS 急上昇", entry.name)

        # Next day: the score is flat, but the promotion is carried while the CVE is exposed.
        res2 = self.run_at(T2, res.snapshot)
        promo2 = res2.promotions["CVE-2026-98432"]
        self.assertEqual((promo2.rule, promo2.new, promo2.detected_at), ("epss_jump", False, T1))
        self.assertEqual(res2.changes["al23"].new_tier1, [])
        self.assertEqual(res2.new_tier1_total, 0)

    def test_small_rise_is_not_a_jump(self):
        base = self.run_at(T0).snapshot
        self.epss["CVE-2026-98432"] = {"epss": 0.09, "percentile": 0.9}
        self.assertEqual(self.run_at(T1, base).promotions, {})

    def test_jump_threshold_is_configurable(self):
        base = self.run_at(T0).snapshot
        self.epss["CVE-2026-98432"] = {"epss": 0.09, "percentile": 0.9}
        self.assertIn("CVE-2026-98432", self.run_at(T1, base, epss_jump=0.05).promotions)

    def test_unavailable_epss_keeps_last_known_scores(self):
        base = self.run_at(T0).snapshot

        def down(_ids):
            raise RuntimeError("EPSS down")
        res = self.run_at(T1, base, epss_lookup=down)
        self.assertEqual(res.promotions, {})
        self.assertEqual(res.snapshot["signals"]["CVE-2026-98432"]["epss"], 0.01)
        self.assertFalse(res.snapshot["epss_available"])
        # When EPSS is back, a jump is measured against the last known score.
        self.epss["CVE-2026-98432"] = {"epss": 0.5, "percentile": 0.99}
        self.assertIn("CVE-2026-98432", self.run_at(T2, res.snapshot).promotions)


class TestCvssRevisionPromotion(HistoryTestCase):
    def test_lpe_vector_shape(self):
        self.assertTrue(is_lpe_vector(LPE_78))
        self.assertFalse(is_lpe_vector(DOS_55))
        self.assertFalse(is_lpe_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
        self.assertFalse(is_lpe_vector("CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"))
        self.assertFalse(is_lpe_vector(None))

    def test_upward_revision_promotes_but_first_score_does_not(self):
        prev = {"signals": {
            "CVE-A": {"cvss": {"vector": DOS_55, "score": 5.5}},
            "CVE-B": {},
            "CVE-C": {"cvss": {"vector": LPE_78, "score": 7.8}},
        }}
        cur = {c: {"vector": LPE_78, "score": 7.8} for c in ("CVE-A", "CVE-B", "CVE-C")}
        promos = evaluate_promotions({"CVE-A", "CVE-B", "CVE-C"}, set(), {}, cur, prev, {}, now=T1)
        self.assertEqual(set(promos), {"CVE-A"})
        self.assertEqual(promos["CVE-A"].rule, "cvss_revision")

    def test_cvss_lookup_is_used_and_recorded(self):
        base = self.run_at(T0, cvss_lookup=lambda ids: {"CVE-2026-68289": {"vector": DOS_55, "score": 5.5}}).snapshot
        self.assertTrue(base["cvss_available"])
        res = self.run_at(T1, base, cvss_lookup=lambda ids: {"CVE-2026-68289": {"vector": LPE_78, "score": 7.8}})
        self.assertEqual(res.promotions["CVE-2026-68289"].rule, "cvss_revision")
        self.assertIn("CVE-2026-68289", res.changes["al23"].new_tier1)

    def test_cvss_failure_is_disclosed(self):
        def down(_ids):
            raise RuntimeError("CVSS down")
        res = self.run_at(T0, cvss_lookup=down)
        self.assertFalse(res.cvss_available)
        self.assertTrue(any("CVSS" in e for e in res.errors))


class TestManualPromotion(HistoryTestCase):
    def test_ledger_requires_a_source_url(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                add_manual_promotion("CVE-2026-68289", "", state_dir=d)
            with self.assertRaises(ValueError):
                add_manual_promotion("not-a-cve", "https://example.invalid/poc", state_dir=d)
            add_manual_promotion("cve-2026-68289", "https://example.invalid/poc", "PoC 公開", state_dir=d, now=T1)
            ledger = load_manual_promotions(d)
            self.assertEqual(ledger["CVE-2026-68289"]["source_url"], "https://example.invalid/poc")
            self.assertTrue(remove_manual_promotion("CVE-2026-68289", state_dir=d))
            self.assertFalse(remove_manual_promotion("CVE-2026-68289", state_dir=d))
            self.assertEqual(load_manual_promotions(d), {})

    def test_manual_promotion_applies_and_is_dropped_when_removed(self):
        base = self.run_at(T0).snapshot
        manual = {"CVE-2026-68289": {"cve_id": "CVE-2026-68289", "source_url": "https://example.invalid/poc",
                                     "reason": "PoC 公開", "promoted_at": T1}}
        res = self.run_at(T1, base, manual_promotions=manual)
        promo = res.promotions["CVE-2026-68289"]
        self.assertEqual((promo.rule, promo.source_url), ("manual", "https://example.invalid/poc"))
        self.assertEqual(res.changes["al23"].new_tier1, ["CVE-2026-68289"])
        # Removed from the ledger: not carried over from the snapshot.
        res2 = self.run_at(T2, res.snapshot, manual_promotions={})
        self.assertNotIn("CVE-2026-68289", res2.promotions)

    def test_unexposed_manual_promotion_is_listed_in_report(self):
        manual = {"CVE-2099-0001": {"cve_id": "CVE-2099-0001", "source_url": "https://example.invalid/x", "promoted_at": T0}}
        res = self.run_at(T0, manual_promotions=manual)
        report = format_chain_audit_markdown([], environment_name="t", kernel_auto=res)
        self.assertIn("今回どのプールにも露出していないもの: `CVE-2099-0001`", report)


class TestChangesBetweenRuns(HistoryTestCase):
    def test_upgrade_resolves_tier1_and_tier2(self):
        base = self.run_at(T0).snapshot
        res = self.run_at(T1, base, version=NEW)
        ch = res.changes["al23"]
        self.assertTrue(ch.baseline)
        self.assertEqual(ch.resolved, ["CVE-2026-72402", "CVE-2026-74289"])
        self.assertTrue(any("カーネルの版が変わりました" in n for n in ch.notes))

    def test_pool_not_looked_up_keeps_previous_data(self):
        base = self.run_at(T0).snapshot
        tel = {"al23": _tel("al23", "amzn", "2023", "kernel", "kernel", OLD, epoch=None)}
        tel["al23"].kernel_package_version = None   # identity lost this time
        res = self.run_auto(self.env("al23"), tel, previous_snapshot=base, now=T1)
        self.assertEqual(res.pools["al23"].status, "unidentified")
        self.assertFalse(res.changes["al23"].baseline)
        kept = res.snapshot["pools"]["al23"]
        self.assertEqual(kept["taken_at"], T0)
        self.assertIn("not_refreshed_reason", kept)

    def test_report_sections(self):
        first = self.run_at(T0)
        report = format_chain_audit_markdown([], environment_name="t", kernel_auto=first)
        self.assertIn("今回の結果が比較の基準になります", report)
        self.assertIn("CVSS の照会元が未接続", report)
        self.epss["CVE-2026-98432"] = {"epss": 0.30, "percentile": 0.97}
        second = self.run_at(T1, first.snapshot)
        report = format_chain_audit_markdown([], environment_name="t", kernel_auto=second)
        self.assertIn(f"### 前回の実行（{T0}）からの変化", report)
        self.assertIn("| `al23` | 1（`CVE-2026-98432`） |", report)
        self.assertIn("### 昇格して層1 として扱っている脆弱性（1 件）", report)
        self.assertIn("1（昇格: EPSS 急上昇）", report)


class TestSnapshotFiles(unittest.TestCase):
    def test_save_rotates_and_load_validates(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(load_snapshot(d), (None, None))
            save_snapshot({"schema": 1, "taken_at": T0}, d)
            save_snapshot({"schema": 1, "taken_at": T1}, d)
            snap, problem = load_snapshot(d)
            self.assertEqual((snap["taken_at"], problem), (T1, None))
            self.assertEqual(json.loads((Path(d) / "snapshot.previous.json").read_text())["taken_at"], T0)
            (Path(d) / "snapshot.json").write_text("{broken", encoding="utf-8")
            snap, problem = load_snapshot(d)
            self.assertIsNone(snap)
            self.assertIn("読めませんでした", problem)
            (Path(d) / "snapshot.json").write_text('{"schema": 99}', encoding="utf-8")
            self.assertIn("形式が違う", load_snapshot(d)[1])


class TestCliPromotion(unittest.TestCase):
    def _cli(self, work, *args):
        return subprocess.run(
            [sys.executable, "-m", "triage_agent.cli", *args], cwd=work, capture_output=True, text=True, timeout=120,
            env={**os.environ, "PYTHONPATH": str(REPO / "src")},
        )

    def _setup(self, work: Path):
        cache = work / "triage-output" / "cache"
        _seed_alas_cache(cache)
        (cache / "cisa_kev_catalog.json").write_text(json.dumps({
            "catalogVersion": "2026.11.02", "dateReleased": "2026-11-02T00:00:00.000Z", "count": 1,
            "vulnerabilities": [{"cveID": "CVE-2026-72402"}],
        }), encoding="utf-8")
        (work / "env.yaml").write_text('environment: "t"\nnode_pools:\n  - id: "al23"\n    nodes_count: 1\n', encoding="utf-8")
        (work / "tel").mkdir()
        (work / "tel" / "n1.json").write_text(json.dumps({
            "node_id": "node-1", "pool_id": "al23", "os_distribution": "amzn", "os_release": "2023",
            "kernel_flavor": "kernel", "kernel_binary_package": "kernel", "kernel_package_epoch": "1",
            "distro_package_version": OLD,
        }), encoding="utf-8")

    def _audit(self, work, *extra):
        return self._cli(work, "--chain-audit", "--environments", "env.yaml", "--telemetry", "tel",
                         "--telemetry-max-age", "0", "--kernel-auto", "--dry-run", "--chain-output", "report.md", *extra)

    def test_promote_command_writes_ledger(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            proc = self._cli(work, "--promote", "CVE-2026-68289")
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            self.assertIn("出典 URL", proc.stdout)
            proc = self._cli(work, "--promote", "CVE-2026-68289", "--promote-source", "https://example.invalid/poc")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            ledger = json.loads((work / "triage-output" / "kernel_auto" / "promotions.json").read_text(encoding="utf-8"))
            self.assertEqual(ledger["promotions"][0]["cve_id"], "CVE-2026-68289")

    def test_fail_on_promoted_needs_a_previous_run(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            self._setup(work)
            proc = self._audit(work, "--fail-on", "promoted")
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertIn("比較の基準", proc.stdout)
            # Offline runs never overwrite the baseline.
            self.assertFalse((work / "triage-output" / "kernel_auto" / "snapshot.json").exists())

    def test_fail_on_promoted_fires_on_new_tier1(self):
        with tempfile.TemporaryDirectory() as d:
            work = Path(d)
            self._setup(work)
            state = work / "triage-output" / "kernel_auto"
            # Previous run: 72402 was exposed but not yet in KEV (tier 3).
            save_snapshot({
                "schema": 1, "taken_at": T0, "kev_available": True, "epss_available": True, "cvss_available": False,
                "signals": {"CVE-2026-72402": {"kev": False}}, "promotions": {},
                "pools": {"al23": {"status": "ok", "installed": f"1:{OLD}", "tiers": {
                    "1": [], "2": [], "3": ["CVE-2026-68289", "CVE-2026-72402", "CVE-2026-74289", "CVE-2026-98432"]}}},
            }, str(state))
            proc = self._audit(work, "--fail-on", "promoted")
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("新たに層1 になったカーネル脆弱性が 1 件", proc.stdout)
            self.assertEqual(json.loads((state / "snapshot.json").read_text())["taken_at"], T0)  # not overwritten
            report = (work / "report.md").read_text(encoding="utf-8")
            self.assertIn("| `al23` | 1（`CVE-2026-72402`） |", report)


if __name__ == "__main__":
    unittest.main()
