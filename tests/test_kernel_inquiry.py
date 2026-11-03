"""Tests for the kernel vulnerability inquiry (--kernel-inquiry / --kernel-inquiry-answers, ADR-022).

Amazon Linux uses the trimmed real ALAS fixtures (offline cache). KEV entries, promotions and the
returned forms are SYNTHETIC, so no network access is needed.
"""

import csv
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_kernel_auto import _seed_alas_cache  # noqa: E402

from triage_agent.chain import kernel_inquiry as ki  # noqa: E402
from triage_agent.chain.kernel_exposure import run_kernel_auto  # noqa: E402
from triage_agent.chain.sources import build_adapters, load_registry  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
KEV = {
    "CVE-2026-68161": {"cveID": "CVE-2026-68161", "vendorProject": "Linux", "product": "Kernel",
                       "vulnerabilityName": "Linux Kernel Use-After-Free Vulnerability", "dateAdded": "2026-10-01",
                       "knownRansomwareCampaignUse": "Known"},
    "CVE-2026-72402": {"cveID": "CVE-2026-72402", "vendorProject": "Linux", "product": "Kernel",
                       "vulnerabilityName": "Linux Kernel Privilege Escalation", "dateAdded": "2026-09-01"},
}
OLD = "kernel-line ID=amzn VERSION_ID=2023 UNAME=6.1.170-1.amzn2023.x86_64 PKG=kernel EVR=1:6.1.170-1.amzn2023 " \
      "SRC=kernel-6.1.170-1.amzn2023.src.rpm LATEST=1:6.1.170-1.amzn2023 LP="
PENDING = "kernel-line ID=amzn VERSION_ID=2023 UNAME=6.1.175-1.amzn2023.x86_64 PKG=kernel EVR=1:6.1.175-1.amzn2023 " \
          "SRC=kernel-6.1.175-1.amzn2023.src.rpm LATEST=1:6.1.189-236.400.amzn2023 LP="
CURRENT = "kernel-line ID=amzn VERSION_ID=2023 UNAME=6.1.189-236.400.amzn2023.x86_64 PKG=kernel EVR=1:6.1.189-236.400.amzn2023 " \
          "SRC=kernel-6.1.189-236.400.amzn2023.src.rpm LATEST=1:6.1.189-236.400.amzn2023 LP="
UBUNTU = "kernel-line ID=ubuntu VERSION_ID=24.04 UNAME=6.8.0-1015-aws PKG=linux-image-6.8.0-1015-aws EVR=6.8.0-1015.16 " \
         "SRC=linux-aws LATEST= LP="


def _write_form(path: Path, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=ki.REQUEST_HEADERS)
        w.writeheader()
        for no, label, line, count in rows:
            w.writerow({h: "" for h in ki.REQUEST_HEADERS} | {
                "DistributionID": "DIST-20261103-abcdef", "No": no, "サーバー群（呼び名・任意）": label,
                "コマンドの出力（1 行をそのまま貼り付け）": line, "台数": count})


class TestRequest(unittest.TestCase):
    def test_request_form_and_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            import triage_agent.tools.vendor_workflow as vw
            metrics = Path(tmp) / "m.json"
            orig = vw.record_workflow_event
            vw.record_workflow_event = lambda et, d, metrics_file=None: orig(et, d, metrics_file=str(metrics))
            try:
                csv_path, md_path, dist_id = ki.write_request("受注システム", Path(tmp) / "req.csv")
            finally:
                vw.record_workflow_event = orig
            text = csv_path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("﻿"))
            rows = list(csv.DictReader(io.StringIO(text.lstrip("﻿"))))
            self.assertEqual(list(rows[0]), ki.REQUEST_HEADERS)
            self.assertEqual(rows[0]["No"], ki.EXAMPLE_NO)
            self.assertIn(ki.COLLECT_COMMAND, rows[0]["備考"])
            self.assertEqual(len(rows), 1 + ki.BLANK_ROWS)
            md = md_path.read_text(encoding="utf-8")
            self.assertIn(ki.COLLECT_COMMAND, md)
            self.assertIn("--kernel-inquiry-answers", md)
            self.assertIn("kernel_inquiry", metrics.read_text(encoding="utf-8"))
            # The example row alone is not an answer.
            lines, problems, _ = ki.read_answers(csv_path)
            self.assertEqual((lines, problems), ([], []))

    def test_collect_command_is_read_only_and_valid_shell(self):
        self.assertNotRegex(ki.COLLECT_COMMAND, r"\b(rm|mv|tee|install|update|upgrade|yum|dnf|apt)\b")
        proc = subprocess.run(["sh", "-n", "-c", ki.COLLECT_COMMAND[len("sh -c '"):-1]], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)


class TestAnswers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.cache = self.dir / "cache"
        _seed_alas_cache(self.cache)

    def tearDown(self):
        self.tmp.cleanup()

    def test_parse_line(self):
        f, _ = ki.parse_line("'" + OLD)
        self.assertEqual((f["ID"], f["PKG"], f["EVR"]), ("amzn", "kernel", "1:6.1.170-1.amzn2023"))
        f, problem = ki.parse_line("kernel-line ID=ubuntu VERSION_ID=24.04 UNAME=6.18.44 PKG=linux-image-6.18.44 EVR= SRC= LATEST= LP=")
        self.assertIsNone(f)
        self.assertIn("EVR", problem)
        self.assertIsNone(ki.parse_line("Linux web01 6.1.170")[0])

    def test_identical_kernels_are_merged_and_counts_kept_honest(self):
        form = self.dir / "a.csv"
        _write_form(form, [("1", "Web", OLD, "3"), ("2", "バッチ", OLD, "2"), ("3", "API", CURRENT, ""),
                           ("4", "", "uname -r の結果: 6.1.170", "1")])
        lines, problems, dist_id = ki.read_answers(form)
        self.assertEqual(dist_id, "DIST-20261103-abcdef")
        self.assertEqual(len(lines), 2)
        self.assertEqual((lines[0].label, lines[0].count), ("Web、バッチ", 5))
        self.assertIsNone(lines[1].count)
        self.assertTrue(any(p.startswith("No 4") for p in problems))

    def _result(self, rows):
        form = self.dir / "answers.csv"
        _write_form(form, rows)
        lines, problems, dist_id = ki.read_answers(form)
        env, tels = ki.to_environment(lines)
        auto = run_kernel_auto(environment=env, telemetries=tels,
                               adapters=build_adapters(load_registry(), cache_dir=str(self.cache)),
                               kev_lookup=lambda: KEV, epss_lookup=None, offline=True)
        return lines, auto, ki.render_result("受注システム", lines, auto, KEV, problems, dist_id, form)

    def test_remaining_cves_and_version_to_update_to(self):
        lines, auto, md = self._result([("1", "Web", OLD, "4"), ("2", "API", CURRENT, "2")])
        old = auto.pools[lines[0].group_id]
        self.assertEqual(sorted(x.cve_id for x in old.exposed if x.tier == 1), ["CVE-2026-68161", "CVE-2026-72402"])
        self.assertEqual(ki._tier1_target("amzn", old.exposed), "1:6.1.189-236.399.amzn2023")
        self.assertIn("| Web | Amazon Linux 2023 | `6.1.170-1.amzn2023.x86_64` | 4 台 | 🚨 2 件 | 6.1.189-236.399.amzn2023 以上 |", md)
        self.assertIn("| API | Amazon Linux 2023 | `6.1.189-236.400.amzn2023.x86_64` | 2 台 | ✅ なし | — |", md)
        self.assertIn("ランサムウェアでの悪用あり", md)
        self.assertIn("**6.1.189-236.399.amzn2023 以上** に更新し、再起動してください", md)

    def test_pending_reboot_is_called_out(self):
        _, _, md = self._result([("1", "Web", PENDING, "1")])
        self.assertIn("再起動されておらず、古いカーネルのまま動いています", md)
        self.assertIn("再起動すれば", md)
        self.assertIn("インストール済みの新しいカーネル（6.1.189-236.400.amzn2023）で再起動してください", md)

    def test_unanswerable_kernel_is_never_reported_clean(self):
        lines, auto, md = self._result([("1", "Ubuntu 群", UBUNTU, "2")])
        self.assertNotEqual(auto.pools[lines[0].group_id].status, "ok")
        self.assertIn("❓ 判定できませんでした", md)
        self.assertNotIn("✅ なし", md)
        self.assertIn("ディストリの勧告でご確認ください", md)

    def test_promoted_cve_counts_like_kev(self):
        form = self.dir / "answers.csv"
        _write_form(form, [("1", "Web", OLD, "1")])
        lines, problems, dist_id = ki.read_answers(form)
        env, tels = ki.to_environment(lines)
        manual = {"CVE-2026-74289": {"reason": "PoC 公開", "source": "https://example.invalid/poc", "promoted_at": "2026-11-02T00:00:00Z"}}
        auto = run_kernel_auto(environment=env, telemetries=tels,
                               adapters=build_adapters(load_registry(), cache_dir=str(self.cache)),
                               kev_lookup=lambda: {}, epss_lookup=None, offline=True, manual_promotions=manual)
        md = ki.render_result("", lines, auto, {}, problems, dist_id, form)
        self.assertIn("CVE-2026-74289", md)
        self.assertIn("警戒を引き上げたもの", md)

    def test_cli_round_trip_offline(self):
        work = self.dir / "work"
        (work / "triage-output").mkdir(parents=True)
        os.rename(self.cache, work / "triage-output" / "cache")
        (work / "triage-output" / "cache" / "cisa_kev_catalog.json").write_text(json.dumps({
            "title": "CISA Catalog of Known Exploited Vulnerabilities", "catalogVersion": "2026.11.03",
            "dateReleased": "2026-11-03T00:00:00Z", "count": len(KEV), "vulnerabilities": list(KEV.values())}), encoding="utf-8")
        env = {**os.environ, "PYTHONPATH": str(REPO / "src")}
        run = lambda *a: subprocess.run([sys.executable, "-m", "triage_agent.cli", *a], cwd=work, capture_output=True,  # noqa: E731
                                        text=True, timeout=120, env=env)
        p = run("--kernel-inquiry", "--kernel-inquiry-target", "受注システム", "--kernel-inquiry-output", "triage-output/req.csv")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        _write_form(work / "back.csv", [("1", "Web", OLD, "4")])
        p = run("--dry-run", "--kernel-inquiry-answers", "back.csv", "--kernel-inquiry-output", "triage-output/res.md")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        md = (work / "triage-output" / "res.md").read_text(encoding="utf-8")
        self.assertIn("🚨 2 件", md)
        # The scheduled --kernel-auto snapshot is not created or overwritten by a one-off lookup.
        self.assertFalse((work / "triage-output" / "kernel_auto" / "snapshot.json").exists())


class TestChainLevelWording(unittest.TestCase):
    def test_report_says_critical_chain_is_a_condition_not_an_attack(self):
        from triage_agent.chain.engine import format_chain_audit_markdown
        md = format_chain_audit_markdown([])
        self.assertIn("実際に攻撃された・侵入されたことを示すものではありません", md)
        self.assertIn("**CRITICAL_CHAIN**", md)


if __name__ == "__main__":
    unittest.main()
