"""Structure of the automatic kernel lookup benchmark cases and the coverage warning (ADR-021 stage 7)."""

import json
import unittest
from pathlib import Path

from triage_agent.benchmark_kernel import run_kernel_auto_cases
from triage_agent.chain.engine import format_chain_audit_markdown

MANIFEST = json.loads((Path(__file__).resolve().parents[1] / "benchmark" / "manifest.json").read_text(encoding="utf-8"))
CASES = MANIFEST["kernel_auto_cases"]


class TestKernelAutoBenchmark(unittest.TestCase):
    def test_cases_are_well_formed(self):
        self.assertGreaterEqual(len(CASES), 10)
        ids = [c["id"] for c in CASES]
        self.assertEqual(len(ids), len(set(ids)))
        for c in CASES:
            self.assertTrue(c.get("description"), c["id"])
            self.assertIn(c.get("polarity", "positive"), ("positive", "negative"), c["id"])
            self.assertTrue(any(k.startswith("expected_") for k in c), c["id"])
        # Both directions are covered: things that must be flagged and things that must stay quiet.
        self.assertTrue(any(c.get("polarity") == "negative" for c in CASES))

    def test_all_cases_pass(self):
        failed = [(r["id"], r["reasoning"]) for r in run_kernel_auto_cases(MANIFEST) if not r["passed"]]
        self.assertEqual(failed, [])

    def test_coverage_warning_is_in_the_report(self):
        from triage_agent import benchmark_kernel as bk
        case = next(c for c in CASES if c["id"] == "kauto_partial_coverage_flagged")
        # Re-run to get the result object for the report.
        import triage_agent.chain.kernel_exposure as ke
        captured = {}
        original = ke.run_kernel_auto

        def spy(*a, **kw):
            captured["res"] = original(*a, **kw)
            return captured["res"]
        bk.run_kernel_auto = spy
        try:
            bk.run_case(case)
        finally:
            bk.run_kernel_auto = original
        report = format_chain_audit_markdown([], environment_name="t", kernel_auto=captured["res"])
        self.assertIn("実機テレメトリが一部のノードのみです（1/3 台）", report)


if __name__ == "__main__":
    unittest.main()
