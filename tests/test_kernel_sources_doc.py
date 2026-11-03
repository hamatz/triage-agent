"""The distribution support table (docs/kernel-sources.md) must list every registered adapter (ADR-021 stage 6)."""

import re
import unittest
from pathlib import Path

from triage_agent.chain.sources import load_registry, load_signal_registry

DOC = (Path(__file__).resolve().parents[1] / "docs" / "kernel-sources.md").read_text(encoding="utf-8")
REQUIRED = ("class", "description", "distros", "verified_at")


class TestKernelSourcesDoc(unittest.TestCase):
    def test_registry_entries_are_complete(self):
        for name, conf in load_registry().items():
            for key in REQUIRED:
                self.assertTrue(conf.get(key), f"[adapters.{name}] に {key} がありません")
            self.assertRegex(str(conf["verified_at"]), r"^\d{4}-\d{2}-\d{2}$")
        for name, conf in load_signal_registry().items():
            self.assertTrue(conf.get("class") and conf.get("verified_at"), f"[signals.{name}]")

    def test_every_adapter_and_distro_is_in_the_table(self):
        table = DOC.split("## 1. ディストリ対応表", 1)[1].split("\n---", 1)[0]
        rows = [line for line in table.splitlines() if line.startswith("| ") and not line.startswith("| :")]
        for name, conf in load_registry().items():
            adapter_rows = [r for r in rows if f"| `{name}` |" in r]
            self.assertTrue(adapter_rows, f"アダプタ {name} が対応表にありません")
            for distro in conf["distros"]:
                self.assertTrue(any(f"`{distro}`" in r for r in adapter_rows),
                                f"ディストリ {distro}（{name}）が対応表にありません")


if __name__ == "__main__":
    unittest.main()
