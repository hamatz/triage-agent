"""The version in pyproject.toml and the fallback in triage_agent/__init__.py must agree."""

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestVersionSync(unittest.TestCase):
    def test_fallback_matches_pyproject(self):
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
        init = (ROOT / "src" / "triage_agent" / "__init__.py").read_text(encoding="utf-8")
        fallback = re.search(r'^__version__ = "([^"]+)"', init, re.M).group(1)
        self.assertEqual(fallback, project)

    def test_user_agent_carries_the_version(self):
        import triage_agent
        self.assertEqual(triage_agent.user_agent(), f"triage-agent/{triage_agent.__version__}")
        # No hard-coded "triage-agent/<version>" strings that would go stale on the next release.
        for path in (ROOT / "src" / "triage_agent").rglob("*.py"):
            self.assertNotRegex(path.read_text(encoding="utf-8"), r"triage-agent/\d", str(path))


if __name__ == "__main__":
    unittest.main()
