import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from triage_agent.tools.sbom import generate_self_sbom, load_sbom_summary


class TestSelfTriageFeature(unittest.TestCase):
    """Unit tests for ADR-018 Self-Triage & Dogfooding capabilities."""

    def test_generate_self_sbom_structure(self):
        """Verify dynamic CycloneDX SBOM generation for triage-agent and Python runtime."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_file = Path(tmpdir) / "self_sbom.json"
            data = generate_self_sbom(output_path=sbom_file, include_transitive=True)

            self.assertTrue(sbom_file.exists())
            self.assertEqual(data.get("bomFormat"), "CycloneDX")
            self.assertEqual(data.get("specVersion"), "1.4")
            self.assertEqual(data.get("metadata", {}).get("component", {}).get("name"), "triage-agent")

            components = data.get("components", [])
            self.assertGreaterEqual(len(components), 5)

            comp_names = {c["name"].lower().replace("_", "-") for c in components}
            # Should contain primary dependencies from pyproject.toml
            self.assertIn("pydantic", comp_names)
            self.assertIn("httpx", comp_names)
            self.assertIn("rich", comp_names)
            # Python runtime itself must be included to avoid runtime omission (Brotli lesson)
            self.assertIn("python", comp_names)

            for c in components:
                self.assertTrue(c.get("name"))
                self.assertTrue(c.get("version"))
                purl = c.get("purl", "")
                self.assertTrue(purl.startswith("pkg:pypi/") or purl.startswith("pkg:generic/python@"))

    def test_load_generated_self_sbom(self):
        """Verify that triage-agent's load_sbom_summary parses its own generated SBOM."""
        with tempfile.TemporaryDirectory() as tmpdir:
            sbom_file = Path(tmpdir) / "self_sbom.json"
            generate_self_sbom(output_path=sbom_file, include_transitive=True)

            parsed = load_sbom_summary(str(sbom_file))
            self.assertGreaterEqual(len(parsed), 5)
            parsed_names = {p.name.lower().replace("_", "-") for p in parsed}
            self.assertIn("pydantic", parsed_names)
            self.assertIn("httpx", parsed_names)
            self.assertIn("python", parsed_names)

    def test_cli_self_triage_invocation(self):
        """Verify that CLI --self-triage runs end-to-end without errors in baseline mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_report = Path(tmpdir) / "out_report.md"
            out_audit = Path(tmpdir) / "out_audit.md"

            res = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "triage_agent.cli",
                    "--self-triage",
                    "--dry-run",
                    "--max-targets",
                    "3",
                    "--output",
                    str(out_report),
                    "--verify-output",
                    str(out_audit),
                ],
                capture_output=True,
                text=True,
            )

            self.assertEqual(
                res.returncode,
                0,
                f"CLI execution failed with returncode {res.returncode}\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
            )
            self.assertTrue(out_report.exists(), "Triage report should be created")
            self.assertTrue(out_audit.exists(), "Verification audit report should be created")

            audit_text = out_audit.read_text(encoding="utf-8")
            self.assertIn("対象コードベース", audit_text)
            self.assertIn("src/triage_agent", audit_text)

    def test_cli_fail_on_unscanned_guardrail(self):
        """Verify that --fail-on unscanned exits with non-zero (exit 2) when uninvestigated items exist."""
        res = subprocess.run(
            [
                sys.executable,
                "-m",
                "triage_agent.cli",
                "--self-triage",
                "--dry-run",
                "--max-targets",
                "2",
                "--fail-on",
                "unscanned",
            ],
            capture_output=True,
            text=True,
        )

        # In offline/dry-run, OSV/network lookup fails or max-targets triggers unscanned warning,
        # so --fail-on unscanned MUST exit with code 2 to prevent silent success in CI.
        self.assertEqual(res.returncode, 2, f"Expected returncode 2, got {res.returncode}\nOUTPUT:\n{res.stdout}")
        self.assertIn("CI/CD ガードレール違反: --fail-on 条件発火", res.stdout)
        self.assertIn("調査不能・未調査コンポーネント", res.stdout)

    def test_script_strict_api_key_guardrail(self):
        """Verify that scripts/self_triage.sh fails fast (exit 1) without GEMINI_API_KEY unless --dry-run is given."""
        env = dict(os.environ)
        env.pop("GEMINI_API_KEY", None)
        env.pop("GOOGLE_GENAI_USE_VERTEXAI", None)

        res = subprocess.run(
            ["./scripts/self_triage.sh"],
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(res.returncode, 1, f"Expected returncode 1, got {res.returncode}\nOUTPUT:\n{res.stdout}")
        self.assertIn("GEMINI_API_KEY または Vertex AI", res.stdout)


    def test_osv_queryable_filter_for_runtime(self):
        """Verify that generic runtime components are safely excluded from OSV queries and return empty hits when clean."""
        from triage_agent.schemas import ComponentInfo
        from triage_agent.tools.osv import is_osv_queryable, query_osv_batch
        from unittest.mock import patch, MagicMock

        py_comp = ComponentInfo(
            name="python",
            version="3.12.2",
            ecosystem="Generic",
            purl="pkg:generic/python@3.12.2",
        )
        pypi_comp = ComponentInfo(
            name="httpx",
            version="0.28.1",
            ecosystem="PyPI",
            purl="pkg:pypi/httpx@0.28.1",
        )

        self.assertFalse(is_osv_queryable(py_comp), "Generic runtime purl should not be queried against OSV")
        self.assertTrue(is_osv_queryable(pypi_comp), "PyPI component should be queryable")

        # Mock OSV batch POST with 0 vulnerabilities (clean)
        with patch("httpx.Client.post") as mock_post:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {"results": [{"vulns": []}]}
            mock_post.return_value = mock_resp

            results, errors, unsupported = query_osv_batch([py_comp, pypi_comp])
            self.assertEqual(len(errors), 0)
            # Crucial Opus Review Fix: results must NOT contain entries with 0 vulnerabilities
            self.assertNotIn("python", results)
            self.assertNotIn("httpx", results)
            self.assertEqual(len(results), 0, "No hits should result in an empty dict, not {comp: []}")

            # Unsupported list must capture the generic runtime
            self.assertEqual(len(unsupported), 1)
            self.assertIn("python", unsupported[0])

            # Ensure mock_post payload ONLY contains httpx, not generic python
            sent_payload = mock_post.call_args[1]["json"]
            queries = sent_payload["queries"]
            self.assertEqual(len(queries), 1, "Only 1 valid component should be sent to OSV")
            self.assertEqual(queries[0]["package"]["purl"], "pkg:pypi/httpx@0.28.1")


if __name__ == "__main__":
    unittest.main()
