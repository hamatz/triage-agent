import unittest
import json
import tempfile
from pathlib import Path
from triage_agent.tools.sbom import load_sbom_summary


class TestSpdxSbomSupport(unittest.TestCase):
    def test_spdx_json_parsing(self):
        """Test parsing of standard SPDX 2.3 JSON format."""
        spdx_data = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "sample-project",
            "packages": [
                {
                    "name": "fastapi",
                    "SPDXID": "SPDXRef-Package-fastapi",
                    "versionInfo": "0.100.0",
                    "packageFileName": "fastapi-0.100.0-py3-none-any.whl",
                    "description": "FastAPI framework",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:pypi/fastapi@0.100.0",
                        }
                    ],
                },
                {
                    "name": "jsonwebtoken",
                    "SPDXID": "SPDXRef-Package-jsonwebtoken",
                    "versionInfo": "8.5.1",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/jsonwebtoken@8.5.1",
                        }
                    ],
                },
                {
                    "name": "log4j-core",
                    "SPDXID": "SPDXRef-Package-log4j-core",
                    "versionInfo": "2.14.1",
                    "packageFileName": "log4j-core-2.14.1.jar",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                        }
                    ],
                },
            ],
        }

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump(spdx_data, tf)
            temp_path = tf.name

        try:
            comps = load_sbom_summary(temp_path)
            self.assertEqual(len(comps), 3)

            # Check fastapi
            c0 = comps[0]
            self.assertEqual(c0.name, "fastapi")
            self.assertEqual(c0.version, "0.100.0")
            self.assertEqual(c0.ecosystem, "PyPI")
            self.assertEqual(c0.purl, "pkg:pypi/fastapi@0.100.0")

            # Check jsonwebtoken
            c1 = comps[1]
            self.assertEqual(c1.name, "jsonwebtoken")
            self.assertEqual(c1.version, "8.5.1")
            self.assertEqual(c1.ecosystem, "npm")

            # Check log4j-core
            c2 = comps[2]
            self.assertEqual(c2.name, "log4j-core")
            self.assertEqual(c2.version, "2.14.1")
            self.assertEqual(c2.ecosystem, "Maven")

        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_unsupported_format_raises_value_error(self):
        """Test unsupported JSON format raises clear ValueError."""
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
            json.dump({"unrelated_key": 123}, tf)
            temp_path = tf.name

        try:
            with self.assertRaises(ValueError) as ctx:
                load_sbom_summary(temp_path)
            self.assertIn("サポートされていないSBOM形式", str(ctx.exception))
        finally:
            Path(temp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
