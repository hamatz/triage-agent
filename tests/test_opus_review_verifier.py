import unittest
import tempfile
from pathlib import Path
from triage_agent.verifier import scan_directory_for_patterns


class TestOpusReviewCases(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.code_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_case1_js_static_glob_before_call(self):
        """Case 1: JS file with '/static/*' URL pattern, followed by jwt.verify"""
        js_file = self.code_dir / "server.js"
        js_file.write_text(
            'const route = "/static/*";\n'
            'const jwt = require("jsonwebtoken");\n'
            'return jwt.verify(token, "secret-key");\n',
            encoding="utf-8",
        )
        matches = scan_directory_for_patterns(self.code_dir, ["jwt.verify"])
        self.assertEqual(len(matches), 1, f"Should detect jwt.verify but got: {matches}")
        self.assertEqual(matches[0].line_number, 3)

    def test_case2_py_api_glob_before_call(self):
        """Case 2: Python file with '/api/*' URL pattern, followed by jwt.verify"""
        py_file = self.code_dir / "app.py"
        py_file.write_text(
            'ROUTE_PATTERN = "/api/*"\n'
            'import jwt\n'
            'jwt.verify(token, key)\n',
            encoding="utf-8",
        )
        matches = scan_directory_for_patterns(self.code_dir, ["jwt.verify"])
        self.assertEqual(len(matches), 1, f"Should detect jwt.verify in Python but got: {matches}")
        self.assertEqual(matches[0].line_number, 3)

    def test_case3_inline_comment_after_code(self):
        """Case 3: Code followed by /* comment on the same line"""
        js_file = self.code_dir / "auth.js"
        js_file.write_text(
            'jwt.verify(token, "secret-key"); /* TODO: update key */\n',
            encoding="utf-8",
        )
        matches = scan_directory_for_patterns(self.code_dir, ["jwt.verify"])
        self.assertEqual(len(matches), 1, f"Should detect inline call before /* but got: {matches}")
        self.assertEqual(matches[0].line_number, 1)

    def test_case4_py_environ_constant_lookup(self):
        """Case 4: Python reading os.environ['HTTPS_PROXY']"""
        py_file = self.code_dir / "client.py"
        py_file.write_text(
            'import os\n'
            'proxy = os.environ["HTTPS_PROXY"]\n',
            encoding="utf-8",
        )
        matches = scan_directory_for_patterns(self.code_dir, ["HTTPS_PROXY"])
        self.assertEqual(len(matches), 1, f"Should detect HTTPS_PROXY in subscript/constant but got: {matches}")
        self.assertEqual(matches[0].line_number, 2)


    def test_case5_string_glob_and_comment_on_same_line(self):
        """Case 5: String containing '/*' AND a real '/*' comment on the very same line"""
        js_file = self.code_dir / "complex.js"
        js_file.write_text(
            'const PUBLIC_GLOB = "/static/*"; jwt.verify(token, "secret-key"); /* TODO: review\n'
            'const nextLine = true;\n',
            encoding="utf-8",
        )
        matches = scan_directory_for_patterns(self.code_dir, ["jwt.verify"])
        self.assertEqual(len(matches), 1, f"Should detect call between string '/*' and real '/*' but got: {matches}")
        self.assertEqual(matches[0].line_number, 1)


if __name__ == "__main__":
    unittest.main()
