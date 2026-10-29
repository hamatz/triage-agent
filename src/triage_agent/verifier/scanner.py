"""AST and heuristic source code scanner for identifying vulnerable pattern matches."""

import ast
import os
import re
from pathlib import Path
from typing import List, Set, Tuple

from triage_agent.verifier.models import MatchSnippet

TARGET_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php",
    ".xml", ".yaml", ".yml", ".json", ".ini", ".conf", ".toml", ".env",
    ".properties", ".gradle", ".dockerfile", "Dockerfile"
}

IGNORE_DIRS = {
    ".git", ".venv", "venv", "node_modules", "dist", "build", "__pycache__",
    ".idea", ".vscode", "target", ".next", ".nuxt"
}

TEST_DIR_PATTERNS = {"test", "tests", "spec", "specs", "__tests__", "mock", "mocks", "fixtures"}
TEST_FILE_REGEX = re.compile(
    r"(^|[\b_\.-])(test|spec|mock)[\b_\.-]|_test\.[a-z0-9]+$|\.test\.[a-z0-9]+$|\.spec\.[a-z0-9]+$|Test\.[a-z0-9]+$",
    re.IGNORECASE,
)

C_STYLE_COMMENT_EXTENSIONS = {
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".java", ".go", ".php", ".c", ".cpp", ".cc", ".h", ".hpp",
    ".cs", ".kt", ".swift", ".rs", ".scala"
}


EXCLUDE_CODE_KEYWORDS = {
    "server.xml", "php.ini", "nginx.conf", "httpd.conf", "apache2.conf",
    "application.properties", "application.yml", "application.yaml",
    "pom.xml", "build.gradle", "package.json", "composer.json"
}


def extract_keywords_from_method(text: str) -> List[str]:
    """Extract code tokens, XML tags, function calls, or config keys from verification method text."""
    patterns = set()

    for token in re.findall(r"`([^`]+)`", text):
        cleaned = token.strip()
        if len(cleaned) >= 3 and cleaned.lower() not in EXCLUDE_CODE_KEYWORDS:
            patterns.add(cleaned)

    for tag in re.findall(r"<([a-zA-Z0-9_\-]+)", text):
        patterns.add(f"<{tag}")

    for kw in [
        "stream(", "read_chunked(", "HTTPS_PROXY", "ProxyManager",
        "jwt.verify", "serialize_handler", "upload_progress",
        "Http2Protocol", "asyncSupported", "startAsync()", "JNDIRealm"
    ]:
        if kw.lower() in text.lower():
            patterns.add(kw)

    return list(patterns)


def is_test_path(rel_path: str) -> bool:
    """Check if the file path belongs to test, mock, or fixture code."""
    path_obj = Path(rel_path)
    for part in path_obj.parts[:-1]:
        if part.lower() in TEST_DIR_PATTERNS:
            return True
    filename = path_obj.parts[-1] if path_obj.parts else ""
    return bool(TEST_FILE_REGEX.search(filename))


def strip_quotes_for_comment_check(line: str) -> str:
    """Mask string literals with equal-length spaces to prevent URLs/globs like '/api/*'
    from triggering block comments while preserving exact character offsets."""
    def mask_match(m):
        s = m.group(0)
        return s[0] + " " * (len(s) - 2) + s[-1] if len(s) >= 2 else s

    res = re.sub(r'"(?:\\.|[^"\\])*"', mask_match, line)
    res = re.sub(r"'(?:\\.|[^'\\])*'", mask_match, res)
    res = re.sub(r"`(?:\\.|[^`\\])*`", mask_match, res)
    return res


def remove_c_style_comments_from_line(raw_line: str) -> Tuple[str, bool]:
    """Remove C-style comments outside of string quotes from a single line.
    
    Returns:
        Tuple of (clean_code_line, starts_multiline_block_comment)
    """
    clean_line = raw_line
    while True:
        masked = strip_quotes_for_comment_check(clean_line)
        start = masked.find("/*")
        if start == -1:
            break
        end = masked.find("*/", start + 2)
        if end != -1:
            # Inline comment /* ... */ outside quotes: replace with spaces to preserve length
            clean_line = clean_line[:start] + " " * (end + 2 - start) + clean_line[end + 2:]
        else:
            # Multiline comment starts outside quotes: keep code before start
            clean_line = clean_line[:start]
            return clean_line, True

    return clean_line, False


def extract_python_docstring_and_code_lines(code_str: str) -> Tuple[Set[int], Set[int]]:
    """Parse Python AST to distinguish docstrings from executable code/constants.
    
    Returns:
        Tuple of (docstring_lines, all_code_lines)
    """
    try:
        tree = ast.parse(code_str)
    except Exception:
        return set(), set()

    docstring_lines = set()
    code_lines = set()

    for node in ast.walk(tree):
        # 1. Collect docstring lines
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            if (node.body and isinstance(node.body[0], ast.Expr) and
                isinstance(node.body[0].value, ast.Constant) and
                isinstance(node.body[0].value.value, str)):
                expr = node.body[0]
                start = expr.lineno
                end = getattr(expr, "end_lineno", expr.lineno)
                for lno in range(start, end + 1):
                    docstring_lines.add(lno)

        # 2. Collect all executable code lines (Calls, Subscripts, Constants, Names, Attributes)
        if hasattr(node, "lineno"):
            code_lines.add(node.lineno)

    return docstring_lines, code_lines


def scan_directory_for_patterns(code_dir: Path, patterns: List[str], max_matches: int = 500) -> List[MatchSnippet]:
    """Scan code directory for occurrences of patterns, returning line and surrounding context snippets."""
    if not patterns:
        return []

    matches: List[MatchSnippet] = []

    for root, dirs, files in os.walk(code_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS and not d.startswith(".")]

        for fname in sorted(files):
            fpath = Path(root) / fname
            suffix = fpath.suffix.lower()

            if suffix in TARGET_EXTENSIONS or fname in TARGET_EXTENSIONS:
                try:
                    raw_content = fpath.read_text(encoding="utf-8", errors="ignore")
                    all_lines = raw_content.splitlines(keepends=True)
                    rel_path = str(fpath.relative_to(code_dir))
                    is_test = is_test_path(rel_path)

                    # Python AST docstring vs executable code identification
                    py_docstrings: Set[int] = set()
                    py_code_lines: Set[int] = set()
                    if suffix == ".py":
                        py_docstrings, py_code_lines = extract_python_docstring_and_code_lines(raw_content)

                    is_c_style = suffix in C_STYLE_COMMENT_EXTENSIONS
                    is_xml_style = suffix in (".xml", ".html", ".xhtml")
                    is_ini_style = suffix in (".ini", ".cnf", ".conf")
                    in_block_comment = False

                    for line_no, raw_line in enumerate(all_lines, 1):
                        line_str = raw_line.strip()
                        effective_line = raw_line

                        # 1. C-Style block comment handling (strictly limited to C-style languages)
                        if is_c_style:
                            if in_block_comment:
                                if "*/" in raw_line:
                                    in_block_comment = False
                                    end_idx = raw_line.find("*/")
                                    # Continue processing remaining code after */ on the same line
                                    effective_line, in_block_comment = remove_c_style_comments_from_line(raw_line[end_idx + 2:])
                                else:
                                    continue
                            else:
                                effective_line, in_block_comment = remove_c_style_comments_from_line(raw_line)
                        # 1.1 XML-Style comment handling (<!-- ... -->)
                        elif is_xml_style:
                            if in_block_comment:
                                if "-->" in raw_line:
                                    in_block_comment = False
                                    end_idx = raw_line.find("-->")
                                    effective_line = raw_line[end_idx + 3:]
                                else:
                                    continue
                            else:
                                if "<!--" in raw_line:
                                    start_idx = raw_line.find("<!--")
                                    end_idx = raw_line.find("-->", start_idx + 4)
                                    if end_idx != -1:
                                        effective_line = raw_line[:start_idx] + " " * (end_idx + 3 - start_idx) + raw_line[end_idx + 3:]
                                    else:
                                        effective_line = raw_line[:start_idx]
                                        in_block_comment = True

                        effective_str = effective_line.strip()

                        # 2. Skip comment lines
                        if not effective_str:
                            continue
                        if effective_str.startswith("//") or effective_str.startswith("#"):
                            continue
                        if is_ini_style and effective_str.startswith(";"):
                            continue

                        # 3. Python docstring filter: skip docstring lines while preserving all executable lines
                        if suffix == ".py" and py_docstrings and line_no in py_docstrings:
                            continue

                        for p in patterns:
                            if p in effective_line:
                                start_idx = max(0, line_no - 2)
                                end_idx = min(len(all_lines), line_no + 6)
                                context_snippet = "".join(all_lines[start_idx:end_idx]).strip()

                                matches.append(
                                    MatchSnippet(
                                        file_path=rel_path,
                                        line_number=line_no,
                                        line_content=line_str,
                                        context_content=context_snippet,
                                        is_test=is_test,
                                    )
                                )
                                if len(matches) >= max_matches:
                                    return matches
                                break
                except Exception:
                    continue

    return matches
