"""Verifier package for triage-agent.

Cross-references TriageReport checkpoints with local codebase and audit sign-offs.
"""

from triage_agent.verifier.attestation import (
    compute_matches_hash,
    extract_cve_id,
    load_audit_attestations,
    normalize_text,
)
from triage_agent.verifier.cli import main
from triage_agent.verifier.engine import verify_codebase
from triage_agent.verifier.models import (
    AttestationFile,
    AuditAttestation,
    CheckVerificationResult,
    CodebaseAuditReport,
    MatchSnippet,
    NoticeVerificationResult,
)
from triage_agent.verifier.report import format_verification_markdown
from triage_agent.verifier.scanner import (
    C_STYLE_COMMENT_EXTENSIONS,
    IGNORE_DIRS,
    TARGET_EXTENSIONS,
    extract_keywords_from_method,
    extract_python_docstring_and_code_lines,
    is_test_path,
    remove_c_style_comments_from_line,
    scan_directory_for_patterns,
    strip_quotes_for_comment_check,
)

__all__ = [
    "MatchSnippet",
    "AuditAttestation",
    "AttestationFile",
    "CheckVerificationResult",
    "NoticeVerificationResult",
    "CodebaseAuditReport",
    "compute_matches_hash",
    "extract_cve_id",
    "load_audit_attestations",
    "normalize_text",
    "C_STYLE_COMMENT_EXTENSIONS",
    "IGNORE_DIRS",
    "TARGET_EXTENSIONS",
    "extract_keywords_from_method",
    "extract_python_docstring_and_code_lines",
    "is_test_path",
    "remove_c_style_comments_from_line",
    "scan_directory_for_patterns",
    "strip_quotes_for_comment_check",
    "verify_codebase",
    "format_verification_markdown",
    "main",
]
