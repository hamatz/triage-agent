"""Attestation, sign-off validation, hashing, and drift detection utilities."""

import hashlib
import json
import re
from pathlib import Path
from typing import List, Optional

from rich.console import Console

from triage_agent.verifier.models import AuditAttestation, MatchSnippet

console = Console()


def compute_matches_hash(matches: List[MatchSnippet]) -> Optional[str]:
    """Compute deterministic fingerprint of code matches for drift detection."""
    if not matches:
        return None
    normalized_items = []
    for m in sorted(matches, key=lambda x: (x.file_path, x.line_number)):
        content = m.context_content if m.context_content else m.line_content
        normalized_content = " ".join(content.split())
        normalized_items.append(f"{m.file_path}:{normalized_content}")
    raw = "\n".join(normalized_items)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def normalize_text(text: str) -> str:
    """Normalize whitespace and lowercase for reliable exact matching."""
    return re.sub(r"\s+", " ", text.strip().lower())


def extract_cve_id(text: str) -> Optional[str]:
    """Extract standard CVE or GHSA identifier from text."""
    m = re.search(r"\b(CVE-\d{4}-\d{4,7}|GHSA-[a-z0-9\-]+)\b", text, re.IGNORECASE)
    return m.group(1).upper() if m else None


def load_audit_attestations(audit_file_path: Optional[str]) -> List[AuditAttestation]:
    """Load human attestation sign-off records if provided."""
    if not audit_file_path:
        return []
    path = Path(audit_file_path)
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [AuditAttestation.model_validate(item) for item in data]
        if isinstance(data, dict) and "attestations" in data:
            return [AuditAttestation.model_validate(item) for item in data["attestations"]]
    except Exception as e:
        console.print(f"[yellow]Warning: Failed to load audit file {audit_file_path}: {e}[/yellow]")
    return []
