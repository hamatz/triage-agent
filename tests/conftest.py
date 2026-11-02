"""Test-suite guard: tests must never modify the data real runs depend on.

A test once wrote a one-entry CISA KEV catalog into the repository's triage-output/cache/, and real
audits then used it for 24 hours without any warning (actively exploited CVEs were silently missed).
This guard fingerprints such files before the session and fails the run if any of them changed.
"""

import hashlib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PROTECTED = [
    REPO / "triage-output" / "cache" / "cisa_kev_catalog.json",
    REPO / "triage-output" / "epss_history.json",
    REPO / "triage-output" / "workflow_metrics.json",
    REPO / "triage-output" / "cache" / "alas",
]


def _fingerprint(path: Path):
    if not path.exists():
        return None
    files = sorted(p for p in path.rglob("*") if p.is_file()) if path.is_dir() else [path]
    h = hashlib.sha256()
    for f in files:
        h.update(str(f.relative_to(REPO)).encode())
        h.update(f.read_bytes())
    return h.hexdigest()


@pytest.fixture(autouse=True, scope="session")
def _protect_real_run_data():
    """Fail the run (teardown error) if any test modified data that real runs depend on."""
    before = {p: _fingerprint(p) for p in PROTECTED}
    yield
    changed = [str(p.relative_to(REPO)) for p in PROTECTED if _fingerprint(p) != before[p]]
    assert not changed, "Tests modified data used by real runs: " + ", ".join(changed)


@pytest.fixture(autouse=True, scope="session")
def _isolated_workflow_metrics(tmp_path_factory):
    """Vendor round-trip metrics recorded by tests go to a temporary file, never to triage-output/."""
    import os
    path = tmp_path_factory.mktemp("workflow") / "workflow_metrics.json"
    previous = os.environ.get("TRIAGE_WORKFLOW_METRICS_FILE")
    os.environ["TRIAGE_WORKFLOW_METRICS_FILE"] = str(path)
    yield path
    if previous is None:
        os.environ.pop("TRIAGE_WORKFLOW_METRICS_FILE", None)
    else:
        os.environ["TRIAGE_WORKFLOW_METRICS_FILE"] = previous
