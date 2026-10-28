#!/usr/bin/env bash
# ==============================================================================
# triage-agent: Self-Triage & Dogfooding Diagnostic Script (ADR-018)
#
# Generates SBOM for triage-agent itself, queries OSV/GitHub for vulnerabilities,
# and verifies triage-agent's own codebase (src/triage_agent) for usage.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"

PYTHON_BIN=".venv/bin/python"
if [ ! -f "${PYTHON_BIN}" ]; then
  PYTHON_BIN="python3"
fi

echo "======================================================================"
echo "🛡️  triage-agent Self-Triage (ドッグフーディング自己診断)"
echo "======================================================================"

# Check Syft if available to generate official CycloneDX SBOM, or use built-in generator
if command -v syft &> /dev/null; then
  echo "📦 Generating self-SBOM using Syft (CycloneDX JSON)..."
  syft dir:. -o cyclonedx-json > self_sbom.json 2>/dev/null || true
fi

# Run self-triage
# Note: Use --dry-run if GEMINI_API_KEY is not configured
EXTRA_FLAGS=""
if [ -z "${GEMINI_API_KEY:-}" ] && [ "${GOOGLE_GENAI_USE_VERTEXAI:-}" != "true" ]; then
  echo "ℹ️  GEMINI_API_KEY not detected. Running in --dry-run (offline verification) mode."
  EXTRA_FLAGS="--dry-run"
fi

"${PYTHON_BIN}" -m triage_agent.cli \
  --self-triage \
  --output triage_self_report.md \
  --verify-output triage_self_audit.md \
  ${EXTRA_FLAGS} "$@"

echo "======================================================================"
echo "✅ Self-Triage completed successfully!"
echo "   - Triage Report: triage_self_report.md"
echo "   - Audit Report:  triage_self_audit.md"
echo "======================================================================"
