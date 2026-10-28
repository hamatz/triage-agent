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

# Determine if --dry-run was explicitly passed in arguments
IS_DRY_RUN=false
for arg in "$@"; do
  if [ "$arg" == "--dry-run" ]; then
    IS_DRY_RUN=true
    break
  fi
done

# If not running dry-run, strictly verify LLM credentials to prevent silent dry-run in CI
if [ "${IS_DRY_RUN}" = false ]; then
  if [ -z "${GEMINI_API_KEY:-}" ] && [ "${GOOGLE_GENAI_USE_VERTEXAI:-}" != "true" ]; then
    echo "❌ [ERROR] GEMINI_API_KEY または Vertex AI (GOOGLE_GENAI_USE_VERTEXAI=true) が設定されていません。"
    echo "   CI/CD環境でのシークレット失効や未設定による「サイレントな成功」を防ぐため、処理を停止します。"
    echo "   ローカル環境等でオフラインシミュレーションを行う場合は、明示的に --dry-run を指定してください。"
    echo "   例: ./scripts/self_triage.sh --dry-run"
    exit 1
  fi
fi

# If syft is available, generate official CycloneDX SBOM upfront
SBOM_FLAG=""
if command -v syft &> /dev/null; then
  echo "📦 Generating self-SBOM using Syft (CycloneDX JSON)..."
  if syft dir:. -o cyclonedx-json > self_sbom.json 2>/dev/null; then
    SBOM_FLAG="--sbom self_sbom.json"
    echo "   ✓ Syft CycloneDX SBOM generated: self_sbom.json"
  fi
fi

# Default failure guardrail: fail if unscanned components or confirmed YES findings exist
FAIL_ON_DEFAULT="--fail-on unscanned,yes"
for arg in "$@"; do
  if [[ "$arg" == --fail-on* ]]; then
    FAIL_ON_DEFAULT=""
    break
  fi
done

echo "🚀 Running Self-Triage CLI..."
"${PYTHON_BIN}" -m triage_agent.cli \
  --self-triage \
  ${SBOM_FLAG} \
  --output triage_self_report.md \
  --verify-output triage_self_audit.md \
  ${FAIL_ON_DEFAULT} "$@"

echo "======================================================================"
echo "✅ Self-Triage completed successfully!"
echo "   - Triage Report: triage_self_report.md"
echo "   - Audit Report:  triage_self_audit.md"
echo "======================================================================"
