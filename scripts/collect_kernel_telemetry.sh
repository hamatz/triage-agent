#!/bin/sh
# POSIX-compliant host telemetry collector for Linux Kernel Exposure & Exploit Chain Triaging.
# Read-only execution. Collects OS kernel version, loaded/builtin modules, modprobe configuration,
# livepatch status, and active networking services to verify mitigations without modifying the host.
#
# Usage:
#   sh collect_kernel_telemetry.sh [-o output.json]
#   If -o is omitted, outputs to stdout.

set -eu

OUTPUT_FILE=""

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [-o output.json]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

NODE_NAME="$(hostname 2>/dev/null || echo 'unknown-node')"
COLLECTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo '1970-01-01T00:00:00Z')"
UNAME_R="$(uname -r 2>/dev/null || echo 'unknown')"

# 1. Distro package version detection
PACKAGE_VER="unknown"
if command -v dpkg >/dev/null 2>&1; then
  # Debian / Ubuntu
  PKG_NAME="linux-image-${UNAME_R}"
  DPKG_OUT="$(dpkg -l "${PKG_NAME}" 2>/dev/null | tail -n 1 || true)"
  if [ -n "${DPKG_OUT}" ]; then
    # Format: ii  linux-image-6.8.0-40-generic  6.8.0-40.40  amd64 ...
    PACKAGE_VER="$(echo "${DPKG_OUT}" | awk '{print $3}')"
  fi
elif command -v rpm >/dev/null 2>&1; then
  # RHEL / Rocky / Alma / Fedora
  RPM_OUT="$(rpm -qf "/boot/vmlinuz-${UNAME_R}" 2>/dev/null || true)"
  if [ -n "${RPM_OUT}" ]; then
    PACKAGE_VER="${RPM_OUT}"
  fi
fi

# 2. Modprobe configuration (lines containing install/blacklist)
MODPROBE_LINES=""
if command -v modprobe >/dev/null 2>&1; then
  MODPROBE_LINES="$(modprobe --showconfig 2>/dev/null | grep -E '^[[:space:]]*(install|blacklist)[[:space:]]+(esp4|esp6|rxrpc)' || true)"
fi

# 3. Built-in modules check
BUILTIN_MODULES=""
BUILTIN_PATH="/lib/modules/${UNAME_R}/modules.builtin"
if [ -f "${BUILTIN_PATH}" ]; then
  BUILTIN_MODULES="$(grep -E '(esp4|esp6|rxrpc)' "${BUILTIN_PATH}" 2>/dev/null || true)"
fi

# 4. Currently loaded kernel modules
LOADED_MODULES=""
if [ -f /proc/modules ]; then
  LOADED_MODULES="$(awk '{print $1}' /proc/modules 2>/dev/null | grep -E '^(esp4|esp6|rxrpc)$' || true)"
fi

# 5. Active networking services that might conflict with mitigations (IPsec, StrongSwan, AFS)
ACTIVE_SERVICES=""
if command -v systemctl >/dev/null 2>&1; then
  for s in ipsec strongswan strongswan-starter openafs-client; do
    if systemctl is-active --quiet "${s}" 2>/dev/null; then
      if [ -n "${ACTIVE_SERVICES}" ]; then
        ACTIVE_SERVICES="${ACTIVE_SERVICES},\"${s}\""
      else
        ACTIVE_SERVICES="\"${s}\""
      fi
    fi
  done
fi

# 6. Livepatch state
LIVEPATCH_ACTIVE="false"
if [ -d /sys/kernel/livepatch ] && [ "$(ls -A /sys/kernel/livepatch 2>/dev/null)" ]; then
  LIVEPATCH_ACTIVE="true"
fi

# Helper to escape JSON strings
json_escape() {
  printf '%s' "$1" | awk '
    BEGIN { first=1 }
    {
      if (!first) printf "\\n";
      gsub(/\\/, "\\\\");
      gsub(/"/, "\\\"");
      gsub(/\r/, "");
      printf "%s", $0;
      first=0
    }
  '
}

# Helper to convert newline-separated list to JSON array of strings
to_json_array() {
  if [ -z "$1" ]; then
    echo "[]"
    return
  fi
  printf '['
  first=1
  for item in $1; do
    if [ "$first" -eq 1 ]; then
      printf '"%s"' "$item"
      first=0
    else
      printf ',"%s"' "$item"
    fi
  done
  printf ']'
}

# Construct JSON payload
JSON_PAYLOAD=$(cat <<EOF
{
  "node_id": "$(json_escape "${NODE_NAME}")",
  "collected_at": "${COLLECTED_AT}",
  "kernel_release": "$(json_escape "${UNAME_R}")",
  "distro_package_version": "$(json_escape "${PACKAGE_VER}")",
  "loaded_modules": $(to_json_array "${LOADED_MODULES}"),
  "builtin_modules": $(to_json_array "${BUILTIN_MODULES}"),
  "modprobe_config": [$(
    first=1
    echo "${MODPROBE_LINES}" | while IFS= read -r line; do
      [ -z "${line}" ] && continue
      esc="$(json_escape "${line}")"
      if [ "$first" -eq 1 ]; then
        printf '"%s"' "${esc}"
        first=0
      else
        printf ',"%s"' "${esc}"
      fi
    done
  )],
  "active_services": [${ACTIVE_SERVICES}],
  "livepatch_active": ${LIVEPATCH_ACTIVE}
}
EOF
)

if [ -n "${OUTPUT_FILE}" ]; then
  mkdir -p "$(dirname "${OUTPUT_FILE}")"
  echo "${JSON_PAYLOAD}" > "${OUTPUT_FILE}"
else
  echo "${JSON_PAYLOAD}"
fi
