#!/bin/sh
# POSIX-compliant host telemetry collector for Linux Kernel Exposure & Exploit Chain Triaging.
# Read-only execution. Collects OS kernel version, package flavor, loaded/builtin modules,
# modprobe configuration, livepatch status, and active networking services (IPsec/xfrm).
#
# Usage:
#   sh collect_kernel_telemetry.sh [-o output.json] [-p pool_id] [-m "esp4 esp6 rxrpc"] [--include-hostname]
#   If -o is omitted, outputs to stdout.

set -eu

OUTPUT_FILE=""
POOL_ID=""
TARGET_MODULES="esp4 esp6 rxrpc"
INCLUDE_HOSTNAME="false"

while [ $# -gt 0 ]; do
  case "$1" in
    -o|--output)
      OUTPUT_FILE="$2"
      shift 2
      ;;
    -p|--pool|--pool-id)
      POOL_ID="$2"
      shift 2
      ;;
    -m|--modules)
      TARGET_MODULES="$2"
      shift 2
      ;;
    --include-hostname)
      INCLUDE_HOSTNAME="true"
      shift 1
      ;;
    -h|--help)
      echo "Usage: $0 [-o output.json] [-p pool_id] [-m \"esp4 esp6 rxrpc\"] [--include-hostname]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

# Convert space-separated modules to grep regex: (esp4|esp6|rxrpc)
MODULES_REGEX="$(echo "${TARGET_MODULES}" | tr ' ' '|' | sed 's/^|//;s/|$//')"

if [ "${INCLUDE_HOSTNAME}" = "true" ]; then
  NODE_NAME="$(hostname 2>/dev/null || echo 'unknown-node')"
else
  NODE_NAME="anonymized-node"
fi

COLLECTED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo '1970-01-01T00:00:00Z')"
UNAME_R="$(uname -r 2>/dev/null || echo 'unknown')"

# 1. OS distribution and release detection from /etc/os-release
OS_DISTRO="unknown"
OS_RELEASE=""
if [ -f /etc/os-release ]; then
  # Parse standard os-release fields
  OS_DISTRO="$(grep -E '^ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"'\'' ' || echo 'unknown')"
  OS_RELEASE="$(grep -E '^VERSION_ID=' /etc/os-release 2>/dev/null | cut -d= -f2 | tr -d '"'\'' ' || true)"
fi

# 2. Distro package version and flavor detection
PACKAGE_NAME="unknown"
PACKAGE_VER="unknown"
KERNEL_FLAVOR="linux"

if command -v dpkg >/dev/null 2>&1; then
  # Debian / Ubuntu
  PKG_NAME="linux-image-${UNAME_R}"
  DPKG_OUT="$(dpkg -l "${PKG_NAME}" 2>/dev/null | tail -n 1 || true)"
  if [ -n "${DPKG_OUT}" ]; then
    PACKAGE_NAME="$(echo "${DPKG_OUT}" | awk '{print $2}')"
    PACKAGE_VER="$(echo "${DPKG_OUT}" | awk '{print $3}')"
  fi
  # Obtain true source package name (e.g. linux-hwe-6.11, linux-aws, linux)
  if command -v dpkg-query >/dev/null 2>&1 && [ "${PACKAGE_NAME}" != "unknown" ]; then
    SRC_PKG="$(dpkg-query -W -f='${source:Package}' "${PACKAGE_NAME}" 2>/dev/null || true)"
    if [ -n "${SRC_PKG}" ]; then
      KERNEL_FLAVOR="${SRC_PKG}"
    fi
  fi
elif command -v rpm >/dev/null 2>&1; then
  # RHEL / Rocky / Alma / Fedora
  RPM_OUT="$(rpm -qf "/boot/vmlinuz-${UNAME_R}" 2>/dev/null || true)"
  if [ -n "${RPM_OUT}" ]; then
    PACKAGE_NAME="${RPM_OUT}"
    PACKAGE_VER="$(rpm -q --qf '%{VERSION}-%{RELEASE}' -f "/boot/vmlinuz-${UNAME_R}" 2>/dev/null || echo "${RPM_OUT}")"
    SRC_RPM="$(rpm -q --qf '%{SOURCERPM}' -f "/boot/vmlinuz-${UNAME_R}" 2>/dev/null || true)"
    if [ -n "${SRC_RPM}" ]; then
      KERNEL_FLAVOR="$(echo "${SRC_RPM}" | sed 's/-[0-9].*//')"
    fi
  fi
fi

# Fallback pattern detection if source package was not directly acquired
if [ "${KERNEL_FLAVOR}" = "linux" ]; then
  case "${PACKAGE_NAME}" in
    *aws*)
      KERNEL_FLAVOR="linux-aws"
      ;;
    *gcp*)
      KERNEL_FLAVOR="linux-gcp"
      ;;
    *azure*)
      KERNEL_FLAVOR="linux-azure"
      ;;
    *oracle*)
      KERNEL_FLAVOR="linux-oracle"
      ;;
    *kvm*)
      KERNEL_FLAVOR="linux-kvm"
      ;;
    *hwe*)
      KERNEL_FLAVOR="linux-hwe"
      ;;
  esac
fi

# 3. Modprobe configuration (lines containing install/blacklist for target modules)
MODPROBE_LINES=""
if command -v modprobe >/dev/null 2>&1 && [ -n "${MODULES_REGEX}" ]; then
  MODPROBE_LINES="$(modprobe --showconfig 2>/dev/null | grep -E "^[[:space:]]*(install|blacklist)[[:space:]]+(${MODULES_REGEX})" || true)"
fi

# 4. Built-in modules check
BUILTIN_MODULES=""
BUILTIN_PATH="/lib/modules/${UNAME_R}/modules.builtin"
if [ -f "${BUILTIN_PATH}" ] && [ -n "${MODULES_REGEX}" ]; then
  BUILTIN_MODULES="$(grep -E "(${MODULES_REGEX})" "${BUILTIN_PATH}" 2>/dev/null || true)"
fi

# 5. Currently loaded kernel modules (/proc/modules)
LOADED_MODULES=""
if [ -f /proc/modules ] && [ -n "${MODULES_REGEX}" ]; then
  LOADED_MODULES="$(awk '{print $1}' /proc/modules 2>/dev/null | grep -E "^(${MODULES_REGEX})$" || true)"
fi

# 6. Active networking services (IPsec, strongswan, libreswan, AFS)
ACTIVE_SERVICES=""
if command -v systemctl >/dev/null 2>&1; then
  for s in ipsec strongswan strongswan-starter libreswan openafs-client; do
    if systemctl is-active --quiet "${s}" 2>/dev/null; then
      if [ -n "${ACTIVE_SERVICES}" ]; then
        ACTIVE_SERVICES="${ACTIVE_SERVICES},\"${s}\""
      else
        ACTIVE_SERVICES="\"${s}\""
      fi
    fi
  done
fi

# 7. Daemonless IPsec (xfrm) state check (e.g. Cilium / Calico node-to-node encryption)
XFRM_ACTIVE="false"
if command -v ip >/dev/null 2>&1; then
  if ip xfrm state 2>/dev/null | grep -q "src "; then
    XFRM_ACTIVE="true"
  elif ip xfrm policy 2>/dev/null | grep -q "src "; then
    XFRM_ACTIVE="true"
  fi
fi

# 8. Livepatch state
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
  "pool_id": $([ -n "${POOL_ID}" ] && printf '"%s"' "$(json_escape "${POOL_ID}")" || printf 'null'),
  "collected_at": "${COLLECTED_AT}",
  "os_distribution": "$(json_escape "${OS_DISTRO}")",
  "os_release": "$(json_escape "${OS_RELEASE}")",
  "kernel_package_name": "$(json_escape "${PACKAGE_NAME}")",
  "kernel_flavor": "$(json_escape "${KERNEL_FLAVOR}")",
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
  "xfrm_active": ${XFRM_ACTIVE},
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
