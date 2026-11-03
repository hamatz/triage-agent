#!/bin/sh
# POSIX-compliant host telemetry collector for Linux Kernel Exposure & Exploit Chain Triaging.
# Read-only execution. Collects OS kernel version, package flavor, loaded/builtin modules,
# modprobe configuration, livepatch status, and active networking services (IPsec/xfrm).
#
# Usage:
#   sh collect_kernel_telemetry.sh -p pool_id [-o output.json] [-m "esp4 esp6 rxrpc"] [-s salt] [--include-hostname]
#   -p is required: it must match a node pool id in environments.yaml.
#   If -o is omitted, outputs to stdout (e.g. `ssh host 'sh -s -- -p pool-a' < collect_kernel_telemetry.sh`).
#
# Node identity (ADR-021): node_id is an anonymized but stable hash of /etc/machine-id (or the hostname
# if machine-id is unavailable) and an optional organization salt (-s or TRIAGE_NODE_ID_SALT). The same
# host always yields the same id, so the audit can count collected nodes and detect duplicates without
# exposing host names. Use --include-hostname to emit the raw hostname instead.

set -eu

OUTPUT_FILE=""
POOL_ID=""
TARGET_MODULES="esp4 esp6 rxrpc"
INCLUDE_HOSTNAME="false"
NODE_ID_SALT="${TRIAGE_NODE_ID_SALT:-}"

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
    -s|--salt)
      NODE_ID_SALT="$2"
      shift 2
      ;;
    --include-hostname)
      INCLUDE_HOSTNAME="true"
      shift 1
      ;;
    -h|--help)
      echo "Usage: $0 -p pool_id [-o output.json] [-m \"esp4 esp6 rxrpc\"] [-s salt] [--include-hostname]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

if [ -z "${POOL_ID}" ]; then
  echo "Error: -p <pool_id> is required (it must match a node pool id in environments.yaml)." >&2
  exit 1
fi

# Convert space-separated modules to grep regex: (esp4|esp6|rxrpc)
MODULES_REGEX="$(echo "${TARGET_MODULES}" | tr ' ' '|' | sed 's/^|//;s/|$//')"

hash_sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 | awk '{print $NF}'
  else
    return 1
  fi
}

if [ "${INCLUDE_HOSTNAME}" = "true" ]; then
  NODE_NAME="$(hostname 2>/dev/null || echo 'unknown-node')"
else
  HOST_KEY=""
  if [ -r /etc/machine-id ]; then
    HOST_KEY="$(tr -d ' \n' < /etc/machine-id 2>/dev/null || true)"
  fi
  if [ -z "${HOST_KEY}" ]; then
    HOST_KEY="$(hostname 2>/dev/null || true)"
  fi
  NODE_HASH=""
  if [ -n "${HOST_KEY}" ]; then
    NODE_HASH="$(printf '%s:%s' "${NODE_ID_SALT}" "${HOST_KEY}" | hash_sha256 2>/dev/null | cut -c1-12 || true)"
  fi
  if [ -n "${NODE_HASH}" ]; then
    NODE_NAME="node-${NODE_HASH}"
  else
    # No hash tool or identity available: the audit counts this file as one node but cannot de-duplicate it.
    NODE_NAME="anonymized-node"
  fi
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
PACKAGE_EPOCH=""
PACKAGE_BIN_NAME=""
LIVEPATCH_PACKAGES=""
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
    # Epoch and binary package name are needed to compare against distro advisories precisely
    # (e.g. Amazon Linux 2023 kernels carry epoch 1; 'kernel' vs 'kernel6.12' are different lines).
    PACKAGE_EPOCH="$(rpm -q --qf '%{EPOCHNUM}' -f "/boot/vmlinuz-${UNAME_R}" 2>/dev/null || true)"
    PACKAGE_BIN_NAME="$(rpm -q --qf '%{NAME}' -f "/boot/vmlinuz-${UNAME_R}" 2>/dev/null || true)"
    SRC_RPM="$(rpm -q --qf '%{SOURCERPM}' -f "/boot/vmlinuz-${UNAME_R}" 2>/dev/null || true)"
    if [ -n "${SRC_RPM}" ]; then
      KERNEL_FLAVOR="$(echo "${SRC_RPM}" | sed 's/-[0-9].*//')"
    fi
  fi
fi

# Installed livepatch packages (RPM based distros ship them as kernel-livepatch-<kernel version>-<release>)
if command -v rpm >/dev/null 2>&1; then
  LIVEPATCH_PACKAGES="$(rpm -qa --qf '%{NAME}=%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n' 'kernel-livepatch-*' 2>/dev/null | sort -u || true)"
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
LIVEPATCH_MODULES=""
if [ -d /sys/kernel/livepatch ] && [ "$(ls -A /sys/kernel/livepatch 2>/dev/null)" ]; then
  LIVEPATCH_ACTIVE="true"
  # Each entry is a loaded livepatch module (e.g. kpatch_..., livepatch_..., lkp_...)
  LIVEPATCH_MODULES="$(ls -1 /sys/kernel/livepatch 2>/dev/null || true)"
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
  "pool_id": "$(json_escape "${POOL_ID}")",
  "collected_at": "${COLLECTED_AT}",
  "os_distribution": "$(json_escape "${OS_DISTRO}")",
  "os_release": "$(json_escape "${OS_RELEASE}")",
  "kernel_package_name": "$(json_escape "${PACKAGE_NAME}")",
  "kernel_flavor": "$(json_escape "${KERNEL_FLAVOR}")",
  "kernel_release": "$(json_escape "${UNAME_R}")",
  "distro_package_version": "$(json_escape "${PACKAGE_VER}")",
  "kernel_package_epoch": "$(json_escape "${PACKAGE_EPOCH}")",
  "kernel_binary_package": "$(json_escape "${PACKAGE_BIN_NAME}")",
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
  "livepatch_active": ${LIVEPATCH_ACTIVE},
  "livepatch_modules": $(to_json_array "${LIVEPATCH_MODULES}"),
  "livepatch_packages": $(to_json_array "${LIVEPATCH_PACKAGES}")
}
EOF
)

if [ -n "${OUTPUT_FILE}" ]; then
  mkdir -p "$(dirname "${OUTPUT_FILE}")"
  echo "${JSON_PAYLOAD}" > "${OUTPUT_FILE}"
else
  echo "${JSON_PAYLOAD}"
fi
