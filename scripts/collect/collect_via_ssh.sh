#!/bin/sh
# Collect kernel telemetry from every host of one node pool over ssh, and write a collection manifest.
# Works with any Linux host reachable by ssh (cloud VMs, on-premises, bare metal). Read-only on hosts.
#
# Usage:
#   sh scripts/collect/collect_via_ssh.sh -p <pool_id> -H <hosts_file> [-o triage-output/telemetry]
#                                         [-s <salt>] [-m "esp4 esp6 rxrpc"] [-x "<extra ssh options>"]
#
#   hosts_file: one ssh destination per line (user@host, host, or an alias from ~/.ssh/config).
#               Blank lines and lines starting with '#' are ignored.
#               Ansible users can produce it with:  ansible <group> --list-hosts | tail -n +2 | sed 's/^ *//'
#
# Exit status: 0 when every host was collected, 2 when some were not (the manifest records which).

set -eu

POOL_ID=""
HOSTS_FILE=""
OUT_DIR="triage-output/telemetry"
SALT="${TRIAGE_NODE_ID_SALT:-}"
MODULES=""
SSH_EXTRA=""

while [ $# -gt 0 ]; do
  case "$1" in
    -p) POOL_ID="$2"; shift 2 ;;
    -H) HOSTS_FILE="$2"; shift 2 ;;
    -o) OUT_DIR="$2"; shift 2 ;;
    -s) SALT="$2"; shift 2 ;;
    -m) MODULES="$2"; shift 2 ;;
    -x) SSH_EXTRA="$2"; shift 2 ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

. "$(dirname "$0")/_common.sh"

[ -n "${HOSTS_FILE}" ] || die "-H <hosts_file> is required"
[ -r "${HOSTS_FILE}" ] || die "hosts file not readable: ${HOSTS_FILE}"
init_run

REMOTE_CMD="sh -s -- $(collector_args)"

# Read the host list first: ssh would otherwise consume the loop's stdin.
grep -v '^[[:space:]]*#' "${HOSTS_FILE}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$' > "${STATE_DIR}/hosts" || true

while IFS= read -r host; do
  add_target "${host}"
  log "Collecting from ${host} ..."
  raw="${STATE_DIR}/raw.json"
  set +e
  # shellcheck disable=SC2086
  ssh -o BatchMode=yes -o ConnectTimeout=10 ${SSH_EXTRA} "${host}" "${REMOTE_CMD}" < "${COLLECTOR_SCRIPT}" > "${raw}" 2> "${STATE_DIR}/err"
  rc=$?
  set -e
  if [ "${rc}" -eq 255 ]; then
    # ssh itself failed (connection, authentication, host key)
    mark_unreachable "${host}"
  elif [ "${rc}" -ne 0 ]; then
    mark_failed "${host}"
  else
    store_result "${host}" "${raw}" || true
  fi
done < "${STATE_DIR}/hosts"

if write_manifest "ssh"; then
  exit 0
fi
exit 2
