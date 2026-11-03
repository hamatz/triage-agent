# Shared helpers for the collection wrappers in scripts/collect/ (ADR-021 decision 4).
# Sourced, not executed. POSIX sh.
#
# Each wrapper distributes scripts/collect_kernel_telemetry.sh to the nodes of ONE pool with some
# transport (ssh, kubectl, AWS SSM, ...), saves every node's JSON as
#   <outdir>/<pool>/node-NNN.json
# and finally writes
#   <outdir>/<pool>/collection_manifest.json
# listing every node it targeted and whether collection succeeded, failed, or the node was unreachable.
# The audit uses the manifest as the pool's expected node count, so a node that silently failed can
# never make the pool look fully patched.
#
# File names never contain host names. The manifest lists the identifiers the wrapper used to reach
# each node (host name, Kubernetes node name, instance id); keep the output directory local
# (triage-output/ is git-ignored).

COMMON_DIR="$(cd "$(dirname "$0")" && pwd)"
COLLECTOR_SCRIPT="${COLLECTOR_SCRIPT:-${COMMON_DIR}/../collect_kernel_telemetry.sh}"

die() {
  echo "Error: $*" >&2
  exit 1
}

log() {
  echo "$*" >&2
}

# Pool ids and salts end up inside remote command lines; restrict them to a safe character set.
validate_token() {
  # $1: name, $2: value, $3: allow empty ("yes"/"no")
  if [ -z "$2" ]; then
    [ "$3" = "yes" ] && return 0
    die "$1 is required"
  fi
  case "$2" in
    *[!A-Za-z0-9._:-]*) die "$1 may only contain letters, digits, '.', '_', ':' and '-' (got: $2)" ;;
  esac
}

# Arguments passed to collect_kernel_telemetry.sh on every node.
collector_args() {
  args="-p ${POOL_ID}"
  [ -n "${SALT:-}" ] && args="${args} -s ${SALT}"
  [ -n "${MODULES:-}" ] && args="${args} -m '${MODULES}'"
  printf '%s' "${args}"
}

init_run() {
  validate_token "-p <pool_id>" "${POOL_ID:-}" no
  validate_token "-s <salt>" "${SALT:-}" yes
  if [ -n "${MODULES:-}" ]; then
    case "${MODULES}" in
      *[!A-Za-z0-9_\ -]*) die "-m may only contain module names separated by spaces" ;;
    esac
  fi
  [ -r "${COLLECTOR_SCRIPT}" ] || die "collector script not found: ${COLLECTOR_SCRIPT}"
  POOL_DIR="${OUT_DIR}/${POOL_ID}"
  mkdir -p "${POOL_DIR}"
  # The wrapper owns <outdir>/<pool>/: results of a previous run must not be counted again.
  rm -f "${POOL_DIR}"/node-*.json "${POOL_DIR}/collection_manifest.json"
  STATE_DIR="$(mktemp -d)"
  : > "${STATE_DIR}/targets"
  : > "${STATE_DIR}/succeeded"
  : > "${STATE_DIR}/failed"
  : > "${STATE_DIR}/unreachable"
  NODE_SEQ=0
  trap 'rm -rf "${STATE_DIR}"' EXIT
}

add_target() {
  printf '%s\n' "$1" >> "${STATE_DIR}/targets"
}

mark_unreachable() {
  printf '%s\n' "$1" >> "${STATE_DIR}/unreachable"
  log "  unreachable: $1"
}

mark_failed() {
  printf '%s\n' "$1" >> "${STATE_DIR}/failed"
  log "  failed: $1"
}

# store_result <target> <file containing the node's stdout>
# Accepts the output only if it looks like telemetry for this pool; otherwise marks the target failed.
store_result() {
  target="$1"
  raw="$2"
  if [ ! -s "${raw}" ] || ! grep -q '"node_id"' "${raw}" || ! grep -q "\"pool_id\": \"${POOL_ID}\"" "${raw}"; then
    mark_failed "${target}"
    return 1
  fi
  if command -v python3 >/dev/null 2>&1 && ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "${raw}" 2>/dev/null; then
    mark_failed "${target}"
    return 1
  fi
  NODE_SEQ=$((NODE_SEQ + 1))
  dest="${POOL_DIR}/$(printf 'node-%03d.json' "${NODE_SEQ}")"
  cp "${raw}" "${dest}"
  printf '%s\n' "${target}" >> "${STATE_DIR}/succeeded"
  log "  ok: ${target}"
  return 0
}

_json_list() {
  # newline separated file -> JSON array of strings (values are already restricted by the callers'
  # transports to host/node/instance names; escape quotes and backslashes defensively)
  printf '['
  first=1
  while IFS= read -r line || [ -n "${line}" ]; do
    [ -z "${line}" ] && continue
    esc="$(printf '%s' "${line}" | sed 's/\\/\\\\/g; s/"/\\"/g')"
    if [ "${first}" -eq 1 ]; then
      printf '"%s"' "${esc}"
      first=0
    else
      printf ', "%s"' "${esc}"
    fi
  done < "$1"
  printf ']'
}

# write_manifest <method>
write_manifest() {
  manifest="${POOL_DIR}/collection_manifest.json"
  generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  {
    printf '{\n'
    printf '  "kind": "collection_manifest",\n'
    printf '  "pool_id": "%s",\n' "${POOL_ID}"
    printf '  "method": "%s",\n' "$1"
    printf '  "generated_at": "%s",\n' "${generated_at}"
    printf '  "targets": %s,\n' "$(_json_list "${STATE_DIR}/targets")"
    printf '  "succeeded": %s,\n' "$(_json_list "${STATE_DIR}/succeeded")"
    printf '  "failed": %s,\n' "$(_json_list "${STATE_DIR}/failed")"
    printf '  "unreachable": %s\n' "$(_json_list "${STATE_DIR}/unreachable")"
    printf '}\n'
  } > "${manifest}"
  total="$(grep -c . "${STATE_DIR}/targets" || true)"
  ok="$(grep -c . "${STATE_DIR}/succeeded" || true)"
  log "Collected ${ok}/${total} node(s) of pool ${POOL_ID} -> ${POOL_DIR}"
  log "Manifest: ${manifest}"
  [ "${ok}" = "${total}" ]
}
