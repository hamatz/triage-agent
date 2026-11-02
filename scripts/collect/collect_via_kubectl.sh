#!/bin/sh
# Collect kernel telemetry from the nodes of one Kubernetes node pool via `kubectl debug node/...`,
# and write a collection manifest. Works with any conformant cluster (managed or self-hosted).
#
# Usage:
#   sh scripts/collect/collect_via_kubectl.sh -p <pool_id> -l <node label selector> [-o triage-output/telemetry]
#                                             [-s <salt>] [-m "esp4 esp6 rxrpc"] [-I <image>] [-k]
#
#   -l  Label selector that picks the nodes of this pool. Examples (use whatever your platform sets):
#         eks.amazonaws.com/nodegroup=dmz        cloud.google.com/gke-nodepool=dmz
#         kubernetes.azure.com/agentpool=dmz     node-role.example.com/pool=dmz
#   -I  Image for the debug container (default: busybox:1.36). It only needs `chroot`; the collector
#       runs with the node's own /bin/sh through `chroot /host`.
#   -k  Keep the debug pods (by default they are deleted after each node).
#
# Requires permission to create debug pods with the `sysadmin` profile on nodes. The debug pod reads
# host files only; nothing is written to the node.
# Exit status: 0 when every node was collected, 2 when some were not (the manifest records which).

set -eu

POOL_ID=""
SELECTOR=""
OUT_DIR="triage-output/telemetry"
SALT="${TRIAGE_NODE_ID_SALT:-}"
MODULES=""
IMAGE="busybox:1.36"
KEEP_PODS="no"

while [ $# -gt 0 ]; do
  case "$1" in
    -p) POOL_ID="$2"; shift 2 ;;
    -l) SELECTOR="$2"; shift 2 ;;
    -o) OUT_DIR="$2"; shift 2 ;;
    -s) SALT="$2"; shift 2 ;;
    -m) MODULES="$2"; shift 2 ;;
    -I) IMAGE="$2"; shift 2 ;;
    -k) KEEP_PODS="yes"; shift 1 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

. "$(dirname "$0")/_common.sh"

[ -n "${SELECTOR}" ] || die "-l <node label selector> is required (it defines which nodes belong to the pool)"
command -v kubectl >/dev/null 2>&1 || die "kubectl not found"
init_run

INNER_CMD="sh -s -- $(collector_args)"

# name<TAB>Ready-status for every node of the pool
kubectl get nodes -l "${SELECTOR}" \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}' \
  > "${STATE_DIR}/nodes" || die "kubectl get nodes failed"
[ -s "${STATE_DIR}/nodes" ] || die "no nodes matched selector: ${SELECTOR}"

while IFS="$(printf '\t')" read -r node ready; do
  [ -z "${node}" ] && continue
  add_target "${node}"
  if [ "${ready}" != "True" ]; then
    mark_unreachable "${node}"
    continue
  fi
  log "Collecting from node ${node} ..."
  raw="${STATE_DIR}/raw.json"
  set +e
  kubectl debug "node/${node}" -i --profile=sysadmin --image="${IMAGE}" \
    -- chroot /host sh -c "${INNER_CMD}" < "${COLLECTOR_SCRIPT}" > "${raw}" 2> "${STATE_DIR}/err"
  rc=$?
  set -e
  pod="$(sed -n 's/.*Creating debugging pod \([^ ]*\) .*/\1/p' "${STATE_DIR}/err" | head -n 1)"
  if [ -n "${pod}" ] && [ "${KEEP_PODS}" = "no" ]; then
    kubectl delete pod "${pod}" --wait=false >/dev/null 2>&1 || log "  warning: could not delete debug pod ${pod}"
  fi
  if [ "${rc}" -ne 0 ]; then
    mark_failed "${node}"
  else
    store_result "${node}" "${raw}" || true
  fi
done < "${STATE_DIR}/nodes"

if write_manifest "kubectl"; then
  exit 0
fi
exit 2
