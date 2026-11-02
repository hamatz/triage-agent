#!/bin/sh
# Collect kernel telemetry from the EC2 instances of one node pool via AWS Systems Manager Run Command,
# and write a collection manifest. One example of a cloud remote-execution transport; other clouds can
# follow the same pattern (list the pool's instances, run the collector, record who answered).
#
# Usage:
#   sh scripts/collect/collect_via_ssm.sh -p <pool_id> -f "<ec2 filter>" [-o triage-output/telemetry]
#                                         [-s <salt>] [-m "esp4 esp6 rxrpc"] [-r <region>] [-t <timeout_sec>]
#
#   -f  EC2 filter that selects the pool's instances, in `aws ec2 describe-instances --filters` syntax,
#       e.g. "Name=tag:triage-pool,Values=dmz" or "Name=tag:aws:autoscaling:groupName,Values=dmz-asg".
#       Only running instances are targeted. Every matching instance is an expected node: instances that
#       are not online in Systems Manager are recorded as unreachable instead of being skipped silently.
#
# Requires the AWS CLI with permission for ec2:DescribeInstances, ssm:DescribeInstanceInformation,
# ssm:SendCommand, ssm:ListCommandInvocations and ssm:GetCommandInvocation. Nothing is stored in AWS
# besides the Run Command history (which includes the command line, i.e. the pool id and the salt).
# Exit status: 0 when every instance was collected, 2 when some were not (the manifest records which).

set -eu

POOL_ID=""
EC2_FILTER=""
OUT_DIR="triage-output/telemetry"
SALT="${TRIAGE_NODE_ID_SALT:-}"
MODULES=""
REGION_OPT=""
TIMEOUT_SEC=600

while [ $# -gt 0 ]; do
  case "$1" in
    -p) POOL_ID="$2"; shift 2 ;;
    -f) EC2_FILTER="$2"; shift 2 ;;
    -o) OUT_DIR="$2"; shift 2 ;;
    -s) SALT="$2"; shift 2 ;;
    -m) MODULES="$2"; shift 2 ;;
    -r) REGION_OPT="--region $2"; shift 2 ;;
    -t) TIMEOUT_SEC="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

. "$(dirname "$0")/_common.sh"

[ -n "${EC2_FILTER}" ] || die "-f <ec2 filter> is required (it defines which instances belong to the pool)"
command -v aws >/dev/null 2>&1 || die "aws CLI not found"
case "${TIMEOUT_SEC}" in *[!0-9]*|'') die "-t must be a number of seconds" ;; esac
init_run

# shellcheck disable=SC2086
aws ${REGION_OPT} ec2 describe-instances \
  --filters "${EC2_FILTER}" "Name=instance-state-name,Values=running" \
  --query 'Reservations[].Instances[].InstanceId' --output text \
  | tr '\t' '\n' | grep -v '^$' | grep -v '^None$' | sort -u > "${STATE_DIR}/instances" \
  || die "aws ec2 describe-instances failed"
[ -s "${STATE_DIR}/instances" ] || die "no running instances matched filter: ${EC2_FILTER}"

while IFS= read -r iid; do
  add_target "${iid}"
done < "${STATE_DIR}/instances"

# Instances currently online in Systems Manager (queried in batches of 40 ids)
: > "${STATE_DIR}/online"
batch=""
n=0
flush_online() {
  [ -z "${batch}" ] && return 0
  # shellcheck disable=SC2086
  aws ${REGION_OPT} ssm describe-instance-information \
    --filters "Key=InstanceIds,Values=${batch}" \
    --query 'InstanceInformationList[?PingStatus==`Online`].InstanceId' --output text \
    | tr '\t' '\n' | grep -v '^$' | grep -v '^None$' >> "${STATE_DIR}/online" || true
  batch=""
  n=0
}
while IFS= read -r iid; do
  batch="${batch:+${batch},}${iid}"
  n=$((n + 1))
  [ "${n}" -ge 40 ] && flush_online
done < "${STATE_DIR}/instances"
flush_online

while IFS= read -r iid; do
  grep -qx "${iid}" "${STATE_DIR}/online" || mark_unreachable "${iid}"
done < "${STATE_DIR}/instances"

if [ -s "${STATE_DIR}/online" ]; then
  # The collector is shipped inline (base64) and piped to sh: nothing is written on the instance.
  payload="$(base64 < "${COLLECTOR_SCRIPT}" | tr -d '\n')"
  # collector_args contains only validated tokens (no double quotes or backslashes), so it is JSON-safe.
  printf '{"commands": ["echo %s | base64 -d | sh -s -- %s"]}\n' "${payload}" "$(collector_args)" \
    > "${STATE_DIR}/params.json"

  # send-command accepts at most 50 instance ids per call
  : > "${STATE_DIR}/commands"
  split -l 50 "${STATE_DIR}/online" "${STATE_DIR}/chunk_"
  for chunk in "${STATE_DIR}"/chunk_*; do
    ids="$(tr '\n' ' ' < "${chunk}")"
    # shellcheck disable=SC2086
    cid="$(aws ${REGION_OPT} ssm send-command --document-name AWS-RunShellScript \
      --comment "triage-agent kernel telemetry (${POOL_ID})" \
      --instance-ids ${ids} --parameters "file://${STATE_DIR}/params.json" \
      --query 'Command.CommandId' --output text)" || die "aws ssm send-command failed"
    printf '%s\n' "${cid}" >> "${STATE_DIR}/commands"
    log "Sent command ${cid} to $(wc -l < "${chunk}" | tr -d ' ') instance(s)"
  done

  # Wait until no invocation is pending
  waited=0
  while :; do
    : > "${STATE_DIR}/status"
    while IFS= read -r cid; do
      # shellcheck disable=SC2086
      aws ${REGION_OPT} ssm list-command-invocations --command-id "${cid}" \
        --query 'CommandInvocations[].[InstanceId,Status]' --output text \
        | awk -v c="${cid}" '{ print c "\t" $0 }' >> "${STATE_DIR}/status" || true
    done < "${STATE_DIR}/commands"
    pending="$(awk -F'\t' '$3 ~ /^(Pending|InProgress|Delayed)$/' "${STATE_DIR}/status" | wc -l | tr -d ' ')"
    reported="$(wc -l < "${STATE_DIR}/status" | tr -d ' ')"
    expected="$(wc -l < "${STATE_DIR}/online" | tr -d ' ')"
    if [ "${pending}" -eq 0 ] && [ "${reported}" -ge "${expected}" ]; then
      break
    fi
    if [ "${waited}" -ge "${TIMEOUT_SEC}" ]; then
      log "Timed out after ${TIMEOUT_SEC}s waiting for Run Command results"
      break
    fi
    sleep 5
    waited=$((waited + 5))
  done

  while IFS= read -r iid; do
    line="$(awk -F'\t' -v id="${iid}" '$2 == id' "${STATE_DIR}/status" | head -n 1)"
    cid="$(printf '%s' "${line}" | cut -f1)"
    status="$(printf '%s' "${line}" | cut -f3)"
    case "${status}" in
      Success)
        raw="${STATE_DIR}/raw.json"
        # shellcheck disable=SC2086
        if aws ${REGION_OPT} ssm get-command-invocation --command-id "${cid}" --instance-id "${iid}" \
            --query 'StandardOutputContent' --output text > "${raw}"; then
          store_result "${iid}" "${raw}" || true
        else
          mark_failed "${iid}"
        fi
        ;;
      Undeliverable|Terminated|"")
        mark_unreachable "${iid}"
        ;;
      *)
        mark_failed "${iid}"
        ;;
    esac
  done < "${STATE_DIR}/online"
fi

if write_manifest "aws-ssm"; then
  exit 0
fi
exit 2
