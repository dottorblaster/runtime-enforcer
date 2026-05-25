#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

LOG_DIR="${1:-test/e2e/logs}"
NAMESPACE="${RUNTIME_ENFORCER_E2E_NAMESPACE:-run-enf-e2e-runtime-enforcer}"
RUNTIME_ENFORCER_POD_PREFIX="${RUNTIME_ENFORCER_POD_PREFIX:-runtime-enforcer}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHITELIST_JSON="${WHITELIST_JSON:-${SCRIPT_DIR}/whitelist.json}"

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required but was not found on PATH" >&2
  exit 2
fi

if [[ ! -f "$WHITELIST_JSON" ]]; then
  echo "whitelist file not found: $WHITELIST_JSON" >&2
  exit 2
fi

if [[ ! -d "$LOG_DIR" ]]; then
  echo "log directory not found: $LOG_DIR" >&2
  exit 2
fi

# kind export logs writes per-node folders with a containers/ subtree. Filenames
# look like "<pod>_<namespace>_<container>-<imageid>.log". Only runtime-enforcer
# pods (agent, controller) in the e2e namespace.
mapfile -t log_files < <(
  find "$LOG_DIR" -type f \
    \( -name '*.log' -o -name '*.txt' \) \
    \( \
      -path "*/containers/${RUNTIME_ENFORCER_POD_PREFIX}-agent-*_${NAMESPACE}_*.log" \
      -o -path "*/containers/${RUNTIME_ENFORCER_POD_PREFIX}-controller-manager-*_${NAMESPACE}_*.log" \
    \) \
  | sort
)

if (( ${#log_files[@]} == 0 )); then
  echo "no runtime-enforcer agent or controller log files found under $LOG_DIR for namespace $NAMESPACE" >&2
  exit 2
fi

# Full logs remain under LOG_DIR for debugging.
unexpected="$(
  jq -Rn --slurpfile whitelist "$WHITELIST_JSON" '
    ($whitelist[0]) as $entries |
    [
      inputs
      | sub("^[^\\{]*"; "")
      | fromjson
      | select((.level? // "" | ascii_upcase) as $l | $l == "ERROR" or $l == "WARN")
      | select(
          (.level? // "" | ascii_upcase) as $lvl
          | (.msg // "") as $m
          | (.component // "") as $c
          | ($entries
            | any(
                .msg == $m
                and .component == $c
                and ((.level // "") | ascii_upcase) == $lvl
              )
            | not)
        )
    ]
  ' "${log_files[@]}"
)"

if jq -e 'length > 0' <<<"$unexpected" >/dev/null; then
  echo "unexpected ERROR or WARN logs detected in runtime-enforcer logs:" >&2
  jq . <<<"$unexpected" >&2
  exit 1
fi

echo "no unexpected ERROR or WARN logs found"
