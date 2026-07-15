#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
THRESHOLDS_FILE="${THRESHOLDS_FILE:-${SCRIPT_DIR}/nri-benchmark-thresholds.txt}"
BENCH_PKG="${BENCH_PKG:-./internal/nri/}"
BENCH_COUNT="${BENCH_COUNT:-1}"
BENCH_TOLERANCE_PERCENT="${BENCH_TOLERANCE_PERCENT:-30}"
UPDATE_BASELINE="${UPDATE_BASELINE:-false}"

if [[ "${GITHUB_ACTIONS:-}" != "true" ]]; then
  if [[ "$UPDATE_BASELINE" == "true" ]]; then
    echo "NRI benchmark baseline update runs in CI only" >&2
    exit 1
  fi
  echo "skipping NRI benchmark check (runs in CI only)"
  exit 0
fi

bench_names=(
  BenchmarkPluginSynchronize
  BenchmarkPluginStartContainer
  BenchmarkPluginRemoveContainer
)

run_benchmarks() {
  set +e
  local bench_stdout go_test_exit_code
  bench_stdout="$(go test \
    -bench='^BenchmarkPlugin(Synchronize|StartContainer|RemoveContainer)$' \
    -benchmem \
    -count="$BENCH_COUNT" \
    -run='^$' \
    -exec "sudo -n -E" \
    "$BENCH_PKG")"
  go_test_exit_code=$?
  set -e

  mapfile -t bench_output <<<"$bench_stdout"

  declare -gA observed_ns_per_op=()
  local pending_bench=""
  record_result() {
    local name="${1%-*}" ns="$2"
    if [[ -z "${observed_ns_per_op[$name]:-}" || "$ns" -gt "${observed_ns_per_op[$name]}" ]]; then
      observed_ns_per_op["$name"]="$ns"
    fi
  }

  for line in "${bench_output[@]}"; do
    if [[ "$line" =~ ^(Benchmark[^[:space:]]+)[[:space:]]+[0-9]+[[:space:]]+([0-9]+)[[:space:]]+ns/op ]]; then
      record_result "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
      pending_bench=""
    elif [[ "$line" =~ ^(Benchmark[^[:space:]]+) ]]; then
      pending_bench="${BASH_REMATCH[1]}"
    elif [[ -n "$pending_bench" && "$line" =~ ^[[:space:]]*[0-9]+[[:space:]]+([0-9]+)[[:space:]]+ns/op ]]; then
      record_result "$pending_bench" "${BASH_REMATCH[1]}"
      pending_bench=""
    fi
  done

  if (( go_test_exit_code != 0 )); then
    echo "go test failed with exit code ${go_test_exit_code}" >&2
    echo >&2
    echo "raw benchmark output:" >&2
    printf '%s\n' "${bench_output[@]}" >&2
    exit "$go_test_exit_code"
  fi
}

write_baseline_file() {
  local commit captured
  commit="$(git -C "$REPO_ROOT" rev-parse HEAD)"
  captured="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  {
    echo "# NRI callback benchmark baseline (ns/op)."
    echo "# commit: ${commit}"
    echo "# captured: ${captured}"
    echo "# tolerance: +${BENCH_TOLERANCE_PERCENT}% — update after intentional performance changes (only fails if slower than baseline)."
    for bench_name in "${bench_names[@]}"; do
      local observed_ns="${observed_ns_per_op[$bench_name]:-}"
      if [[ -z "$observed_ns" ]]; then
        echo "missing benchmark result for ${bench_name}" >&2
        echo >&2
        echo "raw benchmark output:" >&2
        printf '%s\n' "${bench_output[@]}" >&2
        exit 1
      fi
      echo "${bench_name} ${observed_ns}"
    done
  } >"$THRESHOLDS_FILE"

  echo "wrote baseline to ${THRESHOLDS_FILE}"
  cat "$THRESHOLDS_FILE"
}

read_baseline_file() {
  declare -gA baseline_ns_per_op=()
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    read -r bench_name baseline_ns <<<"$line"
    baseline_ns_per_op["$bench_name"]="$baseline_ns"
  done <"$THRESHOLDS_FILE"
}

# With BENCH_COUNT=1 (default), we keep the single ns/op sample with max ns/op. 
# This is because max/min/median are identical. With BENCH_COUNT > 1, prefer median
# for regression detection. One run per PR is enough since CI runs this on every PR.
check_against_baseline() {
  local failed=0
  local max_factor=$((100 + BENCH_TOLERANCE_PERCENT))

  for bench_name in "${bench_names[@]}"; do
    local baseline_ns="${baseline_ns_per_op[$bench_name]:-}"
    local observed_ns="${observed_ns_per_op[$bench_name]:-}"

    if [[ -z "$baseline_ns" ]]; then
      echo "missing baseline for ${bench_name} in ${THRESHOLDS_FILE}" >&2
      failed=1
      continue
    fi

    if [[ -z "$observed_ns" ]]; then
      echo "missing benchmark result for ${bench_name}" >&2
      failed=1
      continue
    fi

    # Only guard against regressions (too slow); running faster than baseline is fine.
    local max_ns=$((baseline_ns * max_factor / 100))

    if (( observed_ns > max_ns )); then
      echo "benchmark ${bench_name} exceeded +${BENCH_TOLERANCE_PERCENT}% of baseline: observed ${observed_ns} ns/op, baseline ${baseline_ns} ns/op (max ${max_ns} ns/op)" >&2
      failed=1
      continue
    fi

    echo "benchmark ${bench_name}: ${observed_ns} ns/op (baseline ${baseline_ns} ns/op, +${BENCH_TOLERANCE_PERCENT}% → max ${max_ns} ns/op)"
  done

  if (( failed != 0 )); then
    echo >&2
    echo "raw benchmark output:" >&2
    printf '%s\n' "${bench_output[@]}" >&2
    echo >&2
    echo "update ${THRESHOLDS_FILE} after intentional performance changes" >&2
    exit 1
  fi
}

if [[ ! -f "$THRESHOLDS_FILE" && "$UPDATE_BASELINE" != "true" ]]; then
  echo "thresholds file not found: $THRESHOLDS_FILE" >&2
  echo "create ${THRESHOLDS_FILE} from a CI benchmark run" >&2
  exit 2
fi

cd "$REPO_ROOT"
run_benchmarks

if [[ "$UPDATE_BASELINE" == "true" ]]; then
  write_baseline_file
  exit 0
fi

read_baseline_file
check_against_baseline
