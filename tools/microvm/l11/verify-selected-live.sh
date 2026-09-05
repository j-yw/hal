#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
umask 077

if [[ "${1:-}" != "matrix" || "$#" -ne 1 ]]; then
  echo "usage: tools/microvm/l11/verify-selected-live.sh matrix" >&2
  exit 2
fi

selected_test=TestL11PreparedLinuxFinalClosure
package=./cmd
tags=l11_final_closure_integration
selected_timeout=30m
report="$(mktemp)"

cleanup() {
  if [[ -f "$report" ]]; then
    rm -f -- "$report"
  fi
}
trap cleanup EXIT

if ! go test -list "^${selected_test}$" -tags="$tags" "$package" >"$report" 2>/dev/null; then
  echo "required_test_missing: selected L11 test discovery failed" >&2
  exit 1
fi
selected_count="$(awk -v selected="$selected_test" '$0 == selected { count++ } END { print count + 0 }' "$report")"
case "$selected_count" in
  0)
    echo "required_test_missing: selected L11 test was not discovered" >&2
    exit 1
    ;;
  1) ;;
  *)
    echo "evidence_mismatch: selected L11 test was discovered more than once" >&2
    exit 1
    ;;
esac

if ! go test -json -race -count=1 -timeout="$selected_timeout" \
  -tags="$tags" "$package" -run "^${selected_test}$" >"$report" 2>/dev/null; then
  echo "scenario_failed: selected L11 test process failed" >&2
  exit 1
fi

matrix_status=0
awk -v selected="$selected_test" '
    BEGIN {
      split("rootless_advisory_success rootless_client_loss_reconnect rootless_daemon_restart_recovery strict_firecracker_success strict_remove_one_proof strict_runtime_loss_reconnect strict_credential_loss_recovery artifact_integrity_and_safe_handoff zero_resource_leaks", required, " ")
    }
    index($0, "\"Action\":\"skip\"") { skipped++ }
    index($0, "\"Action\":\"run\"") && index($0, "\"Test\":\"" selected "\"") { top_run++ }
    index($0, "\"Action\":\"pass\"") && index($0, "\"Test\":\"" selected "\"") { top_pass++ }
    index($0, "\"Test\":\"" selected "/") {
      known = 0
      for (i in required) {
        exact = "\"Test\":\"" selected "/" required[i] "\""
        if (index($0, exact)) {
          known = 1
          if (index($0, "\"Action\":\"run\"")) row_run[required[i]]++
          if (index($0, "\"Action\":\"pass\"")) row_pass[required[i]]++
        }
      }
      if (!known) unexpected++
    }
    END {
      if (skipped != 0) exit 2
      if (unexpected != 0 || top_run > 1 || top_pass > 1) exit 3
      if (top_run == 0 || top_pass == 0) exit 4
      for (i in required) {
        if (row_run[required[i]] > 1 || row_pass[required[i]] > 1) exit 3
        if (row_run[required[i]] == 0 || row_pass[required[i]] == 0) exit 4
      }
    }
  ' "$report" || matrix_status=$?
case "$matrix_status" in
  0) ;;
  2)
    echo "required_test_skipped: selected L11 matrix emitted a skip" >&2
    exit 1
    ;;
  3)
    echo "evidence_mismatch: selected L11 matrix was duplicated or unexpected" >&2
    exit 1
    ;;
  4)
    echo "required_test_missing: selected L11 matrix was incomplete" >&2
    exit 1
    ;;
  *)
    echo "scenario_failed: selected L11 event verification failed" >&2
    exit 1
    ;;
esac
