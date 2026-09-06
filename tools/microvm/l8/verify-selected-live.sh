#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
umask 077

case "${1:-}" in
  prerequisites)
    selected_test=TestL8PreparedLinuxCredentialDeliveryPrerequisites
    selected_timeout=5m
    ;;
  e2e)
    selected_test=TestL8PreparedLinuxCredentialDeliveryE2E
    selected_timeout=20m
    ;;
  *)
    echo "usage: tools/microvm/l8/verify-selected-live.sh prerequisites|e2e" >&2
    exit 2
    ;;
esac

package=./internal/sandboxruntime/microvm/firecrackerhost
tags='firecracker_live network_enforcement_live l7_linux_network_integration l8_production_credential_delivery_live'

if ! go test -list "^${selected_test}$" -tags="$tags" "$package" \
  | awk -v selected="$selected_test" '
      $0 == selected { count++ }
      END { if (count != 1) exit 1 }
    '; then
  echo "selected L8 live test was not discovered exactly once" >&2
  exit 1
fi

require_subtests=false
if [[ "$selected_test" == TestL8PreparedLinuxCredentialDeliveryE2E ]]; then
  require_subtests=true
fi
if ! go test -json -race -count=1 -timeout="$selected_timeout" \
  -tags="$tags" "$package" -run "^${selected_test}$" \
  | awk -v selected="$selected_test" -v require_subtests="$require_subtests" '
      BEGIN {
        split("http_only file_tmpfs_only ssh_agent_only all_modes failure_recovery_matrix", required, " ")
      }
      index($0, "\"Action\":\"skip\"") { skipped++ }
      index($0, "\"Action\":\"run\"") && index($0, "\"Test\":\"" selected "\"") { top_run++ }
      index($0, "\"Action\":\"pass\"") && index($0, "\"Test\":\"" selected "\"") { top_pass++ }
      index($0, "\"Action\":\"pass\"") {
        for (i in required) {
          if (index($0, "\"Test\":\"" selected "/" required[i] "\"")) subtest_pass[required[i]]++
        }
      }
      END {
        if (skipped != 0 || top_run != 1 || top_pass != 1) exit 1
        if (require_subtests == "true") {
          for (i in required) if (subtest_pass[required[i]] != 1) exit 1
        }
      }
    '; then
  echo "selected L8 live test did not run and pass exactly once without skips" >&2
  exit 1
fi
