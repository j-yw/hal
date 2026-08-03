#!/usr/bin/env bash

set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"
umask 077

selectors=(
  ./internal/credentialmemory
  ./internal/credentialsource
  ./internal/credentialproxy
  ./internal/credentialdelivery
  ./internal/factory
  ./internal/sandboxruntime
  ./internal/sandboxruntime/networkenforcement/applicationroute
  ./internal/sandboxruntime/microvm/guestagent
  ./internal/sandboxruntime/microvm/guestagent/server/...
  ./internal/sandboxruntime/microvm/firecrackerhost
  ./internal/sandboxworker
  ./internal/sandboxexecution
  ./cmd
)

reports=()
cleanup() {
  local report
  for report in "${reports[@]:-}"; do
    if [[ -n "$report" && -f "$report" ]]; then
      rm -f -- "$report"
    fi
  done
}
trap cleanup EXIT

for selector in "${selectors[@]}"; do
  report="$(mktemp)"
  reports+=("$report")
  if ! go test -list '^TestL8' "$selector" >"$report"; then
    echo "L8 selector discovery failed" >&2
    exit 1
  fi
  if ! grep -Eq '^TestL8[A-Za-z0-9_]*(/.*)?$' "$report"; then
    echo "L8 selector matched no named L8 test" >&2
    exit 1
  fi
done

go test -count=1 -timeout=240s \
  ./internal/credentialmemory \
  ./internal/credentialsource \
  ./internal/credentialproxy \
  ./internal/credentialdelivery \
  ./internal/factory \
  ./internal/sandboxruntime \
  ./internal/sandboxruntime/networkenforcement/applicationroute \
  ./internal/sandboxruntime/microvm/guestagent \
  ./internal/sandboxruntime/microvm/guestagent/server/... \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  ./internal/sandboxworker \
  ./internal/sandboxexecution \
  ./cmd -run '^TestL8'

go test -race -count=1 -timeout=360s \
  ./internal/credentialmemory \
  ./internal/credentialsource \
  ./internal/credentialproxy \
  ./internal/sandboxruntime/microvm/guestagent/... \
  ./internal/sandboxruntime/microvm/firecrackerhost \
  ./internal/sandboxworker \
  ./internal/sandboxexecution -run '^TestL8'

go test -count=25 -timeout=420s \
  ./internal/credentialmemory \
  ./internal/credentialsource \
  ./internal/credentialproxy \
  ./internal/sandboxruntime/microvm/guestagent/server/... \
  ./internal/sandboxworker -run '^TestL8'
