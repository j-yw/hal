#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "$script_dir/../../../.." && pwd)"
temporary_dir="$(mktemp -d)"
trap 'rm -rf -- "$temporary_dir"' EXIT

export CGO_ENABLED=0
export GOOS=linux
export GOARCH=amd64
export GOTOOLCHAIN=go1.25.7
export GOPROXY=off

go build -trimpath -buildvcs=false -ldflags=-buildid= \
  -o "$temporary_dir/policygen-a" ./tools/microvm/l8/policy/generate
go build -trimpath -buildvcs=false -ldflags=-buildid= \
  -o "$temporary_dir/policygen-b" ./tools/microvm/l8/policy/generate
cmp "$temporary_dir/policygen-a" "$temporary_dir/policygen-b"

expected_generator_sha256="$(tr -d '\n' < tools/microvm/l8/policy/generator-linux-amd64.sha256)"
actual_generator_sha256="$(sha256sum "$temporary_dir/policygen-a" | awk '{print $1}')"
if [[ "$actual_generator_sha256" != "$expected_generator_sha256" ]]; then
  echo "D7 generator executable digest mismatch" >&2
  exit 1
fi

"$temporary_dir/policygen-a" -root "$repo_root" -check
go test -count=1 ./tools/microvm/l8/policy/generate
go test -count=1 ./internal/sandboxruntime/microvm/guestagent/syscallpolicy
go test -count=1 -tags=l8_verified_policy_artifact \
  ./internal/sandboxruntime/microvm/guestagent/syscallpolicy
