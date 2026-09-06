#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
go_bin=$(command -v go)
go_modcache=$("$go_bin" env GOMODCACHE)
go_cache=$("$go_bin" env GOCACHE)
# Host compilation is offline and does not deliver the caller's environment to
# the selected guest build. These two directories are public compiler caches.
helper_dir=$(mktemp -d)
trap 'rm -f -- "$helper_dir/assemble"; rmdir -- "$helper_dir"' EXIT
env -i PATH="$(dirname -- "$go_bin"):/usr/bin:/bin" HOME=/nonexistent \
	GOCACHE="$go_cache" GOMODCACHE="$go_modcache" GOPROXY=off GOSUMDB=off \
	GOTOOLCHAIN=local GOMAXPROCS=3 \
	timeout --signal=TERM --kill-after=10s 5m "$go_bin" -C "$repo_root" build \
	-mod=readonly -trimpath -buildvcs=false -o "$helper_dir/assemble" \
	./tools/microvm/l8-minimal/assembler
# Retain the executable while removing only our compiler scratch. Replacing
# the wrapper process makes a signal to assemble.sh reach the Go controller
# directly, rather than leaving a foreground child running behind a dead shell.
exec {assembler_fd}<"$helper_dir/assemble"
rm -- "$helper_dir/assemble"
rmdir -- "$helper_dir"
trap - EXIT
exec "/proc/self/fd/$assembler_fd" "$@"
