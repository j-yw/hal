#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: fetch.sh --cache ABSOLUTE_DIRECTORY" >&2
	exit 2
}
[[ $# == 2 && $1 == --cache ]] || usage
cache=$2
[[ "$cache" == /* && "$(realpath -m -- "$cache")" == "$cache" ]] || usage
parent=$(dirname -- "$cache")
current_uid=$(id -u)
[[ -d "$parent" && ! -L "$parent" && "$(realpath -e -- "$parent")" == "$parent" &&
	"$(stat -c %u "$parent")" == "$current_uid" && "$(stat -c %a "$parent")" == 700 ]] || {
	echo "cache parent must be a canonical private directory" >&2
	exit 1
}
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
[[ "$cache" != "$repo_root" && "$cache" != "$repo_root"/* ]] || usage
work=$(mktemp -d "$parent/.hal-l8-fetch.XXXXXXXX")
cleanup() {
	if [[ -n "${work:-}" && -d "$work" && ! -L "$work" ]]; then
		rm -rf -- "$work"
	fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -m 0700 "$work/home"

# Compilation is offline. The caller supplies the trusted Go1.25.7 toolchain
# and its already available module cache; no source/registry resolution occurs.
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=3 \
	timeout --signal=TERM --kill-after=10s 5m go -C "$repo_root" build -p 3 -mod=readonly \
	-o "$work/l8-cache" ./tools/microvm/l8/fetch
common=(--cache "$cache" --l5-manifest "$script_dir/../l5/cache.manifest" --l8-manifest "$script_dir/cache.manifest")
if [[ -e "$cache" || -L "$cache" ]]; then
	"$work/l8-cache" "${common[@]}" --verify-only
	exit 0
fi

# 30min aggregate bound, including all retries/signing metadata and Git calls.
# Clean command environment and cwd avoid ambient proxy/auth/git configuration.
(
	cd "$work"
	timeout --signal=TERM --kill-after=10s 30m env -i \
		PATH=/usr/bin:/bin HOME="$work/home" LC_ALL=C \
		GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
		GIT_TERMINAL_PROMPT=0 GIT_ALLOW_PROTOCOL=https \
		/bin/bash "$script_dir/../l5/fetch.sh" --cache "$work/l5" --bounded-transfers
)
# The extension's own 15min context bounds all 142 records together. Timeout
# also contains an unresponsive process independently of cooperative cleanup.
timeout --signal=TERM --kill-after=10s 16m \
	"$work/l8-cache" "${common[@]}" --l5-cache "$work/l5"
