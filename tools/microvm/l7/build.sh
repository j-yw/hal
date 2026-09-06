#!/usr/bin/env bash
set -euo pipefail

readonly build_image=registry.gitlab.com/buildroot.org/buildroot/base@sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6
readonly L7_MAX_JOBS=64

usage() {
	echo "usage: build.sh --cache ABSOLUTE_DIRECTORY --output ABSOLUTE_DIRECTORY [--runtime docker|podman]" >&2
	exit 2
}

cache=
output=
runtime=docker
runtime_metadata=
runtime_admitted=false
runtime_waiting=false
while (($#)); do
	case "$1" in
	--cache)
		(($# >= 2)) || usage
		cache=$2
		shift 2
		;;
	--output)
		(($# >= 2)) || usage
		output=$2
		shift 2
		;;
	--runtime)
		(($# >= 2)) || usage
		runtime=$2
		shift 2
		;;
	*) usage ;;
	esac
done
[[ "$cache" == /* && "$output" == /* ]] || usage
[[ "$runtime" == docker || "$runtime" == podman ]] || usage

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
current_uid=$(id -u)
current_gid=$(id -g)
for path in "$cache" "$output"; do
	[[ "$(realpath -m -- "$path")" == "$path" ]] || usage
done
[[ "$cache" != "$repo_root"/* && "$output" != "$repo_root"/* && "$cache" != "$output" ]] || {
	echo "cache and output must be distinct and outside the source tree" >&2
	exit 1
}
[[ -z "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]] || {
	echo "L7 builds require a clean source tree" >&2
	exit 1
}
[[ -d "$cache" && ! -L "$cache" && "$(realpath -e -- "$cache")" == "$cache" ]] || {
	echo "cache must be a canonical real directory" >&2
	exit 1
}
cache_parent=$(dirname -- "$cache")
[[ -d "$cache_parent" && ! -L "$cache_parent" &&
	"$(realpath -e -- "$cache_parent")" == "$cache_parent" &&
	"$(stat -c %u "$cache_parent")" == "$current_uid" &&
	"$(stat -c %a "$cache_parent")" == 700 ]] || {
	echo "cache parent must be a canonical private directory" >&2
	exit 1
}
"$script_dir/../l5/verify-cache.sh" \
	--manifest "$script_dir/../l5/cache.manifest" \
	--cache "$cache" \
	--expected-owner "$current_uid"

output_parent=$(dirname -- "$output")
[[ -d "$output_parent" && ! -L "$output_parent" &&
	"$(realpath -e -- "$output_parent")" == "$output_parent" &&
	"$(stat -c %u "$output_parent")" == "$current_uid" &&
	"$(stat -c %a "$output_parent")" == 700 ]] || {
	echo "output parent must be a canonical private directory" >&2
	exit 1
}
if [[ ! -e "$output" ]]; then
	mkdir -m 0700 -- "$output"
fi
[[ -d "$output" && ! -L "$output" && "$(realpath -e -- "$output")" == "$output" &&
	"$(stat -c %u "$output")" == "$current_uid" && "$(stat -c %a "$output")" == 700 &&
	-z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
	echo "output must be an empty canonical private directory" >&2
	exit 1
}

build_root=$(mktemp -d --tmpdir="$output_parent" .hal-l7-build.XXXXXXXXXX)
cleanup() {
	local result=$?
	if [[ "$runtime" == podman && -n "${runtime_metadata:-}" ]] && ! cleanup_parent_podman; then
		echo "owned build container cleanup failed; private build evidence retained" >&2
		exit 1
	fi
	if [[ -n "${build_root:-}" && -d "$build_root" ]]; then
		chmod -R u+w -- "$build_root" 2>/dev/null || true
		rm -rf -- "$build_root"
	fi
	return "$result"
}
trap cleanup EXIT

source_revision=$(git -C "$repo_root" rev-parse HEAD)
source_tree=tree-$(git -C "$repo_root" rev-parse 'HEAD^{tree}')
source_date_epoch=$(git -C "$repo_root" show -s --format=%ct HEAD)
if [[ -n ${HAL_L7_JOBS+x} ]]; then
	jobs=$HAL_L7_JOBS
elif [[ "$runtime" == podman ]]; then
	jobs=3
else
	jobs=$(nproc)
	((jobs <= L7_MAX_JOBS)) || jobs=$L7_MAX_JOBS
fi
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] && ((${#jobs} <= 2)) && ((jobs <= L7_MAX_JOBS)) || {
	echo "HAL_L7_JOBS must be a positive decimal no greater than $L7_MAX_JOBS" >&2
	exit 1
}
runtime_probe=("$runtime")
runtime_image=(docker image inspect)
runtime_run=("$runtime")
runtime_args=()
runtime_autoremove=(--rm)
if [[ "$runtime" == podman ]]; then
	source "$script_dir/../l8-minimal/parent-runtime.sh"
	prepare_parent_podman l7
	runtime_image=("${runtime_probe[@]}" image inspect)
	trap 'exit 130' INT
	trap 'exit 143' TERM
fi
local_image=$("${runtime_image[@]}" --format '{{join .RepoDigests "\n"}}' "$build_image" 2>/dev/null) || {
	echo "pinned L7 build image is not installed locally" >&2
	exit 1
}
grep -Fxq "$build_image" <<<"$local_image" || {
	echo "local L7 build image digest does not match the lock" >&2
	exit 1
}

"${runtime_run[@]}" run "${runtime_autoremove[@]}" "${runtime_args[@]}" \
	--pull=never \
	--user="$current_uid:$current_gid" \
	--platform=linux/amd64 \
	--hostname=hal-l7-build \
	--network=none \
	--env HOME=/build/home \
	--env "SOURCE_DATE_EPOCH=$source_date_epoch" \
	--env "SOURCE_REVISION=$source_revision" \
	--env "SOURCE_TREE=$source_tree" \
	--env "HAL_L7_JOBS=$jobs" \
	--env "EXPECTED_CACHE_UID=$current_uid" \
	--mount "type=bind,src=$repo_root,dst=/src,readonly" \
	--mount "type=bind,src=$cache,dst=/cache,readonly" \
	--mount "type=bind,src=$build_root,dst=/build" \
	--mount "type=bind,src=$output,dst=/export" \
	"$build_image" \
	/src/tools/microvm/l7/build-in-container.sh
