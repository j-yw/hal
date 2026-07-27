#!/usr/bin/env bash
set -euo pipefail

readonly build_image=registry.gitlab.com/buildroot.org/buildroot/base@sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6

usage() {
	echo "usage: build.sh --cache ABSOLUTE_DIRECTORY --output ABSOLUTE_DIRECTORY" >&2
	exit 2
}

cache=
output=
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
	*)
		usage
		;;
	esac
done
[[ "$cache" == /* && "$output" == /* ]] || usage

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repo_root=$(git -C "$script_dir" rev-parse --show-toplevel)
[[ "$cache" != "$repo_root"/* && "$output" != "$repo_root"/* ]] || {
	echo "cache and output must be outside the source tree" >&2
	exit 1
}
[[ -z "$(git -C "$repo_root" status --porcelain --untracked-files=all)" ]] || {
	echo "L5 builds require a clean source tree" >&2
	exit 1
}
"$script_dir/verify-cache.sh" --manifest "$script_dir/cache.manifest" --cache "$cache"

mkdir -p -- "$output"
[[ -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
	echo "output directory must be empty" >&2
	exit 1
}
build_root=$(mktemp -d)
cleanup() {
	if [[ -n "${build_root:-}" && -d "$build_root" ]]; then
		rm -rf -- "$build_root"
	fi
}
trap cleanup EXIT

source_revision=$(git -C "$repo_root" rev-parse HEAD)
source_tree=tree-$(git -C "$repo_root" rev-parse 'HEAD^{tree}')
source_date_epoch=$(git -C "$repo_root" show -s --format=%ct HEAD)
jobs=${HAL_L5_JOBS:-$(nproc)}

docker run --rm \
	--platform=linux/amd64 \
	--network=none \
	--env "SOURCE_DATE_EPOCH=$source_date_epoch" \
	--env "SOURCE_REVISION=$source_revision" \
	--env "SOURCE_TREE=$source_tree" \
	--env "HAL_L5_JOBS=$jobs" \
	--mount "type=bind,src=$repo_root,dst=/src,readonly" \
	--mount "type=bind,src=$cache,dst=/cache,readonly" \
	--mount "type=bind,src=$build_root,dst=/build/output" \
	--mount "type=bind,src=$output,dst=/export" \
	"$build_image" \
	/src/tools/microvm/l5/build-in-container.sh
