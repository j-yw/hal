#!/usr/bin/env bash
set -euo pipefail

readonly canonical_source=/src
readonly canonical_cache=/cache
readonly canonical_build=/build/output

usage() {
	echo "usage: verify-reproducible.sh --cache ABSOLUTE_DIRECTORY --output ABSOLUTE_DIRECTORY" >&2
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
[[ "$canonical_source" == /src && "$canonical_cache" == /cache && "$canonical_build" == /build/output ]]

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
scratch=$(mktemp -d)
cleanup() {
	if [[ -d "$scratch" ]]; then
		rm -rf -- "$scratch"
	fi
}
trap cleanup EXIT
build_a=$scratch/build-a
build_b=$scratch/build-b
mkdir -p "$build_a" "$build_b"

"$script_dir/build.sh" --cache "$cache" --output "$build_a"
"$script_dir/build.sh" --cache "$cache" --output "$build_b"

for artifact in vmlinux rootfs.ext4 distribution-manifest.json provenance.json SHA256SUMS; do
	cmp "$build_a/$artifact" "$build_b/$artifact"
done
if grep -aRF -- "$build_a" "$build_a" "$build_b" >/dev/null ||
	grep -aRF -- "$build_b" "$build_a" "$build_b" >/dev/null; then
	echo "caller output path leaked into an L5 artifact" >&2
	exit 1
fi

mkdir -p "$output"
[[ -z "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
	echo "output directory must be empty" >&2
	exit 1
}
for artifact in vmlinux rootfs.ext4 distribution-manifest.json provenance.json SHA256SUMS; do
	cp "$build_a/$artifact" "$output/$artifact"
done
