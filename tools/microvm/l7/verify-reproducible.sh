#!/usr/bin/env bash
set -euo pipefail

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
	*) usage ;;
	esac
done
[[ "$cache" == /* && "$output" == /* ]] || usage

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
current_uid=$(id -u)
[[ "$(realpath -m -- "$output")" == "$output" ]] || usage
output_parent=$(dirname -- "$output")
[[ -d "$output_parent" && ! -L "$output_parent" &&
	"$(realpath -e -- "$output_parent")" == "$output_parent" &&
	"$(stat -c %u "$output_parent")" == "$current_uid" &&
	"$(stat -c %a "$output_parent")" == 700 ]] || {
	echo "output parent must be a canonical private directory" >&2
	exit 1
}
if [[ -e "$output" && (! -d "$output" || -L "$output" || -n "$(find "$output" -mindepth 1 -maxdepth 1 -print -quit)") ]]; then
	echo "output must be absent or an empty real directory" >&2
	exit 1
fi

scratch=$(mktemp -d --tmpdir="$output_parent" .hal-l7-verify.XXXXXXXXXX)
trap 'rm -rf -- "$scratch"' EXIT
build_a=$scratch/build-a
build_b=$scratch/build-b
mkdir -m 0700 "$build_a" "$build_b"
"$script_dir/build.sh" --cache "$cache" --output "$build_a"
"$script_dir/build.sh" --cache "$cache" --output "$build_b"

for artifact in vmlinux rootfs.ext4 distribution-manifest.json provenance.json SHA256SUMS; do
	cmp "$build_a/$artifact" "$build_b/$artifact"
done
if grep -aRF -- "$build_a" "$build_a" "$build_b" >/dev/null ||
	grep -aRF -- "$build_b" "$build_a" "$build_b" >/dev/null; then
	echo "caller output path leaked into an L7 artifact" >&2
	exit 1
fi
if [[ ! -e "$output" ]]; then
	mkdir -m 0700 -- "$output"
fi
for artifact in vmlinux rootfs.ext4 distribution-manifest.json provenance.json SHA256SUMS; do
	cp "$build_a/$artifact" "$output/$artifact"
done
