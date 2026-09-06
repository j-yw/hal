#!/usr/bin/env bash
set -euo pipefail

usage() {
	echo "usage: verify-final-image.sh ROOTFS_EXT4" >&2
	exit 2
}

[[ $# == 1 && "$1" == /* && -f "$1" && ! -L "$1" ]] || usage
readonly image=$1
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

hl8e=$script_dir/policy/verified-pinned-callsites.hl8e
[[ -f "$hl8e" && ! -L "$hl8e" && -s "$hl8e" ]] || {
	echo "HL8E is unissued; L8 final-image verification fails closed" >&2
	exit 1
}

parent_l7=${HAL_L8_PARENT_L7:-}
[[ "$parent_l7" == /* && -d "$parent_l7" && ! -L "$parent_l7" ]] || {
	echo "HAL_L8_PARENT_L7 parent L7 distribution is required" >&2
	exit 1
}
for artifact in SHA256SUMS distribution-manifest.json provenance.json rootfs.ext4 vmlinux; do
	[[ -f "$parent_l7/$artifact" && ! -L "$parent_l7/$artifact" && -s "$parent_l7/$artifact" ]] || {
		echo "parent L7 distribution is missing $artifact" >&2
		exit 1
	}
done
grep -Fq '"imageProfile":"l7-firecracker-network-v1"' "$parent_l7/distribution-manifest.json" || {
	echo "parent L7 evidence must be an L7 distribution; L5 images are not L8 production images" >&2
	exit 1
}

"$script_dir/verify-image-profile.sh" "$image"
