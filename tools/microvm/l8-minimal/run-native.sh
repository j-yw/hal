#!/usr/bin/env bash
set -euo pipefail

(($# == 8)) || exit 2
source_root=$1
cache=$2
build_root=$3
export_root=$4
source_date_epoch=$5
source_revision=$6
source_tree=$7
output_parent=$8
readonly build_image=registry.gitlab.com/buildroot.org/buildroot/base@sha256:f1e7f009dad6b6f44bf5fcb4b0b89c9228e42f9fe689142774b1db802d4c93c6
current_uid=$(id -u)
current_gid=$(id -g)
jobs=3
runtime_metadata=
runtime_admitted=false
runtime_waiting=false
source "$source_root/tools/microvm/l8-minimal/parent-runtime.sh"
cleanup() {
	local result=$?
	if ! cleanup_parent_podman; then
		echo "native assembly: owned runtime cleanup incomplete; evidence retained" >&2
		exit 1
	fi
	return "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
prepare_parent_podman l8-minimal
local_image=$("${runtime_probe[@]}" image inspect --format '{{join .RepoDigests "\n"}}' "$build_image" 2>/dev/null)
grep -Fxq "$build_image" <<<"$local_image"
"${runtime_run[@]}" run "${runtime_args[@]}" \
	--pull=never --network=none --platform=linux/amd64 \
	--user="$current_uid:$current_gid" --hostname=hal-l8-minimal-build \
	--env HOME=/build/home --env "SOURCE_DATE_EPOCH=$source_date_epoch" \
	--env "SOURCE_REVISION=$source_revision" --env "SOURCE_TREE=$source_tree" \
	--env BR2_PRIMARY_SITE=file:///nonexistent --env BR2_PRIMARY_SITE_ONLY=y \
	--mount "type=bind,src=$source_root,dst=/src,readonly" \
	--mount "type=bind,src=$cache,dst=/cache,readonly" \
	--mount "type=bind,src=$build_root,dst=/build" \
	--mount "type=bind,src=$export_root,dst=/export" \
	"$build_image" /bin/bash /src/tools/microvm/l8-minimal/build-native.sh
