#!/bin/sh
set -eu

usage() {
	echo "usage: verify-cache.sh --cache DIR [--expected-owner UID]" >&2
	exit 2
}

cache=
expected_owner=$(id -u)
while [ "$#" -gt 0 ]; do
	case "$1" in
	--cache)
		[ "$#" -ge 2 ] || usage
		cache=$2
		shift 2
		;;
	--expected-owner)
		[ "$#" -ge 2 ] || usage
		expected_owner=$2
		shift 2
		;;
	*)
		usage
		;;
	esac
done

[ -n "$cache" ] || usage
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
l5_manifest=$script_dir/../l5/cache.manifest
l8_manifest=$script_dir/cache.manifest
[ -f "$l5_manifest" ] && [ ! -L "$l5_manifest" ] || {
	echo "L5 cache manifest must be a regular non-symlink file" >&2
	exit 1
}
[ -f "$l8_manifest" ] && [ ! -L "$l8_manifest" ] && [ -s "$l8_manifest" ] || {
	echo "L8 cache manifest is unissued; exact runtime source locks are required" >&2
	exit 1
}
[ -d "$cache" ] && [ ! -L "$cache" ] || {
	echo "cache must be a real directory" >&2
	exit 1
}
case "$expected_owner" in
"" | *[!0-9]*)
	usage
	;;
esac
[ "$(stat -c %u "$cache")" = "$expected_owner" ] && [ "$(stat -c %a "$cache")" = 700 ] || {
	echo "cache must have the expected owner and mode 0700" >&2
	exit 1
}

manifest_count=0
tab=$(printf '\t')
verify_manifest() {
	current_manifest=$1
	current_label=$2
	[ -s "$current_manifest" ] || {
		echo "$current_label cache manifest must not be empty" >&2
		exit 1
	}
	LC_ALL=C sort -c "$current_manifest" >/dev/null 2>&1 || {
		echo "$current_label cache manifest must be sorted" >&2
		exit 1
	}
	while IFS="$tab" read -r digest size filename extra; do
		[ -z "$extra" ] || {
			echo "$current_label cache manifest contains an invalid record" >&2
			exit 1
		}
		case "$digest" in
		*[!0-9a-f]*)
			echo "$current_label cache manifest contains an invalid digest" >&2
			exit 1
			;;
		esac
		[ "${#digest}" -eq 64 ] || {
			echo "$current_label cache manifest contains an invalid digest" >&2
			exit 1
		}
		case "$size" in
		"" | *[!0-9]* | 0)
			echo "$current_label cache manifest contains an invalid size" >&2
			exit 1
			;;
		esac
		case "$filename" in
		"" | "." | ".." | */* | *\\* | *"$tab"*)
			echo "$current_label cache manifest contains an unsafe filename" >&2
			exit 1
			;;
		esac
		entry=$cache/$filename
		[ -f "$entry" ] && [ ! -L "$entry" ] || {
			echo "cache entry is missing or is not a regular file" >&2
			exit 1
		}
		actual_size=$(wc -c <"$entry" | tr -d ' ')
		[ "$actual_size" = "$size" ] || {
			echo "cache entry size mismatch" >&2
			exit 1
		}
		actual_digest=$(sha256sum "$entry" | cut -d ' ' -f 1)
		[ "$actual_digest" = "$digest" ] || {
			echo "cache entry digest mismatch" >&2
			exit 1
		}
		manifest_count=$((manifest_count + 1))
	done <"$current_manifest"
}

verify_manifest "$l5_manifest" L5
verify_manifest "$l8_manifest" L8

duplicate_name=$(awk -F "$tab" 'NF >= 3 { print $3 }' "$l5_manifest" "$l8_manifest" | LC_ALL=C sort | uniq -d | sed -n '1p')
[ -z "$duplicate_name" ] || {
	echo "L5 and L8 cache manifests contain a duplicate filename" >&2
	exit 1
}

# Node 22.22.0, Pi 0.82.1, its shrinkwrap, and every transitive archive must
# be independently locked by the exact L8 cache.manifest. Missing files,
# unsorted records, and duplicate L5/L8 filenames fail closed.
for filename in node-v22.22.0.tar.xz pi-coding-agent-0.82.1.tgz pi-shrinkwrap-0.82.1.json; do
	awk -F "$tab" -v required="$filename" '$3 == required { found = 1 } END { exit !found }' "$l8_manifest" || {
		echo "required L8 cache lock $filename is missing" >&2
		exit 1
	}
done

if [ -n "$(find "$cache" -mindepth 1 -maxdepth 1 ! -type f -print -quit)" ]; then
	echo "cache contains a non-regular entry" >&2
	exit 1
fi
cache_count=$(find "$cache" -mindepth 1 -maxdepth 1 -type f -printf '.' | wc -c | tr -d ' ')
[ "$cache_count" -eq "$manifest_count" ] || {
	echo "cache entry set does not match the exact L5 and L8 manifests" >&2
	exit 1
}
