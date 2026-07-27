#!/bin/sh
set -eu

usage() {
	echo "usage: verify-cache.sh --manifest FILE --cache DIR" >&2
	exit 2
}

manifest=
cache=
while [ "$#" -gt 0 ]; do
	case "$1" in
	--manifest)
		[ "$#" -ge 2 ] || usage
		manifest=$2
		shift 2
		;;
	--cache)
		[ "$#" -ge 2 ] || usage
		cache=$2
		shift 2
		;;
	*)
		usage
		;;
	esac
done

[ -n "$manifest" ] && [ -n "$cache" ] || usage
[ -f "$manifest" ] && [ ! -L "$manifest" ] || {
	echo "cache manifest must be a regular non-symlink file" >&2
	exit 1
}
[ -d "$cache" ] && [ ! -L "$cache" ] || {
	echo "cache must be a real directory" >&2
	exit 1
}
[ -s "$manifest" ] || {
	echo "cache manifest must not be empty" >&2
	exit 1
}
LC_ALL=C sort -c "$manifest" >/dev/null 2>&1 || {
	echo "cache manifest must be sorted" >&2
	exit 1
}

manifest_count=0
tab=$(printf '\t')
while IFS="$tab" read -r digest size filename extra; do
	[ -z "$extra" ] || {
		echo "cache manifest contains an invalid record" >&2
		exit 1
	}
	case "$digest" in
	*[!0-9a-f]*)
		echo "cache manifest contains an invalid digest" >&2
		exit 1
		;;
	esac
	[ "${#digest}" -eq 64 ] || {
		echo "cache manifest contains an invalid digest" >&2
		exit 1
	}
	case "$size" in
	"" | *[!0-9]* | 0)
		echo "cache manifest contains an invalid size" >&2
		exit 1
		;;
	esac
	case "$filename" in
	"" | "." | ".." | */* | *\\* | *"$tab"*)
		echo "cache manifest contains an unsafe filename" >&2
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
done <"$manifest"

cache_count=0
for entry in "$cache"/*; do
	[ -e "$entry" ] || continue
	[ -f "$entry" ] && [ ! -L "$entry" ] || {
		echo "cache contains a non-regular entry" >&2
		exit 1
	}
	cache_count=$((cache_count + 1))
done
[ "$cache_count" -eq "$manifest_count" ] || {
	echo "cache entry set does not match its manifest" >&2
	exit 1
}
