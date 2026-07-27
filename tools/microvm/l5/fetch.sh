#!/usr/bin/env bash
set -euo pipefail

readonly signer_fingerprint=18C7DF2819C1733D822D599EA500D6EE9CB0E540
readonly buildroot_tag_object=de1f9260590a53a7cd8a59addc47c96ecd09f983
readonly buildroot_commit=cb857ba4c87a93e5265a9e4a3f32071abf39e14a
readonly buildroot_digest=ae7f706f087b9ae9083a10a587368dfbf53103c28bf81c2d690198dc4090cb58

usage() {
	echo "usage: fetch.sh --cache ABSOLUTE_DIRECTORY" >&2
	exit 2
}

cache=
while (($#)); do
	case "$1" in
	--cache)
		(($# >= 2)) || usage
		cache=$2
		shift 2
		;;
	*)
		usage
		;;
	esac
done
[[ "$cache" == /* && "$cache" != *"/../"* && "$cache" != */.. ]] || usage

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
lock=$script_dir/sources.lock.json
manifest=$script_dir/cache.manifest
verifier=$script_dir/verify-cache.sh

if [[ -d "$cache" ]] && [[ -n "$(find "$cache" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
	"$verifier" --manifest "$manifest" --cache "$cache"
	exit 0
fi
[[ ! -e "$cache" || -d "$cache" ]] || {
	echo "cache target must be a directory" >&2
	exit 1
}
parent=$(dirname -- "$cache")
mkdir -p -- "$parent"
stage=$(mktemp -d "$parent/.hal-l5-fetch.XXXXXXXX")
metadata=$(mktemp -d "$parent/.hal-l5-metadata.XXXXXXXX")
cleanup() {
	if [[ -n "${stage:-}" && -d "$stage" ]]; then
		rm -rf -- "$stage"
	fi
	if [[ -n "${metadata:-}" && -d "$metadata" ]]; then
		rm -rf -- "$metadata"
	fi
}
trap cleanup EXIT

python3 - "$lock" <<'PY' |
import json
import sys

with open(sys.argv[1], encoding="utf-8") as source:
    lock = json.load(source)
for item in lock["sources"]:
    print("\t".join((
        item["filename"],
        item["url"],
        str(item["sizeBytes"]),
        item["sha256"],
    )))
PY
while IFS=$'\t' read -r filename url expected_size expected_digest; do
	curl --fail --location --retry 3 --output "$stage/$filename" "$url"
	actual_size=$(wc -c <"$stage/$filename" | tr -d ' ')
	actual_digest=$(sha256sum "$stage/$filename" | cut -d ' ' -f 1)
	[[ "$actual_size" == "$expected_size" && "$actual_digest" == "$expected_digest" ]] || {
		echo "download does not match the source lock" >&2
		exit 1
	}
done

"$verifier" --manifest "$manifest" --cache "$stage"

signing_key_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["buildroot"]["signingKeyUrl"])' "$lock")
signature_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["buildroot"]["signatureUrl"])' "$lock")
repository_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["buildroot"]["repositoryUrl"])' "$lock")
curl --fail --location --retry 3 --output "$metadata/release-key.asc" "$signing_key_url"
curl --fail --location --retry 3 --output "$metadata/buildroot-2026.05.1.tar.xz.sign" "$signature_url"

mkdir -m 0700 "$metadata/gnupg"
GNUPGHOME=$metadata/gnupg gpg --batch --import "$metadata/release-key.asc" >/dev/null 2>&1
imported_fingerprint=$(GNUPGHOME=$metadata/gnupg gpg --batch --with-colons --fingerprint |
	awk -F: '$1 == "fpr" { print $10; exit }')
[[ "$imported_fingerprint" == "$signer_fingerprint" ]] || {
	echo "Buildroot release key fingerprint mismatch" >&2
	exit 1
}
signature_status=$(GNUPGHOME=$metadata/gnupg gpg --batch --status-fd 1 \
	--verify "$metadata/buildroot-2026.05.1.tar.xz.sign" 2>/dev/null)
grep -Fq "[GNUPG:] VALIDSIG $signer_fingerprint " <<<"$signature_status" || {
	echo "Buildroot signed release message is invalid" >&2
	exit 1
}
grep -Fq "SHA256: $buildroot_digest  buildroot-2026.05.1.tar.xz" \
	"$metadata/buildroot-2026.05.1.tar.xz.sign" || {
	echo "Buildroot signed release digest is invalid" >&2
	exit 1
}

actual_tag_object=$(git ls-remote "$repository_url" refs/tags/2026.05.1 | awk '{print $1}')
actual_commit=$(git ls-remote "$repository_url" 'refs/tags/2026.05.1^{}' | awk '{print $1}')
[[ "$actual_tag_object" == "$buildroot_tag_object" && "$actual_commit" == "$buildroot_commit" ]] || {
	echo "Buildroot tag identity mismatch" >&2
	exit 1
}

if [[ -d "$cache" ]]; then
	rmdir -- "$cache"
fi
mv -- "$stage" "$cache"
stage=
"$verifier" --manifest "$manifest" --cache "$cache"
