#!/usr/bin/env bash
set -euo pipefail

readonly signer_fingerprint=18C7DF2819C1733D822D599EA500D6EE9CB0E540
readonly buildroot_tag_object=de1f9260590a53a7cd8a59addc47c96ecd09f983
readonly buildroot_commit=cb857ba4c87a93e5265a9e4a3f32071abf39e14a
readonly buildroot_digest=ae7f706f087b9ae9083a10a587368dfbf53103c28bf81c2d690198dc4090cb58

usage() {
	echo "usage: fetch.sh --cache ABSOLUTE_DIRECTORY [--bounded-transfers]" >&2
	exit 2
}

cache=
bounded_transfers=false
while (($#)); do
	case "$1" in
	--cache)
		(($# >= 2)) || usage
		cache=$2
		shift 2
		;;
	--bounded-transfers)
		bounded_transfers=true
		shift
		;;
	*)
		usage
		;;
	esac
done
[[ "$cache" == /* && "$cache" != *"/../"* && "$cache" != */.. ]] || usage
[[ "$(realpath -m -- "$cache")" == "$cache" ]] || usage

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
lock=$script_dir/sources.lock.json
manifest=$script_dir/cache.manifest
verifier=$script_dir/verify-cache.sh

parent=$(dirname -- "$cache")
current_uid=$(id -u)
[[ -d "$parent" && ! -L "$parent" &&
	"$(realpath -e -- "$parent")" == "$parent" &&
	"$(stat -c %u "$parent")" == "$current_uid" &&
	"$(stat -c %a "$parent")" == 700 ]] || {
	echo "cache parent must be a canonical private directory" >&2
	exit 1
}
if [[ -e "$cache" || -L "$cache" ]]; then
	[[ -d "$cache" && ! -L "$cache" &&
		"$(realpath -e -- "$cache")" == "$cache" &&
		"$(stat -c %u "$cache")" == "$current_uid" &&
		"$(stat -c %a "$cache")" == 700 ]] || {
		echo "cache target must be a canonical private directory" >&2
		exit 1
	}
	if [[ -n "$(find "$cache" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
		"$verifier" --manifest "$manifest" --cache "$cache" --expected-owner "$current_uid"
		exit 0
	fi
fi
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

# Opt-in only: existing callers retain their original transfer behavior.
# The new L8 wrapper also sets an aggregate process-group deadline.
fetch_url() (
	maximum=$1
	destination=$2
	url=$3
	if [[ "$bounded_transfers" == true ]]; then
		# RLIMIT_FSIZE is an additional rounded-up disk bound even for a curl
		# version whose size option trusts a Content-Length header.
		ulimit -f "$(((maximum + 1023) / 1024))"
		curl --disable --fail --location --retry 3 --retry-max-time 1200 \
			--connect-timeout 20 --max-time 600 --max-redirs 5 \
			--proto '=https' --proto-redir '=https' --proxy '' --noproxy '*' \
			--max-filesize "$maximum" --output "$destination" "$url"
	else
		curl --fail --location --retry 3 --output "$destination" "$url"
	fi
)

read_release_ref() {
	if [[ "$bounded_transfers" == true ]]; then
		local ref_file
		ref_file=$(mktemp "$metadata/release-ref.XXXXXXXX")
		if ! timeout --signal=TERM --kill-after=5s 120s \
			git -c credential.helper= -c core.askPass= -c http.extraHeader= \
			ls-remote "$repository_url" "$1" 2>/dev/null | head -c 4097 > "$ref_file"; then
			echo "Buildroot release reference lookup failed" >&2
			return 1
		fi
		[[ $(wc -c < "$ref_file") -le 4096 ]] || {
			echo "Buildroot release reference exceeds metadata bound" >&2
			return 1
		}
		cat -- "$ref_file"
		rm -- "$ref_file"
	else
		git ls-remote "$repository_url" "$1"
	fi
}

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
	fetch_url "$expected_size" "$stage/$filename" "$url"
	actual_size=$(wc -c <"$stage/$filename" | tr -d ' ')
	actual_digest=$(sha256sum "$stage/$filename" | cut -d ' ' -f 1)
	[[ "$actual_size" == "$expected_size" && "$actual_digest" == "$expected_digest" ]] || {
		echo "download does not match the source lock" >&2
		exit 1
	}
done

"$verifier" --manifest "$manifest" --cache "$stage" --expected-owner "$current_uid"

signing_key_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["buildroot"]["signingKeyUrl"])' "$lock")
signature_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["buildroot"]["signatureUrl"])' "$lock")
repository_url=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["buildroot"]["repositoryUrl"])' "$lock")
fetch_url 1048576 "$metadata/release-key.asc" "$signing_key_url"
fetch_url 1048576 "$metadata/buildroot-2026.05.1.tar.xz.sign" "$signature_url"

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

actual_tag_object=$(read_release_ref refs/tags/2026.05.1 | awk '{print $1}')
actual_commit=$(read_release_ref 'refs/tags/2026.05.1^{}' | awk '{print $1}')
[[ "$actual_tag_object" == "$buildroot_tag_object" && "$actual_commit" == "$buildroot_commit" ]] || {
	echo "Buildroot tag identity mismatch" >&2
	exit 1
}

if [[ -d "$cache" ]]; then
	rmdir -- "$cache"
fi
mv -- "$stage" "$cache"
stage=
"$verifier" --manifest "$manifest" --cache "$cache" --expected-owner "$current_uid"
