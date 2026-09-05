#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

usage() {
	echo "usage: verify-image-profile.sh ROOTFS_EXT4" >&2
	exit 2
}

[[ $# == 1 && "$1" == /* && -f "$1" && ! -L "$1" ]] || usage
readonly image=$1
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
# These limits mirror the fixed L8 Buildroot ext4 profile. Raise them only with
# the image-size and inode-count locks in buildroot.config.
readonly L8_MAX_PROFILE_INODES=65536
readonly L8_MAX_PROFILE_CONTENT_BYTES=$((512 * 1024 * 1024))
readonly L8_MAX_PROFILE_DIRECTORY_ENTRIES=$((L8_MAX_PROFILE_INODES * 4))

scratch=$(mktemp -d)
cleanup() {
	if [[ -n ${scratch:-} && -d "$scratch" ]]; then
		chmod -R u+w -- "$scratch" 2>/dev/null || true
		rm -rf -- "$scratch"
	fi
}
trap cleanup EXIT

fail() {
	echo "$1" >&2
	exit 1
}

debugfs_stderr_is_clean() {
	local stderr_file=$1
	[[ ! -s "$stderr_file" ]] || awk '
		NR == 1 && /^debugfs [0-9]+([.][0-9]+)+/ { next }
		{ failed = 1 }
		END { exit failed }
	' "$stderr_file"
}

debugfs_request() {
	local request=$1 output=$2
	local stderr_file=$scratch/debugfs.stderr
	if ! debugfs -R "$request" "$image" >"$output" 2>"$stderr_file"; then
		return 1
	fi
	debugfs_stderr_is_clean "$stderr_file"
}

debugfs_batch() {
	local commands=$1 output=$2
	local stderr_file=$scratch/debugfs.stderr
	if ! debugfs -f "$commands" "$image" >"$output" 2>"$stderr_file"; then
		return 1
	fi
	debugfs_stderr_is_clean "$stderr_file"
}

require_entry() {
	local path=$1 type=$2 mode=$3 uid=$4 gid=$5 output=$scratch/entry.stat
	debugfs_request "stat $path" "$output" || fail "final rootfs required-entry inspection failed"
	grep -Eq "Type:[[:space:]]+$type" "$output"
	grep -Eq "Mode:[[:space:]]+$mode([[:space:]]|$)" "$output"
	grep -Eq "User:[[:space:]]+$uid[[:space:]]+Group:[[:space:]]+$gid([[:space:]]|$)" "$output"
}

for path in /sbin/init /sbin/hal-init /sbin/hal-guest-role-bootstrap /usr/bin/hal-guest-agent /usr/bin/hal-guest-credential-helper /usr/bin/hal-guest-mount-monitor /usr/bin/hal-guest-workload-shim /usr/bin/node /usr/bin/pi /bin/busybox /usr/bin/setpriv; do
	require_entry "$path" regular 0755 0 0
done
require_entry /workspace directory 0700 1000 1000
require_entry /run/agent directory 0700 998 998
require_entry /etc/resolv.conf regular 0644 0 0
debugfs_request 'stat /etc/resolv.conf' "$scratch/resolver.stat" || fail "final rootfs required-entry inspection failed"
grep -Eq 'Size:[[:space:]]+0([[:space:]]|$)' "$scratch/resolver.stat"

debugfs_request 'stat /bin/busybox' "$scratch/busybox.stat" || fail "final rootfs required-entry inspection failed"
busybox_inode=$(awk '/^Inode:/ {print $2; exit}' "$scratch/busybox.stat")
[[ "$busybox_inode" =~ ^[1-9][0-9]*$ ]]

require_busybox_applet() {
	local path=$1
	debugfs_request "stat $path" "$scratch/applet.stat" || fail "final rootfs applet inspection failed"
	if grep -Eq 'Type:[[:space:]]+regular' "$scratch/applet.stat"; then
		grep -Eq 'Mode:[[:space:]]+0755([[:space:]]|$)' "$scratch/applet.stat"
		grep -Eq 'User:[[:space:]]+0[[:space:]]+Group:[[:space:]]+0([[:space:]]|$)' "$scratch/applet.stat"
		applet_inode=$(awk '/^Inode:/ {print $2; exit}' "$scratch/applet.stat")
		[[ "$applet_inode" == "$busybox_inode" ]]
	else
		grep -Eq 'Type:[[:space:]]+symlink' "$scratch/applet.stat"
		target=$(sed -n 's/^Fast link dest: "\(.*\)"$/\1/p' "$scratch/applet.stat")
		[[ -n "$target" ]]
		"$script_dir/verify-applet-target.sh" "$path" "$target"
	fi
}

for path in /bin/sh /usr/bin/env; do
	require_busybox_applet "$path"
done

for path in /sbin/ip /usr/bin/nc /bin/ping /bin/ping6 /usr/bin/nslookup /usr/bin/wget; do
	require_busybox_applet "$path"
done

debugfs_request stats "$scratch/filesystem.stats" || fail "final rootfs inode inventory is invalid"
inode_count=$(awk -F: '/^Inode count:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$scratch/filesystem.stats")
[[ "$inode_count" =~ ^[1-9][0-9]*$ ]] || {
	echo "final rootfs inode inventory is invalid" >&2
	exit 1
}
if ((${#inode_count} > 6)) || ((10#$inode_count > L8_MAX_PROFILE_INODES)); then
	echo "final rootfs inode inventory exceeds bounded scan limit" >&2
	exit 1
fi

record_required_content_inode() {
	local path=$1 destination=$2
	local output=$scratch/required-content.stat inode
	debugfs_request "stat $path" "$output" || fail "final rootfs required-content inspection failed"
	grep -Eq 'Type:[[:space:]]+regular' "$output" || fail "final rootfs required-content inspection failed"
	inode=$(awk '/^Inode:/ {print $2; exit}' "$output")
	[[ "$inode" =~ ^[1-9][0-9]*$ && ${#inode} -le 6 ]] && ((10#$inode <= inode_count)) || fail "final rootfs required-content inspection failed"
	printf -v "$destination" '%d' "$((10#$inode))"
}

record_required_content_inode /usr/bin/setpriv setpriv_inode
record_required_content_inode /etc/passwd passwd_inode
record_required_content_inode /etc/group group_inode
record_required_content_inode /etc/shadow shadow_inode

# Walk only directory entries reachable from the root. Reserved filesystem
# metadata and unlinked inodes are not guest-visible files and are excluded.
declare -a directory_queue=(2)
declare -A queued_directories=([2]=1)
declare -a regular_inodes=()
declare -A regular_sizes=()
directory_index=0
directory_entry_count=0
regular_content_bytes=0

while ((directory_index < ${#directory_queue[@]})); do
	directory_inode=${directory_queue[directory_index]}
	directory_index=$((directory_index + 1))
	directory_report=$scratch/directory.report
	debugfs_request "ls -p -r <$directory_inode>" "$directory_report" || fail "final rootfs directory inspection failed"
	directory_self_entries=0
	while IFS= read -r entry || [[ -n "$entry" ]]; do
		[[ -n "$entry" ]] || continue
		directory_entry_count=$((directory_entry_count + 1))
		((directory_entry_count <= L8_MAX_PROFILE_DIRECTORY_ENTRIES)) || fail "final rootfs directory inventory exceeds bounded scan limit"
		# debugfs represents unused directory record slots with this exact
		# inode-zero sentinel (not a reachable filename), notably in lost+found.
		[[ "$entry" != /0/000000/0/0//0/ ]] || continue
		if [[ ! "$entry" =~ ^/([1-9][0-9]*)/([0-7]{6})/([0-9]+)/([0-9]+)/([^/]*)/([0-9]*)/$ ]]; then
			fail "final rootfs directory inspection failed"
		fi
		entry_inode=${BASH_REMATCH[1]}
		entry_mode=${BASH_REMATCH[2]}
		entry_name=${BASH_REMATCH[5]}
		entry_size=${BASH_REMATCH[6]}
		[[ ${#entry_inode} -le 6 ]] && ((10#$entry_inode <= inode_count)) || fail "final rootfs directory inventory is invalid"
		[[ -n "$entry_name" ]] && [[ ! "$entry_name" =~ [[:cntrl:]] ]] || fail "final rootfs directory inspection failed"

		entry_name_lower=${entry_name,,}
		case "$entry_name_lower" in
			.npmrc | .npm | id_rsa | *.pem | *npm-session*)
				fail "final rootfs contains a forbidden secret or package-manager filename"
				;;
		esac

		case "${entry_mode:0:2}" in
			04)
				if [[ "$entry_name" == . ]]; then
					[[ "$entry_inode" == "$directory_inode" ]] || fail "final rootfs directory inspection failed"
					directory_self_entries=$((directory_self_entries + 1))
				elif [[ "$entry_name" != .. && -z ${queued_directories[$entry_inode]+x} ]]; then
					queued_directories[$entry_inode]=1
					directory_queue+=("$entry_inode")
					((${#directory_queue[@]} <= inode_count)) || fail "final rootfs directory inventory is invalid"
				fi
				;;
			10)
				case "${entry_mode:2:1}" in
					2 | 3 | 4 | 5 | 6 | 7) fail "final rootfs contains a setuid or setgid regular file" ;;
				esac
				[[ "$entry_size" =~ ^[0-9]+$ && ${#entry_size} -le 18 ]] || fail "final rootfs regular-file inventory is invalid"
				if [[ -n ${regular_sizes[$entry_inode]+x} ]]; then
					[[ "${regular_sizes[$entry_inode]}" == "$entry_size" ]] || fail "final rootfs regular-file inventory is invalid"
					continue
				fi
				entry_size=$((10#$entry_size))
				((entry_size <= L8_MAX_PROFILE_CONTENT_BYTES - regular_content_bytes)) || fail "final rootfs regular-file content exceeds bounded scan limit"
				regular_content_bytes=$((regular_content_bytes + entry_size))
				regular_sizes[$entry_inode]=$entry_size
				regular_inodes+=("$entry_inode")
				;;
		esac
	done <"$directory_report"
	((directory_self_entries == 1)) || fail "final rootfs directory inspection failed"
done

for inode in "$setpriv_inode" "$passwd_inode" "$group_inode" "$shadow_inode"; do
	[[ -n ${regular_sizes[$inode]+x} ]] || fail "final rootfs required-content inspection failed"
done

attribute_commands=$scratch/regular-attribute.commands
: >"$attribute_commands"
for inode in "${regular_inodes[@]}"; do
	printf 'ea_list <%d>\n' "$((10#$inode))"
done >"$attribute_commands"
attribute_report=$scratch/regular-attribute.report
debugfs_batch "$attribute_commands" "$attribute_report" || fail "final rootfs regular-file attribute inspection failed"
if grep -Fq 'security.capability' "$attribute_report"; then
	fail "final rootfs contains file capabilities"
fi

regular_content=$scratch/regular-file.content
for inode in "${regular_inodes[@]}"; do
	rm -f -- "$regular_content"
	debugfs_request "dump <$inode> $regular_content" "$scratch/dump.output" || fail "final rootfs regular-file content inspection failed"
	[[ -f "$regular_content" && ! -L "$regular_content" ]] || fail "final rootfs regular-file content inspection failed"
	extracted_size=$(stat -c %s -- "$regular_content") || fail "final rootfs regular-file content inspection failed"
	[[ "$extracted_size" == "${regular_sizes[$inode]}" ]] || fail "final rootfs regular-file content inspection failed"
	if [[ "$inode" == "$setpriv_inode" ]]; then
		for option in --reuid --regid --clear-groups --no-new-privs --bounding-set --inh-caps --ambient-caps --securebits; do
			grep -Fq -- "$option" "$regular_content" || fail "final rootfs required-content inspection failed"
		done
	fi
	if [[ "$inode" == "$passwd_inode" ]]; then
		grep -Fq 'agent:x:998:998:Agent:/run/agent:/bin/sh' "$regular_content" || fail "final rootfs required-content inspection failed"
		grep -Fq 'workload:x:1000:1000:Workload:/workspace:/bin/sh' "$regular_content" || fail "final rootfs required-content inspection failed"
	fi
	if [[ "$inode" == "$group_inode" ]]; then
		grep -Fq 'agent:x:998:' "$regular_content" || fail "final rootfs required-content inspection failed"
		grep -Fq 'workload:x:1000:' "$regular_content" || fail "final rootfs required-content inspection failed"
	fi
	if [[ "$inode" == "$shadow_inode" ]]; then
		grep -Fq 'agent:!:::::::' "$regular_content" || fail "final rootfs required-content inspection failed"
		grep -Fq 'workload:!:::::::' "$regular_content" || fail "final rootfs required-content inspection failed"
	fi
	set +e
	grep -aEi 'BEGIN ([[:alnum:]_-]+[[:space:]]+)*PRIVATE KEY' "$regular_content" >/dev/null
	content_scan_status=$?
	set -e
	if ((content_scan_status == 0)); then
		fail "final rootfs contains private-key material"
	fi
	((content_scan_status == 1)) || fail "final rootfs regular-file content inspection failed"
done
