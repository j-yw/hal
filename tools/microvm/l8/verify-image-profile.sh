#!/usr/bin/env bash
set -euo pipefail

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

scratch=$(mktemp -d)
cleanup() {
	if [[ -n ${scratch:-} && -d "$scratch" ]]; then
		chmod -R u+w -- "$scratch" 2>/dev/null || true
		rm -rf -- "$scratch"
	fi
}
trap cleanup EXIT

require_entry() {
	local path=$1 type=$2 mode=$3 uid=$4 gid=$5 output=$scratch/entry.stat
	debugfs -R "stat $path" "$image" >"$output" 2>/dev/null
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
debugfs -R 'stat /etc/resolv.conf' "$image" >"$scratch/resolver.stat" 2>/dev/null
grep -Eq 'Size:[[:space:]]+0([[:space:]]|$)' "$scratch/resolver.stat"

debugfs -R 'stat /bin/busybox' "$image" >"$scratch/busybox.stat" 2>/dev/null
busybox_inode=$(awk '/^Inode:/ {print $2; exit}' "$scratch/busybox.stat")
[[ "$busybox_inode" =~ ^[1-9][0-9]*$ ]]

require_busybox_applet() {
	local path=$1
	debugfs -R "stat $path" "$image" >"$scratch/applet.stat" 2>/dev/null
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

debugfs -R 'cat /usr/bin/setpriv' "$image" >"$scratch/setpriv" 2>/dev/null
for option in --reuid --regid --clear-groups --no-new-privs --bounding-set --inh-caps --ambient-caps --securebits; do
	grep -Fq -- "$option" "$scratch/setpriv"
done
debugfs -R 'cat /etc/passwd' "$image" >"$scratch/passwd" 2>/dev/null
grep -Fq 'agent:x:998:998:Agent:/run/agent:/bin/sh' "$scratch/passwd"
grep -Fq 'workload:x:1000:1000:Workload:/workspace:/bin/sh' "$scratch/passwd"
debugfs -R 'cat /etc/group' "$image" >"$scratch/group" 2>/dev/null
grep -Fq 'agent:x:998:' "$scratch/group"
grep -Fq 'workload:x:1000:' "$scratch/group"
debugfs -R 'cat /etc/shadow' "$image" >"$scratch/shadow" 2>/dev/null
grep -Fq 'agent:!:::::::' "$scratch/shadow"
grep -Fq 'workload:!:::::::' "$scratch/shadow"

for path in /sbin/ip /usr/bin/nc /bin/ping /bin/ping6 /usr/bin/nslookup /usr/bin/wget; do
	require_busybox_applet "$path"
done

inode_count=$(debugfs -R stats "$image" 2>/dev/null | awk -F: '/^Inode count:/ {gsub(/[[:space:]]/, "", $2); print $2; exit}')
[[ "$inode_count" =~ ^[1-9][0-9]*$ ]] || {
	echo "final rootfs inode inventory is invalid" >&2
	exit 1
}
if ((${#inode_count} > 6)) || ((10#$inode_count > L8_MAX_PROFILE_INODES)); then
	echo "final rootfs inode inventory exceeds bounded scan limit" >&2
	exit 1
fi
commands="$scratch/debugfs.commands"
for ((inode = 1; inode <= inode_count; inode++)); do
	printf 'stat <%d>\nea_list <%d>\n' "$inode" "$inode"
done >"$commands"
report="$scratch/debugfs.report"
debugfs -f "$commands" "$image" >"$report" 2>/dev/null

if grep -Eq 'Type:[[:space:]]+regular[[:space:]]+Mode:[[:space:]]+0?[2-7][0-7]{3}([[:space:]]|$)' "$report"; then
	echo "final rootfs contains a setuid or setgid regular file" >&2
	exit 1
fi
if grep -Fq 'security.capability' "$report"; then
	echo "final rootfs contains file capabilities" >&2
	exit 1
fi

directory_inodes="$scratch/directory.inodes"
awk '
$1 == "Inode:" {
	if ($2 ~ /^[0-9]+$/ && $3 == "Type:" && $4 == "directory") {
		print $2
	}
}
' "$report" >"$directory_inodes"
directory_commands="$scratch/directory.commands"
: >"$directory_commands"
while IFS= read -r inode; do
	[[ "$inode" =~ ^[1-9][0-9]*$ ]] && ((${#inode} <= 6)) && ((10#$inode <= inode_count)) || {
		echo "final rootfs directory inventory is invalid" >&2
		exit 1
	}
	printf 'ls -p -r <%d>\n' "$((10#$inode))"
done <"$directory_inodes" >"$directory_commands"
directory_report="$scratch/directory.report"
debugfs -f "$directory_commands" "$image" >"$directory_report" 2>/dev/null
directory_self_inodes="$scratch/directory-self.inodes"
awk -F/ '$2 ~ /^[1-9][0-9]*$/ && $6 == "." {print $2}' "$directory_report" >"$directory_self_inodes"
if ! cmp -s "$directory_inodes" "$directory_self_inodes"; then
	echo "final rootfs directory inspection failed" >&2
	exit 1
fi
if grep -aEqi '/(\.npmrc|\.npm|id_rsa|[^/]*\.pem|[^/]*npm-session[^/]*)/' "$directory_report"; then
	echo "final rootfs contains a forbidden secret or package-manager filename" >&2
	exit 1
fi

regular_files="$scratch/regular-files"
if ! awk '
function emit_regular() {
	if (kind != "regular") {
		return
	}
	if (inode !~ /^[0-9]+$/ || size !~ /^[0-9]+$/) {
		failed = 1
		exit 74
	}
	print inode, size
}
$1 == "Inode:" {
	emit_regular()
	inode = $2
	kind = ""
	size = ""
	for (field = 1; field < NF; field++) {
		if ($field == "Type:") {
			kind = $(field + 1)
		}
	}
	next
}
inode != "" {
	for (field = 1; field < NF; field++) {
		if ($field == "Size:") {
			size = $(field + 1)
		}
	}
}
END {
	if (!failed) {
		emit_regular()
	}
}
' "$report" >"$regular_files"; then
	echo "final rootfs regular-file inventory is invalid" >&2
	exit 1
fi

regular_content_commands="$scratch/regular-content.commands"
: >"$regular_content_commands"
regular_content_bytes=0
while IFS=' ' read -r inode size extra; do
	[[ -z ${extra:-} && "$inode" =~ ^[1-9][0-9]*$ && "$size" =~ ^[0-9]+$ ]] &&
		((${#inode} <= 6)) && ((${#size} <= 18)) && ((10#$inode <= inode_count)) || {
		echo "final rootfs regular-file inventory is invalid" >&2
		exit 1
	}
	size=$((10#$size))
	if ((size > L8_MAX_PROFILE_CONTENT_BYTES - regular_content_bytes)); then
		echo "final rootfs regular-file content exceeds bounded scan limit" >&2
		exit 1
	fi
	regular_content_bytes=$((regular_content_bytes + size))
	printf 'cat <%d>\n' "$((10#$inode))"
done <"$regular_files" >"$regular_content_commands"

set +e
debugfs -f "$regular_content_commands" "$image" 2>/dev/null |
	LC_ALL=C grep -aEi 'BEGIN ([[:alnum:]_-]+[[:space:]]+)*PRIVATE KEY' >/dev/null
content_scan_status=("${PIPESTATUS[@]}")
set -e
if ((${content_scan_status[0]} != 0)); then
	echo "final rootfs regular-file content inspection failed" >&2
	exit 1
fi
if ((${content_scan_status[1]} == 0)); then
	echo "final rootfs contains private-key material" >&2
	exit 1
fi
if ((${content_scan_status[1]} != 1)); then
	echo "final rootfs regular-file content inspection failed" >&2
	exit 1
fi
