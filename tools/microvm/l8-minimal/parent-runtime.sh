#!/usr/bin/env bash
# Sourced only for the explicit local rootless parent-builder selection.

prepare_parent_podman() {
	local lane=$1
	[[ "$lane" == l5 || "$lane" == l7 ]] || return 1
	[[ "$jobs" =~ ^[1-3]$ ]] || {
		echo "rootless builds require one to three compiler jobs" >&2
		return 1
	}
	runtime_probe=(timeout --signal=TERM --kill-after=5s 15s podman --remote=false)
	[[ "$current_uid" != 0 && "$("${runtime_probe[@]}" info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" == true ]] || {
		echo "explicit Podman builds require a rootless runtime" >&2
		return 1
	}
	# This directory is deliberately outside every guest-visible bind mount.
	# The source build cannot rewrite the CID or task label used for cleanup.
	runtime_metadata=$(mktemp -d --tmpdir="$output_parent" ".hal-$lane-runtime.XXXXXXXXXX") || return 1
	runtime_cidfile=$runtime_metadata/container.cid
	runtime_label=${runtime_metadata##*/}
	runtime_run=(run_parent_podman)
	runtime_autoremove=()
	runtime_args=(--userns=keep-id --cpus=3 --memory=12g --pids-limit=512
		--security-opt=no-new-privileges --timeout=10800
		"--cidfile=$runtime_cidfile" "--label=hal.microvm.build=$runtime_label")
}

run_parent_podman() {
	# These two entry scripts own exactly one asynchronous shell job. Waiting
	# explicitly lets a signal to build.sh alone interrupt wait immediately.
	runtime_admitted=true
	timeout --signal=TERM --kill-after=10s 181m podman --remote=false "$@" &
	runtime_pid=$!
	runtime_waiting=true
	local result=0
	wait "$runtime_pid" || result=$?
	runtime_waiting=false
	return "$result"
}

cleanup_parent_podman() {
	if [[ "${runtime_waiting:-false}" == true ]]; then
		# A job spec selects the shell-owned child, not a potentially reused
		# numeric PID. timeout forwards TERM and escalates after its 10s grace.
		kill -TERM %+ 2>/dev/null || true
		wait "$runtime_pid" 2>/dev/null || true
		runtime_waiting=false
	fi
	[[ -n "${runtime_metadata:-}" ]] || return 0
	[[ -d "$runtime_metadata" && ! -L "$runtime_metadata" &&
		"$(stat -c %u "$runtime_metadata")" == "$current_uid" &&
		"$(stat -c %a "$runtime_metadata")" == 700 ]] || return 1
	if [[ -e "$runtime_cidfile" || -L "$runtime_cidfile" ]]; then
		[[ -f "$runtime_cidfile" && ! -L "$runtime_cidfile" &&
			"$(stat -c %u "$runtime_cidfile")" == "$current_uid" ]] || return 1
		local size cid state exists
		size=$(stat -c %s "$runtime_cidfile") || return 1
		[[ "$size" == 64 || "$size" == 65 ]] || return 1
		LC_ALL=C grep --binary-files=text -qxE '[a-f0-9]{64}' "$runtime_cidfile" || return 1
		cid=$(<"$runtime_cidfile")
		[[ "$cid" =~ ^[a-f0-9]{64}$ ]] || return 1
		exists=0
		"${runtime_probe[@]}" container exists "$cid" >/dev/null 2>&1 || exists=$?
		case "$exists" in
		0)
			state=$("${runtime_probe[@]}" container inspect --format '{{.Id}} {{index .Config.Labels "hal.microvm.build"}}' "$cid" 2>/dev/null) || return 1
			[[ "$state" == "$cid $runtime_label" ]] || return 1
			"${runtime_probe[@]}" rm --force --ignore "$cid" >/dev/null 2>&1 || return 1
			exists=0
			"${runtime_probe[@]}" container exists "$cid" >/dev/null 2>&1 || exists=$?
			[[ "$exists" == 1 ]] || return 1
			;;
		1) ;; # The exact owned container was already removed independently.
		*) return 1 ;;
		esac
		# Podman removes its cidfile with the container; remove only a retained
		# regular copy if it is still present after confirmed absence.
		if [[ -e "$runtime_cidfile" || -L "$runtime_cidfile" ]]; then
			[[ -f "$runtime_cidfile" && ! -L "$runtime_cidfile" ]] || return 1
			rm -- "$runtime_cidfile" || return 1
		fi
	elif [[ "${runtime_admitted:-false}" == true ]]; then
		# Launch may have created a container before writing a complete CID.
		# Absence of a CID is not proof of absence of the admitted container.
		return 1
	fi
	rmdir -- "$runtime_metadata" || return 1
}
