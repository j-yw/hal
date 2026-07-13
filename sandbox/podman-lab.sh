#!/bin/sh

set -eu

REPO_ROOT=$(
	unset CDPATH
	cd -- "$(dirname -- "$0")/.."
	pwd
)
HOST_HOME=${HOME:-}
HOST_CODEX_HOME=${CODEX_HOME:-}
HOST_PI_HOME=${PI_HOME:-}
if [ -n "${HAL_SANDBOX_LAB_ROOT:-}" ]; then
	LAB_ROOT=${HAL_SANDBOX_LAB_ROOT%/}
else
	LAB_ROOT=${TMPDIR:-/tmp}
	LAB_ROOT=${LAB_ROOT%/}/hal-sandbox-lab-${USER:-local}
fi
MACHINE=${HAL_SANDBOX_LAB_MACHINE:-hal-sandbox-lab}
MACHINE_PROVIDER=${HAL_SANDBOX_LAB_MACHINE_PROVIDER:-}
if [ -z "$MACHINE_PROVIDER" ] && [ "$(uname -s)" = "Darwin" ]; then
	MACHINE_PROVIDER=applehv
fi
WORKER_ID=${HAL_SANDBOX_LAB_WORKER_ID:-hal-lab-worker}
IMAGE=${HAL_SANDBOX_LAB_IMAGE:-localhost/hal-agent:hal-lab}
BASE_IMAGE=${HAL_SANDBOX_LAB_BASE_IMAGE:-docker.io/library/ubuntu:22.04}
HOST_PROXY=${HAL_SANDBOX_LAB_HOST_PROXY:-}
GUEST_PROXY=${HAL_SANDBOX_LAB_GUEST_PROXY:-}
SOCKET="$LAB_ROOT/run/sandboxd.sock"
PID_FILE="$LAB_ROOT/run/sandboxd.pid"
LOG_FILE="$LAB_ROOT/logs/sandboxd.log"
HAL_BIN="$LAB_ROOT/bin/hal"
LIFECYCLE_LOCK_DIR="${LAB_ROOT}.lifecycle.lock"
LIFECYCLE_LOCK_OWNER="$LIFECYCLE_LOCK_DIR/owner"
LIFECYCLE_REAPER_DIR="${LIFECYCLE_LOCK_DIR}.reaper"
lifecycle_lock_held=
lifecycle_lock_birth=

export HAL_CONFIG_HOME="$LAB_ROOT/config/hal"
export XDG_CONFIG_HOME="$LAB_ROOT/config"
export XDG_DATA_HOME="$LAB_ROOT/data"
export XDG_CACHE_HOME="$LAB_ROOT/cache"
export TMPDIR="$LAB_ROOT/tmp"
export HOME="$LAB_ROOT/home"
export CONTAINER_CONNECTION="$MACHINE"
unset CODEX_HOME PI_HOME
export PATH="$LAB_ROOT/bin:$PATH"
if [ -n "$MACHINE_PROVIDER" ]; then
	export CONTAINERS_MACHINE_PROVIDER="$MACHINE_PROVIDER"
fi

case "$LAB_ROOT" in
	/*) ;;
	*)
		echo "HAL_SANDBOX_LAB_ROOT must be an absolute path" >&2
		exit 2
		;;
esac
case "$LAB_ROOT" in
	/|"${HOST_HOME:-/nonexistent}")
		echo "refusing unsafe lab root: $LAB_ROOT" >&2
		exit 2
		;;
esac
case "${LAB_ROOT##*/}" in
	hal-sandbox-*) ;;
	*)
		echo "HAL_SANDBOX_LAB_ROOT must use a hal-sandbox-* leaf directory" >&2
		exit 2
		;;
esac
case "$MACHINE:$WORKER_ID" in
	*[!A-Za-z0-9_.:-]*)
		echo "lab machine and worker IDs may contain only letters, numbers, dot, underscore, dash, and colon" >&2
		exit 2
		;;
esac

usage() {
	cat <<EOF
Usage: sandbox/podman-lab.sh COMMAND [ARGS]

Commands:
  prepare                 Create the isolated Podman machine, build Hal, and build the lab image
  start                   Start sandboxd and register the lab worker
  seed-auth               Copy supported engine auth files into the isolated lab home
  clone REPOSITORY [NAME] Clone a disposable repository into the lab workspace
  run -- COMMAND [ARGS]   Run a command with the isolated lab environment
  status                  Show the machine, daemon, worker, and sandbox state
  env                     Print the lab environment as shell exports
  destroy                 Delete lab targets, daemon, machine, and all lab files

Lab root: $LAB_ROOT
EOF
}

require_command() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "required command not found: $1" >&2
		exit 1
	fi
}

lab_podman() {
	podman --connection "$MACHINE" "$@"
}

with_host_proxy() {
	if [ -z "$HOST_PROXY" ]; then
		"$@"
		return
	fi
	env HTTP_PROXY="$HOST_PROXY" HTTPS_PROXY="$HOST_PROXY" ALL_PROXY="$HOST_PROXY" \
		NO_PROXY="localhost,127.0.0.1" "$@"
}

with_guest_proxy() {
	if [ -z "$GUEST_PROXY" ]; then
		"$@"
		return
	fi
	env HTTP_PROXY="$GUEST_PROXY" HTTPS_PROXY="$GUEST_PROXY" ALL_PROXY="$GUEST_PROXY" \
		NO_PROXY="localhost,127.0.0.1" "$@"
}

prefetch_base_image() {
	if [ -z "$GUEST_PROXY" ]; then
		lab_podman pull "$BASE_IMAGE"
		return
	fi
	podman machine ssh "$MACHINE" env \
		HTTP_PROXY="$GUEST_PROXY" \
		HTTPS_PROXY="$GUEST_PROXY" \
		ALL_PROXY="$GUEST_PROXY" \
		NO_PROXY="localhost,127.0.0.1" \
		podman pull "$BASE_IMAGE"
}

ensure_dirs() {
	umask 077
	mkdir -p "$HAL_CONFIG_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" \
		"$XDG_CACHE_HOME" "$TMPDIR" "$LAB_ROOT/bin" "$LAB_ROOT/logs" \
		"$LAB_ROOT/run" "$LAB_ROOT/workspaces" "$HOME"
}

copy_auth_file() {
	source_path=$1
	destination_path=$2
	if [ ! -f "$source_path" ]; then
		return
	fi
	mkdir -p "$(dirname "$destination_path")"
	cp -p "$source_path" "$destination_path"
	chmod 0600 "$destination_path"
	echo "Seeded ${destination_path#"$HOME"/}"
}

seed_auth() {
	ensure_dirs
	if [ -z "$HOST_HOME" ]; then
		echo "host HOME is unavailable; cannot seed auth" >&2
		exit 1
	fi
	codex_home=${HOST_CODEX_HOME:-"$HOST_HOME/.codex"}
	pi_home=${HOST_PI_HOME:-"$HOST_HOME/.pi"}
	copy_auth_file "$codex_home/auth.json" "$HOME/.codex/auth.json"
	copy_auth_file "$codex_home/config.toml" "$HOME/.codex/config.toml"
	copy_auth_file "$pi_home/agent/auth.json" "$HOME/.pi/agent/auth.json"
	copy_auth_file "$pi_home/agent/settings.json" "$HOME/.pi/agent/settings.json"
	copy_auth_file "$pi_home/agent/trust.json" "$HOME/.pi/agent/trust.json"
	copy_auth_file "$HOST_HOME/.claude.json" "$HOME/.claude.json"
	copy_auth_file "$HOST_HOME/.claude/settings.json" "$HOME/.claude/settings.json"
	copy_auth_file "$HOST_HOME/.claude/credentials.json" "$HOME/.claude/credentials.json"
	copy_auth_file "$HOST_HOME/.claude/.credentials.json" "$HOME/.claude/.credentials.json"
}

process_birth_fingerprint() {
	process_pid=$1
	LC_ALL=C ps -p "$process_pid" -o lstart= 2>/dev/null |
		sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

process_command_matches_pid() {
	process_pid=$1
	process_command=$(ps -p "$process_pid" -o command= 2>/dev/null) || return 1
	padded_command=" $process_command "
	case "$padded_command" in
		*" $HAL_BIN sandboxd "*) ;;
		*) return 1 ;;
	esac
	case "$padded_command" in
		*" --socket $SOCKET "*) return 0 ;;
	esac
	return 1
}

process_is_zombie() {
	process_pid=$1
	process_state=$(ps -p "$process_pid" -o stat= 2>/dev/null) || return 1
	case "$process_state" in
		*Z*) return 0 ;;
	esac
	return 1
}

process_identity_matches() {
	process_pid=$1
	expected_birth=$2
	process_birth_matches "$process_pid" "$expected_birth" || return 1
	process_command_matches_pid "$process_pid"
}

process_birth_matches() {
	process_pid=$1
	expected_birth=$2
	[ -n "$expected_birth" ] || return 1
	kill -0 "$process_pid" 2>/dev/null || return 1
	process_is_zombie "$process_pid" && return 1
	current_birth=$(process_birth_fingerprint "$process_pid")
	[ -n "$current_birth" ] && [ "$current_birth" = "$expected_birth" ]
}

read_lifecycle_lock_pid() {
	[ -f "$LIFECYCLE_LOCK_OWNER" ] || return 1
	lock_pid_value=$(sed -n 's/^pid=//p' "$LIFECYCLE_LOCK_OWNER" 2>/dev/null) || return 1
	case "$lock_pid_value" in
		''|*[!0-9]*) return 1 ;;
	esac
	[ "$lock_pid_value" -gt 1 ] || return 1
	printf '%s\n' "$lock_pid_value"
}

read_lifecycle_lock_birth() {
	[ -f "$LIFECYCLE_LOCK_OWNER" ] || return 1
	lock_birth_value=$(sed -n 's/^birth=//p' "$LIFECYCLE_LOCK_OWNER" 2>/dev/null) || return 1
	[ -n "$lock_birth_value" ] || return 1
	printf '%s\n' "$lock_birth_value"
}

lifecycle_lock_owner_valid() {
	read_lifecycle_lock_pid >/dev/null && read_lifecycle_lock_birth >/dev/null
}

lifecycle_lock_owner_alive() {
	lock_pid_value=$(read_lifecycle_lock_pid) || return 1
	lock_birth_value=$(read_lifecycle_lock_birth) || return 1
	process_birth_matches "$lock_pid_value" "$lock_birth_value"
}

remove_stale_lifecycle_lock() (
	allow_incomplete_owner=$1
	if ! mkdir "$LIFECYCLE_REAPER_DIR" 2>/dev/null; then
		return 1
	fi
	trap 'rm -rf "$LIFECYCLE_REAPER_DIR"' 0
	if lifecycle_lock_owner_alive; then
		return 1
	fi
	if lifecycle_lock_owner_valid; then
		rm -rf "$LIFECYCLE_LOCK_DIR"
		return
	fi
	if [ "$allow_incomplete_owner" != 1 ]; then
		return 1
	fi
	# A creator writes the owner immediately after mkdir; give that write a final grace.
	sleep 0.1
	if lifecycle_lock_owner_alive; then
		return 1
	fi
	rm -rf "$LIFECYCLE_LOCK_DIR"
)

acquire_lifecycle_lock() {
	lifecycle_lock_birth=$(process_birth_fingerprint "$$")
	if [ -z "$lifecycle_lock_birth" ]; then
		echo "could not fingerprint the lab lifecycle process" >&2
		return 1
	fi
	mkdir -p "$(dirname "$LIFECYCLE_LOCK_DIR")"
	i=0
	incomplete_lock_checks=0
	while ! mkdir "$LIFECYCLE_LOCK_DIR" 2>/dev/null; do
		if [ "$i" -ge 120 ]; then
			echo "timed out waiting for lab lifecycle lock: $LIFECYCLE_LOCK_DIR" >&2
			return 1
		fi
		if lifecycle_lock_owner_alive; then
			incomplete_lock_checks=0
		elif lifecycle_lock_owner_valid; then
			remove_stale_lifecycle_lock 0 || true
		else
			incomplete_lock_checks=$((incomplete_lock_checks + 1))
			if [ "$incomplete_lock_checks" -ge 8 ]; then
				remove_stale_lifecycle_lock 1 || true
				incomplete_lock_checks=0
			fi
		fi
		i=$((i + 1))
		sleep 0.25
	done
	lifecycle_lock_held=1
	trap 'release_lifecycle_lock' 0
	trap 'exit 129' HUP
	trap 'exit 130' INT
	trap 'exit 143' TERM
	{
		printf 'pid=%s\n' "$$"
		printf 'birth=%s\n' "$lifecycle_lock_birth"
	} >"$LIFECYCLE_LOCK_OWNER.tmp"
	chmod 0600 "$LIFECYCLE_LOCK_OWNER.tmp"
	mv -f "$LIFECYCLE_LOCK_OWNER.tmp" "$LIFECYCLE_LOCK_OWNER"
}

release_lifecycle_lock() {
	if [ "${lifecycle_lock_held:-}" != 1 ]; then
		return
	fi
	lock_pid=$(sed -n 's/^pid=//p' "$LIFECYCLE_LOCK_OWNER" 2>/dev/null || true)
	lock_birth=$(sed -n 's/^birth=//p' "$LIFECYCLE_LOCK_OWNER" 2>/dev/null || true)
	if { [ -z "$lock_pid" ] && [ -z "$lock_birth" ]; } ||
		{ [ "$lock_pid" = "$$" ] && [ "$lock_birth" = "$lifecycle_lock_birth" ]; }; then
		rm -rf "$LIFECYCLE_LOCK_DIR"
	fi
	lifecycle_lock_held=
}

read_daemon_pid() {
	[ -f "$PID_FILE" ] || return 1
	daemon_pid_value=$(sed -n 's/^pid=//p' "$PID_FILE" 2>/dev/null) || return 1
	case "$daemon_pid_value" in
		''|*[!0-9]*) return 1 ;;
	esac
	[ "$daemon_pid_value" -gt 1 ] || return 1
	printf '%s\n' "$daemon_pid_value"
}

read_legacy_daemon_pid() {
	[ -f "$PID_FILE" ] || return 1
	legacy_daemon_pid=$(cat "$PID_FILE" 2>/dev/null) || return 1
	case "$legacy_daemon_pid" in
		''|*[!0-9]*) return 1 ;;
	esac
	[ "$legacy_daemon_pid" -gt 1 ] || return 1
	printf '%s\n' "$legacy_daemon_pid"
}

read_daemon_birth() {
	[ -f "$PID_FILE" ] || return 1
	daemon_birth_value=$(sed -n 's/^birth=//p' "$PID_FILE" 2>/dev/null) || return 1
	[ -n "$daemon_birth_value" ] || return 1
	printf '%s\n' "$daemon_birth_value"
}

write_daemon_record() {
	daemon_pid_value=$1
	daemon_birth_value=$2
	daemon_record_tmp="$PID_FILE.tmp.$$"
	{
		printf 'pid=%s\n' "$daemon_pid_value"
		printf 'birth=%s\n' "$daemon_birth_value"
	} >"$daemon_record_tmp" || return 1
	chmod 0600 "$daemon_record_tmp" || {
		rm -f "$daemon_record_tmp"
		return 1
	}
	mv -f "$daemon_record_tmp" "$PID_FILE"
}

adopt_legacy_daemon_record() {
	legacy_daemon_pid=$(read_legacy_daemon_pid) || return 1
	if ! process_command_matches_pid "$legacy_daemon_pid"; then
		return 1
	fi
	legacy_daemon_birth=$(process_birth_fingerprint "$legacy_daemon_pid")
	if [ -z "$legacy_daemon_birth" ]; then
		echo "matching legacy sandboxd PID could not be fingerprinted safely" >&2
		return 2
	fi
	if ! process_identity_matches "$legacy_daemon_pid" "$legacy_daemon_birth"; then
		return 1
	fi
	if write_daemon_record "$legacy_daemon_pid" "$legacy_daemon_birth"; then
		return 0
	fi
	terminate_process_identity "$legacy_daemon_pid" "$legacy_daemon_birth"
	return 1
}

daemon_record_matches_pid() {
	expected_pid=$1
	recorded_pid=$(read_daemon_pid) || return 1
	[ "$recorded_pid" = "$expected_pid" ] || return 1
	recorded_birth=$(read_daemon_birth) || return 1
	process_identity_matches "$recorded_pid" "$recorded_birth"
}

daemon_running() {
	daemon_pid_value=$(read_daemon_pid) || return 1
	daemon_record_matches_pid "$daemon_pid_value"
}

worker_rpc_ready() {
	"$HAL_BIN" sandbox host delete "$WORKER_ID" >/dev/null 2>&1 || true
	"$HAL_BIN" sandbox host register worker "$WORKER_ID" --socket "$SOCKET" --live >/dev/null 2>&1
}

wait_for_worker_rpc() {
	i=0
	while [ "$i" -lt 60 ]; do
		daemon_pid_value=$(read_daemon_pid) || {
			echo "sandboxd PID record disappeared before readiness; see $LOG_FILE" >&2
			return 1
		}
		if ! daemon_record_matches_pid "$daemon_pid_value"; then
			echo "sandboxd exited before becoming ready; see $LOG_FILE" >&2
			return 1
		fi
		if worker_rpc_ready; then
			return 0
		fi
		i=$((i + 1))
		sleep 0.5
	done
	echo "timed out waiting for sandboxd worker RPC; see $LOG_FILE" >&2
	return 1
}

terminate_process_identity() {
	process_pid=$1
	process_birth=$2
	if ! process_identity_matches "$process_pid" "$process_birth"; then
		return
	fi
	kill "$process_pid" 2>/dev/null || true
	i=0
	while process_identity_matches "$process_pid" "$process_birth" && [ "$i" -lt 20 ]; do
		i=$((i + 1))
		sleep 0.25
	done
	if process_identity_matches "$process_pid" "$process_birth"; then
		kill -9 "$process_pid" 2>/dev/null || true
	fi
}

terminate_process_birth_identity() {
	process_pid=$1
	process_birth=$2
	if ! process_birth_matches "$process_pid" "$process_birth"; then
		return
	fi
	kill "$process_pid" 2>/dev/null || true
	i=0
	while process_birth_matches "$process_pid" "$process_birth" && [ "$i" -lt 20 ]; do
		i=$((i + 1))
		sleep 0.25
	done
	if process_birth_matches "$process_pid" "$process_birth"; then
		kill -9 "$process_pid" 2>/dev/null || true
	fi
}

stop_daemon() {
	daemon_pid_value=$(read_daemon_pid 2>/dev/null || true)
	daemon_birth_value=$(read_daemon_birth 2>/dev/null || true)
	if [ -n "$daemon_pid_value" ] && [ -n "$daemon_birth_value" ]; then
		if daemon_record_matches_pid "$daemon_pid_value"; then
			terminate_process_identity "$daemon_pid_value" "$daemon_birth_value"
		fi
	fi
	rm -f "$PID_FILE" "$SOCKET"
}

remove_stale_daemon_state() {
	if daemon_running; then
		return
	fi
	rm -f "$PID_FILE" "$SOCKET"
}

capture_launched_daemon_birth() {
	launched_daemon_pid=$1
	i=0
	while [ "$i" -lt 20 ]; do
		if ! kill -0 "$launched_daemon_pid" 2>/dev/null; then
			return 1
		fi
		launched_daemon_birth=$(process_birth_fingerprint "$launched_daemon_pid")
		if [ -n "$launched_daemon_birth" ] && process_birth_matches "$launched_daemon_pid" "$launched_daemon_birth"; then
			printf '%s\n' "$launched_daemon_birth"
			return
		fi
		i=$((i + 1))
		sleep 0.05
	done
	return 1
}

record_launched_daemon() {
	launched_daemon_pid=$1
	launched_daemon_birth=$2
	i=0
	while [ "$i" -lt 20 ]; do
		if ! process_birth_matches "$launched_daemon_pid" "$launched_daemon_birth"; then
			return 1
		fi
		if process_command_matches_pid "$launched_daemon_pid"; then
			write_daemon_record "$launched_daemon_pid" "$launched_daemon_birth"
			return
		fi
		i=$((i + 1))
		sleep 0.05
	done
	return 1
}

ensure_machine_ready() {
	if ! podman machine inspect "$MACHINE" >/dev/null 2>&1; then
		echo "Podman machine is missing; run prepare first" >&2
		exit 1
	fi
	if lab_podman info >/dev/null 2>&1; then
		return
	fi
	podman machine start "$MACHINE" >/dev/null 2>&1 || true
	i=0
	until lab_podman info >/dev/null 2>&1; do
		if [ "$i" -ge 30 ]; then
			echo "Podman machine started but its named connection did not become ready" >&2
			exit 1
		fi
		i=$((i + 1))
		sleep 1
	done
}

prepare() {
	require_command go
	require_command podman
	ensure_dirs

	if ! podman machine inspect "$MACHINE" >/dev/null 2>&1; then
		if [ -n "$MACHINE_PROVIDER" ]; then
			with_host_proxy podman machine init --provider "$MACHINE_PROVIDER" --cpus 4 --memory 4096 --disk-size 30 "$MACHINE"
		else
			with_host_proxy podman machine init --cpus 4 --memory 4096 --disk-size 30 "$MACHINE"
		fi
	fi
	ensure_machine_ready
	prefetch_base_image

	(
		cd "$REPO_ROOT"
		go build -o "$HAL_BIN" .
		with_guest_proxy podman --connection "$MACHINE" build --pull=never --retry 5 --retry-delay 5s -f sandbox/Dockerfile -t "$IMAGE" .
	)
	cat >"$LAB_ROOT/manifest.txt" <<EOF
lab_root=$LAB_ROOT
machine=$MACHINE
machine_provider=$MACHINE_PROVIDER
worker_id=$WORKER_ID
image=$IMAGE
base_image=$BASE_IMAGE
socket=$SOCKET
hal=$HAL_BIN
EOF
	echo "Lab prepared at $LAB_ROOT"
}

start() {
	require_command podman
	require_command nohup
	require_command ps
	acquire_lifecycle_lock
	ensure_dirs
	if [ ! -x "$HAL_BIN" ]; then
		echo "lab Hal binary is missing; run prepare first" >&2
		exit 1
	fi
	ensure_machine_ready
	if ! lab_podman image exists "$IMAGE"; then
		echo "lab image is missing; run prepare first" >&2
		exit 1
	fi
	legacy_adoption_status=0
	adopt_legacy_daemon_record || legacy_adoption_status=$?
	if [ "$legacy_adoption_status" -eq 2 ]; then
		return 1
	fi
	if daemon_running; then
		if worker_rpc_ready; then
			echo "sandboxd is running with PID $(read_daemon_pid)"
			return
		fi
		echo "sandboxd is not responding to worker RPC; restarting it" >&2
		stop_daemon
	else
		remove_stale_daemon_state
	fi

	nohup "$HAL_BIN" sandboxd \
		--socket "$SOCKET" \
		--worker-id "$WORKER_ID" \
		--driver rootless_podman \
		--image "$IMAGE" \
		</dev/null >>"$LOG_FILE" 2>&1 &
	daemon_pid_value=$!
	if ! launched_daemon_birth=$(capture_launched_daemon_birth "$daemon_pid_value"); then
		# The unreaped background job still owns this PID, so it cannot be reused.
		kill "$daemon_pid_value" 2>/dev/null || true
		wait "$daemon_pid_value" 2>/dev/null || true
		rm -f "$PID_FILE" "$SOCKET"
		echo "sandboxd exited before its process birth could be captured; see $LOG_FILE" >&2
		return 1
	fi
	if ! record_launched_daemon "$daemon_pid_value" "$launched_daemon_birth"; then
		terminate_process_birth_identity "$daemon_pid_value" "$launched_daemon_birth"
		wait "$daemon_pid_value" 2>/dev/null || true
		rm -f "$PID_FILE" "$SOCKET"
		echo "sandboxd did not establish a verifiable process identity; see $LOG_FILE" >&2
		return 1
	fi
	if ! wait_for_worker_rpc; then
		terminate_process_birth_identity "$daemon_pid_value" "$launched_daemon_birth"
		wait "$daemon_pid_value" 2>/dev/null || true
		rm -f "$PID_FILE" "$SOCKET"
		return 1
	fi
	echo "sandboxd is running with PID $(read_daemon_pid)"
}

clone_repo() {
	if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
		usage >&2
		exit 2
	fi
	require_command git
	ensure_dirs
	source_repo=$1
	name=${2:-$(basename "${source_repo%.git}")}
	destination="$LAB_ROOT/workspaces/$name"
	if [ -e "$destination" ]; then
		echo "workspace already exists: $destination" >&2
		exit 1
	fi
	git clone --no-hardlinks "$source_repo" "$destination"
	echo "$destination"
}

run_command() {
	if [ "$#" -lt 2 ] || [ "$1" != "--" ]; then
		usage >&2
		exit 2
	fi
	shift
	ensure_dirs
	exec "$@"
}

status() {
	require_command podman
	require_command ps
	ensure_dirs
	echo "Lab root: $LAB_ROOT"
	if podman machine inspect "$MACHINE"; then
		if lab_podman info >/dev/null 2>&1; then
			echo "Podman connection: $MACHINE (ready)"
		else
			echo "Podman connection: $MACHINE (unavailable)"
		fi
	else
		echo "Podman machine: $MACHINE (missing)"
	fi
	if daemon_running && [ -x "$HAL_BIN" ] && "$HAL_BIN" sandbox host status "$WORKER_ID" --live >/dev/null 2>&1; then
		echo "sandboxd: running (PID $(read_daemon_pid), worker RPC ready)"
	elif daemon_running; then
		echo "sandboxd: process verified but worker RPC unavailable (PID $(read_daemon_pid))"
	else
		echo "sandboxd: stopped"
	fi
	if [ -x "$HAL_BIN" ]; then
		"$HAL_BIN" sandbox host status "$WORKER_ID" --live || true
		"$HAL_BIN" sandbox list || true
	fi
}

print_env() {
	printf "export HAL_SANDBOX_LAB_ROOT='%s'\n" "$LAB_ROOT"
	printf "export HAL_CONFIG_HOME='%s'\n" "$HAL_CONFIG_HOME"
	printf "export XDG_CONFIG_HOME='%s'\n" "$XDG_CONFIG_HOME"
	printf "export XDG_DATA_HOME='%s'\n" "$XDG_DATA_HOME"
	printf "export XDG_CACHE_HOME='%s'\n" "$XDG_CACHE_HOME"
	printf "export TMPDIR='%s'\n" "$TMPDIR"
	printf "export HOME='%s'\n" "$HOME"
	printf "export PATH='%s':\"\$PATH\"\n" "$LAB_ROOT/bin"
}

destroy() {
	require_command ps
	acquire_lifecycle_lock
	ensure_dirs
	if [ -x "$HAL_BIN" ] && daemon_running; then
		"$HAL_BIN" sandbox delete --all --yes >/dev/null 2>&1 || true
		"$HAL_BIN" sandbox host delete "$WORKER_ID" >/dev/null 2>&1 || true
	fi
	stop_daemon
	if command -v podman >/dev/null 2>&1; then
		if lab_podman info >/dev/null 2>&1; then
			lab_podman rm -af --filter label=dev.jywlabs.hal.runtime=rootless_podman >/dev/null 2>&1 || true
		fi
		podman machine stop "$MACHINE" >/dev/null 2>&1 || true
		podman machine rm -f "$MACHINE" >/dev/null 2>&1 || true
	fi
	# Go module caches are intentionally read-only. The lab root has already
	# passed the absolute-path and leaf-name safety checks above.
	chmod -R u+w "$LAB_ROOT" 2>/dev/null || true
	rm -rf "$LAB_ROOT"
	if [ -e "$LAB_ROOT" ]; then
		echo "failed to remove lab root: $LAB_ROOT" >&2
		exit 1
	fi
	echo "Destroyed lab $LAB_ROOT"
}

command=${1:-}
if [ -z "$command" ]; then
	usage
	exit 2
fi
shift

case "$command" in
	prepare) prepare "$@" ;;
	start) start "$@" ;;
	seed-auth) seed_auth "$@" ;;
	clone) clone_repo "$@" ;;
	run) run_command "$@" ;;
	status) status "$@" ;;
	env) print_env "$@" ;;
	destroy) destroy "$@" ;;
	-h|--help|help) usage ;;
	*)
		echo "unknown command: $command" >&2
		usage >&2
		exit 2
		;;
esac
