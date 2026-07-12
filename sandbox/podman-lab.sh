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

export HAL_CONFIG_HOME="$LAB_ROOT/config/hal"
export XDG_CONFIG_HOME="$LAB_ROOT/config"
export XDG_DATA_HOME="$LAB_ROOT/data"
export XDG_CACHE_HOME="$LAB_ROOT/cache"
export TMPDIR="$LAB_ROOT/tmp"
export HOME="$LAB_ROOT/home"
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
		podman pull "$BASE_IMAGE"
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

daemon_running() {
	[ -f "$PID_FILE" ] || return 1
	pid=$(cat "$PID_FILE")
	[ -n "$pid" ] && kill -0 "$pid" 2>/dev/null
}

wait_for_socket() {
	i=0
	while [ "$i" -lt 60 ]; do
		if [ -S "$SOCKET" ]; then
			return 0
		fi
		if ! daemon_running; then
			echo "sandboxd exited before creating its socket; see $LOG_FILE" >&2
			return 1
		fi
		i=$((i + 1))
		sleep 0.5
	done
	echo "timed out waiting for sandboxd socket; see $LOG_FILE" >&2
	return 1
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
	if ! podman info >/dev/null 2>&1; then
		podman machine start "$MACHINE" >/dev/null
	fi
	i=0
	until podman info >/dev/null 2>&1; do
		if [ "$i" -ge 30 ]; then
			echo "Podman machine started but its API did not become ready" >&2
			exit 1
		fi
		i=$((i + 1))
		sleep 1
	done
	prefetch_base_image

	(
		cd "$REPO_ROOT"
		go build -o "$HAL_BIN" .
		with_guest_proxy podman build --pull=never --retry 5 --retry-delay 5s -f sandbox/Dockerfile -t "$IMAGE" .
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
	ensure_dirs
	if [ ! -x "$HAL_BIN" ]; then
		echo "lab Hal binary is missing; run prepare first" >&2
		exit 1
	fi
	if ! podman image exists "$IMAGE"; then
		echo "lab image is missing; run prepare first" >&2
		exit 1
	fi
	if ! daemon_running; then
		rm -f "$SOCKET" "$PID_FILE"
		"$HAL_BIN" sandboxd \
			--socket "$SOCKET" \
			--worker-id "$WORKER_ID" \
			--driver rootless_podman \
			--image "$IMAGE" \
			>"$LOG_FILE" 2>&1 &
		echo $! >"$PID_FILE"
	fi
	wait_for_socket
	"$HAL_BIN" sandbox host delete "$WORKER_ID" >/dev/null 2>&1 || true
	"$HAL_BIN" sandbox host register worker "$WORKER_ID" --socket "$SOCKET" --live
	echo "sandboxd is running with PID $(cat "$PID_FILE")"
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
	ensure_dirs
	echo "Lab root: $LAB_ROOT"
	podman machine list
	if daemon_running; then
		echo "sandboxd: running (PID $(cat "$PID_FILE"))"
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
	ensure_dirs
	if [ -x "$HAL_BIN" ] && daemon_running; then
		"$HAL_BIN" sandbox delete --all --yes >/dev/null 2>&1 || true
		"$HAL_BIN" sandbox host delete "$WORKER_ID" >/dev/null 2>&1 || true
	fi
	if daemon_running; then
		pid=$(cat "$PID_FILE")
		kill "$pid" 2>/dev/null || true
		i=0
		while kill -0 "$pid" 2>/dev/null && [ "$i" -lt 20 ]; do
			i=$((i + 1))
			sleep 0.25
		done
		kill -9 "$pid" 2>/dev/null || true
	fi
	rm -f "$PID_FILE" "$SOCKET"
	if command -v podman >/dev/null 2>&1; then
		podman rm -af --filter label=dev.jywlabs.hal.runtime=rootless_podman >/dev/null 2>&1 || true
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
