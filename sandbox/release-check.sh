#!/bin/sh

set -eu
REPO_ROOT=$(
	unset CDPATH
	cd -- "$(dirname -- "$0")/.."
	pwd
)
cd "$REPO_ROOT"
with_engine=0
case "${1:-}" in
	'') [ "$#" -eq 0 ] ;;
	--with-engine) [ "$#" -eq 1 ]; with_engine=1 ;;
	-h|--help)
		echo 'Usage: sandbox/release-check.sh [--with-engine]'
		exit 0 ;;
	*) echo 'Usage: sandbox/release-check.sh [--with-engine]' >&2; exit 2 ;;
esac

# This gate owns the lab for its entire run. Never share it with another run.
export HAL_SANDBOX_LAB_PODMAN_MODE=native
LAB=./sandbox/podman-lab.sh
logs=$(mktemp -d "$REPO_ROOT/.sandbox-release.XXXXXX")
cleanup() {
	result=$?
	trap - 0
	if ! "$LAB" destroy >"$logs/destroy.log" 2>&1; then
		echo 'FAIL: lab destroy' >&2
		result=1
	else
		echo 'PASS: lab destroy'
	fi
	rm -rf "$logs"
	exit "$result"
}
trap cleanup 0
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

command -v jq >/dev/null 2>&1 || { echo 'jq is required' >&2; exit 1; }
[ "$(uname -s)" = Linux ] && [ "$(id -u)" != 0 ] || {
	echo 'Native release acceptance requires non-root Linux' >&2
	exit 1
}

check() {
	label=$1
	shift
	if ! "$@" >"$logs/check.log" 2>&1; then
		echo "FAIL: $label" >&2
		exit 1
	fi
	echo "PASS: $label"
}
check 'go test -count=1 -json ./...' go test -count=1 -json ./...
jq -sr '
	"Default tests: pass=\([.[] | select(.Action == "pass" and .Test != null)] | length) fail=\([.[] | select(.Action == "fail" and .Test != null)] | length) skip=\([.[] | select(.Action == "skip" and .Test != null)] | length)"
' "$logs/check.log"
check 'go vet ./...' go vet ./...
check 'make docs-check' make docs-check
check 'make build' make build
check 'gofmt' sh -c 'set -e; git ls-files -z "*.go" > "$1/files"; xargs -0 gofmt -l < "$1/files" > "$1/gofmt.txt"; test ! -s "$1/gofmt.txt"' sh "$logs"
check 'git diff --check' git diff --check
check 'darwin/arm64 compile' env CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build ./...
check 'windows/amd64 compile' env CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./...
if command -v golangci-lint >/dev/null 2>&1; then
	check 'golangci-lint' golangci-lint run ./...
else
	echo 'UNAVAILABLE: golangci-lint (not a passed check)'
fi

# Reuse the host Go caches, not credentials, under the isolated lab environment.
modcache=$(go env GOMODCACHE)
gocache=$(go env GOCACHE)
export HAL_PODMAN_TEST_IMAGE=${HAL_SANDBOX_LAB_IMAGE:-localhost/hal-agent:hal-lab}
check 'lab prepare' "$LAB" prepare
check 'lab start' "$LAB" start
[ "$("$LAB" run -- podman info --format '{{.Host.Security.Rootless}}')" = true ] || {
	echo 'FAIL: lab Podman is not rootless' >&2
	exit 1
}
echo 'PASS: native rootless Podman'
printf 'Image ID: '
"$LAB" run -- podman image inspect "$HAL_PODMAN_TEST_IMAGE" --format '{{.Id}}'

# Never pipe go test into a parser: retain both the process status and JSON status.
# Require a real passing test in every selected family, not just package success.
native_check() {
	label=$1
	required=$2
	shift 2
	status=0
	"$LAB" run -- env GOMODCACHE="$modcache" GOCACHE="$gocache" \
		sh -c '
			export HAL_WORKER_INTEGRATION_ENDPOINT="unix://$(dirname "$HOME")/run/sandboxd.sock"
			export HAL_WORKER_INTEGRATION_HOST_NAME=${HAL_SANDBOX_LAB_WORKER_ID:-hal-lab-worker}
			export HAL_WORKER_INTEGRATION_RUNTIME_DRIVER=rootless_podman
			export HAL_WORKER_INTEGRATION_IMAGE=$HAL_PODMAN_TEST_IMAGE
			exec "$@"
		' sh "$@" >"$logs/native.json" 2>"$logs/native.stderr" || status=$?
	jq -sr --arg label "$label" '
		"\($label): tests=\([.[] | select(.Action == "pass" and .Test != null)] | length) failure_actions=\([.[] | select(.Action == "fail")] | length) skip_actions=\([.[] | select(.Action == "skip")] | length)"
	' "$logs/native.json" || { echo "FAIL: $label JSON" >&2; exit 1; }
	if ! jq -se --arg required "$required" '
		. as $events |
		all(.[]; .Action != "skip" and .Action != "fail") and
		($required | split(",") | all(.[]; . as $name |
			any($events[]; .Action == "pass" and ((.Test // "") | test($name)))))
	' "$logs/native.json" >/dev/null || [ "$status" -ne 0 ]; then
		echo "FAIL: $label (failure, skip, malformed JSON, or missing required tests)" >&2
		exit 1
	fi
	echo "PASS: $label"
}
native_check 'rootless lifecycle/jobs/recovery' \
	'^TestPodmanIntegrationLifecycleExecAndCopy$,^TestWorkerJobPodmanIntegrationSurvivesClientDisconnect$,^TestL3PreparedLinuxRecoveryE2E$' \
	go test -race -count=1 -json -tags=podman_integration,l3_recovery_e2e \
	./internal/sandboxruntime/rootlesspodman ./internal/sandboxworker ./cmd \
	-run '^(TestPodmanIntegration|TestWorkerJobPodmanIntegration|TestL3PreparedLinuxRecoveryE2E)'
native_check 'worker/factory bundles' \
	'^TestWorkerIntegrationRootlessPodmanExecutionThroughSharedResolver$,^TestFactoryRootlessBundleRealGit,^TestFactoryFinalizationRecoveryRealGit$,^TestFactoryFinalizationRecoveryWorkerRoundTrip$' \
	go test -race -count=1 -json -tags=worker_integration,integration ./cmd \
	-run '^(TestWorkerIntegrationRootlessPodmanExecutionThroughSharedResolver|TestFactoryRootlessBundleRealGit|TestFactoryFinalizationRecovery)'

if [ "$with_engine" -eq 1 ]; then
	# Operator supplies a disposable fixture smoke, never an implicit token spend.
	# The documented run/rerun/apply/failure assertions must all exit successfully.
	[ -n "${HAL_SANDBOX_RELEASE_ENGINE_SMOKE:-}" ] && [ -x "$HAL_SANDBOX_RELEASE_ENGINE_SMOKE" ] || {
		echo '--with-engine requires HAL_SANDBOX_RELEASE_ENGINE_SMOKE (see release doc)' >&2
		exit 1
	}
	check 'lab seed-auth (explicit token-spending mode)' "$LAB" seed-auth
	check 'engine run/rerun/apply/failure smoke' "$LAB" run -- "$HAL_SANDBOX_RELEASE_ENGINE_SMOKE"
else
	echo 'NOT SELECTED: token-spending engine smoke (--with-engine)'
fi
echo 'PASS: Sandbox v2.0 rootless release gate'
