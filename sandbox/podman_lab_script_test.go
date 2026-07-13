package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestPodmanLabStartDetachesDaemonAndUsesLiveReadiness(t *testing.T) {
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	scriptPath := filepath.Join(filepath.Dir(sourcePath), "podman-lab.sh")
	data, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", scriptPath, err)
	}
	script := string(data)
	for _, want := range []string{
		`nohup "$HAL_BIN" sandboxd`,
		`</dev/null`,
		`>>"$LOG_FILE"`,
		`-o lstart=`,
		`mkdir "$LIFECYCLE_LOCK_DIR"`,
		`remove_stale_lifecycle_lock`,
		`"$HAL_BIN" sandbox host register worker "$WORKER_ID" --socket "$SOCKET" --live`,
		`"$HAL_BIN" sandbox host status "$WORKER_ID" --live`,
	} {
		if !strings.Contains(script, want) {
			t.Errorf("podman-lab.sh missing lifecycle contract %q", want)
		}
	}
	if strings.Contains(script, "wait_for_socket()") {
		t.Error("podman-lab.sh must verify worker RPC readiness instead of socket existence alone")
	}
}

func TestPodmanLabPrepareUsesNamedConnectionWhenDefaultIsHealthy(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	writePodmanLabGoStub(t, env.binDir)

	runPodmanLabScript(t, env, "prepare")

	log := readPodmanLabLog(t, env.logPath)
	for _, want := range []string{
		"machine inspect lab-machine",
		"machine start lab-machine",
		"--connection lab-machine info",
		"--connection lab-machine pull example.invalid/base:latest",
		"--connection lab-machine build --pull=never",
	} {
		if !strings.Contains(log, want) {
			t.Fatalf("podman log missing %q:\n%s", want, log)
		}
	}
	assertNoUnboundPodmanOperation(t, log, "info", "pull", "build")
}

func TestPodmanLabDestroyRemovesContainersOnlyOnNamedConnection(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	if err := os.MkdirAll(env.labRoot, 0o700); err != nil {
		t.Fatalf("MkdirAll(lab root) error = %v", err)
	}
	if err := os.WriteFile(env.statePath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("WriteFile(machine state) error = %v", err)
	}

	runPodmanLabScript(t, env, "destroy")

	log := readPodmanLabLog(t, env.logPath)
	if !strings.Contains(log, "--connection lab-machine rm -af --filter label=dev.jywlabs.hal.runtime=rootless_podman") {
		t.Fatalf("podman log missing connection-bound container removal:\n%s", log)
	}
	assertNoUnboundPodmanOperation(t, log, "rm")
	if !strings.Contains(log, "machine stop lab-machine") || !strings.Contains(log, "machine rm -f lab-machine") {
		t.Fatalf("podman log missing named machine cleanup:\n%s", log)
	}
}

type podmanLabTestEnv struct {
	scriptPath    string
	binDir        string
	labRoot       string
	hostHome      string
	logPath       string
	statePath     string
	halLogPath    string
	halPIDPath    string
	halReady      string
	halStartDelay string
}

func newPodmanLabTestEnv(t *testing.T) podmanLabTestEnv {
	t.Helper()
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller() failed")
	}
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(fake bin) error = %v", err)
	}
	env := podmanLabTestEnv{
		scriptPath:    filepath.Join(filepath.Dir(sourcePath), "podman-lab.sh"),
		binDir:        binDir,
		labRoot:       filepath.Join(root, "hal-sandbox-binding"),
		hostHome:      filepath.Join(root, "host-home"),
		logPath:       filepath.Join(root, "podman.log"),
		statePath:     filepath.Join(root, "machine-ready"),
		halLogPath:    filepath.Join(root, "hal.log"),
		halPIDPath:    filepath.Join(root, "hal-daemon.pid"),
		halReady:      filepath.Join(root, "hal-daemon.ready"),
		halStartDelay: "0",
	}
	if err := os.MkdirAll(env.hostHome, 0o700); err != nil {
		t.Fatalf("MkdirAll(host home) error = %v", err)
	}
	writePodmanLabExecutable(t, filepath.Join(binDir, "podman"), `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$PODMAN_TEST_LOG"

if [ "${1:-}" = "--connection" ]; then
	[ "${2:-}" = "$PODMAN_TEST_MACHINE" ] || exit 91
	shift 2
	case "${1:-}" in
		info) [ -f "$PODMAN_TEST_STATE" ] ;;
		pull|build|image|rm) exit 0 ;;
		*) exit 0 ;;
	esac
fi

if [ "${1:-}" = "machine" ]; then
	case "${2:-}" in
		inspect) exit 0 ;;
		start) : > "$PODMAN_TEST_STATE"; exit 0 ;;
		stop|rm|init|ssh|list) exit 0 ;;
	esac
fi

case "${1:-}" in
	info|pull|build|image|rm) exit 0 ;;
esac
exit 0
`)
	return env
}

func writePodmanLabHalStub(t *testing.T, env podmanLabTestEnv) {
	t.Helper()
	path := filepath.Join(env.labRoot, "bin", "hal")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(fake Hal bin) error = %v", err)
	}
	writePodmanLabExecutable(t, path, `#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$HAL_TEST_LOG"

if [ "${1:-}" = "sandboxd" ]; then
	printf '%s\n' "$$" > "$HAL_TEST_DAEMON_PID"
	sleep "$HAL_TEST_START_DELAY"
	: > "$HAL_TEST_DAEMON_READY"
	trap 'rm -f "$HAL_TEST_DAEMON_READY"; exit 0' HUP INT TERM
	while :; do
		sleep 1
	done
fi

if [ "${1:-}" = "sandbox" ] && [ "${2:-}" = "host" ] && [ "${3:-}" = "register" ]; then
	[ -f "$HAL_TEST_DAEMON_READY" ] || exit 1
	pid=$(cat "$HAL_TEST_DAEMON_PID")
	kill -0 "$pid" 2>/dev/null
	exit 0
fi

if [ "${1:-}" = "sandbox" ] && [ "${2:-}" = "host" ] && [ "${3:-}" = "status" ]; then
	[ -f "$HAL_TEST_DAEMON_READY" ] || exit 1
	pid=$(cat "$HAL_TEST_DAEMON_PID")
	kill -0 "$pid" 2>/dev/null
	exit 0
fi

exit 0
`)
}

func writePodmanLabGoStub(t *testing.T, binDir string) {
	t.Helper()
	writePodmanLabExecutable(t, filepath.Join(binDir, "go"), `#!/bin/sh
set -eu
output=
while [ "$#" -gt 0 ]; do
	if [ "$1" = "-o" ]; then
		shift
		output=$1
		break
	fi
	shift
done
[ -n "$output" ] || exit 1
mkdir -p "$(dirname "$output")"
: > "$output"
chmod 0700 "$output"
`)
}

func writePodmanLabExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o700); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func runPodmanLabScript(t *testing.T, env podmanLabTestEnv, command string) {
	t.Helper()
	_ = runPodmanLabScriptOutput(t, env, command)
}

func runPodmanLabScriptOutput(t *testing.T, env podmanLabTestEnv, command string) string {
	t.Helper()
	cmd := newPodmanLabCommand(env, command)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("podman-lab.sh %s error = %v; output = %s", command, err, output)
	}
	return string(output)
}

func newPodmanLabCommand(env podmanLabTestEnv, command string) *exec.Cmd {
	cmd := exec.Command("sh", env.scriptPath, command)
	cmd.Env = append(os.Environ(),
		"HOME="+env.hostHome,
		"PATH="+env.binDir+":"+os.Getenv("PATH"),
		"HAL_SANDBOX_LAB_ROOT="+env.labRoot,
		"HAL_SANDBOX_LAB_MACHINE=lab-machine",
		"HAL_SANDBOX_LAB_MACHINE_PROVIDER=",
		"HAL_SANDBOX_LAB_BASE_IMAGE=example.invalid/base:latest",
		"PODMAN_TEST_LOG="+env.logPath,
		"PODMAN_TEST_MACHINE=lab-machine",
		"PODMAN_TEST_STATE="+env.statePath,
		"HAL_TEST_LOG="+env.halLogPath,
		"HAL_TEST_DAEMON_PID="+env.halPIDPath,
		"HAL_TEST_DAEMON_READY="+env.halReady,
		"HAL_TEST_START_DELAY="+env.halStartDelay,
	)
	return cmd
}

func readPodmanLabPID(t *testing.T, env podmanLabTestEnv) int {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(env.labRoot, "run", "sandboxd.pid"))
	if err != nil {
		t.Fatalf("ReadFile(sandboxd.pid) error = %v", err)
	}
	pid, err := parsePodmanLabPID(data)
	if err != nil {
		t.Fatalf("invalid sandboxd PID %q: %v", data, err)
	}
	return pid
}

func parsePodmanLabPID(data []byte) (int, error) {
	value := strings.TrimSpace(string(data))
	for _, line := range strings.Split(value, "\n") {
		if strings.HasPrefix(line, "pid=") {
			value = strings.TrimPrefix(line, "pid=")
			break
		}
	}
	return strconv.Atoi(value)
}

func readPodmanLabLog(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(podman log) error = %v", err)
	}
	return string(data)
}

func assertNoUnboundPodmanOperation(t *testing.T, log string, operations ...string) {
	t.Helper()
	for _, line := range strings.Split(strings.TrimSpace(log), "\n") {
		for _, operation := range operations {
			if line == operation || strings.HasPrefix(line, operation+" ") {
				t.Fatalf("unbound podman %s operation: %q\n%s", operation, line, log)
			}
		}
	}
}
