package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
	scriptPath string
	binDir     string
	labRoot    string
	hostHome   string
	logPath    string
	statePath  string
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
		scriptPath: filepath.Join(filepath.Dir(sourcePath), "podman-lab.sh"),
		binDir:     binDir,
		labRoot:    filepath.Join(root, "hal-sandbox-binding"),
		hostHome:   filepath.Join(root, "host-home"),
		logPath:    filepath.Join(root, "podman.log"),
		statePath:  filepath.Join(root, "machine-ready"),
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
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("podman-lab.sh %s error = %v; output = %s", command, err, output)
	}
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
