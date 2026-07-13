//go:build !windows

package sandbox

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPodmanLabStartRecoversStaleLifecycleLock(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	writePodmanLabHalStub(t, env)
	if err := os.WriteFile(env.statePath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("WriteFile(machine state) error = %v", err)
	}
	lockDir := env.labRoot + ".lifecycle.lock"
	if err := os.MkdirAll(lockDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(stale lifecycle lock) error = %v", err)
	}
	owner := "pid=99999999\nbirth=Mon Jan  1 00:00:00 2001\n"
	if err := os.WriteFile(filepath.Join(lockDir, "owner"), []byte(owner), 0o600); err != nil {
		t.Fatalf("WriteFile(stale lifecycle owner) error = %v", err)
	}
	t.Cleanup(func() { stopPodmanLabDaemon(t, env) })

	runPodmanLabScript(t, env, "start")
	pid := readPodmanLabPID(t, env)
	assertProcessAlive(t, pid)
	if _, err := os.Stat(lockDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale lifecycle lock still exists after start: %v", err)
	}
}

func TestPodmanLabStartSurvivesShellExitAndIsIdempotent(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	writePodmanLabHalStub(t, env)
	if err := os.WriteFile(env.statePath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("WriteFile(machine state) error = %v", err)
	}
	t.Cleanup(func() { stopPodmanLabDaemon(t, env) })

	runPodmanLabScript(t, env, "start")
	firstPID := readPodmanLabPID(t, env)
	assertProcessAlive(t, firstPID)
	pidRecord, err := os.ReadFile(filepath.Join(env.labRoot, "run", "sandboxd.pid"))
	if err != nil {
		t.Fatalf("ReadFile(sandboxd PID record) error = %v", err)
	}
	if !strings.Contains(string(pidRecord), "pid=") || !strings.Contains(string(pidRecord), "birth=") {
		t.Fatalf("sandboxd PID record lacks PID and birth fingerprint:\n%s", pidRecord)
	}

	runPodmanLabScript(t, env, "start")
	secondPID := readPodmanLabPID(t, env)
	if secondPID != firstPID {
		t.Fatalf("second start changed daemon PID from %d to %d", firstPID, secondPID)
	}
	log := readPodmanLabLog(t, env.halLogPath)
	if got := strings.Count(log, "sandboxd --socket "); got != 1 {
		t.Fatalf("sandboxd launch count = %d, want 1:\n%s", got, log)
	}
	if got := strings.Count(log, "sandbox host register worker"); got < 2 {
		t.Fatalf("live worker readiness checks = %d, want at least 2:\n%s", got, log)
	}

	runPodmanLabScript(t, env, "destroy")
	waitForProcessExit(t, firstPID)
	if _, err := os.Stat(env.labRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lab root still exists after destroy: %v", err)
	}
}

func TestPodmanLabStartAdoptsMatchingLegacyPIDRecord(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	writePodmanLabHalStub(t, env)
	if err := os.WriteFile(env.statePath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("WriteFile(machine state) error = %v", err)
	}
	runDir := filepath.Join(env.labRoot, "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(run dir) error = %v", err)
	}
	socketPath := filepath.Join(runDir, "sandboxd.sock")
	daemon := exec.Command(filepath.Join(env.labRoot, "bin", "hal"),
		"sandboxd", "--socket", socketPath,
		"--worker-id", "hal-lab-worker",
		"--driver", "rootless_podman",
		"--image", "localhost/hal-agent:hal-lab")
	daemon.Env = append(os.Environ(),
		"HAL_TEST_LOG="+env.halLogPath,
		"HAL_TEST_DAEMON_PID="+env.halPIDPath,
		"HAL_TEST_DAEMON_READY="+env.halReady,
		"HAL_TEST_START_DELAY=0",
	)
	if err := daemon.Start(); err != nil {
		t.Fatalf("start legacy sandboxd: %v", err)
	}
	daemonDone := make(chan error, 1)
	go func() { daemonDone <- daemon.Wait() }()
	daemonWaited := false
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		if !daemonWaited {
			select {
			case <-daemonDone:
			case <-time.After(3 * time.Second):
			}
		}
		stopPodmanLabDaemon(t, env)
	})
	waitForPodmanLabFile(t, env.halReady)
	legacyPID := daemon.Process.Pid
	if err := os.WriteFile(filepath.Join(runDir, "sandboxd.pid"), []byte(strconv.Itoa(legacyPID)+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(legacy PID) error = %v", err)
	}

	runPodmanLabScript(t, env, "start")
	if got := readPodmanLabPID(t, env); got != legacyPID {
		t.Fatalf("start replaced matching legacy daemon PID %d with %d", legacyPID, got)
	}
	record, err := os.ReadFile(filepath.Join(runDir, "sandboxd.pid"))
	if err != nil {
		t.Fatalf("ReadFile(adopted PID record) error = %v", err)
	}
	if !strings.Contains(string(record), "pid=") || !strings.Contains(string(record), "birth=") {
		t.Fatalf("legacy PID was not upgraded atomically:\n%s", record)
	}
	log := readPodmanLabLog(t, env.halLogPath)
	if got := strings.Count(log, "sandboxd --socket "); got != 1 {
		t.Fatalf("matching legacy daemon launch count = %d, want 1:\n%s", got, log)
	}

	runPodmanLabScript(t, env, "destroy")
	select {
	case <-daemonDone:
		daemonWaited = true
	case <-time.After(3 * time.Second):
		t.Fatalf("adopted legacy daemon %d did not exit during destroy", legacyPID)
	}
}

func TestPodmanLabStartCleansUpCommandVerificationTimeout(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	writePodmanLabHalStub(t, env)
	writePodmanLabPSCommandMismatchStub(t, env)
	if err := os.WriteFile(env.statePath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("WriteFile(machine state) error = %v", err)
	}
	t.Cleanup(func() {
		if data, err := os.ReadFile(env.halPIDPath); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				_ = syscall.Kill(pid, syscall.SIGKILL)
			}
		}
	})

	cmd := newPodmanLabCommand(env, "start")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("start with command mismatch unexpectedly succeeded: %s", output)
	}
	launchedPID := readIntegerFile(t, env.halPIDPath)
	waitForProcessExit(t, launchedPID)
	for _, path := range []string{
		filepath.Join(env.labRoot, "run", "sandboxd.pid"),
		filepath.Join(env.labRoot, "run", "sandboxd.sock"),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("startup failure left stale state %s: %v", path, err)
		}
	}
}

func TestPodmanLabConcurrentStartsLaunchOneDaemon(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	env.halStartDelay = "0.5"
	writePodmanLabHalStub(t, env)
	if err := os.WriteFile(env.statePath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("WriteFile(machine state) error = %v", err)
	}
	t.Cleanup(func() { stopPodmanLabDaemon(t, env) })

	commands := []*exec.Cmd{
		newPodmanLabCommand(env, "start"),
		newPodmanLabCommand(env, "start"),
	}
	outputs := make([]bytes.Buffer, len(commands))
	for i, cmd := range commands {
		cmd.Stdout = &outputs[i]
		cmd.Stderr = &outputs[i]
		if err := cmd.Start(); err != nil {
			t.Fatalf("start command %d: %v", i, err)
		}
	}
	for i, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("wait command %d: %v; output = %s", i, err, outputs[i].String())
		}
	}

	pid := readPodmanLabPID(t, env)
	assertProcessAlive(t, pid)
	log := readPodmanLabLog(t, env.halLogPath)
	if got := strings.Count(log, "sandboxd --socket "); got != 1 {
		t.Fatalf("concurrent starts launched sandboxd %d times, want 1:\n%s", got, log)
	}
}

func TestPodmanLabConcurrentStartAndDestroySerializeLifecycle(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	env.halStartDelay = "0.5"
	writePodmanLabHalStub(t, env)
	if err := os.WriteFile(env.statePath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("WriteFile(machine state) error = %v", err)
	}
	t.Cleanup(func() { stopPodmanLabDaemon(t, env) })

	startCmd := newPodmanLabCommand(env, "start")
	var startOutput bytes.Buffer
	startCmd.Stdout = &startOutput
	startCmd.Stderr = &startOutput
	if err := startCmd.Start(); err != nil {
		t.Fatalf("start start command: %v", err)
	}
	waitForPodmanLabFile(t, env.halPIDPath)

	destroyCmd := newPodmanLabCommand(env, "destroy")
	var destroyOutput bytes.Buffer
	destroyCmd.Stdout = &destroyOutput
	destroyCmd.Stderr = &destroyOutput
	if err := destroyCmd.Start(); err != nil {
		t.Fatalf("start destroy command: %v", err)
	}
	if err := startCmd.Wait(); err != nil {
		t.Fatalf("wait start command: %v; output = %s", err, startOutput.String())
	}
	daemonPID := readIntegerFile(t, env.halPIDPath)
	if err := destroyCmd.Wait(); err != nil {
		t.Fatalf("wait destroy command: %v; output = %s", err, destroyOutput.String())
	}
	waitForProcessExit(t, daemonPID)
	if _, err := os.Stat(env.labRoot); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lab root still exists after serialized destroy: %v", err)
	}
	if _, err := os.Stat(env.labRoot + ".lifecycle.lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lifecycle lock still exists after serialized destroy: %v", err)
	}
}

func TestPodmanLabDestroyDoesNotSignalUnverifiedLivePID(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	writePodmanLabHalStub(t, env)
	if err := os.MkdirAll(filepath.Join(env.labRoot, "run"), 0o700); err != nil {
		t.Fatalf("MkdirAll(run dir) error = %v", err)
	}
	if err := os.WriteFile(env.statePath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("WriteFile(machine state) error = %v", err)
	}

	socketPath := filepath.Join(env.labRoot, "run", "sandboxd.sock")
	daemon := exec.Command(filepath.Join(env.labRoot, "bin", "hal"),
		"sandboxd", "--socket", socketPath, "--worker-id", "hal-lab-worker")
	daemon.Env = append(os.Environ(),
		"HAL_TEST_LOG="+env.halLogPath,
		"HAL_TEST_DAEMON_PID="+env.halPIDPath,
		"HAL_TEST_DAEMON_READY="+env.halReady,
		"HAL_TEST_START_DELAY=0",
	)
	if err := daemon.Start(); err != nil {
		t.Fatalf("start unverified sandboxd: %v", err)
	}
	t.Cleanup(func() {
		_ = daemon.Process.Kill()
		_ = daemon.Wait()
	})
	waitForPodmanLabFile(t, env.halReady)
	pidPath := filepath.Join(env.labRoot, "run", "sandboxd.pid")
	invalidRecord := "pid=" + strconv.Itoa(daemon.Process.Pid) + "\nbirth=not-the-process-birth\n"
	if err := os.WriteFile(pidPath, []byte(invalidRecord), 0o600); err != nil {
		t.Fatalf("WriteFile(unverified PID) error = %v", err)
	}

	runPodmanLabScript(t, env, "destroy")
	assertProcessAlive(t, daemon.Process.Pid)
}

func TestPodmanLabStatusRequiresWorkerRPCBeforeReportingRunning(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	writePodmanLabHalStub(t, env)
	if err := os.WriteFile(env.statePath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("WriteFile(machine state) error = %v", err)
	}
	t.Cleanup(func() { stopPodmanLabDaemon(t, env) })

	runPodmanLabScript(t, env, "start")
	if err := os.Remove(env.halReady); err != nil {
		t.Fatalf("Remove(worker readiness) error = %v", err)
	}
	output := runPodmanLabScriptOutput(t, env, "status")
	if strings.Contains(output, "sandboxd: running") {
		t.Fatalf("status reported running without worker RPC readiness:\n%s", output)
	}
	if !strings.Contains(output, "process verified but worker RPC unavailable") {
		t.Fatalf("status omitted verified-process RPC failure:\n%s", output)
	}
}

func TestPodmanLabStartReplacesStaleStateWithoutKillingReusedPID(t *testing.T) {
	env := newPodmanLabTestEnv(t)
	writePodmanLabHalStub(t, env)
	if err := os.WriteFile(env.statePath, []byte("ready"), 0o600); err != nil {
		t.Fatalf("WriteFile(machine state) error = %v", err)
	}
	runDir := filepath.Join(env.labRoot, "run")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatalf("MkdirAll(run dir) error = %v", err)
	}

	unrelated := exec.Command("sleep", "60")
	if err := unrelated.Start(); err != nil {
		t.Fatalf("start unrelated process: %v", err)
	}
	t.Cleanup(func() {
		_ = unrelated.Process.Kill()
		_ = unrelated.Wait()
		stopPodmanLabDaemon(t, env)
	})
	if err := os.WriteFile(filepath.Join(runDir, "sandboxd.pid"), []byte(strconv.Itoa(unrelated.Process.Pid)+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(stale PID) error = %v", err)
	}
	socketPath := filepath.Join(runDir, "sandboxd.sock")
	if err := os.WriteFile(socketPath, []byte("stale"), 0o600); err != nil {
		t.Fatalf("WriteFile(stale socket path) error = %v", err)
	}

	runPodmanLabScript(t, env, "start")
	newPID := readPodmanLabPID(t, env)
	if newPID == unrelated.Process.Pid {
		t.Fatalf("stale PID %d was retained", newPID)
	}
	assertProcessAlive(t, newPID)
	assertProcessAlive(t, unrelated.Process.Pid)
}

func assertProcessAlive(t *testing.T, pid int) {
	t.Helper()
	if err := syscall.Kill(pid, 0); err != nil {
		t.Fatalf("process %d is not alive: %v", pid, err)
	}
}

func waitForProcessExit(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("process %d remained alive", pid)
}

func waitForPodmanLabFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func readIntegerFile(t *testing.T, path string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	value, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("invalid integer in %s: %q", path, data)
	}
	return value
}

func stopPodmanLabDaemon(t *testing.T, env podmanLabTestEnv) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(env.labRoot, "run", "sandboxd.pid"))
	if err != nil {
		return
	}
	pid, err := parsePodmanLabPID(data)
	if err != nil {
		return
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
