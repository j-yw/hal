//go:build firecracker_live

package firecracker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

const (
	firecrackerLiveEnvExecutable = "HAL_FIRECRACKER_LIVE_FIRECRACKER"
	firecrackerLiveEnvKernel     = "HAL_FIRECRACKER_LIVE_KERNEL"
	firecrackerLiveEnvRootfs     = "HAL_FIRECRACKER_LIVE_ROOTFS"
	firecrackerLiveEnvInitrd     = "HAL_FIRECRACKER_LIVE_INITRD"
	firecrackerLiveEnvTimeout    = "HAL_FIRECRACKER_LIVE_TIMEOUT"
	firecrackerLiveEnvCPUCount   = "HAL_FIRECRACKER_LIVE_CPU_COUNT"
	firecrackerLiveEnvMemoryMiB  = "HAL_FIRECRACKER_LIVE_MEMORY_MIB"

	firecrackerLiveDefaultTimeout   = 10 * time.Second
	firecrackerLiveDefaultCPUCount  = 1
	firecrackerLiveDefaultMemoryMiB = 256
	firecrackerLiveStopTimeout      = 2 * time.Second
)

func TestFirecrackerLiveBootWithRealProcess(t *testing.T) {
	prereqs, skip := firecrackerLivePrerequisitesFromEnv(os.Getenv, firecrackerLiveHostPrerequisiteChecks())
	if skip != "" {
		t.Skip(skip)
	}

	ctx, cancel := context.WithTimeout(context.Background(), prereqs.Timeout+firecrackerLiveStopTimeout)
	defer cancel()

	processes := newFirecrackerLiveProcessHarness(prereqs.Timeout, firecrackerLiveStopTimeout)
	t.Cleanup(func() {
		_ = processes.cleanupAll(context.Background())
	})

	config := microvm.DefaultConfig()
	config.HypervisorPath = prereqs.ExecutablePath
	config.KernelImagePath = prereqs.KernelImagePath
	config.RootfsPath = prereqs.RootfsPath
	config.InitrdPath = prereqs.InitrdPath
	config.CPUCount = prereqs.CPUCount
	config.MemoryMiB = prereqs.MemoryMiB
	config.GuestWorkDir = "/"

	backend := NewBackend(BackendOptions{
		BaseStateDir:         filepath.Join(t.TempDir(), "firecracker-state"),
		ProcessAdapter:       ProcessLaunchAdapter{Starter: processes},
		BootAcceptanceWaiter: processes,
		LiveProcessManager:   processes,
		LiveStart:            true,
	})
	created, err := backend.Create(ctx, microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    config,
		Name:      "firecracker-live-integration",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	controller, err := backend.Controller(ctx, microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v", err)
	}

	started, err := controller.Start(ctx, microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if started == nil || started.Runtime.Metadata == nil || started.Runtime.Metadata.ProcessLaunch == nil {
		t.Fatalf("Start() target metadata = %#v, want host-side Firecracker launch metadata", started)
	}
	launch := started.Runtime.Metadata.ProcessLaunch
	if launch.State != string(ProcessLaunchStateAccepted) {
		t.Fatalf("ProcessLaunch.State = %q, want %q", launch.State, ProcessLaunchStateAccepted)
	}
	if strings.TrimSpace(launch.ProcessID) == "" || strings.TrimSpace(launch.ProcessIDSource) == "" {
		t.Fatalf("ProcessLaunch handle = %#v, want sanitized live process identity", launch)
	}
	if started.Connection.Address != "" || started.Connection.PublicIP != "" || started.Connection.TailscaleIP != "" {
		t.Fatalf("connection metadata = %#v, want no network or guest-readiness claim", started.Connection)
	}

	stopped, err := controller.Stop(ctx, microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStop,
		Config:    config,
		Target:    *started,
	})
	if err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if err := controller.Delete(ctx, microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationDelete,
		Config:    config,
		Target:    *stopped,
	}); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
}

func TestFirecrackerLivePrerequisiteSkipMessagesAreClearAndRedacted(t *testing.T) {
	sensitiveExecutable := "/Users/alice/private/bin/firecracker-ghp_secret"
	sensitiveKernel := "/Users/alice/private/images/vmlinux"
	sensitiveRootfs := "/Users/alice/private/images/rootfs.ext4"

	okChecks := firecrackerLivePrerequisiteChecks{
		executable:     func(string, string) string { return "" },
		readableAsset:  func(string, string, string) string { return "" },
		readWriteAsset: func(string, string, string) string { return "" },
		kvm:            func() string { return "" },
	}

	tests := []struct {
		name   string
		env    map[string]string
		checks firecrackerLivePrerequisiteChecks
		want   []string
	}{
		{
			name:   "missing executable env",
			env:    map[string]string{},
			checks: okChecks,
			want:   []string{firecrackerLiveEnvExecutable, "required"},
		},
		{
			name: "missing kernel env",
			env: map[string]string{
				firecrackerLiveEnvExecutable: sensitiveExecutable,
			},
			checks: okChecks,
			want:   []string{firecrackerLiveEnvKernel, "required"},
		},
		{
			name: "binary not executable",
			env:  firecrackerLiveCompleteTestEnv(sensitiveExecutable, sensitiveKernel, sensitiveRootfs),
			checks: firecrackerLivePrerequisiteChecks{
				executable: func(envName, _ string) string {
					return fmt.Sprintf("%s Firecracker binary is not executable", envName)
				},
				readableAsset:  okChecks.readableAsset,
				readWriteAsset: okChecks.readWriteAsset,
				kvm:            okChecks.kvm,
			},
			want: []string{firecrackerLiveEnvExecutable, "not executable"},
		},
		{
			name: "rootfs permission",
			env:  firecrackerLiveCompleteTestEnv(sensitiveExecutable, sensitiveKernel, sensitiveRootfs),
			checks: firecrackerLivePrerequisiteChecks{
				executable:    okChecks.executable,
				readableAsset: okChecks.readableAsset,
				readWriteAsset: func(envName, _, _ string) string {
					return fmt.Sprintf("%s rootfs asset is not read/write accessible due to permissions", envName)
				},
				kvm: okChecks.kvm,
			},
			want: []string{firecrackerLiveEnvRootfs, "permissions"},
		},
		{
			name: "kvm missing",
			env:  firecrackerLiveCompleteTestEnv(sensitiveExecutable, sensitiveKernel, sensitiveRootfs),
			checks: firecrackerLivePrerequisiteChecks{
				executable:     okChecks.executable,
				readableAsset:  okChecks.readableAsset,
				readWriteAsset: okChecks.readWriteAsset,
				kvm:            func() string { return "KVM device /dev/kvm is missing" },
			},
			want: []string{"KVM", "/dev/kvm", "missing"},
		},
		{
			name: "invalid timeout",
			env: func() map[string]string {
				env := firecrackerLiveCompleteTestEnv(sensitiveExecutable, sensitiveKernel, sensitiveRootfs)
				env[firecrackerLiveEnvTimeout] = "not-a-duration"
				return env
			}(),
			checks: okChecks,
			want:   []string{firecrackerLiveEnvTimeout, "positive Go duration"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, skip := firecrackerLivePrerequisitesFromEnv(func(key string) string {
				return tt.env[key]
			}, tt.checks)
			if skip == "" {
				t.Fatal("skip message = empty, want clear missing-prerequisite message")
			}
			for _, want := range tt.want {
				if !strings.Contains(skip, want) {
					t.Fatalf("skip message = %q, want fragment %q", skip, want)
				}
			}
			for _, forbidden := range []string{"/Users/alice", "private", "ghp_secret", "vmlinux", "rootfs.ext4"} {
				if strings.Contains(skip, forbidden) {
					t.Fatalf("skip message leaked sensitive fragment %q in %q", forbidden, skip)
				}
			}
		})
	}
}

type firecrackerLivePrerequisites struct {
	ExecutablePath  string
	KernelImagePath string
	RootfsPath      string
	InitrdPath      string
	Timeout         time.Duration
	CPUCount        int
	MemoryMiB       int
}

type firecrackerLivePrerequisiteChecks struct {
	executable     func(envName, path string) string
	readableAsset  func(envName, label, path string) string
	readWriteAsset func(envName, label, path string) string
	kvm            func() string
}

func firecrackerLivePrerequisitesFromEnv(getenv func(string) string, checks firecrackerLivePrerequisiteChecks) (firecrackerLivePrerequisites, string) {
	executablePath := strings.TrimSpace(getenv(firecrackerLiveEnvExecutable))
	if executablePath == "" {
		return firecrackerLivePrerequisites{}, fmt.Sprintf("%s is required for Firecracker live integration tests", firecrackerLiveEnvExecutable)
	}
	if skip := checks.executable(firecrackerLiveEnvExecutable, executablePath); skip != "" {
		return firecrackerLivePrerequisites{}, skip
	}

	kernelPath := strings.TrimSpace(getenv(firecrackerLiveEnvKernel))
	if kernelPath == "" {
		return firecrackerLivePrerequisites{}, fmt.Sprintf("%s is required for Firecracker live integration tests", firecrackerLiveEnvKernel)
	}
	if skip := checks.readableAsset(firecrackerLiveEnvKernel, "kernel asset", kernelPath); skip != "" {
		return firecrackerLivePrerequisites{}, skip
	}

	rootfsPath := strings.TrimSpace(getenv(firecrackerLiveEnvRootfs))
	if rootfsPath == "" {
		return firecrackerLivePrerequisites{}, fmt.Sprintf("%s is required for Firecracker live integration tests", firecrackerLiveEnvRootfs)
	}
	if skip := checks.readWriteAsset(firecrackerLiveEnvRootfs, "rootfs asset", rootfsPath); skip != "" {
		return firecrackerLivePrerequisites{}, skip
	}

	initrdPath := strings.TrimSpace(getenv(firecrackerLiveEnvInitrd))
	if initrdPath != "" {
		if skip := checks.readableAsset(firecrackerLiveEnvInitrd, "initrd asset", initrdPath); skip != "" {
			return firecrackerLivePrerequisites{}, skip
		}
	}

	timeout, skip := firecrackerLiveDurationFromEnv(getenv)
	if skip != "" {
		return firecrackerLivePrerequisites{}, skip
	}
	cpuCount, skip := firecrackerLivePositiveIntFromEnv(getenv, firecrackerLiveEnvCPUCount, firecrackerLiveDefaultCPUCount, 1)
	if skip != "" {
		return firecrackerLivePrerequisites{}, skip
	}
	memoryMiB, skip := firecrackerLivePositiveIntFromEnv(getenv, firecrackerLiveEnvMemoryMiB, firecrackerLiveDefaultMemoryMiB, 1)
	if skip != "" {
		return firecrackerLivePrerequisites{}, skip
	}
	if skip := checks.kvm(); skip != "" {
		return firecrackerLivePrerequisites{}, skip
	}

	return firecrackerLivePrerequisites{
		ExecutablePath:  executablePath,
		KernelImagePath: kernelPath,
		RootfsPath:      rootfsPath,
		InitrdPath:      initrdPath,
		Timeout:         timeout,
		CPUCount:        cpuCount,
		MemoryMiB:       memoryMiB,
	}, ""
}

func firecrackerLiveHostPrerequisiteChecks() firecrackerLivePrerequisiteChecks {
	return firecrackerLivePrerequisiteChecks{
		executable:     firecrackerLiveCheckExecutable,
		readableAsset:  firecrackerLiveCheckReadableRegularFile,
		readWriteAsset: firecrackerLiveCheckReadWriteRegularFile,
		kvm:            firecrackerLiveCheckKVM,
	}
}

func firecrackerLiveCheckExecutable(envName, path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return firecrackerLivePathSkip(envName, "Firecracker binary", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Sprintf("%s Firecracker binary must be a regular file", envName)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Sprintf("%s Firecracker binary is not executable", envName)
	}
	file, err := os.Open(path)
	if err != nil {
		return firecrackerLivePathSkip(envName, "Firecracker binary", err)
	}
	_ = file.Close()
	return ""
}

func firecrackerLiveCheckReadableRegularFile(envName, label, path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return firecrackerLivePathSkip(envName, label, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Sprintf("%s %s must be a regular file", envName, label)
	}
	file, err := os.Open(path)
	if err != nil {
		return firecrackerLivePathSkip(envName, label, err)
	}
	_ = file.Close()
	return ""
}

func firecrackerLiveCheckReadWriteRegularFile(envName, label, path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return firecrackerLivePathSkip(envName, label, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Sprintf("%s %s must be a regular file", envName, label)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return firecrackerLivePathSkip(envName, label, err)
	}
	_ = file.Close()
	return ""
}

func firecrackerLiveCheckKVM() string {
	if runtime.GOOS != "linux" {
		return fmt.Sprintf("KVM device /dev/kvm is required for Firecracker live integration tests; current GOOS is %s", runtime.GOOS)
	}
	file, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		switch {
		case errors.Is(err, os.ErrNotExist):
			return "KVM device /dev/kvm is missing"
		case errors.Is(err, os.ErrPermission):
			return "KVM device /dev/kvm is not read/write accessible due to permissions"
		default:
			return "KVM device /dev/kvm is not available"
		}
	}
	_ = file.Close()
	return ""
}

func firecrackerLivePathSkip(envName, label string, err error) string {
	switch {
	case errors.Is(err, os.ErrNotExist):
		return fmt.Sprintf("%s %s is missing", envName, label)
	case errors.Is(err, os.ErrPermission):
		return fmt.Sprintf("%s %s is not accessible due to permissions", envName, label)
	default:
		return fmt.Sprintf("%s %s is not accessible", envName, label)
	}
}

func firecrackerLiveDurationFromEnv(getenv func(string) string) (time.Duration, string) {
	value := strings.TrimSpace(getenv(firecrackerLiveEnvTimeout))
	if value == "" {
		return firecrackerLiveDefaultTimeout, ""
	}
	timeout, err := time.ParseDuration(value)
	if err != nil || timeout <= 0 {
		return 0, fmt.Sprintf("%s must be a positive Go duration such as 10s", firecrackerLiveEnvTimeout)
	}
	return timeout, ""
}

func firecrackerLivePositiveIntFromEnv(getenv func(string) string, envName string, fallback int, min int) (int, string) {
	value := strings.TrimSpace(getenv(envName))
	if value == "" {
		return fallback, ""
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < min {
		return 0, fmt.Sprintf("%s must be an integer >= %d", envName, min)
	}
	return parsed, ""
}

func firecrackerLiveCompleteTestEnv(executablePath, kernelPath, rootfsPath string) map[string]string {
	return map[string]string{
		firecrackerLiveEnvExecutable: executablePath,
		firecrackerLiveEnvKernel:     kernelPath,
		firecrackerLiveEnvRootfs:     rootfsPath,
	}
}

type firecrackerLiveProcessHarness struct {
	mu          sync.Mutex
	processes   map[string]*firecrackerLiveProcess
	waitTimeout time.Duration
	stopTimeout time.Duration
}

type firecrackerLiveProcess struct {
	cmd  *exec.Cmd
	done chan error
}

var _ ProcessStarter = (*firecrackerLiveProcessHarness)(nil)
var _ bootAcceptanceWaiter = (*firecrackerLiveProcessHarness)(nil)
var _ LiveProcessManager = (*firecrackerLiveProcessHarness)(nil)

func newFirecrackerLiveProcessHarness(waitTimeout, stopTimeout time.Duration) *firecrackerLiveProcessHarness {
	return &firecrackerLiveProcessHarness{
		processes:   map[string]*firecrackerLiveProcess{},
		waitTimeout: waitTimeout,
		stopTimeout: stopTimeout,
	}
}

func (harness *firecrackerLiveProcessHarness) StartProcess(ctx context.Context, req ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
	if strings.TrimSpace(req.Executable) == "" {
		return ProcessHandleMetadata{}, errors.New("firecracker executable is required")
	}
	if len(req.Environment) != 0 {
		return ProcessHandleMetadata{}, errors.New("firecracker live integration test does not deliver environment variables")
	}
	cmd := exec.CommandContext(ctx, req.Executable, req.Args...)
	cmd.Env = []string{}
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return ProcessHandleMetadata{}, err
	}

	handle := ProcessHandleMetadata{
		ID:     strconv.Itoa(cmd.Process.Pid),
		Source: "firecracker_live_test",
	}
	process := &firecrackerLiveProcess{
		cmd:  cmd,
		done: make(chan error, 1),
	}
	go func() {
		process.done <- cmd.Wait()
	}()

	harness.mu.Lock()
	harness.processes[handle.ID] = process
	harness.mu.Unlock()
	return handle, nil
}

func (harness *firecrackerLiveProcessHarness) WaitForBootAcceptance(ctx context.Context, req bootAcceptanceRequest) (bootAcceptanceResult, error) {
	process := harness.lookup(req.Handle.ID)
	if process == nil {
		return bootAcceptanceResult{ProcessAccepted: false}, nil
	}

	deadline := time.NewTimer(harness.waitTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case err := <-process.done:
			harness.remove(req.Handle.ID)
			if err != nil {
				return bootAcceptanceResult{}, fmt.Errorf("firecracker process exited before host-side API socket acceptance: %w", err)
			}
			return bootAcceptanceResult{}, errors.New("firecracker process exited before host-side API socket acceptance")
		case <-ctx.Done():
			return bootAcceptanceResult{}, ctx.Err()
		case <-deadline.C:
			return bootAcceptanceResult{}, context.DeadlineExceeded
		case <-ticker.C:
			available, err := firecrackerLiveAPISocketAvailable(req.APISocket.Path)
			if err != nil {
				return bootAcceptanceResult{}, err
			}
			if available {
				return bootAcceptanceResult{
					ProcessAccepted:    true,
					APISocketAvailable: true,
				}, nil
			}
		}
	}
}

func (harness *firecrackerLiveProcessHarness) CleanupLiveProcess(ctx context.Context, req LiveProcessRequest) error {
	if err := harness.terminate(ctx, req.Handle.ID); err != nil {
		return err
	}
	return firecrackerLiveRemoveStateDir(req.Paths)
}

func (harness *firecrackerLiveProcessHarness) StopLiveProcess(ctx context.Context, req LiveProcessRequest) error {
	return harness.terminate(ctx, req.Handle.ID)
}

func (harness *firecrackerLiveProcessHarness) DeleteLiveProcess(ctx context.Context, req LiveProcessRequest) error {
	if err := harness.terminate(ctx, req.Handle.ID); err != nil {
		return err
	}
	return firecrackerLiveRemoveStateDir(req.Paths)
}

func (harness *firecrackerLiveProcessHarness) cleanupAll(ctx context.Context) error {
	harness.mu.Lock()
	ids := make([]string, 0, len(harness.processes))
	for id := range harness.processes {
		ids = append(ids, id)
	}
	harness.mu.Unlock()

	var out error
	for _, id := range ids {
		out = errors.Join(out, harness.terminate(ctx, id))
	}
	return out
}

func (harness *firecrackerLiveProcessHarness) lookup(id string) *firecrackerLiveProcess {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	return harness.processes[id]
}

func (harness *firecrackerLiveProcessHarness) remove(id string) {
	harness.mu.Lock()
	delete(harness.processes, id)
	harness.mu.Unlock()
}

func (harness *firecrackerLiveProcessHarness) take(id string) *firecrackerLiveProcess {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	process := harness.processes[id]
	delete(harness.processes, id)
	return process
}

func (harness *firecrackerLiveProcessHarness) terminate(ctx context.Context, id string) error {
	process := harness.take(id)
	if process == nil || process.cmd == nil || process.cmd.Process == nil {
		return nil
	}
	_ = process.cmd.Process.Signal(os.Interrupt)

	timer := time.NewTimer(harness.stopTimeout)
	defer timer.Stop()

	select {
	case <-process.done:
		return nil
	case <-ctx.Done():
		_ = process.cmd.Process.Kill()
		<-process.done
		return ctx.Err()
	case <-timer.C:
		_ = process.cmd.Process.Kill()
		<-process.done
		return nil
	}
}

func firecrackerLiveAPISocketAvailable(path string) (bool, error) {
	info, err := os.Stat(path)
	if err == nil {
		return info.Mode()&os.ModeSocket != 0, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func firecrackerLiveRemoveStateDir(paths PathPlan) error {
	cleaned, err := validateLiveBootRenderPaths(paths)
	if err != nil {
		return err
	}
	return os.RemoveAll(cleaned.StateDir)
}
