package firecrackerhost

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestNewLiveBackendOptionsComposesExplicitFirecrackerLiveDependencies(t *testing.T) {
	baseStateDir := filepath.Join(t.TempDir(), "firecracker-state")
	runner := &fakeHostProcessRunner{}
	poller := &fakeBootAcceptancePoller{}
	clock := fakeClock{now: time.Unix(123, 0)}
	sleeper := &fakeSleeper{}
	cleanupFS := newFakeCleanupFilesystem()

	options, err := NewLiveBackendOptions(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         baseStateDir,
		HostProcessRunner:    runner,
		BootAcceptancePoller: poller,
		Clock:                clock,
		Sleeper:              sleeper,
		BootTimeout:          5 * time.Second,
		BootPollInterval:     25 * time.Millisecond,
		CleanupFilesystem:    cleanupFS,
		CapabilityDetector:   liveDriverAvailableDetector{},
	})
	if err != nil {
		t.Fatalf("NewLiveBackendOptions() error = %v, want nil", err)
	}

	if options.BaseStateDir != baseStateDir {
		t.Fatalf("BaseStateDir = %q, want %q", options.BaseStateDir, baseStateDir)
	}
	if !options.LiveStart {
		t.Fatal("LiveStart = false, want true")
	}

	processAdapter, ok := options.ProcessAdapter.(firecracker.ProcessLaunchAdapter)
	if !ok {
		t.Fatalf("ProcessAdapter = %T, want firecracker.ProcessLaunchAdapter", options.ProcessAdapter)
	}
	hostAdapter, ok := processAdapter.Starter.(*Adapter)
	if !ok {
		t.Fatalf("ProcessLaunchAdapter.Starter = %T, want *Adapter", processAdapter.Starter)
	}
	if options.BootAcceptanceWaiter != hostAdapter {
		t.Fatalf("BootAcceptanceWaiter = %T, want same host adapter used by ProcessLaunchAdapter", options.BootAcceptanceWaiter)
	}
	if options.LiveProcessManager != hostAdapter {
		t.Fatalf("LiveProcessManager = %T, want same host adapter used by ProcessLaunchAdapter", options.LiveProcessManager)
	}

	lifecycle, ok := hostAdapter.processRunner.(*ProcessLifecycleManager)
	if !ok {
		t.Fatalf("adapter process runner = %T, want *ProcessLifecycleManager", hostAdapter.processRunner)
	}
	if lifecycle.runner != runner {
		t.Fatal("process lifecycle manager did not receive injected host process runner")
	}
	if lifecycle.cleanupFS != cleanupFS {
		t.Fatal("process lifecycle manager did not receive injected cleanup filesystem")
	}
	if hostAdapter.cleanup != lifecycle {
		t.Fatal("adapter live cleanup does not use the same process lifecycle manager as process start")
	}
	if hostAdapter.poller != poller {
		t.Fatal("adapter did not receive injected boot acceptance poller")
	}
	if got := hostAdapter.clock.Now(); !got.Equal(clock.now) {
		t.Fatalf("adapter clock Now() = %s, want %s", got, clock.now)
	}
	if hostAdapter.sleeper != sleeper {
		t.Fatal("adapter did not receive injected sleeper")
	}
	if hostAdapter.bootTimeout != 5*time.Second {
		t.Fatalf("adapter boot timeout = %s, want 5s", hostAdapter.bootTimeout)
	}
	if hostAdapter.bootInterval != 25*time.Millisecond {
		t.Fatalf("adapter boot interval = %s, want 25ms", hostAdapter.bootInterval)
	}
}

func TestNewLiveDriverUsesExplicitBackendAndCapabilityOverride(t *testing.T) {
	detector := &recordingLiveDriverCapabilityDetector{report: liveDriverAvailableCapabilityReport()}
	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:             liveDriverValidConfig(),
		BaseStateDir:       filepath.Join(t.TempDir(), "firecracker-state"),
		CapabilityDetector: detector,
		HostProcessRunner:  &fakeHostProcessRunner{},
		BootAcceptancePoller: &fakeBootAcceptancePoller{result: firecracker.BootAcceptanceResult{
			ProcessAccepted:    true,
			APISocketAvailable: true,
		}},
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}

	if detector.calls != 1 {
		t.Fatalf("capability detector calls = %d, want 1", detector.calls)
	}
	if !reflect.DeepEqual(detector.request.Config, microvm.ApplyDefaults(liveDriverValidConfig())) {
		t.Fatalf("capability detector config = %#v, want defaulted live config", detector.request.Config)
	}

	metadata := driver.Metadata()
	if !metadata.BackendConfigured {
		t.Fatal("driver metadata BackendConfigured = false, want true")
	}
	if metadata.Availability != microvm.CapabilityAvailabilityAvailable {
		t.Fatalf("driver metadata Availability = %q, want %q", metadata.Availability, microvm.CapabilityAvailabilityAvailable)
	}
	if metadata.ReasonCode != microvm.DriverReasonAvailable {
		t.Fatalf("driver metadata ReasonCode = %q, want %q", metadata.ReasonCode, microvm.DriverReasonAvailable)
	}

	target, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-live-dev"})
	if err != nil {
		t.Fatalf("driver Create() error = %v, want nil", err)
	}
	if target == nil || target.Runtime.Metadata == nil {
		t.Fatalf("driver Create() target = %#v, want Firecracker metadata", target)
	}
	if target.Runtime.Metadata.Backend != firecracker.BackendID {
		t.Fatalf("target backend = %q, want %q", target.Runtime.Metadata.Backend, firecracker.BackendID)
	}
}

func TestNewLiveDriverStartUsesFakeHostRunnerAndBootAcceptance(t *testing.T) {
	baseStateDir := filepath.Join(t.TempDir(), "firecracker-state")
	process := &fakeHostProcess{rawPID: 424242}
	runner := &fakeHostProcessRunner{processes: []HostProcess{process}}
	poller := &fakeBootAcceptancePoller{result: firecracker.BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	}}

	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         baseStateDir,
		CapabilityDetector:   liveDriverAvailableDetector{},
		HostProcessRunner:    runner,
		BootAcceptancePoller: poller,
		CleanupFilesystem:    newFakeCleanupFilesystem(),
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}

	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-live-start"})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	if runner.calls != 0 || poller.calls != 0 {
		t.Fatalf("Create() live calls = runner:%d poller:%d, want none before Start", runner.calls, poller.calls)
	}

	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() error = %v, want nil through fake live dependencies", err)
	}
	if started == nil || started.Runtime.Metadata == nil || started.Runtime.Metadata.ProcessLaunch == nil {
		t.Fatalf("Start() target = %#v, want live process launch metadata", started)
	}
	launch := started.Runtime.Metadata.ProcessLaunch
	if launch.State != string(firecracker.ProcessLaunchStateAccepted) {
		t.Fatalf("ProcessLaunch.State = %q, want %q", launch.State, firecracker.ProcessLaunchStateAccepted)
	}

	if runner.calls != 1 {
		t.Fatalf("fake host runner calls = %d, want one live start", runner.calls)
	}
	if len(runner.requests) != 1 {
		t.Fatalf("fake host runner requests = %#v, want one request", runner.requests)
	}
	if runner.requests[0].Executable != liveDriverValidConfig().HypervisorPath {
		t.Fatalf("runner executable = %q, want configured Firecracker executable", runner.requests[0].Executable)
	}
	if len(runner.requests[0].Environment) != 0 {
		t.Fatalf("runner environment = %#v, want no environment delivery", runner.requests[0].Environment)
	}
	if poller.calls != 1 {
		t.Fatalf("boot acceptance poller calls = %d, want one host-side acceptance poll", poller.calls)
	}
	if poller.req.Handle.ID != launch.ProcessID || poller.req.Handle.Source != launch.ProcessIDSource {
		t.Fatalf("poller handle = %#v, launch metadata = %#v, want same sanitized fake handle", poller.req.Handle, launch)
	}
	if poller.req.APISocket.Role != firecracker.OperationPathRoleAPISocket {
		t.Fatalf("poller API socket role = %q, want %q", poller.req.APISocket.Role, firecracker.OperationPathRoleAPISocket)
	}
	assertLiveDriverPathUnderBaseStateDir(t, poller.req.APISocket.Path, baseStateDir)
	if process.signalCalls != 0 || process.killCalls != 0 || process.waitCalls != 0 {
		t.Fatalf("fake process cleanup calls after accepted start = signal:%d kill:%d wait:%d, want none", process.signalCalls, process.killCalls, process.waitCalls)
	}
}

func TestNewLiveDriverReportsHonestLiveFirecrackerRuntimeMetadata(t *testing.T) {
	baseStateDir := filepath.Join(t.TempDir(), "firecracker-state")
	process := &fakeHostProcess{rawPID: 424242}
	runner := &fakeHostProcessRunner{processes: []HostProcess{process}}
	poller := &fakeBootAcceptancePoller{result: firecracker.BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	}}

	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         baseStateDir,
		CapabilityDetector:   liveDriverAvailableDetector{},
		HostProcessRunner:    runner,
		BootAcceptancePoller: poller,
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}

	driverMetadata := driver.Metadata()
	if driverMetadata.DriverID != sandboxruntime.DriverMicroVM {
		t.Fatalf("driver metadata DriverID = %q, want %q", driverMetadata.DriverID, sandboxruntime.DriverMicroVM)
	}
	if driverMetadata.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("driver metadata IsolationLevel = %q, want %q", driverMetadata.IsolationLevel, sandbox.SandboxIsolationLevelVM)
	}
	if driverMetadata.UsesHostDockerSocket {
		t.Fatal("driver metadata UsesHostDockerSocket = true, want false for live Firecracker")
	}

	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-live-metadata"})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	assertLiveFirecrackerRuntimeMetadata(t, created)
	assertLiveFirecrackerProcessLaunchState(t, created, firecracker.ProcessLaunchStateBoundaryAvailable)
	if poller.calls != 0 {
		t.Fatalf("boot acceptance poller calls before Start = %d, want 0", poller.calls)
	}

	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() error = %v, want nil", err)
	}
	if poller.calls != 1 {
		t.Fatalf("boot acceptance poller calls after Start = %d, want 1", poller.calls)
	}
	assertLiveFirecrackerRuntimeMetadata(t, started)
	assertLiveFirecrackerProcessLaunchState(t, started, firecracker.ProcessLaunchStateAccepted)
}

func TestNewLiveDriverDoesNotReportAcceptedLaunchWhenBootAcceptanceFails(t *testing.T) {
	process := &fakeHostProcess{rawPID: 424242}
	runner := &fakeHostProcessRunner{processes: []HostProcess{process}}
	poller := &fakeBootAcceptancePoller{err: errors.New("fake acceptance rejected")}

	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         filepath.Join(t.TempDir(), "firecracker-state"),
		CapabilityDetector:   liveDriverAvailableDetector{},
		HostProcessRunner:    runner,
		BootAcceptancePoller: poller,
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-live-rejected"})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}

	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})

	if err == nil {
		t.Fatal("Start() error = nil, want failed boot acceptance")
	}
	if started != nil {
		t.Fatalf("Start() target = %#v, want nil when fake acceptance does not succeed", started)
	}
	if runner.calls != 1 || poller.calls != 1 {
		t.Fatalf("live calls = runner:%d poller:%d, want one start and one failed acceptance poll", runner.calls, poller.calls)
	}
	assertLiveFirecrackerProcessLaunchState(t, created, firecracker.ProcessLaunchStateBoundaryAvailable)
}

func TestNewLiveDriverBootAcceptanceFailureCleansUpFakeHostProcess(t *testing.T) {
	acceptanceErr := errors.New("fake boot acceptance failed at /Users/alice/private/firecracker.sock token=ghp_secret")
	baseStateDir := filepath.Join(t.TempDir(), "firecracker-state")
	cleanupFS := newFakeCleanupFilesystem()
	process := &fakeHostProcess{rawPID: 424242}
	runner := &fakeHostProcessRunner{processes: []HostProcess{process}}
	poller := &fakeBootAcceptancePoller{err: acceptanceErr}

	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         baseStateDir,
		CapabilityDetector:   liveDriverAvailableDetector{},
		HostProcessRunner:    runner,
		BootAcceptancePoller: poller,
		CleanupFilesystem:    cleanupFS,
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-live-cleanup"})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	paths, err := firecracker.PlanPaths(firecracker.PathPlanRequest{
		RuntimeID:    created.Runtime.RuntimeID,
		BaseStateDir: baseStateDir,
	})
	if err != nil {
		t.Fatalf("PlanPaths() error = %v, want nil", err)
	}
	cleanupFS.addDir(paths.StateDir)
	cleanupFS.addFile(paths.APISocketPath)
	cleanupFS.addFile(paths.ConfigPath)
	cleanupFS.addFile(paths.LogPath)
	cleanupFS.addFile(paths.MetricsPath)

	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})

	if err == nil {
		t.Fatal("Start() error = nil, want boot acceptance failure")
	}
	if started != nil {
		t.Fatalf("Start() target = %#v, want nil after boot acceptance failure", started)
	}
	if !errors.Is(err, acceptanceErr) {
		t.Fatalf("errors.Is(Start() error, acceptanceErr) = false for %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("fake host runner calls = %d, want one process start before cleanup", runner.calls)
	}
	if poller.calls != 1 {
		t.Fatalf("boot acceptance poller calls = %d, want one failed acceptance poll", poller.calls)
	}
	if process.killCalls != 1 || process.waitCalls != 1 || process.signalCalls != 0 {
		t.Fatalf("fake process cleanup calls = signal:%d kill:%d wait:%d, want kill+wait cleanup", process.signalCalls, process.killCalls, process.waitCalls)
	}
	if !reflect.DeepEqual(cleanupFS.removeCalls, []string{paths.StateDir}) {
		t.Fatalf("cleanup RemoveAll calls = %#v, want only state dir %q", cleanupFS.removeCalls, paths.StateDir)
	}
	if cleanupFS.exists(paths.StateDir) {
		t.Fatalf("cleanup left Firecracker state dir %q in fake filesystem", paths.StateDir)
	}
}

func TestNewLiveBackendOptionsRejectsInvalidExplicitInputs(t *testing.T) {
	tests := []struct {
		name    string
		options LiveDriverOptions
		field   string
	}{
		{
			name: "missing firecracker executable path",
			options: LiveDriverOptions{
				Config:               liveDriverConfigWithoutHypervisorPath(),
				BaseStateDir:         filepath.Join(t.TempDir(), "firecracker-state"),
				BootAcceptancePoller: &fakeBootAcceptancePoller{},
			},
			field: "executablePath",
		},
		{
			name: "missing base state dir",
			options: LiveDriverOptions{
				Config:               liveDriverValidConfig(),
				BootAcceptancePoller: &fakeBootAcceptancePoller{},
			},
			field: "baseStateDir",
		},
		{
			name: "missing boot poller",
			options: LiveDriverOptions{
				Config:       liveDriverValidConfig(),
				BaseStateDir: filepath.Join(t.TempDir(), "firecracker-state"),
			},
			field: "bootAcceptancePoller",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewLiveBackendOptions(tt.options)
			if err == nil {
				t.Fatal("NewLiveBackendOptions() error = nil, want validation error")
			}
			var operationErr *microvm.OperationError
			if !errors.As(err, &operationErr) {
				t.Fatalf("error = %T %v, want *microvm.OperationError", err, err)
			}
			if operationErr.Field != tt.field {
				t.Fatalf("OperationError.Field = %q, want %q", operationErr.Field, tt.field)
			}
		})
	}
}

func assertLiveDriverPathUnderBaseStateDir(t *testing.T, path, baseStateDir string) {
	t.Helper()

	rel, err := filepath.Rel(filepath.Clean(baseStateDir), filepath.Clean(path))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		t.Fatalf("path %q is not under base state dir %q", path, baseStateDir)
	}
}

func liveDriverValidConfig() microvm.Config {
	return microvm.Config{
		HypervisorPath:  "/usr/bin/firecracker",
		KernelImagePath: "/opt/hal/images/vmlinux",
		RootfsPath:      "/opt/hal/images/rootfs.ext4",
		CPUCount:        1,
		MemoryMiB:       256,
		DiskSizeMiB:     1024,
		GuestWorkDir:    "/workspace",
		NetworkMode:     microvm.NetworkModeNoLiveNetworking,
	}
}

func liveDriverConfigWithoutHypervisorPath() microvm.Config {
	config := liveDriverValidConfig()
	config.HypervisorPath = ""
	return config
}

type liveDriverAvailableDetector struct{}

func (liveDriverAvailableDetector) DetectMicroVMCapability(microvm.CapabilityDetectionRequest) microvm.CapabilityReport {
	return liveDriverAvailableCapabilityReport()
}

type recordingLiveDriverCapabilityDetector struct {
	calls   int
	request microvm.CapabilityDetectionRequest
	report  microvm.CapabilityReport
}

func (detector *recordingLiveDriverCapabilityDetector) DetectMicroVMCapability(request microvm.CapabilityDetectionRequest) microvm.CapabilityReport {
	detector.calls++
	detector.request = request
	return detector.report
}

func liveDriverAvailableCapabilityReport() microvm.CapabilityReport {
	kvmReadable := true
	hypervisorAvailable := true
	return microvm.CapabilityReport{
		OS:                             "linux",
		Architecture:                   "amd64",
		KVMDevicePresent:               true,
		KVMReadable:                    &kvmReadable,
		HypervisorExecutableConfigured: true,
		HypervisorExecutableAvailable:  &hypervisorAvailable,
		Availability:                   microvm.CapabilityAvailabilityAvailable,
		ReasonCode:                     microvm.CapabilityReasonAvailable,
	}
}

func assertLiveFirecrackerRuntimeMetadata(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()
	if target == nil {
		t.Fatal("target = nil, want live Firecracker runtime target")
	}
	if target.Runtime.Driver != sandboxruntime.DriverMicroVM {
		t.Fatalf("target runtime Driver = %q, want %q", target.Runtime.Driver, sandboxruntime.DriverMicroVM)
	}
	if target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelVM {
		t.Fatalf("target runtime IsolationLevel = %q, want %q", target.Runtime.IsolationLevel, sandbox.SandboxIsolationLevelVM)
	}
	if target.Runtime.Metadata == nil {
		t.Fatal("target runtime Metadata = nil, want Firecracker metadata")
	}
	if target.Runtime.Metadata.Backend != firecracker.BackendID {
		t.Fatalf("target runtime Backend = %q, want %q", target.Runtime.Metadata.Backend, firecracker.BackendID)
	}
	assertLiveFirecrackerMetadataDoesNotOverclaim(t, target.Runtime.Metadata)
}

func assertLiveFirecrackerProcessLaunchState(t *testing.T, target *sandboxruntime.Target, want firecracker.ProcessLaunchState) {
	t.Helper()
	if target == nil || target.Runtime.Metadata == nil || target.Runtime.Metadata.ProcessLaunch == nil {
		t.Fatalf("target launch metadata = %#v, want %q", target, want)
	}
	launch := target.Runtime.Metadata.ProcessLaunch
	if launch.State != string(want) {
		t.Fatalf("ProcessLaunch.State = %q, want %q", launch.State, want)
	}
	if want != firecracker.ProcessLaunchStateAccepted && (launch.ProcessID != "" || launch.ProcessIDSource != "") {
		t.Fatalf("ProcessLaunch exposes process identity before acceptance: %#v", launch)
	}
}

func assertLiveFirecrackerMetadataDoesNotOverclaim(t *testing.T, metadata *sandboxruntime.RuntimeMetadata) {
	t.Helper()
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(runtime metadata) error = %v", err)
	}
	publicText := strings.ToLower(string(encoded))
	for _, unsupported := range []string{
		"guest_exec",
		"guest_copy",
		"deny_by_default",
		"brokered_secret",
		"secret_broker",
		"network_proxy",
		"credential_broker",
		"credential_proxy",
		"template",
		"kit",
		"docker_in_guest",
		"host_docker_socket",
		"rootless_podman",
	} {
		if strings.Contains(publicText, unsupported) {
			t.Fatalf("live Firecracker metadata claims unsupported capability %q in %s", unsupported, publicText)
		}
	}
}
