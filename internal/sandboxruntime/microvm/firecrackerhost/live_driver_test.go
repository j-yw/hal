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
	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
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
	if options.GuestReadinessWaiter != nil {
		t.Fatalf("GuestReadinessWaiter = %T, want nil until a guest readiness probe is supplied", options.GuestReadinessWaiter)
	}
	if options.GuestTransport != nil {
		t.Fatalf("GuestTransport = %T, want nil until a guest transport is supplied", options.GuestTransport)
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
	if hostAdapter.guestReadinessProbe != nil {
		t.Fatal("adapter guest readiness probe configured without explicit probe option")
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

func TestNewLiveBackendOptionsConfiguresOptionalGuestReadinessProbe(t *testing.T) {
	baseStateDir := filepath.Join(t.TempDir(), "firecracker-state")
	probe := &fakeGuestReadinessProbe{}

	options, err := NewLiveBackendOptions(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         baseStateDir,
		HostProcessRunner:    &fakeHostProcessRunner{},
		BootAcceptancePoller: &fakeBootAcceptancePoller{},
		GuestReadinessProbe:  probe,
		GuestTimeout:         9 * time.Second,
		GuestPollInterval:    75 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewLiveBackendOptions() error = %v, want nil", err)
	}

	processAdapter, ok := options.ProcessAdapter.(firecracker.ProcessLaunchAdapter)
	if !ok {
		t.Fatalf("ProcessAdapter = %T, want firecracker.ProcessLaunchAdapter", options.ProcessAdapter)
	}
	hostAdapter, ok := processAdapter.Starter.(*Adapter)
	if !ok {
		t.Fatalf("ProcessLaunchAdapter.Starter = %T, want *Adapter", processAdapter.Starter)
	}
	if options.GuestReadinessWaiter != hostAdapter {
		t.Fatalf("GuestReadinessWaiter = %T, want same host adapter used by ProcessLaunchAdapter", options.GuestReadinessWaiter)
	}
	if hostAdapter.guestReadinessProbe != probe {
		t.Fatal("adapter did not receive injected guest readiness probe")
	}
	if hostAdapter.guestTimeout != 9*time.Second {
		t.Fatalf("adapter guest timeout = %s, want 9s", hostAdapter.guestTimeout)
	}
	if hostAdapter.guestInterval != 75*time.Millisecond {
		t.Fatalf("adapter guest interval = %s, want 75ms", hostAdapter.guestInterval)
	}
}

func TestNewLiveBackendOptionsConfiguresOptionalGuestTransport(t *testing.T) {
	baseStateDir := filepath.Join(t.TempDir(), "firecracker-state")
	transport := &fakeLiveGuestTransport{}

	options, err := NewLiveBackendOptions(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         baseStateDir,
		HostProcessRunner:    &fakeHostProcessRunner{},
		BootAcceptancePoller: &fakeBootAcceptancePoller{},
		GuestTransport:       transport,
	})
	if err != nil {
		t.Fatalf("NewLiveBackendOptions() error = %v, want nil", err)
	}

	if options.GuestTransport != transport {
		t.Fatalf("GuestTransport = %T, want supplied fake guest transport", options.GuestTransport)
	}
	if options.GuestReadinessWaiter != nil {
		t.Fatalf("GuestReadinessWaiter = %T, want nil without explicit readiness probe", options.GuestReadinessWaiter)
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

func TestNewLiveDriverStartUsesOptionalGuestReadinessProbe(t *testing.T) {
	baseStateDir := filepath.Join(t.TempDir(), "firecracker-state")
	process := &fakeHostProcess{rawPID: 424242}
	runner := &fakeHostProcessRunner{processes: []HostProcess{process}}
	poller := &fakeBootAcceptancePoller{result: firecracker.BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	}}
	probe := &fakeGuestReadinessProbe{result: firecracker.NewGuestReadinessResult(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"VSOCK",
		[]string{"probe_ok", "exec_support", "copy_support", "credential_proxy"},
	)}

	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         baseStateDir,
		CapabilityDetector:   liveDriverAvailableDetector{},
		HostProcessRunner:    runner,
		BootAcceptancePoller: poller,
		GuestReadinessProbe:  probe,
		CleanupFilesystem:    newFakeCleanupFilesystem(),
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}

	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-live-guest-ready"})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() error = %v, want nil through optional fake guest readiness probe", err)
	}

	if poller.calls != 1 || probe.calls != 1 {
		t.Fatalf("readiness calls = boot:%d guest:%d, want one host acceptance and one guest readiness wait", poller.calls, probe.calls)
	}
	if probe.req.RuntimeID != created.Runtime.RuntimeID {
		t.Fatalf("guest readiness runtime ID = %q, want %q", probe.req.RuntimeID, created.Runtime.RuntimeID)
	}
	launch := started.Runtime.Metadata.ProcessLaunch
	if probe.req.Handle.ID != launch.ProcessID || probe.req.Handle.Source != launch.ProcessIDSource {
		t.Fatalf("guest readiness handle = %#v, launch metadata = %#v, want accepted host handle", probe.req.Handle, launch)
	}
	readiness := started.Runtime.Metadata.GuestReadiness
	if readiness == nil {
		t.Fatal("GuestReadiness = nil, want ready metadata from optional probe")
	}
	if readiness.State != sandboxruntime.RuntimeGuestReadinessStateReady || readiness.Transport != "vsock" {
		t.Fatalf("GuestReadiness = %#v, want sanitized ready vsock metadata", readiness)
	}
	if !reflect.DeepEqual(readiness.Labels, []string{"ready", "probe_ok"}) {
		t.Fatalf("GuestReadiness.Labels = %#v, want sanitized labels", readiness.Labels)
	}
	assertLiveFirecrackerMetadataDoesNotOverclaim(t, started.Runtime.Metadata)
}

func TestNewLiveDriverGuestAgentReadinessFailureCleansUpFakeHostProcess(t *testing.T) {
	readinessErr := errors.New("dial unix /Users/alice/private/guest-agent.sock endpoint=https://guest.internal:9443/status token=ghp_secret docker=/var/run/docker.sock")
	baseStateDir := filepath.Join(t.TempDir(), "firecracker-state")
	cleanupFS := newFakeCleanupFilesystem()
	process := &fakeHostProcess{rawPID: 424242}
	runner := &fakeHostProcessRunner{processes: []HostProcess{process}}
	poller := &fakeBootAcceptancePoller{result: firecracker.BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	}}
	client := &recordingGuestAgentReadinessClient{err: readinessErr}
	probe := NewGuestAgentReadinessProbe(GuestAgentReadinessProbeOptions{Client: client})

	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         baseStateDir,
		CapabilityDetector:   liveDriverAvailableDetector{},
		HostProcessRunner:    runner,
		BootAcceptancePoller: poller,
		GuestReadinessProbe:  probe,
		CleanupFilesystem:    cleanupFS,
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-live-agent-readiness-failure"})
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
	cleanupFS.addFile(paths.ConfigPath)
	cleanupFS.addFile(paths.LogPath)
	cleanupFS.addFile(paths.MetricsPath)

	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})

	if err == nil {
		t.Fatal("Start() error = nil, want guest-agent readiness failure")
	}
	if started != nil {
		t.Fatalf("Start() target = %#v, want nil after guest-agent readiness failure", started)
	}
	if !errors.Is(err, readinessErr) {
		t.Fatalf("errors.Is(Start() error, readinessErr) = false for %v", err)
	}
	if runner.calls != 1 || poller.calls != 1 || client.calls != 1 {
		t.Fatalf("live calls = runner:%d boot:%d readiness:%d, want one call each", runner.calls, poller.calls, client.calls)
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
	assertLiveDriverErrorDoesNotLeak(t, err,
		"/Users/alice",
		"guest-agent.sock",
		"guest.internal",
		"9443",
		"ghp_secret",
		"/var/run/docker.sock",
	)
}

func TestNewLiveDriverDelegatesGuestOperationsThroughOptionalGuestTransportAfterReadiness(t *testing.T) {
	baseStateDir := filepath.Join(t.TempDir(), "firecracker-state")
	process := &fakeHostProcess{rawPID: 424242}
	runner := &fakeHostProcessRunner{processes: []HostProcess{process}}
	poller := &fakeBootAcceptancePoller{result: firecracker.BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	}}
	probe := &fakeGuestReadinessProbe{result: firecracker.NewGuestReadinessResult(
		sandboxruntime.RuntimeGuestReadinessStateReady,
		"vsock",
		[]string{"ready"},
	)}
	transport := &fakeLiveGuestTransport{result: &sandboxruntime.ExecResult{ExitCode: 17}}

	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         baseStateDir,
		CapabilityDetector:   liveDriverAvailableDetector{},
		HostProcessRunner:    runner,
		BootAcceptancePoller: poller,
		GuestReadinessProbe:  probe,
		GuestTransport:       transport,
		CleanupFilesystem:    newFakeCleanupFilesystem(),
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}

	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{Name: "firecracker-live-guest-transport"})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	_, err = driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target: *created,
		Args:   []string{"true"},
	})
	assertLiveDriverUnsupportedGuestOperation(t, err, microvm.OperationExec)
	if transport.execCalls != 0 || transport.copyInCalls != 0 || transport.copyOutCalls != 0 {
		t.Fatalf("guest transport calls before guest readiness = exec:%d copyIn:%d copyOut:%d, want none", transport.execCalls, transport.copyInCalls, transport.copyOutCalls)
	}

	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() error = %v, want nil through fake live dependencies", err)
	}

	result, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{
		Target:  *started,
		Args:    []string{"printf", "ok"},
		Env:     map[string]string{"SAFE": "value"},
		WorkDir: "/workspace/project",
	})
	if err != nil {
		t.Fatalf("Exec() error = %v, want nil through injected fake guest transport", err)
	}
	if result == nil || result.ExitCode != 17 {
		t.Fatalf("Exec() result = %#v, want fake transport exit code 17", result)
	}
	if err := driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
		Target:          *started,
		SourcePath:      "/host/input.txt",
		DestinationPath: "/guest/input.txt",
	}); err != nil {
		t.Fatalf("CopyIn() error = %v, want nil through injected fake guest transport", err)
	}
	if err := driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
		Target:          *started,
		SourcePath:      "/guest/output.txt",
		DestinationPath: "/host/output.txt",
	}); err != nil {
		t.Fatalf("CopyOut() error = %v, want nil through injected fake guest transport", err)
	}

	if transport.execCalls != 1 || transport.copyInCalls != 1 || transport.copyOutCalls != 1 {
		t.Fatalf("guest transport calls = exec:%d copyIn:%d copyOut:%d, want one call each", transport.execCalls, transport.copyInCalls, transport.copyOutCalls)
	}
	if !reflect.DeepEqual(transport.execRequest.Args, []string{"printf", "ok"}) {
		t.Fatalf("exec args = %#v, want delegated args", transport.execRequest.Args)
	}
	if transport.execRequest.WorkDir != "/workspace/project" {
		t.Fatalf("exec workdir = %q, want delegated workdir", transport.execRequest.WorkDir)
	}
	if !reflect.DeepEqual(transport.execRequest.Env, map[string]string{"SAFE": "value"}) {
		t.Fatalf("exec env = %#v, want delegated env", transport.execRequest.Env)
	}
	if transport.copyInRequest.SourcePath != "/host/input.txt" || transport.copyInRequest.DestinationPath != "/guest/input.txt" {
		t.Fatalf("copy-in request = %#v, want delegated source and destination paths", transport.copyInRequest)
	}
	if transport.copyOutRequest.SourcePath != "/guest/output.txt" || transport.copyOutRequest.DestinationPath != "/host/output.txt" {
		t.Fatalf("copy-out request = %#v, want delegated source and destination paths", transport.copyOutRequest)
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

func TestNewLiveDriverPassesExplicitNetworkEnforcementPlanningToMicroVMDriver(t *testing.T) {
	request := firecrackerHostNetworkEnforcementPlanRequest()
	var plannerCalls int
	planner := networkenforcement.PlannerFunc(func(got networkenforcement.PlanRequest) networkenforcement.Plan {
		plannerCalls++
		if !reflect.DeepEqual(got, request) {
			t.Fatalf("planner request = %#v, want %#v", got, request)
		}
		return networkenforcement.BuildPlan(got)
	})
	adapter := &recordingFirecrackerHostNetworkEnforcementAdapter{
		result: networkenforcement.Result{
			AdapterID:       "fake-firecrackerhost-network-adapter",
			Outcome:         networkenforcement.ResultOutcomeSuccess,
			EnforcementMode: networkenforcement.ResultModeFirewall,
			Mechanisms:      []networkenforcement.EnforcementMechanism{networkenforcement.EnforcementMechanismFirewall},
			Operations:      []string{"firewall_apply"},
			Capability: &networkenforcement.ResultCapability{
				Supported:                  true,
				Modes:                      []networkenforcement.ResultMode{networkenforcement.ResultModeFirewall},
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: networkenforcement.ResultReasonApplied,
		},
	}
	runner := &fakeHostProcessRunner{}
	poller := &fakeBootAcceptancePoller{}

	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               liveDriverValidConfig(),
		BaseStateDir:         filepath.Join(t.TempDir(), "firecracker-state"),
		CapabilityDetector:   liveDriverAvailableDetector{},
		HostProcessRunner:    runner,
		BootAcceptancePoller: poller,
		NetworkEnforcement: &microvm.NetworkEnforcementPlanning{
			Request: request,
			Planner: planner,
			Adapter: adapter,
		},
	})
	if err != nil {
		t.Fatalf("NewLiveDriver() error = %v, want nil", err)
	}

	if plannerCalls != 1 || adapter.calls != 1 {
		t.Fatalf("planner calls=%d adapter calls=%d, want one explicit planning pass", plannerCalls, adapter.calls)
	}
	if runner.calls != 0 || poller.calls != 0 {
		t.Fatalf("live calls before Start = runner:%d poller:%d, want none", runner.calls, poller.calls)
	}
	metadata := driver.Metadata().NetworkEnforcement
	if metadata == nil || metadata.Plan == nil || metadata.Result == nil {
		t.Fatalf("NetworkEnforcement = %#v, want explicit live-driver planning metadata", metadata)
	}
	if metadata.Plan.Source != string(networkenforcement.PlanSourceMicroVM) ||
		metadata.Result.AdapterID != "fake-firecrackerhost-network-adapter" ||
		metadata.Result.EnforcementMode != string(networkenforcement.ResultModeFirewall) {
		t.Fatalf("NetworkEnforcement metadata = %#v, want explicit firewall capability", metadata)
	}
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

type recordingFirecrackerHostNetworkEnforcementAdapter struct {
	calls  int
	plan   networkenforcement.Plan
	result networkenforcement.Result
}

func (adapter *recordingFirecrackerHostNetworkEnforcementAdapter) EnforceNetwork(_ context.Context, plan networkenforcement.SanitizedPlan) networkenforcement.Result {
	adapter.calls++
	adapter.plan = plan.Plan()
	result := adapter.result
	if result.PlanID == "" {
		result.PlanID = adapter.plan.ID
	}
	if result.PolicySnapshot == nil {
		result.PolicySnapshot = adapter.plan.PolicySnapshot
	}
	return result
}

func firecrackerHostNetworkEnforcementPlanRequest() networkenforcement.PlanRequest {
	return networkenforcement.PlanRequest{
		ID:        "network-plan-firecrackerhost",
		Source:    networkenforcement.PlanSourceMicroVM,
		Operation: "prepare_network",
		PolicySnapshot: &networkenforcement.PolicySnapshotIdentity{
			ID:     "policy-snapshot-firecrackerhost",
			Preset: networkenforcement.PolicyPresetDenyByDefault,
		},
		RequestedPolicy: networkenforcement.RequestedNetworkPosture{
			Preset:            networkenforcement.PolicyPresetDenyByDefault,
			PrivateNetwork:    networkenforcement.PostureBlock,
			MetadataEndpoint:  networkenforcement.PostureBlock,
			FirewallMode:      networkenforcement.FirewallIntentModeApply,
			FirewallMechanism: networkenforcement.EnforcementMechanismFirewall,
		},
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

func assertLiveDriverUnsupportedGuestOperation(t *testing.T, err error, operation string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s error = nil, want unavailable guest transport capability", operation)
	}
	var operationErr *microvm.OperationError
	if !errors.As(err, &operationErr) {
		t.Fatalf("%s error = %T %v, want *microvm.OperationError", operation, err, err)
	}
	if operationErr.Code != microvm.ErrorCodeUnavailableCapability {
		t.Fatalf("%s error code = %q, want %q", operation, operationErr.Code, microvm.ErrorCodeUnavailableCapability)
	}
	if operationErr.Operation != operation {
		t.Fatalf("%s error operation = %q, want %q", operation, operationErr.Operation, operation)
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

func assertLiveDriverErrorDoesNotLeak(t *testing.T, err error, forbidden ...string) {
	t.Helper()
	publicText := strings.ToLower(err.Error())
	for _, fragment := range forbidden {
		if strings.Contains(publicText, strings.ToLower(fragment)) {
			t.Fatalf("error leaked %q in %q", fragment, publicText)
		}
	}
}

type fakeLiveGuestTransport struct {
	execCalls      int
	copyInCalls    int
	copyOutCalls   int
	execRequest    firecracker.GuestExecRequest
	copyInRequest  firecracker.GuestCopyRequest
	copyOutRequest firecracker.GuestCopyRequest
	result         *sandboxruntime.ExecResult
}

func (transport *fakeLiveGuestTransport) Exec(_ context.Context, req firecracker.GuestExecRequest) (*sandboxruntime.ExecResult, error) {
	transport.execCalls++
	transport.execRequest = req
	if transport.result != nil {
		return transport.result, nil
	}
	return &sandboxruntime.ExecResult{ExitCode: 0}, nil
}

func (transport *fakeLiveGuestTransport) CopyIn(_ context.Context, req firecracker.GuestCopyRequest) error {
	transport.copyInCalls++
	transport.copyInRequest = req
	return nil
}

func (transport *fakeLiveGuestTransport) CopyOut(_ context.Context, req firecracker.GuestCopyRequest) error {
	transport.copyOutCalls++
	transport.copyOutRequest = req
	return nil
}
