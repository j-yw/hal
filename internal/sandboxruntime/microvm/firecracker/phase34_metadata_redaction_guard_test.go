package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestPhase34LiveBootMissingSafetyOptionsDoesNotLaunchAndKeepsPublicOutputRedacted(t *testing.T) {
	fixture := phase34NewSensitiveRedactionFixture(t)
	deps := &phase34MetadataRedactionProbe{
		handle: ProcessHandleMetadata{
			ID:     "phase34-live-handle",
			Source: "phase34-fake",
		},
	}
	backend := NewBackend(BackendOptions{
		BaseStateDir:   fixture.StateRoot,
		ProcessAdapter: ProcessLaunchAdapter{Starter: deps},
		LiveStart:      true,
	})

	started, err := phase34CreateAndStart(t, backend, fixture.Config, fixture.UnsafeTargetName)

	if deps.startCalls != 0 {
		t.Fatalf("starter calls = %d, want no process launch before complete live boot safety options", deps.startCalls)
	}
	if err == nil {
		assertPhase34PlanningOnlyStart(t, started)
		paths := fixture.PathsForRuntime(t, started.Runtime.RuntimeID)
		publicText := phase34PublicJSON(t, started)
		phase34AssertPublicTextRedacted(t, "incomplete live boot planning metadata", publicText, fixture.UnsafeFragments(&paths)...)
		phase34AssertPublicTextRedacted(t, "incomplete live boot planning metadata", publicText, phase34UnsupportedLiveClaimMarkers()...)
		return
	}

	if started != nil {
		t.Fatalf("Start() target = %#v, want nil when live boot safety options return an error", started)
	}
	phase34AssertPublicErrorRedacted(t, "incomplete live boot public error", err, fixture.UnsafeFragments(nil)...)

	var opErr *microvm.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("Start() error type = %T, want *microvm.OperationError", err)
	}
	if opErr.Code != microvm.ErrorCodeInvalidConfig {
		t.Fatalf("OperationError.Code = %q, want %q", opErr.Code, microvm.ErrorCodeInvalidConfig)
	}
}

func TestPhase34LiveBootPublicMetadataRedactsSensitiveInputsAndUnsupportedClaims(t *testing.T) {
	fixture := phase34NewSensitiveRedactionFixture(t)
	deps := &phase34MetadataRedactionProbe{
		handle: ProcessHandleMetadata{
			ID:     "pid:/Users/alice/private/firecracker.sock",
			Source: "env:OPENAI_API_KEY=sk-phase34-secret",
		},
	}
	backend := NewBackend(BackendOptions{
		BaseStateDir:         fixture.StateRoot,
		ProcessAdapter:       ProcessLaunchAdapter{Starter: deps},
		BootAcceptanceWaiter: deps,
		LiveProcessManager:   deps,
		LiveStart:            true,
	})

	started, err := phase34CreateAndStart(t, backend, fixture.Config, fixture.UnsafeTargetName)
	if err != nil {
		t.Fatalf("Start() error = %v, want redaction-safe public metadata for fake accepted live boot", err)
	}
	if deps.startCalls != 1 {
		t.Fatalf("starter calls = %d, want one explicit fake live boot start", deps.startCalls)
	}
	if started == nil {
		t.Fatal("Start() target = nil, want redaction-safe public metadata")
	}

	paths := fixture.PathsForRuntime(t, started.Runtime.RuntimeID)
	publicText := phase34PublicJSON(t, started)
	phase34AssertPublicTextRedacted(t, "live boot public metadata", publicText, fixture.UnsafeFragments(&paths)...)
	phase34AssertPublicTextRedacted(t, "live boot public metadata", publicText, phase34UnsupportedLiveClaimMarkers()...)
	phase34AssertPublicMetadataUsesOnlySafeProcessIdentity(t, started)
	assertFirecrackerRuntimeMetadataDoesNotClaimUnsupportedLiveCapabilities(t, started)
}

func TestPhase34LiveBootPublicJSONErrorRedactsRunnerDetails(t *testing.T) {
	fixture := phase34NewSensitiveRedactionFixture(t)
	backend := NewBackend(BackendOptions{
		BaseStateDir: fixture.StateRoot,
		LiveStart:    true,
	})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    fixture.Config,
		Name:      fixture.UnsafeTargetName,
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	paths := fixture.PathsForRuntime(t, created.Runtime.RuntimeID)
	deps := &phase34MetadataRedactionProbe{
		startErr: errors.New(fmt.Sprintf(
			"firecracker runner failed stateDir=%s apiSocket=%s kernel=%s rootfs=%s argv=%q endpoint=%s env OPENAI_API_KEY=%s SECRET_TOKEN=%s token=%s",
			paths.StateDir,
			paths.APISocketPath,
			fixture.Config.KernelImagePath,
			fixture.Config.RootfsPath,
			fixture.RawArgv(paths),
			fixture.Endpoint,
			fixture.EnvValue,
			fixture.SecretValue,
			fixture.TokenValue,
		)),
	}
	backend = NewBackend(BackendOptions{
		BaseStateDir:         fixture.StateRoot,
		ProcessAdapter:       ProcessLaunchAdapter{Starter: deps},
		BootAcceptanceWaiter: deps,
		LiveProcessManager:   deps,
		LiveStart:            true,
	})
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Config:    fixture.Config,
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}

	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    fixture.Config,
		Target:    *created,
	})

	if err == nil {
		t.Fatal("Start() error = nil, want fake runner failure")
	}
	if started != nil {
		t.Fatalf("Start() target = %#v, want nil after runner failure", started)
	}
	if deps.startCalls != 1 {
		t.Fatalf("starter calls = %d, want one explicit fake live boot start before runner failure", deps.startCalls)
	}
	phase34AssertPublicErrorRedacted(t, "runner failure public error", err, fixture.UnsafeFragments(&paths)...)
}

type phase34SensitiveRedactionFixture struct {
	Config           microvm.Config
	StateRoot        string
	Endpoint         string
	EnvValue         string
	SecretValue      string
	TokenValue       string
	UnsafeTargetName string
}

func phase34NewSensitiveRedactionFixture(t *testing.T) phase34SensitiveRedactionFixture {
	t.Helper()

	root := filepath.Join(t.TempDir(), "Users", "alice", "private", "phase34-sensitive")
	config := validMicroVMConfig()
	config.HypervisorPath = filepath.Join(root, "bin", "firecracker")
	config.KernelImagePath = filepath.Join(root, "images", "vmlinux")
	config.RootfsPath = filepath.Join(root, "images", "rootfs.ext4")
	config.InitrdPath = filepath.Join(root, "images", "initrd.img")
	return phase34SensitiveRedactionFixture{
		Config:           config,
		StateRoot:        filepath.Join(root, "state", "api-sockets"),
		Endpoint:         "https://boot-secret.example.test:8443/api",
		EnvValue:         "sk-phase34-secret",
		SecretValue:      "hunter2-phase34-secret",
		TokenValue:       "ghp_phase34secret",
		UnsafeTargetName: "phase34-/Users/alice/private?token=ghp_phase34secret",
	}
}

func (fixture phase34SensitiveRedactionFixture) PathsForRuntime(t *testing.T, runtimeID string) PathPlan {
	t.Helper()

	paths, err := PlanPaths(PathPlanRequest{
		RuntimeID:    runtimeID,
		BaseStateDir: fixture.StateRoot,
	})
	if err != nil {
		t.Fatalf("PlanPaths() error = %v, want nil", err)
	}
	return paths
}

func (fixture phase34SensitiveRedactionFixture) RawArgv(paths PathPlan) string {
	return strings.Join([]string{
		fixture.Config.HypervisorPath,
		"--api-sock",
		paths.APISocketPath,
		"--config-file",
		paths.ConfigPath,
		"--log-path",
		paths.LogPath,
		"--metrics-path",
		paths.MetricsPath,
	}, " ")
}

func (fixture phase34SensitiveRedactionFixture) UnsafeFragments(paths *PathPlan) []string {
	fragments := []string{
		fixture.StateRoot,
		fixture.Config.HypervisorPath,
		fixture.Config.KernelImagePath,
		fixture.Config.RootfsPath,
		fixture.Endpoint,
		fixture.EnvValue,
		fixture.SecretValue,
		fixture.TokenValue,
		"OPENAI_API_KEY",
		"SECRET_TOKEN",
		"boot-secret.example.test",
		"8443",
		"sk-phase34-secret",
		"hunter2-phase34-secret",
		"ghp_phase34secret",
	}
	if fixture.Config.InitrdPath != "" {
		fragments = append(fragments, fixture.Config.InitrdPath)
	}
	if paths != nil {
		fragments = append(fragments,
			paths.StateDir,
			paths.APISocketPath,
			paths.ConfigPath,
			paths.LogPath,
			paths.MetricsPath,
			fixture.RawArgv(*paths),
			"--api-sock "+paths.APISocketPath,
			"--config-file "+paths.ConfigPath,
			"--log-path "+paths.LogPath,
			"--metrics-path "+paths.MetricsPath,
		)
	}
	return fragments
}

type phase34MetadataRedactionProbe struct {
	handle   ProcessHandleMetadata
	startErr error

	startCalls   int
	waitCalls    int
	cleanupCalls int
	stopCalls    int
	deleteCalls  int
}

var _ ProcessStarter = (*phase34MetadataRedactionProbe)(nil)
var _ BootAcceptanceWaiter = (*phase34MetadataRedactionProbe)(nil)
var _ LiveProcessManager = (*phase34MetadataRedactionProbe)(nil)

func (probe *phase34MetadataRedactionProbe) StartProcess(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
	probe.startCalls++
	if probe.startErr != nil {
		return ProcessHandleMetadata{}, probe.startErr
	}
	return probe.handle, nil
}

func (probe *phase34MetadataRedactionProbe) WaitForBootAcceptance(context.Context, BootAcceptanceRequest) (BootAcceptanceResult, error) {
	probe.waitCalls++
	return BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	}, nil
}

func (probe *phase34MetadataRedactionProbe) CleanupLiveProcess(context.Context, LiveProcessRequest) error {
	probe.cleanupCalls++
	return nil
}

func (probe *phase34MetadataRedactionProbe) StopLiveProcess(context.Context, LiveProcessRequest) error {
	probe.stopCalls++
	return nil
}

func (probe *phase34MetadataRedactionProbe) DeleteLiveProcess(context.Context, LiveProcessRequest) error {
	probe.deleteCalls++
	return nil
}

func phase34AssertPublicMetadataUsesOnlySafeProcessIdentity(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()

	if target == nil || target.Runtime.Metadata == nil || target.Runtime.Metadata.ProcessLaunch == nil {
		t.Fatalf("target process launch metadata = %#v, want safe public launch metadata", target)
	}
	launch := target.Runtime.Metadata.ProcessLaunch
	for name, value := range map[string]string{
		"processId":       launch.ProcessID,
		"processIdSource": launch.ProcessIDSource,
	} {
		if value == "" {
			continue
		}
		if !safeLaunchTokenForTest(value) {
			t.Fatalf("%s = %q, want strict redaction-safe token", name, value)
		}
	}
}

func phase34AssertPublicErrorRedacted(t *testing.T, label string, err error, unsafeFragments ...string) {
	t.Helper()

	if err == nil {
		t.Fatalf("%s error = nil, want public error to inspect", label)
	}
	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(%s) error = %v", label, marshalErr)
	}
	phase34AssertPublicTextRedacted(t, label, err.Error()+" "+string(encoded), unsafeFragments...)
}

func phase34PublicJSON(t *testing.T, value any) string {
	t.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(public value) error = %v", err)
	}
	return string(encoded)
}

func phase34AssertPublicTextRedacted(t *testing.T, label, publicText string, unsafeFragments ...string) {
	t.Helper()

	for _, unsafe := range unsafeFragments {
		if strings.TrimSpace(unsafe) == "" {
			continue
		}
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("%s leaked unsafe fragment %q in %s", label, unsafe, publicText)
		}
	}
}

func phase34UnsupportedLiveClaimMarkers() []string {
	return []string{
		"guest_ready",
		"guestReady",
		"vm_boot_ready",
		"boot_ready",
		"guest_exec",
		"guestExec",
		"exec_support",
		"copy_support",
		"file_copy",
		"docker",
		"podman",
		"network_enforced",
		"networking_enforcement",
		"network_policy_enforced",
		"deny_by_default",
		"workspace_sync",
		"workspaceSync",
		"sync_out",
		"credential_delivery",
		"credentialDelivery",
		"credential_proxy",
	}
}
