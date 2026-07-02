package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

// Phase 34 contract tests are expected to fail against the Phase 33
// live-start adapter. They become passing tests as US-005, US-006, US-008, and
// US-009 add complete opt-in live boot options, boot rendering, host-side
// acceptance waiting, and cleanup manager plumbing.

func TestPhase34DefaultBackendOptionsKeepLiveBootPlanningOnly(t *testing.T) {
	started, err := phase34CreateAndStart(t, NewBackend(BackendOptions{}), validMicroVMConfig(), "phase34-default")
	if err != nil {
		t.Fatalf("Start() error = %v, want default BackendOptions{} to stay planning-only", err)
	}

	assertPhase34PlanningOnlyStart(t, started)
	if started.Runtime.Metadata.OperationPlan == nil || started.Runtime.Metadata.OperationPlan.ProcessDescriptor == nil {
		t.Fatalf("operation plan = %#v, want planning metadata without live boot", started.Runtime.Metadata.OperationPlan)
	}
}

func TestPhase34LiveBootRequiresCompleteOptionsBeforeProcessStart(t *testing.T) {
	deps := &phase34LiveBootDependencyProbe{}
	backend := NewBackend(BackendOptions{
		BaseStateDir:   firecrackerPathTestBase("phase34-incomplete-live"),
		ProcessAdapter: ProcessLaunchAdapter{Starter: deps},
		LiveStart:      true,
	})

	started, err := phase34CreateAndStart(t, backend, validMicroVMConfig(), "phase34-incomplete-live")

	deps.assertNoLiveCalls(t)
	assertPhase34IncompleteLiveBootResult(t, started, err)
}

func TestPhase34LiveBootMissingProcessBoundaryReturnsPlanningOrConfigError(t *testing.T) {
	backend := NewBackend(BackendOptions{
		BaseStateDir: firecrackerPathTestBase("phase34-missing-process-boundary"),
		LiveStart:    true,
	})

	started, err := phase34CreateAndStart(t, backend, validMicroVMConfig(), "phase34-missing-process-boundary")

	assertPhase34IncompleteLiveBootResult(t, started, err)
}

func phase34CreateAndStart(t *testing.T, backend *Backend, config microvm.Config, name string) (*sandboxruntime.Target, error) {
	t.Helper()

	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    config,
		Name:      name,
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    *created,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}
	return controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    config,
		Target:    *created,
	})
}

func assertPhase34IncompleteLiveBootResult(t *testing.T, target *sandboxruntime.Target, err error) {
	t.Helper()

	if err != nil {
		assertPhase34SanitizedLiveBootConfigError(t, err)
		return
	}
	assertPhase34PlanningOnlyStart(t, target)
}

func assertPhase34PlanningOnlyStart(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()

	if target == nil {
		t.Fatal("Start() target = nil, want planning-only target")
	}
	if target.Status != sandbox.StatusStopped {
		t.Fatalf("Start() status = %q, want %q for planning-only Firecracker start", target.Status, sandbox.StatusStopped)
	}
	if target.Runtime.Metadata == nil {
		t.Fatal("runtime metadata = nil, want Firecracker planning metadata")
	}
	if target.Runtime.Metadata.ProcessLaunch == nil {
		t.Fatal("ProcessLaunch = nil, want planning-only process-boundary metadata")
	}
	if target.Runtime.Metadata.ProcessLaunch.State != string(ProcessLaunchStateBoundaryAvailable) {
		t.Fatalf("ProcessLaunch.State = %q, want planning-only %q", target.Runtime.Metadata.ProcessLaunch.State, ProcessLaunchStateBoundaryAvailable)
	}
	if target.Runtime.Metadata.ProcessLaunch.ProcessID != "" || target.Runtime.Metadata.ProcessLaunch.ProcessIDSource != "" {
		t.Fatalf("ProcessLaunch exposes live process identity for planning-only start: %#v", target.Runtime.Metadata.ProcessLaunch)
	}
}

func assertPhase34SanitizedLiveBootConfigError(t *testing.T, err error) {
	t.Helper()

	var opErr *microvm.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("live boot error type = %T, want *microvm.OperationError", err)
	}
	if opErr.Code != microvm.ErrorCodeInvalidConfig {
		t.Fatalf("live boot error code = %q, want sanitized configuration error %q", opErr.Code, microvm.ErrorCodeInvalidConfig)
	}
	if strings.TrimSpace(opErr.Operation) == "" {
		t.Fatalf("live boot error operation is empty: %#v", opErr)
	}

	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(live boot error) error = %v", marshalErr)
	}
	publicText := err.Error() + " " + string(encoded)
	for _, unsafe := range []string{
		"/Users/alice",
		"private",
		"firecracker.sock",
		"firecracker-config.json",
		"firecracker.log",
		"firecracker.metrics",
		"vmlinux",
		"rootfs.ext4",
		"ghp_secret",
		"OPENAI_API_KEY",
		"SECRET_TOKEN",
		"pid=",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("live boot error leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}

type phase34LiveBootDependencyProbe struct {
	startCalls   int
	waitCalls    int
	cleanupCalls int
}

func (probe *phase34LiveBootDependencyProbe) StartProcess(context.Context, ProcessRunnerStartRequest) (ProcessHandleMetadata, error) {
	probe.startCalls++
	return ProcessHandleMetadata{ID: "phase34-handle", Source: "phase34-fake"}, nil
}

func (probe *phase34LiveBootDependencyProbe) WaitForBootAcceptance(context.Context, ProcessHandleMetadata) error {
	probe.waitCalls++
	return nil
}

func (probe *phase34LiveBootDependencyProbe) CleanupLiveBoot(context.Context, ProcessHandleMetadata) error {
	probe.cleanupCalls++
	return nil
}

func (probe *phase34LiveBootDependencyProbe) assertNoLiveCalls(t *testing.T) {
	t.Helper()

	if probe.startCalls != 0 || probe.waitCalls != 0 || probe.cleanupCalls != 0 {
		t.Fatalf("live dependency calls = start:%d wait:%d cleanup:%d, want none for incomplete live boot options", probe.startCalls, probe.waitCalls, probe.cleanupCalls)
	}
}
