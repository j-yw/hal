package firecracker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestPhase37DefaultPlanningBackendRemainsInertAndUnsupported(t *testing.T) {
	tests := []struct {
		name    string
		options BackendOptions
		waiter  *fakeGuestReadinessWaiter
		adapter *fakeProcessAdapter
	}{
		{
			name: "zero value backend options",
		},
		{
			name:    "guest readiness waiter without live start",
			waiter:  &fakeGuestReadinessWaiter{},
			adapter: &fakeProcessAdapter{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := tt.options
			if tt.waiter != nil {
				options.GuestReadinessWaiter = tt.waiter
			}
			if tt.adapter != nil {
				options.ProcessAdapter = tt.adapter
			}
			backend := NewBackend(options)
			if backend.liveStart {
				t.Fatal("NewBackend(default/planning options) enabled liveStart, want planning-only")
			}

			created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
				Operation: microvm.OperationCreate,
				Config:    validMicroVMConfig(),
				Name:      "phase37-default-planning",
			})
			if err != nil {
				t.Fatalf("Create() error = %v, want nil", err)
			}
			assertPhase37PlanningTargetDoesNotClaimReadinessOrIsolation(t, created)

			controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
				Operation: microvm.OperationStart,
				Config:    validMicroVMConfig(),
				Target:    *created,
			})
			if err != nil {
				t.Fatalf("Controller() error = %v, want nil", err)
			}
			started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
				Operation: microvm.OperationStart,
				Config:    validMicroVMConfig(),
				Target:    *created,
			})
			if err != nil {
				t.Fatalf("Start() error = %v, want planning-only nil error", err)
			}
			if started.Status != sandbox.StatusStopped {
				t.Fatalf("Start() status = %q, want %q for planning-only backend", started.Status, sandbox.StatusStopped)
			}
			if started.Runtime.Metadata == nil || started.Runtime.Metadata.OperationPlan == nil {
				t.Fatalf("Start() metadata = %#v, want planning operation metadata", started.Runtime.Metadata)
			}
			assertPhase37PlanningTargetDoesNotClaimReadinessOrIsolation(t, started)
			assertPhase37DefaultUnsupportedOperations(t, controller, *started)

			if tt.waiter != nil && tt.waiter.calls != 0 {
				t.Fatalf("guest readiness waiter calls = %d, want none without LiveStart", tt.waiter.calls)
			}
			if tt.adapter != nil {
				if tt.adapter.prepareCalls != 1 {
					t.Fatalf("adapter prepare calls = %d, want one planning call", tt.adapter.prepareCalls)
				}
				if tt.adapter.startCalls != 0 {
					t.Fatalf("adapter start calls = %d, want none without LiveStart", tt.adapter.startCalls)
				}
			}
		})
	}
}

func assertPhase37PlanningTargetDoesNotClaimReadinessOrIsolation(t *testing.T, target *sandboxruntime.Target) {
	t.Helper()
	if target == nil {
		t.Fatal("target = nil, want Firecracker planning target")
	}
	if target.Runtime.IsolationLevel != "" {
		t.Fatalf("backend Runtime.IsolationLevel = %q, want empty backend metadata; driver metadata owns VM isolation", target.Runtime.IsolationLevel)
	}
	assertFirecrackerOwnedRuntimeMetadata(t, target)
	assertFirecrackerRuntimeMetadataDoesNotClaimUnsupportedLiveCapabilities(t, target)

	encoded, err := json.Marshal(target.Runtime.Metadata)
	if err != nil {
		t.Fatalf("Marshal(runtime metadata) error = %v", err)
	}
	publicText := strings.ToLower(string(encoded))
	for _, marker := range []string{
		"guestreadiness",
		"guest_readiness",
		"guest_ready",
		"vm_boot_ready",
		"boot_ready",
	} {
		if strings.Contains(publicText, marker) {
			t.Fatalf("planning/default Firecracker metadata claims readiness marker %q in %s", marker, publicText)
		}
	}
}

func assertPhase37DefaultUnsupportedOperations(t *testing.T, controller microvm.Controller, target sandboxruntime.Target) {
	t.Helper()

	_, err := controller.Exec(context.Background(), microvm.ControllerExecRequest{
		Operation: microvm.OperationExec,
		Target:    target,
		Args:      []string{"sh", "-lc", "true"},
	})
	assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationExec)

	err = controller.CopyIn(context.Background(), microvm.ControllerCopyRequest{
		Operation:       microvm.OperationCopyIn,
		Target:          target,
		SourcePath:      "/safe/input.txt",
		DestinationPath: "/workspace/input.txt",
	})
	assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationCopyIn)

	err = controller.CopyOut(context.Background(), microvm.ControllerCopyRequest{
		Operation:       microvm.OperationCopyOut,
		Target:          target,
		SourcePath:      "/workspace/output.txt",
		DestinationPath: "/safe/output.txt",
	})
	assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationCopyOut)
}
