package firecracker

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestPhase38DefaultPlanningBackendDoesNotExposeLiveGuestTransportMetadata(t *testing.T) {
	backend := NewBackend(BackendOptions{})
	created, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Operation: microvm.OperationCreate,
		Config:    validMicroVMConfig(),
		Name:      "phase38-default-transport",
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	assertFirecrackerRuntimeMetadataDoesNotClaimUnsupportedLiveCapabilities(t, created)
	assertPhase38RuntimeMetadataDoesNotClaimLiveGuestTransport(t, "created target", created.Runtime.Metadata)

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
	assertFirecrackerRuntimeMetadataDoesNotClaimUnsupportedLiveCapabilities(t, started)
	assertPhase38RuntimeMetadataDoesNotClaimLiveGuestTransport(t, "started target", started.Runtime.Metadata)
}

func TestPhase38PlanningBackendWithInjectedGuestTransportDoesNotDelegateWithoutLiveStart(t *testing.T) {
	transport := &phase38RecordingGuestTransport{result: &sandboxruntime.ExecResult{ExitCode: 99}}
	controller := phase38ExecController(t, NewBackend(BackendOptions{GuestTransport: transport}), phase38ExecTarget(&sandboxruntime.RuntimeGuestReadinessMetadata{
		State: sandboxruntime.RuntimeGuestReadinessStateReady,
	}))

	_, err := controller.Exec(context.Background(), microvm.ControllerExecRequest{
		Operation: microvm.OperationExec,
		Target:    phase38ExecTarget(&sandboxruntime.RuntimeGuestReadinessMetadata{State: sandboxruntime.RuntimeGuestReadinessStateReady}),
		Args:      []string{"sh", "-lc", "true"},
	})
	assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationExec)

	err = controller.CopyIn(context.Background(), microvm.ControllerCopyRequest{
		Operation:       microvm.OperationCopyIn,
		Target:          phase38ExecTarget(&sandboxruntime.RuntimeGuestReadinessMetadata{State: sandboxruntime.RuntimeGuestReadinessStateReady}),
		SourcePath:      "/safe/input.txt",
		DestinationPath: "/workspace/input.txt",
	})
	assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationCopyIn)

	err = controller.CopyOut(context.Background(), microvm.ControllerCopyRequest{
		Operation:       microvm.OperationCopyOut,
		Target:          phase38ExecTarget(&sandboxruntime.RuntimeGuestReadinessMetadata{State: sandboxruntime.RuntimeGuestReadinessStateReady}),
		SourcePath:      "/workspace/output.txt",
		DestinationPath: "/safe/output.txt",
	})
	assertFirecrackerUnsupportedOperationError(t, err, microvm.OperationCopyOut)

	if transport.execCalls != 0 || transport.copyInCalls != 0 || transport.copyOutCalls != 0 {
		t.Fatalf("guest transport calls = exec:%d copyIn:%d copyOut:%d, want none without LiveStart", transport.execCalls, transport.copyInCalls, transport.copyOutCalls)
	}
}

func assertPhase38RuntimeMetadataDoesNotClaimLiveGuestTransport(t *testing.T, label string, metadata *sandboxruntime.RuntimeMetadata) {
	t.Helper()
	if metadata == nil {
		t.Fatalf("%s metadata = nil, want default Firecracker metadata", label)
	}
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(%s metadata) error = %v", label, err)
	}
	publicText := strings.ToLower(string(encoded))
	for _, marker := range []string{
		"guesttransport",
		"guest_transport",
		"liveguesttransport",
		"live_guest_transport",
		"guestexec",
		"guest_exec",
		"guestcopy",
		"guest_copy",
		"networkproxy",
		"network_proxy",
		"credentialbroker",
		"credential_broker",
		"credentialproxy",
		"credential_proxy",
		"secure_by_default",
		"production_secure",
	} {
		if strings.Contains(publicText, marker) {
			t.Fatalf("%s metadata claims unsupported marker %q in %s", label, marker, publicText)
		}
	}
}
