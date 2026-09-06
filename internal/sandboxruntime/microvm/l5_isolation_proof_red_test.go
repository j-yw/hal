package microvm

import (
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL5SyntheticTargetLabelsCannotManufactureIsolationProof(t *testing.T) {
	target := &sandboxruntime.Target{
		ID:     "fc-forged",
		Status: sandbox.StatusRunning,
		Runtime: sandboxruntime.RuntimeState{
			Driver:         sandboxruntime.DriverMicroVM,
			RuntimeID:      "fc-forged",
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			Metadata: &sandboxruntime.RuntimeMetadata{
				ProcessLaunch: &sandboxruntime.RuntimeProcessLaunchMetadata{
					State: "accepted",
				},
				GuestReadiness: sandboxruntime.NewRuntimeGuestReadinessMetadata(
					sandboxruntime.RuntimeGuestReadinessStateReady,
					"vsock",
					[]string{"protocol_v1", "runtime_bound", "probe_ok"},
				),
			},
		},
	}
	proof := ProjectMicroVMIsolationProofMetadata(target)
	if sandbox.SandboxMicroVMIsolationProofProvesActiveVMIsolation(proof) {
		t.Fatalf("synthetic caller-carried target produced active isolation proof: %#v", proof)
	}
}
