package microvm

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestUS002ProjectMicroVMIsolationProofRequiresRunningVMRuntimeEvidence(t *testing.T) {
	tests := []struct {
		name      string
		target    *sandboxruntime.Target
		wantReady bool
	}{
		{
			name: "running microvm target with guest readiness",
			target: &sandboxruntime.Target{
				ID:     "microvm-us002",
				Name:   "microvm-us002",
				Status: sandbox.StatusRunning,
				Runtime: sandboxruntime.RuntimeState{
					Driver:         sandboxruntime.DriverMicroVM,
					RuntimeID:      "microvm-us002-runtime",
					IsolationLevel: sandbox.SandboxIsolationLevelVM,
					Metadata: &sandboxruntime.RuntimeMetadata{
						ProcessLaunch: &sandboxruntime.RuntimeProcessLaunchMetadata{
							State: "accepted",
						},
						GuestReadiness: &sandboxruntime.RuntimeGuestReadinessMetadata{
							State: sandboxruntime.RuntimeGuestReadinessStateReady,
						},
					},
				},
			},
			wantReady: true,
		},
		{
			name: "microvm posture without running status is diagnostic only",
			target: &sandboxruntime.Target{
				ID:     "microvm-us002-planned",
				Name:   "microvm-us002-planned",
				Status: "planned",
				Runtime: sandboxruntime.RuntimeState{
					Driver:         sandboxruntime.DriverMicroVM,
					RuntimeID:      "microvm-us002-runtime",
					IsolationLevel: sandbox.SandboxIsolationLevelVM,
				},
			},
		},
		{
			name: "container runtime cannot prove microvm isolation",
			target: &sandboxruntime.Target{
				ID:     "podman-us002",
				Name:   "podman-us002",
				Status: sandbox.StatusRunning,
				Runtime: sandboxruntime.RuntimeState{
					Driver:         sandboxruntime.DriverRootlessPodman,
					RuntimeID:      "podman-us002-runtime",
					IsolationLevel: sandbox.SandboxIsolationLevelContainer,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proof := ProjectMicroVMIsolationProofMetadata(tt.target)
			if got := sandbox.SandboxMicroVMIsolationProofProvesActiveVMIsolation(proof); got != tt.wantReady {
				t.Fatalf("SandboxMicroVMIsolationProofProvesActiveVMIsolation() = %t, want %t: %#v", got, tt.wantReady, proof)
			}

			encoded, err := json.Marshal(proof)
			if err != nil {
				t.Fatalf("Marshal(proof) error = %v", err)
			}
			for _, unsafe := range []string{
				"/tmp",
				".sock",
				"provider",
				"firecracker",
				"token",
				"secret",
				"://",
			} {
				if strings.Contains(string(encoded), unsafe) {
					t.Fatalf("microvm isolation proof leaked unsafe fragment %q in %s", unsafe, encoded)
				}
			}
		})
	}
}
