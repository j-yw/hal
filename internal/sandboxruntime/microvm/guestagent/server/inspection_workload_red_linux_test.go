package server

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

// The local optional interface keeps this behavioral RED compiling before the
// method exists. The separate transport RED reaches real encrypted rejection.
func TestSelectedInspectionServerReturnsFreshResultWithoutBackendWork(t *testing.T) {
	boundary := &workloadLinuxBoundary{status: validLinuxIsolationStatus(), rawErr: unix.EPERM,
		network: NetworkIsolationProofResult{Status: guestagent.IsolationProofStatusVerified,
			SingleInterface: true, StaticRoutes: true, ProxyReachable: true}}
	verifier, err := NewLinuxWorkloadIsolationVerifier(LinuxIsolationVerifierOptions{ProcessBoundary: boundary, NetworkVerifier: boundary})
	if err != nil {
		t.Fatal("actual concrete no-request verifier construction failed")
	}
	backend := &l4FakeBackend{}
	t.Cleanup(func() {
		if backend.closeCalls.Load() != 1 {
			t.Error("actual Serve did not join backend Close exactly once")
		}
	})
	agent := workloadForwardServer(t, backend, verifier)
	if agent.PrepareWorkload(context.Background()) != nil || backend.readyCalls.Load() != 1 || len(boundary.order) != 4 || !agent.isolationProven {
		t.Fatal("actual selected Serve and initial preparation prerequisite failed")
	}
	inspection, ok := any(agent).(interface {
		InspectWorkloadIsolation(context.Context) (IsolationProofResult, error)
	})
	if !ok {
		t.Fatal("actual serving Server has no selected result-bearing inspection entry after successful preparation")
	}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := inspection.InspectWorkloadIsolation(context.Background())
		if err != nil || result != l7VerifiedIsolationResult() || !agent.isolationProven {
			t.Fatal("selected inspection did not return the actual fresh complete local result")
		}
		if len(boundary.order) != 4*(attempt+2) || backend.readyCalls.Load() != 1 || backend.execCalls.Load() != 0 || backend.copyInCalls.Load() != 0 || backend.copyOutCalls.Load() != 0 {
			t.Fatal("inspection reused preparation or invoked backend work")
		}
	}
}
