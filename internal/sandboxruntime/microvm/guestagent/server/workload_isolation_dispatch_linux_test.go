package server

import (
	"context"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"golang.org/x/sys/unix"
)

func TestWorkloadLinuxIsolationConstructorDoesNotInspectExplicitProcess(t *testing.T) {
	for _, selected := range []bool{false, true} {
		process, network := &workloadLinuxBoundary{}, &workloadLinuxBoundary{}
		options := LinuxIsolationVerifierOptions{ProcessBoundary: process, NetworkVerifier: network}
		var err error
		if selected {
			_, err = NewLinuxWorkloadIsolationVerifier(options)
		} else {
			_, err = NewLinuxIsolationVerifier(options)
		}
		if err != nil || len(process.order) != 0 || len(network.order) != 0 {
			t.Fatal("construction invoked process or network inspection")
		}
	}
}

func TestWorkloadLinuxIsolationConcreteDispatchRejectsLateCanceledSnapshot(t *testing.T) {
	// The concrete inspector consumes explicit fake process/network observations.
	// Actual Server.Serve owns lifecycle and the post-inspection context check.
	boundary := &workloadLinuxBoundary{status: validLinuxIsolationStatus(), rawErr: unix.EPERM,
		network: NetworkIsolationProofResult{Status: guestagent.IsolationProofStatusVerified,
			SingleInterface: true, StaticRoutes: true, ProxyReachable: true}}
	verifier, err := NewLinuxWorkloadIsolationVerifier(LinuxIsolationVerifierOptions{ProcessBoundary: boundary, NetworkVerifier: boundary})
	if err != nil {
		t.Fatal("concrete constructor failed")
	}
	backend := &l4FakeBackend{}
	t.Cleanup(func() {
		if backend.closeCalls.Load() != 1 {
			t.Fatal("Serve did not join and close backend exactly once")
		}
	})
	agent := workloadForwardServer(t, backend, verifier)
	if err := agent.PrepareWorkload(context.Background()); err != nil {
		t.Fatal("initial concrete inspection failed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	boundary.cancel, boundary.cancelAfter = cancel, "network"
	request := workloadDispatchExec(t, nil)
	l4RequireResponseCode(t, agent.HandleWorkload(ctx, request), guestagent.ErrorCodeRequestCanceled)
	if agent.isolationProven || backend.execCalls.Load() != 0 || len(boundary.order) != 8 {
		t.Fatal("snapshot from canceled final network callback authorized work")
	}
	boundary.cancelAfter, boundary.network.ProxyReachable = "", false
	l4RequireResponseCode(t, agent.HandleWorkload(context.Background(), request), guestagent.ErrorCodeServerNotReady)
	if agent.isolationProven || backend.execCalls.Load() != 0 || len(boundary.order) != 12 {
		t.Fatal("fresh invalid network inspection authorized work")
	}
	boundary.network.ProxyReachable = true
	response := agent.HandleWorkload(context.Background(), request)
	if guestagent.ValidateExecResponse(l4DecodeResponse[guestagent.ExecResponse](t, response)) != nil || backend.execCalls.Load() != 1 || len(boundary.order) != 16 {
		t.Fatal("fresh valid inspection did not recover the original work permit")
	}
}
