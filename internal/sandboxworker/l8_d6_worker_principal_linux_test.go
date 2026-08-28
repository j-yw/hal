//go:build linux

package sandboxworker

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8D6WorkerServerPassesSameOwnerPrincipalOutOfBand(t *testing.T) {
	request := l8D6WorkerStartRequest(t)
	seed := l8D6RecentLifecycleSeed(t, request)
	seed.PrincipalID = "local-unix-owner"
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8WorkerGuestSessionGeneration(), "helper-generation-worker")
	if err != nil {
		t.Fatal(err)
	}
	preflight := &l8D6WorkerPreflight{
		identity: identity, loss: make(chan sandboxruntime.JobCredentialLoss), cleanup: l8WorkerCleanupProof(t, identity),
		session: &l8D6LifecycleSession{proof: l8D6LifecycleActiveProof(t, identity, 1), cleanup: l8D6LifecycleCleanupProof(t, identity, 2), loss: make(chan sandboxruntime.JobCredentialLoss)},
	}
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(&l8D6WorkerProvider{
		seed: seed, runtime: &l8D6WorkerRuntime{preflight: preflight},
	})
	if err != nil {
		t.Fatal(err)
	}
	authority, err := sandboxruntime.NewAuthenticatedWorkerPrincipalAuthority("worker-peer-authority", l8WorkerV2DaemonGeneration)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewL8DurableService(L8DurableServiceOptions{
		WorkerID: seed.WorkerID, DaemonGeneration: l8WorkerV2DaemonGeneration,
		StateDir: t.TempDir() + "/jobs-v2", Binder: binder, PrincipalAuthority: authority,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	var fallbackCalls atomic.Int32
	server, err := NewL8AuthenticatedServer(L8AuthenticatedServerOptions{
		Server: ServerOptions{
			SocketPath: testWorkerSocketPath(t),
			Handler: RequestHandlerFunc(func(_ context.Context, request Request) Response {
				fallbackCalls.Add(1)
				return unsupportedOperationResponse(request)
			}),
		},
		Service: service, PrincipalID: "local-unix-owner",
	})
	if err != nil {
		t.Fatal(err)
	}
	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)
	response := roundTripWorkerRequest(t, server.socketPath, request)
	if !response.OK || response.JobV2 == nil {
		t.Fatalf("authenticated response = %#v", response)
	}
	if calls := fallbackCalls.Load(); calls != 0 {
		t.Fatalf("ordinary handler calls = %d, want authenticated V2 dispatch only", calls)
	}
	stored, err := service.jobs.store.load(seed.WorkerJobID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.PrincipalID != "local-unix-owner" || stored.CredentialState == nil || stored.CredentialState.Identity == nil {
		t.Fatalf("transport principal was not privately correlated: %#v", stored)
	}
}

func TestL8D6WorkerServerPrincipalInjectionIsExplicitAndPaired(t *testing.T) {
	base := ServerOptions{SocketPath: testWorkerSocketPath(t), Handler: RequestHandlerFunc(func(_ context.Context, request Request) Response {
		return unsupportedOperationResponse(request)
	})}
	binder, err := sandboxruntime.NewJobCredentialRuntimeBinder(&l8D6WorkerProvider{})
	if err != nil {
		t.Fatal(err)
	}
	neutral, err := NewL8Service(binder)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		options L8AuthenticatedServerOptions
	}{
		{name: "missing service", options: L8AuthenticatedServerOptions{Server: base, PrincipalID: "local-unix-owner"}},
		{name: "neutral service", options: L8AuthenticatedServerOptions{Server: base, Service: neutral, PrincipalID: "local-unix-owner"}},
		{name: "missing principal id", options: L8AuthenticatedServerOptions{Server: base, Service: &L8Service{jobs: &jobManagerV2{}, principalAuthority: &sandboxruntime.AuthenticatedWorkerPrincipalAuthority{}}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if server, err := NewL8AuthenticatedServer(tt.options); err == nil || server != nil {
				t.Fatalf("NewL8AuthenticatedServer() = %#v, %v", server, err)
			}
		})
	}
}
