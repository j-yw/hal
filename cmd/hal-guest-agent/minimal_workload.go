package main

import (
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/vsock"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestnetwork"
)

// Construction-only injection: the selected path owns its actual transport and
// server. No request handler, proof result, or serving algorithm is injectable.
type minimalGuestAgentDependencies struct {
	lookupEnvironment   func(string) (string, bool)
	listen              func() (vsock.Listener, error)
	newBackend          func(server.LinuxBackendOptions) (server.Backend, error)
	newNetworkVerifier  func(guestnetwork.LinuxNetworkIsolationVerifierOptions) (server.NetworkIsolationVerifier, error)
	newWorkloadVerifier func(server.LinuxIsolationVerifierOptions) (server.WorkloadIsolationVerifier, error)
}

// Compiling RED: retain the existing selected bootstrap behavior. The next
// implementation must replace this delegation, not add an alternate test server.
func runMinimalGuestAgentWithDependencies(ctx context.Context, line string, dependencies minimalGuestAgentDependencies) error {
	return runMinimalGuestAgentWithListener(ctx, line, dependencies.listen)
}
