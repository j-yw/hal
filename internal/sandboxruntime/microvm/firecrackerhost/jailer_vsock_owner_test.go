//go:build linux

package firecrackerhost

import (
	"context"
	"os"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

// This reproduces the existing bridge ignoring the strict owner recorded by
// the manager. No chown or alternate-UID process is needed: caller-owned socket
// bytes must not satisfy a deliberately different tracked strict UID.
func TestJailerVsockOwnerRejectsCallerOwnedSocketForDifferentTrackedUID(t *testing.T) {
	fixture := newL5ProductionBridgeFixture(t, os.Getpid())
	state, err := statPrivateFirecrackerStateDir(fixture.paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	state.uid = uint32(os.Geteuid()) + 1
	manager := fixture.bridge.lifecycle
	fixture.handle = manager.storeStrictJailerProcess(fixture.process, fixture.paths, state, true, state.uid)
	listener := l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
	release := make(chan struct{})
	close(release)
	go func() { _ = l5ServeReadyBridge(listener, release) }()
	_, generation, err := fixture.bridge.ActivateSession(context.Background(), firecracker.ProductionVsockSessionRequest{
		Handle: fixture.handle, RuntimeID: "fc-production-test", SocketPath: fixture.paths.VsockSocketPath,
	})
	if err == nil || generation != "" {
		t.Fatalf("ActivateSession() = generation %q, error %v; want strict owner rejection", generation, err)
	}
}
