//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"net"
	"os"
	"sync/atomic"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
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

func newJailerVsockOwnerFixture(t *testing.T) l5ProductionBridgeFixture {
	t.Helper()
	fixture := newL5ProductionBridgeFixture(t, os.Getpid())
	state, err := statPrivateFirecrackerStateDir(fixture.paths.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	state.uid = uint32(os.Geteuid()) + 1
	fixture.handle = fixture.bridge.lifecycle.storeStrictJailerProcess(fixture.process, fixture.paths, state, true, state.uid)
	fixture.bridge.ownerChecks = vsockOwnerChecks{
		observe: func(path string) (vsockSocketObservation, error) {
			observed, err := observeVsockSocketOwner(path)
			observed.uid, observed.parentUID = state.uid, state.uid
			return observed, err
		},
		peer: func(conn *net.UnixConn) (vsockPeerIdentity, error) {
			observed, err := observeVsockPeerOwner(conn)
			observed.uid = state.uid
			return observed, err
		},
	}
	return fixture
}

func jailerVsockRequest(fixture l5ProductionBridgeFixture) firecracker.ProductionVsockSessionRequest {
	return firecracker.ProductionVsockSessionRequest{Handle: fixture.handle, RuntimeID: "fc-production-test", SocketPath: fixture.paths.VsockSocketPath}
}

func jailerVsockTarget(fixture l5ProductionBridgeFixture) sandboxruntime.Target {
	return sandboxruntime.Target{ID: "fc-production-test", Runtime: sandboxruntime.RuntimeState{RuntimeID: "fc-production-test", Metadata: &sandboxruntime.RuntimeMetadata{
		ProcessLaunch: &sandboxruntime.RuntimeProcessLaunchMetadata{ProcessID: fixture.handle.ID, ProcessIDSource: fixture.handle.Source},
	}}}
}

func jailerVsockServeReady(t *testing.T, fixture l5ProductionBridgeFixture) net.Listener {
	t.Helper()
	listener := l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
	release := make(chan struct{})
	close(release)
	go func() { _ = l5ServeReadyBridge(listener, release) }()
	return listener
}

func TestJailerVsockOwnerBridgeSuccessAndInvalidation(t *testing.T) {
	for _, name := range []string{"active", "socket replaced", "parent replaced", "wrong parent owner", "wrong socket owner", "wrong generation", "wrong handle", "exited", "closed", "record changed"} {
		t.Run(name, func(t *testing.T) {
			fixture := newJailerVsockOwnerFixture(t)
			listener := jailerVsockServeReady(t, fixture)
			_, generation, err := fixture.bridge.ActivateSession(context.Background(), jailerVsockRequest(fixture))
			if err != nil || generation == "" {
				t.Fatalf("ActivateSession = %q, %v", generation, err)
			}
			t.Cleanup(func() { fixture.bridge.InvalidateSession(jailerVsockRequest(fixture), generation) })
			if !fixture.bridge.SessionActive(jailerVsockRequest(fixture), generation) {
				t.Fatal("strict session not active")
			}
			request := jailerVsockRequest(fixture)
			switch name {
			case "socket replaced":
				listener.(*net.UnixListener).SetUnlinkOnClose(false)
				if err := os.Rename(fixture.paths.VsockSocketPath, fixture.paths.VsockSocketPath+".old"); err != nil {
					t.Fatal(err)
				}
				l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
			case "parent replaced":
				listener.(*net.UnixListener).SetUnlinkOnClose(false)
				if err := os.Rename(fixture.paths.StateDir, fixture.paths.StateDir+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(fixture.paths.StateDir, 0o700); err != nil {
					t.Fatal(err)
				}
				l5ListenBridgeSocket(t, fixture.paths.VsockSocketPath)
			case "wrong parent owner", "wrong socket owner":
				wire := fixture.bridge.session("fc-production-test").wire
				observe := wire.ownerChecks.observe
				wire.ownerChecks.observe = func(path string) (vsockSocketObservation, error) {
					value, err := observe(path)
					if name == "wrong parent owner" {
						value.parentUID++
					} else {
						value.uid++
					}
					return value, err
				}
			case "wrong generation":
				generation += "stale"
			case "wrong handle":
				request.Handle.ID += "stale"
			case "exited":
				fixture.process.stop()
			case "closed":
				fixture.bridge.session("fc-production-test").wire.Close()
			case "record changed":
				manager := fixture.bridge.lifecycle
				manager.mu.Lock()
				manager.processes[fixture.handle.ID].strictRuntimeUID++
				manager.mu.Unlock()
			}
			if got := fixture.bridge.SessionActive(request, generation); got != (name == "active") {
				t.Fatalf("SessionActive = %v", got)
			}
		})
	}
}

func TestJailerVsockOwnerRejectsObservedMismatch(t *testing.T) {
	for _, name := range []string{"socket uid", "parent uid", "socket mode", "parent mode", "socket type", "parent type", "parent inode", "parent device", "peer uid", "peer pid", "observe error", "peer error", "real peer uid"} {
		t.Run(name, func(t *testing.T) {
			fixture := newJailerVsockOwnerFixture(t)
			observe, peer := fixture.bridge.ownerChecks.observe, fixture.bridge.ownerChecks.peer
			fixture.bridge.ownerChecks.observe = func(path string) (vsockSocketObservation, error) {
				value, err := observe(path)
				switch name {
				case "socket uid":
					value.uid++
				case "parent uid":
					value.parentUID++
				case "socket mode":
					value.socketMode |= 0o040
				case "parent mode":
					value.parentMode |= 0o040
				case "socket type":
					value.socketMode = 0o600
				case "parent type":
					value.parentMode = os.ModeSymlink | 0o700
				case "parent inode":
					value.identity.parentInode++
				case "parent device":
					value.identity.parentDevice++
				case "observe error":
					err = errors.New("fixture observation failure")
				}
				return value, err
			}
			fixture.bridge.ownerChecks.peer = func(conn *net.UnixConn) (vsockPeerIdentity, error) {
				value, err := peer(conn)
				switch name {
				case "peer uid":
					value.uid++
				case "peer pid":
					value.pid++
				case "peer error":
					err = errors.New("fixture peer failure")
				}
				return value, err
			}
			if name == "real peer uid" {
				fixture.bridge.ownerChecks.peer = nil
			}
			jailerVsockServeReady(t, fixture)
			_, generation, err := fixture.bridge.ActivateSession(context.Background(), jailerVsockRequest(fixture))
			if err == nil || generation != "" {
				t.Fatalf("ActivateSession = %q, %v", generation, err)
			}
		})
	}
}

func TestJailerVsockOwnerRejectsIncompleteAuthority(t *testing.T) {
	for _, name := range []string{"zero uid", "missing strict flag", "missing parent", "wrong parent uid", "removed state", "missing paths", "exited"} {
		t.Run(name, func(t *testing.T) {
			fixture := newJailerVsockOwnerFixture(t)
			manager := fixture.bridge.lifecycle
			manager.mu.Lock()
			record := manager.processes[fixture.handle.ID]
			switch name {
			case "zero uid":
				record.strictRuntimeUID = 0
			case "missing strict flag":
				record.hasStrictUID = false
			case "missing parent":
				record.hasStateIdentity = false
			case "wrong parent uid":
				record.stateIdentity.uid++
			case "removed state":
				record.stateRemoved = true
			case "missing paths":
				record.hasPaths = false
			}
			manager.mu.Unlock()
			if name == "exited" {
				fixture.process.stop()
			}
			identity, err := manager.resolveLiveProcessIdentity(fixture.handle)
			if err == nil && (identity.owner == nil || identity.owner.active()) {
				t.Fatal("incomplete owner accepted or downgraded to legacy")
			}
			if _, generation, err := fixture.bridge.ActivateSession(context.Background(), jailerVsockRequest(fixture)); err == nil || generation != "" {
				t.Fatal("incomplete readiness authority accepted")
			}
		})
	}
}

func TestJailerVsockOwnerCancellationCannotPublish(t *testing.T) {
	for _, stage := range []string{"before", "final observation"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newJailerVsockOwnerFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if stage == "before" {
				cancel()
			}
			observe := fixture.bridge.ownerChecks.observe
			var calls atomic.Int32
			fixture.bridge.ownerChecks.observe = func(path string) (vsockSocketObservation, error) {
				value, err := observe(path)
				if calls.Add(1) == 5 {
					cancel()
				}
				return value, err
			}
			jailerVsockServeReady(t, fixture)
			_, generation, err := fixture.bridge.ActivateSession(ctx, jailerVsockRequest(fixture))
			if !errors.Is(err, context.Canceled) || generation != "" {
				t.Fatalf("ActivateSession = %q, %v", generation, err)
			}
			if fixture.bridge.session("fc-production-test") != nil {
				t.Fatal("canceled readiness published session")
			}
		})
	}
}
