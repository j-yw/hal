//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestJailerRecoveryPrelaunchVsockSelectsPinWithoutChangingLegacy(t *testing.T) {
	for _, route := range []string{"selected", "explicit-control", "legacy"} {
		t.Run(route, func(t *testing.T) {
			fixture := newJailerRecoveryPinFixture(t, route)
			original, err := statStrictJailerPrivateStateDir(fixture.plan.hostPaths.StateDir, fixture.plan.runtimeUID)
			if err != nil {
				t.Fatal(err)
			}
			started, err := fixture.start(context.Background())
			if err != nil || fixture.provider.calls != 1 || fixture.starter.calls != 1 {
				t.Fatalf("start: err=%v, namespace/starter=%d/%d", err, fixture.provider.calls, fixture.starter.calls)
			}
			snapshot, ok := fixture.lifecycle.manager.lookupProcessSnapshot(started.handle)
			if !ok || !snapshot.hasStrictUID || snapshot.strictRuntimeUID != fixture.plan.runtimeUID {
				t.Fatal("actual lifecycle start lost its structured runtime identity")
			}
			identity, err := fixture.lifecycle.manager.resolveLiveProcessIdentity(started.handle)
			if err != nil || identity.owner == nil {
				t.Fatalf("retained strict process identity: %v", err)
			}
			if route == "legacy" {
				if snapshot.hasStateIdentity || identity.owner.active() {
					t.Fatal("legacy constructor gained production socket-owner authority")
				}
				return
			}
			if !snapshot.hasStateIdentity || snapshot.stateIdentity != original || !identity.owner.active() || identity.owner.parent != original {
				t.Fatal("selected lifecycle did not retain the original private parent identity")
			}
		})
	}
}

func TestJailerRecoveryPrelaunchVsockRejectsUnsafeParentBeforeRunner(t *testing.T) {
	for _, route := range []string{"selected", "explicit-control"} {
		t.Run(route, func(t *testing.T) {
			for _, scenario := range []string{"missing", "wrong-owner", "group-readable", "world-writable", "symlink", "regular-file"} {
				t.Run(scenario, func(t *testing.T) {
					fixture := newJailerRecoveryPinFixture(t, route)
					path := fixture.plan.hostPaths.StateDir
					switch scenario {
					case "wrong-owner":
						fixture.request.UID++ // Mismatch the real file owner without chown.
						fixture.replan(t)
					case "group-readable":
						mustJailerRecoveryPin(t, os.Chmod(path, 0o750))
					case "world-writable":
						mustJailerRecoveryPin(t, os.Chmod(path, 0o777))
					default:
						mustJailerRecoveryPin(t, os.Rename(path, path+"-original"))
						if scenario == "symlink" {
							mustJailerRecoveryPin(t, os.Symlink(path+"-original", path))
						} else if scenario == "regular-file" {
							mustJailerRecoveryPin(t, os.WriteFile(path, []byte("not a directory"), 0o600))
						}
					}
					started, err := fixture.start(context.Background())
					if !errors.Is(err, ErrUnsafeCleanupPath) || started.handle != (firecracker.ProcessHandleMetadata{}) {
						t.Errorf("unsafe parent reached launch: err=%v, hasHandle=%t", err, started.handle.ID != "")
					}
					if fixture.provider.calls != 0 || fixture.starter.calls != 0 || strictJailerLifecycleRecordCount(fixture.lifecycle) != 0 {
						t.Error("unsafe parent crossed the namespace/process boundary or created a process record")
					}
				})
			}
		})
	}
}

func TestJailerRecoveryPrelaunchVsockPinsBeforeRunnerAndNeverRepairsReplacement(t *testing.T) {
	for _, route := range []string{"selected", "explicit-control"} {
		t.Run(route, func(t *testing.T) {
			for _, when := range []string{"namespace-handoff", "after-start"} {
				t.Run(when, func(t *testing.T) {
					fixture := newJailerRecoveryPinFixture(t, route)
					path := fixture.plan.hostPaths.StateDir
					original, err := statStrictJailerPrivateStateDir(path, fixture.plan.runtimeUID)
					mustJailerRecoveryPin(t, err)
					const canary = "replacement belongs to somebody else\n"
					replace := func() {
						mustJailerRecoveryPin(t, os.Rename(path, path+"-original"))
						mustJailerRecoveryPin(t, os.Mkdir(path, 0o700))
						mustJailerRecoveryPin(t, os.WriteFile(filepath.Join(path, "canary"), []byte(canary), 0o600))
					}
					if when == "namespace-handoff" {
						fixture.provider.before = replace
					}
					started, err := fixture.start(context.Background())
					if err != nil || fixture.provider.calls != 1 || fixture.starter.calls != 1 {
						t.Fatalf("fake process handoff failed: %v", err)
					}
					if when == "after-start" {
						replace()
					}
					replacement, err := statStrictJailerPrivateStateDir(path, fixture.plan.runtimeUID)
					mustJailerRecoveryPin(t, err)
					if replacement == original {
						t.Fatal("fixture did not replace the parent inode")
					}
					snapshot, ok := fixture.lifecycle.manager.lookupProcessSnapshot(started.handle)
					if !ok || !snapshot.hasStateIdentity || snapshot.stateIdentity != original {
						t.Error("lifecycle did not capture the original parent before entering the runner")
					}
					identity, err := fixture.lifecycle.manager.resolveLiveProcessIdentity(started.handle)
					if err != nil || identity.owner == nil || !identity.owner.active() || identity.owner.parent != original {
						t.Errorf("original parent was lost or repaired from the replacement: %v", err)
					}
					// Use the real pinned cleanup boundary without opening a socket.
					// Even an absent endpoint cannot authorize a different parent.
					if err := removeStrictJailerPinnedStateEntry(path, "guest.vsock", snapshot.stateIdentity, fixture.plan.runtimeUID); err == nil {
						t.Error("replacement parent was accepted by pinned cleanup")
					}
					got, err := os.ReadFile(filepath.Join(path, "canary"))
					if err != nil || string(got) != canary {
						t.Fatal("rejected replacement contents changed")
					}
					mustJailerRecoveryPin(t, os.Rename(path, path+"-replacement"))
					mustJailerRecoveryPin(t, os.Rename(path+"-original", path))
					// Exact original identity remains usable; no re-pinning occurs.
					if err := removeStrictJailerPinnedStateEntry(path, "guest.vsock", snapshot.stateIdentity, fixture.plan.runtimeUID); err != nil {
						t.Errorf("original retained parent no longer authoritative: %v", err)
					}
					after, _ := fixture.lifecycle.manager.lookupProcessSnapshot(started.handle)
					if after != snapshot {
						t.Error("lookup or rejected cleanup repaired the stored parent identity")
					}
				})
			}
		})
	}
}

func TestJailerRecoveryPrelaunchVsockCancellationPrecedesRunner(t *testing.T) {
	fixture := newJailerRecoveryPinFixture(t, "selected")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fixture.start(ctx)
	if !errors.Is(err, context.Canceled) || fixture.provider.calls != 0 || fixture.starter.calls != 0 {
		t.Fatalf("canceled launch crossed runner: %v", err)
	}
}

type jailerRecoveryPinFixture struct {
	request   strictJailerLaunchRequest
	plan      strictJailerLaunchPlan
	lifecycle *strictJailerLifecycle
	provider  *jailerRecoveryPinNamespace
	starter   *atomicJailerNamespaceStarter
}

type jailerRecoveryPinNamespace struct {
	*atomicJailerNamespaceProvider
	before func()
}

func (provider *jailerRecoveryPinNamespace) DuplicateNetworkNamespaceForStrictJailer() (*os.File, error) {
	if provider.before != nil {
		provider.before()
	}
	return provider.atomicJailerNamespaceProvider.DuplicateNetworkNamespaceForStrictJailer()
}

func newJailerRecoveryPinFixture(t *testing.T, route string) *jailerRecoveryPinFixture {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("real-file pin fixture requires an unprivileged caller; it never chowns or changes UID")
	}
	request := validStrictJailerLaunchRequest()
	request.RuntimeID = "run-pin"
	request.ChrootBaseDir = t.TempDir()
	request.UID = uint32(os.Geteuid())
	request.GID = uint32(os.Getegid())
	request.JailPaths = atomicJailerReplaceRuntime(request.JailPaths, request.RuntimeID)
	root := filepath.Join(request.ChrootBaseDir, filepath.Base(request.CanonicalFirecrackerPath), request.RuntimeID, "root")
	request.HostPaths = atomicJailerHostPaths(root, request.JailPaths)
	request.Firecracker.Args = strictFirecrackerArgs(request.HostPaths)
	mustJailerRecoveryPin(t, os.MkdirAll(request.HostPaths.StateDir, 0o700))
	process := newAtomicJailerTestProcess()
	runner, starter, provider := atomicJailerTestRunner(t, process, nil)
	wrapped := &jailerRecoveryPinNamespace{atomicJailerNamespaceProvider: provider}
	runner.namespace = wrapped
	var lifecycle *strictJailerLifecycle
	var err error
	switch route {
	case "selected":
		lifecycle, err = newJailerRecoveryLifecycle(runner)
	case "explicit-control":
		lifecycle, err = newStrictJailerLifecycle(runner, withProcessLifecycleProductionVsock())
	case "legacy":
		lifecycle, err = newStrictJailerLifecycle(runner)
	default:
		t.Fatal("unknown fixture route")
	}
	mustJailerRecoveryPin(t, err)
	// Only the in-memory fake process needs closing; this is fixture disposal,
	// not runtime cleanup evidence. Temporary paths belong exclusively to t.
	t.Cleanup(func() { _ = process.Signal(context.Background(), ProcessSignalTerminate) })
	fixture := &jailerRecoveryPinFixture{request: request, lifecycle: lifecycle, provider: wrapped, starter: starter}
	fixture.replan(t)
	return fixture
}

func (fixture *jailerRecoveryPinFixture) replan(t *testing.T) {
	t.Helper()
	plan, err := planStrictJailerLaunch(fixture.request)
	mustJailerRecoveryPin(t, err)
	fixture.plan = plan
}

func (fixture *jailerRecoveryPinFixture) start(ctx context.Context) (strictJailerLifecycleProcess, error) {
	return fixture.lifecycle.start(ctx, strictJailerLifecycleStartRequest{launchPlan: fixture.plan, hostPaths: fixture.plan.hostPathPlan()})
}

func mustJailerRecoveryPin(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
