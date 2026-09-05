//go:build linux

package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStrictJailerLifecycleProductionStateOwnerMustMatchStructuredRuntimeUID(t *testing.T) {
	request := validStrictJailerLaunchRequest()
	request.RuntimeID = "run-owner"
	request.ChrootBaseDir = t.TempDir()
	request.UID = uint32(os.Geteuid() + 1)
	request.JailPaths = atomicJailerReplaceRuntime(request.JailPaths, request.RuntimeID)
	jailRoot := filepath.Join(request.ChrootBaseDir, filepath.Base(request.CanonicalFirecrackerPath), request.RuntimeID, "root")
	request.HostPaths = atomicJailerHostPaths(jailRoot, request.JailPaths)
	request.Firecracker.Args = strictFirecrackerArgs(request.HostPaths)
	if err := os.MkdirAll(request.HostPaths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	plan, err := planStrictJailerLaunch(request)
	if err != nil {
		t.Fatal(err)
	}
	runner, starter, provider := atomicJailerTestRunner(t, newAtomicJailerTestProcess(), nil)
	lifecycle, err := newStrictJailerLifecycle(runner, withProcessLifecycleProductionVsock())
	if err != nil {
		t.Fatal(err)
	}

	_, err = lifecycle.start(context.Background(), strictJailerLifecycleStartRequest{launchPlan: plan, hostPaths: plan.hostPathPlan()})
	if err == nil || !errors.Is(err, ErrUnsafeCleanupPath) {
		t.Fatalf("start() error = %v, want expected-runtime-UID ownership rejection", err)
	}
	if starter.calls != 0 || provider.calls != 0 {
		t.Fatalf("namespace/start calls = %d/%d, want no live boundary", provider.calls, starter.calls)
	}
}

func TestStrictJailerCleanupAuthorityAllowsOnlyRootOrExpectedRuntimeUID(t *testing.T) {
	const expected = uint32(1001)
	for _, test := range []struct {
		name   string
		caller uint32
		want   bool
	}{
		{name: "root", caller: 0, want: true},
		{name: "runtime owner", caller: expected, want: true},
		{name: "unrelated uid", caller: 1002, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := strictJailerCallerMayCleanup(test.caller, expected); got != test.want {
				t.Fatalf("strictJailerCallerMayCleanup(%d, %d) = %v, want %v", test.caller, expected, got, test.want)
			}
		})
	}
}
