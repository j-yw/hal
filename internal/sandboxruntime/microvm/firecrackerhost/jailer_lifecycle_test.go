package firecrackerhost

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

func TestStrictJailerLifecycleStartsInspectsAndStopsAtomicPlan(t *testing.T) {
	plan := atomicJailerTestPlan(t, "run-alpha")
	process := newAtomicJailerTestProcess()
	runner, starter, provider := atomicJailerTestRunner(t, process, nil)
	lifecycle, err := newStrictJailerLifecycle(runner)
	if err != nil {
		t.Fatalf("newStrictJailerLifecycle() error = %v, want nil", err)
	}

	started, err := lifecycle.start(context.Background(), strictJailerLifecycleStartRequest{
		launchPlan: plan,
		hostPaths:  plan.hostPathPlan(),
	})
	if err != nil {
		t.Fatalf("start() error = %v, want nil", err)
	}
	if started.handle.ID == "" || started.handle.Source == "" || started.hostPaths != plan.hostPathPlan() {
		t.Fatalf("started process = %#v, want opaque handle bound to authoritative host paths", started)
	}
	if provider.calls != 1 || starter.calls != 1 {
		t.Fatalf("namespace/start calls = %d/%d, want 1/1", provider.calls, starter.calls)
	}
	inspection, err := lifecycle.inspect(started)
	if err != nil || !inspection.active {
		t.Fatalf("inspect() = %#v, %v, want active", inspection, err)
	}

	if err := lifecycle.stop(context.Background(), started); err != nil {
		t.Fatalf("stop() error = %v, want nil", err)
	}
	if process.signalCalls != 1 || process.waitCalls != 1 || process.killCalls != 0 {
		t.Fatalf("process signal/wait/kill = %d/%d/%d, want 1/1/0", process.signalCalls, process.waitCalls, process.killCalls)
	}
	if _, err := lifecycle.inspect(started); !errors.Is(err, errStrictJailerLifecycleInactive) {
		t.Fatalf("inspect(after stop) error = %v, want inactive", err)
	}
}

func TestStrictJailerLifecycleRejectsCrossGenerationAndPathMixingBeforeStart(t *testing.T) {
	alpha := atomicJailerTestPlan(t, "run-alpha")
	beta := atomicJailerTestPlan(t, "run-beta")
	mixedHost := alpha
	mixedHost.hostPaths = beta.hostPathPlan()
	mixedJail := alpha
	mixedJail.jailPaths = beta.jailPathPlan()

	tests := []struct {
		name    string
		request strictJailerLifecycleStartRequest
	}{
		{name: "authoritative paths from another generation", request: strictJailerLifecycleStartRequest{launchPlan: alpha, hostPaths: beta.hostPathPlan()}},
		{name: "command and host plan mixed", request: strictJailerLifecycleStartRequest{launchPlan: mixedHost, hostPaths: beta.hostPathPlan()}},
		{name: "command and jail plan mixed", request: strictJailerLifecycleStartRequest{launchPlan: mixedJail, hostPaths: alpha.hostPathPlan()}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runner, starter, provider := atomicJailerTestRunner(t, newAtomicJailerTestProcess(), nil)
			lifecycle, err := newStrictJailerLifecycle(runner)
			if err != nil {
				t.Fatal(err)
			}

			_, err = lifecycle.start(context.Background(), tt.request)
			if !errors.Is(err, errStrictJailerLifecycleInvalid) {
				t.Fatalf("start() error = %v, want invalid atomic lifecycle request", err)
			}
			if starter.calls != 0 || provider.calls != 0 {
				t.Fatalf("namespace/start calls = %d/%d, want no live boundary", provider.calls, starter.calls)
			}
		})
	}
}

func TestStrictJailerLifecycleRejectsCrossGenerationHandlePaths(t *testing.T) {
	plan := atomicJailerTestPlan(t, "run-alpha")
	process := newAtomicJailerTestProcess()
	runner, _, _ := atomicJailerTestRunner(t, process, nil)
	lifecycle, err := newStrictJailerLifecycle(runner)
	if err != nil {
		t.Fatal(err)
	}
	started, err := lifecycle.start(context.Background(), strictJailerLifecycleStartRequest{
		launchPlan: plan, hostPaths: plan.hostPathPlan(),
	})
	if err != nil {
		t.Fatal(err)
	}

	forged := started
	forged.hostPaths = atomicJailerTestPlan(t, "run-beta").hostPathPlan()
	if _, err := lifecycle.inspect(forged); !errors.Is(err, errStrictJailerLifecycleInvalid) {
		t.Fatalf("inspect(forged) error = %v, want invalid", err)
	}
	if err := lifecycle.stop(context.Background(), forged); !errors.Is(err, errStrictJailerLifecycleInvalid) {
		t.Fatalf("stop(forged) error = %v, want invalid", err)
	}
	if process.signalCalls != 0 || process.killCalls != 0 {
		t.Fatalf("forged handle reached process: signal/kill = %d/%d", process.signalCalls, process.killCalls)
	}
	if err := lifecycle.stop(context.Background(), started); err != nil {
		t.Fatalf("stop(valid) error = %v", err)
	}
}

func TestStrictJailerLifecycleErrorsRemainSanitized(t *testing.T) {
	plan := atomicJailerTestPlan(t, "run-alpha")
	plan.process.Args[1] = "secret-generation-/Users/alice/private"
	runner, _, _ := atomicJailerTestRunner(t, newAtomicJailerTestProcess(), nil)
	lifecycle, err := newStrictJailerLifecycle(runner)
	if err != nil {
		t.Fatal(err)
	}

	_, err = lifecycle.start(context.Background(), strictJailerLifecycleStartRequest{
		launchPlan: plan, hostPaths: plan.hostPathPlan(),
	})
	if !errors.Is(err, errStrictJailerLifecycleInvalid) {
		t.Fatalf("start() error = %v, want invalid", err)
	}
	for _, unsafe := range []string{"secret-generation", "/Users/alice", "private"} {
		if strings.Contains(err.Error(), unsafe) {
			t.Fatalf("error leaked %q in %q", unsafe, err)
		}
	}
}

func atomicJailerTestPlan(t *testing.T, runtimeID string) strictJailerLaunchPlan {
	t.Helper()
	request := validStrictJailerLaunchRequest()
	request.RuntimeID = runtimeID
	request.JailPaths = atomicJailerReplaceRuntime(request.JailPaths, runtimeID)
	jailRoot := request.ChrootBaseDir + "/firecracker/" + runtimeID + "/root"
	request.HostPaths = atomicJailerHostPaths(jailRoot, request.JailPaths)
	request.Firecracker.Args = strictFirecrackerArgs(request.HostPaths)
	plan, err := planStrictJailerLaunch(request)
	if err != nil {
		t.Fatalf("planStrictJailerLaunch(%q) error = %v", runtimeID, err)
	}
	return plan
}

func atomicJailerReplaceRuntime(paths firecracker.PathPlan, runtimeID string) firecracker.PathPlan {
	stateDir := "/run/fc-" + runtimeID
	return firecracker.PathPlan{
		StateDir:        stateDir,
		APISocketPath:   stateDir + "/firecracker.sock",
		ConfigPath:      stateDir + "/firecracker-config.json",
		LogPath:         stateDir + "/firecracker.log",
		MetricsPath:     stateDir + "/firecracker.metrics",
		VsockSocketPath: stateDir + "/guest.vsock",
	}
}

func atomicJailerHostPaths(jailRoot string, jailPaths firecracker.PathPlan) firecracker.PathPlan {
	trim := func(value string) string { return jailRoot + "/" + strings.TrimPrefix(value, "/") }
	return firecracker.PathPlan{
		StateDir: trim(jailPaths.StateDir), APISocketPath: trim(jailPaths.APISocketPath),
		ConfigPath: trim(jailPaths.ConfigPath), LogPath: trim(jailPaths.LogPath),
		MetricsPath: trim(jailPaths.MetricsPath), VsockSocketPath: trim(jailPaths.VsockSocketPath),
	}
}
