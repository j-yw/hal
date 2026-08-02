package firecrackerhost

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecrackerhost/l7network"
)

func TestL7RuntimeControllerPartialPrepareFailureRetainsExactAbortForRetry(t *testing.T) {
	harness := newL7RuntimeControllerHarness(t, "partial-prepare", nil)
	harness.topologies.errors[harness.identity.RuntimeGenerationID] = errors.New("private partial topology failure")
	harness.session.abortErrors = []error{errors.New("private rollback failure"), nil}

	if target, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart)); err == nil || target != nil {
		t.Fatalf("Start(partial topology) = %#v, %v, want sanitized failure", target, err)
	}
	if harness.session.abortCalls != 1 || !harness.session.abortDeadline {
		t.Fatalf("partial topology abort = calls:%d bounded:%t, want 1/true", harness.session.abortCalls, harness.session.abortDeadline)
	}
	stopped, err := harness.controller.Stop(context.Background(), harness.request(microvm.OperationStop))
	if err != nil {
		t.Fatalf("Stop(retry retained abort) error = %v, want nil", err)
	}
	if stopped == nil || stopped.Status != string(l7network.StatusStopped) {
		t.Fatalf("Stop(retry retained abort) = %#v, want stopped target", stopped)
	}
	if harness.session.abortCalls != 2 {
		t.Fatalf("partial topology abort calls = %d, want exact retained retry", harness.session.abortCalls)
	}
	if harness.runtimes.runtime(harness.identity.RuntimeGenerationID) != nil {
		t.Fatal("partial topology failure constructed a Firecracker runtime")
	}
}

func TestL7RuntimeControllerRetriesAfterCompletePreVMCleanup(t *testing.T) {
	harness := newL7RuntimeControllerHarness(t, "complete-pre-vm-retry", nil)
	harness.topologies.errors[harness.identity.RuntimeGenerationID] = errors.New("private initial topology failure")

	if target, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart)); err == nil || target != nil {
		t.Fatalf("first Start() = %#v, %v, want sanitized failure", target, err)
	}
	if harness.session.abortCalls != 1 || harness.controller.preVMCleanup != nil {
		t.Fatalf("first cleanup = aborts:%d retained:%t, want complete rollback", harness.session.abortCalls, harness.controller.preVMCleanup != nil)
	}
	if harness.runtimes.runtime(harness.identity.RuntimeGenerationID) != nil {
		t.Fatal("failed topology preparation constructed a Firecracker runtime")
	}

	retrySession := newL7RuntimeFakeTopologySession(harness.identity, harness.session.sequence)
	t.Cleanup(retrySession.closeLoss)
	harness.topologies.mu.Lock()
	harness.topologies.sessions[harness.identity.RuntimeGenerationID] = retrySession
	delete(harness.topologies.errors, harness.identity.RuntimeGenerationID)
	harness.topologies.mu.Unlock()

	started, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart))
	if err != nil || started == nil || started.Status != string(l7network.StatusActive) {
		t.Fatalf("retry Start() = %#v, %v, want active", started, err)
	}
	if retrySession.abortCalls != 0 || retrySession.inspectCalls != 1 {
		t.Fatalf("retry session calls = abort:%d inspect:%d, want 0/1", retrySession.abortCalls, retrySession.inspectCalls)
	}
}

func TestL7RuntimeControllerPreVMFailuresAbortExactPreparedTopology(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*l7RuntimeControllerHarness)
	}{
		{name: "launch handoff", configure: func(h *l7RuntimeControllerHarness) {
			h.session.launchErr = errors.New("private launch handoff failure")
		}},
		{name: "asset acquisition", configure: func(h *l7RuntimeControllerHarness) {
			h.assets.errors[h.identity.RuntimeGenerationID] = errors.New("private asset acquisition failure")
		}},
		{name: "runtime construction", configure: func(h *l7RuntimeControllerHarness) {
			h.runtimes.errors[h.identity.RuntimeGenerationID] = errors.New("private runtime construction failure")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newL7RuntimeControllerHarness(t, "pre-vm-"+safeL7RuntimeTestSuffix(test.name), nil)
			test.configure(harness)
			if target, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart)); err == nil || target != nil {
				t.Fatalf("Start() = %#v, %v, want sanitized failure", target, err)
			}
			if harness.session.abortCalls != 1 || !harness.session.abortDeadline {
				t.Fatalf("pre-VM abort = calls:%d bounded:%t, want 1/true", harness.session.abortCalls, harness.session.abortDeadline)
			}
			if harness.session.quarantineCalls != 0 {
				t.Fatalf("pre-VM quarantine calls = %d, want rollback/abort boundary", harness.session.quarantineCalls)
			}
		})
	}
}

func TestL7RuntimeControllerTreatsEveryStartReturnAsVMPossible(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*l7RuntimeFakeFirecrackerRuntime, sandboxruntime.Target)
	}{
		{name: "nil target with error", configure: func(runtime *l7RuntimeFakeFirecrackerRuntime, _ sandboxruntime.Target) {
			runtime.claimOnStart = true
			runtime.startErr = errors.New("private start failure")
		}},
		{name: "target with error", configure: func(runtime *l7RuntimeFakeFirecrackerRuntime, target sandboxruntime.Target) {
			runtime.claimOnStart = true
			runtime.startErr = errors.New("private uncertain start failure")
			runtime.startTarget = &target
		}},
		{name: "nil target without error", configure: func(runtime *l7RuntimeFakeFirecrackerRuntime, _ sandboxruntime.Target) {
			runtime.startNil = true
		}},
		{name: "unclaimed live config", configure: func(runtime *l7RuntimeFakeFirecrackerRuntime, _ sandboxruntime.Target) {
			runtime.skipClaim = true
		}},
		{name: "substituted target", configure: func(runtime *l7RuntimeFakeFirecrackerRuntime, target sandboxruntime.Target) {
			target.ID = "runtime-substituted"
			runtime.startTarget = &target
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var runtime *l7RuntimeFakeFirecrackerRuntime
			harness := newL7RuntimeControllerHarness(t, "start-return-"+safeL7RuntimeTestSuffix(test.name), func(candidate *l7RuntimeFakeFirecrackerRuntime) {
				runtime = candidate
				test.configure(candidate, l7RuntimeControllerLifecycleRequest(microvm.OperationStart, candidate.request.Identity.RuntimeGenerationID).Target)
			})
			if target, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart)); err == nil || target != nil {
				t.Fatalf("Start() = %#v, %v, want contained sanitized failure", target, err)
			}
			if runtime == nil {
				t.Fatal("Firecracker runtime was not constructed")
			}
			if runtime.stopCalls != 1 || runtime.terminationCalls != 1 || harness.session.cleanupCalls != 1 {
				t.Fatalf("containment calls = stop:%d termination:%d cleanup:%d, want 1/1/1", runtime.stopCalls, runtime.terminationCalls, harness.session.cleanupCalls)
			}
			if harness.session.quarantineCalls != 1 || !runtime.stopDeadline || !harness.session.cleanupDeadline {
				t.Fatalf("bounded containment = quarantine:%d stopDeadline:%t cleanupDeadline:%t", harness.session.quarantineCalls, runtime.stopDeadline, harness.session.cleanupDeadline)
			}
			slot, ok := runtime.request.LiveConfigProvider.(*l7LiveConfigSlot)
			if !ok {
				t.Fatalf("live config provider type = %T, want owned slot", runtime.request.LiveConfigProvider)
			}
			if test.name == "unclaimed live config" {
				if !slot.closed || slot.claimed {
					t.Fatalf("unclaimed slot state = claimed:%t closed:%t, want false/true", slot.claimed, slot.closed)
				}
			} else if slot.closed || !slot.claimed {
				t.Fatalf("claimed slot state = claimed:%t closed:%t, want true/false", slot.claimed, slot.closed)
			}
		})
	}
}

func TestL7RuntimeControllerRejectsIncompleteInitialGuestProofAndContains(t *testing.T) {
	tests := []struct {
		name             string
		configureRuntime func(*l7RuntimeFakeFirecrackerRuntime)
		configureHarness func(*l7RuntimeControllerHarness)
	}{
		{name: "nil guest binding", configureRuntime: func(runtime *l7RuntimeFakeFirecrackerRuntime) {
			runtime.returnNilBinding = true
		}},
		{name: "incomplete inspected metadata", configureHarness: func(h *l7RuntimeControllerHarness) {
			metadata := l7network.Metadata{Identity: h.identity, Status: l7network.StatusInspected, RawPacketIsolationVerified: true}
			h.session.inspectMetadata = &metadata
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newL7RuntimeControllerHarness(t, "initial-proof-"+safeL7RuntimeTestSuffix(test.name), func(candidate *l7RuntimeFakeFirecrackerRuntime) {
				if test.configureRuntime != nil {
					test.configureRuntime(candidate)
				}
			})
			if test.configureHarness != nil {
				test.configureHarness(harness)
			}
			target, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart))
			if err == nil || target != nil {
				t.Fatalf("Start(incomplete proof) = %#v, %v, want contained failure", target, err)
			}
			runtime := harness.runtimes.runtime(harness.identity.RuntimeGenerationID)
			if runtime == nil || runtime.stopCalls != 1 || runtime.terminationCalls != 1 || harness.session.cleanupCalls != 1 {
				t.Fatalf("proof containment = stop:%d termination:%d cleanup:%d, want 1/1/1", runtime.stopCalls, runtime.terminationCalls, harness.session.cleanupCalls)
			}
		})
	}
}

func TestL7RuntimeControllerCallerCancellationCannotInterruptOwnedContainment(t *testing.T) {
	var runtime *l7RuntimeFakeFirecrackerRuntime
	harness := newL7RuntimeControllerHarness(t, "caller-cancel", func(candidate *l7RuntimeFakeFirecrackerRuntime) {
		runtime = candidate
		candidate.claimOnStart = true
		candidate.startErr = context.Canceled
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if target, err := harness.controller.Start(ctx, harness.request(microvm.OperationStart)); err == nil || target != nil {
		t.Fatalf("Start(canceled after handoff) = %#v, %v, want contained failure", target, err)
	}
	if runtime == nil || !runtime.stopDeadline || !harness.session.quarantineDeadline || !harness.session.cleanupDeadline {
		t.Fatalf("caller cancellation reached cleanup: runtime=%v stop=%t quarantine=%t cleanup=%t",
			runtime != nil, runtime != nil && runtime.stopDeadline, harness.session.quarantineDeadline, harness.session.cleanupDeadline)
	}
}

func TestL7RuntimeControllerContainmentFailuresRemainRetryable(t *testing.T) {
	tests := []struct {
		name           string
		configure      func(*l7RuntimeFakeTopologySession, *l7RuntimeFakeFirecrackerRuntime)
		wantStopCalls  int
		wantTermCalls  int
		wantCleanCalls int
	}{
		{name: "quarantine", configure: func(session *l7RuntimeFakeTopologySession, _ *l7RuntimeFakeFirecrackerRuntime) {
			session.quarantineErrors = []error{errors.New("private quarantine failure"), nil}
		}, wantStopCalls: 1, wantTermCalls: 1, wantCleanCalls: 1},
		{name: "stop and termination", configure: func(_ *l7RuntimeFakeTopologySession, runtime *l7RuntimeFakeFirecrackerRuntime) {
			runtime.stopErrors = []error{errors.New("private stop failure"), nil}
			runtime.terminationErrors = []error{errors.New("private termination uncertainty"), nil}
		}, wantStopCalls: 2, wantTermCalls: 2, wantCleanCalls: 1},
		{name: "termination", configure: func(_ *l7RuntimeFakeTopologySession, runtime *l7RuntimeFakeFirecrackerRuntime) {
			runtime.terminationErrors = []error{errors.New("private termination uncertainty"), nil}
		}, wantStopCalls: 1, wantTermCalls: 2, wantCleanCalls: 1},
		{name: "topology cleanup", configure: func(session *l7RuntimeFakeTopologySession, _ *l7RuntimeFakeFirecrackerRuntime) {
			session.cleanupErrors = []error{errors.New("private cleanup failure"), nil}
		}, wantStopCalls: 1, wantTermCalls: 1, wantCleanCalls: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var runtime *l7RuntimeFakeFirecrackerRuntime
			harness := newL7RuntimeControllerHarness(t, "retry-"+safeL7RuntimeTestSuffix(test.name), func(candidate *l7RuntimeFakeFirecrackerRuntime) {
				runtime = candidate
			})
			if _, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart)); err != nil {
				t.Fatal(err)
			}
			test.configure(harness.session, runtime)
			if target, err := harness.controller.Stop(context.Background(), harness.request(microvm.OperationStop)); err == nil || target != nil {
				t.Fatalf("first Stop() = %#v, %v, want retained cleanup uncertainty", target, err)
			}
			stopped, err := harness.controller.Stop(context.Background(), harness.request(microvm.OperationStop))
			if err != nil || stopped == nil || stopped.Status != string(l7network.StatusStopped) {
				t.Fatalf("retry Stop() = %#v, %v, want stopped", stopped, err)
			}
			if runtime.stopCalls != test.wantStopCalls || runtime.terminationCalls != test.wantTermCalls || harness.session.cleanupCalls != test.wantCleanCalls {
				t.Fatalf("retry calls = stop:%d termination:%d cleanup:%d, want %d/%d/%d",
					runtime.stopCalls, runtime.terminationCalls, harness.session.cleanupCalls,
					test.wantStopCalls, test.wantTermCalls, test.wantCleanCalls)
			}
		})
	}
}

func TestL7RuntimeControllerInspectComposesFreshProofAndContainsDrift(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*l7RuntimeControllerHarness, *l7RuntimeFakeFirecrackerRuntime)
	}{
		{name: "runtime target substitution", configure: func(h *l7RuntimeControllerHarness, runtime *l7RuntimeFakeFirecrackerRuntime) {
			target := h.request(microvm.OperationStart).Target
			target.ID = "runtime-substituted"
			runtime.inspectTarget = &target
		}},
		{name: "host proof drift", configure: func(h *l7RuntimeControllerHarness, _ *l7RuntimeFakeFirecrackerRuntime) {
			h.session.inspectErr = errors.New("private inspected topology drift")
		}},
		{name: "host proof substitution", configure: func(h *l7RuntimeControllerHarness, _ *l7RuntimeFakeFirecrackerRuntime) {
			metadata := l7network.Metadata{Identity: l7RuntimeControllerIdentity("other"), Status: l7network.StatusInspected, RawPacketIsolationVerified: true}
			h.session.inspectMetadata = &metadata
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var runtime *l7RuntimeFakeFirecrackerRuntime
			harness := newL7RuntimeControllerHarness(t, "inspect-"+safeL7RuntimeTestSuffix(test.name), func(candidate *l7RuntimeFakeFirecrackerRuntime) { runtime = candidate })
			if _, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart)); err != nil {
				t.Fatal(err)
			}
			test.configure(harness, runtime)
			result, err := harness.controller.Inspect(context.Background(), microvm.ControllerInspectRequest{Operation: microvm.OperationInspect, Target: harness.request(microvm.OperationStart).Target})
			if err == nil || result != nil {
				t.Fatalf("Inspect(drift) = %#v, %v, want contained failure", result, err)
			}
			if runtime.stopCalls != 1 || runtime.terminationCalls != 1 || harness.session.cleanupCalls != 1 {
				t.Fatalf("drift containment = stop:%d termination:%d cleanup:%d, want 1/1/1", runtime.stopCalls, runtime.terminationCalls, harness.session.cleanupCalls)
			}
			if test.name != "runtime target substitution" && harness.session.freshInspectCalls != 1 {
				t.Fatalf("fresh topology inspect calls = %d, want 1", harness.session.freshInspectCalls)
			}
		})
	}
}

func TestL7RuntimeControllerInspectReturnsActiveOnlyAfterFreshRuntimeAndTopologyProof(t *testing.T) {
	harness := newL7RuntimeControllerHarness(t, "inspect-fresh-success", nil)
	if _, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart)); err != nil {
		t.Fatal(err)
	}
	result, err := harness.controller.Inspect(context.Background(), microvm.ControllerInspectRequest{
		Operation: microvm.OperationInspect,
		Target:    harness.request(microvm.OperationStart).Target,
	})
	if err != nil {
		t.Fatalf("Inspect() error = %v, want nil", err)
	}
	if result == nil || result.Status != string(l7network.StatusActive) || !harness.controller.requestMatchesRuntime(*result) {
		t.Fatalf("Inspect() result = %#v, want exact active target", result)
	}
	if harness.session.freshInspectCalls != 1 {
		t.Fatalf("fresh topology inspect calls = %d, want 1", harness.session.freshInspectCalls)
	}
	runtime := harness.runtimes.runtime(harness.identity.RuntimeGenerationID)
	if runtime == nil || runtime.inspectCalls != 1 {
		t.Fatalf("fresh runtime inspect calls = %d, want 1", runtime.inspectCalls)
	}
}

func TestL7RuntimeControllerHungWorkDoesNotBlockProxyLossContainment(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*l7RuntimeFakeFirecrackerRuntime) (<-chan struct{}, chan<- struct{})
		invoke    func(*l7RuntimeControllerHarness) error
	}{
		{name: "exec", configure: func(runtime *l7RuntimeFakeFirecrackerRuntime) (<-chan struct{}, chan<- struct{}) {
			runtime.execEntered, runtime.execRelease = make(chan struct{}), make(chan struct{})
			return runtime.execEntered, runtime.execRelease
		}, invoke: func(h *l7RuntimeControllerHarness) error {
			_, err := h.controller.Exec(context.Background(), microvm.ControllerExecRequest{Operation: microvm.OperationExec, Target: h.request(microvm.OperationStart).Target})
			return err
		}},
		{name: "copy in", configure: func(runtime *l7RuntimeFakeFirecrackerRuntime) (<-chan struct{}, chan<- struct{}) {
			runtime.copyInEntered, runtime.copyInRelease = make(chan struct{}), make(chan struct{})
			return runtime.copyInEntered, runtime.copyInRelease
		}, invoke: func(h *l7RuntimeControllerHarness) error {
			return h.controller.CopyIn(context.Background(), microvm.ControllerCopyRequest{Operation: microvm.OperationCopyIn, Target: h.request(microvm.OperationStart).Target})
		}},
		{name: "copy out", configure: func(runtime *l7RuntimeFakeFirecrackerRuntime) (<-chan struct{}, chan<- struct{}) {
			runtime.copyOutEntered, runtime.copyOutRelease = make(chan struct{}), make(chan struct{})
			return runtime.copyOutEntered, runtime.copyOutRelease
		}, invoke: func(h *l7RuntimeControllerHarness) error {
			return h.controller.CopyOut(context.Background(), microvm.ControllerCopyRequest{Operation: microvm.OperationCopyOut, Target: h.request(microvm.OperationStart).Target})
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var entered <-chan struct{}
			var release chan<- struct{}
			harness := newL7RuntimeControllerHarness(t, "hung-"+safeL7RuntimeTestSuffix(test.name), func(runtime *l7RuntimeFakeFirecrackerRuntime) {
				entered, release = test.configure(runtime)
			})
			if _, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart)); err != nil {
				t.Fatal(err)
			}
			workDone := make(chan error, 1)
			go func() { workDone <- test.invoke(harness) }()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("runtime work did not enter blocking fake")
			}
			harness.session.publishLoss(l7RuntimeProxyLoss{Metadata: l7network.Metadata{Identity: harness.identity, Status: l7network.StatusQuarantined}})
			select {
			case <-harness.session.cleaned:
			case <-time.After(500 * time.Millisecond):
				close(release)
				<-workDone
				t.Fatal("proxy loss could not contain runtime while work was hung")
			}
			close(release)
			if err := <-workDone; err != nil {
				t.Fatalf("released work error = %v, want nil fake result", err)
			}
		})
	}
}

func TestL7RuntimeControllerRejectsConflictingTargetIdentityBeforeMutation(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*sandboxruntime.Target)
	}{
		{name: "target id", mutate: func(target *sandboxruntime.Target) { target.ID = "runtime-other" }},
		{name: "runtime id", mutate: func(target *sandboxruntime.Target) { target.Runtime.RuntimeID = "runtime-other" }},
		{name: "target id whitespace", mutate: func(target *sandboxruntime.Target) { target.ID = " " + target.ID }},
		{name: "runtime id whitespace", mutate: func(target *sandboxruntime.Target) { target.Runtime.RuntimeID += " " }},
		{name: "provider", mutate: func(target *sandboxruntime.Target) { target.Provider = "provider-other" }},
		{name: "driver", mutate: func(target *sandboxruntime.Target) { target.Runtime.Driver = sandboxruntime.DriverRootlessPodman }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newL7RuntimeControllerHarness(t, "identity-"+safeL7RuntimeTestSuffix(test.name), nil)
			request := harness.request(microvm.OperationStart)
			test.mutate(&request.Target)
			if target, err := harness.controller.Start(context.Background(), request); err == nil || target != nil {
				t.Fatalf("Start(conflict) = %#v, %v, want rejection", target, err)
			}
			if harness.intents.calls != 0 || harness.session.abortCalls != 0 || harness.session.quarantineCalls != 0 {
				t.Fatalf("conflicting target crossed mutation boundary: intent=%d abort=%d quarantine=%d",
					harness.intents.calls, harness.session.abortCalls, harness.session.quarantineCalls)
			}
		})
	}
}

func TestL7RuntimeControllerValidatesProxyLossChannelAndIdentity(t *testing.T) {
	t.Run("nil channel blocks activation", func(t *testing.T) {
		harness := newL7RuntimeControllerHarness(t, "loss-nil", nil)
		harness.session.loss = nil
		if target, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart)); err == nil || target != nil {
			t.Fatalf("Start(nil loss channel) = %#v, %v, want contained failure", target, err)
		}
		runtime := harness.runtimes.runtime(harness.identity.RuntimeGenerationID)
		if runtime == nil || runtime.stopCalls != 1 || harness.session.cleanupCalls != 1 {
			t.Fatalf("nil loss containment = runtime:%v stop:%d cleanup:%d", runtime != nil, runtime.stopCalls, harness.session.cleanupCalls)
		}
	})

	tests := []struct {
		name   string
		result *l7RuntimeProxyLoss
	}{
		{name: "closed without result", result: nil},
		{name: "stopped wrong identity", result: &l7RuntimeProxyLoss{Metadata: l7network.Metadata{Identity: l7RuntimeControllerIdentity("other"), Status: l7network.StatusStopped}}},
		{name: "stopped with error", result: &l7RuntimeProxyLoss{Metadata: l7network.Metadata{Status: l7network.StatusStopped}, Err: errors.New("private loss error")}},
		{name: "unknown status", result: &l7RuntimeProxyLoss{Metadata: l7network.Metadata{Status: l7network.StatusPrepared}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newL7RuntimeControllerHarness(t, "loss-"+safeL7RuntimeTestSuffix(test.name), nil)
			if _, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart)); err != nil {
				t.Fatal(err)
			}
			if test.result == nil {
				harness.session.closeLoss()
			} else {
				result := *test.result
				if result.Metadata.Identity == (l7network.Identity{}) {
					result.Metadata.Identity = harness.identity
				}
				harness.session.publishLoss(result)
			}
			select {
			case <-harness.session.cleaned:
			case <-time.After(time.Second):
				t.Fatal("invalid proxy-loss result did not trigger containment")
			}
		})
	}

	t.Run("stopped while controller active is inconsistent", func(t *testing.T) {
		harness := newL7RuntimeControllerHarness(t, "loss-active-stopped", nil)
		if _, err := harness.controller.Start(context.Background(), harness.request(microvm.OperationStart)); err != nil {
			t.Fatal(err)
		}
		harness.session.publishLoss(l7RuntimeProxyLoss{Metadata: l7network.Metadata{Identity: harness.identity, Status: l7network.StatusStopped}})
		select {
		case <-harness.session.cleaned:
		case <-time.After(time.Second):
			t.Fatal("active controller trusted an out-of-order stopped loss result")
		}
		runtime := harness.runtimes.runtime(harness.identity.RuntimeGenerationID)
		if runtime.stopCalls != 1 || harness.session.cleanupCalls != 1 {
			t.Fatalf("inconsistent stopped containment = stop:%d cleanup:%d, want 1/1", runtime.stopCalls, harness.session.cleanupCalls)
		}
	})
}

func TestL7RuntimeControllerProxyLossResultValidation(t *testing.T) {
	identity := l7RuntimeControllerIdentity("loss-shape")
	tests := []struct {
		name   string
		result l7RuntimeProxyLoss
		valid  bool
	}{
		{name: "quarantined", result: l7RuntimeProxyLoss{Metadata: l7network.Metadata{Identity: identity, Status: l7network.StatusQuarantined}}, valid: true},
		{name: "cleanup incomplete", result: l7RuntimeProxyLoss{Metadata: l7network.Metadata{Identity: identity, Status: l7network.StatusCleanupIncomplete}, Err: l7network.ErrCleanupIncomplete}, valid: true},
		{name: "wrong identity", result: l7RuntimeProxyLoss{Metadata: l7network.Metadata{Identity: l7RuntimeControllerIdentity("other"), Status: l7network.StatusQuarantined}}},
		{name: "quarantined with error", result: l7RuntimeProxyLoss{Metadata: l7network.Metadata{Identity: identity, Status: l7network.StatusQuarantined}, Err: l7network.ErrQuarantineFailed}},
		{name: "incomplete without error", result: l7RuntimeProxyLoss{Metadata: l7network.Metadata{Identity: identity, Status: l7network.StatusCleanupIncomplete}}},
		{name: "incomplete with private error", result: l7RuntimeProxyLoss{Metadata: l7network.Metadata{Identity: identity, Status: l7network.StatusCleanupIncomplete}, Err: errors.New("private loss detail")}},
		{name: "stopped", result: l7RuntimeProxyLoss{Metadata: l7network.Metadata{Identity: identity, Status: l7network.StatusStopped}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := validL7RuntimeProxyLossResult(test.result, identity); got != test.valid {
				t.Fatalf("validL7RuntimeProxyLossResult() = %t, want %t", got, test.valid)
			}
		})
	}
}

type l7RuntimeControllerHarness struct {
	identity   l7network.Identity
	intents    *l7RuntimeFakeIntentProvider
	topologies *l7RuntimeFakeTopologyFactory
	session    *l7RuntimeFakeTopologySession
	assets     *l7RuntimeFakeAssetProvider
	runtimes   *l7RuntimeFakeFirecrackerFactory
	controller *l7RuntimeController
}

func newL7RuntimeControllerHarness(t *testing.T, suffix string, configure func(*l7RuntimeFakeFirecrackerRuntime)) *l7RuntimeControllerHarness {
	t.Helper()
	identity := l7RuntimeControllerIdentity(suffix)
	sequence := &l7RuntimeCallSequence{}
	session := newL7RuntimeFakeTopologySession(identity, sequence)
	intents := &l7RuntimeFakeIntentProvider{requests: map[string]l7network.PrepareRequest{
		identity.RuntimeGenerationID: {Identity: identity, Plan: l7RuntimeControllerPlan(identity)},
	}}
	topologies := &l7RuntimeFakeTopologyFactory{
		sessions: map[string]*l7RuntimeFakeTopologySession{identity.RuntimeGenerationID: session},
		errors:   make(map[string]error),
	}
	assetProvider := &l7RuntimeFakeAssetProvider{
		assets: map[string]l7RuntimeAssets{identity.RuntimeGenerationID: l7RuntimeControllerAssets(identity.RuntimeGenerationID)},
		errors: make(map[string]error),
	}
	runtimes := &l7RuntimeFakeFirecrackerFactory{
		sequence:  sequence,
		runtimes:  make(map[string]*l7RuntimeFakeFirecrackerRuntime),
		errors:    make(map[string]error),
		configure: configure,
	}
	registry, err := newL7RuntimeControllerRegistry(l7RuntimeControllerDependencies{
		Intent: intents, Topology: topologies, Assets: assetProvider, Firecracker: runtimes,
	})
	if err != nil {
		t.Fatal(err)
	}
	controllerValue, err := registry.Controller(identity.RuntimeGenerationID)
	if err != nil {
		t.Fatal(err)
	}
	controller, ok := controllerValue.(*l7RuntimeController)
	if !ok {
		t.Fatalf("Controller() type = %T, want *l7RuntimeController", controllerValue)
	}
	registerL7RuntimeControllerTestCleanup(t, controller, session)
	return &l7RuntimeControllerHarness{
		identity: identity, intents: intents, topologies: topologies, session: session,
		assets: assetProvider, runtimes: runtimes, controller: controller,
	}
}

func registerL7RuntimeControllerTestCleanup(
	t *testing.T,
	controllerValue microvm.Controller,
	session *l7RuntimeFakeTopologySession,
) {
	t.Helper()
	controller, ok := controllerValue.(*l7RuntimeController)
	if !ok {
		t.Fatalf("controller cleanup type = %T, want *l7RuntimeController", controllerValue)
	}
	t.Cleanup(func() {
		session.closeLoss()
		controller.opMu.Lock()
		done := controller.lossDone
		controller.opMu.Unlock()
		if done == nil {
			return
		}
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("L7 runtime controller loss watcher did not finish during cleanup")
		}
	})
}

func (h *l7RuntimeControllerHarness) request(operation string) microvm.ControllerLifecycleRequest {
	return l7RuntimeControllerLifecycleRequest(operation, h.identity.RuntimeGenerationID)
}

func safeL7RuntimeTestSuffix(value string) string {
	result := make([]byte, 0, len(value))
	for index := range len(value) {
		character := value[index]
		if character >= 'a' && character <= 'z' {
			result = append(result, character)
			continue
		}
		if len(result) > 0 && result[len(result)-1] != '-' {
			result = append(result, '-')
		}
	}
	for len(result) > 0 && result[len(result)-1] == '-' {
		result = result[:len(result)-1]
	}
	return string(result)
}

var _ = firecracker.BackendID
