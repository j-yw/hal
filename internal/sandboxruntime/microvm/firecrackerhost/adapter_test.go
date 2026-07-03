package firecrackerhost

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

var _ firecracker.ProcessStarter = (*Adapter)(nil)
var _ firecracker.BootAcceptanceWaiter = (*Adapter)(nil)
var _ firecracker.LiveProcessManager = (*Adapter)(nil)

func TestNewAdapterAppliesDependencyOptions(t *testing.T) {
	runner := &fakeProcessRunner{}
	poller := &fakeBootAcceptancePoller{}
	clock := fakeClock{now: time.Unix(100, 0)}
	sleeper := &fakeSleeper{}
	cleanup := &fakeLiveProcessCleanup{}

	adapter := NewAdapter(
		WithProcessRunner(runner),
		WithBootAcceptancePoller(poller),
		WithClock(clock),
		WithSleeper(sleeper),
		WithLiveProcessCleanup(cleanup),
	)

	if adapter.processRunner != runner {
		t.Fatal("process runner option was not applied")
	}
	if adapter.poller != poller {
		t.Fatal("boot acceptance poller option was not applied")
	}
	if got := adapter.clock.Now(); !got.Equal(clock.now) {
		t.Fatalf("clock option Now() = %s, want %s", got, clock.now)
	}
	if adapter.sleeper != sleeper {
		t.Fatal("sleeper option was not applied")
	}
	if adapter.cleanup != cleanup {
		t.Fatal("cleanup option was not applied")
	}
}

func TestAdapterDelegatesProcessStartToInjectedRunner(t *testing.T) {
	type contextKey string
	ctx := context.WithValue(context.Background(), contextKey("start"), "sentinel")
	req := firecracker.ProcessRunnerStartRequest{
		Executable:  "firecracker-test-binary",
		Args:        []string{"--api-sock", "state/api.sock"},
		Environment: []string{},
	}
	runner := &fakeProcessRunner{
		handle: firecracker.ProcessHandleMetadata{ID: "fc-host-handle", Source: "firecrackerhost"},
	}
	adapter := NewAdapter(WithProcessRunner(runner))

	handle, err := adapter.StartProcess(ctx, req)
	if err != nil {
		t.Fatalf("StartProcess() error = %v, want nil", err)
	}

	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
	if runner.ctx.Value(contextKey("start")) != "sentinel" {
		t.Fatal("runner context missing sentinel value")
	}
	if !reflect.DeepEqual(runner.req, req) {
		t.Fatalf("runner request = %#v, want %#v", runner.req, req)
	}
	if handle != runner.handle {
		t.Fatalf("handle = %#v, want %#v", handle, runner.handle)
	}
}

func TestAdapterDelegatesBootAcceptanceToInjectedPoller(t *testing.T) {
	req := firecracker.BootAcceptanceRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: "fc-host-handle", Source: "firecrackerhost"},
		APISocket: firecracker.OperationPathReference{
			Role: firecracker.OperationPathRoleAPISocket,
			Path: "state/api.sock",
		},
	}
	want := firecracker.BootAcceptanceResult{
		ProcessAccepted:    true,
		APISocketAvailable: true,
	}
	poller := &fakeBootAcceptancePoller{result: want}
	adapter := NewAdapter(WithBootAcceptancePoller(poller))

	got, err := adapter.WaitForBootAcceptance(context.Background(), req)
	if err != nil {
		t.Fatalf("WaitForBootAcceptance() error = %v, want nil", err)
	}

	if poller.calls != 1 {
		t.Fatalf("poller calls = %d, want 1", poller.calls)
	}
	if !reflect.DeepEqual(poller.req, req) {
		t.Fatalf("poller request = %#v, want %#v", poller.req, req)
	}
	if got != want {
		t.Fatalf("result = %#v, want %#v", got, want)
	}
}

func TestAdapterDelegatesLiveProcessMethodsToInjectedCleanup(t *testing.T) {
	req := firecracker.LiveProcessRequest{
		Handle: firecracker.ProcessHandleMetadata{ID: "fc-host-handle", Source: "firecrackerhost"},
	}
	cleanup := &fakeLiveProcessCleanup{}
	adapter := NewAdapter(WithLiveProcessCleanup(cleanup))

	if err := adapter.CleanupLiveProcess(context.Background(), req); err != nil {
		t.Fatalf("CleanupLiveProcess() error = %v, want nil", err)
	}
	if err := adapter.StopLiveProcess(context.Background(), req); err != nil {
		t.Fatalf("StopLiveProcess() error = %v, want nil", err)
	}
	if err := adapter.DeleteLiveProcess(context.Background(), req); err != nil {
		t.Fatalf("DeleteLiveProcess() error = %v, want nil", err)
	}

	if cleanup.cleanupCalls != 1 || cleanup.stopCalls != 1 || cleanup.deleteCalls != 1 {
		t.Fatalf("cleanup calls = cleanup:%d stop:%d delete:%d, want one each", cleanup.cleanupCalls, cleanup.stopCalls, cleanup.deleteCalls)
	}
	if !reflect.DeepEqual(cleanup.lastReq, req) {
		t.Fatalf("cleanup request = %#v, want %#v", cleanup.lastReq, req)
	}
}

func TestAdapterWithoutDependenciesReturnsConfiguredSentinelError(t *testing.T) {
	adapter := NewAdapter()

	if _, err := adapter.StartProcess(context.Background(), firecracker.ProcessRunnerStartRequest{}); !errors.Is(err, ErrDependencyNotConfigured) {
		t.Fatalf("StartProcess() error = %v, want ErrDependencyNotConfigured", err)
	}
	if _, err := adapter.WaitForBootAcceptance(context.Background(), firecracker.BootAcceptanceRequest{}); !errors.Is(err, ErrDependencyNotConfigured) {
		t.Fatalf("WaitForBootAcceptance() error = %v, want ErrDependencyNotConfigured", err)
	}
	if err := adapter.CleanupLiveProcess(context.Background(), firecracker.LiveProcessRequest{}); !errors.Is(err, ErrDependencyNotConfigured) {
		t.Fatalf("CleanupLiveProcess() error = %v, want ErrDependencyNotConfigured", err)
	}
	if err := adapter.StopLiveProcess(context.Background(), firecracker.LiveProcessRequest{}); !errors.Is(err, ErrDependencyNotConfigured) {
		t.Fatalf("StopLiveProcess() error = %v, want ErrDependencyNotConfigured", err)
	}
	if err := adapter.DeleteLiveProcess(context.Background(), firecracker.LiveProcessRequest{}); !errors.Is(err, ErrDependencyNotConfigured) {
		t.Fatalf("DeleteLiveProcess() error = %v, want ErrDependencyNotConfigured", err)
	}
}

type fakeProcessRunner struct {
	calls  int
	ctx    context.Context
	req    firecracker.ProcessRunnerStartRequest
	handle firecracker.ProcessHandleMetadata
	err    error
}

func (runner *fakeProcessRunner) StartProcess(ctx context.Context, req firecracker.ProcessRunnerStartRequest) (firecracker.ProcessHandleMetadata, error) {
	runner.calls++
	runner.ctx = ctx
	runner.req = req
	return runner.handle, runner.err
}

type fakeBootAcceptancePoller struct {
	calls  int
	req    firecracker.BootAcceptanceRequest
	result firecracker.BootAcceptanceResult
	err    error
}

func (poller *fakeBootAcceptancePoller) PollBootAcceptance(_ context.Context, req firecracker.BootAcceptanceRequest) (firecracker.BootAcceptanceResult, error) {
	poller.calls++
	poller.req = req
	return poller.result, poller.err
}

type fakeClock struct {
	now time.Time
}

func (clock fakeClock) Now() time.Time {
	return clock.now
}

type fakeSleeper struct {
	calls int
}

func (sleeper *fakeSleeper) Sleep(context.Context, time.Duration) error {
	sleeper.calls++
	return nil
}

type fakeLiveProcessCleanup struct {
	cleanupCalls int
	stopCalls    int
	deleteCalls  int
	lastReq      firecracker.LiveProcessRequest
}

func (cleanup *fakeLiveProcessCleanup) CleanupLiveProcess(_ context.Context, req firecracker.LiveProcessRequest) error {
	cleanup.cleanupCalls++
	cleanup.lastReq = req
	return nil
}

func (cleanup *fakeLiveProcessCleanup) StopLiveProcess(_ context.Context, req firecracker.LiveProcessRequest) error {
	cleanup.stopCalls++
	cleanup.lastReq = req
	return nil
}

func (cleanup *fakeLiveProcessCleanup) DeleteLiveProcess(_ context.Context, req firecracker.LiveProcessRequest) error {
	cleanup.deleteCalls++
	cleanup.lastReq = req
	return nil
}
