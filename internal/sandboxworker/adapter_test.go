package sandboxworker

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestClientDriverSatisfiesSandboxRuntimeDriver(t *testing.T) {
	var _ sandboxruntime.Driver = (*ClientDriver)(nil)
	var _ RuntimeDriverClient = (*Client)(nil)
}

func TestNewClientDriverRequiresDriverIDAndClient(t *testing.T) {
	if driver, err := NewClientDriver(ClientDriverOptions{Client: &recordingRuntimeDriverClient{}}); driver != nil || !errors.Is(err, ErrDriverIDRequired) {
		t.Fatalf("NewClientDriver(missing driver) = %#v, %v; want ErrDriverIDRequired", driver, err)
	}
	if driver, err := NewClientDriver(ClientDriverOptions{DriverID: "fake_runtime"}); driver != nil || !errors.Is(err, ErrWorkerClientRequired) {
		t.Fatalf("NewClientDriver(missing client) = %#v, %v; want ErrWorkerClientRequired", driver, err)
	}
}

func TestClientDriverMapsLifecycleAndInspectCallsToWorkerClient(t *testing.T) {
	client := &recordingRuntimeDriverClient{}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	env := map[string]string{"TOKEN": "raw-secret"}
	created, err := driver.Create(context.Background(), sandboxruntime.CreateRequest{
		Name: "adapter-dev",
		Env:  env,
	})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	env["TOKEN"] = "changed"
	if client.createReq.Name != "adapter-dev" || client.createReq.Env["TOKEN"] != "raw-secret" {
		t.Fatalf("Create() worker request = %#v, want cloned adapter-dev env", client.createReq)
	}
	if created.Name != "adapter-dev" || created.Status != "created" || created.Runtime.Driver != "fake_runtime" {
		t.Fatalf("Create() target = %#v, want created fake runtime target", created)
	}

	runtimeTarget := sandboxruntime.Target{
		ID:       "target-adapter-dev",
		Name:     "adapter-dev",
		Provider: "legacy-provider",
		Status:   "created",
		Runtime: sandboxruntime.RuntimeState{
			RuntimeID:      "runtime-adapter-dev",
			Image:          "image-ref",
			WorkerID:       "worker-001",
			IsolationLevel: IsolationLevelContainer,
		},
		Connection: sandboxruntime.ConnectionInfo{
			Address:     "10.0.0.1",
			PublicIP:    "203.0.113.2",
			WorkspaceID: "host-sensitive-workspace",
		},
	}
	started, err := driver.Start(context.Background(), sandboxruntime.LifecycleRequest{Target: runtimeTarget})
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if started.Status != "running" {
		t.Fatalf("Start() status = %q, want running", started.Status)
	}
	startTarget := client.lifecycleReqs[OperationStart].Target
	if startTarget.Runtime.Driver != "fake_runtime" {
		t.Fatalf("Start() worker target runtime driver = %q, want fallback driver", startTarget.Runtime.Driver)
	}
	if startTarget.Runtime.RuntimeID != "runtime-adapter-dev" || startTarget.Runtime.WorkerID != "worker-001" {
		t.Fatalf("Start() worker target runtime metadata = %#v, want safe runtime metadata", startTarget.Runtime)
	}

	stopped, err := driver.Stop(context.Background(), sandboxruntime.LifecycleRequest{Target: *started})
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if stopped.Status != "stopped" {
		t.Fatalf("Stop() status = %q, want stopped", stopped.Status)
	}

	inspected, err := driver.Inspect(context.Background(), sandboxruntime.InspectRequest{Target: *stopped})
	if err != nil {
		t.Fatalf("Inspect() error: %v", err)
	}
	if inspected.Status != "inspected" || inspected.Runtime.Driver != "fake_runtime" {
		t.Fatalf("Inspect() target = %#v, want inspected fake runtime target", inspected)
	}

	if err := driver.Delete(context.Background(), sandboxruntime.LifecycleRequest{Target: *inspected}); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}
	wantCalls := []string{OperationCreate, OperationStart, OperationStop, OperationInspect, OperationDelete}
	if !reflect.DeepEqual(client.calls, wantCalls) {
		t.Fatalf("worker client calls = %#v, want %#v", client.calls, wantCalls)
	}
	for operation, driverID := range client.driverIDs {
		if driverID != "fake_runtime" {
			t.Fatalf("%s driverID = %q, want fake_runtime", operation, driverID)
		}
	}
}

func TestClientDriverUnsupportedExecAndCopyReturnExplicitErrors(t *testing.T) {
	client := &recordingRuntimeDriverClient{}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	execResult, err := driver.Exec(context.Background(), sandboxruntime.ExecRequest{})
	if execResult != nil || !errors.Is(err, ErrWorkerOperationUnsupported) {
		t.Fatalf("Exec() = %#v, %v; want nil result and unsupported error", execResult, err)
	}
	assertClientDriverError(t, err, OperationExec, "fake_runtime")

	err = driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{})
	if !errors.Is(err, ErrWorkerOperationUnsupported) {
		t.Fatalf("CopyIn() error = %v, want unsupported error", err)
	}
	assertClientDriverError(t, err, OperationCopyIn, "fake_runtime")

	err = driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{})
	if !errors.Is(err, ErrWorkerOperationUnsupported) {
		t.Fatalf("CopyOut() error = %v, want unsupported error", err)
	}
	assertClientDriverError(t, err, OperationCopyOut, "fake_runtime")

	if len(client.calls) != 0 {
		t.Fatalf("worker client calls = %#v, want no calls for unsupported operations", client.calls)
	}
}

func TestClientDriverPreservesContextErrorsFromWorkerClient(t *testing.T) {
	client := &recordingRuntimeDriverClient{}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := driver.Create(canceledCtx, sandboxruntime.CreateRequest{Name: "dev"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Create(canceled) error = %v, want context.Canceled", err)
	}

	timeoutCtx, timeoutCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer timeoutCancel()
	if _, err := driver.Inspect(timeoutCtx, sandboxruntime.InspectRequest{Target: sandboxruntime.Target{Name: "dev"}}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Inspect(timeout) error = %v, want context deadline", err)
	}
}

func TestClientDriverErrorsSanitizeWorkerClientDetails(t *testing.T) {
	client := &recordingRuntimeDriverClient{
		errByOperation: map[string]error{
			OperationStart: errors.New("provider failed token=raw-secret under /Users/alice/worktree"),
		},
	}
	driver, err := NewClientDriver(ClientDriverOptions{
		DriverID: "fake_runtime",
		Client:   client,
	})
	if err != nil {
		t.Fatalf("NewClientDriver() error: %v", err)
	}

	_, err = driver.Start(context.Background(), sandboxruntime.LifecycleRequest{
		Target: sandboxruntime.Target{
			Name:    "dev",
			Runtime: sandboxruntime.RuntimeState{Driver: "fake_runtime"},
		},
	})
	if err == nil {
		t.Fatal("Start() error = nil, want sanitized worker client error")
	}
	message := err.Error()
	for _, unsafe := range []string{"raw-secret", "/Users/alice", "worktree"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("Start() error leaked unsafe detail %q in %q", unsafe, message)
		}
	}
	for _, want := range []string{"token=[redacted]", "[redacted-path]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("Start() error = %q, want sanitized marker %q", message, want)
		}
	}
}

func assertClientDriverError(t *testing.T, err error, operation, driverID string) {
	t.Helper()

	var driverErr *ClientDriverError
	if !errors.As(err, &driverErr) {
		t.Fatalf("error = %T, want *ClientDriverError", err)
	}
	if driverErr.Operation != operation || driverErr.Driver != driverID {
		t.Fatalf("ClientDriverError = %#v, want operation %q driver %q", driverErr, operation, driverID)
	}
}

type recordingRuntimeDriverClient struct {
	calls          []string
	driverIDs      map[string]string
	createReq      CreateRequest
	lifecycleReqs  map[string]LifecycleRequest
	inspectReq     InspectRequest
	errByOperation map[string]error
}

func (client *recordingRuntimeDriverClient) Create(ctx context.Context, driverID string, req CreateRequest) (*Target, error) {
	client.record(OperationCreate, driverID)
	client.createReq = req
	if err := client.operationError(ctx, OperationCreate); err != nil {
		return nil, err
	}
	target := lifecycleWorkerTarget(driverID, req.Name, "created")
	return &target, nil
}

func (client *recordingRuntimeDriverClient) Start(ctx context.Context, driverID string, req LifecycleRequest) (*Target, error) {
	client.record(OperationStart, driverID)
	client.setLifecycleReq(OperationStart, req)
	if err := client.operationError(ctx, OperationStart); err != nil {
		return nil, err
	}
	target := req.Target
	target.Status = "running"
	return &target, nil
}

func (client *recordingRuntimeDriverClient) Stop(ctx context.Context, driverID string, req LifecycleRequest) (*Target, error) {
	client.record(OperationStop, driverID)
	client.setLifecycleReq(OperationStop, req)
	if err := client.operationError(ctx, OperationStop); err != nil {
		return nil, err
	}
	target := req.Target
	target.Status = "stopped"
	return &target, nil
}

func (client *recordingRuntimeDriverClient) Delete(ctx context.Context, driverID string, req LifecycleRequest) error {
	client.record(OperationDelete, driverID)
	client.setLifecycleReq(OperationDelete, req)
	return client.operationError(ctx, OperationDelete)
}

func (client *recordingRuntimeDriverClient) Inspect(ctx context.Context, driverID string, req InspectRequest) (*Target, error) {
	client.record(OperationInspect, driverID)
	client.inspectReq = req
	if err := client.operationError(ctx, OperationInspect); err != nil {
		return nil, err
	}
	target := req.Target
	target.Status = "inspected"
	return &target, nil
}

func (client *recordingRuntimeDriverClient) record(operation, driverID string) {
	client.calls = append(client.calls, operation)
	if client.driverIDs == nil {
		client.driverIDs = map[string]string{}
	}
	client.driverIDs[operation] = driverID
}

func (client *recordingRuntimeDriverClient) setLifecycleReq(operation string, req LifecycleRequest) {
	if client.lifecycleReqs == nil {
		client.lifecycleReqs = map[string]LifecycleRequest{}
	}
	client.lifecycleReqs[operation] = req
}

func (client *recordingRuntimeDriverClient) operationError(ctx context.Context, operation string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if client.errByOperation == nil {
		return nil
	}
	return client.errByOperation[operation]
}
