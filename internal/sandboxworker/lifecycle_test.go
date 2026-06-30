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

func TestServiceLifecycleOperationsRouteThroughRegistry(t *testing.T) {
	driver := &recordingLifecycleDriver{id: "fake_runtime"}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	createResp := service.HandleRequest(context.Background(), Request{
		RequestID: "req-create",
		Operation: OperationCreate,
		DriverID:  "fake_runtime",
		Create: &CreateRequest{
			Name: "worker-dev",
			Env:  map[string]string{"TOKEN": "raw-secret"},
		},
	})
	assertLifecycleResponseTarget(t, createResp, OperationCreate, "worker-dev", "created")
	if driver.createName != "worker-dev" || driver.createEnv["TOKEN"] != "raw-secret" {
		t.Fatalf("create request captured as name=%q env=%#v, want worker-dev env", driver.createName, driver.createEnv)
	}

	target := *createResp.Target
	startResp := service.HandleRequest(context.Background(), Request{
		RequestID: "req-start",
		Operation: OperationStart,
		DriverID:  "fake_runtime",
		Lifecycle: &LifecycleRequest{Target: target},
	})
	assertLifecycleResponseTarget(t, startResp, OperationStart, "worker-dev", "running")

	stopResp := service.HandleRequest(context.Background(), Request{
		RequestID: "req-stop",
		Operation: OperationStop,
		DriverID:  "fake_runtime",
		Lifecycle: &LifecycleRequest{Target: target},
	})
	assertLifecycleResponseTarget(t, stopResp, OperationStop, "worker-dev", "stopped")

	deleteResp := service.HandleRequest(context.Background(), Request{
		RequestID: "req-delete",
		Operation: OperationDelete,
		DriverID:  "fake_runtime",
		Lifecycle: &LifecycleRequest{Target: target},
	})
	if err := deleteResp.Validate(); err != nil {
		t.Fatalf("delete response Validate() error: %v", err)
	}
	if !deleteResp.OK || deleteResp.Operation != OperationDelete || deleteResp.Target != nil {
		t.Fatalf("delete response = %#v, want successful delete without target payload", deleteResp)
	}

	wantCalls := []string{OperationCreate, OperationStart, OperationStop, OperationDelete}
	if !reflect.DeepEqual(driver.calls, wantCalls) {
		t.Fatalf("driver calls = %#v, want %#v", driver.calls, wantCalls)
	}
}

func TestServiceServesLifecycleOperationsOverUnixSocket(t *testing.T) {
	socketPath := testWorkerSocketPath(t)
	driver := &recordingLifecycleDriver{id: "fake_runtime"}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID:   "worker-001",
		SocketPath: socketPath,
		Registry:   registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    service,
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)

	createResp := roundTripWorkerRequest(t, socketPath, Request{
		RequestID: "req-create",
		Operation: OperationCreate,
		DriverID:  "fake_runtime",
		Create:    &CreateRequest{Name: "socket-dev"},
	})
	assertLifecycleResponseTarget(t, createResp, OperationCreate, "socket-dev", "created")

	target := *createResp.Target
	for _, tt := range []struct {
		requestID string
		operation string
		status    string
	}{
		{requestID: "req-start", operation: OperationStart, status: "running"},
		{requestID: "req-stop", operation: OperationStop, status: "stopped"},
	} {
		resp := roundTripWorkerRequest(t, socketPath, Request{
			RequestID: tt.requestID,
			Operation: tt.operation,
			DriverID:  "fake_runtime",
			Lifecycle: &LifecycleRequest{Target: target},
		})
		assertLifecycleResponseTarget(t, resp, tt.operation, "socket-dev", tt.status)
	}

	deleteResp := roundTripWorkerRequest(t, socketPath, Request{
		RequestID: "req-delete",
		Operation: OperationDelete,
		DriverID:  "fake_runtime",
		Lifecycle: &LifecycleRequest{Target: target},
	})
	if err := deleteResp.Validate(); err != nil {
		t.Fatalf("delete response Validate() error: %v", err)
	}
	if !deleteResp.OK || deleteResp.Operation != OperationDelete {
		t.Fatalf("delete response = %#v, want successful delete", deleteResp)
	}
	if !reflect.DeepEqual(driver.calls, []string{OperationCreate, OperationStart, OperationStop, OperationDelete}) {
		t.Fatalf("driver calls = %#v, want create/start/stop/delete", driver.calls)
	}
}

func TestClientLifecycleOperationsOverUnixSocket(t *testing.T) {
	socketPath := testWorkerSocketPath(t)
	driver := &recordingLifecycleDriver{id: "fake_runtime"}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID:   "worker-001",
		SocketPath: socketPath,
		Registry:   registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler:    service,
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)

	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	created, err := client.Create(context.Background(), "fake_runtime", CreateRequest{Name: "client-dev"})
	if err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if created.Name != "client-dev" || created.Status != "created" || created.Runtime.Driver != "fake_runtime" {
		t.Fatalf("Create() target = %#v, want created fake runtime target", created)
	}

	started, err := client.Start(context.Background(), "fake_runtime", LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if started.Status != "running" {
		t.Fatalf("Start() status = %q, want running", started.Status)
	}

	stopped, err := client.Stop(context.Background(), "fake_runtime", LifecycleRequest{Target: *created})
	if err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if stopped.Status != "stopped" {
		t.Fatalf("Stop() status = %q, want stopped", stopped.Status)
	}

	if err := client.Delete(context.Background(), "fake_runtime", LifecycleRequest{Target: *created}); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}
}

func TestClientLifecycleRequestsUseInjectedTransport(t *testing.T) {
	var got []Request
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
			got = append(got, req)
			target := lifecycleWorkerTarget(req.DriverID, "transport-dev", "ok")
			return Response{
				RequestID: req.RequestID,
				Operation: req.Operation,
				OK:        true,
				Target:    &target,
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	target := lifecycleWorkerTarget("fake_runtime", "transport-dev", "created")
	if _, err := client.Create(context.Background(), "fake_runtime", CreateRequest{Name: "transport-dev"}); err != nil {
		t.Fatalf("Create() error: %v", err)
	}
	if _, err := client.Start(context.Background(), "fake_runtime", LifecycleRequest{Target: target}); err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if _, err := client.Stop(context.Background(), "fake_runtime", LifecycleRequest{Target: target}); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}
	if err := client.Delete(context.Background(), "fake_runtime", LifecycleRequest{Target: target}); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	if len(got) != 4 {
		t.Fatalf("transport request count = %d, want 4", len(got))
	}
	for i, operation := range []string{OperationCreate, OperationStart, OperationStop, OperationDelete} {
		req := got[i]
		if req.ProtocolVersion != ProtocolVersion || req.Operation != operation || req.DriverID != "fake_runtime" {
			t.Fatalf("request[%d] = %#v, want %s fake_runtime request", i, req, operation)
		}
		if operation == OperationCreate && req.Create == nil {
			t.Fatalf("request[%d] missing create payload", i)
		}
		if operation != OperationCreate && req.Lifecycle == nil {
			t.Fatalf("request[%d] missing lifecycle payload", i)
		}
	}
}

func TestServiceLifecycleUnknownDriverAndDriverErrorsAreStructured(t *testing.T) {
	driver := &recordingLifecycleDriver{
		id: "fake_runtime",
		errByOperation: map[string]error{
			OperationStart: errors.New("provider failed token=raw-secret under /Users/alice/worktree"),
		},
	}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	unknownResp := service.HandleRequest(context.Background(), Request{
		RequestID: "req-missing",
		Operation: OperationCreate,
		DriverID:  "missing_runtime",
		Create:    &CreateRequest{Name: "dev"},
	})
	if err := unknownResp.Validate(); err != nil {
		t.Fatalf("unknown driver response Validate() error: %v", err)
	}
	if unknownResp.OK || unknownResp.Error == nil || unknownResp.Error.Code != ErrorCodeDriverNotFound {
		t.Fatalf("unknown driver response = %#v, want driver_not_found error", unknownResp)
	}

	driverResp := service.HandleRequest(context.Background(), Request{
		RequestID: "req-driver-error",
		Operation: OperationStart,
		DriverID:  "fake_runtime",
		Lifecycle: &LifecycleRequest{Target: lifecycleWorkerTarget("fake_runtime", "dev", "created")},
	})
	if err := driverResp.Validate(); err != nil {
		t.Fatalf("driver error response Validate() error: %v", err)
	}
	if driverResp.OK || driverResp.Error == nil || driverResp.Error.Code != ErrorCodeDriverFailed {
		t.Fatalf("driver error response = %#v, want driver_error", driverResp)
	}
	message := driverResp.Error.Message
	for _, unsafe := range []string{"raw-secret", "/Users/alice", "worktree"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("driver error leaked unsafe detail %q in %q", unsafe, message)
		}
	}
	for _, want := range []string{"token=[redacted]", "[redacted-path]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("driver error message = %q, want sanitized marker %q", message, want)
		}
	}
}

func TestServiceLifecycleContextErrorsAreStructured(t *testing.T) {
	driver := &recordingLifecycleDriver{id: "fake_runtime"}
	registry, err := NewDriverRegistry(driver)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID: "worker-001",
		Registry: registry,
	})
	if err != nil {
		t.Fatalf("NewService() error: %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	canceledResp := service.HandleRequest(canceledCtx, Request{
		RequestID: "req-canceled",
		Operation: OperationCreate,
		DriverID:  "fake_runtime",
		Create:    &CreateRequest{Name: "dev"},
	})
	if canceledResp.OK || canceledResp.Error == nil || canceledResp.Error.Code != ErrorCodeRequestCanceled {
		t.Fatalf("canceled response = %#v, want request_canceled", canceledResp)
	}

	timeoutCtx, timeoutCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer timeoutCancel()
	timeoutResp := service.HandleRequest(timeoutCtx, Request{
		RequestID: "req-timeout",
		Operation: OperationStart,
		DriverID:  "fake_runtime",
		Lifecycle: &LifecycleRequest{Target: lifecycleWorkerTarget("fake_runtime", "dev", "created")},
	})
	if timeoutResp.OK || timeoutResp.Error == nil || timeoutResp.Error.Code != ErrorCodeRequestTimeout {
		t.Fatalf("timeout response = %#v, want request_timeout", timeoutResp)
	}

	if len(driver.calls) != 0 {
		t.Fatalf("driver calls = %#v, want no calls for already-finished contexts", driver.calls)
	}
}

func assertLifecycleResponseTarget(t *testing.T, resp Response, operation, name, status string) {
	t.Helper()

	if err := resp.Validate(); err != nil {
		t.Fatalf("%s response Validate() error: %v", operation, err)
	}
	if !resp.OK || resp.Operation != operation || resp.Target == nil {
		t.Fatalf("%s response = %#v, want successful target response", operation, resp)
	}
	if resp.Target.Name != name || resp.Target.Status != status {
		t.Fatalf("%s target = %#v, want name %q status %q", operation, resp.Target, name, status)
	}
	if resp.Target.Runtime.Driver == "" || resp.Target.Runtime.RuntimeID == "" {
		t.Fatalf("%s target runtime metadata = %#v, want command-agnostic driver/runtime IDs", operation, resp.Target.Runtime)
	}
}

func lifecycleWorkerTarget(driverID, name, status string) Target {
	return Target{
		ID:     "target-" + name,
		Name:   name,
		Status: status,
		Runtime: RuntimeTarget{
			Driver:         driverID,
			RuntimeID:      "runtime-" + name,
			WorkerID:       "worker-001",
			IsolationLevel: IsolationLevelContainer,
		},
	}
}

type recordingLifecycleDriver struct {
	id             string
	calls          []string
	createName     string
	createEnv      map[string]string
	errByOperation map[string]error
}

func (driver *recordingLifecycleDriver) ID() string {
	return driver.id
}

func (driver *recordingLifecycleDriver) Create(ctx context.Context, req sandboxruntime.CreateRequest) (*sandboxruntime.Target, error) {
	driver.calls = append(driver.calls, OperationCreate)
	driver.createName = req.Name
	driver.createEnv = cloneStringMap(req.Env)
	if err := driver.operationError(ctx, OperationCreate); err != nil {
		return nil, err
	}
	return driver.runtimeTarget(req.Name, "created"), nil
}

func (driver *recordingLifecycleDriver) Start(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	driver.calls = append(driver.calls, OperationStart)
	if err := driver.operationError(ctx, OperationStart); err != nil {
		return nil, err
	}
	target := req.Target
	target.Status = "running"
	return &target, nil
}

func (driver *recordingLifecycleDriver) Stop(ctx context.Context, req sandboxruntime.LifecycleRequest) (*sandboxruntime.Target, error) {
	driver.calls = append(driver.calls, OperationStop)
	if err := driver.operationError(ctx, OperationStop); err != nil {
		return nil, err
	}
	target := req.Target
	target.Status = "stopped"
	return &target, nil
}

func (driver *recordingLifecycleDriver) Delete(ctx context.Context, req sandboxruntime.LifecycleRequest) error {
	driver.calls = append(driver.calls, OperationDelete)
	if req.Target.Name == "" {
		return errors.New("delete target name is required")
	}
	return driver.operationError(ctx, OperationDelete)
}

func (driver *recordingLifecycleDriver) Inspect(ctx context.Context, req sandboxruntime.InspectRequest) (*sandboxruntime.Target, error) {
	if err := driver.operationError(ctx, OperationInspect); err != nil {
		return nil, err
	}
	return &req.Target, nil
}

func (driver *recordingLifecycleDriver) Exec(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	return &sandboxruntime.ExecResult{}, nil
}

func (driver *recordingLifecycleDriver) CopyIn(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (driver *recordingLifecycleDriver) CopyOut(context.Context, sandboxruntime.CopyRequest) error {
	return nil
}

func (driver *recordingLifecycleDriver) operationError(ctx context.Context, operation string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if driver.errByOperation == nil {
		return nil
	}
	return driver.errByOperation[operation]
}

func (driver *recordingLifecycleDriver) runtimeTarget(name, status string) *sandboxruntime.Target {
	return &sandboxruntime.Target{
		ID:     "target-" + name,
		Name:   name,
		Status: status,
		Runtime: sandboxruntime.RuntimeState{
			Driver:         driver.id,
			RuntimeID:      "runtime-" + name,
			WorkerID:       "worker-001",
			IsolationLevel: IsolationLevelContainer,
		},
	}
}
