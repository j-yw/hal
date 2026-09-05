package sandboxworker

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestWorkerInspectRequestJSONRoundTripPreservesPayload(t *testing.T) {
	target := lifecycleWorkerTarget(RuntimeDriverRootlessPodman, "inspect-dev", "running")
	req := Request{
		ProtocolVersion: ProtocolVersion,
		RequestID:       "req-inspect",
		Operation:       OperationInspect,
		DriverID:        RuntimeDriverRootlessPodman,
		Inspect:         &InspectRequest{Target: target},
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("request Validate() unexpected error: %v", err)
	}

	var decoded Request
	roundTripJSON(t, req, &decoded)
	if !reflect.DeepEqual(decoded, req) {
		t.Fatalf("decoded request = %#v, want %#v", decoded, req)
	}
	if decoded.Inspect == nil || decoded.Inspect.Target.Runtime.Driver != RuntimeDriverRootlessPodman {
		t.Fatalf("decoded request missing inspect target metadata: %#v", decoded)
	}
}

func TestServiceInspectOperationRoutesThroughRegistry(t *testing.T) {
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

	resp := service.HandleRequest(context.Background(), Request{
		RequestID: "req-inspect",
		Operation: OperationInspect,
		DriverID:  "fake_runtime",
		Inspect: &InspectRequest{
			Target: lifecycleWorkerTarget("fake_runtime", "inspect-dev", "running"),
		},
	})
	assertInspectResponseTarget(t, resp, "inspect-dev", "inspected")

	if !reflect.DeepEqual(driver.calls, []string{OperationInspect}) {
		t.Fatalf("driver calls = %#v, want inspect call", driver.calls)
	}
}

func TestServiceServesInspectOperationOverUnixSocket(t *testing.T) {
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

	resp := roundTripWorkerRequest(t, socketPath, Request{
		RequestID: "req-inspect",
		Operation: OperationInspect,
		DriverID:  "fake_runtime",
		Inspect: &InspectRequest{
			Target: lifecycleWorkerTarget("fake_runtime", "socket-dev", "running"),
		},
	})
	assertInspectResponseTarget(t, resp, "socket-dev", "inspected")

	if !reflect.DeepEqual(driver.calls, []string{OperationInspect}) {
		t.Fatalf("driver calls = %#v, want inspect call", driver.calls)
	}
}

func TestClientInspectOperationOverUnixSocket(t *testing.T) {
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

	inspected, err := client.Inspect(context.Background(), "fake_runtime", InspectRequest{
		Target: lifecycleWorkerTarget("fake_runtime", "client-dev", "running"),
	})
	if err != nil {
		t.Fatalf("Inspect() error: %v", err)
	}
	if inspected.Name != "client-dev" || inspected.Status != "inspected" || inspected.Runtime.Driver != "fake_runtime" {
		t.Fatalf("Inspect() target = %#v, want inspected fake runtime target", inspected)
	}
}

func TestClientInspectRequestUsesInjectedTransport(t *testing.T) {
	var got Request
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
			got = req
			target := lifecycleWorkerTarget(req.DriverID, "transport-dev", "inspected")
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

	inspected, err := client.Inspect(context.Background(), "fake_runtime", InspectRequest{
		Target: lifecycleWorkerTarget("fake_runtime", "transport-dev", "running"),
	})
	if err != nil {
		t.Fatalf("Inspect() error: %v", err)
	}
	if inspected.Status != "inspected" {
		t.Fatalf("Inspect() status = %q, want inspected", inspected.Status)
	}
	if got.ProtocolVersion != ProtocolVersion || got.Operation != OperationInspect || got.DriverID != "fake_runtime" {
		t.Fatalf("transport request = %#v, want inspect fake_runtime request", got)
	}
	if got.Inspect == nil || got.Lifecycle != nil || got.Create != nil {
		t.Fatalf("transport request payloads = %#v, want inspect payload only", got)
	}
	if !strings.HasPrefix(got.RequestID, OperationInspect+"-") {
		t.Fatalf("transport requestID = %q, want generated inspect request ID", got.RequestID)
	}
}

func TestInspectMissingTargetReturnsStructuredErrorOverUnixSocket(t *testing.T) {
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

	resp := roundTripWorkerRequest(t, socketPath, Request{
		RequestID: "req-missing-target",
		Operation: OperationInspect,
		DriverID:  "fake_runtime",
		Inspect: &InspectRequest{
			Target: Target{
				Runtime: RuntimeTarget{Driver: "fake_runtime"},
			},
		},
	})
	if err := resp.Validate(); err != nil {
		t.Fatalf("response Validate() error: %v", err)
	}
	if resp.OK || resp.Operation != OperationInspect || resp.Error == nil {
		t.Fatalf("missing target response = %#v, want inspect malformed-request error", resp)
	}
	if resp.Error.Code != ErrorCodeMalformedRequest || !strings.Contains(resp.Error.Message, "target name or id") {
		t.Fatalf("missing target error = %#v, want target validation detail", resp.Error)
	}
	if len(driver.calls) != 0 {
		t.Fatalf("driver calls = %#v, want no dispatch for malformed inspect request", driver.calls)
	}
}

func TestServiceInspectUnknownDriverAndDriverErrorsAreStructured(t *testing.T) {
	driver := &recordingLifecycleDriver{
		id: "fake_runtime",
		errByOperation: map[string]error{
			OperationInspect: errors.New("provider failed token=raw-secret under /Users/alice/worktree"),
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
		Operation: OperationInspect,
		DriverID:  "missing_runtime",
		Inspect: &InspectRequest{
			Target: lifecycleWorkerTarget("missing_runtime", "dev", "running"),
		},
	})
	if err := unknownResp.Validate(); err != nil {
		t.Fatalf("unknown driver response Validate() error: %v", err)
	}
	if unknownResp.OK || unknownResp.Error == nil || unknownResp.Error.Code != ErrorCodeDriverNotFound {
		t.Fatalf("unknown driver response = %#v, want driver_not_found error", unknownResp)
	}

	driverResp := service.HandleRequest(context.Background(), Request{
		RequestID: "req-driver-error",
		Operation: OperationInspect,
		DriverID:  "fake_runtime",
		Inspect: &InspectRequest{
			Target: lifecycleWorkerTarget("fake_runtime", "dev", "running"),
		},
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

func TestServiceInspectContextErrorsAreStructured(t *testing.T) {
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
		Operation: OperationInspect,
		DriverID:  "fake_runtime",
		Inspect: &InspectRequest{
			Target: lifecycleWorkerTarget("fake_runtime", "dev", "running"),
		},
	})
	if canceledResp.OK || canceledResp.Error == nil || canceledResp.Error.Code != ErrorCodeRequestCanceled {
		t.Fatalf("canceled response = %#v, want request_canceled", canceledResp)
	}

	timeoutCtx, timeoutCancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer timeoutCancel()
	timeoutResp := service.HandleRequest(timeoutCtx, Request{
		RequestID: "req-timeout",
		Operation: OperationInspect,
		DriverID:  "fake_runtime",
		Inspect: &InspectRequest{
			Target: lifecycleWorkerTarget("fake_runtime", "dev", "running"),
		},
	})
	if timeoutResp.OK || timeoutResp.Error == nil || timeoutResp.Error.Code != ErrorCodeRequestTimeout {
		t.Fatalf("timeout response = %#v, want request_timeout", timeoutResp)
	}

	if len(driver.calls) != 0 {
		t.Fatalf("driver calls = %#v, want no calls for already-finished contexts", driver.calls)
	}
}

func assertInspectResponseTarget(t *testing.T, resp Response, name, status string) {
	t.Helper()

	if err := resp.Validate(); err != nil {
		t.Fatalf("inspect response Validate() error: %v", err)
	}
	if !resp.OK || resp.Operation != OperationInspect || resp.Target == nil {
		t.Fatalf("inspect response = %#v, want successful target response", resp)
	}
	if resp.Target.Name != name || resp.Target.Status != status {
		t.Fatalf("inspect target = %#v, want name %q status %q", resp.Target, name, status)
	}
	if resp.Target.Runtime.Driver == "" || resp.Target.Runtime.RuntimeID == "" {
		t.Fatalf("inspect target runtime metadata = %#v, want command-agnostic driver/runtime IDs", resp.Target.Runtime)
	}
}
