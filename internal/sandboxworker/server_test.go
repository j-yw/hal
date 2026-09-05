package sandboxworker

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestServerListenAndServeDispatchesValidatedRequestsOverUnixSocket(t *testing.T) {
	var handled atomic.Bool
	socketPath := testWorkerSocketPath(t)
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler: RequestHandlerFunc(func(_ context.Context, req Request) Response {
			handled.Store(true)
			if req.ProtocolVersion != ProtocolVersion {
				t.Fatalf("handler request protocolVersion = %q, want %q", req.ProtocolVersion, ProtocolVersion)
			}
			if req.Operation != OperationStatus || req.RequestID != "req-001" {
				t.Fatalf("handler request = %#v, want status request req-001", req)
			}
			return Response{
				RequestID: req.RequestID,
				Operation: req.Operation,
				OK:        true,
			}
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)

	resp := roundTripWorkerRequest(t, socketPath, Request{
		RequestID: "req-001",
		Operation: OperationStatus,
	})
	if err := resp.Validate(); err != nil {
		t.Fatalf("response Validate() error: %v", err)
	}
	if !resp.OK || resp.RequestID != "req-001" || resp.Operation != OperationStatus {
		t.Fatalf("response = %#v, want successful status response", resp)
	}
	if !handled.Load() {
		t.Fatal("handler was not called")
	}
}

func TestServiceServesStatusAndCapabilitiesOverUnixSocket(t *testing.T) {
	socketPath := testWorkerSocketPath(t)
	registry, err := NewDriverRegistry(
		&fakeWorkerRuntimeDriver{id: RuntimeDriverSSHMachine},
		&fakeWorkerRuntimeDriver{id: RuntimeDriverRootlessPodman},
	)
	if err != nil {
		t.Fatalf("NewDriverRegistry() error: %v", err)
	}
	service, err := NewService(ServiceOptions{
		WorkerID:   "worker-001",
		SocketPath: socketPath,
		Registry:   registry,
		Health: WorkerHealth{
			Status:  HealthStatusDegraded,
			Message: "warming",
		},
		Capacity: WorkerCapacity{
			MaxConcurrentSandboxes: 3,
			ActiveSandboxes:        1,
		},
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

	statusResp := roundTripWorkerRequest(t, socketPath, Request{
		RequestID: "req-status",
		Operation: OperationStatus,
	})
	if err := statusResp.Validate(); err != nil {
		t.Fatalf("status response Validate() error: %v", err)
	}
	if !statusResp.OK || statusResp.Operation != OperationStatus || statusResp.Status == nil {
		t.Fatalf("status response = %#v, want successful status payload", statusResp)
	}
	if statusResp.Status.WorkerID != "worker-001" || statusResp.Status.SocketPath != socketPath {
		t.Fatalf("status payload = %#v, want configured worker and socket path", statusResp.Status)
	}
	if statusResp.Status.Health.Status != HealthStatusDegraded || statusResp.Status.Capacity.ActiveSandboxes != 1 {
		t.Fatalf("status payload = %#v, want configured health and capacity", statusResp.Status)
	}
	wantDrivers := []string{RuntimeDriverRootlessPodman, RuntimeDriverSSHMachine}
	if len(statusResp.Status.SupportedRuntimeDrivers) != len(wantDrivers) ||
		statusResp.Status.SupportedRuntimeDrivers[0] != wantDrivers[0] ||
		statusResp.Status.SupportedRuntimeDrivers[1] != wantDrivers[1] {
		t.Fatalf("status drivers = %#v, want %#v", statusResp.Status.SupportedRuntimeDrivers, wantDrivers)
	}

	capabilitiesResp := roundTripWorkerRequest(t, socketPath, Request{
		RequestID: "req-capabilities",
		Operation: OperationCapabilities,
	})
	if err := capabilitiesResp.Validate(); err != nil {
		t.Fatalf("capabilities response Validate() error: %v", err)
	}
	if !capabilitiesResp.OK || capabilitiesResp.Operation != OperationCapabilities || capabilitiesResp.Capabilities == nil {
		t.Fatalf("capabilities response = %#v, want successful capabilities payload", capabilitiesResp)
	}
	if capabilitiesResp.Capabilities.WorkerID != "worker-001" {
		t.Fatalf("capabilities workerId = %q, want worker-001", capabilitiesResp.Capabilities.WorkerID)
	}
	if len(capabilitiesResp.Capabilities.RuntimeDrivers) != 2 {
		t.Fatalf("capabilities drivers = %#v, want two registered drivers", capabilitiesResp.Capabilities.RuntimeDrivers)
	}
}

func TestServiceReturnsStructuredOperationErrorsOverUnixSocket(t *testing.T) {
	socketPath := testWorkerSocketPath(t)
	service, err := NewService(ServiceOptions{
		WorkerID:   "worker-001",
		SocketPath: socketPath,
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

	unknownResp := roundTripWorkerRequest(t, socketPath, Request{
		RequestID: "req-unknown",
		Operation: "launch",
	})
	if err := unknownResp.Validate(); err != nil {
		t.Fatalf("unknown response Validate() error: %v", err)
	}
	if unknownResp.OK || unknownResp.Operation != OperationProtocolError || unknownResp.Error == nil {
		t.Fatalf("unknown response = %#v, want structured protocol error", unknownResp)
	}
	if unknownResp.Error.Code != ErrorCodeMalformedRequest {
		t.Fatalf("unknown error code = %q, want %q", unknownResp.Error.Code, ErrorCodeMalformedRequest)
	}

	missingDriverCopyReq := validWorkerCopyInRequest()
	missingDriverCopyReq.RequestID = "req-copy-in"
	missingDriverResp := roundTripWorkerRequest(t, socketPath, missingDriverCopyReq)
	if err := missingDriverResp.Validate(); err != nil {
		t.Fatalf("missing driver response Validate() error: %v", err)
	}
	if missingDriverResp.OK || missingDriverResp.Operation != OperationCopyIn || missingDriverResp.Error == nil {
		t.Fatalf("missing driver response = %#v, want structured driver-not-found error", missingDriverResp)
	}
	if missingDriverResp.Error.Code != ErrorCodeDriverNotFound {
		t.Fatalf("missing driver error code = %q, want %q", missingDriverResp.Error.Code, ErrorCodeDriverNotFound)
	}
}

func TestServerRejectsMalformedRequestsWithStructuredProtocolError(t *testing.T) {
	var handled atomic.Bool
	socketPath := testWorkerSocketPath(t)
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler: RequestHandlerFunc(func(context.Context, Request) Response {
			handled.Store(true)
			return Response{Operation: OperationStatus, OK: true}
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)

	conn := dialWorkerSocket(t, socketPath)
	defer conn.Close()
	if _, err := conn.Write([]byte("{not json")); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error: %v", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("Decode(response) error: %v", err)
	}
	if err := resp.Validate(); err != nil {
		t.Fatalf("response Validate() error: %v", err)
	}
	if resp.OK || resp.Operation != OperationProtocolError || resp.Error == nil {
		t.Fatalf("response = %#v, want structured protocol error", resp)
	}
	if resp.Error.Code != ErrorCodeMalformedRequest {
		t.Fatalf("error code = %q, want %q", resp.Error.Code, ErrorCodeMalformedRequest)
	}
	if !strings.Contains(resp.Error.Message, "malformed worker request") {
		t.Fatalf("error message = %q, want malformed request message", resp.Error.Message)
	}
	if handled.Load() {
		t.Fatal("handler was called for malformed request")
	}
}

func TestServerRejectsInvalidRequestsBeforeDispatch(t *testing.T) {
	var handled atomic.Bool
	socketPath := testWorkerSocketPath(t)
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler: RequestHandlerFunc(func(context.Context, Request) Response {
			handled.Store(true)
			return Response{Operation: OperationStatus, OK: true}
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	defer stopTestServer(t, cancel, errCh)

	resp := roundTripWorkerRequest(t, socketPath, Request{
		RequestID: "req-bad",
		Operation: "launch",
	})
	if err := resp.Validate(); err != nil {
		t.Fatalf("response Validate() error: %v", err)
	}
	if resp.OK || resp.Operation != OperationProtocolError || resp.Error == nil {
		t.Fatalf("response = %#v, want protocol error for invalid request", resp)
	}
	if resp.RequestID != "req-bad" {
		t.Fatalf("response requestID = %q, want req-bad", resp.RequestID)
	}
	if resp.Error.Code != ErrorCodeMalformedRequest {
		t.Fatalf("error code = %q, want %q", resp.Error.Code, ErrorCodeMalformedRequest)
	}
	if handled.Load() {
		t.Fatal("handler was called for invalid request")
	}
}

func TestServerShutdownIsContextAware(t *testing.T) {
	socketPath := testWorkerSocketPath(t)
	server, err := NewServer(ServerOptions{
		SocketPath: socketPath,
		Handler: RequestHandlerFunc(func(context.Context, Request) Response {
			return Response{Operation: OperationStatus, OK: true}
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	cancel, errCh := runTestServer(t, server)
	cancel()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe() error after cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe() did not stop after context cancellation")
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket path still exists after shutdown: %v", err)
	}
}

func TestServerRejectsInvalidConfiguration(t *testing.T) {
	if server, err := NewServer(ServerOptions{
		Handler: RequestHandlerFunc(func(context.Context, Request) Response {
			return Response{Operation: OperationStatus, OK: true}
		}),
	}); err == nil {
		t.Fatalf("NewServer() error = nil, want socketPath error (server %#v)", server)
	}
	if server, err := NewServer(ServerOptions{
		SocketPath: "relative-worker.sock",
		Handler: RequestHandlerFunc(func(context.Context, Request) Response {
			return Response{Operation: OperationStatus, OK: true}
		}),
	}); err == nil {
		t.Fatalf("NewServer() error = nil, want absolute socketPath error (server %#v)", server)
	}
	if server, err := NewServer(ServerOptions{SocketPath: "/tmp/worker.sock"}); err == nil {
		t.Fatalf("NewServer() error = nil, want handler error (server %#v)", server)
	}
	if server, err := NewServer(ServerOptions{
		SocketPath: "/tmp/worker.sock",
		Handler:    RequestHandlerFunc(nil),
	}); err == nil {
		t.Fatalf("NewServer() error = nil, want nil handler function error (server %#v)", server)
	}
}

func TestServerServeRejectsNonUnixListeners(t *testing.T) {
	listener := &fakeWorkerListener{
		addr: fakeWorkerAddr{network: "tcp", address: "127.0.0.1:0"},
	}
	server, err := NewServer(ServerOptions{
		SocketPath: testWorkerSocketPath(t),
		Handler: RequestHandlerFunc(func(context.Context, Request) Response {
			return Response{Operation: OperationStatus, OK: true}
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	err = server.Serve(context.Background(), listener)
	if err == nil {
		t.Fatal("Serve() error = nil, want non-unix listener error")
	}
	if !strings.Contains(err.Error(), "unix is required") {
		t.Fatalf("Serve() error = %q, want unix listener requirement", err.Error())
	}
	if !listener.closed.Load() {
		t.Fatal("Serve() did not close rejected listener")
	}
}

func TestValidateWorkerPeerFilesystemFallbackFailsClosed(t *testing.T) {
	for _, filesystemBoundaryProven := range []bool{false, true} {
		if err := validateWorkerPeerFilesystemFallback(filesystemBoundaryProven); err == nil {
			t.Fatalf("validateWorkerPeerFilesystemFallback(%t) error = nil", filesystemBoundaryProven)
		}
	}
}

func runTestServer(t *testing.T, server *Server) (context.CancelFunc, <-chan error) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.ListenAndServe(ctx)
	}()
	waitForWorkerSocket(t, server.socketPath, errCh)
	return cancel, errCh
}

func testWorkerSocketPath(t *testing.T) string {
	t.Helper()

	return filepath.Join(resolvedWorkerTempDir(t), "worker.sock")
}

func resolvedWorkerTempDir(t *testing.T) string {
	t.Helper()

	tempRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(temp root) error: %v", err)
	}
	dir, err := os.MkdirTemp(tempRoot, "hal-worker-")
	if err != nil {
		t.Fatalf("MkdirTemp(resolved temp root) error: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func stopTestServer(t *testing.T, cancel context.CancelFunc, errCh <-chan error) {
	t.Helper()

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("ListenAndServe() error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ListenAndServe() did not stop")
	}
}

func waitForWorkerSocket(t *testing.T, socketPath string, errCh <-chan error) {
	t.Helper()

	deadline := time.After(2 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Stat(socketPath); err == nil {
			return
		}
		select {
		case err := <-errCh:
			t.Fatalf("ListenAndServe() exited before socket was ready: %v", err)
		case <-deadline:
			t.Fatalf("socket %s was not created", socketPath)
		case <-tick.C:
		}
	}
}

func roundTripWorkerRequest(t *testing.T, socketPath string, req Request) Response {
	t.Helper()

	conn := dialWorkerSocket(t, socketPath)
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("Encode(request) error: %v", err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite(request) error: %v", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("Decode(response) error: %v", err)
	}
	return resp
}

func dialWorkerSocket(t *testing.T, socketPath string) *net.UnixConn {
	t.Helper()

	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("DialTimeout(%s) error: %v", socketPath, err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		t.Fatalf("DialTimeout(%s) returned %T, want *net.UnixConn", socketPath, conn)
	}
	if err := unixConn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		unixConn.Close()
		t.Fatalf("SetDeadline() error: %v", err)
	}
	return unixConn
}

type fakeWorkerListener struct {
	addr   net.Addr
	closed atomic.Bool
}

func (listener *fakeWorkerListener) Accept() (net.Conn, error) {
	return nil, net.ErrClosed
}

func (listener *fakeWorkerListener) Close() error {
	listener.closed.Store(true)
	return nil
}

func (listener *fakeWorkerListener) Addr() net.Addr {
	return listener.addr
}

type fakeWorkerAddr struct {
	network string
	address string
}

func (addr fakeWorkerAddr) Network() string {
	return addr.network
}

func (addr fakeWorkerAddr) String() string {
	return addr.address
}
