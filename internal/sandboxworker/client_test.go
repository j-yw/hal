package sandboxworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClientStatusAndCapabilitiesOverUnixSocket(t *testing.T) {
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
			MaxConcurrentSandboxes: 2,
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

	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	status, err := client.Status(context.Background())
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if status.WorkerID != "worker-001" || status.SocketPath != socketPath {
		t.Fatalf("Status() = %#v, want configured worker and socket path", status)
	}
	if status.Health.Status != HealthStatusDegraded || status.Capacity.ActiveSandboxes != 1 {
		t.Fatalf("Status() = %#v, want configured health and capacity", status)
	}
	wantDrivers := []string{RuntimeDriverRootlessPodman, RuntimeDriverSSHMachine}
	if len(status.SupportedRuntimeDrivers) != len(wantDrivers) ||
		status.SupportedRuntimeDrivers[0] != wantDrivers[0] ||
		status.SupportedRuntimeDrivers[1] != wantDrivers[1] {
		t.Fatalf("Status() drivers = %#v, want %#v", status.SupportedRuntimeDrivers, wantDrivers)
	}

	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatalf("Capabilities() error: %v", err)
	}
	if capabilities.WorkerID != "worker-001" {
		t.Fatalf("Capabilities() workerId = %q, want worker-001", capabilities.WorkerID)
	}
	if len(capabilities.RuntimeDrivers) != 2 {
		t.Fatalf("Capabilities() runtime drivers = %#v, want two registered drivers", capabilities.RuntimeDrivers)
	}
}

func TestClientUsesInjectedTransportAndPropagatesContext(t *testing.T) {
	var called atomic.Bool
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(ctx context.Context, req Request) (Response, error) {
			called.Store(true)
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("transport context did not include caller deadline")
			}
			if req.ProtocolVersion != ProtocolVersion {
				t.Fatalf("request protocolVersion = %q, want %q", req.ProtocolVersion, ProtocolVersion)
			}
			if req.Operation != OperationStatus || !strings.HasPrefix(req.RequestID, OperationStatus+"-") {
				t.Fatalf("request = %#v, want status request with generated request ID", req)
			}
			status := validClientTestStatus("")
			return Response{
				RequestID: req.RequestID,
				Operation: req.Operation,
				OK:        true,
				Status:    &status,
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if !called.Load() {
		t.Fatal("injected transport was not called")
	}
	if status.WorkerID != "worker-001" {
		t.Fatalf("Status() workerId = %q, want worker-001", status.WorkerID)
	}
}

func TestClientReturnsCancellationAndTimeoutErrors(t *testing.T) {
	var called atomic.Bool
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(ctx context.Context, req Request) (Response, error) {
			called.Store(true)
			<-ctx.Done()
			return Response{}, ctx.Err()
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Status(canceledCtx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Status(canceled) error = %v, want context.Canceled", err)
	}
	if called.Load() {
		t.Fatal("transport was called for already-canceled context")
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer timeoutCancel()
	if _, err := client.Capabilities(timeoutCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Capabilities(timeout) error = %v, want context deadline", err)
	}
	if !called.Load() {
		t.Fatal("transport was not called before timeout")
	}
}

func TestClientRejectsMalformedResponses(t *testing.T) {
	tests := []struct {
		name      string
		transport ClientTransport
		want      string
	}{
		{
			name: "invalid response operation",
			transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
				return Response{
					RequestID: req.RequestID,
					Operation: "launch",
					OK:        true,
				}, nil
			}),
			want: ErrorCodeMalformedRequest,
		},
		{
			name: "missing status payload",
			transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
				return Response{
					RequestID: req.RequestID,
					Operation: req.Operation,
					OK:        true,
				}, nil
			}),
			want: "status payload",
		},
		{
			name: "mismatched request id",
			transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
				status := validClientTestStatus("")
				return Response{
					RequestID: "other-" + req.RequestID,
					Operation: req.Operation,
					OK:        true,
					Status:    &status,
				}, nil
			}),
			want: "requestId",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := NewClient(ClientOptions{Transport: tt.transport})
			if err != nil {
				t.Fatalf("NewClient() error: %v", err)
			}
			_, err = client.Status(context.Background())
			if err == nil {
				t.Fatal("Status() error = nil, want malformed response error")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Status() error = %q, want substring %q", err.Error(), tt.want)
			}
		})
	}
}

func TestClientRejectsMalformedJSONResponseOverUnixSocket(t *testing.T) {
	socketPath := runRawWorkerResponseSocket(t, "{not json\n")
	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = client.Status(context.Background())
	if err == nil {
		t.Fatal("Status() error = nil, want malformed JSON response error")
	}
	if !strings.Contains(err.Error(), "read worker response") {
		t.Fatalf("Status() error = %q, want read response detail", err.Error())
	}
}

func TestClientReturnsProtocolErrorsWithSanitizedDetail(t *testing.T) {
	client, err := NewClient(ClientOptions{
		Transport: ClientTransportFunc(func(_ context.Context, req Request) (Response, error) {
			return Response{
				RequestID: req.RequestID,
				Operation: req.Operation,
				OK:        false,
				Error: &Error{
					Code:    ErrorCodeUnsupportedOp,
					Message: "provider failed token=raw-secret from /Users/alice/worktree",
				},
			}, nil
		}),
	})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = client.Status(context.Background())
	if err == nil {
		t.Fatal("Status() error = nil, want protocol error")
	}
	var protocolErr *ProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("Status() error = %T, want *ProtocolError", err)
	}
	if protocolErr.Code != ErrorCodeUnsupportedOp {
		t.Fatalf("ProtocolError.Code = %q, want %q", protocolErr.Code, ErrorCodeUnsupportedOp)
	}
	message := err.Error()
	for _, unsafe := range []string{"raw-secret", "/Users/alice", "worktree"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("protocol error leaked unsafe detail %q in %q", unsafe, message)
		}
	}
	for _, want := range []string{"token=[redacted]", "[redacted-path]"} {
		if !strings.Contains(message, want) {
			t.Fatalf("protocol error = %q, want sanitized detail %q", message, want)
		}
	}
}

func TestClientConnectionFailureIsSanitized(t *testing.T) {
	const socketPath = "/tmp/hal-worker-token=raw-secret/missing.sock"
	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}

	_, err = client.Status(context.Background())
	if err == nil {
		t.Fatal("Status() error = nil, want connection failure")
	}
	message := err.Error()
	for _, unsafe := range []string{socketPath, "raw-secret", "hal-worker-token"} {
		if strings.Contains(message, unsafe) {
			t.Fatalf("connection error leaked unsafe detail %q in %q", unsafe, message)
		}
	}
	if !strings.Contains(message, "[redacted-path]") {
		t.Fatalf("connection error = %q, want redacted path marker", message)
	}
}

func TestNewClientRejectsInvalidConfiguration(t *testing.T) {
	if client, err := NewClient(ClientOptions{}); err == nil {
		t.Fatalf("NewClient() error = nil, want socketPath or transport error (client %#v)", client)
	}
	if client, err := NewClient(ClientOptions{Transport: ClientTransportFunc(nil)}); err == nil {
		t.Fatalf("NewClient() error = nil, want nil transport function error (client %#v)", client)
	}
}

func validClientTestStatus(socketPath string) Status {
	return Status{
		ProtocolVersion: ProtocolVersion,
		WorkerID:        "worker-001",
		HostKind:        HostKindLocal,
		SocketPath:      socketPath,
		Health: WorkerHealth{
			Status: HealthStatusHealthy,
		},
		Capacity: WorkerCapacity{
			MaxConcurrentSandboxes: 1,
		},
		Security: DefaultWorkerSecurityPolicy(),
	}
}

func runRawWorkerResponseSocket(t *testing.T, payload string) string {
	t.Helper()

	socketPath := testWorkerSocketPath(t)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("Listen(unix, %s) error: %v", socketPath, err)
	}
	errCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		var req Request
		_ = json.NewDecoder(conn).Decode(&req)
		_, err = io.WriteString(conn, payload)
		errCh <- err
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case err := <-errCh:
			if err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("raw response socket error: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("raw response socket did not stop")
		}
	})
	return socketPath
}
