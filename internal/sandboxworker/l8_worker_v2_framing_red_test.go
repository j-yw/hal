package sandboxworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestL8WorkerV2ServerWaitsForRequestEOFBeforeDispatch(t *testing.T) {
	dispatched := make(chan struct{}, 1)
	server := &Server{
		maxRequestBytes: defaultMaxRequestBytes,
		handler: RequestHandlerFunc(func(_ context.Context, request Request) Response {
			dispatched <- struct{}{}
			return l8WorkerV2FramingStatusResponse(request)
		}),
	}
	request := Request{ProtocolVersion: ProtocolVersion, RequestID: "request-framing", Operation: OperationStatus}
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("Marshal(request) error: %v", err)
	}
	raw = append(raw, '\n')
	clientConn, postFrameRead, connectionDone, cancel := l8WorkerV2OpenObservedUnixConnection(t, server, len(raw))
	defer cancel()
	defer clientConn.Close()
	if _, err := clientConn.Write(raw); err != nil {
		t.Fatalf("Write(request) error: %v", err)
	}
	select {
	case <-dispatched:
		t.Fatal("server dispatched a complete-looking request before request EOF")
	case <-postFrameRead:
	case <-time.After(2 * time.Second):
		t.Fatal("server neither awaited request EOF nor dispatched")
	}
	select {
	case <-dispatched:
		t.Fatal("server dispatched while the request write half remained open")
	default:
	}
	if err := clientConn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite(request) error: %v", err)
	}
	select {
	case <-dispatched:
	case <-time.After(2 * time.Second):
		t.Fatal("server did not promptly dispatch after request EOF")
	}
	var response Response
	if err := json.NewDecoder(clientConn).Decode(&response); err != nil {
		t.Fatalf("Decode(response) error: %v", err)
	}
	if response.RequestID != request.RequestID || response.Operation != request.Operation || !response.OK {
		t.Fatalf("response = %#v, want matching successful status response", response)
	}
	l8WorkerV2AwaitConnectionDone(t, connectionDone)
}

func TestL8WorkerV2MissingRequestHalfCloseUnblocksOnPeerCloseOrServerCancellation(t *testing.T) {
	for _, test := range []struct {
		name     string
		complete bool
		unblock  func(*net.UnixConn, context.CancelFunc) error
	}{
		{name: "peer close with partial JSON", complete: false, unblock: func(connection *net.UnixConn, _ context.CancelFunc) error { return connection.Close() }},
		{name: "server cancellation", complete: true, unblock: func(_ *net.UnixConn, cancel context.CancelFunc) error { cancel(); return nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			dispatched := make(chan struct{}, 1)
			server := &Server{
				maxRequestBytes: defaultMaxRequestBytes,
				handler: RequestHandlerFunc(func(_ context.Context, request Request) Response {
					dispatched <- struct{}{}
					return l8WorkerV2FramingStatusResponse(request)
				}),
			}
			request := Request{ProtocolVersion: ProtocolVersion, RequestID: "request-incomplete-frame", Operation: OperationStatus}
			var raw []byte
			if test.complete {
				var err error
				raw, err = json.Marshal(request)
				if err != nil {
					t.Fatalf("Marshal(request) error: %v", err)
				}
				raw = append(raw, '\n')
			} else {
				raw = []byte(`{"protocolVersion":"sandboxworker-v1","operation":"status"`)
			}
			clientConn, postFrameRead, connectionDone, cancel := l8WorkerV2OpenObservedUnixConnection(t, server, len(raw))
			defer cancel()
			defer clientConn.Close()
			if _, err := clientConn.Write(raw); err != nil {
				t.Fatalf("Write(request) error: %v", err)
			}
			select {
			case <-dispatched:
				t.Fatal("server dispatched before request EOF")
			case <-postFrameRead:
			case <-time.After(2 * time.Second):
				t.Fatal("server did not enter the post-frame EOF read")
			}
			if err := test.unblock(clientConn, cancel); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("unblock connection error: %v", err)
			}
			l8WorkerV2AwaitConnectionDone(t, connectionDone)
			select {
			case <-dispatched:
				t.Fatal("incomplete request was dispatched during cleanup")
			default:
			}
		})
	}
}

func TestL8WorkerV2OfficialUnixClientHalfClosesRequestBeforeReadingResponse(t *testing.T) {
	socketPath, requestEOF, serverDone := l8WorkerV2StartRawUnixResponder(t, func(request Request) ([]byte, error) {
		response := l8WorkerV2FramingStatusResponse(request)
		return json.Marshal(response)
	})
	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	status, err := client.Status(ctx)
	if err != nil {
		t.Fatalf("Status() error: %v", err)
	}
	if status.WorkerID != "worker-framing" {
		t.Fatalf("Status() workerID = %q, want worker-framing", status.WorkerID)
	}
	select {
	case <-requestEOF:
	default:
		t.Fatal("raw server responded without observing request EOF")
	}
	l8WorkerV2AwaitRawServerDone(t, serverDone)
}

func TestL8WorkerV2OfficialUnixClientOmitsMalformedResponseCanaryFromError(t *testing.T) {
	const canary = "opaque-canary"
	socketPath, requestEOF, serverDone := l8WorkerV2StartRawUnixResponder(t, func(request Request) ([]byte, error) {
		response, err := json.Marshal(l8WorkerV2FramingStatusResponse(request))
		if err != nil {
			return nil, err
		}
		return bytes.Replace(response, []byte(`"ok":true`), []byte(`"ok":true,"ticket":"`+canary+`"`), 1), nil
	})
	client, err := NewClient(ClientOptions{SocketPath: socketPath})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = client.Status(ctx)
	if err == nil {
		t.Fatal("client accepted a response with an unknown canary field")
	}
	if !strings.Contains(err.Error(), "read worker response failed") {
		t.Fatalf("client error = %q, want stable safe response-decode category", err)
	}
	if strings.Contains(err.Error(), "ticket") || strings.Contains(err.Error(), canary) {
		t.Fatalf("client error leaked malformed response field/value: %q", err)
	}
	select {
	case <-requestEOF:
	default:
		t.Fatal("malformed responder did not observe request EOF")
	}
	l8WorkerV2AwaitRawServerSuccess(t, serverDone)
}

func TestL8WorkerV2ConfiguredCodecLimitsPreserveFullPositiveRange(t *testing.T) {
	for _, limit := range []int64{(1 << 20) + 1, math.MaxInt64} {
		handler := RequestHandlerFunc(func(_ context.Context, request Request) Response {
			return l8WorkerV2FramingStatusResponse(request)
		})
		server, err := NewServer(ServerOptions{SocketPath: l8WorkerV2SocketPath(t), Handler: handler, MaxRequestBytes: limit})
		if err != nil {
			t.Fatalf("NewServer(%d) error: %v", limit, err)
		}
		if server.maxRequestBytes != limit {
			t.Fatalf("server maxRequestBytes = %d, want exact %d", server.maxRequestBytes, limit)
		}
		client, err := NewClient(ClientOptions{SocketPath: l8WorkerV2SocketPath(t), MaxResponseBytes: limit})
		if err != nil {
			t.Fatalf("NewClient(%d) error: %v", limit, err)
		}
		transport, ok := client.transport.(unixSocketClientTransport)
		if !ok {
			t.Fatalf("NewClient(%d) transport = %T, want unixSocketClientTransport", limit, client.transport)
		}
		if transport.maxResponseBytes != limit {
			t.Fatalf("client maxResponseBytes = %d, want exact %d", transport.maxResponseBytes, limit)
		}
	}
}

func TestL8WorkerV2ConfiguredCodecLimitsCarryRequestAndResponseAboveOneMiB(t *testing.T) {
	const limit int64 = 2 << 20
	padding := strings.Repeat("x", (1<<20)+1)
	socketPath := l8WorkerV2SocketPath(t)
	server, err := NewServer(ServerOptions{
		SocketPath:      socketPath,
		MaxRequestBytes: limit,
		Handler: RequestHandlerFunc(func(_ context.Context, request Request) Response {
			return Response{RequestID: request.RequestID, Operation: request.Operation, OK: true, Target: &request.Inspect.Target}
		}),
	})
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}
	serverContext, cancelServer := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() { serverDone <- server.ListenAndServe(serverContext) }()
	l8WorkerV2AwaitSocket(t, socketPath, serverDone)
	defer func() {
		cancelServer()
		l8WorkerV2AwaitRawServerDone(t, serverDone)
	}()
	client, err := NewClient(ClientOptions{SocketPath: socketPath, MaxResponseBytes: limit})
	if err != nil {
		t.Fatalf("NewClient() error: %v", err)
	}
	target := Target{Name: "sandbox-large", Runtime: RuntimeTarget{Driver: RuntimeDriverMicroVM}, Labels: map[string]string{"padding": padding}}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	got, err := client.Inspect(ctx, RuntimeDriverMicroVM, InspectRequest{Target: target})
	if err != nil {
		t.Fatalf("Inspect(>1MiB request/response) error: %v", err)
	}
	if got.Labels["padding"] != padding {
		t.Fatalf("Inspect() padding length = %d, want %d", len(got.Labels["padding"]), len(padding))
	}
}

type l8WorkerV2ObservedUnixConn struct {
	*net.UnixConn
	expected      int
	read          int
	postFrameRead chan struct{}
	postFrameOnce sync.Once
}

func (connection *l8WorkerV2ObservedUnixConn) Read(payload []byte) (int, error) {
	if connection.read >= connection.expected {
		connection.postFrameOnce.Do(func() { close(connection.postFrameRead) })
	}
	n, err := connection.UnixConn.Read(payload)
	connection.read += n
	return n, err
}

func l8WorkerV2OpenObservedUnixConnection(t *testing.T, server *Server, expected int) (*net.UnixConn, <-chan struct{}, <-chan struct{}, context.CancelFunc) {
	t.Helper()
	socketPath := l8WorkerV2SocketPath(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix() error: %v", err)
	}
	postFrameRead := make(chan struct{})
	connectionDone := make(chan struct{})
	serverContext, cancel := context.WithCancel(context.Background())
	go func() {
		defer close(connectionDone)
		defer listener.Close()
		connection, acceptErr := listener.AcceptUnix()
		if acceptErr != nil {
			return
		}
		server.handleConnection(serverContext, &l8WorkerV2ObservedUnixConn{UnixConn: connection, expected: expected, postFrameRead: postFrameRead})
	}()
	clientConn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		cancel()
		listener.Close()
		t.Fatalf("DialUnix() error: %v", err)
	}
	if err := clientConn.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		clientConn.Close()
		cancel()
		listener.Close()
		t.Fatalf("SetDeadline() error: %v", err)
	}
	return clientConn, postFrameRead, connectionDone, cancel
}

func l8WorkerV2FramingStatusResponse(request Request) Response {
	return Response{
		RequestID: request.RequestID,
		Operation: request.Operation,
		OK:        true,
		Status: &Status{
			WorkerID: "worker-framing",
			HostKind: HostKindLocal,
			Health:   WorkerHealth{Status: HealthStatusHealthy},
		},
	}
}

func l8WorkerV2StartRawUnixResponder(t *testing.T, response func(Request) ([]byte, error)) (string, <-chan struct{}, <-chan error) {
	t.Helper()
	socketPath := l8WorkerV2SocketPath(t)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		t.Fatalf("ListenUnix() error: %v", err)
	}
	requestEOF := make(chan struct{})
	done := make(chan error, 1)
	terminated := make(chan struct{})
	var connectionMu sync.Mutex
	var acceptedConnection *net.UnixConn
	stopping := false
	go func() {
		defer close(terminated)
		defer listener.Close()
		connection, err := listener.AcceptUnix()
		if err != nil {
			done <- err
			return
		}
		connectionMu.Lock()
		acceptedConnection = connection
		if stopping {
			connection.Close()
		}
		connectionMu.Unlock()
		defer connection.Close()
		raw, err := io.ReadAll(connection)
		if err != nil {
			done <- err
			return
		}
		close(requestEOF)
		var request Request
		if err := json.Unmarshal(raw, &request); err != nil {
			done <- err
			return
		}
		payload, err := response(request)
		if err != nil {
			done <- err
			return
		}
		if _, err := connection.Write(append(payload, '\n')); err != nil {
			done <- err
			return
		}
		done <- nil
	}()
	t.Cleanup(func() {
		listener.Close()
		connectionMu.Lock()
		stopping = true
		if acceptedConnection != nil {
			acceptedConnection.Close()
		}
		connectionMu.Unlock()
		select {
		case <-terminated:
		case <-time.After(2 * time.Second):
			t.Error("raw Unix responder did not terminate during cleanup")
		}
	})
	return socketPath, requestEOF, done
}

func l8WorkerV2SocketPath(t *testing.T) string {
	t.Helper()
	resolvedTempDir, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(temp dir) error: %v", err)
	}
	directory, err := os.MkdirTemp(resolvedTempDir, "hal-worker-l8-")
	if err != nil {
		t.Fatalf("MkdirTemp(socket dir) error: %v", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		os.RemoveAll(directory)
		t.Fatalf("Chmod(socket dir) error: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	return filepath.Join(directory, "worker.sock")
}

func l8WorkerV2AwaitConnectionDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("server connection did not promptly clean up")
	}
}

func l8WorkerV2AwaitRawServerDone(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Unix server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Unix server did not promptly stop")
	}
}

func l8WorkerV2AwaitRawServerSuccess(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Unix server error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Unix server did not promptly stop")
	}
}

func l8WorkerV2AwaitSocket(t *testing.T, socketPath string, serverDone <-chan error) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		connection, err := net.DialTimeout("unix", socketPath, 20*time.Millisecond)
		if err == nil {
			connection.Close()
			return
		}
		select {
		case serverErr := <-serverDone:
			t.Fatalf("ListenAndServe() exited before readiness: %v", serverErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("socket %s was not ready: %v", socketPath, err)
		}
	}
}
