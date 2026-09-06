package vsock

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/frame"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

func TestL5GuestVsockTransportDispatchesOneBoundedFrameAndCloses(t *testing.T) {
	var input bytes.Buffer
	request := []byte(`{"protocolVersion":"guest-agent-v1"}`)
	if err := frame.Write(&input, request, 1024); err != nil {
		t.Fatalf("frame.Write() error = %v", err)
	}
	conn := &l5MemoryConn{input: &input}
	listener := &l5Listener{conn: conn}
	transport, err := NewTransport(Options{Listener: listener})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- transport.Serve(ctx, server.Limits{
			MaxRequestBytes:  1024,
			MaxResponseBytes: 1024,
		}, l5HandlerFunc(func(_ context.Context, request server.Request) server.Response {
			cancel()
			return server.Response{Encoded: append([]byte("ack:"), request.Encoded...)}
		}))
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop")
	}
	response, err := frame.Read(bytes.NewReader(conn.output.Bytes()), 1024)
	if err != nil {
		t.Fatalf("frame.Read(response) error = %v", err)
	}
	if got := string(response); got != `ack:{"protocolVersion":"guest-agent-v1"}` {
		t.Fatalf("response = %q", got)
	}
	if conn.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", conn.closeCalls)
	}
}

func TestL5GuestVsockTransportRejectsOversizedRequestBeforeHandler(t *testing.T) {
	conn := &l5MemoryConn{input: l5FramedInput(t, bytes.Repeat([]byte("x"), 9))}
	listener := &l5Listener{conn: conn}
	transport, err := NewTransport(Options{Listener: listener})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	called := false
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	_ = transport.Serve(ctx, server.Limits{MaxRequestBytes: 8, MaxResponseBytes: 512}, l5HandlerFunc(func(context.Context, server.Request) server.Response {
		called = true
		return server.Response{}
	}))
	if called {
		t.Fatal("handler called for oversized request")
	}
	if conn.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", conn.closeCalls)
	}
}

func TestL5GuestVsockTransportRecoversHandlerPanicAndClosesConnection(t *testing.T) {
	conn := &l5MemoryConn{input: l5FramedInput(t, []byte(`{}`))}
	listener := &l5Listener{conn: conn}
	transport, err := NewTransport(Options{Listener: listener, MaxConnections: 1})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	_ = transport.Serve(ctx, server.Limits{MaxRequestBytes: 8, MaxResponseBytes: 512}, l5HandlerFunc(func(context.Context, server.Request) server.Response {
		panic("path=/private token=ghp_secret")
	}))
	if conn.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1 after handler panic", conn.closeCalls)
	}
	if bytes.Contains(conn.output.Bytes(), []byte("ghp_secret")) || bytes.Contains(conn.output.Bytes(), []byte("/private")) {
		t.Fatalf("panic detail leaked to response: %q", conn.output.Bytes())
	}
}

func TestL5GuestVsockTransportCancellationClosesBlockedAcceptedConnection(t *testing.T) {
	conn := newL5BlockingConn()
	listener := &l5BlockingListener{conn: conn}
	transport, err := NewTransport(Options{Listener: listener})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- transport.Serve(ctx, server.Limits{
			MaxRequestBytes:  1024,
			MaxResponseBytes: 1024,
		}, l5HandlerFunc(func(context.Context, server.Request) server.Response {
			return server.Response{}
		}))
	}()
	select {
	case <-conn.readStarted:
	case <-time.After(time.Second):
		t.Fatal("accepted connection did not begin its blocking read")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not close the blocked accepted connection")
	}
	if got := conn.closeCount(); got != 1 {
		t.Fatalf("connection close calls = %d, want exactly 1", got)
	}
}

func TestL5GuestVsockTransportPeerFullCloseCancelsHandler(t *testing.T) {
	conn := newL5PeerCloseConn(l5FramedInput(t, []byte(`{"protocolVersion":"guest-agent-v1"}`)))
	listener := &l5BlockingListener{conn: conn}
	transport, err := NewTransport(Options{Listener: listener})
	if err != nil {
		t.Fatalf("NewTransport() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handlerStarted := make(chan struct{})
	handlerCanceled := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- transport.Serve(ctx, server.Limits{
			MaxRequestBytes:  1024,
			MaxResponseBytes: 1024,
		}, l5HandlerFunc(func(handlerCtx context.Context, _ server.Request) server.Response {
			close(handlerStarted)
			<-handlerCtx.Done()
			close(handlerCanceled)
			cancel()
			return server.Response{Encoded: []byte(`{"canceled":true}`)}
		}))
	}()
	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("peer-close fixture did not dispatch its handler")
	}
	close(conn.peerClosed)
	select {
	case <-handlerCanceled:
	case <-time.After(time.Second):
		t.Fatal("full peer close did not cancel the per-request handler context")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop after peer-close cancellation")
	}
}

type l5HandlerFunc func(context.Context, server.Request) server.Response

func (fn l5HandlerFunc) Handle(ctx context.Context, request server.Request) server.Response {
	return fn(ctx, request)
}

type l5Listener struct {
	mu       sync.Mutex
	conn     io.ReadWriteCloser
	accepted bool
}

func (listener *l5Listener) Accept(context.Context) (io.ReadWriteCloser, error) {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if !listener.accepted {
		listener.accepted = true
		return listener.conn, nil
	}
	return nil, context.Canceled
}

func (*l5Listener) Close() error { return nil }

type l5MemoryConn struct {
	input      *bytes.Buffer
	output     bytes.Buffer
	closeCalls int
}

func l5FramedInput(t *testing.T, payload []byte) *bytes.Buffer {
	t.Helper()
	var input bytes.Buffer
	if err := frame.Write(&input, payload, int64(len(payload))); err != nil {
		t.Fatalf("frame.Write() error = %v", err)
	}
	return &input
}

func (conn *l5MemoryConn) Read(p []byte) (int, error)  { return conn.input.Read(p) }
func (conn *l5MemoryConn) Write(p []byte) (int, error) { return conn.output.Write(p) }
func (conn *l5MemoryConn) Close() error {
	conn.closeCalls++
	return nil
}

type l5BlockingListener struct {
	conn     io.ReadWriteCloser
	accepted chan struct{}
	closed   chan struct{}
	once     sync.Once
}

func (listener *l5BlockingListener) Accept(ctx context.Context) (io.ReadWriteCloser, error) {
	if listener.accepted == nil {
		listener.accepted = make(chan struct{})
		listener.closed = make(chan struct{})
		close(listener.accepted)
		return listener.conn, nil
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-listener.closed:
		return nil, context.Canceled
	}
}

func (listener *l5BlockingListener) Close() error {
	listener.once.Do(func() {
		if listener.closed == nil {
			listener.closed = make(chan struct{})
		}
		close(listener.closed)
	})
	return nil
}

type l5BlockingConn struct {
	readStarted chan struct{}
	closed      chan struct{}
	startOnce   sync.Once
	closeOnce   sync.Once
	mu          sync.Mutex
	closeCalls  int
}

func newL5BlockingConn() *l5BlockingConn {
	return &l5BlockingConn{
		readStarted: make(chan struct{}),
		closed:      make(chan struct{}),
	}
}

func (conn *l5BlockingConn) Read([]byte) (int, error) {
	conn.startOnce.Do(func() { close(conn.readStarted) })
	<-conn.closed
	return 0, io.EOF
}

func (*l5BlockingConn) Write(value []byte) (int, error) { return len(value), nil }

func (conn *l5BlockingConn) Close() error {
	conn.closeOnce.Do(func() {
		conn.mu.Lock()
		conn.closeCalls++
		conn.mu.Unlock()
		close(conn.closed)
	})
	return nil
}

func (conn *l5BlockingConn) closeCount() int {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.closeCalls
}

type l5PeerCloseConn struct {
	input      *bytes.Buffer
	output     bytes.Buffer
	peerClosed chan struct{}
}

func newL5PeerCloseConn(input *bytes.Buffer) *l5PeerCloseConn {
	return &l5PeerCloseConn{
		input:      input,
		peerClosed: make(chan struct{}),
	}
}

func (conn *l5PeerCloseConn) Read(value []byte) (int, error) {
	return conn.input.Read(value)
}

func (conn *l5PeerCloseConn) Write(value []byte) (int, error) {
	return conn.output.Write(value)
}

func (*l5PeerCloseConn) Close() error {
	return nil
}

func (conn *l5PeerCloseConn) WaitPeerClosed(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-conn.peerClosed:
		return nil
	}
}
