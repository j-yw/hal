package vsock

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server"
)

func TestL5GuestVsockTransportDispatchesOneBoundedFrameAndCloses(t *testing.T) {
	conn := &l5MemoryConn{input: bytes.NewBufferString(`{"protocolVersion":"guest-agent-v1"}`)}
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
	if got := conn.output.String(); got != `ack:{"protocolVersion":"guest-agent-v1"}` {
		t.Fatalf("output = %q", got)
	}
	if conn.closeCalls != 1 {
		t.Fatalf("close calls = %d, want 1", conn.closeCalls)
	}
}

func TestL5GuestVsockTransportRejectsOversizedRequestBeforeHandler(t *testing.T) {
	conn := &l5MemoryConn{input: bytes.NewBuffer(bytes.Repeat([]byte("x"), 9))}
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
	conn := &l5MemoryConn{input: bytes.NewBufferString(`{}`)}
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

func (conn *l5MemoryConn) Read(p []byte) (int, error)  { return conn.input.Read(p) }
func (conn *l5MemoryConn) Write(p []byte) (int, error) { return conn.output.Write(p) }
func (conn *l5MemoryConn) Close() error {
	conn.closeCalls++
	return nil
}
