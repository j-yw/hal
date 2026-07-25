package server

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

type l4FakeBackend struct {
	readyErr error
	execErr  error
	copyErr  error
	closeErr error

	execResult    ExecResult
	copyInResult  CopyResult
	copyOutResult CopyResult

	execStarted  chan struct{}
	execRelease  chan struct{}
	closeStarted chan struct{}
	closeRelease chan struct{}

	readyReturnAfterContext   bool
	execReturnAfterContext    bool
	copyInReturnAfterContext  bool
	copyOutReturnAfterContext bool

	readyCalls   atomic.Int32
	execCalls    atomic.Int32
	copyInCalls  atomic.Int32
	copyOutCalls atomic.Int32
	closeCalls   atomic.Int32

	mu           sync.Mutex
	execPlans    []ExecPlan
	copyInPlans  []CopyInPlan
	copyOutPlans []CopyOutPlan
}

func (backend *l4FakeBackend) Ready(ctx context.Context) error {
	backend.readyCalls.Add(1)
	if backend.readyReturnAfterContext {
		<-ctx.Done()
	}
	return backend.readyErr
}

func (backend *l4FakeBackend) Exec(ctx context.Context, plan ExecPlan) (ExecResult, error) {
	backend.execCalls.Add(1)
	backend.mu.Lock()
	backend.execPlans = append(backend.execPlans, plan)
	backend.mu.Unlock()
	if backend.execStarted != nil {
		select {
		case backend.execStarted <- struct{}{}:
		default:
		}
	}
	if backend.execRelease != nil {
		select {
		case <-ctx.Done():
			return ExecResult{}, ctx.Err()
		case <-backend.execRelease:
		}
	}
	if backend.execReturnAfterContext {
		<-ctx.Done()
	}
	return backend.execResult, backend.execErr
}

func (backend *l4FakeBackend) CopyIn(ctx context.Context, plan CopyInPlan) (CopyResult, error) {
	backend.copyInCalls.Add(1)
	backend.mu.Lock()
	backend.copyInPlans = append(backend.copyInPlans, plan)
	backend.mu.Unlock()
	if backend.copyInReturnAfterContext {
		<-ctx.Done()
	}
	return backend.copyInResult, backend.copyErr
}

func (backend *l4FakeBackend) CopyOut(ctx context.Context, plan CopyOutPlan) (CopyResult, error) {
	backend.copyOutCalls.Add(1)
	backend.mu.Lock()
	backend.copyOutPlans = append(backend.copyOutPlans, plan)
	backend.mu.Unlock()
	if backend.copyOutReturnAfterContext {
		<-ctx.Done()
	}
	return backend.copyOutResult, backend.copyErr
}

func (backend *l4FakeBackend) Close(ctx context.Context) error {
	backend.closeCalls.Add(1)
	if backend.closeStarted != nil {
		select {
		case backend.closeStarted <- struct{}{}:
		default:
		}
	}
	if backend.closeRelease != nil {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-backend.closeRelease:
		}
	}
	return backend.closeErr
}

func (backend *l4FakeBackend) totalOperationCalls() int32 {
	return backend.readyCalls.Load() + backend.execCalls.Load() + backend.copyInCalls.Load() + backend.copyOutCalls.Load()
}

type l4Resolver struct {
	value              string
	err                error
	returnAfterContext bool
	calls              atomic.Int32

	mu      sync.Mutex
	entries []guestagent.EnvironmentEntry
}

func (resolver *l4Resolver) Resolve(ctx context.Context, entry guestagent.EnvironmentEntry) (string, error) {
	resolver.calls.Add(1)
	resolver.mu.Lock()
	resolver.entries = append(resolver.entries, entry)
	resolver.mu.Unlock()
	if resolver.returnAfterContext {
		<-ctx.Done()
	}
	return resolver.value, resolver.err
}

type l4BlockingTransport struct {
	started    chan Limits
	release    chan struct{}
	err        error
	serveCalls atomic.Int32
}

func newL4BlockingTransport() *l4BlockingTransport {
	return &l4BlockingTransport{
		started: make(chan Limits, 1),
		release: make(chan struct{}),
	}
}

func (transport *l4BlockingTransport) Serve(ctx context.Context, limits Limits, _ Handler) error {
	transport.serveCalls.Add(1)
	transport.started <- limits
	select {
	case <-ctx.Done():
		return nil
	case <-transport.release:
		return transport.err
	}
}

type l4ServerRun struct {
	server *Server
	cancel context.CancelFunc
	done   chan error
	limits Limits
}

func startL4Server(t *testing.T, options Options) l4ServerRun {
	t.Helper()

	transport, ok := options.Transport.(*l4BlockingTransport)
	if !ok {
		t.Fatalf("Transport = %T, want *l4BlockingTransport", options.Transport)
	}
	server, err := New(options)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
	}()
	var limits Limits
	select {
	case limits = <-transport.started:
	case <-ctx.Done():
		t.Fatal("Serve() did not start transport")
	}
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
		cancel()
		select {
		case <-done:
		default:
		}
	})
	return l4ServerRun{server: server, cancel: cancel, done: done, limits: limits}
}

func l4DecodeResponse[T any](t *testing.T, response Response) T {
	t.Helper()

	var decoded T
	if err := json.Unmarshal(response.Encoded, &decoded); err != nil {
		t.Fatalf("Unmarshal(%s) error: %v", response.Encoded, err)
	}
	return decoded
}

func l4ResponseError(t *testing.T, response Response) *guestagent.ProtocolError {
	t.Helper()

	var envelope struct {
		ProtocolVersion guestagent.ProtocolVersion `json:"protocolVersion"`
		Operation       guestagent.Operation       `json:"operation,omitempty"`
		Error           *guestagent.ProtocolError  `json:"error"`
	}
	if err := json.Unmarshal(response.Encoded, &envelope); err != nil {
		t.Fatalf("Unmarshal(%s) error: %v", response.Encoded, err)
	}
	if envelope.ProtocolVersion != guestagent.ProtocolVersionV1 {
		t.Fatalf("protocolVersion = %q, want %q", envelope.ProtocolVersion, guestagent.ProtocolVersionV1)
	}
	if envelope.Error == nil {
		t.Fatalf("response = %s, want error envelope", response.Encoded)
	}
	return envelope.Error
}

func l4RequireResponseCode(t *testing.T, response Response, want guestagent.ErrorCode) {
	t.Helper()

	if got := l4ResponseError(t, response).Code; got != want {
		t.Fatalf("error code = %q, want %q; response=%s", got, want, response.Encoded)
	}
}

func l4WaitState(t *testing.T, server *Server, want string) {
	t.Helper()

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if got := string(server.State()); got == want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("State() = %q, want %q", server.State(), want)
}
