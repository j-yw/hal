package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestL4ServerCanonicalReadinessByStateAndBackend(t *testing.T) {
	t.Run("new is not ready", func(t *testing.T) {
		server, err := New(Options{Transport: newL4BlockingTransport(), Backend: &l4FakeBackend{}})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		response := l4HandleJSON[guestagent.ReadinessResponse](t, server, guestagent.ReadinessRequest{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationReadiness,
		})
		l4RequireNotReady(t, response)
		if err := server.Shutdown(context.Background()); err != nil {
			t.Fatalf("Shutdown() error: %v", err)
		}
	})

	t.Run("serving and backend ready", func(t *testing.T) {
		run := startL4Server(t, Options{Transport: newL4BlockingTransport(), Backend: &l4FakeBackend{}})
		response := l4HandleJSON[guestagent.ReadinessResponse](t, run.server, guestagent.ReadinessRequest{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationReadiness,
		})
		if !response.Ready || response.Status != guestagent.ReadinessStatusReady {
			t.Fatalf("readiness = %#v, want ready=true,status=ready", response)
		}
	})

	t.Run("backend unavailable", func(t *testing.T) {
		run := startL4Server(t, Options{
			Transport: newL4BlockingTransport(),
			Backend:   &l4FakeBackend{readyErr: errors.New("backend unavailable")},
		})
		response := l4HandleJSON[guestagent.ReadinessResponse](t, run.server, guestagent.ReadinessRequest{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationReadiness,
		})
		l4RequireNotReady(t, response)
	})

	t.Run("draining and stopped are not ready", func(t *testing.T) {
		closeStarted := make(chan struct{}, 1)
		closeRelease := make(chan struct{})
		backend := &l4FakeBackend{closeStarted: closeStarted, closeRelease: closeRelease}
		run := startL4Server(t, Options{Transport: newL4BlockingTransport(), Backend: backend})
		shutdownDone := make(chan error, 1)
		go func() {
			shutdownDone <- run.server.Shutdown(context.Background())
		}()
		select {
		case <-closeStarted:
		case <-time.After(time.Second):
			t.Fatal("backend close did not start")
		}
		l4WaitState(t, run.server, "draining")
		draining := l4HandleJSON[guestagent.ReadinessResponse](t, run.server, guestagent.ReadinessRequest{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationReadiness,
		})
		l4RequireNotReady(t, draining)
		close(closeRelease)
		if err := <-shutdownDone; err != nil {
			t.Fatalf("Shutdown() error: %v", err)
		}
		l4WaitState(t, run.server, "stopped")
		stopped := l4HandleJSON[guestagent.ReadinessResponse](t, run.server, guestagent.ReadinessRequest{
			ProtocolVersion: guestagent.ProtocolVersionV1,
			Operation:       guestagent.OperationReadiness,
		})
		l4RequireNotReady(t, stopped)
	})
}

func TestL4ServerCancellationAndTimingNeverLeakBackendErrors(t *testing.T) {
	request := guestagent.ExecRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationExec,
		Args:            []string{"tool"},
		WorkDir:         "/workspace",
		Stdout:          guestagent.StreamMetadata{MaxBytes: 16},
		Stderr:          guestagent.StreamMetadata{MaxBytes: 16},
	}

	t.Run("already canceled", func(t *testing.T) {
		backend := &l4FakeBackend{}
		run := startL4Server(t, Options{Transport: newL4BlockingTransport(), Backend: backend})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		response := l4HandleContext(t, ctx, run.server, request)
		l4RequireResponseCode(t, response, guestagent.ErrorCodeRequestCanceled)
		if backend.execCalls.Load() != 0 {
			t.Fatalf("Exec calls = %d, want 0", backend.execCalls.Load())
		}
	})

	t.Run("request timeout", func(t *testing.T) {
		backend := &l4FakeBackend{execRelease: make(chan struct{})}
		run := startL4Server(t, Options{Transport: newL4BlockingTransport(), Backend: backend})
		timed := request
		timed.Timing = &guestagent.TimingMetadata{TimeoutMillis: 1}
		response := l4HandleContext(t, context.Background(), run.server, timed)
		l4RequireResponseCode(t, response, guestagent.ErrorCodeRequestTimeout)
	})

	t.Run("server operation timeout", func(t *testing.T) {
		backend := &l4FakeBackend{execRelease: make(chan struct{})}
		run := startL4Server(t, Options{
			Transport:        newL4BlockingTransport(),
			Backend:          backend,
			MaxOperationTime: time.Millisecond,
		})
		response := l4HandleContext(t, context.Background(), run.server, request)
		l4RequireResponseCode(t, response, guestagent.ErrorCodeRequestTimeout)
	})
}

func TestL4ServerLateBackendSuccessNeverOverridesContext(t *testing.T) {
	copyData := []byte("copy payload")
	copyDigest := digestBytes(copyData)
	tests := []struct {
		name    string
		backend *l4FakeBackend
		request any
	}{
		{
			name:    "readiness",
			backend: &l4FakeBackend{readyReturnAfterContext: true},
			request: guestagent.ReadinessRequest{
				ProtocolVersion: guestagent.ProtocolVersionV1,
				Operation:       guestagent.OperationReadiness,
				Timing:          &guestagent.TimingMetadata{TimeoutMillis: 1},
			},
		},
		{
			name:    "exec",
			backend: &l4FakeBackend{execReturnAfterContext: true},
			request: guestagent.ExecRequest{
				ProtocolVersion: guestagent.ProtocolVersionV1,
				Operation:       guestagent.OperationExec,
				Args:            []string{"tool"},
				WorkDir:         "/workspace",
				Stdout:          guestagent.StreamMetadata{MaxBytes: 16},
				Stderr:          guestagent.StreamMetadata{MaxBytes: 16},
				Timing:          &guestagent.TimingMetadata{TimeoutMillis: 1},
			},
		},
		{
			name: "copy in",
			backend: &l4FakeBackend{
				copyInReturnAfterContext: true,
				copyInResult:             CopyResult{SizeBytes: int64(len(copyData)), Digest: copyDigest},
			},
			request: guestagent.CopyInRequest{
				ProtocolVersion: guestagent.ProtocolVersionV1,
				Operation:       guestagent.OperationCopyIn,
				DestinationPath: "/workspace/input.bin",
				Payload: guestagent.PayloadMetadata{
					SizeBytes: int64(len(copyData)),
					MaxBytes:  64,
					Digest:    copyDigest,
					Encoding:  guestagent.PayloadEncodingBase64,
					Data:      base64.StdEncoding.EncodeToString(copyData),
				},
				Timing: &guestagent.TimingMetadata{TimeoutMillis: 1},
			},
		},
		{
			name: "copy out",
			backend: &l4FakeBackend{
				copyOutReturnAfterContext: true,
				copyOutResult:             CopyResult{Data: copyData, SizeBytes: int64(len(copyData)), Digest: copyDigest},
			},
			request: guestagent.CopyOutRequest{
				ProtocolVersion: guestagent.ProtocolVersionV1,
				Operation:       guestagent.OperationCopyOut,
				SourcePath:      "/workspace/output.bin",
				Payload: guestagent.PayloadMetadata{
					MaxBytes: 64,
					Encoding: guestagent.PayloadEncodingBase64,
				},
				Timing: &guestagent.TimingMetadata{TimeoutMillis: 1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := startL4Server(t, Options{Transport: newL4BlockingTransport(), Backend: tt.backend})
			response := l4Handle(t, run.server, tt.request)
			l4RequireResponseCode(t, response, guestagent.ErrorCodeRequestTimeout)
		})
	}
}

func TestL4ServerCopyInPublishedOutcomeOutranksLateCancellation(t *testing.T) {
	copyData := []byte("published copy payload")
	copyDigest := digestBytes(copyData)
	request := guestagent.CopyInRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationCopyIn,
		DestinationPath: "/workspace/published.bin",
		Payload: guestagent.PayloadMetadata{
			SizeBytes: int64(len(copyData)),
			MaxBytes:  64,
			Digest:    copyDigest,
			Encoding:  guestagent.PayloadEncodingBase64,
			Data:      base64.StdEncoding.EncodeToString(copyData),
		},
		Timing: &guestagent.TimingMetadata{TimeoutMillis: 1},
	}

	t.Run("durable success", func(t *testing.T) {
		backend := &l4FakeBackend{
			copyInReturnAfterContext: true,
			copyInResult:             CopyResult{Published: true, SizeBytes: int64(len(copyData)), Digest: copyDigest},
		}
		run := startL4Server(t, Options{Transport: newL4BlockingTransport(), Backend: backend})
		response := l4HandleJSON[guestagent.CopyInResponse](t, run.server, request)
		if err := guestagent.ValidateCopyInResponse(response); err != nil {
			t.Fatalf("copy-in response error = %v, want committed success", err)
		}
		if response.Written.SizeBytes != int64(len(copyData)) || response.Written.Digest != copyDigest {
			t.Fatalf("written metadata = %#v, want published payload", response.Written)
		}
	})

	t.Run("durability uncertain", func(t *testing.T) {
		backend := &l4FakeBackend{
			copyInReturnAfterContext: true,
			copyInResult:             CopyResult{Published: true, SizeBytes: int64(len(copyData)), Digest: copyDigest},
			copyErr: &guestagent.ProtocolError{
				Code:      guestagent.ErrorCodeDurabilityUncertain,
				Operation: guestagent.OperationCopyIn,
				Field:     "destinationPath",
				Message:   "copy publication durability is uncertain",
			},
		}
		run := startL4Server(t, Options{Transport: newL4BlockingTransport(), Backend: backend})
		response := l4Handle(t, run.server, request)
		l4RequireResponseCode(t, response, guestagent.ErrorCodeDurabilityUncertain)
	})
}

func TestL4ServerBusyAdmissionIsImmediateAndDoesNotQueue(t *testing.T) {
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	backend := &l4FakeBackend{execStarted: started, execRelease: release}
	run := startL4Server(t, Options{
		Transport:     newL4BlockingTransport(),
		Backend:       backend,
		MaxConcurrent: 1,
	})
	request := guestagent.ExecRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationExec,
		Args:            []string{"tool"},
		WorkDir:         "/workspace",
		Stdout:          guestagent.StreamMetadata{MaxBytes: 16},
		Stderr:          guestagent.StreamMetadata{MaxBytes: 16},
	}
	firstDone := make(chan Response, 1)
	go func() {
		firstDone <- l4Handle(t, run.server, request)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first Exec did not reach backend")
	}

	before := time.Now()
	second := l4Handle(t, run.server, request)
	if elapsed := time.Since(before); elapsed > 100*time.Millisecond {
		t.Fatalf("busy response took %s, want nonblocking admission", elapsed)
	}
	l4RequireResponseCode(t, second, guestagent.ErrorCodeServerBusy)
	if backend.execCalls.Load() != 1 {
		t.Fatalf("Exec calls = %d, want 1", backend.execCalls.Load())
	}
	close(release)
	select {
	case <-firstDone:
	case <-time.After(time.Second):
		t.Fatal("first Exec did not finish")
	}
}

func TestL4ServerShutdownBeforeServeIsIdempotentAndClosesOnce(t *testing.T) {
	transport := newL4BlockingTransport()
	backend := &l4FakeBackend{}
	server, err := New(Options{Transport: transport, Backend: backend})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if got := string(server.State()); got != "new" {
		t.Fatalf("State() = %q, want new", got)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() error: %v", err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("second Shutdown() error: %v", err)
	}
	if got := string(server.State()); got != "stopped" {
		t.Fatalf("State() = %q, want stopped", got)
	}
	if backend.closeCalls.Load() != 1 {
		t.Fatalf("Close calls = %d, want 1", backend.closeCalls.Load())
	}
	if err := server.Serve(context.Background()); err == nil {
		t.Fatal("Serve() error = nil after pre-serve shutdown")
	}
	if transport.serveCalls.Load() != 0 {
		t.Fatalf("transport Serve calls = %d, want 0", transport.serveCalls.Load())
	}
}

func TestL4ServerRepeatedShutdownRetainsCleanupFailure(t *testing.T) {
	closeErr := errors.New("backend cleanup failed")
	backend := &l4FakeBackend{closeErr: closeErr}
	server, err := New(Options{Transport: newL4BlockingTransport(), Backend: backend})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if err := server.Shutdown(context.Background()); !errors.Is(err, closeErr) {
		t.Fatalf("Shutdown() error = %v, want cleanup failure", err)
	}
	if err := server.Shutdown(context.Background()); !errors.Is(err, closeErr) {
		t.Fatalf("second Shutdown() error = %v, want retained cleanup failure", err)
	}
	if got := server.State(); got != StateFailed {
		t.Fatalf("State() = %q, want %q", got, StateFailed)
	}
	if backend.closeCalls.Load() != 1 {
		t.Fatalf("Close calls = %d, want 1", backend.closeCalls.Load())
	}
}

func TestL4ServerTransportFailureDrainsThenFailsAndClosesOnce(t *testing.T) {
	transport := newL4BlockingTransport()
	transport.err = errors.New("transport endpoint /private/agent.sock failed")
	closeStarted := make(chan struct{}, 1)
	closeRelease := make(chan struct{})
	backend := &l4FakeBackend{closeStarted: closeStarted, closeRelease: closeRelease}
	server, err := New(Options{Transport: transport, Backend: backend})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(context.Background())
	}()
	<-transport.started
	close(transport.release)
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("transport failure did not start backend cleanup")
	}
	if got := string(server.State()); got != "draining" {
		t.Fatalf("State() during failure cleanup = %q, want draining", got)
	}
	readiness := l4HandleJSON[guestagent.ReadinessResponse](t, server, guestagent.ReadinessRequest{
		ProtocolVersion: guestagent.ProtocolVersionV1,
		Operation:       guestagent.OperationReadiness,
	})
	l4RequireNotReady(t, readiness)
	close(closeRelease)
	if err := <-done; err == nil {
		t.Fatal("Serve() error = nil, want transport failure")
	}
	if got := string(server.State()); got != "failed" {
		t.Fatalf("State() = %q, want failed", got)
	}
	if backend.closeCalls.Load() != 1 {
		t.Fatalf("Close calls = %d, want 1", backend.closeCalls.Load())
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() after failure error: %v", err)
	}
	if backend.closeCalls.Load() != 1 {
		t.Fatalf("Close calls after Shutdown = %d, want 1", backend.closeCalls.Load())
	}
}

func TestL4ServerConcurrentShutdownDoesNotMaskTransportFailure(t *testing.T) {
	transportErr := errors.New("transport failed independently")
	transport := &l4ConcurrentShutdownTransport{
		started:      make(chan struct{}),
		release:      make(chan struct{}),
		shutdownDone: make(chan error, 1),
		err:          transportErr,
	}
	closeStarted := make(chan struct{}, 1)
	closeRelease := make(chan struct{})
	backend := &l4FakeBackend{closeStarted: closeStarted, closeRelease: closeRelease}
	server, err := New(Options{Transport: transport, Backend: backend})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(context.Background())
	}()
	<-transport.started
	close(transport.release)
	<-closeStarted
	close(closeRelease)

	if err := <-done; !errors.Is(err, transportErr) {
		t.Fatalf("Serve() error = %v, want transport failure", err)
	}
	if err := <-transport.shutdownDone; err != nil {
		t.Fatalf("concurrent Shutdown() error: %v", err)
	}
	if got := server.State(); got != StateFailed {
		t.Fatalf("State() = %q, want %q", got, StateFailed)
	}
	if backend.closeCalls.Load() != 1 {
		t.Fatalf("Close calls = %d, want 1", backend.closeCalls.Load())
	}
}

func TestL4ServerCancellationErrorContract(t *testing.T) {
	t.Run("matching context error stops cleanly", func(t *testing.T) {
		transport := newL4CancellationErrorTransport(true)
		server, err := New(Options{Transport: transport, Backend: &l4FakeBackend{}})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- server.Serve(ctx)
		}()
		<-transport.started
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Serve() error = %v, want nil", err)
		}
		if got := server.State(); got != StateStopped {
			t.Fatalf("State() = %q, want %q", got, StateStopped)
		}
	})

	t.Run("nonmatching error fails closed", func(t *testing.T) {
		transportErr := errors.New("listener close failed")
		transport := newL4CancellationErrorTransport(false)
		transport.err = transportErr
		server, err := New(Options{Transport: transport, Backend: &l4FakeBackend{}})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- server.Serve(ctx)
		}()
		<-transport.started
		cancel()
		if err := <-done; !errors.Is(err, transportErr) {
			t.Fatalf("Serve() error = %v, want transport failure", err)
		}
		if got := server.State(); got != StateFailed {
			t.Fatalf("State() = %q, want %q", got, StateFailed)
		}
	})

	t.Run("joined cancellation causes stop cleanly", func(t *testing.T) {
		transport := newL4CancellationErrorTransport(false)
		transport.joinCancellationOnly = true
		server, err := New(Options{Transport: transport, Backend: &l4FakeBackend{}})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- server.Serve(ctx)
		}()
		<-transport.started
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("Serve() error = %v, want nil", err)
		}
		if got := server.State(); got != StateStopped {
			t.Fatalf("State() = %q, want %q", got, StateStopped)
		}
	})

	t.Run("joined cancellation and failure fails closed", func(t *testing.T) {
		transportErr := errors.New("listener close failed")
		transport := newL4CancellationErrorTransport(false)
		transport.err = transportErr
		transport.joinFailureWithCancellation = true
		server, err := New(Options{Transport: transport, Backend: &l4FakeBackend{}})
		if err != nil {
			t.Fatalf("New() error: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() {
			done <- server.Serve(ctx)
		}()
		<-transport.started
		cancel()
		if err := <-done; !errors.Is(err, transportErr) {
			t.Fatalf("Serve() error = %v, want transport failure", err)
		}
		if got := server.State(); got != StateFailed {
			t.Fatalf("State() = %q, want %q", got, StateFailed)
		}
	})
}

func TestL4ServerServeCancellationStopsAndClosesOnce(t *testing.T) {
	transport := newL4BlockingTransport()
	backend := &l4FakeBackend{}
	server, err := New(Options{Transport: transport, Backend: backend})
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
	}()
	<-transport.started
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Serve(canceled) error: %v", err)
	}
	if got := string(server.State()); got != "stopped" {
		t.Fatalf("State() = %q, want stopped", got)
	}
	if backend.closeCalls.Load() != 1 {
		t.Fatalf("Close calls = %d, want 1", backend.closeCalls.Load())
	}
}

type l4ConcurrentShutdownTransport struct {
	started      chan struct{}
	release      chan struct{}
	shutdownDone chan error
	err          error
}

func (transport *l4ConcurrentShutdownTransport) Serve(_ context.Context, _ Limits, handler Handler) error {
	close(transport.started)
	<-transport.release

	server := handler.(*Server)
	go func() {
		transport.shutdownDone <- server.Shutdown(context.Background())
	}()
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for server.State() != StateDraining {
		select {
		case <-deadline.C:
			return errors.New("concurrent shutdown did not begin draining")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	return transport.err
}

type l4CancellationErrorTransport struct {
	started                     chan struct{}
	wrap                        bool
	joinCancellationOnly        bool
	joinFailureWithCancellation bool
	err                         error
}

func newL4CancellationErrorTransport(wrap bool) *l4CancellationErrorTransport {
	return &l4CancellationErrorTransport{started: make(chan struct{}), wrap: wrap}
}

func (transport *l4CancellationErrorTransport) Serve(ctx context.Context, _ Limits, _ Handler) error {
	close(transport.started)
	<-ctx.Done()
	if transport.wrap {
		return fmt.Errorf("transport canceled: %w", ctx.Err())
	}
	if transport.joinCancellationOnly {
		return errors.Join(ctx.Err(), fmt.Errorf("transport canceled: %w", ctx.Err()))
	}
	if transport.joinFailureWithCancellation {
		return errors.Join(ctx.Err(), transport.err)
	}
	return transport.err
}

func l4HandleContext(t *testing.T, ctx context.Context, server *Server, value any) Response {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", value, err)
	}
	return server.Handle(ctx, Request{Encoded: encoded})
}

func l4RequireNotReady(t *testing.T, response guestagent.ReadinessResponse) {
	t.Helper()
	if response.Ready || response.Status != guestagent.ReadinessStatusNotReady {
		t.Fatalf("readiness = %#v, want ready=false,status=not_ready", response)
	}
}
