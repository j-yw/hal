package server

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"
)

// Server dispatches bounded guest-agent protocol requests through an injected
// transport and backend.
type Server struct {
	transport Transport
	backend   Backend
	resolver  EnvironmentResolver
	limits    Limits

	maxOperationTime time.Duration
	maxShutdownTime  time.Duration
	admission        chan struct{}

	mu              sync.Mutex
	state           State
	serveUsed       bool
	serveCancel     context.CancelFunc
	operationCtx    context.Context
	operationCancel context.CancelFunc
	operations      sync.WaitGroup
	transportDone   chan struct{}
	transportOnce   sync.Once

	cleanupOnce sync.Once
	cleanupDone chan struct{}
	terminal    State
	cleanupErr  error
}

// New constructs a server without starting its transport.
func New(options Options) (*Server, error) {
	if !configuredDependency(options.Transport) {
		return nil, errors.New("guest-agent server transport is required")
	}
	if !configuredDependency(options.Backend) {
		return nil, errors.New("guest-agent server backend is required")
	}
	maxRequestBytes, err := boundedInt64Option(
		"maximum request bytes",
		options.MaxRequestBytes,
		DefaultMaxRequestBytes,
		1,
		MaximumEncodedMessageBytes,
	)
	if err != nil {
		return nil, err
	}
	maxResponseBytes, err := boundedInt64Option(
		"maximum response bytes",
		options.MaxResponseBytes,
		DefaultMaxResponseBytes,
		MinimumMaxResponseBytes,
		MaximumEncodedMessageBytes,
	)
	if err != nil {
		return nil, err
	}
	maxConcurrent, err := boundedIntOption(
		"maximum concurrency",
		options.MaxConcurrent,
		DefaultMaxConcurrent,
		1,
		MaximumMaxConcurrent,
	)
	if err != nil {
		return nil, err
	}
	maxOperationTime, err := boundedDurationOption(
		"maximum operation time",
		options.MaxOperationTime,
		DefaultMaxOperationTime,
		MaximumMaxOperationTime,
	)
	if err != nil {
		return nil, err
	}
	maxShutdownTime, err := boundedDurationOption(
		"maximum shutdown time",
		options.MaxShutdownTime,
		DefaultMaxShutdownTime,
		MaximumMaxShutdownTime,
	)
	if err != nil {
		return nil, err
	}
	resolver := options.EnvironmentResolver
	if !configuredDependency(resolver) {
		resolver = rejectingEnvironmentResolver{}
	}
	operationCtx, operationCancel := context.WithCancel(context.Background())
	return &Server{
		transport:        options.Transport,
		backend:          options.Backend,
		resolver:         resolver,
		limits:           Limits{MaxRequestBytes: maxRequestBytes, MaxResponseBytes: maxResponseBytes},
		maxOperationTime: maxOperationTime,
		maxShutdownTime:  maxShutdownTime,
		admission:        make(chan struct{}, maxConcurrent),
		state:            StateNew,
		operationCtx:     operationCtx,
		operationCancel:  operationCancel,
		transportDone:    make(chan struct{}),
		cleanupDone:      make(chan struct{}),
	}, nil
}

// State returns the current server lifecycle state.
func (server *Server) State() State {
	if server == nil {
		return StateFailed
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.state
}

// Serve starts the injected transport once and owns the server lifecycle until
// transport return and cleanup complete.
func (server *Server) Serve(ctx context.Context) error {
	if server == nil {
		return errors.New("guest-agent server is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	serveCtx, cancel := context.WithCancel(ctx)

	server.mu.Lock()
	if server.serveUsed || server.state != StateNew {
		server.mu.Unlock()
		cancel()
		return errors.New("guest-agent server cannot be served in its current state")
	}
	server.serveUsed = true
	server.serveCancel = cancel
	server.state = StateServing
	server.mu.Unlock()

	transportErr := server.transport.Serve(serveCtx, server.limits, server)
	transportFailure := transportErr != nil
	if serveErr := serveCtx.Err(); serveErr != nil && cancellationOnlyError(transportErr, serveErr) {
		transportFailure = false
	}

	server.mu.Lock()
	target := StateStopped
	if transportFailure {
		target = StateFailed
	}
	server.beginDrainLocked(target)
	done := server.cleanupDone
	server.mu.Unlock()
	server.markTransportDone()
	<-done

	server.mu.Lock()
	cleanupErr := server.cleanupErr
	server.mu.Unlock()
	if transportFailure {
		transportFailureErr := &serverFailure{message: "guest-agent server transport failed", cause: transportErr}
		if cleanupErr != nil {
			return errors.Join(transportFailureErr, cleanupErr)
		}
		return transportFailureErr
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	return nil
}

const maximumCancellationErrorDepth = 64

func cancellationOnlyError(err, cancellationErr error) bool {
	return cancellationOnlyErrorAtDepth(err, cancellationErr, 0)
}

func cancellationOnlyErrorAtDepth(err, cancellationErr error, depth int) bool {
	if err == nil || cancellationErr == nil || depth >= maximumCancellationErrorDepth {
		return false
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		causes := wrapped.Unwrap()
		sawCause := false
		for _, cause := range causes {
			if cause == nil {
				continue
			}
			sawCause = true
			if !cancellationOnlyErrorAtDepth(cause, cancellationErr, depth+1) {
				return false
			}
		}
		return sawCause
	case interface{ Unwrap() error }:
		if cause := wrapped.Unwrap(); cause != nil {
			return cancellationOnlyErrorAtDepth(cause, cancellationErr, depth+1)
		}
	}
	return errors.Is(err, cancellationErr)
}

// Shutdown cancels active work and waits up to the caller's context for the
// shared cleanup sequence. Cleanup continues when the caller stops waiting.
func (server *Server) Shutdown(ctx context.Context) error {
	if server == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	server.mu.Lock()
	switch server.state {
	case StateStopped, StateFailed:
		err := server.cleanupErr
		server.mu.Unlock()
		return err
	case StateNew:
		server.serveUsed = true
		server.markTransportDone()
		server.beginDrainLocked(StateStopped)
	case StateServing:
		server.beginDrainLocked(StateStopped)
	case StateDraining:
		server.ensureCleanupLocked()
	}
	done := server.cleanupDone
	server.mu.Unlock()

	select {
	case <-done:
		server.mu.Lock()
		err := server.cleanupErr
		server.mu.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (server *Server) beginDrainLocked(target State) {
	if target == StateFailed {
		server.terminal = StateFailed
	} else if server.terminal == "" {
		server.terminal = StateStopped
	}
	switch server.state {
	case StateNew, StateServing:
		server.state = StateDraining
	}
	if server.serveCancel != nil {
		server.serveCancel()
	}
	server.operationCancel()
	server.ensureCleanupLocked()
}

func (server *Server) ensureCleanupLocked() {
	server.cleanupOnce.Do(func() {
		go server.cleanup()
	})
}

func (server *Server) cleanup() {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), server.maxShutdownTime)
	defer cancel()
	cleanupResult := make(chan error, 1)
	go func() {
		<-server.transportDone
		server.operations.Wait()
		cleanupResult <- server.backend.Close(cleanupCtx)
	}()

	var cleanupErr error
	select {
	case cleanupErr = <-cleanupResult:
	case <-cleanupCtx.Done():
		cleanupErr = cleanupCtx.Err()
	}

	server.mu.Lock()
	if cleanupErr != nil {
		server.cleanupErr = &serverFailure{message: "guest-agent server cleanup failed", cause: cleanupErr}
		server.terminal = StateFailed
	}
	if server.terminal == "" {
		server.terminal = StateStopped
	}
	server.state = server.terminal
	close(server.cleanupDone)
	server.mu.Unlock()
}

func (server *Server) markTransportDone() {
	server.transportOnce.Do(func() {
		close(server.transportDone)
	})
}

func (server *Server) beginBackendCall(ctx context.Context, stateChanging bool) (context.Context, func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}

	server.mu.Lock()
	if server.state != StateServing {
		server.mu.Unlock()
		return nil, nil, errServerNotReady
	}
	if stateChanging {
		select {
		case server.admission <- struct{}{}:
		default:
			server.mu.Unlock()
			return nil, nil, errServerBusy
		}
	}
	server.operations.Add(1)
	operationRoot := server.operationCtx
	server.mu.Unlock()

	callCtx, cancel := context.WithCancel(ctx)
	stopRootCancel := context.AfterFunc(operationRoot, cancel)
	release := func() {
		stopRootCancel()
		cancel()
		server.operations.Done()
		if stateChanging {
			<-server.admission
		}
	}
	return callCtx, release, nil
}

func boundedInt64Option(name string, value, fallback, minimum, maximum int64) (int64, error) {
	if value == 0 {
		return fallback, nil
	}
	if value < minimum || value > maximum {
		return 0, fmt.Errorf("%s is outside the supported range", name)
	}
	return value, nil
}

func boundedIntOption(name string, value, fallback, minimum, maximum int) (int, error) {
	if value == 0 {
		return fallback, nil
	}
	if value < minimum || value > maximum {
		return 0, fmt.Errorf("%s is outside the supported range", name)
	}
	return value, nil
}

func boundedDurationOption(name string, value, fallback, maximum time.Duration) (time.Duration, error) {
	if value == 0 {
		return fallback, nil
	}
	if value < 0 || value > maximum {
		return 0, fmt.Errorf("%s is outside the supported range", name)
	}
	return value, nil
}

func configuredDependency(value any) bool {
	if value == nil {
		return false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !reflected.IsNil()
	default:
		return true
	}
}

type serverFailure struct {
	message string
	cause   error
}

func (failure *serverFailure) Error() string {
	if failure == nil {
		return ""
	}
	return failure.message
}

func (failure *serverFailure) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

var (
	errServerNotReady = errors.New("guest-agent server is not ready")
	errServerBusy     = errors.New("guest-agent server is busy")
)
