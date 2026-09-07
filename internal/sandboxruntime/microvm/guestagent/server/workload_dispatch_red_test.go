package server

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/server/credentialclient"
)

func TestWorkloadDispatchRejectsReadinessBeforeBackendOrProof(t *testing.T) {
	for _, originalHandle := range []bool{false, true} {
		name := "workload entry"
		if originalHandle {
			name = "original Handle on selected server"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newWorkloadDispatchFixture(t, true, nil)
			request := Request{Encoded: []byte(`{"protocolVersion":"guest-agent-v1","operation":"readiness"}`)}
			var response Response
			if originalHandle {
				response = fixture.server.Handle(context.Background(), request)
			} else {
				response = fixture.work.HandleWorkload(context.Background(), request)
			}
			fixture.server.mu.Lock()
			attempt := fixture.server.proofAttemptSequence
			fixture.server.mu.Unlock()
			if attempt != 0 || fixture.backend.totalOperationCalls() != 0 || fixture.verifier.calls.Load() != 0 {
				t.Errorf("selected readiness changed backend/proof state: attempt=%d backend=%d local=%d", attempt, fixture.backend.totalOperationCalls(), fixture.verifier.calls.Load())
			}
			l4RequireResponseCode(t, response, guestagent.ErrorCodeUnknownOperation)
		})
	}
}

func TestWorkloadDispatchRequiresActualLocalPreparation(t *testing.T) {
	fixture := newWorkloadDispatchFixture(t, true, nil)
	if err := fixture.work.PrepareWorkload(context.Background()); err != nil {
		t.Fatalf("selected local preparation unavailable on actual serving server: %v (local calls=%d)", err, fixture.verifier.calls.Load())
	}
	if fixture.verifier.calls.Load() != 1 || fixture.backend.readyCalls.Load() != 1 || !fixture.server.isolationProven {
		t.Fatal("preparation did not run the actual local verifier/backend gate")
	}
	response := fixture.work.HandleWorkload(context.Background(), workloadDispatchExec(t, nil))
	result := l4DecodeResponse[guestagent.ExecResponse](t, response)
	if guestagent.ValidateExecResponse(result) != nil || fixture.backend.execCalls.Load() != 1 || fixture.verifier.calls.Load() != 2 {
		t.Fatal("work did not use a fresh complete local inspection and existing exec dispatcher")
	}
}

func TestWorkloadDispatchLocalPredicateRejectsEveryMissingObservation(t *testing.T) {
	for name, mutate := range map[string]func(*IsolationProofResult){
		"identity":          func(r *IsolationProofResult) { r.RestrictedIdentity = false },
		"capabilities":      func(r *IsolationProofResult) { r.CapabilitiesCleared = false },
		"no new privileges": func(r *IsolationProofResult) { r.NoNewPrivileges = false },
		"groups":            func(r *IsolationProofResult) { r.SupplementaryGroupsCleared = false },
		"raw packet":        func(r *IsolationProofResult) { r.RawPacketSocketDenied = false },
		"network status":    func(r *IsolationProofResult) { r.Network.Status = guestagent.IsolationProofStatusUnavailable },
		"network failed":    func(r *IsolationProofResult) { r.Network.Status = guestagent.IsolationProofStatusFailed },
		"single interface":  func(r *IsolationProofResult) { r.Network.SingleInterface = false },
		"static routes":     func(r *IsolationProofResult) { r.Network.StaticRoutes = false },
		"proxy":             func(r *IsolationProofResult) { r.Network.ProxyReachable = false },
	} {
		t.Run(name, func(t *testing.T) {
			result := l7VerifiedIsolationResult()
			mutate(&result)
			fixture := newWorkloadDispatchFixture(t, true, func(context.Context, int32) (IsolationProofResult, error) { return result, nil })
			if err := fixture.work.PrepareWorkload(context.Background()); err == nil || fixture.verifier.calls.Load() != 1 {
				t.Fatalf("actual local inspection missing or incomplete result accepted: err=%v calls=%d", err, fixture.verifier.calls.Load())
			}
			if fixture.server.isolationProven || fixture.backend.execCalls.Load() != 0 {
				t.Fatal("failed local observation granted work")
			}
		})
	}
}

func TestWorkloadDispatchFreshAttemptDoesNotReuseSuccessfulProof(t *testing.T) {
	fixture := newWorkloadDispatchFixture(t, true, func(_ context.Context, call int32) (IsolationProofResult, error) {
		if call == 1 {
			return l7VerifiedIsolationResult(), nil
		}
		return IsolationProofResult{}, errors.New("private inspection failure")
	})
	if err := fixture.work.PrepareWorkload(context.Background()); err != nil {
		t.Fatalf("initial inspection unavailable: %v", err)
	}
	response := fixture.work.HandleWorkload(context.Background(), workloadDispatchExec(t, nil))
	if fixture.verifier.calls.Load() != 2 || fixture.backend.execCalls.Load() != 0 || fixture.server.isolationProven {
		t.Fatal("work reused a cached success instead of the failed current inspection")
	}
	l4RequireResponseCode(t, response, guestagent.ErrorCodeServerNotReady)
}

func TestWorkloadDispatchCanceledLocalAttemptCannotBecomeProof(t *testing.T) {
	started := make(chan struct{})
	fixture := newWorkloadDispatchFixture(t, true, func(ctx context.Context, _ int32) (IsolationProofResult, error) {
		close(started)
		<-ctx.Done()
		return l7VerifiedIsolationResult(), nil // Deliberately late, not authority.
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- fixture.work.PrepareWorkload(ctx) }()
	select {
	case <-started:
		cancel()
	case err := <-done:
		t.Fatalf("preparation returned without reaching local verifier: %v", err)
	case <-time.After(2 * time.Second):
		cancel()
		workloadDispatchWait(t, done)
		t.Fatal("preparation never reached local verifier")
	}
	if err := workloadDispatchWait(t, done); err == nil || fixture.server.isolationProven || fixture.backend.execCalls.Load() != 0 {
		t.Fatal("canceled current local attempt granted work")
	}
}

func TestWorkloadDispatchStaleConcurrentPreparationCannotOverwriteFailure(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture := newWorkloadDispatchFixture(t, true, func(ctx context.Context, call int32) (IsolationProofResult, error) {
		if call == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
				return IsolationProofResult{}, ctx.Err()
			}
			return l7VerifiedIsolationResult(), nil
		}
		return IsolationProofResult{}, errors.New("newer local observation failed")
	})
	first := make(chan error, 1)
	go func() { first <- fixture.work.PrepareWorkload(ctx) }()
	select {
	case <-started:
	case err := <-first:
		t.Fatalf("older attempt never entered actual inspection: %v", err)
	case <-time.After(2 * time.Second):
		cancel()
		workloadDispatchWait(t, first)
		t.Fatal("older attempt never entered actual inspection")
	}
	second := make(chan error, 1)
	go func() { second <- fixture.work.PrepareWorkload(ctx) }()
	var secondErr error
	select {
	case secondErr = <-second:
	case <-time.After(2 * time.Second):
		cancel()
		workloadDispatchWait(t, second)
		workloadDispatchWait(t, first)
		t.Fatal("newer inspection blocked behind older callback")
	}
	close(release)
	firstErr := workloadDispatchWait(t, first)
	if secondErr == nil || firstErr == nil || fixture.verifier.calls.Load() != 2 || fixture.server.isolationProven {
		t.Fatal("older successful observation overwrote newer failure")
	}
}

func TestWorkloadDispatchRequestTimingIncludesFreshInspection(t *testing.T) {
	var deadlineSeen atomic.Bool
	fixture := newWorkloadDispatchFixture(t, true, func(ctx context.Context, call int32) (IsolationProofResult, error) {
		if call == 1 {
			return l7VerifiedIsolationResult(), nil
		}
		deadline, ok := ctx.Deadline()
		deadlineSeen.Store(ok && time.Until(deadline) <= 100*time.Millisecond)
		<-ctx.Done()
		return l7VerifiedIsolationResult(), nil
	})
	if err := fixture.work.PrepareWorkload(context.Background()); err != nil {
		t.Fatalf("initial inspection unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response := fixture.work.HandleWorkload(ctx, workloadDispatchExec(t, &guestagent.TimingMetadata{TimeoutMillis: 30}))
	if !deadlineSeen.Load() || fixture.verifier.calls.Load() != 2 || fixture.backend.execCalls.Load() != 0 {
		t.Fatal("request deadline did not bound actual inspection")
	}
	l4RequireResponseCode(t, response, guestagent.ErrorCodeRequestTimeout)
}

func TestWorkloadDispatchRejectsUnselectedEntryAndPreservesLegacy(t *testing.T) {
	t.Run("selected method unavailable on legacy", func(t *testing.T) {
		fixture := newWorkloadDispatchFixture(t, false, nil)
		response := fixture.work.HandleWorkload(context.Background(), workloadDispatchExec(t, nil))
		if fixture.backend.execCalls.Load() != 0 {
			t.Error("selected entry dispatched on unselected legacy server")
		}
		l4RequireResponseCode(t, response, guestagent.ErrorCodeServerNotReady)
	})
	t.Run("original legacy exec control", func(t *testing.T) {
		fixture := newWorkloadDispatchFixture(t, false, nil)
		response := fixture.server.Handle(context.Background(), workloadDispatchExec(t, nil))
		if fixture.backend.execCalls.Load() != 1 || guestagent.ValidateExecResponse(l4DecodeResponse[guestagent.ExecResponse](t, response)) != nil {
			t.Fatal("legacy exec behavior changed")
		}
	})
	t.Run("pre-canceled preparation control", func(t *testing.T) {
		fixture := newWorkloadDispatchFixture(t, true, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if fixture.work.PrepareWorkload(ctx) == nil || fixture.verifier.calls.Load() != 0 || fixture.backend.totalOperationCalls() != 0 {
			t.Fatal("pre-canceled prepare reached dependencies")
		}
	})
}

func TestWorkloadDispatchConstructorRejectsIncompleteAndMixedModes(t *testing.T) {
	for name, mutate := range map[string]func(*Options){
		"nil local":               func(o *Options) { o.WorkloadIsolationVerifier = nil },
		"typed nil local":         func(o *Options) { o.WorkloadIsolationVerifier = (*workloadDispatchVerifier)(nil) },
		"network gate absent":     func(o *Options) { o.RequireNetworkProofBeforeWork = false },
		"isolation gate absent":   func(o *Options) { o.RequireIsolationProofBeforeWork = false },
		"both gates absent":       func(o *Options) { o.RequireIsolationProofBeforeWork = false; o.RequireNetworkProofBeforeWork = false },
		"mixed legacy verifier":   func(o *Options) { o.IsolationVerifier = &l7FakeIsolationVerifier{} },
		"mixed credential client": func(o *Options) { o.CredentialClient = &credentialclient.Client{} },
	} {
		t.Run(name, func(t *testing.T) {
			backend := &l4FakeBackend{}
			verifier := &workloadDispatchVerifier{}
			options := Options{Transport: &workloadDispatchTransport{entered: make(chan Handler, 1)}, Backend: backend,
				WorkloadIsolationVerifier: verifier, RequireIsolationProofBeforeWork: true, RequireNetworkProofBeforeWork: true}
			mutate(&options)
			candidate, err := New(options)
			if candidate != nil {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_ = candidate.Shutdown(ctx)
			}
			if err == nil || candidate != nil {
				t.Fatal("incomplete or mixed selected mode accepted")
			}
			if verifier.calls.Load() != 0 || backend.totalOperationCalls() != 0 {
				t.Fatal("constructor inspected or executed work")
			}
		})
	}
}

func TestWorkloadDispatchMalformedInnerRequestControl(t *testing.T) {
	for name, encoded := range map[string][]byte{
		"nil":        nil,
		"duplicate":  []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","operation":"exec"}`),
		"unknown":    []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","extra":true}`),
		"wrong type": []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec","args":1}`),
		"trailing":   []byte(`{"protocolVersion":"guest-agent-v1","operation":"exec"} {}`),
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newWorkloadDispatchFixture(t, true, nil)
			response := fixture.work.HandleWorkload(context.Background(), Request{Encoded: encoded})
			l4RequireResponseCode(t, response, guestagent.ErrorCodeMalformedRequest)
			if fixture.verifier.calls.Load() != 0 || fixture.backend.totalOperationCalls() != 0 || fixture.server.proofAttemptSequence != 0 {
				t.Fatal("malformed inner request reached proof/backend")
			}
		})
	}
}

type workloadDispatchTransport struct{ entered chan Handler }

func (transport *workloadDispatchTransport) Serve(ctx context.Context, _ Limits, handler Handler) error {
	transport.entered <- handler
	<-ctx.Done()
	return ctx.Err()
}

type workloadDispatchVerifier struct {
	calls   atomic.Int32
	inspect func(context.Context, int32) (IsolationProofResult, error)
}

func (verifier *workloadDispatchVerifier) VerifyWorkloadIsolation(ctx context.Context) (IsolationProofResult, error) {
	call := verifier.calls.Add(1)
	if verifier.inspect != nil {
		return verifier.inspect(ctx, call)
	}
	return l7VerifiedIsolationResult(), nil // Explicit fake observations only.
}

type workloadDispatchFixture struct {
	server   *Server
	work     WorkloadHandler
	backend  *l4FakeBackend
	verifier *workloadDispatchVerifier
}

func newWorkloadDispatchFixture(t *testing.T, selected bool, inspect func(context.Context, int32) (IsolationProofResult, error)) *workloadDispatchFixture {
	t.Helper()
	transport := &workloadDispatchTransport{entered: make(chan Handler, 1)}
	backend, verifier := &l4FakeBackend{}, &workloadDispatchVerifier{inspect: inspect}
	options := Options{Transport: transport, Backend: backend}
	if selected {
		options.WorkloadIsolationVerifier = verifier
		options.RequireIsolationProofBeforeWork, options.RequireNetworkProofBeforeWork = true, true
	}
	agent, err := New(options)
	if err != nil {
		t.Fatalf("actual selected constructor unavailable: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		workloadDispatchWait(t, done)
		if backend.closeCalls.Load() != 1 {
			t.Fatal("Serve cleanup did not close backend exactly once")
		}
	})
	var handler Handler
	select {
	case handler = <-transport.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("actual Serve never entered transport")
	}
	work, ok := handler.(WorkloadHandler)
	if !ok || agent.State() != StateServing {
		t.Fatal("actual serving handler lacks selected methods")
	}
	return &workloadDispatchFixture{server: agent, work: work, backend: backend, verifier: verifier}
}

func workloadDispatchExec(t *testing.T, timing *guestagent.TimingMetadata) Request {
	t.Helper()
	request := guestagent.ExecRequest{ProtocolVersion: guestagent.ProtocolVersionV1, Operation: guestagent.OperationExec,
		Args: []string{"hal", "--version"}, WorkDir: "/workspace", Timing: timing,
		Stdout: guestagent.StreamMetadata{MaxBytes: 64}, Stderr: guestagent.StreamMetadata{MaxBytes: 64}}
	if err := guestagent.ValidateExecRequest(request); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	return Request{Encoded: encoded}
}

func workloadDispatchWait(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("owned server/call did not join; watchdog is not completion")
	}
	return nil
}
