package server

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

func TestWorkloadDispatchTransientFailureRequiresFreshInspection(t *testing.T) {
	for _, panicFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "failure", true: "panic"}[panicFirst], func(t *testing.T) {
			fixture := newWorkloadDispatchFixture(t, true, func(_ context.Context, call int32) (IsolationProofResult, error) {
				if call == 1 {
					if panicFirst {
						panic("token=private-panic-canary")
					}
					return IsolationProofResult{}, errors.New("token=private-failure-canary")
				}
				return l7VerifiedIsolationResult(), nil
			})
			request := workloadDispatchExec(t, nil)
			failed := fixture.work.HandleWorkload(context.Background(), request)
			l4RequireResponseCode(t, failed, guestagent.ErrorCodeServerNotReady)
			if strings.Contains(string(failed.Encoded), "private-") || fixture.server.isolationProven || fixture.backend.execCalls.Load() != 0 {
				t.Fatal("failed inspection leaked or granted work")
			}
			// No second Prepare, cached flag assignment or readiness workaround.
			retried := fixture.work.HandleWorkload(context.Background(), request)
			if fixture.verifier.calls.Load() != 2 || fixture.backend.execCalls.Load() != 1 ||
				guestagent.ValidateExecResponse(l4DecodeResponse[guestagent.ExecResponse](t, retried)) != nil {
				t.Fatal("fresh inspection did not recover released permit")
			}
		})
	}
}

func TestWorkloadDispatchCanceledInspectionReleasesPermit(t *testing.T) {
	started := make(chan struct{})
	fixture := newWorkloadDispatchFixture(t, true, func(ctx context.Context, call int32) (IsolationProofResult, error) {
		if call == 1 {
			close(started)
			<-ctx.Done()
		}
		return l7VerifiedIsolationResult(), nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request := workloadDispatchExec(t, nil)
	done := make(chan Response, 1)
	go func() { done <- fixture.work.HandleWorkload(ctx, request) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("actual inspection did not start")
	}
	busy := fixture.work.HandleWorkload(context.Background(), request)
	l4RequireResponseCode(t, busy, guestagent.ErrorCodeServerBusy)
	if fixture.verifier.calls.Load() != 1 {
		t.Fatal("busy work invoked another inspection")
	}
	cancel()
	l4RequireResponseCode(t, workloadForwardResponse(t, done), guestagent.ErrorCodeRequestCanceled)
	if fixture.server.isolationProven || fixture.backend.execCalls.Load() != 0 {
		t.Fatal("canceled observation granted work")
	}
	response := fixture.work.HandleWorkload(context.Background(), request)
	if fixture.verifier.calls.Load() != 2 || fixture.backend.execCalls.Load() != 1 ||
		guestagent.ValidateExecResponse(l4DecodeResponse[guestagent.ExecResponse](t, response)) != nil {
		t.Fatal("canceled inspection retained the permit or prevented fresh proof")
	}
}

func TestWorkloadDispatchOlderFailedObservationCannotClearNewerSuccess(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fixture := newWorkloadDispatchFixture(t, true, func(ctx context.Context, call int32) (IsolationProofResult, error) {
		if call == 1 {
			close(started)
			select {
			case <-release:
			case <-ctx.Done():
			}
			return IsolationProofResult{}, errors.New("older failed")
		}
		return l7VerifiedIsolationResult(), nil
	})
	done := make(chan error, 1)
	go func() { done <- fixture.work.PrepareWorkload(ctx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("older inspection did not start")
	}
	second := make(chan error, 1)
	go func() { second <- fixture.work.PrepareWorkload(ctx) }()
	secondErr := workloadDispatchWait(t, second)
	close(release)
	firstErr := workloadDispatchWait(t, done)
	if secondErr != nil || firstErr == nil || !fixture.server.isolationProven {
		t.Fatal("stale failed completion replaced the newer checked observation")
	}
}

func TestWorkloadDispatchReadyFailuresAreTrackedAndSanitized(t *testing.T) {
	for _, kind := range []string{"error", "panic", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			backend := &workloadForwardBackend{l4FakeBackend: &l4FakeBackend{}}
			backend.ready = func(ctx context.Context) error {
				switch kind {
				case "panic":
					panic("token=private-ready-panic")
				case "cancel":
					<-ctx.Done()
					return nil
				default:
					return errors.New("token=private-ready-error")
				}
			}
			verifier := &workloadDispatchVerifier{}
			agent := workloadForwardServer(t, backend, verifier)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			err := agent.PrepareWorkload(ctx)
			if err == nil || strings.Contains(err.Error(), "private-") || agent.isolationProven || verifier.calls.Load() != 0 {
				t.Fatal("failed Ready leaked, invoked proof, or granted work")
			}
			backend.ready = nil // Prior synchronous call has returned and joined.
			if err := agent.PrepareWorkload(context.Background()); err != nil || verifier.calls.Load() != 1 {
				t.Fatal("Ready failure left a tracked lifetime or prevented a fresh preparation")
			}
		})
	}
}

func TestWorkloadDispatchProofCallbackOutsideLockAndShutdownJoins(t *testing.T) {
	started := make(chan struct{})
	var agent *Server
	verifier := &workloadDispatchVerifier{inspect: func(ctx context.Context, _ int32) (IsolationProofResult, error) {
		if agent.State() != StateServing { // A real reentrant lock-taking getter.
			return IsolationProofResult{}, errors.New("not serving")
		}
		close(started)
		<-ctx.Done()
		return l7VerifiedIsolationResult(), nil
	}}
	backend := &workloadForwardBackend{l4FakeBackend: &l4FakeBackend{}}
	agent = workloadForwardServer(t, backend, verifier)
	done := make(chan error, 1)
	go func() { done <- agent.PrepareWorkload(context.Background()) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("verifier callback held server mutex")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := agent.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := workloadDispatchWait(t, done); err == nil || agent.isolationProven || backend.closeCalls.Load() != 1 {
		t.Fatal("shutdown returned before canceled proof released tracked lifetime")
	}
}

func TestWorkloadDispatchPreCanceledAndOversizedRequestsDoNotInspect(t *testing.T) {
	fixture := newWorkloadDispatchFixture(t, true, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l4RequireResponseCode(t, fixture.work.HandleWorkload(ctx, workloadDispatchExec(t, nil)), guestagent.ErrorCodeRequestCanceled)
	l4RequireResponseCode(t, fixture.work.HandleWorkload(context.Background(), Request{Encoded: make([]byte, DefaultMaxRequestBytes+1)}), guestagent.ErrorCodeOversizedRequest)
	if fixture.verifier.calls.Load() != 0 || fixture.backend.totalOperationCalls() != 0 {
		t.Fatal("invalid entry reached inspector/backend")
	}
}

func TestWorkloadDispatchCopyInPublicationStillOutranksLateCancellation(t *testing.T) {
	data := []byte("selected published copy")
	digest := digestBytes(data)
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "published", true: "uncertain"}[uncertain], func(t *testing.T) {
			fixture := newWorkloadDispatchFixture(t, true, nil)
			fixture.backend.copyInReturnAfterContext = true
			fixture.backend.copyInResult = CopyResult{Published: true, SizeBytes: int64(len(data)), Digest: digest}
			if uncertain {
				fixture.backend.copyErr = errors.New("private publication failed")
			}
			request := guestagent.CopyInRequest{ProtocolVersion: guestagent.ProtocolVersionV1, Operation: guestagent.OperationCopyIn,
				DestinationPath: "/workspace/published.bin", Timing: &guestagent.TimingMetadata{TimeoutMillis: 100},
				Payload: guestagent.PayloadMetadata{SizeBytes: int64(len(data)), MaxBytes: 64, Digest: digest,
					Encoding: guestagent.PayloadEncodingBase64, Data: base64.StdEncoding.EncodeToString(data)}}
			response := fixture.work.HandleWorkload(context.Background(), Request{Encoded: l7JSON(t, request)})
			if fixture.verifier.calls.Load() != 1 || fixture.backend.copyInCalls.Load() != 1 {
				t.Fatal("selected copy did not reach fresh proof then actual backend")
			}
			if uncertain {
				l4RequireResponseCode(t, response, guestagent.ErrorCodeDurabilityUncertain)
			} else if result := l4DecodeResponse[guestagent.CopyInResponse](t, response); guestagent.ValidateCopyInResponse(result) != nil || result.Written.Digest != digest {
				t.Fatal("selected dispatch suppressed observed publication")
			}
		})
	}
}

type workloadForwardBackend struct {
	*l4FakeBackend
	ready func(context.Context) error
}

func (backend *workloadForwardBackend) Ready(ctx context.Context) error {
	backend.readyCalls.Add(1)
	if backend.ready != nil {
		return backend.ready(ctx)
	}
	return nil
}

func workloadForwardServer(t *testing.T, backend Backend, verifier WorkloadIsolationVerifier) *Server {
	t.Helper()
	transport := &workloadDispatchTransport{entered: make(chan Handler, 1)}
	agent, err := New(Options{Transport: transport, Backend: backend, WorkloadIsolationVerifier: verifier,
		RequireIsolationProofBeforeWork: true, RequireNetworkProofBeforeWork: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- agent.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		workloadDispatchWait(t, done)
	})
	select {
	case <-transport.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("actual Serve did not enter transport")
	}
	return agent
}

func workloadForwardResponse(t *testing.T, done <-chan Response) Response {
	t.Helper()
	select {
	case response := <-done:
		return response
	case <-time.After(2 * time.Second):
		t.Fatal("selected request did not join")
		return Response{}
	}
}
