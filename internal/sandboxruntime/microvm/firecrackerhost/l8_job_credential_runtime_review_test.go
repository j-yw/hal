package firecrackerhost

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8JobCredentialRuntimeDoesNotProveCleanupWhenResourceRevokeFails(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed, identity, request := l8JobCredentialRuntimePrepareFixture(t, now)
	runtime := l8JobCredentialRuntimeForTest(t, now,
		&l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)},
		&l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("file")}, nil,
	)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	sessionValue, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	session := sessionValue.(*l8JobCredentialRuntimeSession)
	failing := &l8JobCredentialReviewHTTPHandle{revokeErr: errors.New("secret cleanup failure")}
	session.resources.http = append(session.resources.http, failing)

	proof, err := session.Revoke(context.Background(), sandboxruntime.JobCredentialRevokeReason("requested"))
	if sandboxruntime.CleanupProofKind(proof) != "" || !errors.Is(err, ErrL8JobCredentialRuntimeUnavailable) {
		t.Fatalf("cleanup failure returned proof=%#v err=%v", proof, err)
	}
	if sandboxruntime.ActiveProofKind(session.ActiveProof()) != "" {
		t.Fatal("cleanup failure left revoking authority projected as active")
	}
	if failing.revokes != 1 {
		t.Fatalf("failing revoke calls=%d, want 1", failing.revokes)
	}

	failing.revokeErr = nil
	proof, err = session.Revoke(context.Background(), sandboxruntime.JobCredentialRevokeReason("requested"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxruntime.ValidateJobCredentialCleanupProof(proof, identity, 2, now.Add(2*time.Second)); err != nil {
		t.Fatalf("retry cleanup proof: %v", err)
	}
}

func TestL8JobCredentialRuntimeReclaimsValuePlusErrorActivationHandle(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeHTTPProxy})
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8JobCredentialRuntimeGuestSessionGeneration(), "helper-generation-runtime")
	if err != nil {
		t.Fatal(err)
	}
	request := l8JobCredentialRuntimePrepareRequest(t, identity)
	handle := &l8JobCredentialReviewHTTPHandle{serviceID: request.Admission.Bindings[0].ServiceID}
	activator := &l8JobCredentialReviewHTTPActivator{handle: handle, err: errors.New("private activation failure")}
	runtime := l8JobCredentialRuntimeForTest(t, now,
		&l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}, activator, nil, nil,
	)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	result, err := preflight.PrepareJobCredentials(context.Background(), request)
	if !l8JobCredentialRuntimeValueIsNil(result) || !errors.Is(err, ErrL8JobCredentialRuntimeUnavailable) {
		t.Fatalf("prepare value+error = %#v, %v", result, err)
	}
	if handle.revokes != 1 {
		t.Fatalf("returned activation handle revokes=%d, want 1", handle.revokes)
	}
}

func TestL8JobCredentialRuntimeRejectsIncompleteGuestBindingProofs(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed, _, request := l8JobCredentialRuntimePrepareFixture(t, now)
	guest := &l8JobCredentialReviewGuestSession{
		l8JobCredentialGuestSessionFake: l8JobCredentialGuestSessionFakeForTest(t, now),
		prepareResult: l8JobCredentialGuestPrepareResult{
			ActiveProofID: "guest-active-1",
			ExecBindingID: "exec-binding-1",
		},
	}
	runtime := l8JobCredentialRuntimeForTest(t, now, &l8JobCredentialGuestSessionOpenerFake{session: guest},
		&l8JobCredentialHTTPProxyFake{}, &l8JobCredentialFileTmpfsFake{payload: []byte("file")}, nil,
	)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if !l8JobCredentialRuntimeValueIsNil(session) || !errors.Is(err, ErrL8JobCredentialRuntimeInvalid) {
		t.Fatalf("prepare without binding proofs = %#v, %v", session, err)
	}
}

func TestL8JobCredentialRuntimeAbortWaitsForInFlightPrepareOwnership(t *testing.T) {
	now := l8JobCredentialRuntimeNow()
	seed := l8JobCredentialRuntimeSeed(t, now, []sandboxruntime.JobCredentialDeliveryMode{sandboxruntime.JobCredentialDeliveryModeHTTPProxy})
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8JobCredentialRuntimeGuestSessionGeneration(), "helper-generation-runtime")
	if err != nil {
		t.Fatal(err)
	}
	request := l8JobCredentialRuntimePrepareRequest(t, identity)
	entered := make(chan struct{})
	release := make(chan struct{})
	activator := &l8JobCredentialReviewHTTPActivator{entered: entered, release: release, handle: &l8JobCredentialReviewHTTPHandle{serviceID: request.Admission.Bindings[0].ServiceID}}
	runtime := l8JobCredentialRuntimeForTest(t, now,
		&l8JobCredentialGuestSessionOpenerFake{session: l8JobCredentialGuestSessionFakeForTest(t, now)}, activator, nil, nil,
	)
	preflight, err := runtime.PreflightJobCredentials(context.Background(), seed)
	if err != nil {
		t.Fatal(err)
	}
	prepareDone := make(chan error, 1)
	go func() {
		_, prepareErr := preflight.PrepareJobCredentials(context.Background(), request)
		prepareDone <- prepareErr
	}()
	<-entered
	abortDone := make(chan struct {
		proof sandboxruntime.JobCredentialCleanupProof
		err   error
	}, 1)
	go func() {
		proof, abortErr := preflight.Abort(context.Background())
		abortDone <- struct {
			proof sandboxruntime.JobCredentialCleanupProof
			err   error
		}{proof: proof, err: abortErr}
	}()
	select {
	case result := <-abortDone:
		t.Fatalf("abort returned before prepare ownership converged: proof=%#v err=%v", result.proof, result.err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-prepareDone; err != nil {
		t.Fatalf("prepare: %v", err)
	}
	result := <-abortDone
	if sandboxruntime.CleanupProofKind(result.proof) != "" || !errors.Is(result.err, sandboxruntime.ErrJobCredentialTransition) {
		t.Fatalf("abort after transfer = %#v, %v", result.proof, result.err)
	}
}

type l8JobCredentialReviewHTTPActivator struct {
	handle  l8JobCredentialHTTPProxyHandle
	err     error
	entered chan struct{}
	release chan struct{}
}

func (value *l8JobCredentialReviewHTTPActivator) Activate(context.Context, sandboxruntime.JobCredentialIdentity, sandboxruntime.JobCredentialBindingRequest, sandboxruntime.LiveSecretSource) (l8JobCredentialHTTPProxyHandle, error) {
	if value.entered != nil {
		close(value.entered)
		<-value.release
	}
	return value.handle, value.err
}

type l8JobCredentialReviewHTTPHandle struct {
	mu        sync.Mutex
	serviceID string
	revokeErr error
	revokes   int
}

func (value *l8JobCredentialReviewHTTPHandle) ServiceID() string     { return value.serviceID }
func (*l8JobCredentialReviewHTTPHandle) Renew(context.Context) error { return nil }
func (value *l8JobCredentialReviewHTTPHandle) Revoke(context.Context) error {
	value.mu.Lock()
	defer value.mu.Unlock()
	value.revokes++
	return value.revokeErr
}

type l8JobCredentialReviewGuestSession struct {
	*l8JobCredentialGuestSessionFake
	prepareResult l8JobCredentialGuestPrepareResult
}

func (value *l8JobCredentialReviewGuestSession) Prepare(context.Context, sandboxruntime.JobCredentialIdentity, time.Time, []l8JobCredentialGuestBindingManifest) (l8JobCredentialGuestPrepareResult, error) {
	return value.prepareResult, nil
}
