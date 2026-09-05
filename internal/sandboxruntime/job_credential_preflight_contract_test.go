package sandboxruntime

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestL8JobCredentialRuntimePreflightExactMethodSets(t *testing.T) {
	runtimeType := reflect.TypeOf((*JobCredentialRuntime)(nil)).Elem()
	assertExactInterfaceMethods(t, runtimeType, map[string]reflect.Type{
		"PreflightJobCredentials": reflect.TypeOf((func(context.Context, JobCredentialIdentitySeed) (JobCredentialRuntimePreflight, error))(nil)),
		"RecoverJobCredentials":   reflect.TypeOf((func(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error))(nil)),
	})
	if _, ok := runtimeType.MethodByName("PrepareJobCredentials"); ok {
		t.Fatal("JobCredentialRuntime retains the forbidden direct PrepareJobCredentials method")
	}

	preflightType := reflect.TypeOf((*JobCredentialRuntimePreflight)(nil)).Elem()
	assertExactInterfaceMethods(t, preflightType, map[string]reflect.Type{
		"Identity":              reflect.TypeOf((func() JobCredentialIdentity)(nil)),
		"PrepareJobCredentials": reflect.TypeOf((func(context.Context, JobCredentialPrepareRequest) (JobCredentialSession, error))(nil)),
		"Abort":                 reflect.TypeOf((func(context.Context) (JobCredentialCleanupProof, error))(nil)),
		"Loss":                  reflect.TypeOf((func() <-chan JobCredentialLoss)(nil)),
	})

	var _ JobCredentialRuntime = (*l8PreflightFakeRuntime)(nil)
	var _ JobCredentialRuntimePreflight = (*l8PreflightFake)(nil)
	var _ JobCredentialSession = (*l8PreflightFakeSession)(nil)
}

func TestL8JobCredentialRuntimePreflightIdentityIsExactAndDefensive(t *testing.T) {
	seed, identity, _ := l8PreflightFixtures(t)
	preflight := newL8PreflightFake(t, identity)

	first := preflight.Identity()
	if err := ValidateJobCredentialIdentityCompletion(seed, first); err != nil {
		t.Fatalf("preflight identity is not the exact seed completion: %v", err)
	}
	first.BindingIDs[0] = "caller-mutated"
	first.DeliveryModes[0] = JobCredentialDeliveryModeSSHAgent
	second := preflight.Identity()
	if err := ValidateJobCredentialIdentityCompletion(seed, second); err != nil {
		t.Fatalf("identity retained caller-owned slices: %v", err)
	}
	if second.BindingIDs[0] != identity.BindingIDs[0] || second.DeliveryModes[0] != identity.DeliveryModes[0] {
		t.Fatal("Identity did not return a defensive deep copy")
	}
}

func TestL8JobCredentialRuntimePreflightSinglePrepareTransfersOwnership(t *testing.T) {
	_, identity, request := l8PreflightFixtures(t)
	preflight := newL8PreflightFake(t, identity)
	preflight.prepareResult = &l8PreflightFakeSession{loss: preflight.loss}
	close(preflight.releasePrepare)

	session, err := preflight.PrepareJobCredentials(context.Background(), request)
	if err != nil || isNilL8PreflightContractValue(session) {
		t.Fatalf("first prepare = %#v, %v; want a non-nil session", session, err)
	}
	if got := preflight.currentState(); got != l8PreflightTransferred {
		t.Fatalf("state = %s, want transferred", got)
	}
	if second, err := preflight.PrepareJobCredentials(context.Background(), request); !errors.Is(err, ErrJobCredentialTransition) || second != nil {
		t.Fatalf("second prepare = %#v, %v; want nil transition error", second, err)
	}
	if proof, err := preflight.Abort(context.Background()); !errors.Is(err, ErrJobCredentialTransition) || !reflect.DeepEqual(proof, JobCredentialCleanupProof{}) {
		t.Fatalf("abort after transfer = %#v, %v; want zero transition error", proof, err)
	}
	if session.Loss() != preflight.Loss() {
		t.Fatal("preflight and transferred session do not expose the same loss latch")
	}
}

func TestL8JobCredentialRuntimePreflightAbortIsIdempotentBeforeTransfer(t *testing.T) {
	_, identity, request := l8PreflightFixtures(t)
	preflight := newL8PreflightFake(t, identity)

	first, err := preflight.Abort(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := preflight.Abort(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !sameJobCredentialCleanupProof(first, second) {
		t.Fatal("repeated abort did not return the identical cleanup proof")
	}
	if err := ValidateJobCredentialCleanupProof(first, identity, 2, identity.IssuedAt.Add(2*time.Second)); err != nil {
		t.Fatalf("abort cleanup proof is invalid: %v", err)
	}
	if got := preflight.currentState(); got != l8PreflightAborted {
		t.Fatalf("state = %s, want aborted", got)
	}
	if session, err := preflight.PrepareJobCredentials(context.Background(), request); !errors.Is(err, ErrJobCredentialTransition) || session != nil {
		t.Fatalf("prepare after abort = %#v, %v; want nil transition error", session, err)
	}
}

func TestL8JobCredentialRuntimePreflightPrepareReturnMatrix(t *testing.T) {
	_, identity, request := l8PreflightFixtures(t)
	prepareErr := errors.New("sanitized prepare failure")
	validSession := func(loss <-chan JobCredentialLoss) JobCredentialSession {
		return &l8PreflightFakeSession{loss: loss}
	}
	typedNilSession := func(<-chan JobCredentialLoss) JobCredentialSession {
		var session *l8PreflightFakeSession
		return session
	}

	tests := []struct {
		name      string
		session   func(<-chan JobCredentialLoss) JobCredentialSession
		err       error
		transfers bool
	}{
		{name: "session nil error", session: validSession, transfers: true},
		{name: "nil session error", err: prepareErr},
		{name: "session plus error", session: validSession, err: prepareErr},
		{name: "nil session nil error"},
		{name: "typed nil session nil error", session: typedNilSession},
		{name: "typed nil session error", session: typedNilSession, err: prepareErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			preflight := newL8PreflightFake(t, identity)
			if tt.session != nil {
				preflight.prepareResult = tt.session(preflight.loss)
			}
			preflight.prepareErr = tt.err
			close(preflight.releasePrepare)

			session, err := preflight.PrepareJobCredentials(context.Background(), request)
			if !errors.Is(err, tt.err) {
				t.Fatalf("prepare error = %v, want %v", err, tt.err)
			}
			if tt.transfers {
				if isNilL8PreflightContractValue(session) || preflight.currentState() != l8PreflightTransferred {
					t.Fatalf("valid return did not transfer ownership: %#v, %s", session, preflight.currentState())
				}
				return
			}
			if got := preflight.currentState(); got != l8PreflightOpen {
				t.Fatalf("invalid return state = %s, want open for abort", got)
			}
			if _, abortErr := preflight.Abort(context.Background()); abortErr != nil {
				t.Fatalf("invalid return did not retain abort ownership: %v", abortErr)
			}
		})
	}
}

func TestL8JobCredentialRuntimePreflightReturnMatrix(t *testing.T) {
	seed, identity, _ := l8PreflightFixtures(t)
	preflightErr := errors.New("sanitized preflight failure")
	valid := newL8PreflightFake(t, identity)
	var typedNil *l8PreflightFake
	tests := []struct {
		name      string
		preflight JobCredentialRuntimePreflight
		err       error
		valid     bool
	}{
		{name: "handle nil error", preflight: valid, valid: true},
		{name: "nil handle error", err: preflightErr, valid: true},
		{name: "handle plus error", preflight: valid, err: preflightErr},
		{name: "nil handle nil error"},
		{name: "typed nil handle nil error", preflight: typedNil},
		{name: "typed nil handle error", preflight: typedNil, err: preflightErr},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &l8PreflightFakeRuntime{preflight: tt.preflight, err: tt.err}
			got, err := runtime.PreflightJobCredentials(context.Background(), seed)
			if !errors.Is(err, tt.err) {
				t.Fatalf("error = %v, want %v", err, tt.err)
			}
			if contractValid := l8ValidPreflightReturn(got, err); contractValid != tt.valid {
				t.Fatalf("return (%#v, %v) validity = %t, want %t", got, err, contractValid, tt.valid)
			}
		})
	}
}

func TestL8JobCredentialRuntimePreflightTransferAbortAndLossRaces(t *testing.T) {
	_, identity, request := l8PreflightFixtures(t)

	t.Run("abort wins prepare", func(t *testing.T) {
		preflight := newL8PreflightFake(t, identity)
		preflight.prepareResult = &l8PreflightFakeSession{loss: preflight.loss}
		result := make(chan struct {
			session JobCredentialSession
			err     error
		}, 1)
		go func() {
			session, err := preflight.PrepareJobCredentials(context.Background(), request)
			result <- struct {
				session JobCredentialSession
				err     error
			}{session: session, err: err}
		}()
		<-preflight.prepareStarted
		if got := preflight.currentState(); got != l8PreflightPreparing {
			t.Fatalf("state = %s, want preparing", got)
		}
		if _, err := preflight.Abort(context.Background()); err != nil {
			t.Fatal(err)
		}
		close(preflight.releasePrepare)
		got := <-result
		if got.session != nil || !errors.Is(got.err, ErrJobCredentialTransition) {
			t.Fatalf("prepare after abort won = %#v, %v", got.session, got.err)
		}
	})

	t.Run("transfer wins abort", func(t *testing.T) {
		preflight := newL8PreflightFake(t, identity)
		preflight.prepareResult = &l8PreflightFakeSession{loss: preflight.loss}
		close(preflight.releasePrepare)
		if _, err := preflight.PrepareJobCredentials(context.Background(), request); err != nil {
			t.Fatal(err)
		}
		if _, err := preflight.Abort(context.Background()); !errors.Is(err, ErrJobCredentialTransition) {
			t.Fatalf("abort error = %v, want transition", err)
		}
	})

	t.Run("loss wins prepare", func(t *testing.T) {
		preflight := newL8PreflightFake(t, identity)
		preflight.prepareResult = &l8PreflightFakeSession{loss: preflight.loss}
		result := make(chan error, 1)
		go func() {
			session, err := preflight.PrepareJobCredentials(context.Background(), request)
			if session != nil {
				result <- errors.New("loss-winning prepare returned a session")
				return
			}
			result <- err
		}()
		<-preflight.prepareStarted
		preflight.emitLoss()
		close(preflight.releasePrepare)
		if err := <-result; !errors.Is(err, ErrJobCredentialTransition) {
			t.Fatalf("prepare error = %v, want transition", err)
		}
		if _, err := preflight.Abort(context.Background()); err != nil {
			t.Fatalf("abort after loss: %v", err)
		}
	})

	t.Run("transfer wins loss", func(t *testing.T) {
		preflight := newL8PreflightFake(t, identity)
		preflight.prepareResult = &l8PreflightFakeSession{loss: preflight.loss}
		close(preflight.releasePrepare)
		session, err := preflight.PrepareJobCredentials(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		preflight.emitLoss()
		got, ok := <-session.Loss()
		if !ok || got.Revision != 1 || got.Code != JobCredentialFailureGuestHelperUnavailable || !sameJobCredentialIdentity(got.Identity, identity) {
			t.Fatalf("transferred loss = %#v, %t", got, ok)
		}
		if _, ok := <-session.Loss(); ok {
			t.Fatal("loss channel emitted more than one value")
		}
	})
}

func TestL8JobCredentialRuntimePreflightLossEmitsOneValueThenCloses(t *testing.T) {
	_, identity, _ := l8PreflightFixtures(t)
	preflight := newL8PreflightFake(t, identity)
	preflight.emitLoss()
	preflight.emitLoss()

	got, ok := <-preflight.Loss()
	if !ok || got.Revision != 1 || got.Code != JobCredentialFailureGuestHelperUnavailable || !sameJobCredentialIdentity(got.Identity, identity) {
		t.Fatalf("loss = %#v, %t", got, ok)
	}
	if _, ok := <-preflight.Loss(); ok {
		t.Fatal("loss channel did not close after exactly one value")
	}
}

func assertExactInterfaceMethods(t *testing.T, interfaceType reflect.Type, want map[string]reflect.Type) {
	t.Helper()
	if interfaceType.Kind() != reflect.Interface {
		t.Fatalf("%s kind = %s, want interface", interfaceType, interfaceType.Kind())
	}
	if interfaceType.NumMethod() != len(want) {
		t.Fatalf("%s has %d methods, want %d", interfaceType, interfaceType.NumMethod(), len(want))
	}
	for name, signature := range want {
		method, ok := interfaceType.MethodByName(name)
		if !ok {
			t.Fatalf("%s lacks %s", interfaceType, name)
		}
		if method.Type != signature {
			t.Fatalf("%s.%s type = %s, want %s", interfaceType, name, method.Type, signature)
		}
	}
}

type l8PreflightFakeState string

const (
	l8PreflightOpen        l8PreflightFakeState = "open"
	l8PreflightPreparing   l8PreflightFakeState = "preparing"
	l8PreflightTransferred l8PreflightFakeState = "transferred"
	l8PreflightAborted     l8PreflightFakeState = "aborted"
)

type l8PreflightFakeRuntime struct {
	preflight JobCredentialRuntimePreflight
	err       error
}

func (runtime *l8PreflightFakeRuntime) PreflightJobCredentials(context.Context, JobCredentialIdentitySeed) (JobCredentialRuntimePreflight, error) {
	return runtime.preflight, runtime.err
}

func (*l8PreflightFakeRuntime) RecoverJobCredentials(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error) {
	return JobCredentialCleanupProof{}, nil
}

type l8PreflightFake struct {
	mu               sync.Mutex
	identity         JobCredentialIdentity
	state            l8PreflightFakeState
	cleanupProof     JobCredentialCleanupProof
	prepareResult    JobCredentialSession
	prepareErr       error
	prepareStarted   chan struct{}
	prepareStartOnce sync.Once
	releasePrepare   chan struct{}
	loss             chan JobCredentialLoss
	lossOnce         sync.Once
	lossLatched      bool
}

func newL8PreflightFake(t *testing.T, identity JobCredentialIdentity) *l8PreflightFake {
	t.Helper()
	revokedAt := identity.IssuedAt.Add(time.Second)
	proof, err := NewJobCredentialCleanupProof(JobCredentialCleanupProofInput{
		ProofID: "preflight-abort-proof", Identity: identity, Revision: 2,
		RevokedAt: revokedAt, AbsenceInspectedAt: revokedAt,
		AuthorityAbsent: true, ResourcesAbsent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &l8PreflightFake{
		identity: identity, state: l8PreflightOpen, cleanupProof: proof,
		prepareStarted: make(chan struct{}), releasePrepare: make(chan struct{}),
		loss: make(chan JobCredentialLoss, 1),
	}
}

func (preflight *l8PreflightFake) Identity() JobCredentialIdentity {
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	return cloneJobCredentialIdentity(preflight.identity)
}

func (preflight *l8PreflightFake) PrepareJobCredentials(ctx context.Context, request JobCredentialPrepareRequest) (JobCredentialSession, error) {
	preflight.mu.Lock()
	if preflight.state != l8PreflightOpen || !sameJobCredentialIdentity(request.Identity, preflight.identity) {
		preflight.mu.Unlock()
		return nil, ErrJobCredentialTransition
	}
	preflight.state = l8PreflightPreparing
	preflight.prepareStartOnce.Do(func() { close(preflight.prepareStarted) })
	preflight.mu.Unlock()

	select {
	case <-ctx.Done():
		preflight.mu.Lock()
		if preflight.state == l8PreflightPreparing {
			preflight.state = l8PreflightOpen
		}
		preflight.mu.Unlock()
		return nil, ctx.Err()
	case <-preflight.releasePrepare:
	}

	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	if preflight.state != l8PreflightPreparing || preflight.lossLatched {
		if preflight.state == l8PreflightPreparing {
			preflight.state = l8PreflightOpen
		}
		return nil, ErrJobCredentialTransition
	}
	if !isNilL8PreflightContractValue(preflight.prepareResult) && preflight.prepareErr == nil {
		preflight.state = l8PreflightTransferred
		return preflight.prepareResult, nil
	}
	preflight.state = l8PreflightOpen
	return preflight.prepareResult, preflight.prepareErr
}

func (preflight *l8PreflightFake) Abort(context.Context) (JobCredentialCleanupProof, error) {
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	switch preflight.state {
	case l8PreflightTransferred:
		return JobCredentialCleanupProof{}, ErrJobCredentialTransition
	case l8PreflightAborted:
		return preflight.cleanupProof, nil
	case l8PreflightOpen, l8PreflightPreparing:
		preflight.state = l8PreflightAborted
		return preflight.cleanupProof, nil
	default:
		return JobCredentialCleanupProof{}, ErrJobCredentialTransition
	}
}

func (preflight *l8PreflightFake) Loss() <-chan JobCredentialLoss { return preflight.loss }

func (preflight *l8PreflightFake) emitLoss() {
	preflight.lossOnce.Do(func() {
		preflight.mu.Lock()
		preflight.lossLatched = true
		loss := JobCredentialLoss{
			Identity: cloneJobCredentialIdentity(preflight.identity), Revision: 1,
			Code: JobCredentialFailureGuestHelperUnavailable,
		}
		preflight.mu.Unlock()
		preflight.loss <- loss
		close(preflight.loss)
	})
}

func (preflight *l8PreflightFake) currentState() l8PreflightFakeState {
	preflight.mu.Lock()
	defer preflight.mu.Unlock()
	return preflight.state
}

type l8PreflightFakeSession struct {
	loss <-chan JobCredentialLoss
}

func (*l8PreflightFakeSession) ExecBinding() JobCredentialExecBinding { return nil }
func (*l8PreflightFakeSession) ActiveProof() JobCredentialActiveProof {
	return JobCredentialActiveProof{}
}
func (*l8PreflightFakeSession) Renew(context.Context) (JobCredentialActiveProof, error) {
	return JobCredentialActiveProof{}, nil
}
func (*l8PreflightFakeSession) Revoke(context.Context, JobCredentialRevokeReason) (JobCredentialCleanupProof, error) {
	return JobCredentialCleanupProof{}, nil
}
func (session *l8PreflightFakeSession) Loss() <-chan JobCredentialLoss { return session.loss }

func isNilL8PreflightContractValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return reflected.Kind() == reflect.Pointer && reflected.IsNil()
}

func l8ValidPreflightReturn(preflight JobCredentialRuntimePreflight, err error) bool {
	if err != nil {
		return preflight == nil
	}
	return !isNilL8PreflightContractValue(preflight)
}

func l8PreflightFixtures(t *testing.T) (JobCredentialIdentitySeed, JobCredentialIdentity, JobCredentialPrepareRequest) {
	t.Helper()
	seed := d2JobCredentialIdentitySeed(time.Date(2026, time.August, 5, 3, 4, 5, 0, time.UTC))
	identity, err := CompleteJobCredentialIdentity(seed, d2GuestSessionGeneration(7), "helper-generation-7")
	if err != nil {
		t.Fatal(err)
	}
	return seed, identity, JobCredentialPrepareRequest{Identity: cloneJobCredentialIdentity(identity)}
}
