package firecrackerhost

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestL8RuntimeOwnerRecoveryBindingSatisfiesInterface(t *testing.T) {
	var _ sandboxruntime.JobCredentialRuntimeRecoveryBinding = (*l8RuntimeOwnerRecoveryBinding)(nil)
}

func TestL8RuntimeOwnerRecoveryBindingRecoverRequiresCompleteIdentityThenAlwaysStopReaps(t *testing.T) {
	if !l8RuntimeOwnerPlatformSupported() {
		t.Skip("Linux-only recovery binding")
	}
	seed := l8RuntimeOwnerTestSeed()
	identity := l8RuntimeOwnerTestIdentity(t, seed)
	record := l8RuntimeOwnerTestRunningRecord(t, seed)
	binding, store := l8RuntimeOwnerTestRecoveryBinding(t, record, func() (l8RuntimeOwnerAbsenceObservation, error) {
		return l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindWait, ObservedAt: seed.IssuedAt.Add(2 * time.Second)}, nil
	})
	stopCalls := 0
	inner := binding.proveAbsence
	binding.proveAbsence = func(ctx context.Context) (l8RuntimeOwnerAbsenceObservation, error) {
		stopCalls++
		return inner(ctx)
	}

	mismatch := identity
	mismatch.RuntimeID = "runtime-neighbor"
	proof, err := binding.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{Identity: mismatch, Revision: 1})
	if proof != (sandboxruntime.JobCredentialCleanupProof{}) || !errors.Is(err, sandboxruntime.ErrJobCredentialIdentityMismatch) {
		t.Fatalf("mismatch recover = %#v, %v", proof, err)
	}
	if stopCalls != 0 || store.record.State != "running" {
		t.Fatalf("mismatch contained: calls %d state %s", stopCalls, store.record.State)
	}

	cleanup := l8RuntimeOwnerTestCleanupProof(t, identity)
	binding.recoverCredentials = func(context.Context, sandboxruntime.JobCredentialRecoveryRequest) (sandboxruntime.JobCredentialCleanupProof, error) {
		return cleanup, nil
	}
	got, err := binding.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{Identity: identity, Revision: 4})
	if err != nil || got != cleanup {
		t.Fatalf("complete-identity recover = %#v, %v", got, err)
	}
	if stopCalls != 1 || store.record.State != "absent" {
		t.Fatalf("valid recover skipped stop/reap: calls %d state %s", stopCalls, store.record.State)
	}

	binding.recoverCredentials = func(context.Context, sandboxruntime.JobCredentialRecoveryRequest) (sandboxruntime.JobCredentialCleanupProof, error) {
		return sandboxruntime.JobCredentialCleanupProof{}, errors.New("private credential path /tmp/secret pid=4242")
	}
	failed, err := binding.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{Identity: identity, Revision: 4})
	if failed != (sandboxruntime.JobCredentialCleanupProof{}) || !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("failed recover = %#v, %v", failed, err)
	}
	if stopCalls != 2 {
		t.Fatalf("failed recover skipped stop/reap: calls %d", stopCalls)
	}
	if strings.Contains(err.Error(), "pid") || strings.Contains(err.Error(), "/tmp") || strings.Contains(err.Error(), "secret") {
		t.Fatalf("recover error leaked internals: %v", err)
	}

	binding.recoverCredentials = func(context.Context, sandboxruntime.JobCredentialRecoveryRequest) (sandboxruntime.JobCredentialCleanupProof, error) {
		panic("private recover panic")
	}
	if _, err := binding.RecoverJobCredentials(context.Background(), sandboxruntime.JobCredentialRecoveryRequest{Identity: identity, Revision: 4}); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("panic recover = %v", err)
	}
	if stopCalls != 3 {
		t.Fatalf("panic recover skipped stop/reap: calls %d", stopCalls)
	}
}

func TestL8RuntimeOwnerRecoveryBindingStopReapIsSoleAbsenceProofIssuer(t *testing.T) {
	if !l8RuntimeOwnerPlatformSupported() {
		t.Skip("Linux-only recovery binding")
	}
	seed := l8RuntimeOwnerTestSeed()
	now := seed.IssuedAt.Add(time.Minute)
	record := l8RuntimeOwnerTestRunningRecord(t, seed)
	binding, store := l8RuntimeOwnerTestRecoveryBinding(t, record, func() (l8RuntimeOwnerAbsenceObservation, error) {
		return l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindWait, ObservedAt: seed.IssuedAt.Add(3 * time.Second)}, nil
	})
	binding.now = func() time.Time { return now }

	proof, err := binding.StopReapJobCredentialRuntime(context.Background())
	if err != nil {
		t.Fatalf("stop/reap: %v", err)
	}
	if err := sandboxruntime.ValidateJobCredentialRuntimeAbsenceProof(proof, seed, now); err != nil {
		t.Fatalf("issued proof invalid: %v", err)
	}
	if store.record.State != "absent" || store.record.AbsenceKind != "direct_wait" {
		t.Fatalf("absent record = %#v", store.record)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	fresh, err := binding.StopReapJobCredentialRuntime(canceled)
	if err != nil {
		t.Fatalf("reinspect after cancel: %v", err)
	}
	if err := sandboxruntime.ValidateJobCredentialRuntimeAbsenceProof(fresh, seed, now); err != nil || fresh == proof {
		t.Fatalf("fresh absence proof = %#v, %v", fresh, err)
	}

	failed := &l8RuntimeOwnerRecoveryBinding{seed: seed, proveAbsence: func(context.Context) (l8RuntimeOwnerAbsenceObservation, error) {
		return l8RuntimeOwnerAbsenceObservation{}, errors.New("private wait /proc/4242")
	}}
	zero, err := failed.StopReapJobCredentialRuntime(context.Background())
	if zero != (sandboxruntime.JobCredentialRuntimeAbsenceProof{}) || !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("failed stop/reap = %#v, %v", zero, err)
	}
	if strings.Contains(err.Error(), "4242") || strings.Contains(err.Error(), "/proc") {
		t.Fatalf("stop/reap error leaked internals: %v", err)
	}

	boolean := &l8RuntimeOwnerRecoveryBinding{seed: seed, proveAbsence: func(context.Context) (l8RuntimeOwnerAbsenceObservation, error) {
		return l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindNone, ObservedAt: now}, nil
	}}
	if proof, err := boolean.StopReapJobCredentialRuntime(context.Background()); proof != (sandboxruntime.JobCredentialRuntimeAbsenceProof{}) || !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("caller boolean minted proof = %#v, %v", proof, err)
	}
}

func TestL8RuntimeOwnerRecoveryBindingStopReapReplacementProcIssuesProof(t *testing.T) {
	if !l8RuntimeOwnerPlatformSupported() {
		t.Skip("Linux-only recovery binding")
	}
	seed := l8RuntimeOwnerTestSeed()
	now := seed.IssuedAt.Add(time.Minute)
	record := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState = "absent", "controlled"
	store := &l8RuntimeOwnerTestStore{record: record}
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
		Store: store, ExpectedUID: 1000, CommitKey: bytes32("0123456789abcdef0123456789abcdef"),
		ReinspectAbsence: func() (l8RuntimeOwnerAbsenceObservation, error) {
			return l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindProc, ObservedAt: seed.IssuedAt.Add(4 * time.Second)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := &l8RuntimeOwnerRecoveryBinding{
		seed: seed, store: store, commitKey: bytes32("0123456789abcdef0123456789abcdef"),
		now: func() time.Time { return now },
		proveAbsence: func(ctx context.Context) (l8RuntimeOwnerAbsenceObservation, error) {
			loaded, err := store.Load(ctx)
			if err != nil {
				return l8RuntimeOwnerAbsenceObservation{}, err
			}
			next, err := owner.reinspectAbsence(ctx, loaded)
			if err != nil {
				return l8RuntimeOwnerAbsenceObservation{}, err
			}
			return l8RuntimeOwnerAbsenceObservation{
				Kind:       l8RuntimeOwnerAbsenceKindByte(next.AbsenceKind),
				Revision:   next.AbsenceRevision,
				ObservedAt: time.Unix(0, next.AbsenceObservedAtUnixNano).UTC(),
			}, nil
		},
	}
	proof, err := binding.StopReapJobCredentialRuntime(context.Background())
	if err != nil {
		t.Fatalf("replacement stop/reap: %v", err)
	}
	if err := sandboxruntime.ValidateJobCredentialRuntimeAbsenceProof(proof, seed, now); err != nil {
		t.Fatalf("replacement proof: %v", err)
	}
	if store.record.AbsenceKind != "replacement_proc" {
		t.Fatalf("absence kind = %s", store.record.AbsenceKind)
	}
}

func TestL8RuntimeOwnerRecoveryBindingFinalizeFailClosesWithoutRecoveredL7Binding(t *testing.T) {
	if !l8RuntimeOwnerPlatformSupported() {
		t.Skip("Linux-only recovery binding")
	}
	seed := l8RuntimeOwnerTestSeed()
	now := seed.IssuedAt.Add(time.Minute)
	record := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState = "absent", "controlled"
	binding, store := l8RuntimeOwnerTestRecoveryBinding(t, record, nil)
	binding.now = func() time.Time { return now }
	binding.proveAbsence = func(context.Context) (l8RuntimeOwnerAbsenceObservation, error) {
		return l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindWait, ObservedAt: seed.IssuedAt.Add(time.Second)}, nil
	}
	proof, err := sandboxruntime.NewJobCredentialRuntimeAbsenceProof(sandboxruntime.JobCredentialRuntimeAbsenceProofInput{
		Seed: seed, AbsenceInspectedAt: seed.IssuedAt.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := binding.FinalizeJobCredentialRuntimeRecovery(context.Background(), proof)
	if receipt != (sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt{}) || !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("finalize without recovered L7 = %#v, %v", receipt, err)
	}
	if store.record.State != "absent" {
		t.Fatalf("finalize persisted tombstone without L7: %#v", store.record)
	}

	stale := proof
	binding.now = func() time.Time {
		return seed.IssuedAt.Add(sandboxruntime.MaxJobCredentialRuntimeAbsenceObservationAge + 2*time.Minute)
	}
	if _, err := binding.FinalizeJobCredentialRuntimeRecovery(context.Background(), stale); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("stale finalize = %v", err)
	}
	binding.now = func() time.Time { return now }
	binding.currentBootID = func() (string, error) { return "22345678-1234-4abc-8def-1234567890ab", nil }
	if _, err := binding.FinalizeJobCredentialRuntimeRecovery(context.Background(), proof); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("old-boot finalize = %v", err)
	}
	if store.record.State != "absent" {
		t.Fatalf("old-boot retired state: %#v", store.record)
	}
}

func TestL8RuntimeOwnerRecoveryBindingCommitUsesOwnerVerifier(t *testing.T) {
	if !l8RuntimeOwnerPlatformSupported() {
		t.Skip("Linux-only recovery binding")
	}
	seed := l8RuntimeOwnerTestSeed()
	key := bytes32("0123456789abcdef0123456789abcdef")
	digest, err := l8RuntimeOwnerSeedDigest(seed)
	if err != nil {
		t.Fatal(err)
	}
	commitID, err := l8RuntimeOwnerCommitID(key, digest, 9)
	if err != nil {
		t.Fatal(err)
	}
	record := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState, record.Revision = "finalized", "controlled", 9
	record.FinalizeTargetRevision = 9
	record.FinalizedCommitID = commitID
	store := &l8RuntimeOwnerTestStore{record: record}
	binding := &l8RuntimeOwnerRecoveryBinding{seed: seed, commitKey: key, store: store}
	receipt := sandboxruntime.JobCredentialRuntimeRecoveryCommitReceipt{CommitID: commitID, FinalizedRevision: 9}
	if err := binding.CommitJobCredentialRuntimeRecovery(context.Background(), receipt); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !store.retiredFinal {
		t.Fatal("commit did not retire finalized record")
	}

	store.retiredFinal = false
	store.record = record
	wrong := receipt
	wrong.CommitID = l8RuntimeOwnerTestToken(9)
	if err := binding.CommitJobCredentialRuntimeRecovery(context.Background(), wrong); !errors.Is(err, errL8RuntimeOwnerInvalid) || store.retiredFinal {
		t.Fatalf("wrong HMAC commit = %v retired %t", err, store.retiredFinal)
	}

	store.retiredFinal = false
	store.record = record
	store.record.FinalizedCommitID = l8RuntimeOwnerTestToken(9)
	if err := binding.CommitJobCredentialRuntimeRecovery(context.Background(), receipt); !errors.Is(err, errL8RuntimeOwnerInvalid) || store.retiredFinal {
		t.Fatalf("receipt/record commit mismatch = %v retired %t", err, store.retiredFinal)
	}

	commitOnly := &l8RuntimeOwnerRecoveryBinding{seed: seed, commitKey: key, store: &l8RuntimeOwnerMissingStore{}, commitOnly: true}
	if err := commitOnly.CommitJobCredentialRuntimeRecovery(context.Background(), receipt); err != nil {
		t.Fatalf("commit-only: %v", err)
	}
	reappeared := &l8RuntimeOwnerRecoveryBinding{seed: seed, commitKey: key, store: store, commitOnly: true}
	if err := reappeared.CommitJobCredentialRuntimeRecovery(context.Background(), receipt); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("commit-only with record = %v", err)
	}
	uncertain := &l8RuntimeOwnerRecoveryBinding{seed: seed, commitKey: key, store: l8RuntimeOwnerUncertainMissingStore{}, commitOnly: true}
	if err := uncertain.CommitJobCredentialRuntimeRecovery(context.Background(), receipt); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("commit-only with uncertain record absence = %v", err)
	}

	store.record = record
	store.retiredFinal = false
	if err := binding.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := binding.CommitJobCredentialRuntimeRecovery(context.Background(), receipt); !errors.Is(err, errL8RuntimeOwnerInvalid) || store.retiredFinal {
		t.Fatalf("commit after close = %v retired %t", err, store.retiredFinal)
	}
}

func TestL8RuntimeOwnerRecoveryBindingCloseDoesNotImplyAbsence(t *testing.T) {
	if !l8RuntimeOwnerPlatformSupported() {
		t.Skip("Linux-only recovery binding")
	}
	seed := l8RuntimeOwnerTestSeed()
	record := l8RuntimeOwnerTestRunningRecord(t, seed)
	binding, store := l8RuntimeOwnerTestRecoveryBinding(t, record, func() (l8RuntimeOwnerAbsenceObservation, error) {
		t.Fatal("close must not stop/reap")
		return l8RuntimeOwnerAbsenceObservation{}, nil
	})
	if err := binding.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := binding.Close(context.Background()); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	if store.record.State != "running" || store.retiredFinal {
		t.Fatalf("close retired owner state: %#v", store.record)
	}
	if _, err := binding.StopReapJobCredentialRuntime(context.Background()); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("stop/reap after close = %v", err)
	}
	if err := binding.Close(nil); !errors.Is(err, errL8RuntimeOwnerInvalid) {
		t.Fatalf("close with nil context = %v", err)
	}
}

func l8RuntimeOwnerTestIdentity(t *testing.T, seed sandboxruntime.JobCredentialIdentitySeed) sandboxruntime.JobCredentialIdentity {
	t.Helper()
	identity, err := sandboxruntime.CompleteJobCredentialIdentity(seed, l8RuntimeOwnerTestToken(4), "helper-generation-1")
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func l8RuntimeOwnerTestCleanupProof(t *testing.T, identity sandboxruntime.JobCredentialIdentity) sandboxruntime.JobCredentialCleanupProof {
	t.Helper()
	proof, err := sandboxruntime.NewJobCredentialCleanupProof(sandboxruntime.JobCredentialCleanupProofInput{
		ProofID:            "cleanup-runtime-owner",
		Identity:           identity,
		Revision:           4,
		RevokedAt:          identity.IssuedAt.Add(time.Second),
		AbsenceInspectedAt: identity.IssuedAt.Add(2 * time.Second),
		AuthorityAbsent:    true,
		ResourcesAbsent:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return proof
}

func l8RuntimeOwnerTestRunningRecord(t *testing.T, seed sandboxruntime.JobCredentialIdentitySeed) firecrackerRuntimeOwnerRecordV1 {
	t.Helper()
	record := l8RuntimeOwnerTestRecord(t, seed, "01234567-89ab-cdef-0123-456789abcdef")
	record.State, record.ControllerState, record.Revision = "running", "controlled", 2
	record.AbsenceKind, record.AbsenceRevision, record.AbsenceObservedAtUnixNano = "", 0, 0
	return record
}

func l8RuntimeOwnerTestRecoveryBinding(t *testing.T, record firecrackerRuntimeOwnerRecordV1, contain func() (l8RuntimeOwnerAbsenceObservation, error)) (*l8RuntimeOwnerRecoveryBinding, *l8RuntimeOwnerTestStore) {
	t.Helper()
	seed := l8RuntimeOwnerTestSeed()
	store := &l8RuntimeOwnerTestStore{record: record}
	key := bytes32("0123456789abcdef0123456789abcdef")
	owner, err := newL8RuntimeOwnerSupervisor(l8RuntimeOwnerSupervisorOptions{
		Store: store, ExpectedUID: 1000, CommitKey: key, ContainChild: contain,
		ReinspectAbsence: func() (l8RuntimeOwnerAbsenceObservation, error) {
			return l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindWait, ObservedAt: seed.IssuedAt.Add(5 * time.Second)}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding := &l8RuntimeOwnerRecoveryBinding{
		seed:      seed,
		commitKey: key,
		store:     store,
		now:       func() time.Time { return seed.IssuedAt.Add(time.Minute) },
		currentBootID: func() (string, error) {
			return record.HostBootID, nil
		},
		proveAbsence: func(ctx context.Context) (l8RuntimeOwnerAbsenceObservation, error) {
			loaded, err := store.Load(ctx)
			if err != nil {
				return l8RuntimeOwnerAbsenceObservation{}, err
			}
			next, err := owner.reinspectAbsence(ctx, loaded)
			if err != nil {
				return l8RuntimeOwnerAbsenceObservation{}, err
			}
			return l8RuntimeOwnerAbsenceObservation{
				Kind:       l8RuntimeOwnerAbsenceKindByte(next.AbsenceKind),
				Revision:   next.AbsenceRevision,
				ObservedAt: time.Unix(0, next.AbsenceObservedAtUnixNano).UTC(),
			}, nil
		},
	}
	return binding, store
}

func bytes32(value string) []byte {
	return []byte(value)
}

type l8RuntimeOwnerMissingStore struct{}

func (l8RuntimeOwnerMissingStore) RecordAbsent(context.Context) (bool, error) {
	return true, nil
}

func (l8RuntimeOwnerMissingStore) Load(context.Context) (firecrackerRuntimeOwnerRecordV1, error) {
	return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
}
func (l8RuntimeOwnerMissingStore) CreateGenesis(context.Context, firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error) {
	return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
}
func (l8RuntimeOwnerMissingStore) Transition(context.Context, uint64, firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error) {
	return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
}
func (l8RuntimeOwnerMissingStore) RetireStartingZero(context.Context, uint64) error {
	return errL8RuntimeOwnerInvalid
}
func (l8RuntimeOwnerMissingStore) RetireFinalized(context.Context, uint64, string) error {
	return errL8RuntimeOwnerInvalid
}

type l8RuntimeOwnerUncertainMissingStore struct {
	l8RuntimeOwnerMissingStore
}

func (l8RuntimeOwnerUncertainMissingStore) RecordAbsent(context.Context) (bool, error) {
	return false, errors.New("private record inspection failed")
}
