package sandboxruntime

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestJobCredentialRuntimeBinderRejectsMissingAndTypedNilProviders(t *testing.T) {
	var typedNil *l8BindingProvider
	for _, provider := range []JobCredentialRuntimeBindingProvider{nil, typedNil} {
		binder, err := NewJobCredentialRuntimeBinder(provider)
		if binder != nil || !errors.Is(err, ErrJobCredentialRuntimeBindingUnavailable) {
			t.Fatalf("NewJobCredentialRuntimeBinder(%T) = %#v, %v; want unavailable", provider, binder, err)
		}
	}
}

func TestJobCredentialRuntimeBindingSourceCannotDeriveOrMintAuthority(t *testing.T) {
	source, err := os.ReadFile("job_credential_runtime_binding.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"target.Runtime.Metadata",
		"target.Connection.",
		"PrepareJobCredentials(",
		"NewJobCredentialActiveProof",
		"NewJobCredentialCleanupProof",
		"LiveSecretSource",
	} {
		if strings.Contains(string(source), forbidden) {
			t.Fatalf("neutral runtime binding source contains forbidden authority marker %q", forbidden)
		}
	}
}

func TestJobCredentialRuntimeBinderContainsProviderFailures(t *testing.T) {
	secret := "token=provider-secret path=/private/provider.sock"
	for _, tt := range []struct {
		name     string
		provider *l8BindingProvider
	}{
		{name: "error", provider: &l8BindingProvider{err: errors.New(secret)}},
		{name: "panic", provider: &l8BindingProvider{panicValue: secret}},
		{name: "handle plus error", provider: &l8BindingProvider{runtime: &l8BindingRuntime{}, err: errors.New(secret)}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			binder, err := NewJobCredentialRuntimeBinder(tt.provider)
			if err != nil {
				t.Fatal(err)
			}
			binding, err := binder.Bind(context.Background(), l8BindingTarget())
			if binding != nil || !errors.Is(err, ErrJobCredentialRuntimeBindingUnavailable) {
				t.Fatalf("Bind() = %#v, %v; want unavailable", binding, err)
			}
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("Bind() leaked provider detail: %v", err)
			}
		})
	}
}

func TestJobCredentialRuntimeBinderRejectsMissingAndTypedNilRuntimes(t *testing.T) {
	seed := d2JobCredentialIdentitySeed(time.Date(2026, time.August, 21, 0, 1, 2, 0, time.UTC))
	var typedNil *l8BindingRuntime
	for _, runtime := range []JobCredentialRuntime{nil, typedNil} {
		binder, err := NewJobCredentialRuntimeBinder(&l8BindingProvider{seed: seed, runtime: runtime})
		if err != nil {
			t.Fatal(err)
		}
		binding, err := binder.Bind(context.Background(), l8BindingTarget())
		if binding != nil || !errors.Is(err, ErrJobCredentialRuntimeBindingInvalid) {
			t.Fatalf("Bind(runtime %T) = %#v, %v; want invalid", runtime, binding, err)
		}
	}
}

func TestJobCredentialRuntimeBinderValidatesAndOwnsProviderSeedBeforePreflight(t *testing.T) {
	seed := d2JobCredentialIdentitySeed(time.Date(2026, time.August, 21, 1, 2, 3, 0, time.UTC))
	runtime := &l8BindingRuntime{panicOnPreflight: true}
	provider := &l8BindingProvider{seed: seed, runtime: runtime}
	binder, err := NewJobCredentialRuntimeBinder(provider)
	if err != nil {
		t.Fatal(err)
	}

	target := l8BindingTarget()
	target.Runtime.Metadata = &RuntimeMetadata{CapabilityLabels: []string{"runtime-generation-from-untrusted-metadata"}}
	target.Connection.Address = "/private/runtime.sock"
	binding, err := binder.Bind(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if provider.target.Runtime.Metadata != nil || provider.target.Connection != (ConnectionInfo{}) {
		t.Fatalf("provider target retained metadata or connection authority: %#v", provider.target)
	}

	seed.BindingIDs[0] = "caller-mutated"
	got := binding.Seed()
	if got.BindingIDs[0] == "caller-mutated" {
		t.Fatal("binding retained provider-owned seed slice")
	}
	got.BindingIDs[0] = "reader-mutated"
	if binding.Seed().BindingIDs[0] == "reader-mutated" {
		t.Fatal("Seed returned binding-owned storage")
	}

	invalid := provider.seed
	invalid.RuntimeGeneration = ""
	invalidRuntime := &l8BindingRuntime{panicOnPreflight: true}
	invalidBinder, err := NewJobCredentialRuntimeBinder(&l8BindingProvider{seed: invalid, runtime: invalidRuntime})
	if err != nil {
		t.Fatal(err)
	}
	if invalidBinding, bindErr := invalidBinder.Bind(context.Background(), target); invalidBinding != nil || !errors.Is(bindErr, ErrJobCredentialRuntimeBindingInvalid) {
		t.Fatalf("Bind(invalid seed) = %#v, %v; want invalid", invalidBinding, bindErr)
	}
	if invalidRuntime.preflightCalls != 0 {
		t.Fatal("invalid seed reached runtime preflight")
	}
}

func TestJobCredentialRuntimeBindingPreflightOrdersLossAndIdentity(t *testing.T) {
	seed := d2JobCredentialIdentitySeed(time.Date(2026, time.August, 21, 2, 3, 4, 0, time.UTC))
	identity, err := CompleteJobCredentialIdentity(seed, d2GuestSessionGeneration(8), "helper-generation-8")
	if err != nil {
		t.Fatal(err)
	}
	events := []string{}
	preflight := &l8BindingPreflight{identity: identity, loss: make(chan JobCredentialLoss), events: &events}
	runtime := &l8BindingRuntime{preflight: preflight, events: &events}
	provider := &l8BindingProvider{seed: seed, runtime: runtime, events: &events}
	binder, err := NewJobCredentialRuntimeBinder(provider)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := binder.Bind(context.Background(), l8BindingTarget())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := binding.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"bind", "preflight", "loss", "identity"}; !reflect.DeepEqual(events, want) {
		t.Fatalf("preflight events = %#v, want %#v", events, want)
	}
	if got := handle.Identity(); !sameJobCredentialIdentity(got, identity) {
		t.Fatal("preflight handle identity changed")
	}
	if second, secondErr := binding.Preflight(context.Background()); second != nil || !errors.Is(secondErr, ErrJobCredentialTransition) {
		t.Fatalf("second Preflight() = %#v, %v; want transition rejection", second, secondErr)
	}
	close(preflight.loss)
}

func TestJobCredentialRuntimeBindingPreflightRejectsTypedNilAndInvalidIdentityWithAbort(t *testing.T) {
	seed := d2JobCredentialIdentitySeed(time.Date(2026, time.August, 21, 3, 4, 5, 0, time.UTC))
	var typedNil *l8BindingPreflight
	for _, tt := range []struct {
		name      string
		preflight JobCredentialRuntimePreflight
		wantAbort int
	}{
		{name: "typed nil", preflight: typedNil},
		{name: "invalid identity", preflight: &l8BindingPreflight{loss: make(chan JobCredentialLoss)}, wantAbort: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			runtime := &l8BindingRuntime{preflight: tt.preflight}
			binder, err := NewJobCredentialRuntimeBinder(&l8BindingProvider{seed: seed, runtime: runtime})
			if err != nil {
				t.Fatal(err)
			}
			binding, err := binder.Bind(context.Background(), l8BindingTarget())
			if err != nil {
				t.Fatal(err)
			}
			handle, err := binding.Preflight(context.Background())
			if handle != nil || !errors.Is(err, ErrJobCredentialRuntimeBindingInvalid) {
				t.Fatalf("Preflight() = %#v, %v; want invalid", handle, err)
			}
			if concrete, ok := tt.preflight.(*l8BindingPreflight); ok && concrete != nil {
				if concrete.abortCalls != tt.wantAbort {
					t.Fatalf("Abort calls = %d, want %d", concrete.abortCalls, tt.wantAbort)
				}
				if tt.wantAbort != 0 && (concrete.abortContextErr != nil || !concrete.abortHadDeadline) {
					t.Fatalf("invalid preflight abort context = err %v, deadline %t; want live independent bounded context", concrete.abortContextErr, concrete.abortHadDeadline)
				}
				close(concrete.loss)
			}
		})
	}
}

func TestJobCredentialRuntimeBindingContainsPreflightFailureMatrix(t *testing.T) {
	seed := d2JobCredentialIdentitySeed(time.Date(2026, time.August, 21, 3, 30, 0, 0, time.UTC))
	secret := errors.New("token=preflight-secret path=/private/control.sock")
	for _, tt := range []struct {
		name       string
		runtime    *l8BindingRuntime
		want       error
		wantAbort  int
		closeAfter chan JobCredentialLoss
	}{
		{name: "nil without error", runtime: &l8BindingRuntime{}, want: ErrJobCredentialRuntimeBindingInvalid},
		{name: "error", runtime: &l8BindingRuntime{err: secret}, want: ErrJobCredentialRuntimeBindingUnavailable},
		{name: "panic", runtime: &l8BindingRuntime{panicValue: secret}, want: ErrJobCredentialRuntimeBindingUnavailable},
		{name: "handle plus error", runtime: &l8BindingRuntime{preflight: &l8BindingPreflight{loss: make(chan JobCredentialLoss), abortErr: secret}, err: secret}, want: ErrJobCredentialRuntimeBindingInvalid, wantAbort: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			binder, err := NewJobCredentialRuntimeBinder(&l8BindingProvider{seed: seed, runtime: tt.runtime})
			if err != nil {
				t.Fatal(err)
			}
			binding, err := binder.Bind(context.Background(), l8BindingTarget())
			if err != nil {
				t.Fatal(err)
			}
			handle, err := binding.Preflight(context.Background())
			if handle != nil || !errors.Is(err, tt.want) {
				t.Fatalf("Preflight() = %#v, %v; want %v", handle, err, tt.want)
			}
			if strings.Contains(err.Error(), "preflight-secret") || strings.Contains(err.Error(), "/private") {
				t.Fatalf("Preflight() leaked implementation detail: %v", err)
			}
			if concrete, ok := tt.runtime.preflight.(*l8BindingPreflight); ok {
				if concrete.abortCalls != tt.wantAbort {
					t.Fatalf("Abort calls = %d, want %d", concrete.abortCalls, tt.wantAbort)
				}
				if tt.wantAbort != 0 && (concrete.abortContextErr != nil || !concrete.abortHadDeadline) {
					t.Fatalf("failed preflight abort context = err %v, deadline %t; want live independent bounded context", concrete.abortContextErr, concrete.abortHadDeadline)
				}
			}
		})
	}
}

func TestJobCredentialRuntimePreflightBindingLatchesAbortOwnership(t *testing.T) {
	seed := d2JobCredentialIdentitySeed(time.Date(2026, time.August, 21, 4, 5, 6, 0, time.UTC))
	identity, err := CompleteJobCredentialIdentity(seed, d2GuestSessionGeneration(9), "helper-generation-9")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := NewJobCredentialCleanupProof(JobCredentialCleanupProofInput{
		ProofID:            "cleanup-neutral-boundary",
		Identity:           identity,
		Revision:           1,
		RevokedAt:          identity.IssuedAt.Add(time.Second),
		AbsenceInspectedAt: identity.IssuedAt.Add(2 * time.Second),
		AuthorityAbsent:    true,
		ResourcesAbsent:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	loss := make(chan JobCredentialLoss)
	preflight := &l8BindingPreflight{identity: identity, loss: loss, abortProof: proof}
	binder, err := NewJobCredentialRuntimeBinder(&l8BindingProvider{seed: seed, runtime: &l8BindingRuntime{preflight: preflight}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := binder.Bind(context.Background(), l8BindingTarget())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := binding.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first, firstErr := handle.Abort(context.Background())
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	second, secondErr := handle.Abort(canceled)
	if firstErr != nil || secondErr != nil || first != proof || second != proof || preflight.abortCalls != 1 {
		t.Fatalf("latched Abort = (%#v, %v), (%#v, %v), calls %d", first, firstErr, second, secondErr, preflight.abortCalls)
	}
	close(loss)

	failedLoss := make(chan JobCredentialLoss)
	failed := &l8BindingPreflight{identity: identity, loss: failedLoss, abortErr: errors.New("token=abort-secret")}
	failedBinder, err := NewJobCredentialRuntimeBinder(&l8BindingProvider{seed: seed, runtime: &l8BindingRuntime{preflight: failed}})
	if err != nil {
		t.Fatal(err)
	}
	failedBinding, err := failedBinder.Bind(context.Background(), l8BindingTarget())
	if err != nil {
		t.Fatal(err)
	}
	failedHandle, err := failedBinding.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, abortErr := failedHandle.Abort(context.Background()); !errors.Is(abortErr, ErrJobCredentialRuntimeCleanupIncomplete) || strings.Contains(abortErr.Error(), "abort-secret") {
		t.Fatalf("failed Abort() error = %v; want sanitized cleanup incomplete", abortErr)
	}
	close(failedLoss)
}

func TestJobCredentialRuntimePreflightBindingAbortJoinsLossWatcher(t *testing.T) {
	seed := d2JobCredentialIdentitySeed(time.Date(2026, time.August, 21, 4, 30, 0, 0, time.UTC))
	identity, err := CompleteJobCredentialIdentity(seed, d2GuestSessionGeneration(10), "helper-generation-10")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := NewJobCredentialCleanupProof(JobCredentialCleanupProofInput{
		ProofID:            "cleanup-neutral-watcher",
		Identity:           identity,
		Revision:           1,
		RevokedAt:          identity.IssuedAt.Add(time.Second),
		AbsenceInspectedAt: identity.IssuedAt.Add(2 * time.Second),
		AuthorityAbsent:    true,
		ResourcesAbsent:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	loss := make(chan JobCredentialLoss)
	preflight := &l8BindingPreflight{identity: identity, loss: loss, abortProof: proof}
	binder, err := NewJobCredentialRuntimeBinder(&l8BindingProvider{seed: seed, runtime: &l8BindingRuntime{preflight: preflight}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := binder.Bind(context.Background(), l8BindingTarget())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := binding.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	latched := handle.Loss()
	if _, err := handle.Abort(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case _, ok := <-latched:
		if ok {
			t.Fatal("abort synthesized a loss")
		}
	case <-time.After(time.Second):
		t.Fatal("Abort returned before joining the loss watcher")
	}
}

func TestJobCredentialRuntimePreflightBindingAbortBoundedUsesIndependentDeadline(t *testing.T) {
	seed := d2JobCredentialIdentitySeed(time.Date(2026, time.August, 21, 4, 40, 0, 0, time.UTC))
	identity, err := CompleteJobCredentialIdentity(seed, d2GuestSessionGeneration(12), "helper-generation-12")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := NewJobCredentialCleanupProof(JobCredentialCleanupProofInput{
		ProofID:            "cleanup-neutral-independent",
		Identity:           identity,
		Revision:           1,
		RevokedAt:          identity.IssuedAt.Add(time.Second),
		AbsenceInspectedAt: identity.IssuedAt.Add(2 * time.Second),
		AuthorityAbsent:    true,
		ResourcesAbsent:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	preflight := &l8BindingPreflight{identity: identity, loss: make(chan JobCredentialLoss), abortProof: proof}
	binder, err := NewJobCredentialRuntimeBinder(&l8BindingProvider{seed: seed, runtime: &l8BindingRuntime{preflight: preflight}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := binder.Bind(context.Background(), l8BindingTarget())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := binding.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got, abortErr := handle.AbortBounded(); abortErr != nil || got != proof {
		t.Fatalf("AbortBounded() = %#v, %v; want proof", got, abortErr)
	}
	if preflight.abortContextErr != nil || !preflight.abortHadDeadline {
		t.Fatalf("abort context = err %v, deadline %t; want live independent bounded context", preflight.abortContextErr, preflight.abortHadDeadline)
	}
}

func TestJobCredentialRuntimePreflightBindingRejectsEmptyLossCloseAtFinalization(t *testing.T) {
	seed := d2JobCredentialIdentitySeed(time.Date(2026, time.August, 21, 4, 45, 0, 0, time.UTC))
	identity, err := CompleteJobCredentialIdentity(seed, d2GuestSessionGeneration(11), "helper-generation-11")
	if err != nil {
		t.Fatal(err)
	}
	proof, err := NewJobCredentialCleanupProof(JobCredentialCleanupProofInput{
		ProofID:            "cleanup-neutral-empty-loss",
		Identity:           identity,
		Revision:           1,
		RevokedAt:          identity.IssuedAt.Add(time.Second),
		AbsenceInspectedAt: identity.IssuedAt.Add(2 * time.Second),
		AuthorityAbsent:    true,
		ResourcesAbsent:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	loss := make(chan JobCredentialLoss)
	close(loss)
	preflight := &l8BindingPreflight{identity: identity, loss: loss, abortProof: proof}
	binder, err := NewJobCredentialRuntimeBinder(&l8BindingProvider{seed: seed, runtime: &l8BindingRuntime{preflight: preflight}})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := binder.Bind(context.Background(), l8BindingTarget())
	if err != nil {
		t.Fatal(err)
	}
	handle, err := binding.Preflight(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if proof, abortErr := handle.Abort(context.Background()); proof != (JobCredentialCleanupProof{}) || !errors.Is(abortErr, ErrJobCredentialRuntimeBindingInvalid) {
		t.Fatalf("Abort(empty loss close) = %#v, %v; want invalid contract", proof, abortErr)
	}
}

type l8BindingProvider struct {
	seed       JobCredentialIdentitySeed
	runtime    JobCredentialRuntime
	err        error
	panicValue any
	target     Target
	events     *[]string
}

func (provider *l8BindingProvider) BindJobCredentialRuntime(_ context.Context, target Target) (JobCredentialIdentitySeed, JobCredentialRuntime, error) {
	if provider.panicValue != nil {
		panic(provider.panicValue)
	}
	provider.target = target
	if provider.events != nil {
		*provider.events = append(*provider.events, "bind")
	}
	return provider.seed, provider.runtime, provider.err
}

type l8BindingRuntime struct {
	preflight        JobCredentialRuntimePreflight
	err              error
	panicValue       any
	panicOnPreflight bool
	preflightCalls   int
	events           *[]string
}

func (runtime *l8BindingRuntime) PreflightJobCredentials(context.Context, JobCredentialIdentitySeed) (JobCredentialRuntimePreflight, error) {
	runtime.preflightCalls++
	if runtime.panicValue != nil {
		panic(runtime.panicValue)
	}
	if runtime.panicOnPreflight {
		panic("preflight must not run")
	}
	if runtime.events != nil {
		*runtime.events = append(*runtime.events, "preflight")
	}
	return runtime.preflight, runtime.err
}

func (*l8BindingRuntime) RecoverJobCredentials(context.Context, JobCredentialRecoveryRequest) (JobCredentialCleanupProof, error) {
	return JobCredentialCleanupProof{}, nil
}

type l8BindingPreflight struct {
	identity         JobCredentialIdentity
	loss             chan JobCredentialLoss
	abortProof       JobCredentialCleanupProof
	abortErr         error
	abortCalls       int
	abortContextErr  error
	abortHadDeadline bool
	events           *[]string
}

func (preflight *l8BindingPreflight) Identity() JobCredentialIdentity {
	if preflight.events != nil {
		*preflight.events = append(*preflight.events, "identity")
	}
	return preflight.identity
}

func (*l8BindingPreflight) PrepareJobCredentials(context.Context, JobCredentialPrepareRequest) (JobCredentialSession, error) {
	panic("neutral binding must not prepare credentials")
}

func (preflight *l8BindingPreflight) Abort(ctx context.Context) (JobCredentialCleanupProof, error) {
	preflight.abortCalls++
	preflight.abortContextErr = ctx.Err()
	_, preflight.abortHadDeadline = ctx.Deadline()
	return preflight.abortProof, preflight.abortErr
}

func (preflight *l8BindingPreflight) Loss() <-chan JobCredentialLoss {
	if preflight.events != nil {
		*preflight.events = append(*preflight.events, "loss")
	}
	return preflight.loss
}

func l8BindingTarget() Target {
	return Target{
		ID:     "sandbox-binding",
		Name:   "sandbox-binding",
		Status: "running",
		Runtime: RuntimeState{
			Driver:         DriverMicroVM,
			RuntimeID:      "runtime-binding",
			WorkerID:       "worker-binding",
			IsolationLevel: "microvm",
		},
	}
}
