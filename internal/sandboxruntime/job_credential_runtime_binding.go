package sandboxruntime

import (
	"context"
	"errors"
	"reflect"
	"sync"
)

var (
	ErrJobCredentialRuntimeBindingUnavailable = errors.New("job credential runtime binding unavailable")
	ErrJobCredentialRuntimeBindingInvalid     = errors.New("job credential runtime binding invalid")
	ErrJobCredentialRuntimeCleanupIncomplete  = errors.New("job credential runtime cleanup incomplete")
	errJobCredentialRuntimeInvalidCleanup     = jobCredentialRuntimeInvalidCleanupError{}
)

type jobCredentialRuntimeInvalidCleanupError struct{}

func (jobCredentialRuntimeInvalidCleanupError) Error() string {
	return "job credential runtime binding invalid with incomplete cleanup"
}

func (jobCredentialRuntimeInvalidCleanupError) Is(target error) bool {
	return target == ErrJobCredentialRuntimeBindingInvalid || target == ErrJobCredentialRuntimeCleanupIncomplete
}

// JobCredentialRuntimeBindingProvider resolves daemon-owned credential
// runtime authority for an already selected runtime target.
type JobCredentialRuntimeBindingProvider interface {
	BindJobCredentialRuntime(context.Context, Target) (JobCredentialIdentitySeed, JobCredentialRuntime, error)
}

// JobCredentialRuntimeBinder contains provider dispatch outside worker
// protocol code.
type JobCredentialRuntimeBinder struct {
	provider JobCredentialRuntimeBindingProvider
}

// JobCredentialRuntimeBinding retains one validated seed and runtime.
type JobCredentialRuntimeBinding struct {
	mu               sync.Mutex
	seed             JobCredentialIdentitySeed
	runtime          JobCredentialRuntime
	preflightClaimed bool
}

// JobCredentialRuntimePreflightBinding retains preflight cleanup ownership.
type JobCredentialRuntimePreflightBinding struct {
	identity   JobCredentialIdentity
	preflight  JobCredentialRuntimePreflight
	loss       <-chan JobCredentialLoss
	abortOnce  sync.Once
	abortProof JobCredentialCleanupProof
	abortErr   error
}

func NewJobCredentialRuntimeBinder(provider JobCredentialRuntimeBindingProvider) (*JobCredentialRuntimeBinder, error) {
	if jobCredentialBindingValueIsNil(provider) {
		return nil, ErrJobCredentialRuntimeBindingUnavailable
	}
	return &JobCredentialRuntimeBinder{provider: provider}, nil
}

func (binder *JobCredentialRuntimeBinder) Bind(ctx context.Context, target Target) (*JobCredentialRuntimeBinding, error) {
	if binder == nil || jobCredentialBindingValueIsNil(binder.provider) || jobCredentialBindingValueIsNil(ctx) {
		return nil, ErrJobCredentialRuntimeBindingUnavailable
	}
	seed, runtime, err := callJobCredentialRuntimeBindingProvider(binder.provider, ctx, jobCredentialBindingTarget(target))
	if err != nil {
		return nil, ErrJobCredentialRuntimeBindingUnavailable
	}
	cloned, err := CloneJobCredentialIdentitySeed(seed)
	if err != nil || jobCredentialBindingValueIsNil(runtime) {
		return nil, ErrJobCredentialRuntimeBindingInvalid
	}
	return &JobCredentialRuntimeBinding{seed: cloned, runtime: runtime}, nil
}

// BindTarget is the context-free protocol adapter for callers whose request
// context was already classified at their boundary.
func (binder *JobCredentialRuntimeBinder) BindTarget(target Target) (*JobCredentialRuntimeBinding, error) {
	return binder.Bind(context.Background(), target)
}

func (binding *JobCredentialRuntimeBinding) Seed() JobCredentialIdentitySeed {
	if binding == nil {
		return JobCredentialIdentitySeed{}
	}
	binding.mu.Lock()
	defer binding.mu.Unlock()
	seed, err := CloneJobCredentialIdentitySeed(binding.seed)
	if err != nil {
		return JobCredentialIdentitySeed{}
	}
	return seed
}

func (binding *JobCredentialRuntimeBinding) Preflight(ctx context.Context) (*JobCredentialRuntimePreflightBinding, error) {
	if binding == nil || jobCredentialBindingValueIsNil(ctx) {
		return nil, ErrJobCredentialRuntimeBindingUnavailable
	}
	binding.mu.Lock()
	if binding.preflightClaimed {
		binding.mu.Unlock()
		return nil, ErrJobCredentialTransition
	}
	binding.preflightClaimed = true
	seed, seedErr := CloneJobCredentialIdentitySeed(binding.seed)
	runtime := binding.runtime
	binding.mu.Unlock()
	if seedErr != nil || jobCredentialBindingValueIsNil(runtime) {
		return nil, ErrJobCredentialRuntimeBindingInvalid
	}

	preflight, err := callJobCredentialRuntimePreflight(runtime, ctx, seed)
	if err != nil {
		if !jobCredentialBindingValueIsNil(preflight) {
			cleanupErr := abortInvalidJobCredentialRuntimePreflight(ctx, preflight)
			if cleanupErr != nil {
				return nil, errJobCredentialRuntimeInvalidCleanup
			}
			return nil, ErrJobCredentialRuntimeBindingInvalid
		}
		return nil, ErrJobCredentialRuntimeBindingUnavailable
	}
	if jobCredentialBindingValueIsNil(preflight) {
		return nil, ErrJobCredentialRuntimeBindingInvalid
	}

	loss, lossErr := callJobCredentialRuntimePreflightLoss(preflight)
	if lossErr != nil || loss == nil {
		cleanupErr := abortInvalidJobCredentialRuntimePreflight(ctx, preflight)
		if cleanupErr != nil {
			return nil, errJobCredentialRuntimeInvalidCleanup
		}
		return nil, ErrJobCredentialRuntimeBindingInvalid
	}
	latchedLoss := latchJobCredentialRuntimePreflightLoss(loss)
	identity, identityErr := callJobCredentialRuntimePreflightIdentity(preflight)
	if identityErr != nil || ValidateJobCredentialIdentityCompletion(seed, identity) != nil {
		cleanupErr := abortInvalidJobCredentialRuntimePreflight(ctx, preflight)
		if cleanupErr != nil {
			return nil, errJobCredentialRuntimeInvalidCleanup
		}
		return nil, ErrJobCredentialRuntimeBindingInvalid
	}
	return &JobCredentialRuntimePreflightBinding{
		identity:  cloneJobCredentialIdentity(identity),
		preflight: preflight,
		loss:      latchedLoss,
	}, nil
}

// PreflightNow is the context-free protocol adapter paired with BindTarget.
func (binding *JobCredentialRuntimeBinding) PreflightNow() (*JobCredentialRuntimePreflightBinding, error) {
	return binding.Preflight(context.Background())
}

func (binding *JobCredentialRuntimePreflightBinding) Identity() JobCredentialIdentity {
	if binding == nil {
		return JobCredentialIdentity{}
	}
	return cloneJobCredentialIdentity(binding.identity)
}

// Loss returns the worker-owned terminal latch started before Identity was
// inspected. The channel carries at most one defensively copied loss.
func (binding *JobCredentialRuntimePreflightBinding) Loss() <-chan JobCredentialLoss {
	if binding == nil {
		return nil
	}
	return binding.loss
}

func (binding *JobCredentialRuntimePreflightBinding) Abort(ctx context.Context) (JobCredentialCleanupProof, error) {
	if binding == nil {
		return JobCredentialCleanupProof{}, ErrJobCredentialRuntimeCleanupIncomplete
	}
	binding.abortOnce.Do(func() {
		if jobCredentialBindingValueIsNil(ctx) {
			binding.abortErr = ErrJobCredentialRuntimeCleanupIncomplete
			return
		}
		proof, err := callJobCredentialRuntimePreflightAbort(binding.preflight, ctx)
		if err != nil || CleanupProofKind(proof) == "" {
			binding.abortErr = ErrJobCredentialRuntimeCleanupIncomplete
			return
		}
		binding.abortProof = proof
	})
	return binding.abortProof, binding.abortErr
}

// AbortNow is the context-free protocol adapter paired with PreflightNow.
func (binding *JobCredentialRuntimePreflightBinding) AbortNow() (JobCredentialCleanupProof, error) {
	return binding.Abort(context.Background())
}

func callJobCredentialRuntimeBindingProvider(provider JobCredentialRuntimeBindingProvider, ctx context.Context, target Target) (seed JobCredentialIdentitySeed, runtime JobCredentialRuntime, err error) {
	defer func() {
		if recover() != nil {
			seed = JobCredentialIdentitySeed{}
			runtime = nil
			err = ErrJobCredentialRuntimeBindingUnavailable
		}
	}()
	return provider.BindJobCredentialRuntime(ctx, target)
}

func callJobCredentialRuntimePreflight(runtime JobCredentialRuntime, ctx context.Context, seed JobCredentialIdentitySeed) (preflight JobCredentialRuntimePreflight, err error) {
	defer func() {
		if recover() != nil {
			preflight = nil
			err = ErrJobCredentialRuntimeBindingUnavailable
		}
	}()
	return runtime.PreflightJobCredentials(ctx, seed)
}

func callJobCredentialRuntimePreflightLoss(preflight JobCredentialRuntimePreflight) (loss <-chan JobCredentialLoss, err error) {
	defer func() {
		if recover() != nil {
			loss = nil
			err = ErrJobCredentialRuntimeBindingInvalid
		}
	}()
	return preflight.Loss(), nil
}

func callJobCredentialRuntimePreflightIdentity(preflight JobCredentialRuntimePreflight) (identity JobCredentialIdentity, err error) {
	defer func() {
		if recover() != nil {
			identity = JobCredentialIdentity{}
			err = ErrJobCredentialRuntimeBindingInvalid
		}
	}()
	return preflight.Identity(), nil
}

func callJobCredentialRuntimePreflightAbort(preflight JobCredentialRuntimePreflight, ctx context.Context) (proof JobCredentialCleanupProof, err error) {
	defer func() {
		if recover() != nil {
			proof = JobCredentialCleanupProof{}
			err = ErrJobCredentialRuntimeCleanupIncomplete
		}
	}()
	return preflight.Abort(ctx)
}

func abortInvalidJobCredentialRuntimePreflight(ctx context.Context, preflight JobCredentialRuntimePreflight) error {
	if jobCredentialBindingValueIsNil(preflight) || jobCredentialBindingValueIsNil(ctx) {
		return ErrJobCredentialRuntimeCleanupIncomplete
	}
	proof, err := callJobCredentialRuntimePreflightAbort(preflight, ctx)
	if err != nil || CleanupProofKind(proof) == "" {
		return ErrJobCredentialRuntimeCleanupIncomplete
	}
	return nil
}

func latchJobCredentialRuntimePreflightLoss(source <-chan JobCredentialLoss) <-chan JobCredentialLoss {
	latched := make(chan JobCredentialLoss, 1)
	go func() {
		loss, ok := <-source
		if ok {
			loss.Identity = cloneJobCredentialIdentity(loss.Identity)
			latched <- loss
		}
		close(latched)
	}()
	return latched
}

func jobCredentialBindingTarget(target Target) Target {
	return Target{
		ID:       target.ID,
		Name:     target.Name,
		Provider: target.Provider,
		Status:   target.Status,
		Runtime: RuntimeState{
			Driver:         target.Runtime.Driver,
			RuntimeID:      target.Runtime.RuntimeID,
			Image:          target.Runtime.Image,
			WorkerID:       target.Runtime.WorkerID,
			IsolationLevel: target.Runtime.IsolationLevel,
		},
	}
}

func jobCredentialBindingValueIsNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}
