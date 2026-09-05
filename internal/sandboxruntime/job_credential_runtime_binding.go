package sandboxruntime

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"time"
)

const jobCredentialRuntimeNeutralCleanupTimeout = 5 * time.Second

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
	loss       *jobCredentialRuntimeLossLatch
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
			cleanupErr := abortInvalidJobCredentialRuntimePreflight(preflight)
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
		cleanupErr := abortInvalidJobCredentialRuntimePreflight(preflight)
		if cleanupErr != nil {
			return nil, errJobCredentialRuntimeInvalidCleanup
		}
		return nil, ErrJobCredentialRuntimeBindingInvalid
	}
	latchedLoss := latchJobCredentialRuntimePreflightLoss(loss)
	identity, identityErr := callJobCredentialRuntimePreflightIdentity(preflight)
	if identityErr != nil || ValidateJobCredentialIdentityCompletion(seed, identity) != nil {
		cleanupErr := abortInvalidJobCredentialRuntimePreflight(preflight)
		lossErr := latchedLoss.stopAndWait()
		if cleanupErr != nil {
			return nil, errJobCredentialRuntimeInvalidCleanup
		}
		if lossErr != nil {
			return nil, ErrJobCredentialRuntimeBindingInvalid
		}
		return nil, ErrJobCredentialRuntimeBindingInvalid
	}
	return &JobCredentialRuntimePreflightBinding{
		identity:  cloneJobCredentialIdentity(identity),
		preflight: preflight,
		loss:      latchedLoss,
	}, nil
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
	return binding.loss.output
}

func (binding *JobCredentialRuntimePreflightBinding) Abort(ctx context.Context) (JobCredentialCleanupProof, error) {
	if binding == nil {
		return JobCredentialCleanupProof{}, ErrJobCredentialRuntimeCleanupIncomplete
	}
	binding.abortOnce.Do(func() {
		if jobCredentialBindingValueIsNil(ctx) {
			if binding.loss.stopAndWait() != nil {
				binding.abortErr = errJobCredentialRuntimeInvalidCleanup
			} else {
				binding.abortErr = ErrJobCredentialRuntimeCleanupIncomplete
			}
			return
		}
		proof, err := callJobCredentialRuntimePreflightAbort(binding.preflight, ctx)
		lossErr := binding.loss.stopAndWait()
		if err != nil || CleanupProofKind(proof) == "" {
			if lossErr != nil {
				binding.abortErr = errJobCredentialRuntimeInvalidCleanup
			} else {
				binding.abortErr = ErrJobCredentialRuntimeCleanupIncomplete
			}
			return
		}
		if lossErr != nil {
			binding.abortErr = ErrJobCredentialRuntimeBindingInvalid
			return
		}
		binding.abortProof = proof
	})
	return binding.abortProof, binding.abortErr
}

// AbortBounded uses a caller-independent cleanup context. Runtime
// implementations are trusted to honor this fixed neutral-boundary deadline;
// full D6 composition replaces it with the remaining owned cleanup budget.
func (binding *JobCredentialRuntimePreflightBinding) AbortBounded() (JobCredentialCleanupProof, error) {
	ctx, cancel := jobCredentialRuntimeNeutralCleanupContext()
	defer cancel()
	return binding.Abort(ctx)
}

func jobCredentialRuntimeNeutralCleanupContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), jobCredentialRuntimeNeutralCleanupTimeout)
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

func abortInvalidJobCredentialRuntimePreflight(preflight JobCredentialRuntimePreflight) error {
	if jobCredentialBindingValueIsNil(preflight) {
		return ErrJobCredentialRuntimeCleanupIncomplete
	}
	ctx, cancel := jobCredentialRuntimeNeutralCleanupContext()
	defer cancel()
	proof, err := callJobCredentialRuntimePreflightAbort(preflight, ctx)
	if err != nil || CleanupProofKind(proof) == "" {
		return ErrJobCredentialRuntimeCleanupIncomplete
	}
	return nil
}

type jobCredentialRuntimeLossLatch struct {
	output      chan JobCredentialLoss
	stop        chan struct{}
	done        chan struct{}
	stopOnce    sync.Once
	mu          sync.Mutex
	contractErr error
}

func latchJobCredentialRuntimePreflightLoss(source <-chan JobCredentialLoss) *jobCredentialRuntimeLossLatch {
	latch := &jobCredentialRuntimeLossLatch{
		output: make(chan JobCredentialLoss, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	go latch.run(source)
	return latch
}

func (latch *jobCredentialRuntimeLossLatch) run(source <-chan JobCredentialLoss) {
	defer close(latch.done)
	defer close(latch.output)
	select {
	case loss, ok := <-source:
		latch.recordSourceResult(loss, ok)
	case <-latch.stop:
		select {
		case loss, ok := <-source:
			latch.recordSourceResult(loss, ok)
		default:
		}
	}
}

func (latch *jobCredentialRuntimeLossLatch) recordSourceResult(loss JobCredentialLoss, ok bool) {
	if !ok {
		latch.mu.Lock()
		latch.contractErr = ErrJobCredentialRuntimeBindingInvalid
		latch.mu.Unlock()
		return
	}
	loss.Identity = cloneJobCredentialIdentity(loss.Identity)
	latch.output <- loss
}

func (latch *jobCredentialRuntimeLossLatch) stopAndWait() error {
	if latch == nil {
		return ErrJobCredentialRuntimeBindingInvalid
	}
	latch.stopOnce.Do(func() { close(latch.stop) })
	<-latch.done
	latch.mu.Lock()
	defer latch.mu.Unlock()
	return latch.contractErr
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
