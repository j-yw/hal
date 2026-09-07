package sandboxruntime

import (
	"context"
	"sync"
	"time"
)

// MinimalLaunchRecoveryBinding is a retained cleanup-attempt handle, not prior-
// daemon authorization, a runtime owner, or resource-absence proof. The caller
// retains one handle per admitted identity; this is not a cross-handle registry.
type MinimalLaunchRecoveryBinding struct {
	self     *MinimalLaunchRecoveryBinding
	binding  *MinimalLaunchProviderBinding
	identity MinimalLaunchIdentity
	mu       sync.Mutex
	active   *minimalLaunchRecoveryAttempt
	owner    *MinimalLaunchOwnerBinding
	err      error
}

type minimalLaunchFinalizeAttempt struct {
	done    chan struct{}
	receipt MinimalLaunchCleanupReceipt
	err     error
}

type minimalLaunchRecoveryAttempt struct {
	done  chan struct{}
	owner *MinimalLaunchOwnerBinding
	err   error
}

func retainMinimalLaunchOwner(binding *MinimalLaunchProviderBinding, returned MinimalJobRuntimeOwner, identity MinimalLaunchIdentity) *MinimalLaunchOwnerBinding {
	owner := &MinimalLaunchOwnerBinding{binding: binding, owner: returned, identity: identity}
	owner.self = owner
	return owner
}

// Finalize serializes the original owner's idempotent callback. Its checked
// receipt is metadata only; it is not whole-job cleanup or terminal authority.
func (owner *MinimalLaunchOwnerBinding) Finalize(ctx context.Context) (MinimalLaunchCleanupReceipt, error) {
	if owner == nil || owner.self != owner || !validMinimalLaunchProviderBinding(owner.binding) || jobCredentialBindingValueIsNil(owner.owner) || !minimalLaunchCleanupContextCurrent(ctx) {
		return MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable
	}
	owner.mu.Lock()
	if owner.quarantined {
		owner.mu.Unlock()
		return MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable
	}
	if attempt := owner.active; attempt != nil {
		owner.mu.Unlock()
		if !waitMinimalLaunchCleanupAttempt(ctx, attempt.done) {
			return MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable
		}
		return owner.finalizeAttemptResult(ctx, attempt)
	}
	attempt := &minimalLaunchFinalizeAttempt{done: make(chan struct{})}
	owner.active = attempt
	cached := owner.receipt
	owner.mu.Unlock()

	receipt, err, quarantine := owner.callFinalize(ctx, cached)
	owner.mu.Lock()
	owner.quarantined = owner.quarantined || quarantine
	if owner.quarantined {
		owner.receipt = MinimalLaunchCleanupReceipt{}
	}
	if err == nil {
		owner.receipt = receipt
	}
	attempt.receipt, attempt.err = receipt, err
	owner.active = nil
	close(attempt.done)
	owner.mu.Unlock()
	return owner.finalizeAttemptResult(ctx, attempt)
}

func (owner *MinimalLaunchOwnerBinding) finalizeAttemptResult(ctx context.Context, attempt *minimalLaunchFinalizeAttempt) (MinimalLaunchCleanupReceipt, error) {
	owner.mu.Lock()
	quarantined := owner.quarantined
	owner.mu.Unlock()
	if quarantined || attempt.err != nil || !minimalLaunchCleanupContextCurrent(ctx) {
		return MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable
	}
	return attempt.receipt, nil
}

func (owner *MinimalLaunchOwnerBinding) callFinalize(ctx context.Context, cached MinimalLaunchCleanupReceipt) (MinimalLaunchCleanupReceipt, error, bool) {
	if !minimalLaunchCleanupContextCurrent(ctx) {
		return MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable, false
	}
	if !minimalLaunchOwnerIdentityMatches(owner.owner, owner.identity) {
		return MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable, true
	}
	if !minimalLaunchCleanupContextCurrent(ctx) {
		return MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable, false
	}
	if cached != (MinimalLaunchCleanupReceipt{}) {
		return cached, nil, false
	}
	receipt, err := callMinimalLaunchFinalize(ctx, owner.owner)
	identityMatches := minimalLaunchOwnerIdentityMatches(owner.owner, owner.identity)
	if !identityMatches || receipt != (MinimalLaunchCleanupReceipt{}) && receipt.Identity != owner.identity {
		return MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable, true
	}
	if err != nil || !minimalLaunchCleanupContextCurrent(ctx) || receipt.Identity != owner.identity || ValidateJobCredentialRuntimeRecoveryCommitReceipt(JobCredentialRuntimeRecoveryCommitReceipt{CommitID: receipt.OwnerCommitID, FinalizedRevision: receipt.FinalizedRevision}) != nil {
		return MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable, false
	}
	return receipt, nil, false
}

func callMinimalLaunchFinalize(ctx context.Context, owner MinimalJobRuntimeOwner) (receipt MinimalLaunchCleanupReceipt, err error) {
	defer func() {
		if recover() != nil {
			receipt, err = MinimalLaunchCleanupReceipt{}, ErrMinimalLaunchUnavailable
		}
	}()
	return owner.Finalize(ctx)
}

func minimalLaunchOwnerIdentityMatches(owner MinimalJobRuntimeOwner, identity MinimalLaunchIdentity) (matches bool) {
	defer func() {
		if recover() != nil {
			matches = false
		}
	}()
	return owner.Identity() == identity
}

// BindRecovery validates correlation syntax only. The worker must separately
// authorize stored identity and retain this handle; it grants no launch rights.
func (binding *MinimalLaunchProviderBinding) BindRecovery(identity MinimalLaunchIdentity) (*MinimalLaunchRecoveryBinding, error) {
	if !validMinimalLaunchProviderBinding(binding) || !validMinimalLaunchCleanupIdentity(identity) {
		return nil, ErrMinimalLaunchUnavailable
	}
	recovery := &MinimalLaunchRecoveryBinding{binding: binding, identity: identity}
	recovery.self = recovery
	return recovery, nil
}

// Recover retains the first nonnil owner even on failure. No later call can
// replace it. Nil-owner uncertainty may be retried explicitly on this handle.
func (recovery *MinimalLaunchRecoveryBinding) Recover(ctx context.Context) (*MinimalLaunchOwnerBinding, error) {
	if recovery == nil || recovery.self != recovery || !validMinimalLaunchProviderBinding(recovery.binding) || !minimalLaunchCleanupContextCurrent(ctx) {
		return nil, ErrMinimalLaunchUnavailable
	}
	recovery.mu.Lock()
	if recovery.owner != nil {
		owner, err := recovery.owner, recovery.err
		recovery.mu.Unlock()
		return minimalLaunchRecoveryResult(ctx, owner, err)
	}
	if attempt := recovery.active; attempt != nil {
		recovery.mu.Unlock()
		if !waitMinimalLaunchCleanupAttempt(ctx, attempt.done) {
			return nil, ErrMinimalLaunchUnavailable
		}
		return minimalLaunchRecoveryResult(ctx, attempt.owner, attempt.err)
	}
	attempt := &minimalLaunchRecoveryAttempt{done: make(chan struct{})}
	recovery.active = attempt
	recovery.mu.Unlock()

	owner, err := recovery.callRecover(ctx)
	recovery.mu.Lock()
	if owner != nil {
		recovery.owner, recovery.err = owner, err
	}
	attempt.owner, attempt.err = owner, err
	recovery.active = nil
	close(attempt.done)
	recovery.mu.Unlock()
	return minimalLaunchRecoveryResult(ctx, owner, err)
}

func (recovery *MinimalLaunchRecoveryBinding) callRecover(ctx context.Context) (owner *MinimalLaunchOwnerBinding, err error) {
	defer func() {
		if recover() != nil {
			err = ErrMinimalLaunchUnavailable
		}
	}()
	if !minimalLaunchCleanupContextCurrent(ctx) {
		return nil, ErrMinimalLaunchUnavailable
	}
	returned, err := recovery.binding.provider.RecoverMinimalJob(ctx, recovery.identity)
	if !jobCredentialBindingValueIsNil(returned) {
		owner = retainMinimalLaunchOwner(recovery.binding, returned, recovery.identity)
		owner.quarantined = !minimalLaunchOwnerIdentityMatches(returned, recovery.identity)
	}
	if owner == nil || owner.quarantined || err != nil || !minimalLaunchCleanupContextCurrent(ctx) {
		return owner, ErrMinimalLaunchUnavailable
	}
	return owner, nil
}

func minimalLaunchRecoveryResult(ctx context.Context, owner *MinimalLaunchOwnerBinding, err error) (*MinimalLaunchOwnerBinding, error) {
	if err != nil || !minimalLaunchCleanupContextCurrent(ctx) {
		return owner, ErrMinimalLaunchUnavailable
	}
	return owner, nil
}

func validMinimalLaunchProviderBinding(binding *MinimalLaunchProviderBinding) bool {
	return binding != nil && binding.self == binding && !jobCredentialBindingValueIsNil(binding.provider)
}

func validMinimalLaunchCleanupIdentity(identity MinimalLaunchIdentity) bool {
	for _, id := range []string{identity.WorkerJobID, identity.JobGeneration, identity.WorkerID, identity.HostID, identity.PrincipalID, identity.SandboxID, identity.ExecutionID, identity.SubmissionID, identity.RuntimeID, identity.RuntimeGeneration, identity.PlanID, identity.LaunchGrantID, identity.LaunchPolicyID} {
		if !ValidMinimalLaunchID(id) {
			return false
		}
	}
	return identity.WorkerJobID != identity.JobGeneration && validMinimalLaunchRequestKey(identity.RequestKey) && identity.LaunchPolicyRevision != 0
}

// These checks bound admission/publication, not arbitrary blocking trusted
// callbacks. No goroutine is detached to simulate cancellation of provider work.
func minimalLaunchCleanupContextCurrent(ctx context.Context) (current bool) {
	defer func() {
		if recover() != nil {
			current = false
		}
	}()
	if jobCredentialBindingValueIsNil(ctx) || ctx.Err() != nil {
		return false
	}
	deadline, ok := ctx.Deadline()
	return !ok || time.Now().Before(deadline)
}

func waitMinimalLaunchCleanupAttempt(ctx context.Context, done <-chan struct{}) (completed bool) {
	defer func() {
		if recover() != nil {
			completed = false
		}
	}()
	select {
	case <-ctx.Done():
		return false
	case <-done:
		return minimalLaunchCleanupContextCurrent(ctx)
	}
}
