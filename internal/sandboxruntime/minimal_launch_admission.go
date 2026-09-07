package sandboxruntime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// MinimalLaunchPreparedSelection is owned by the existing worker manager after
// reservation. It cannot be reconstructed from its public identity fields.
type MinimalLaunchPreparedSelection struct {
	self       *MinimalLaunchPreparedSelection
	mu         sync.Mutex
	active     sync.WaitGroup
	closeOnce  sync.Once
	closed     bool
	closeErr   error
	authorizer *MinimalLaunchAuthorizer
	binding    *MinimalLaunchProviderBinding
	source     MinimalLaunchSelection
	identity   MinimalLaunchSelectionIdentity
	hints      MinimalLaunchSelectionHints
	principal  string
	scope      MinimalLaunchScope
}

// MinimalLaunchOwnerBinding retains partial ownership without exposing runtime
// callbacks to worker code. A retained handle is not itself cleanup proof.
type MinimalLaunchOwnerBinding struct {
	self        *MinimalLaunchOwnerBinding
	binding     *MinimalLaunchProviderBinding
	owner       MinimalJobRuntimeOwner
	identity    MinimalLaunchIdentity
	mu          sync.Mutex
	active      *minimalLaunchFinalizeAttempt
	receipt     MinimalLaunchCleanupReceipt
	quarantined bool
}

func (authorizer *MinimalLaunchAuthorizer) ResolveSelection(ctx context.Context, principal AuthenticatedWorkerPrincipal, workerID string, hints MinimalLaunchSelectionHints) (result *MinimalLaunchPreparedSelection, err error) {
	if authorizer == nil || !authorizer.MatchesDependencies(authorizer.authority, authorizer.provider) || ctx == nil || ctx.Err() != nil || !ValidMinimalLaunchID(workerID) || !validMinimalLaunchHints(hints) {
		return nil, ErrMinimalLaunchUnavailable
	}
	principalID, err := authorizer.authority.AuthenticatedWorkerPrincipalID(principal)
	if err != nil || !ValidMinimalLaunchID(principalID) {
		return nil, ErrMinimalLaunchUnavailable
	}
	eligible := false
	for _, scope := range authorizer.scopes {
		eligible = eligible || scope.PrincipalID == principalID && scope.WorkerID == workerID && scope.TemplatePolicyID == hints.TemplatePolicyID && scope.WorkspacePolicyID == hints.WorkspacePolicyID
	}
	if !eligible {
		return nil, ErrMinimalLaunchUnavailable
	}
	var source MinimalLaunchSelection
	defer func() {
		if recover() != nil {
			result, err = nil, ErrMinimalLaunchUnavailable
		}
		if result == nil && !jobCredentialBindingValueIsNil(source) {
			_ = closeMinimalLaunchSelection(source)
		}
	}()
	source, err = authorizer.provider.provider.ResolveMinimalSelection(ctx, hints)
	if err != nil || jobCredentialBindingValueIsNil(source) {
		return nil, ErrMinimalLaunchUnavailable
	}
	identity, err := source.Current(ctx)
	if err != nil || ctx.Err() != nil || authorizer.ctx.Err() != nil || !validMinimalLaunchSelection(identity) || identity.WorkerID != workerID || identity.RuntimeID != hints.RuntimeID || identity.PlanID != hints.PlanID || identity.TemplatePolicyID != hints.TemplatePolicyID || identity.WorkspacePolicyID != hints.WorkspacePolicyID {
		return nil, ErrMinimalLaunchUnavailable
	}
	for _, scope := range authorizer.scopes {
		if scope.PrincipalID == principalID && scope.WorkerID == identity.WorkerID && scope.HostID == identity.HostID && scope.TemplatePolicyID == identity.TemplatePolicyID && scope.WorkspacePolicyID == identity.WorkspacePolicyID && scope.NetworkPolicyID == identity.NetworkPolicyID {
			result = &MinimalLaunchPreparedSelection{authorizer: authorizer, binding: authorizer.provider, source: source, identity: identity, hints: hints, principal: principalID, scope: scope}
			result.self = result
			return result, nil
		}
	}
	return nil, ErrMinimalLaunchUnavailable
}

func (selection *MinimalLaunchPreparedSelection) Identity() MinimalLaunchSelectionIdentity {
	if selection == nil || selection.self != selection {
		return MinimalLaunchSelectionIdentity{}
	}
	return selection.identity
}

func (selection *MinimalLaunchPreparedSelection) Current(ctx context.Context) (err error) {
	if selection == nil || selection.self != selection || ctx == nil || ctx.Err() != nil || selection.authorizer.ctx.Err() != nil {
		return ErrMinimalLaunchUnavailable
	}
	selection.mu.Lock()
	if selection.closed {
		selection.mu.Unlock()
		return ErrMinimalLaunchUnavailable
	}
	selection.active.Add(1)
	selection.mu.Unlock()
	defer selection.active.Done()
	defer func() {
		if recover() != nil {
			err = ErrMinimalLaunchUnavailable
		}
	}()
	identity, err := selection.source.Current(ctx)
	if err != nil || identity != selection.identity || ctx.Err() != nil || selection.authorizer.ctx.Err() != nil {
		return ErrMinimalLaunchUnavailable
	}
	return nil
}

func (selection *MinimalLaunchPreparedSelection) Close() error {
	if selection == nil || selection.self != selection {
		return ErrMinimalLaunchUnavailable
	}
	selection.closeOnce.Do(func() {
		selection.mu.Lock()
		selection.closed = true
		selection.mu.Unlock()
		selection.active.Wait()
		selection.closeErr = closeMinimalLaunchSelection(selection.source)
	})
	return selection.closeErr
}

// Reserve binds caller-allocated IDs to the exact checked selection. It does
// not arm dispatch; the manager must first persist and read back both phases.
func (selection *MinimalLaunchPreparedSelection) Reserve(ctx, ownerContext context.Context, workerJobID, jobGeneration, requestKey string, deadline time.Time) (*MinimalLaunchReservation, error) {
	if selection == nil || selection.self != selection || ctx == nil || ctx.Err() != nil || ownerContext == nil || ownerContext.Err() != nil || !ValidMinimalLaunchID(workerJobID) || !ValidMinimalLaunchID(jobGeneration) || workerJobID == jobGeneration || !validMinimalLaunchRequestKey(requestKey) || !time.Now().Before(deadline) {
		return nil, ErrMinimalLaunchUnavailable
	}
	// Provider Current runs outside the bookkeeper lock before this cheap
	// issuance boundary, then again at Start before provider entry. Issuance
	// checks only our retained local identity/lifetime, never provider IO.
	selection.mu.Lock()
	defer selection.mu.Unlock()
	if selection.closed || selection.authorizer.ctx.Err() != nil {
		return nil, ErrMinimalLaunchUnavailable
	}
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, ErrMinimalLaunchUnavailable
	}
	grantID := "launch-" + hex.EncodeToString(entropy[:])
	clear(entropy[:])
	identity := MinimalLaunchIdentity{
		WorkerJobID: workerJobID, JobGeneration: jobGeneration, WorkerID: selection.identity.WorkerID, HostID: selection.identity.HostID, PrincipalID: selection.principal,
		SandboxID: selection.hints.SandboxID, ExecutionID: selection.hints.ExecutionID, SubmissionID: selection.hints.SubmissionID, RuntimeID: selection.identity.RuntimeID,
		RuntimeGeneration: selection.identity.RuntimeGeneration, PlanID: selection.identity.PlanID, RequestKey: requestKey,
		LaunchGrantID: grantID, LaunchPolicyID: selection.scope.PolicyID, LaunchPolicyRevision: selection.scope.Revision,
	}
	owned, cancel := context.WithDeadline(ownerContext, deadline)
	value := &MinimalLaunchReservation{identity: identity, selection: selection, ctx: owned, cancel: cancel, deadline: deadline}
	value.self = value
	value.stopAuthority = context.AfterFunc(selection.authorizer.ctx, cancel)
	if ctx.Err() != nil || selection.authorizer.ctx.Err() != nil || !time.Now().Before(deadline) {
		value.Revoke()
		return nil, ErrMinimalLaunchUnavailable
	}
	return value, nil
}

func (reservation *MinimalLaunchReservation) Identity() MinimalLaunchIdentity {
	if reservation == nil || reservation.self != reservation {
		return MinimalLaunchIdentity{}
	}
	return reservation.identity
}

func (reservation *MinimalLaunchReservation) Context() context.Context {
	if reservation == nil || reservation.self != reservation {
		return nil
	}
	return reservation.ctx
}

// OwnedContext is the compiling RED seam. It deliberately exposes the current
// combined lifetime until owned cancellation is separated from preparation.
func (reservation *MinimalLaunchReservation) OwnedContext() context.Context {
	return reservation.Context()
}

// ArmDispatch is called only by the manager after exact durable dispatch
// readback while holding its submission lock. No decoded record calls it.
func (reservation *MinimalLaunchReservation) ArmDispatch(ctx context.Context, identity MinimalLaunchIdentity) error {
	if reservation == nil || reservation.self != reservation || ctx == nil || ctx.Err() != nil {
		return ErrMinimalLaunchUnavailable
	}
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	if reservation.identity != identity || reservation.armed || reservation.claimed || !reservation.currentLocked() {
		return ErrMinimalLaunchUnavailable
	}
	reservation.armed = true
	return nil
}

func (reservation *MinimalLaunchReservation) ClaimLaunch(ctx context.Context) (MinimalLaunchIdentity, error) {
	if reservation == nil || reservation.self != reservation || ctx == nil || ctx.Err() != nil {
		return MinimalLaunchIdentity{}, ErrMinimalLaunchUnavailable
	}
	reservation.mu.Lock()
	defer reservation.mu.Unlock()
	if !reservation.armed || reservation.claimed || !reservation.currentLocked() {
		return MinimalLaunchIdentity{}, ErrMinimalLaunchUnavailable
	}
	reservation.claimed = true
	return reservation.identity, nil
}

func (reservation *MinimalLaunchReservation) currentLocked() bool {
	return !reservation.revoked && reservation.ctx.Err() == nil && reservation.selection.authorizer.ctx.Err() == nil && time.Now().Before(reservation.deadline)
}

func (reservation *MinimalLaunchReservation) Revoke() {
	if reservation == nil || reservation.self != reservation {
		return
	}
	reservation.mu.Lock()
	reservation.revoked = true
	reservation.cancel()
	reservation.stopAuthority()
	reservation.mu.Unlock()
}

func (authorizer *MinimalLaunchAuthorizer) Close() {
	if authorizer != nil && authorizer.self == authorizer && authorizer.cancel != nil {
		authorizer.cancel()
	}
}

// Start dispatches only this binding's armed reservation and original input
// handle. The caller must retain a nonnil returned owner even alongside errors.
func (binding *MinimalLaunchProviderBinding) Start(reservation *MinimalLaunchReservation, selection *MinimalLaunchPreparedSelection, barrier func() error) (owner *MinimalLaunchOwnerBinding, err error) {
	if binding == nil || binding.self != binding || reservation == nil || reservation.self != reservation || selection == nil || selection.self != selection || selection.binding != binding || reservation.selection != selection || barrier == nil {
		return nil, ErrMinimalLaunchUnavailable
	}
	reservation.mu.Lock()
	admitted := reservation.armed && !reservation.attempted && !reservation.claimed && reservation.currentLocked()
	if admitted {
		reservation.attempted = true
	}
	reservation.mu.Unlock()
	if !admitted {
		return nil, ErrMinimalLaunchUnavailable
	}
	selection.mu.Lock()
	if selection.closed {
		selection.mu.Unlock()
		return nil, ErrMinimalLaunchUnavailable
	}
	selection.active.Add(1)
	selection.mu.Unlock()
	defer selection.active.Done()
	defer func() {
		if recover() != nil {
			err = ErrMinimalLaunchUnavailable
		}
	}()
	// No provider or barrier callback runs under either retained mutex. Mark
	// the one attempt before callbacks, but leave ClaimLaunch to the provider.
	if selection.Current(reservation.ctx) != nil || barrier() != nil {
		return nil, ErrMinimalLaunchUnavailable
	}
	reservation.mu.Lock()
	current := reservation.armed && !reservation.claimed && reservation.currentLocked()
	reservation.mu.Unlock()
	if !current {
		return nil, ErrMinimalLaunchUnavailable
	}
	returned, err := binding.provider.StartMinimalJob(reservation.ctx, reservation, selection.source)
	if !jobCredentialBindingValueIsNil(returned) {
		owner = retainMinimalLaunchOwner(binding, returned, reservation.identity)
	}
	if err != nil || owner == nil {
		return owner, ErrMinimalLaunchUnavailable
	}
	if !minimalLaunchOwnerIdentityMatches(owner.owner, reservation.identity) {
		owner.quarantined = true
		return owner, ErrMinimalLaunchUnavailable
	}
	if reservation.ctx.Err() != nil {
		return owner, ErrMinimalLaunchUnavailable
	}
	reservation.mu.Lock()
	claimed := reservation.claimed
	reservation.mu.Unlock()
	if !claimed {
		return owner, ErrMinimalLaunchUnavailable
	}
	return owner, nil
}

func closeMinimalLaunchSelection(selection MinimalLaunchSelection) (err error) {
	defer func() {
		if recover() != nil {
			err = ErrMinimalLaunchUnavailable
		}
	}()
	if selection.Close() != nil {
		return ErrMinimalLaunchUnavailable
	}
	return nil
}

// ValidMinimalLaunchID checks syntax only, not identity or launch authority.
// Selected minimal IDs must match [A-Za-z0-9][A-Za-z0-9._-]{0,63}.
func ValidMinimalLaunchID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i := range len(value) {
		ch := value[i]
		if ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || i > 0 && (ch == '.' || ch == '_' || ch == '-') {
			continue
		}
		return false
	}
	return true
}

func validMinimalLaunchHints(hints MinimalLaunchSelectionHints) bool {
	for _, value := range []string{hints.SandboxID, hints.ExecutionID, hints.SubmissionID, hints.RuntimeID, hints.PlanID, hints.TemplatePolicyID, hints.WorkspacePolicyID} {
		if !ValidMinimalLaunchID(value) {
			return false
		}
	}
	return true
}

func validMinimalLaunchSelection(identity MinimalLaunchSelectionIdentity) bool {
	for _, value := range []string{identity.WorkerID, identity.HostID, identity.RuntimeID, identity.RuntimeGeneration, identity.PlanID, identity.TemplatePolicyID, identity.WorkspacePolicyID, identity.NetworkPolicyID} {
		if !ValidMinimalLaunchID(value) {
			return false
		}
	}
	return true
}

func validMinimalLaunchRequestKey(value string) bool {
	if !strings.HasPrefix(value, "request-v2-") || len(value) != len("request-v2-")+64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "request-v2-"))
	return err == nil
}
