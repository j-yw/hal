package sandboxruntime

import (
	"context"
	"errors"
)

var ErrMinimalLaunchUnavailable = errors.New("minimal launch unavailable")

// MinimalLaunchScope is trusted constructor configuration, not request authority.
// Correlation IDs for individual jobs are deliberately absent.
type MinimalLaunchScope struct {
	PolicyID, PrincipalID, WorkerID, HostID              string
	TemplatePolicyID, WorkspacePolicyID, NetworkPolicyID string
	Revision                                             uint64
}

// MinimalLaunchSelectionHints contains request correlation only. A provider
// must resolve current inputs from its independently configured ownership.
type MinimalLaunchSelectionHints struct {
	SandboxID, ExecutionID, SubmissionID, RuntimeID, PlanID string
	TemplatePolicyID, WorkspacePolicyID                     string
}

type MinimalLaunchSelectionIdentity struct {
	WorkerID, HostID, RuntimeID, RuntimeGeneration, PlanID string
	TemplatePolicyID, WorkspacePolicyID, NetworkPolicyID   string
}

// MinimalLaunchSelection retains provider-owned input currentness. Its strings
// alone cannot grant launch permission or establish preparation success.
type MinimalLaunchSelection interface {
	Current(context.Context) (MinimalLaunchSelectionIdentity, error)
	Close() error
}

// MinimalLaunchIdentity is correlation, not a complete credential identity.
type MinimalLaunchIdentity struct {
	WorkerJobID, JobGeneration, WorkerID, HostID, PrincipalID string
	SandboxID, ExecutionID, SubmissionID, RuntimeID           string
	RuntimeGeneration, PlanID, RequestKey                     string
	LaunchGrantID, LaunchPolicyID                             string
	LaunchPolicyRevision                                      uint64
}

// MinimalLaunchReservation is deliberately unissuable in the compiling RED
// checkpoint. Only the manager's reviewed durable dispatch boundary may later
// create its one-shot live authority; a zero value never authorizes launch.
type MinimalLaunchReservation struct{}

func (*MinimalLaunchReservation) ClaimLaunch(context.Context) (MinimalLaunchIdentity, error) {
	return MinimalLaunchIdentity{}, ErrMinimalLaunchUnavailable
}

// MinimalLaunchCleanupReceipt is bookkeeping returned by the same trusted
// provider after exact owner finalization. Decoding it cannot create authority.
type MinimalLaunchCleanupReceipt struct {
	Identity          MinimalLaunchIdentity
	OwnerCommitID     string
	FinalizedRevision uint64
}

type MinimalJobRuntimeOwner interface {
	Identity() MinimalLaunchIdentity
	Finalize(context.Context) (MinimalLaunchCleanupReceipt, error)
}

// MinimalJobRuntimeProvider is constructor-injected, never request-provided.
// Resolve is read-only; Start must claim the reservation before allocation and
// retain any partial owner alongside an error. Recover is cleanup-only.
type MinimalJobRuntimeProvider interface {
	ResolveMinimalSelection(context.Context, MinimalLaunchSelectionHints) (MinimalLaunchSelection, error)
	StartMinimalJob(context.Context, *MinimalLaunchReservation, MinimalLaunchSelection) (MinimalJobRuntimeOwner, error)
	RecoverMinimalJob(context.Context, MinimalLaunchIdentity) (MinimalJobRuntimeOwner, error)
}

// MinimalLaunchProviderBinding retains the exact constructor-injected provider.
// No dispatch method exists yet: wrapping an interface does not authorize a
// callback, and a zero or copied binding is not operational.
type MinimalLaunchProviderBinding struct {
	self     *MinimalLaunchProviderBinding
	provider MinimalJobRuntimeProvider
}

func NewMinimalLaunchProviderBinding(provider MinimalJobRuntimeProvider) (*MinimalLaunchProviderBinding, error) {
	if jobCredentialBindingValueIsNil(provider) {
		return nil, ErrMinimalLaunchUnavailable
	}
	binding := &MinimalLaunchProviderBinding{provider: provider}
	binding.self = binding
	return binding, nil
}

// MinimalLaunchAuthorizer retains constructor scope and exact dependency
// pairing only in this RED checkpoint. No grant issuance is implemented.
type MinimalLaunchAuthorizer struct {
	self      *MinimalLaunchAuthorizer
	authority *AuthenticatedWorkerPrincipalAuthority
	provider  *MinimalLaunchProviderBinding
	scopes    []MinimalLaunchScope
}

func NewMinimalLaunchAuthorizer(authority *AuthenticatedWorkerPrincipalAuthority, provider *MinimalLaunchProviderBinding, scopes []MinimalLaunchScope) (*MinimalLaunchAuthorizer, error) {
	if _, ok := loadAuthenticatedWorkerPrincipalAuthorityState(authority); !ok || provider == nil || provider.self != provider {
		return nil, ErrMinimalLaunchUnavailable
	}
	for _, scope := range scopes {
		if scope.Revision == 0 {
			return nil, ErrMinimalLaunchUnavailable
		}
		for _, id := range []string{scope.PolicyID, scope.PrincipalID, scope.WorkerID, scope.HostID, scope.TemplatePolicyID, scope.WorkspacePolicyID, scope.NetworkPolicyID} {
			if len(id) > 64 || !validJobCredentialSafeID(id) {
				return nil, ErrMinimalLaunchUnavailable
			}
		}
	}
	value := &MinimalLaunchAuthorizer{authority: authority, provider: provider, scopes: append([]MinimalLaunchScope(nil), scopes...)}
	value.self = value
	return value, nil
}

// MatchesDependencies checks the exact live constructor pairing; matching
// visible principal or provider labels is insufficient.
func (authorizer *MinimalLaunchAuthorizer) MatchesDependencies(authority *AuthenticatedWorkerPrincipalAuthority, provider *MinimalLaunchProviderBinding) bool {
	return authorizer != nil && authorizer.self == authorizer && authorizer.authority == authority &&
		provider != nil && provider.self == provider && authorizer.provider == provider
}
