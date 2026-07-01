package sandboxtarget

import (
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// SchedulerIntent identifies callers that intentionally opt into cached target
// scheduling instead of legacy default sandbox resolution.
type SchedulerIntent string

const (
	SchedulerIntentNone              SchedulerIntent = ""
	SchedulerIntentExplicitTarget    SchedulerIntent = "explicit_target"
	SchedulerIntentAnyEligibleTarget SchedulerIntent = "any_eligible_target"
)

// SchedulerRequest describes the command-agnostic inputs needed to schedule a
// sandbox target from cached durable metadata.
type SchedulerRequest struct {
	Purpose        Purpose
	SandboxName    string
	HostID         string
	RuntimeDriver  string
	IsolationLevel string
	Intent         SchedulerIntent
	Project        ProjectContext
	Workspace      WorkspaceContext
	Fallback       FallbackPolicy
}

// WorkspaceContext carries stable workspace identity used for deterministic
// scheduling and lease-resource construction.
type WorkspaceContext struct {
	ID          string
	ResourceKey string
	Mode        string
	InputSource string
	Repository  string
	Branch      string
	SyncRef     string
}

// HasSchedulerIntent reports whether the request explicitly opts into the
// scheduler.
func (r SchedulerRequest) HasSchedulerIntent() bool {
	return strings.TrimSpace(string(r.Intent)) != ""
}

// HasHostConstraint reports whether the scheduler request names a durable host.
func (r SchedulerRequest) HasHostConstraint() bool {
	return strings.TrimSpace(r.HostID) != ""
}

// HasRuntimeConstraint reports whether the scheduler request names a runtime.
func (r SchedulerRequest) HasRuntimeConstraint() bool {
	return strings.TrimSpace(r.RuntimeDriver) != ""
}

// HasIsolationConstraint reports whether the scheduler request names an
// isolation level.
func (r SchedulerRequest) HasIsolationConstraint() bool {
	return strings.TrimSpace(r.IsolationLevel) != ""
}

// EffectiveFallbackPolicy returns the fallback policy that should be applied to
// this scheduler request.
func (r SchedulerRequest) EffectiveFallbackPolicy() FallbackPolicy {
	return r.Fallback.Effective()
}

// SchedulerResult describes a cached scheduler decision without coupling the
// scheduler to command packages, runtime adapters, worker clients, or providers.
type SchedulerResult struct {
	Selection      *SchedulerSelection
	DecisionReason SchedulerDecisionReason
	Capacity       SchedulerCapacityDecision
	Lease          SchedulerLeaseRequirement
	Rejection      *SchedulerRejection
}

// Selected reports whether the scheduler selected a target candidate.
func (r SchedulerResult) Selected() bool {
	return r.Selection != nil
}

// Rejected reports whether the scheduler reached a stable rejection.
func (r SchedulerResult) Rejected() bool {
	return r.Rejection != nil && r.Rejection.Reason != FailureReasonNone
}

// RequiresLease reports whether the selected result must acquire a durable
// lease before command execution proceeds.
func (r SchedulerResult) RequiresLease() bool {
	return r.Lease.Required
}

// SchedulerSelection carries selected durable target metadata and a compact
// identity that command packages can propagate into safe metadata.
type SchedulerSelection struct {
	Identity SchedulerTargetIdentity
	Sandbox  *sandbox.SandboxState
	Host     *sandbox.SandboxHost
	Runtime  *sandboxruntime.RuntimeState
}

// SchedulerTargetIdentity identifies the selected target without raw endpoints,
// endpoint hostnames, filesystem paths, or provider credentials.
type SchedulerTargetIdentity struct {
	SandboxID      string
	SandboxName    string
	HostID         string
	HostName       string
	HostKind       string
	RuntimeDriver  string
	RuntimeID      string
	IsolationLevel string
}

// SchedulerDecisionReason is a stable machine-readable scheduler decision
// reason.
type SchedulerDecisionReason string

const (
	SchedulerDecisionReasonNone                SchedulerDecisionReason = ""
	SchedulerDecisionReasonExplicitHost        SchedulerDecisionReason = "explicit_host"
	SchedulerDecisionReasonRequestedRuntime    SchedulerDecisionReason = "requested_runtime"
	SchedulerDecisionReasonRequestedIsolation  SchedulerDecisionReason = "requested_isolation"
	SchedulerDecisionReasonRankedCandidate     SchedulerDecisionReason = "ranked_candidate"
	SchedulerDecisionReasonCapacityAvailable   SchedulerDecisionReason = "capacity_available"
	SchedulerDecisionReasonCapacityUnavailable SchedulerDecisionReason = "capacity_unavailable"
	SchedulerDecisionReasonCapacityBlocked     SchedulerDecisionReason = "capacity_blocked"
)

// SchedulerCapacityDecision records the capacity facts used for a scheduling
// decision.
type SchedulerCapacityDecision struct {
	Known                   bool
	Allowed                 bool
	MaxConcurrentSandboxes  int
	ActiveLeases            int
	AvailableSlots          int
	ConservativeUnavailable bool
	Reason                  SchedulerDecisionReason
}

// SchedulerLeaseRequirement describes the durable lease a command boundary must
// acquire after a successful scheduled selection.
type SchedulerLeaseRequirement struct {
	Required    bool
	ResourceKey string
	Holder      string
	Purpose     Purpose
	RunID       string
	TTL         time.Duration
}

// SchedulerRejection carries redaction-safe rejection context for failed
// scheduler decisions.
type SchedulerRejection struct {
	Reason         FailureReason
	Message        string
	SandboxName    string
	HostID         string
	RuntimeDriver  string
	IsolationLevel string
}

// Error returns a stable, human-readable scheduler rejection description.
func (r SchedulerRejection) Error() string {
	if message := strings.TrimSpace(r.Message); message != "" {
		return message
	}
	if r.Reason != FailureReasonNone {
		return "sandbox target scheduling failed: " + string(r.Reason)
	}
	return "sandbox target scheduling failed"
}
