package sandboxtarget

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// SchedulerCandidate is a cached durable host considered by the scheduler.
type SchedulerCandidate struct {
	Identity SchedulerTargetIdentity
	Host     *sandbox.SandboxHost
	Runtime  *sandboxruntime.RuntimeState
}

// SchedulerCandidateSet describes cached candidates or the deterministic
// rejection that prevented candidate enumeration.
type SchedulerCandidateSet struct {
	Candidates []SchedulerCandidate
	Rejection  *SchedulerRejection
}

// Failed reports whether candidate enumeration reached a stable rejection.
func (s SchedulerCandidateSet) Failed() bool {
	return s.Rejection != nil && s.Rejection.Reason != FailureReasonNone
}

// Empty reports whether candidate enumeration produced no cached candidates.
func (s SchedulerCandidateSet) Empty() bool {
	return len(s.Candidates) == 0
}

// EnumerateSchedulerCandidates reads cached durable hosts through the injected
// cache and returns them in deterministic host name then ID order.
func EnumerateSchedulerCandidates(req SchedulerRequest, cache CachedState) SchedulerCandidateSet {
	if cache.ListHosts == nil {
		return SchedulerCandidateSet{Rejection: schedulerRejection(req, FailureReasonInvalidRequest, "cached host lister is required")}
	}

	hosts, err := cache.ListHosts()
	if err != nil {
		return SchedulerCandidateSet{Rejection: schedulerRejection(req, FailureReasonInvalidRequest, "list cached sandbox hosts failed")}
	}

	ordered := orderedHosts(hosts)
	if len(ordered) == 0 {
		return SchedulerCandidateSet{Rejection: schedulerRejection(req, FailureReasonHostNotFound, "no cached sandbox hosts")}
	}

	candidates := make([]SchedulerCandidate, 0, len(ordered))
	for _, host := range ordered {
		candidates = append(candidates, schedulerCandidateFromHost(host))
	}
	return SchedulerCandidateSet{Candidates: candidates}
}

// Schedule makes the scheduler's current deterministic cached-host decision.
// Later scheduler phases add filtering, capacity, lease, and ranking behavior
// between candidate enumeration and the final selection.
func Schedule(req SchedulerRequest, cache CachedState) SchedulerResult {
	candidateSet := EnumerateSchedulerCandidates(req, cache)
	if candidateSet.Failed() {
		return SchedulerResult{Rejection: candidateSet.Rejection}
	}
	if candidateSet.Empty() {
		return SchedulerResult{Rejection: schedulerRejection(req, FailureReasonHostNotFound, "no cached sandbox hosts")}
	}

	candidate := candidateSet.Candidates[0]
	return SchedulerResult{
		Selection: &SchedulerSelection{
			Identity: candidate.Identity,
			Host:     cloneSandboxHost(candidate.Host),
			Runtime:  cloneRuntimeState(candidate.Runtime),
		},
		DecisionReason: SchedulerDecisionReasonRankedCandidate,
	}
}

func schedulerCandidateFromHost(host *sandbox.SandboxHost) SchedulerCandidate {
	clonedHost := cloneSandboxHost(host)
	candidate := SchedulerCandidate{
		Host: clonedHost,
	}
	if clonedHost != nil {
		candidate.Identity = SchedulerTargetIdentity{
			HostID:   strings.TrimSpace(clonedHost.ID),
			HostName: strings.TrimSpace(clonedHost.Name),
			HostKind: strings.TrimSpace(clonedHost.Kind),
		}
	}
	return candidate
}

func schedulerRejection(req SchedulerRequest, reason FailureReason, message string) *SchedulerRejection {
	return &SchedulerRejection{
		Reason:         reason,
		Message:        message,
		SandboxName:    strings.TrimSpace(req.SandboxName),
		HostID:         strings.TrimSpace(req.HostID),
		RuntimeDriver:  strings.TrimSpace(req.RuntimeDriver),
		IsolationLevel: strings.TrimSpace(req.IsolationLevel),
	}
}

func cloneRuntimeState(runtime *sandboxruntime.RuntimeState) *sandboxruntime.RuntimeState {
	if runtime == nil {
		return nil
	}
	cloned := *runtime
	return &cloned
}
