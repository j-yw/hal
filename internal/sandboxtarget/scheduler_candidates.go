package sandboxtarget

import (
	"fmt"
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
// Later scheduler phases add health, capacity, lease, and ranking behavior
// between candidate enumeration and the final selection.
func Schedule(req SchedulerRequest, cache CachedState) SchedulerResult {
	if rejection := validateSchedulerRequestedIsolation(req); rejection != nil {
		return SchedulerResult{Rejection: rejection}
	}
	if rejection := validateSchedulerRequestedRuntimeIsolation(req); rejection != nil {
		return SchedulerResult{Rejection: rejection}
	}

	candidateSet := EnumerateSchedulerCandidates(req, cache)
	candidateSet = filterSchedulerCandidatesByRuntimeAndIsolation(req, candidateSet)
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

func filterSchedulerCandidatesByRuntimeAndIsolation(req SchedulerRequest, candidateSet SchedulerCandidateSet) SchedulerCandidateSet {
	if candidateSet.Failed() || candidateSet.Empty() || (!req.HasRuntimeConstraint() && !req.HasIsolationConstraint()) {
		return candidateSet
	}
	if rejection := validateSchedulerRequestedIsolation(req); rejection != nil {
		return SchedulerCandidateSet{Rejection: rejection}
	}
	if rejection := validateSchedulerRequestedRuntimeIsolation(req); rejection != nil {
		return SchedulerCandidateSet{Rejection: rejection}
	}

	filtered := make([]SchedulerCandidate, 0, len(candidateSet.Candidates))
	matchedRequestedRuntime := false
	for _, candidate := range candidateSet.Candidates {
		runtime := schedulerCandidateRuntimeForRequest(req, candidate)
		if req.HasRuntimeConstraint() {
			if runtime == nil {
				continue
			}
			matchedRequestedRuntime = true
		}
		if req.HasIsolationConstraint() {
			if runtime == nil {
				runtime = schedulerCandidateRuntimeForIsolation(candidate, strings.TrimSpace(req.IsolationLevel))
			}
			if runtime == nil || !runtimeSatisfiesIsolation(*runtime, req.IsolationLevel) {
				continue
			}
		}
		filtered = append(filtered, schedulerCandidateWithRuntime(candidate, runtime))
	}
	if len(filtered) > 0 {
		return SchedulerCandidateSet{Candidates: filtered}
	}

	if req.HasRuntimeConstraint() && !matchedRequestedRuntime {
		runtimeDriver := strings.TrimSpace(req.RuntimeDriver)
		return SchedulerCandidateSet{Rejection: schedulerRejection(req, FailureReasonRuntimeUnsupported, fmt.Sprintf("no durable host supports requested runtime %q", runtimeDriver))}
	}
	if req.HasIsolationConstraint() {
		isolationLevel := strings.TrimSpace(req.IsolationLevel)
		return SchedulerCandidateSet{Rejection: schedulerRejection(req, FailureReasonIsolationUnavailable, fmt.Sprintf("no durable host supports requested isolation %q", isolationLevel))}
	}
	return SchedulerCandidateSet{Rejection: schedulerRejection(req, FailureReasonHostNotFound, "no cached sandbox hosts")}
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

func schedulerCandidateWithRuntime(candidate SchedulerCandidate, runtime *sandboxruntime.RuntimeState) SchedulerCandidate {
	candidate.Host = cloneSandboxHost(candidate.Host)
	if candidate.Identity.HostID == "" && candidate.Host != nil {
		candidate.Identity = SchedulerTargetIdentity{
			HostID:   strings.TrimSpace(candidate.Host.ID),
			HostName: strings.TrimSpace(candidate.Host.Name),
			HostKind: strings.TrimSpace(candidate.Host.Kind),
		}
	}
	candidate.Runtime = cloneRuntimeState(runtime)
	if candidate.Runtime != nil {
		candidate.Identity.RuntimeDriver = strings.TrimSpace(candidate.Runtime.Driver)
		candidate.Identity.RuntimeID = strings.TrimSpace(candidate.Runtime.RuntimeID)
		candidate.Identity.IsolationLevel = selectedRuntimeIsolation(*candidate.Runtime)
	}
	return candidate
}

func schedulerCandidateRuntimeForRequest(req SchedulerRequest, candidate SchedulerCandidate) *sandboxruntime.RuntimeState {
	if !req.HasRuntimeConstraint() {
		return nil
	}
	runtimeDriver := strings.TrimSpace(req.RuntimeDriver)
	if !hostSupportsRuntime(candidate.Host, runtimeDriver) {
		return nil
	}
	return schedulerCandidateRuntimeForDriver(candidate, runtimeDriver)
}

func schedulerCandidateRuntimeForIsolation(candidate SchedulerCandidate, isolationLevel string) *sandboxruntime.RuntimeState {
	if candidate.Host == nil {
		return nil
	}
	for _, runtimeDriver := range orderedRuntimeDrivers(candidate.Host.SupportedRuntimes) {
		runtime := schedulerCandidateRuntimeForDriver(candidate, runtimeDriver)
		if runtime != nil && runtimeSatisfiesIsolation(*runtime, isolationLevel) {
			return runtime
		}
	}
	return nil
}

func schedulerCandidateRuntimeForDriver(candidate SchedulerCandidate, runtimeDriver string) *sandboxruntime.RuntimeState {
	runtime := runtimeStateForDriver(runtimeDriver)
	if runtime == nil {
		return nil
	}
	if candidate.Runtime != nil && strings.TrimSpace(candidate.Runtime.Driver) == strings.TrimSpace(runtimeDriver) {
		merged := mergeRuntimeState(runtime, candidate.Runtime)
		return &merged
	}
	return runtime
}

func validateSchedulerRequestedIsolation(req SchedulerRequest) *SchedulerRejection {
	if !req.HasIsolationConstraint() {
		return nil
	}
	isolationLevel := strings.TrimSpace(req.IsolationLevel)
	if isRecognizedIsolationLevel(isolationLevel) {
		return nil
	}
	return schedulerRejection(req, FailureReasonIsolationUnavailable, fmt.Sprintf("requested isolation %q is not supported", isolationLevel))
}

func validateSchedulerRequestedRuntimeIsolation(req SchedulerRequest) *SchedulerRejection {
	if !req.HasRuntimeConstraint() || !req.HasIsolationConstraint() {
		return nil
	}
	runtimeDriver := strings.TrimSpace(req.RuntimeDriver)
	isolationLevel := strings.TrimSpace(req.IsolationLevel)
	runtime := runtimeStateForDriver(runtimeDriver)
	if runtime == nil || runtimeSatisfiesIsolation(*runtime, isolationLevel) {
		return nil
	}
	return schedulerRejection(req, FailureReasonIsolationUnavailable, fmt.Sprintf("requested runtime %q provides isolation %q, not requested isolation %q", runtimeDriver, selectedRuntimeIsolation(*runtime), isolationLevel))
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
