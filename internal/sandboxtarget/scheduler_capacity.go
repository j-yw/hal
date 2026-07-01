package sandboxtarget

import (
	"fmt"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func selectSchedulerCandidateWithCapacity(req SchedulerRequest, candidateSet SchedulerCandidateSet, cache CachedState) SchedulerResult {
	if candidateSet.Failed() {
		return SchedulerResult{Rejection: candidateSet.Rejection}
	}
	if candidateSet.Empty() {
		return SchedulerResult{Rejection: schedulerRejection(req, FailureReasonHostNotFound, "no cached sandbox hosts")}
	}

	if !schedulerCandidateSetHasUsableCapacity(candidateSet) {
		return schedulerCapacityUnavailableResult(req, "no cached sandbox hosts have usable capacity metadata")
	}
	if cache.ListLeases == nil {
		return schedulerCapacityUnavailableResult(req, "cached lease lister is required")
	}
	if cache.Now == nil {
		return schedulerCapacityUnavailableResult(req, "scheduler clock is required")
	}

	leases, err := cache.ListLeases()
	if err != nil {
		return schedulerCapacityUnavailableResult(req, "list cached sandbox leases failed")
	}
	now := cache.Now()

	var firstBlocked *schedulerCapacityEvaluation
	for _, candidate := range candidateSet.Candidates {
		evaluation := schedulerEvaluateCandidateCapacity(candidate, leases, now)
		if !evaluation.Decision.Known {
			continue
		}
		if evaluation.Decision.Allowed {
			return schedulerSelectedCapacityResult(req, evaluation)
		}
		if firstBlocked == nil {
			copied := evaluation
			firstBlocked = &copied
		}
	}
	if firstBlocked != nil {
		message := "no cached sandbox hosts have available capacity"
		if hostID := strings.TrimSpace(req.HostID); hostID != "" {
			message = fmt.Sprintf("host %q has no available cached capacity", hostID)
		}
		return SchedulerResult{
			Capacity:  firstBlocked.Decision,
			Rejection: schedulerRejection(req, FailureReasonCapacityBlocked, message),
		}
	}
	return schedulerCapacityUnavailableResult(req, "no cached sandbox hosts have usable capacity metadata")
}

type schedulerCapacityEvaluation struct {
	Candidate   SchedulerCandidate
	Decision    SchedulerCapacityDecision
	ResourceKey string
}

func schedulerSelectedCapacityResult(req SchedulerRequest, evaluation schedulerCapacityEvaluation) SchedulerResult {
	candidate := evaluation.Candidate
	return SchedulerResult{
		Selection: &SchedulerSelection{
			Identity: candidate.Identity,
			Host:     cloneSandboxHost(candidate.Host),
			Runtime:  cloneRuntimeState(candidate.Runtime),
		},
		DecisionReason: SchedulerDecisionReasonRankedCandidate,
		Capacity:       evaluation.Decision,
		Lease: SchedulerLeaseRequirement{
			Required:    true,
			ResourceKey: evaluation.ResourceKey,
			Purpose:     req.Purpose,
		},
	}
}

func schedulerCandidateSetHasUsableCapacity(candidateSet SchedulerCandidateSet) bool {
	for _, candidate := range candidateSet.Candidates {
		if maxConcurrent, ok := schedulerCandidateCapacityLimit(candidate); ok && maxConcurrent > 0 && schedulerCandidateHostResourceKey(candidate) != "" {
			return true
		}
	}
	return false
}

func schedulerEvaluateCandidateCapacity(candidate SchedulerCandidate, leases []*sandbox.SandboxLease, now time.Time) schedulerCapacityEvaluation {
	maxConcurrent, ok := schedulerCandidateCapacityLimit(candidate)
	if !ok || maxConcurrent <= 0 {
		return schedulerCapacityEvaluation{
			Candidate: candidate,
			Decision:  schedulerCapacityUnavailableDecision(),
		}
	}
	resourceKey := schedulerCandidateHostResourceKey(candidate)
	if resourceKey == "" {
		return schedulerCapacityEvaluation{
			Candidate: candidate,
			Decision:  schedulerCapacityUnavailableDecision(),
		}
	}

	activeLeases := schedulerActiveLeaseCount(resourceKey, leases, now)
	availableSlots := maxConcurrent - activeLeases
	if availableSlots < 0 {
		availableSlots = 0
	}
	allowed := activeLeases < maxConcurrent
	reason := SchedulerDecisionReasonCapacityBlocked
	if allowed {
		reason = SchedulerDecisionReasonCapacityAvailable
	}

	return schedulerCapacityEvaluation{
		Candidate:   candidate,
		ResourceKey: resourceKey,
		Decision: SchedulerCapacityDecision{
			Known:                  true,
			Allowed:                allowed,
			MaxConcurrentSandboxes: maxConcurrent,
			ActiveLeases:           activeLeases,
			AvailableSlots:         availableSlots,
			Reason:                 reason,
		},
	}
}

func schedulerCandidateCapacityLimit(candidate SchedulerCandidate) (int, bool) {
	if candidate.Host == nil || candidate.Host.Capacity == nil {
		return 0, false
	}
	return candidate.Host.Capacity.MaxConcurrentSandboxes, true
}

func schedulerCandidateHostResourceKey(candidate SchedulerCandidate) string {
	hostID := strings.TrimSpace(candidate.Identity.HostID)
	if hostID == "" && candidate.Host != nil {
		hostID = strings.TrimSpace(candidate.Host.ID)
	}
	if hostID == "" {
		return ""
	}
	return "host:" + hostID
}

func schedulerActiveLeaseCount(resourceKey string, leases []*sandbox.SandboxLease, now time.Time) int {
	resourceKey = strings.TrimSpace(resourceKey)
	if resourceKey == "" {
		return 0
	}

	count := 0
	for _, lease := range leases {
		if lease == nil {
			continue
		}
		if strings.TrimSpace(lease.ResourceKey) != resourceKey {
			continue
		}
		if strings.TrimSpace(lease.Status) != sandbox.SandboxLeaseStatusActive {
			continue
		}
		if !lease.ExpiresAt.After(now) {
			continue
		}
		count++
	}
	return count
}

func schedulerCapacityUnavailableResult(req SchedulerRequest, message string) SchedulerResult {
	return SchedulerResult{
		Capacity:  schedulerCapacityUnavailableDecision(),
		Rejection: schedulerRejection(req, FailureReasonCapacityUnavailable, message),
	}
}

func schedulerCapacityUnavailableDecision() SchedulerCapacityDecision {
	return SchedulerCapacityDecision{
		ConservativeUnavailable: true,
		Reason:                  SchedulerDecisionReasonCapacityUnavailable,
	}
}
