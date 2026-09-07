package sandboxworker

import (
	"bytes"
	"context"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func (service *L8Service) handleMinimalLaunchCancel(ctx context.Context, principalID string, request Request) Response {
	if request.Validate() != nil || request.DriverID != RuntimeDriverMicroVM || request.JobCancelV2 == nil || !sandboxruntime.ValidMinimalLaunchID(request.JobCancelV2.JobID) {
		return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeMalformedRequest, "malformed worker minimal job cancel request")
	}
	entry := service.jobs.cancelMinimalLaunch(ctx, principalID, request.JobCancelV2.JobID)
	if entry != nil {
		// The caller may stop waiting, but cannot revive the reservation or
		// abandon the manager's independently joined provider handoff.
		select {
		case <-ctx.Done():
		case <-entry.dispatchDone:
		}
	}
	if response, canceled := contextErrorResponse(ctx, request); canceled {
		return response
	}
	// This slice has no terminal cleanup consumer, including after a successful
	// pending publication and joined Start. Never manufacture cancellation proof.
	return l8ServiceFailureResponse(request)
}

func (manager *jobManagerV2) cancelMinimalLaunch(ctx context.Context, principalID, jobID string) *minimalLaunchEntry {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !manager.minimal || manager.closed || ctx == nil || ctx.Err() != nil {
		return nil
	}
	state, found := manager.states[jobID]
	entry := manager.minimalLive[jobID]
	if !found || state.JobV2.ID != jobID || state.JobV2.WorkerID != manager.workerID || state.DaemonGeneration != manager.daemonGeneration || state.PrincipalID != principalID || !minimalLaunchCancelIdentityMatches(entry, state) {
		return nil
	}
	// Exact retained local ownership survives a failed Start or lost store.
	// Revocation never grants permission to mutate a successor path.
	entry.reservation.Revoke()
	attempted := entry.cancelAttempted
	entry.cancelAttempted = true
	if manager.store.checkMinimalAuthority(manager.stateLock) != nil {
		manager.minimalPoisoned = true
		return entry
	}
	actual, err := manager.store.readMinimalLaunchFile(jobID + ".json")
	want, wantErr := encodeStoredJobStateV2(state)
	got, gotErr := encodeStoredJobStateV2(actual)
	if err != nil || wantErr != nil || gotErr != nil || !bytes.Equal(want, got) {
		manager.minimalPoisoned = true
		return entry
	}
	if attempted {
		return entry // Join only; an uncertain publication is never retried.
	}
	if state.MinimalLaunch.Phase != "dispatching" || state.MinimalLaunch.Revision != 2 {
		manager.minimalPoisoned = true
		return entry
	}
	next := cloneStoredJobStateV2(state)
	next.MinimalLaunch.Phase, next.MinimalLaunch.Revision = "cleanup_pending", 3
	next.JobV2.CancelRequested = true
	if manager.store.save(next) != nil {
		manager.minimalPoisoned = true
		return entry
	}
	manager.states[jobID] = next // Only exact confirmed readback publishes pending memory state.
	return entry
}

// Compare the original live handles to every stored launch correlation, never
// ask a provider to resolve a replacement or treat these scalar IDs as authority.
func minimalLaunchCancelIdentityMatches(entry *minimalLaunchEntry, state storedJobStateV2) bool {
	if entry == nil || entry.reservation == nil || entry.selection == nil || entry.dispatchDone == nil || state.MinimalLaunch == nil || state.Validate() != nil {
		return false
	}
	m, job := state.MinimalLaunch, state.JobV2
	want := sandboxruntime.MinimalLaunchIdentity{
		WorkerJobID: job.ID, JobGeneration: m.JobGeneration, WorkerID: job.WorkerID, HostID: job.HostID, PrincipalID: state.PrincipalID,
		SandboxID: m.SandboxID, ExecutionID: m.ExecutionID, SubmissionID: m.SubmissionID, RuntimeID: job.RuntimeID, RuntimeGeneration: m.RuntimeGeneration,
		PlanID: job.CredentialIntent.PlanID, RequestKey: state.RequestKey, LaunchGrantID: m.LaunchGrantID, LaunchPolicyID: m.LaunchPolicyID, LaunchPolicyRevision: m.LaunchPolicyRevision,
	}
	selected := sandboxruntime.MinimalLaunchSelectionIdentity{WorkerID: job.WorkerID, HostID: job.HostID, RuntimeID: job.RuntimeID, RuntimeGeneration: m.RuntimeGeneration,
		PlanID: job.CredentialIntent.PlanID, TemplatePolicyID: job.CredentialIntent.TemplatePolicyID, WorkspacePolicyID: job.CredentialIntent.WorkspacePolicyID, NetworkPolicyID: m.NetworkPolicyID}
	return entry.reservation.Identity() == want && entry.selection.Identity() == selected
}
