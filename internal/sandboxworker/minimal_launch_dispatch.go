package sandboxworker

import (
	"context"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

type minimalLaunchEntry struct {
	reservation *sandboxruntime.MinimalLaunchReservation
	selection   *sandboxruntime.MinimalLaunchPreparedSelection
	owner       *sandboxruntime.MinimalLaunchOwnerBinding
}

func (service *L8Service) handleMinimalLaunch(ctx context.Context, principal sandboxruntime.AuthenticatedWorkerPrincipal, principalID string, request Request) Response {
	if request.Operation != OperationJobStartV2 || request.JobStartV2 == nil || !request.JobStartV2.ProductionCredentialsRequested {
		return unsupportedOperationResponse(request)
	}
	if request.Validate() != nil || request.DriverID != RuntimeDriverMicroVM || request.JobStartV2.Exec.Target.Runtime.Driver != RuntimeDriverMicroVM {
		return protocolErrorResponse(request.RequestID, request.Operation, ErrorCodeMalformedRequest, "malformed worker minimal job start request")
	}
	start := cloneJobStartRequestV2(*request.JobStartV2)
	key, err := jobRequestKeyV2(request.DriverID, principalID, service.daemonGeneration, start)
	if err != nil {
		return l8ServiceFailureResponse(request)
	}
	if job, found, err := service.jobs.resolveMinimalSubmission(principalID, start.SubmissionID, key); err != nil {
		return l8ServiceFailureResponse(request)
	} else if found {
		return l8JobV2SuccessResponse(request, job)
	}
	started := time.Now().UTC()
	deadline := started.Add(service.minimalLaunch.PreparationTimeout)
	preparation, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	hints := sandboxruntime.MinimalLaunchSelectionHints{SandboxID: workerV2RequestSandboxID(start.Exec.Target), ExecutionID: start.Exec.OperationID, SubmissionID: start.SubmissionID,
		RuntimeID: start.Exec.Target.Runtime.RuntimeID, PlanID: start.PlanID, TemplatePolicyID: start.TemplatePolicyID, WorkspacePolicyID: start.WorkspacePolicyID}
	selection, err := service.minimalLaunch.Authorizer.ResolveSelection(preparation, principal, service.workerID, hints)
	if err != nil || selection == nil {
		return l8ServiceFailureResponse(request)
	}
	entry, job, retained, err := service.jobs.reserveMinimalLaunch(preparation, principalID, key, start, selection, started, deadline)
	if !retained {
		_ = selection.Close()
	}
	if err != nil {
		return l8ServiceFailureResponse(request)
	}
	if entry == nil {
		return l8JobV2SuccessResponse(request, job)
	}
	owner, startErr := service.minimalLaunch.Provider.Start(entry.reservation, entry.selection)
	service.jobs.finishMinimalDispatch(entry, owner, startErr)
	// This initial reachable boundary has no credential/workload result
	// consumer. Keep exact ownership, but do not manufacture worker success.
	return l8ServiceFailureResponse(request)
}

func (manager *jobManagerV2) resolveMinimalSubmission(principalID, submissionID, requestKey string) (JobV2, bool, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !manager.minimal || manager.closed || manager.minimalPoisoned || manager.stateLock == nil {
		return JobV2{}, false, errMinimalLaunchState
	}
	return manager.findMinimalSubmissionLocked(principalID, submissionID, requestKey)
}

func (manager *jobManagerV2) findMinimalSubmissionLocked(principalID, submissionID, requestKey string) (JobV2, bool, error) {
	for _, state := range manager.states {
		if state.MinimalLaunch != nil && state.PrincipalID == principalID && state.DaemonGeneration == manager.daemonGeneration && state.MinimalLaunch.SubmissionID == submissionID {
			if state.RequestKey != requestKey {
				return JobV2{}, false, errJobV2SubmissionConflict
			}
			return cloneJobV2(state.JobV2), true, nil
		}
	}
	return JobV2{}, false, nil
}

func (manager *jobManagerV2) reserveMinimalLaunch(ctx context.Context, principalID, requestKey string, request JobStartRequestV2, selection *sandboxruntime.MinimalLaunchPreparedSelection, started, deadline time.Time) (*minimalLaunchEntry, JobV2, bool, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !manager.minimal || manager.closed || manager.minimalPoisoned || manager.stateLock == nil || ctx == nil || ctx.Err() != nil || selection == nil {
		return nil, JobV2{}, false, errMinimalLaunchState
	}
	if job, found, err := manager.findMinimalSubmissionLocked(principalID, request.SubmissionID, requestKey); found || err != nil {
		return nil, job, false, err
	}
	selected := selection.Identity()
	for _, state := range manager.states {
		if state.MinimalLaunch != nil && state.JobV2.WorkerID == selected.WorkerID && state.JobV2.HostID == selected.HostID && state.JobV2.RuntimeDriver == RuntimeDriverMicroVM && state.JobV2.RuntimeID == selected.RuntimeID {
			return nil, JobV2{}, false, errMinimalLaunchState
		}
	}
	jobID, err := newOpaqueJobID()
	if err != nil {
		return nil, JobV2{}, false, errMinimalLaunchState
	}
	generation, err := newOpaqueJobID()
	if err != nil || jobID == generation {
		return nil, JobV2{}, false, errMinimalLaunchState
	}
	if _, exists := manager.states[jobID]; exists {
		return nil, JobV2{}, false, errMinimalLaunchState
	}
	reservation, err := selection.Reserve(ctx, jobID, generation, requestKey, deadline)
	if err != nil {
		return nil, JobV2{}, false, errMinimalLaunchState
	}
	identity := reservation.Identity()
	if identity.PrincipalID != principalID || identity.WorkerID != manager.workerID || identity.SubmissionID != request.SubmissionID {
		reservation.Revoke()
		return nil, JobV2{}, false, errMinimalLaunchState
	}
	job := JobV2{ContractVersion: JobContractVersionV2, ID: jobID, SubmissionKey: jobSubmissionKeyV2(principalID, manager.daemonGeneration, request), WorkerID: identity.WorkerID, HostID: identity.HostID,
		RuntimeDriver: RuntimeDriverMicroVM, RuntimeID: identity.RuntimeID, State: JobStateQueued, SubmittedAt: started, CredentialIntent: request.credentialIntent()}
	state := storedJobStateV2{JobV2: job, RequestKey: requestKey, PrincipalID: principalID, DaemonGeneration: manager.daemonGeneration, MinimalLaunch: &storedMinimalLaunchV1{
		ContractVersion: minimalLaunchPrivateVersion, Revision: 1, Phase: "reserved", JobGeneration: generation, SandboxID: identity.SandboxID, ExecutionID: identity.ExecutionID,
		SubmissionID: identity.SubmissionID, RuntimeGeneration: identity.RuntimeGeneration, LaunchGrantID: identity.LaunchGrantID, LaunchPolicyID: identity.LaunchPolicyID, LaunchPolicyRevision: identity.LaunchPolicyRevision,
		NetworkPolicyID: selected.NetworkPolicyID, PreparationStartedAt: started, PreparationDeadline: deadline,
	}}
	if state.Validate() != nil || ctx.Err() != nil {
		reservation.Revoke()
		return nil, JobV2{}, false, errMinimalLaunchState
	}
	entry := &minimalLaunchEntry{reservation: reservation, selection: selection}
	// Install pending ownership before IO. A save error may be after publish;
	// never roll this entry back or release it as though no dispatch occurred.
	manager.minimalLive[jobID] = entry
	manager.states[jobID] = cloneStoredJobStateV2(state)
	manager.submissions[job.SubmissionKey] = jobID
	poison := func() (*minimalLaunchEntry, JobV2, bool, error) {
		manager.minimalPoisoned = true
		reservation.Revoke()
		return nil, JobV2{}, true, errMinimalLaunchState
	}
	if manager.store.save(state) != nil {
		return poison()
	}
	// Client context no longer owns cancellation after durable acceptance.
	if reservation.Context().Err() != nil {
		return poison()
	}
	state.MinimalLaunch.Phase, state.MinimalLaunch.Revision = "dispatching", 2
	manager.states[jobID] = cloneStoredJobStateV2(state)
	if manager.store.save(state) != nil || reservation.ArmDispatch(reservation.Context(), identity) != nil {
		return poison()
	}
	manager.minimalActive.Add(1)
	return entry, job, true, nil
}

func (manager *jobManagerV2) finishMinimalDispatch(entry *minimalLaunchEntry, owner *sandboxruntime.MinimalLaunchOwnerBinding, startErr error) {
	manager.mu.Lock()
	entry.owner = owner // retain partial ownership before interpreting its error
	if startErr != nil || owner == nil {
		manager.minimalPoisoned = true
		entry.reservation.Revoke()
	}
	manager.mu.Unlock()
	manager.minimalActive.Done()
}

func (manager *jobManagerV2) closeMinimalLaunch() {
	manager.mu.Lock()
	manager.closed = true
	for _, entry := range manager.minimalLive {
		entry.reservation.Revoke()
	}
	manager.mu.Unlock()
	// No manager lock across provider completion. Keep the process-shared lock
	// until every entered callback has returned and ownership is retained.
	manager.minimalActive.Wait()
	manager.mu.Lock()
	stateLock := manager.stateLock
	manager.stateLock = nil
	manager.mu.Unlock()
	closeJobManagerV2StateLock(stateLock)
	// Pending owners/selections and durable records are deliberately retained.
	// Exact terminal cleanup and cleanup-only recovery are the next boundary.
}
