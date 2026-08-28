package sandboxworker

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

var (
	ErrL8RecoveryDependency    = errors.New("worker L8 recovery dependency is required")
	errJobV2NotFound           = errors.New("worker v2 job not found")
	errJobV2SubmissionConflict = errors.New("worker v2 job submission identity conflicts with accepted request")
)

type jobManagerV2Options struct {
	StateDir         string
	WorkerID         string
	DaemonGeneration string
	Recovery         sandboxruntime.JobCredentialRuntimeRecoveryProvider
}

type jobManagerV2 struct {
	mu               sync.Mutex
	store            *jobStoreV2
	stateLock        *jobStateLock
	workerID         string
	daemonGeneration string
	states           map[string]storedJobStateV2
	submissions      map[string]string
	closed           bool
}

func newJobManagerV2(options jobManagerV2Options) (*jobManagerV2, error) {
	workerID := strings.TrimSpace(options.WorkerID)
	daemonGeneration := strings.TrimSpace(options.DaemonGeneration)
	if !validWorkerV2SafeID(workerID) || !validWorkerV2SafeID(daemonGeneration) {
		return nil, errors.New("worker v2 job manager identity is invalid")
	}
	store, err := newJobStoreV2(options.StateDir)
	if err != nil {
		return nil, err
	}
	stateLock, err := acquireJobStateLock(store.root)
	if err != nil {
		return nil, err
	}
	states, err := reconcileJobStoreV2AtStartupWithRecovery(store, time.Now().UTC(), options.Recovery)
	if err != nil {
		closeJobManagerV2StateLock(stateLock)
		return nil, err
	}
	manager := &jobManagerV2{
		store:            store,
		stateLock:        stateLock,
		workerID:         workerID,
		daemonGeneration: daemonGeneration,
		states:           make(map[string]storedJobStateV2, len(states)),
		submissions:      make(map[string]string, len(states)),
	}
	for _, state := range states {
		if state.JobV2.WorkerID != manager.workerID || state.DaemonGeneration != manager.daemonGeneration {
			manager.close()
			return nil, errors.New("worker v2 job state belongs to another service identity")
		}
		if existingID, exists := manager.submissions[state.JobV2.SubmissionKey]; exists && existingID != state.JobV2.ID {
			manager.close()
			return nil, errors.New("worker v2 job submission identity is duplicated")
		}
		manager.states[state.JobV2.ID] = cloneStoredJobStateV2(state)
		manager.submissions[state.JobV2.SubmissionKey] = state.JobV2.ID
	}
	return manager, nil
}

func closeJobManagerV2StateLock(stateLock *jobStateLock) {
	if stateLock != nil {
		_ = stateLock.Close()
	}
}

func (manager *jobManagerV2) close() {
	if manager == nil {
		return
	}
	manager.mu.Lock()
	manager.closed = true
	stateLock := manager.stateLock
	manager.stateLock = nil
	manager.mu.Unlock()
	closeJobManagerV2StateLock(stateLock)
}

func (manager *jobManagerV2) resolveAcceptedSubmission(driverID, principalID string, request JobStartRequestV2) (JobV2, bool, error) {
	if manager == nil || request.Validate() != nil {
		return JobV2{}, false, errors.New("worker v2 request identity is invalid")
	}
	requestKey, err := jobRequestKeyV2(strings.TrimSpace(driverID), strings.TrimSpace(principalID), manager.daemonGeneration, request)
	if err != nil {
		return JobV2{}, false, errors.New("worker v2 request identity is invalid")
	}
	submissionKey := jobSubmissionKeyV2(strings.TrimSpace(principalID), manager.daemonGeneration, request)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed || manager.stateLock == nil {
		return JobV2{}, false, errors.New("worker v2 job manager is closed")
	}
	existingID, exists := manager.submissions[submissionKey]
	if !exists {
		return JobV2{}, false, nil
	}
	existing, ok := manager.states[existingID]
	if !ok || existing.RequestKey != requestKey {
		return JobV2{}, false, errJobV2SubmissionConflict
	}
	return cloneJobV2(existing.JobV2), true, nil
}

func (manager *jobManagerV2) acceptCredentialSeed(driverID, principalID string, request JobStartRequestV2, seed sandboxruntime.JobCredentialIdentitySeed) (JobV2, bool, error) {
	driverID = strings.TrimSpace(driverID)
	principalID = strings.TrimSpace(principalID)
	if manager == nil || manager.store == nil || request.Validate() != nil || sandboxruntime.ValidateJobCredentialIdentitySeed(seed) != nil ||
		driverID != seed.RuntimeDriver || strings.TrimSpace(request.Exec.Target.Runtime.Driver) != driverID || principalID != seed.PrincipalID || manager.workerID != seed.WorkerID ||
		strings.TrimSpace(request.SubmissionID) != seed.SubmissionID || strings.TrimSpace(request.Exec.OperationID) != seed.ExecutionID || workerV2RequestSandboxID(request.Exec.Target) != seed.SandboxID ||
		strings.TrimSpace(request.Exec.Target.Runtime.RuntimeID) != seed.RuntimeID || strings.TrimSpace(request.PlanID) != seed.PlanID || strings.TrimSpace(request.AdmissionGrantID) != seed.AdmissionGrantID ||
		request.AdmissionGrantRevision != seed.AdmissionGrantRevision || strings.TrimSpace(request.TemplatePolicyID) != seed.TemplatePolicyID ||
		strings.TrimSpace(request.WorkspacePolicyID) != seed.WorkspacePolicyID || !storedJobCredentialBindingsExactV2(seed, request.credentialIntent()) {
		return JobV2{}, false, errors.New("worker v2 credential seed is invalid")
	}
	requestKey, err := jobRequestKeyV2(driverID, principalID, manager.daemonGeneration, request)
	if err != nil {
		return JobV2{}, false, errors.New("worker v2 request identity is invalid")
	}
	submissionKey := jobSubmissionKeyV2(principalID, manager.daemonGeneration, request)
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed || manager.stateLock == nil {
		return JobV2{}, false, errors.New("worker v2 job manager is closed")
	}
	if existingID, exists := manager.submissions[submissionKey]; exists {
		existing, ok := manager.states[existingID]
		if !ok || existing.RequestKey != requestKey {
			return JobV2{}, false, errJobV2SubmissionConflict
		}
		return cloneJobV2(existing.JobV2), true, nil
	}
	if _, exists := manager.states[seed.WorkerJobID]; exists {
		return JobV2{}, false, errors.New("worker v2 job identity is unavailable")
	}
	credentialState, err := newStoredJobCredentialStateV2(seed)
	if err != nil {
		return JobV2{}, false, err
	}
	job := JobV2{
		ContractVersion: JobContractVersionV2, ID: seed.WorkerJobID, SubmissionKey: submissionKey,
		WorkerID: seed.WorkerID, HostID: seed.HostID, RuntimeDriver: seed.RuntimeDriver, RuntimeID: seed.RuntimeID,
		State: JobStateQueued, SubmittedAt: seed.IssuedAt.UTC(), CredentialIntent: request.credentialIntent(),
	}
	state := storedJobStateV2{
		JobV2: job, RequestKey: requestKey, PrincipalID: principalID,
		DaemonGeneration: manager.daemonGeneration, CredentialState: credentialState,
	}
	if err := state.Validate(); err != nil {
		return JobV2{}, false, errors.New("worker v2 credential state is invalid")
	}
	if err := manager.store.save(state); err != nil {
		return JobV2{}, false, errors.New("worker v2 credential state could not be persisted")
	}
	manager.states[job.ID] = cloneStoredJobStateV2(state)
	manager.submissions[submissionKey] = job.ID
	return cloneJobV2(job), false, nil
}

func workerV2RequestSandboxID(target Target) string {
	if id := strings.TrimSpace(target.ID); id != "" {
		return id
	}
	return strings.TrimSpace(target.Name)
}

func (manager *jobManagerV2) persistCredentialIdentity(jobID, principalID string, identity sandboxruntime.JobCredentialIdentity) error {
	if manager == nil || manager.store == nil || sandboxruntime.ValidateJobCredentialIdentity(identity) != nil {
		return errors.New("worker v2 credential identity is invalid")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed || manager.stateLock == nil {
		return errors.New("worker v2 job manager is closed")
	}
	state, ok := manager.states[jobID]
	if !ok || state.PrincipalID != principalID || state.CredentialState == nil {
		return errJobV2NotFound
	}
	seed, err := state.CredentialState.Seed.runtimeSeed()
	if err != nil || sandboxruntime.ValidateJobCredentialIdentityCompletion(seed, identity) != nil {
		return errors.New("worker v2 credential identity is invalid")
	}
	if state.CredentialState.Identity != nil {
		current, currentErr := state.CredentialState.Identity.runtimeIdentity()
		currentDigest, currentDigestErr := sandboxruntime.JobCredentialIdentityDigest(current)
		identityDigest, identityDigestErr := sandboxruntime.JobCredentialIdentityDigest(identity)
		if currentErr != nil || currentDigestErr != nil || identityDigestErr != nil || currentDigest != identityDigest {
			return errors.New("worker v2 credential identity conflicts with durable state")
		}
		return nil
	}
	credentialState, err := state.CredentialState.withIdentity(identity)
	if err != nil {
		return err
	}
	state.CredentialState = credentialState
	if err := manager.store.save(state); err != nil {
		return errors.New("worker v2 credential identity could not be persisted")
	}
	manager.states[jobID] = cloneStoredJobStateV2(state)
	return nil
}

func (manager *jobManagerV2) status(jobID, principalID string) (JobV2, error) {
	if manager == nil {
		return JobV2{}, errJobV2NotFound
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed || manager.stateLock == nil {
		return JobV2{}, errJobV2NotFound
	}
	state, ok := manager.states[jobID]
	if !ok || state.PrincipalID != principalID {
		return JobV2{}, errJobV2NotFound
	}
	return cloneJobV2(state.JobV2), nil
}

func (manager *jobManagerV2) persistCredentialRevision(jobID, principalID string, revision uint64) error {
	if manager == nil || manager.store == nil || revision == 0 {
		return errors.New("worker v2 credential revision is invalid")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed || manager.stateLock == nil {
		return errors.New("worker v2 job manager is closed")
	}
	state, ok := manager.states[jobID]
	if !ok || state.PrincipalID != principalID || state.CredentialState == nil || state.CredentialState.Identity == nil {
		return errJobV2NotFound
	}
	cloned := cloneStoredJobCredentialStateV2(state.CredentialState)
	cloned.Revision = revision
	state.CredentialState = cloned
	if err := manager.store.save(state); err != nil {
		return errors.New("worker v2 credential revision could not be persisted")
	}
	manager.states[jobID] = cloneStoredJobStateV2(state)
	return nil
}

func (manager *jobManagerV2) clearCredentialState(jobID, principalID, jobState, failureCode string, finishedAt time.Time, cleanupProved bool) (JobV2, error) {
	if manager == nil || manager.store == nil || !validWorkerV2JobState(jobState) {
		return JobV2{}, errors.New("worker v2 credential state is invalid")
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.closed || manager.stateLock == nil {
		return JobV2{}, errors.New("worker v2 job manager is closed")
	}
	state, ok := manager.states[jobID]
	if !ok || state.PrincipalID != principalID {
		return JobV2{}, errJobV2NotFound
	}
	if !cleanupProved && (state.CredentialState != nil || state.CredentialRecoveryReceipt != nil) {
		return JobV2{}, ErrL8RecoveryDependency
	}
	state.CredentialState = nil
	state.CredentialRecoveryReceipt = nil
	state.JobV2.State = jobState
	if failureCode != "" {
		state.JobV2.FailureCode = failureCode
	}
	finished := finishedAt.UTC()
	state.JobV2.FinishedAt = &finished
	if jobState == JobStateCanceled {
		state.JobV2.CancelRequested = true
	}
	if err := state.Validate(); err != nil {
		return JobV2{}, errors.New("worker v2 credential state is invalid")
	}
	if err := manager.store.save(state); err != nil {
		return JobV2{}, errors.New("worker v2 credential state could not be cleared")
	}
	manager.states[jobID] = cloneStoredJobStateV2(state)
	return cloneJobV2(state.JobV2), nil
}

func recoverStoredJobCredentialsV2(store *jobStoreV2, state storedJobStateV2, recovery sandboxruntime.JobCredentialRuntimeRecoveryProvider, now time.Time) (recovered storedJobStateV2, resultErr error) {
	defer recoverStoredJobCredentialsV2Panic(&recovered, &resultErr)
	if store == nil || sandboxruntime.JobCredentialRuntimeInterfaceNil(recovery) {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	if state.CredentialState == nil && state.CredentialRecoveryReceipt == nil {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	storedSeed := storedJobCredentialIdentitySeedV1{}
	if state.CredentialState != nil {
		storedSeed = state.CredentialState.Seed
	} else {
		storedSeed = state.CredentialRecoveryReceipt.Seed
	}
	seed, err := storedSeed.runtimeSeed()
	if err != nil {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	ctx := context.Background()
	binding, err := bindJobCredentialRuntimeRecovery(recovery, ctx, seed)
	if err != nil || sandboxruntime.JobCredentialRuntimeInterfaceNil(binding) {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	defer closeJobCredentialRuntimeRecoveryBinding(binding, ctx)
	if state.CredentialRecoveryReceipt != nil {
		return replayStoredJobCredentialRuntimeRecoveryReceiptV2(store, state, binding, now)
	}
	if state.CredentialState.Identity != nil {
		identity, identityErr := state.CredentialState.Identity.runtimeIdentity()
		if identityErr == nil && sandboxruntime.ValidateJobCredentialIdentityCompletion(seed, identity) == nil {
			recoverJobCredentialsIgnoringFailure(binding, ctx, sandboxruntime.JobCredentialRecoveryRequest{
				Identity: identity,
				Revision: state.CredentialState.Revision,
			})
		}
	}
	proof, err := binding.StopReapJobCredentialRuntime(ctx)
	if err != nil {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	if err := sandboxruntime.ValidateJobCredentialRuntimeAbsenceProof(proof, seed, now); err != nil {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	receipt, err := binding.FinalizeJobCredentialRuntimeRecovery(ctx, proof)
	if err != nil {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	if err := sandboxruntime.ValidateJobCredentialRuntimeRecoveryCommitReceipt(receipt); err != nil {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	storedReceipt, err := storedJobCredentialRuntimeRecoveryReceiptV1FromRuntime(state.CredentialState.Seed, receipt)
	if err != nil {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	state.CredentialState = nil
	state.CredentialRecoveryReceipt = &storedReceipt
	if err := store.save(state); err != nil {
		return storedJobStateV2{}, err
	}
	if err := binding.CommitJobCredentialRuntimeRecovery(ctx, receipt); err != nil {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	state.CredentialRecoveryReceipt = nil
	finishedAt := now.UTC()
	state.JobV2.State = JobStateInterrupted
	state.JobV2.FailureCode = "daemon_restarted_before_start"
	state.JobV2.FinishedAt = &finishedAt
	if err := store.save(state); err != nil {
		return storedJobStateV2{}, err
	}
	return cloneStoredJobStateV2(state), nil
}

func recoverStoredJobCredentialsV2Panic(recovered *storedJobStateV2, resultErr *error) {
	if recover() == nil || recovered == nil || resultErr == nil {
		return
	}
	*recovered = storedJobStateV2{}
	*resultErr = ErrL8RecoveryDependency
}

func replayStoredJobCredentialRuntimeRecoveryReceiptV2(store *jobStoreV2, state storedJobStateV2, binding sandboxruntime.JobCredentialRuntimeRecoveryBinding, now time.Time) (storedJobStateV2, error) {
	receipt, err := storedJobCredentialRuntimeRecoveryReceiptV1ToRuntime(*state.CredentialRecoveryReceipt)
	if err != nil {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	if err := binding.CommitJobCredentialRuntimeRecovery(context.Background(), receipt); err != nil {
		return storedJobStateV2{}, ErrL8RecoveryDependency
	}
	state.CredentialRecoveryReceipt = nil
	finishedAt := now.UTC()
	state.JobV2.State = JobStateInterrupted
	state.JobV2.FailureCode = "daemon_restarted_before_start"
	state.JobV2.FinishedAt = &finishedAt
	if err := store.save(state); err != nil {
		return storedJobStateV2{}, err
	}
	return cloneStoredJobStateV2(state), nil
}

func bindJobCredentialRuntimeRecovery(recovery sandboxruntime.JobCredentialRuntimeRecoveryProvider, ctx context.Context, seed sandboxruntime.JobCredentialIdentitySeed) (binding sandboxruntime.JobCredentialRuntimeRecoveryBinding, err error) {
	defer recoverJobCredentialRuntimeBindPanic(&binding, &err)
	return recovery.BindJobCredentialRuntimeRecovery(ctx, seed)
}

func recoverJobCredentialRuntimeBindPanic(binding *sandboxruntime.JobCredentialRuntimeRecoveryBinding, err *error) {
	if recover() == nil || binding == nil || err == nil {
		return
	}
	*binding = nil
	*err = ErrL8RecoveryDependency
}

func recoverJobCredentialsIgnoringFailure(binding sandboxruntime.JobCredentialRuntimeRecoveryBinding, ctx context.Context, request sandboxruntime.JobCredentialRecoveryRequest) {
	defer recoverJobCredentialRuntimeIgnoredPanic()
	_, _ = binding.RecoverJobCredentials(ctx, request)
}

func recoverJobCredentialRuntimeIgnoredPanic() {
	_ = recover()
}

func closeJobCredentialRuntimeRecoveryBinding(binding sandboxruntime.JobCredentialRuntimeRecoveryBinding, ctx context.Context) {
	if sandboxruntime.JobCredentialRuntimeInterfaceNil(binding) {
		return
	}
	_ = binding.Close(ctx)
}
