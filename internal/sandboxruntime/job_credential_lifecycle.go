package sandboxruntime

import (
	"sync"
	"time"
)

type jobCredentialLifecycleTransition uint8

const (
	jobCredentialLifecycleTransitionRenew jobCredentialLifecycleTransition = iota + 1
	jobCredentialLifecycleTransitionRevoke
	jobCredentialLifecycleTransitionObserveLoss
	jobCredentialLifecycleTransitionBeginRevoke
)

type jobCredentialLifecycleOptions struct {
	beforeCommit func(jobCredentialLifecycleTransition)
}

type JobCredentialLifecycle struct {
	mu           sync.Mutex
	identity     JobCredentialIdentity
	state        JobCredentialState
	revision     uint64
	activeProof  JobCredentialActiveProof
	cleanupProof JobCredentialCleanupProof
	version      uint64
	beforeCommit func(jobCredentialLifecycleTransition)
}

func NewJobCredentialLifecycle(identity JobCredentialIdentity) (*JobCredentialLifecycle, error) {
	return newJobCredentialLifecycleWithOptions(identity, jobCredentialLifecycleOptions{})
}

func newJobCredentialLifecycleWithOptions(identity JobCredentialIdentity, options jobCredentialLifecycleOptions) (*JobCredentialLifecycle, error) {
	if !validJobCredentialIdentity(identity) {
		return nil, ErrJobCredentialIdentityMismatch
	}
	return &JobCredentialLifecycle{
		identity:     cloneJobCredentialIdentity(identity),
		beforeCommit: options.beforeCommit,
	}, nil
}

func (lifecycle *JobCredentialLifecycle) BeginPrepare(identity JobCredentialIdentity) error {
	if lifecycle == nil {
		return ErrJobCredentialTransition
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if !validJobCredentialIdentity(identity) || !sameJobCredentialIdentity(lifecycle.identity, identity) {
		return ErrJobCredentialIdentityMismatch
	}
	switch lifecycle.state {
	case "":
		lifecycle.state = JobCredentialStatePreparing
		lifecycle.version++
		return nil
	case JobCredentialStatePreparing:
		return nil
	default:
		return ErrJobCredentialTransition
	}
}

func (lifecycle *JobCredentialLifecycle) Activate(proof JobCredentialActiveProof) error {
	if lifecycle == nil {
		return ErrJobCredentialTransition
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.state == JobCredentialStateActive && sameJobCredentialActiveProof(lifecycle.activeProof, proof) {
		return nil
	}
	if lifecycle.state == JobCredentialStateActive {
		var err error
		if !validJobCredentialActiveProof(proof) {
			err = ErrJobCredentialProofInvalid
		} else if proof.identityDigest() != jobCredentialIdentityDigest(lifecycle.identity) {
			err = ErrJobCredentialIdentityMismatch
		} else {
			err = ErrJobCredentialReplayRejected
		}
		lifecycle.enterRevokingLocked()
		return err
	}
	if lifecycle.state != JobCredentialStatePreparing {
		return ErrJobCredentialTransition
	}
	if !validJobCredentialActiveProof(proof) {
		lifecycle.enterRevokingLocked()
		return ErrJobCredentialProofInvalid
	}
	if err := lifecycle.validateActiveCandidateLocked(proof, proof.revision()); err != nil {
		lifecycle.enterRevokingLocked()
		return err
	}
	lifecycle.activeProof = proof
	lifecycle.cleanupProof = JobCredentialCleanupProof{}
	lifecycle.revision = proof.revision()
	lifecycle.state = JobCredentialStateActive
	lifecycle.version++
	return nil
}

func (lifecycle *JobCredentialLifecycle) BeginRenew() error {
	if lifecycle == nil {
		return ErrJobCredentialTransition
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	switch lifecycle.state {
	case JobCredentialStateActive:
		lifecycle.state = JobCredentialStateRenewing
		lifecycle.version++
		return nil
	case JobCredentialStateExpired:
		return ErrJobCredentialExpired
	default:
		return ErrJobCredentialTransition
	}
}

func (lifecycle *JobCredentialLifecycle) Renew(proof JobCredentialActiveProof) error {
	if lifecycle == nil {
		return ErrJobCredentialTransition
	}
	lifecycle.mu.Lock()
	if lifecycle.state != JobCredentialStateRenewing {
		lifecycle.mu.Unlock()
		return ErrJobCredentialTransition
	}
	if sameJobCredentialActiveProof(lifecycle.activeProof, proof) {
		lifecycle.enterRevokingLocked()
		lifecycle.mu.Unlock()
		return ErrJobCredentialReplayRejected
	}
	if err := lifecycle.validateActiveCandidateLocked(proof, lifecycle.revision+1); err != nil {
		lifecycle.enterRevokingLocked()
		lifecycle.mu.Unlock()
		return err
	}
	previousIssuedAt, previousExpiresAt := lifecycle.activeProof.times()
	issuedAt, expiresAt := proof.times()
	if !issuedAt.After(previousIssuedAt) || !expiresAt.After(previousExpiresAt) {
		lifecycle.enterRevokingLocked()
		lifecycle.mu.Unlock()
		return ErrJobCredentialRevisionStale
	}
	version := lifecycle.version
	hook := lifecycle.beforeCommit
	lifecycle.mu.Unlock()

	if hook != nil {
		hook(jobCredentialLifecycleTransitionRenew)
	}

	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.version != version || lifecycle.state != JobCredentialStateRenewing {
		if lifecycle.state == JobCredentialStateActive && sameJobCredentialActiveProof(lifecycle.activeProof, proof) {
			return nil
		}
		if lifecycle.state == JobCredentialStateExpired {
			return ErrJobCredentialExpired
		}
		return ErrJobCredentialTransition
	}
	if err := lifecycle.validateActiveCandidateLocked(proof, lifecycle.revision+1); err != nil {
		lifecycle.enterRevokingLocked()
		return err
	}
	previousIssuedAt, previousExpiresAt = lifecycle.activeProof.times()
	issuedAt, expiresAt = proof.times()
	if !issuedAt.After(previousIssuedAt) || !expiresAt.After(previousExpiresAt) {
		lifecycle.enterRevokingLocked()
		return ErrJobCredentialRevisionStale
	}
	lifecycle.activeProof = proof
	lifecycle.revision = proof.revision()
	lifecycle.state = JobCredentialStateActive
	lifecycle.version++
	return nil
}

func (lifecycle *JobCredentialLifecycle) Expire(observedAt time.Time) error {
	if lifecycle == nil {
		return ErrJobCredentialTransition
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.state == JobCredentialStateExpired {
		return nil
	}
	if lifecycle.state != JobCredentialStateActive {
		return ErrJobCredentialTransition
	}
	if err := ValidateJobCredentialActiveProof(lifecycle.activeProof, lifecycle.identity, lifecycle.revision, observedAt); err != ErrJobCredentialExpired {
		return ErrJobCredentialTransition
	}
	lifecycle.activeProof = JobCredentialActiveProof{}
	lifecycle.state = JobCredentialStateExpired
	lifecycle.version++
	return nil
}

func (lifecycle *JobCredentialLifecycle) BeginRevoke() error {
	if lifecycle == nil {
		return ErrJobCredentialTransition
	}
	lifecycle.mu.Lock()
	switch lifecycle.state {
	case JobCredentialStateRevoking, JobCredentialStateCleanupIncomplete, JobCredentialStateRevoked:
		lifecycle.mu.Unlock()
		return nil
	case JobCredentialStatePreparing, JobCredentialStateActive, JobCredentialStateRenewing, JobCredentialStateExpired:
	default:
		lifecycle.mu.Unlock()
		return ErrJobCredentialTransition
	}
	version := lifecycle.version
	hook := lifecycle.beforeCommit
	lifecycle.mu.Unlock()

	if hook != nil {
		hook(jobCredentialLifecycleTransitionBeginRevoke)
	}

	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.version != version {
		switch lifecycle.state {
		case JobCredentialStateRevoking, JobCredentialStateCleanupIncomplete, JobCredentialStateRevoked:
			return nil
		default:
			return ErrJobCredentialTransition
		}
	}
	lifecycle.enterRevokingLocked()
	return nil
}

func (lifecycle *JobCredentialLifecycle) ObserveLoss(loss JobCredentialLoss) error {
	if lifecycle == nil {
		return ErrJobCredentialTransition
	}
	lifecycle.mu.Lock()
	if lifecycle.state == JobCredentialStateRevoked {
		lifecycle.mu.Unlock()
		return nil
	}
	expectedRevision := lifecycle.revision
	if expectedRevision == 0 {
		expectedRevision = 1
	}
	var validationErr error
	if !validJobCredentialIdentity(loss.Identity) || !sameJobCredentialIdentity(lifecycle.identity, loss.Identity) {
		validationErr = ErrJobCredentialIdentityMismatch
	} else if loss.Revision != expectedRevision {
		validationErr = ErrJobCredentialRevisionStale
	} else if loss.Code == "" {
		validationErr = ErrJobCredentialProofInvalid
	}
	if validationErr != nil {
		if lifecycle.state != JobCredentialStateRevoking && lifecycle.state != JobCredentialStateCleanupIncomplete {
			lifecycle.enterRevokingLocked()
			if lifecycle.revision == 0 {
				lifecycle.revision = expectedRevision
			}
		}
		lifecycle.mu.Unlock()
		return validationErr
	}
	if lifecycle.state == JobCredentialStateRevoking || lifecycle.state == JobCredentialStateCleanupIncomplete {
		lifecycle.mu.Unlock()
		return nil
	}
	switch lifecycle.state {
	case JobCredentialStatePreparing, JobCredentialStateActive, JobCredentialStateRenewing, JobCredentialStateExpired:
	default:
		lifecycle.mu.Unlock()
		return ErrJobCredentialTransition
	}
	version := lifecycle.version
	hook := lifecycle.beforeCommit
	lifecycle.mu.Unlock()

	if hook != nil {
		hook(jobCredentialLifecycleTransitionObserveLoss)
	}

	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.version != version {
		if lifecycle.state == JobCredentialStateRevoking || lifecycle.state == JobCredentialStateCleanupIncomplete || lifecycle.state == JobCredentialStateRevoked {
			return nil
		}
		return ErrJobCredentialTransition
	}
	lifecycle.enterRevokingLocked()
	if lifecycle.revision == 0 {
		lifecycle.revision = expectedRevision
	}
	return nil
}

func (lifecycle *JobCredentialLifecycle) Revoke(proof JobCredentialCleanupProof, observedAt time.Time) (JobCredentialCleanupProof, error) {
	if lifecycle == nil {
		return JobCredentialCleanupProof{}, ErrJobCredentialTransition
	}
	lifecycle.mu.Lock()
	if lifecycle.state == JobCredentialStateRevoked {
		result, err := lifecycle.reinspectRevokedLocked(proof, observedAt)
		lifecycle.mu.Unlock()
		return result, err
	}
	if lifecycle.state != JobCredentialStateRevoking && lifecycle.state != JobCredentialStateCleanupIncomplete {
		lifecycle.mu.Unlock()
		return JobCredentialCleanupProof{}, ErrJobCredentialTransition
	}
	expectedRevision := lifecycle.revision
	if expectedRevision < 2 {
		expectedRevision = 2
	}
	if err := ValidateJobCredentialCleanupProof(proof, lifecycle.identity, expectedRevision, observedAt); err != nil {
		lifecycle.revision = expectedRevision
		lifecycle.enterCleanupIncompleteLocked()
		lifecycle.mu.Unlock()
		return JobCredentialCleanupProof{}, err
	}
	version := lifecycle.version
	hook := lifecycle.beforeCommit
	lifecycle.mu.Unlock()

	if hook != nil {
		hook(jobCredentialLifecycleTransitionRevoke)
	}

	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.version != version || (lifecycle.state != JobCredentialStateRevoking && lifecycle.state != JobCredentialStateCleanupIncomplete) {
		if lifecycle.state == JobCredentialStateRevoked {
			return lifecycle.reinspectRevokedLocked(proof, observedAt)
		}
		return JobCredentialCleanupProof{}, ErrJobCredentialTransition
	}
	expectedRevision = lifecycle.revision
	if expectedRevision < 2 {
		expectedRevision = 2
	}
	if err := ValidateJobCredentialCleanupProof(proof, lifecycle.identity, expectedRevision, observedAt); err != nil {
		lifecycle.revision = expectedRevision
		lifecycle.enterCleanupIncompleteLocked()
		return JobCredentialCleanupProof{}, err
	}
	lifecycle.cleanupProof = proof
	lifecycle.activeProof = JobCredentialActiveProof{}
	lifecycle.revision = expectedRevision
	lifecycle.state = JobCredentialStateRevoked
	lifecycle.version++
	return proof, nil
}

func (lifecycle *JobCredentialLifecycle) State() JobCredentialState {
	if lifecycle == nil {
		return ""
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.state
}

func (lifecycle *JobCredentialLifecycle) Revision() uint64 {
	if lifecycle == nil {
		return 0
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.revision
}

func (lifecycle *JobCredentialLifecycle) HasActiveProof() bool {
	if lifecycle == nil {
		return false
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.state == JobCredentialStateActive || lifecycle.state == JobCredentialStateRenewing
}

func (lifecycle *JobCredentialLifecycle) HasCleanupProof() bool {
	if lifecycle == nil {
		return false
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	return lifecycle.state == JobCredentialStateRevoked && validJobCredentialCleanupProof(lifecycle.cleanupProof)
}

func (lifecycle *JobCredentialLifecycle) validateActiveCandidateLocked(proof JobCredentialActiveProof, revision uint64) error {
	if !validJobCredentialActiveProof(proof) {
		return ErrJobCredentialProofInvalid
	}
	if proof.identityDigest() != jobCredentialIdentityDigest(lifecycle.identity) {
		return ErrJobCredentialIdentityMismatch
	}
	if proof.revision() != revision {
		return ErrJobCredentialRevisionStale
	}
	return nil
}

func (lifecycle *JobCredentialLifecycle) enterRevokingLocked() {
	changed := lifecycle.state != JobCredentialStateRevoking || validJobCredentialActiveProof(lifecycle.activeProof)
	lifecycle.activeProof = JobCredentialActiveProof{}
	lifecycle.cleanupProof = JobCredentialCleanupProof{}
	lifecycle.state = JobCredentialStateRevoking
	if changed {
		lifecycle.version++
	}
}

func (lifecycle *JobCredentialLifecycle) enterCleanupIncompleteLocked() {
	if lifecycle.state != JobCredentialStateCleanupIncomplete {
		lifecycle.state = JobCredentialStateCleanupIncomplete
		lifecycle.activeProof = JobCredentialActiveProof{}
		lifecycle.cleanupProof = JobCredentialCleanupProof{}
		lifecycle.version++
	}
}

func (lifecycle *JobCredentialLifecycle) reinspectRevokedLocked(proof JobCredentialCleanupProof, observedAt time.Time) (JobCredentialCleanupProof, error) {
	if err := ValidateJobCredentialCleanupProof(proof, lifecycle.identity, lifecycle.revision, observedAt); err != nil {
		return JobCredentialCleanupProof{}, err
	}
	if sameJobCredentialCleanupProof(lifecycle.cleanupProof, proof) {
		return lifecycle.cleanupProof, nil
	}
	_, inspectedAt := proof.times()
	_, durableInspectedAt := lifecycle.cleanupProof.times()
	if inspectedAt.After(durableInspectedAt) {
		return lifecycle.cleanupProof, nil
	}
	return JobCredentialCleanupProof{}, ErrJobCredentialReplayRejected
}
