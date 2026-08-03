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
	identity jobCredentialLifecycleOwner
	state    *jobCredentialLifecycleState
}

type jobCredentialLifecycleOwner struct{ _ byte }

type jobCredentialLifecycleState struct {
	owner        *jobCredentialLifecycleOwner
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
	lifecycle := &JobCredentialLifecycle{}
	lifecycle.state = &jobCredentialLifecycleState{
		owner:        &lifecycle.identity,
		identity:     cloneJobCredentialIdentity(identity),
		beforeCommit: options.beforeCommit,
	}
	return lifecycle, nil
}

func (lifecycle *JobCredentialLifecycle) BeginPrepare(identity JobCredentialIdentity) error {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return ErrJobCredentialTransition
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	if !validJobCredentialIdentity(identity) || !sameJobCredentialIdentity(live.identity, identity) {
		return ErrJobCredentialIdentityMismatch
	}
	switch live.state {
	case "":
		live.state = JobCredentialStatePreparing
		live.version++
		return nil
	case JobCredentialStatePreparing:
		return nil
	default:
		return ErrJobCredentialTransition
	}
}

func (lifecycle *JobCredentialLifecycle) Activate(proof JobCredentialActiveProof, observedAt time.Time) error {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return ErrJobCredentialTransition
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	if live.state == JobCredentialStateActive && sameJobCredentialActiveProof(live.activeProof, proof) {
		if err := ValidateJobCredentialActiveProof(proof, live.identity, live.revision, observedAt); err != nil {
			live.enterRevokingLocked()
			return err
		}
		return nil
	}
	if live.state == JobCredentialStateActive {
		var err error
		if !validJobCredentialActiveProof(proof) {
			err = ErrJobCredentialProofInvalid
		} else if proof.identityDigest() != jobCredentialIdentityDigest(live.identity) {
			err = ErrJobCredentialIdentityMismatch
		} else {
			err = ErrJobCredentialReplayRejected
		}
		live.enterRevokingLocked()
		return err
	}
	if live.state != JobCredentialStatePreparing {
		return ErrJobCredentialTransition
	}
	if err := ValidateJobCredentialActiveProof(proof, live.identity, proof.revision(), observedAt); err != nil {
		live.enterRevokingLocked()
		return err
	}
	live.activeProof = proof
	live.cleanupProof = JobCredentialCleanupProof{}
	live.revision = proof.revision()
	live.state = JobCredentialStateActive
	live.version++
	return nil
}

func (lifecycle *JobCredentialLifecycle) BeginRenew() error {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return ErrJobCredentialTransition
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	switch live.state {
	case JobCredentialStateActive:
		live.state = JobCredentialStateRenewing
		live.version++
		return nil
	case JobCredentialStateExpired:
		return ErrJobCredentialExpired
	default:
		return ErrJobCredentialTransition
	}
}

func (lifecycle *JobCredentialLifecycle) Renew(proof JobCredentialActiveProof, observedAt time.Time) error {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return ErrJobCredentialTransition
	}
	live.mu.Lock()
	if live.state != JobCredentialStateRenewing {
		live.mu.Unlock()
		return ErrJobCredentialTransition
	}
	if sameJobCredentialActiveProof(live.activeProof, proof) {
		live.enterRevokingLocked()
		live.mu.Unlock()
		return ErrJobCredentialReplayRejected
	}
	if err := ValidateJobCredentialActiveProof(proof, live.identity, live.revision+1, observedAt); err != nil {
		live.enterRevokingLocked()
		live.mu.Unlock()
		return err
	}
	previousIssuedAt, previousExpiresAt := live.activeProof.times()
	issuedAt, expiresAt := proof.times()
	if !issuedAt.After(previousIssuedAt) || !expiresAt.After(previousExpiresAt) {
		live.enterRevokingLocked()
		live.mu.Unlock()
		return ErrJobCredentialRevisionStale
	}
	version := live.version
	hook := live.beforeCommit
	live.mu.Unlock()

	if hook != nil {
		hook(jobCredentialLifecycleTransitionRenew)
	}

	live.mu.Lock()
	defer live.mu.Unlock()
	if live.version != version || live.state != JobCredentialStateRenewing {
		if live.state == JobCredentialStateActive && sameJobCredentialActiveProof(live.activeProof, proof) {
			if err := ValidateJobCredentialActiveProof(proof, live.identity, live.revision, observedAt); err != nil {
				live.enterRevokingLocked()
				return err
			}
			return nil
		}
		if live.state == JobCredentialStateExpired {
			return ErrJobCredentialExpired
		}
		return ErrJobCredentialTransition
	}
	if err := ValidateJobCredentialActiveProof(proof, live.identity, live.revision+1, observedAt); err != nil {
		live.enterRevokingLocked()
		return err
	}
	previousIssuedAt, previousExpiresAt = live.activeProof.times()
	issuedAt, expiresAt = proof.times()
	if !issuedAt.After(previousIssuedAt) || !expiresAt.After(previousExpiresAt) {
		live.enterRevokingLocked()
		return ErrJobCredentialRevisionStale
	}
	live.activeProof = proof
	live.revision = proof.revision()
	live.state = JobCredentialStateActive
	live.version++
	return nil
}

func (lifecycle *JobCredentialLifecycle) Expire(observedAt time.Time) error {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return ErrJobCredentialTransition
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	if live.state == JobCredentialStateExpired {
		return nil
	}
	if live.state != JobCredentialStateActive {
		return ErrJobCredentialTransition
	}
	if err := ValidateJobCredentialActiveProof(live.activeProof, live.identity, live.revision, observedAt); err != ErrJobCredentialExpired {
		return ErrJobCredentialTransition
	}
	live.activeProof = JobCredentialActiveProof{}
	live.state = JobCredentialStateExpired
	live.version++
	return nil
}

func (lifecycle *JobCredentialLifecycle) BeginRevoke() error {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return ErrJobCredentialTransition
	}
	live.mu.Lock()
	switch live.state {
	case JobCredentialStateRevoking, JobCredentialStateCleanupIncomplete, JobCredentialStateRevoked:
		live.mu.Unlock()
		return nil
	case JobCredentialStatePreparing, JobCredentialStateActive, JobCredentialStateRenewing, JobCredentialStateExpired:
	default:
		live.mu.Unlock()
		return ErrJobCredentialTransition
	}
	version := live.version
	hook := live.beforeCommit
	live.mu.Unlock()

	if hook != nil {
		hook(jobCredentialLifecycleTransitionBeginRevoke)
	}

	live.mu.Lock()
	defer live.mu.Unlock()
	if live.version != version {
		switch live.state {
		case JobCredentialStateRevoking, JobCredentialStateCleanupIncomplete, JobCredentialStateRevoked:
			return nil
		default:
			return ErrJobCredentialTransition
		}
	}
	live.enterRevokingLocked()
	return nil
}

func (lifecycle *JobCredentialLifecycle) ObserveLoss(loss JobCredentialLoss) error {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return ErrJobCredentialTransition
	}
	live.mu.Lock()
	if live.state == JobCredentialStateRevoked {
		live.mu.Unlock()
		return nil
	}
	expectedRevision := live.revision
	if expectedRevision == 0 {
		expectedRevision = 1
	}
	var validationErr error
	if !validJobCredentialIdentity(loss.Identity) || !sameJobCredentialIdentity(live.identity, loss.Identity) {
		validationErr = ErrJobCredentialIdentityMismatch
	} else if loss.Revision != expectedRevision {
		validationErr = ErrJobCredentialRevisionStale
	} else if loss.Code == "" {
		validationErr = ErrJobCredentialProofInvalid
	}
	if validationErr != nil {
		if live.state != JobCredentialStateRevoking && live.state != JobCredentialStateCleanupIncomplete {
			live.enterRevokingLocked()
			if live.revision == 0 {
				live.revision = expectedRevision
			}
		}
		live.mu.Unlock()
		return validationErr
	}
	if live.state == JobCredentialStateRevoking || live.state == JobCredentialStateCleanupIncomplete {
		live.mu.Unlock()
		return nil
	}
	switch live.state {
	case JobCredentialStatePreparing, JobCredentialStateActive, JobCredentialStateRenewing, JobCredentialStateExpired:
	default:
		live.mu.Unlock()
		return ErrJobCredentialTransition
	}
	version := live.version
	hook := live.beforeCommit
	live.mu.Unlock()

	if hook != nil {
		hook(jobCredentialLifecycleTransitionObserveLoss)
	}

	live.mu.Lock()
	defer live.mu.Unlock()
	if live.version != version {
		if live.state == JobCredentialStateRevoking || live.state == JobCredentialStateCleanupIncomplete || live.state == JobCredentialStateRevoked {
			return nil
		}
		return ErrJobCredentialTransition
	}
	live.enterRevokingLocked()
	if live.revision == 0 {
		live.revision = expectedRevision
	}
	return nil
}

func (lifecycle *JobCredentialLifecycle) Revoke(proof JobCredentialCleanupProof, observedAt time.Time) (JobCredentialCleanupProof, error) {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return JobCredentialCleanupProof{}, ErrJobCredentialTransition
	}
	live.mu.Lock()
	if live.state == JobCredentialStateRevoked {
		result, err := live.reinspectRevokedLocked(proof, observedAt)
		live.mu.Unlock()
		return result, err
	}
	if live.state != JobCredentialStateRevoking && live.state != JobCredentialStateCleanupIncomplete {
		live.mu.Unlock()
		return JobCredentialCleanupProof{}, ErrJobCredentialTransition
	}
	expectedRevision := live.revision
	if expectedRevision < 2 {
		expectedRevision = 2
	}
	if err := ValidateJobCredentialCleanupProof(proof, live.identity, expectedRevision, observedAt); err != nil {
		live.revision = expectedRevision
		live.enterCleanupIncompleteLocked()
		live.mu.Unlock()
		return JobCredentialCleanupProof{}, err
	}
	version := live.version
	hook := live.beforeCommit
	live.mu.Unlock()

	if hook != nil {
		hook(jobCredentialLifecycleTransitionRevoke)
	}

	live.mu.Lock()
	defer live.mu.Unlock()
	if live.version != version || (live.state != JobCredentialStateRevoking && live.state != JobCredentialStateCleanupIncomplete) {
		if live.state == JobCredentialStateRevoked {
			return live.reinspectRevokedLocked(proof, observedAt)
		}
		return JobCredentialCleanupProof{}, ErrJobCredentialTransition
	}
	expectedRevision = live.revision
	if expectedRevision < 2 {
		expectedRevision = 2
	}
	if err := ValidateJobCredentialCleanupProof(proof, live.identity, expectedRevision, observedAt); err != nil {
		live.revision = expectedRevision
		live.enterCleanupIncompleteLocked()
		return JobCredentialCleanupProof{}, err
	}
	live.cleanupProof = proof
	live.activeProof = JobCredentialActiveProof{}
	live.revision = expectedRevision
	live.state = JobCredentialStateRevoked
	live.version++
	return proof, nil
}

func (lifecycle *JobCredentialLifecycle) State() JobCredentialState {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return ""
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	return live.state
}

func (lifecycle *JobCredentialLifecycle) Revision() uint64 {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return 0
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	return live.revision
}

func (lifecycle *JobCredentialLifecycle) HasActiveProof() bool {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return false
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	return live.state == JobCredentialStateActive || live.state == JobCredentialStateRenewing
}

func (lifecycle *JobCredentialLifecycle) HasCleanupProof() bool {
	live, ok := loadJobCredentialLifecycleState(lifecycle)
	if !ok {
		return false
	}
	live.mu.Lock()
	defer live.mu.Unlock()
	return live.state == JobCredentialStateRevoked && validJobCredentialCleanupProof(live.cleanupProof)
}

func (live *jobCredentialLifecycleState) enterRevokingLocked() {
	changed := live.state != JobCredentialStateRevoking || validJobCredentialActiveProof(live.activeProof)
	live.activeProof = JobCredentialActiveProof{}
	live.cleanupProof = JobCredentialCleanupProof{}
	live.state = JobCredentialStateRevoking
	if changed {
		live.version++
	}
}

func (live *jobCredentialLifecycleState) enterCleanupIncompleteLocked() {
	if live.state != JobCredentialStateCleanupIncomplete {
		live.state = JobCredentialStateCleanupIncomplete
		live.activeProof = JobCredentialActiveProof{}
		live.cleanupProof = JobCredentialCleanupProof{}
		live.version++
	}
}

func (live *jobCredentialLifecycleState) reinspectRevokedLocked(proof JobCredentialCleanupProof, observedAt time.Time) (JobCredentialCleanupProof, error) {
	if err := ValidateJobCredentialCleanupProof(proof, live.identity, live.revision, observedAt); err != nil {
		return JobCredentialCleanupProof{}, err
	}
	if sameJobCredentialCleanupProof(live.cleanupProof, proof) {
		return live.cleanupProof, nil
	}
	_, inspectedAt := proof.times()
	_, durableInspectedAt := live.cleanupProof.times()
	if inspectedAt.After(durableInspectedAt) {
		return live.cleanupProof, nil
	}
	return JobCredentialCleanupProof{}, ErrJobCredentialReplayRejected
}

func loadJobCredentialLifecycleState(lifecycle *JobCredentialLifecycle) (*jobCredentialLifecycleState, bool) {
	if lifecycle == nil || lifecycle.state == nil || lifecycle.state.owner != &lifecycle.identity {
		return nil, false
	}
	return lifecycle.state, true
}
