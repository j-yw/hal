package cloud

import (
	"context"
	"fmt"
	"time"
)

// ClaimResult holds the outcome of a successful claim-and-lock operation.
type ClaimResult struct {
	Run     *Run
	Attempt *Attempt
	Lock    *AuthProfileLock
}

// ClaimConfig holds configuration for the claim service.
type ClaimConfig struct {
	// LeaseDuration is the initial lease duration for both the attempt and
	// the auth lock. Defaults to 30 seconds if zero.
	LeaseDuration time.Duration
	// IDFunc generates unique IDs for attempts. If nil, callers must
	// provide an alternative.
	IDFunc func() string
}

// ClaimService implements atomic claim and lock acquisition. A single call
// transitions one eligible queued run to claimed, creates an attempt row,
// and acquires an auth lock lease. If lock acquisition fails, the claim and
// attempt are rolled back.
type ClaimService struct {
	store  Store
	config ClaimConfig
}

// NewClaimService creates a new ClaimService with the given store and config.
func NewClaimService(store Store, config ClaimConfig) *ClaimService {
	if config.LeaseDuration == 0 {
		config.LeaseDuration = 30 * time.Second
	}
	return &ClaimService{
		store:  store,
		config: config,
	}
}

// ClaimAndLock atomically claims one eligible queued run for the given worker,
// creates an attempt, and acquires the auth lock lease. If no eligible run
// exists, returns ErrNotFound. If the auth lock cannot be acquired, the claim
// and attempt are rolled back and the original lock error is returned.
func (s *ClaimService) ClaimAndLock(ctx context.Context, workerID string) (*ClaimResult, error) {
	if workerID == "" {
		return nil, fmt.Errorf("workerID must not be empty")
	}

	// Step 1: Claim one eligible queued run.
	run, err := s.store.ClaimRun(ctx, workerID)
	if err != nil {
		return nil, err
	}

	// Step 2: Create an attempt row.
	now := time.Now().UTC().Truncate(time.Second)
	leaseExpiry := now.Add(s.config.LeaseDuration)

	attemptID := ""
	if s.config.IDFunc != nil {
		attemptID = s.config.IDFunc()
	}

	attempt := &Attempt{
		ID:             attemptID,
		RunID:          run.ID,
		AttemptNumber:  run.AttemptCount + 1,
		WorkerID:       workerID,
		Status:         AttemptStatusActive,
		StartedAt:      now,
		HeartbeatAt:    now,
		LeaseExpiresAt: leaseExpiry,
	}

	if err := s.store.CreateAttempt(ctx, attempt); err != nil {
		// Rollback: transition run back to queued.
		_ = s.store.TransitionRun(ctx, run.ID, RunStatusClaimed, RunStatusQueued)
		return nil, fmt.Errorf("failed to create attempt: %w", err)
	}

	// Step 3: Acquire auth lock lease.
	lock := &AuthProfileLock{
		AuthProfileID:  run.AuthProfileID,
		RunID:          run.ID,
		WorkerID:       workerID,
		AcquiredAt:     now,
		HeartbeatAt:    now,
		LeaseExpiresAt: leaseExpiry,
	}

	if err := s.store.AcquireAuthLock(ctx, lock); err != nil {
		// Rollback: mark attempt failed and transition run back to queued.
		lockErr := err
		errCode := "lock_acquisition_failed"
		errMsg := lockErr.Error()
		_ = s.store.TransitionAttempt(ctx, attempt.ID, AttemptStatusFailed, now, &errCode, &errMsg)
		_ = s.store.TransitionRun(ctx, run.ID, RunStatusClaimed, RunStatusQueued)
		return nil, fmt.Errorf("failed to acquire auth lock: %w", lockErr)
	}

	return &ClaimResult{
		Run:     run,
		Attempt: attempt,
		Lock:    lock,
	}, nil
}
