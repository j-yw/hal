package cloud

import (
	"context"
	"fmt"
	"time"
)

// HeartbeatConfig holds configuration for the heartbeat service.
type HeartbeatConfig struct {
	// LeaseDuration is the duration to extend the lease on each heartbeat.
	// Defaults to 30 seconds if zero.
	LeaseDuration time.Duration
	// IDFunc generates unique IDs for events. If nil, callers must provide
	// an alternative.
	IDFunc func() string
}

// HeartbeatService manages lease renewals for active attempts and their
// associated auth profile locks. A single Renew call updates both the
// attempt and auth lock heartbeat/lease timestamps. If either renewal
// fails due to lease expiry, a lease_lost event is emitted and the
// attempt is marked terminal.
type HeartbeatService struct {
	store  Store
	config HeartbeatConfig
}

// NewHeartbeatService creates a new HeartbeatService with the given store and config.
func NewHeartbeatService(store Store, config HeartbeatConfig) *HeartbeatService {
	if config.LeaseDuration == 0 {
		config.LeaseDuration = 30 * time.Second
	}
	return &HeartbeatService{
		store:  store,
		config: config,
	}
}

// Renew extends the lease on an active attempt and its associated auth lock.
// If the attempt lease has expired, it emits a lease_lost event and marks the
// attempt as failed. If the auth lock renewal fails due to lease expiry, the
// same lease_lost handling is applied.
func (s *HeartbeatService) Renew(ctx context.Context, attemptID, authProfileID, runID string) error {
	if attemptID == "" {
		return fmt.Errorf("attemptID must not be empty")
	}
	if authProfileID == "" {
		return fmt.Errorf("authProfileID must not be empty")
	}
	if runID == "" {
		return fmt.Errorf("runID must not be empty")
	}

	now := time.Now().UTC().Truncate(time.Second)
	newExpiry := now.Add(s.config.LeaseDuration)

	// Step 1: Renew attempt lease.
	err := s.store.HeartbeatAttempt(ctx, attemptID, now, newExpiry)
	if err != nil {
		if IsLeaseExpired(err) {
			s.emitLeaseLostAndTerminate(ctx, attemptID, runID, now)
			return ErrLeaseExpired
		}
		return fmt.Errorf("failed to heartbeat attempt: %w", err)
	}

	// Step 2: Check auth profile revocation status.
	profile, err := s.store.GetAuthProfile(ctx, authProfileID)
	if err != nil {
		return fmt.Errorf("failed to get auth profile: %w", err)
	}
	if profile.Status == AuthProfileStatusRevoked {
		s.emitProfileRevokedAndTerminate(ctx, attemptID, authProfileID, runID, now)
		return ErrProfileRevoked
	}

	// Step 3: Renew auth lock lease.
	err = s.store.RenewAuthLock(ctx, authProfileID, runID, now, newExpiry)
	if err != nil {
		if IsLeaseExpired(err) {
			s.emitLeaseLostAndTerminate(ctx, attemptID, runID, now)
			return ErrLeaseExpired
		}
		return fmt.Errorf("failed to renew auth lock: %w", err)
	}

	return nil
}

// emitProfileRevokedAndTerminate emits a profile_revoked event, marks the
// attempt as failed with error_code profile_revoked, and releases the auth
// lock. Errors from side-effects are deliberately ignored — the caller
// already has the authoritative ErrProfileRevoked.
func (s *HeartbeatService) emitProfileRevokedAndTerminate(ctx context.Context, attemptID, authProfileID, runID string, now time.Time) {
	eventID := ""
	if s.config.IDFunc != nil {
		eventID = s.config.IDFunc()
	}

	event := &Event{
		ID:        eventID,
		RunID:     runID,
		AttemptID: &attemptID,
		EventType: "profile_revoked",
		CreatedAt: now,
	}
	_ = s.store.InsertEvent(ctx, event)

	errCode := "profile_revoked"
	errMsg := "auth profile revoked during heartbeat renewal"
	_ = s.store.TransitionAttempt(ctx, attemptID, AttemptStatusFailed, now, &errCode, &errMsg)

	// Release auth lock — tolerate ErrNotFound (lock may already be released).
	_ = s.store.ReleaseAuthLock(ctx, authProfileID, runID, now)
}

// emitLeaseLostAndTerminate emits a lease_lost event and marks the attempt
// as failed with error_code lease_lost. Errors from event insertion and
// attempt transition are deliberately ignored — the caller already has the
// authoritative lease-expired error.
func (s *HeartbeatService) emitLeaseLostAndTerminate(ctx context.Context, attemptID, runID string, now time.Time) {
	eventID := ""
	if s.config.IDFunc != nil {
		eventID = s.config.IDFunc()
	}

	event := &Event{
		ID:        eventID,
		RunID:     runID,
		AttemptID: &attemptID,
		EventType: "lease_lost",
		CreatedAt: now,
	}
	_ = s.store.InsertEvent(ctx, event)

	errCode := "lease_lost"
	errMsg := "lease expired during heartbeat renewal"
	_ = s.store.TransitionAttempt(ctx, attemptID, AttemptStatusFailed, now, &errCode, &errMsg)
}
