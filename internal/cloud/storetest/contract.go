// Package storetest provides adapter-neutral contract tests for the cloud.Store
// interface. Any adapter implementation can validate correctness by calling
// Suite(t, factory) with a factory that returns a fresh, empty Store instance.
package storetest

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

// NewStoreFunc creates a fresh Store instance with empty tables for each test.
// The returned Store must have all schema (tables, indexes, triggers) applied.
type NewStoreFunc func(t *testing.T) cloud.Store

// Suite runs the full adapter contract test suite against the provided factory.
func Suite(t *testing.T, newStore NewStoreFunc) {
	t.Run("Enqueue", func(t *testing.T) { testEnqueue(t, newStore) })
	t.Run("AtomicClaim", func(t *testing.T) { testAtomicClaim(t, newStore) })
	t.Run("ParallelClaim", func(t *testing.T) { testParallelClaim(t, newStore) })
	t.Run("OneActiveAttempt", func(t *testing.T) { testOneActiveAttempt(t, newStore) })
	t.Run("HeartbeatRenew", func(t *testing.T) { testHeartbeatRenew(t, newStore) })
	t.Run("TransitionGuards", func(t *testing.T) { testTransitionGuards(t, newStore) })
}

// --- helpers ---

func validRun(id string) *cloud.Run {
	now := time.Now().UTC().Truncate(time.Second)
	return &cloud.Run{
		ID:            id,
		Repo:          "owner/repo",
		BaseBranch:    "main",
		Engine:        "claude",
		AuthProfileID: "auth-001",
		ScopeRef:      "prd-001",
		Status:        cloud.RunStatusQueued,
		AttemptCount:  0,
		MaxAttempts:   3,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
}

func validAttempt(id, runID, workerID string, num int) *cloud.Attempt {
	now := time.Now().UTC().Truncate(time.Second)
	return &cloud.Attempt{
		ID:             id,
		RunID:          runID,
		AttemptNumber:  num,
		WorkerID:       workerID,
		Status:         cloud.AttemptStatusActive,
		StartedAt:      now,
		HeartbeatAt:    now,
		LeaseExpiresAt: now.Add(30 * time.Second),
	}
}

// --- contract tests ---

// testEnqueue verifies that EnqueueRun creates a retrievable run in queued status.
func testEnqueue(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	run := validRun("run-enqueue-001")
	if err := s.EnqueueRun(ctx, run); err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}

	got, err := s.GetRun(ctx, "run-enqueue-001")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.ID != "run-enqueue-001" {
		t.Errorf("got ID %q, want %q", got.ID, "run-enqueue-001")
	}
	if got.Status != cloud.RunStatusQueued {
		t.Errorf("got status %q, want %q", got.Status, cloud.RunStatusQueued)
	}
	if got.Repo != "owner/repo" {
		t.Errorf("got repo %q, want %q", got.Repo, "owner/repo")
	}

	// GetRun for non-existent ID returns ErrNotFound.
	_, err = s.GetRun(ctx, "does-not-exist")
	if !cloud.IsNotFound(err) {
		t.Errorf("GetRun(non-existent): got %v, want ErrNotFound", err)
	}
}

// testAtomicClaim verifies that ClaimRun atomically transitions a queued run
// to claimed and returns the claimed run.
func testAtomicClaim(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	// No runs queued — claim returns ErrNotFound.
	_, err := s.ClaimRun(ctx, "worker-1")
	if !cloud.IsNotFound(err) {
		t.Fatalf("ClaimRun(empty): got %v, want ErrNotFound", err)
	}

	// Enqueue two runs with staggered created_at so claim order is deterministic.
	run1 := validRun("run-claim-001")
	run1.CreatedAt = time.Now().UTC().Add(-2 * time.Second).Truncate(time.Second)
	run2 := validRun("run-claim-002")
	run2.ID = "run-claim-002"
	run2.CreatedAt = time.Now().UTC().Add(-1 * time.Second).Truncate(time.Second)

	if err := s.EnqueueRun(ctx, run1); err != nil {
		t.Fatalf("EnqueueRun(run1): %v", err)
	}
	if err := s.EnqueueRun(ctx, run2); err != nil {
		t.Fatalf("EnqueueRun(run2): %v", err)
	}

	// Claim should pick the oldest queued run (run1).
	claimed, err := s.ClaimRun(ctx, "worker-1")
	if err != nil {
		t.Fatalf("ClaimRun: %v", err)
	}
	if claimed.ID != "run-claim-001" {
		t.Errorf("claimed ID %q, want run-claim-001 (oldest)", claimed.ID)
	}
	if claimed.Status != cloud.RunStatusClaimed {
		t.Errorf("claimed status %q, want %q", claimed.Status, cloud.RunStatusClaimed)
	}

	// The run should be claimed in the store too.
	got, err := s.GetRun(ctx, "run-claim-001")
	if err != nil {
		t.Fatalf("GetRun(claimed): %v", err)
	}
	if got.Status != cloud.RunStatusClaimed {
		t.Errorf("stored status %q, want %q", got.Status, cloud.RunStatusClaimed)
	}

	// Second claim should pick run2.
	claimed2, err := s.ClaimRun(ctx, "worker-2")
	if err != nil {
		t.Fatalf("ClaimRun(second): %v", err)
	}
	if claimed2.ID != "run-claim-002" {
		t.Errorf("second claimed ID %q, want run-claim-002", claimed2.ID)
	}

	// No more queued runs — claim returns ErrNotFound.
	_, err = s.ClaimRun(ctx, "worker-3")
	if !cloud.IsNotFound(err) {
		t.Errorf("ClaimRun(exhausted): got %v, want ErrNotFound", err)
	}
}

// testParallelClaim asserts that concurrent ClaimRun calls for a single queued
// run produce exactly one winner.
func testParallelClaim(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	run := validRun("run-parallel-001")
	if err := s.EnqueueRun(ctx, run); err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}

	const numWorkers = 10
	var (
		wg       sync.WaitGroup
		winners  atomic.Int32
		notFound atomic.Int32
	)

	wg.Add(numWorkers)
	for i := range numWorkers {
		go func(workerID string) {
			defer wg.Done()
			_, err := s.ClaimRun(ctx, workerID)
			if err == nil {
				winners.Add(1)
			} else if cloud.IsNotFound(err) {
				notFound.Add(1)
			}
		}(fmt.Sprintf("worker-%d", i))
	}
	wg.Wait()

	if w := winners.Load(); w != 1 {
		t.Errorf("parallel claim: got %d winners, want exactly 1", w)
	}
	if nf := notFound.Load(); nf != int32(numWorkers-1) {
		t.Errorf("parallel claim: got %d not-found, want %d", nf, numWorkers-1)
	}
}

// testOneActiveAttempt verifies that creating a second active attempt for the
// same run fails (one-active-attempt invariant).
func testOneActiveAttempt(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	// Setup: enqueue and claim a run.
	run := validRun("run-oaa-001")
	if err := s.EnqueueRun(ctx, run); err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}
	if _, err := s.ClaimRun(ctx, "worker-1"); err != nil {
		t.Fatalf("ClaimRun: %v", err)
	}

	// First attempt succeeds.
	a1 := validAttempt("att-oaa-001", "run-oaa-001", "worker-1", 1)
	if err := s.CreateAttempt(ctx, a1); err != nil {
		t.Fatalf("CreateAttempt(first): %v", err)
	}

	// Second active attempt for the same run must fail.
	a2 := validAttempt("att-oaa-002", "run-oaa-001", "worker-1", 2)
	err := s.CreateAttempt(ctx, a2)
	if err == nil {
		t.Fatal("CreateAttempt(second active): expected error, got nil")
	}

	// After terminating the first attempt, a new active attempt should succeed.
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.TransitionAttempt(ctx, "att-oaa-001", cloud.AttemptStatusFailed, now, nil, nil); err != nil {
		t.Fatalf("TransitionAttempt(terminate first): %v", err)
	}

	a3 := validAttempt("att-oaa-003", "run-oaa-001", "worker-1", 2)
	if err := s.CreateAttempt(ctx, a3); err != nil {
		t.Fatalf("CreateAttempt(after terminate): %v", err)
	}
}

// testHeartbeatRenew verifies heartbeat behavior: successful renew and
// lease-expired rejection.
func testHeartbeatRenew(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	// Setup: enqueue, claim, create attempt.
	run := validRun("run-hb-001")
	if err := s.EnqueueRun(ctx, run); err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}
	if _, err := s.ClaimRun(ctx, "worker-1"); err != nil {
		t.Fatalf("ClaimRun: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	att := validAttempt("att-hb-001", "run-hb-001", "worker-1", 1)
	att.LeaseExpiresAt = now.Add(30 * time.Second)
	if err := s.CreateAttempt(ctx, att); err != nil {
		t.Fatalf("CreateAttempt: %v", err)
	}

	// Successful heartbeat extends lease.
	newHeartbeat := now.Add(10 * time.Second)
	newLease := now.Add(40 * time.Second)
	if err := s.HeartbeatAttempt(ctx, "att-hb-001", newHeartbeat, newLease); err != nil {
		t.Fatalf("HeartbeatAttempt: %v", err)
	}

	got, err := s.GetAttempt(ctx, "att-hb-001")
	if err != nil {
		t.Fatalf("GetAttempt: %v", err)
	}
	if !got.HeartbeatAt.Equal(newHeartbeat) {
		t.Errorf("heartbeat_at = %v, want %v", got.HeartbeatAt, newHeartbeat)
	}
	if !got.LeaseExpiresAt.Equal(newLease) {
		t.Errorf("lease_expires_at = %v, want %v", got.LeaseExpiresAt, newLease)
	}

	// Heartbeat on non-existent attempt returns ErrNotFound.
	err = s.HeartbeatAttempt(ctx, "does-not-exist", newHeartbeat, newLease)
	if !cloud.IsNotFound(err) {
		t.Errorf("HeartbeatAttempt(non-existent): got %v, want ErrNotFound", err)
	}

	// Terminate the attempt, then heartbeat should fail.
	endedAt := now.Add(20 * time.Second)
	if err := s.TransitionAttempt(ctx, "att-hb-001", cloud.AttemptStatusFailed, endedAt, nil, nil); err != nil {
		t.Fatalf("TransitionAttempt(terminate): %v", err)
	}

	err = s.HeartbeatAttempt(ctx, "att-hb-001", now.Add(30*time.Second), now.Add(60*time.Second))
	if err == nil {
		t.Error("HeartbeatAttempt(terminated attempt): expected error, got nil")
	}
}

// testTransitionGuards verifies that only valid run status transitions are
// allowed and invalid transitions return ErrInvalidTransition.
func testTransitionGuards(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	// Helper to create and claim a run for transition testing.
	setupClaimedRun := func(id string) {
		t.Helper()
		run := validRun(id)
		if err := s.EnqueueRun(ctx, run); err != nil {
			t.Fatalf("EnqueueRun(%s): %v", id, err)
		}
		if _, err := s.ClaimRun(ctx, "worker-1"); err != nil {
			t.Fatalf("ClaimRun(%s): %v", id, err)
		}
	}

	t.Run("claimed_to_running", func(t *testing.T) {
		setupClaimedRun("run-tg-001")
		if err := s.TransitionRun(ctx, "run-tg-001", cloud.RunStatusClaimed, cloud.RunStatusRunning); err != nil {
			t.Fatalf("TransitionRun(claimed->running): %v", err)
		}
		got, _ := s.GetRun(ctx, "run-tg-001")
		if got.Status != cloud.RunStatusRunning {
			t.Errorf("status = %q, want %q", got.Status, cloud.RunStatusRunning)
		}
	})

	t.Run("running_to_succeeded", func(t *testing.T) {
		setupClaimedRun("run-tg-002")
		_ = s.TransitionRun(ctx, "run-tg-002", cloud.RunStatusClaimed, cloud.RunStatusRunning)
		if err := s.TransitionRun(ctx, "run-tg-002", cloud.RunStatusRunning, cloud.RunStatusSucceeded); err != nil {
			t.Fatalf("TransitionRun(running->succeeded): %v", err)
		}
	})

	t.Run("running_to_failed", func(t *testing.T) {
		setupClaimedRun("run-tg-003")
		_ = s.TransitionRun(ctx, "run-tg-003", cloud.RunStatusClaimed, cloud.RunStatusRunning)
		if err := s.TransitionRun(ctx, "run-tg-003", cloud.RunStatusRunning, cloud.RunStatusFailed); err != nil {
			t.Fatalf("TransitionRun(running->failed): %v", err)
		}
	})

	t.Run("invalid_queued_to_succeeded", func(t *testing.T) {
		run := validRun("run-tg-004")
		if err := s.EnqueueRun(ctx, run); err != nil {
			t.Fatalf("EnqueueRun: %v", err)
		}
		err := s.TransitionRun(ctx, "run-tg-004", cloud.RunStatusQueued, cloud.RunStatusSucceeded)
		if !cloud.IsInvalidTransition(err) {
			t.Errorf("TransitionRun(queued->succeeded): got %v, want ErrInvalidTransition", err)
		}
	})

	t.Run("status_mismatch_returns_conflict", func(t *testing.T) {
		setupClaimedRun("run-tg-005")
		// Run is in claimed status, but we claim fromStatus is queued.
		err := s.TransitionRun(ctx, "run-tg-005", cloud.RunStatusQueued, cloud.RunStatusRunning)
		if !cloud.IsConflict(err) {
			t.Errorf("TransitionRun(wrong fromStatus): got %v, want ErrConflict", err)
		}
	})

	t.Run("non_existent_run", func(t *testing.T) {
		err := s.TransitionRun(ctx, "does-not-exist", cloud.RunStatusQueued, cloud.RunStatusClaimed)
		if !cloud.IsNotFound(err) {
			t.Errorf("TransitionRun(non-existent): got %v, want ErrNotFound", err)
		}
	})
}
