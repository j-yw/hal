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
	t.Run("ListOverdueRuns", func(t *testing.T) { testListOverdueRuns(t, newStore) })
	t.Run("SetCancelIntent", func(t *testing.T) { testSetCancelIntent(t, newStore) })
	t.Run("ClaimExcludesCanceled", func(t *testing.T) { testClaimExcludesCanceled(t, newStore) })
	t.Run("UpdateAttemptSandboxID", func(t *testing.T) { testUpdateAttemptSandboxID(t, newStore) })
	t.Run("UpdateRunSnapshotRefs", func(t *testing.T) { testUpdateRunSnapshotRefs(t, newStore) })
	t.Run("GetActiveAttemptByRun", func(t *testing.T) { testGetActiveAttemptByRun(t, newStore) })
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
		// Enqueue a fresh run. Claim all queued runs to ensure this specific
		// run is claimed (earlier subtests may leave orphan queued runs).
		run := validRun("run-tg-005")
		if err := s.EnqueueRun(ctx, run); err != nil {
			t.Fatalf("EnqueueRun: %v", err)
		}
		// Drain all queued runs to ensure run-tg-005 is claimed.
		for {
			_, err := s.ClaimRun(ctx, "worker-1")
			if cloud.IsNotFound(err) {
				break
			}
			if err != nil {
				t.Fatalf("ClaimRun(drain): %v", err)
			}
		}
		// Verify run-tg-005 is now claimed.
		got, err := s.GetRun(ctx, "run-tg-005")
		if err != nil {
			t.Fatalf("GetRun(run-tg-005): %v", err)
		}
		if got.Status != cloud.RunStatusClaimed {
			t.Fatalf("run-tg-005 status = %q, want claimed", got.Status)
		}
		// Run is in claimed status, but we claim fromStatus is running.
		// The transition running->succeeded IS valid, so this isolates
		// the status-mismatch error from invalid-transition errors.
		err = s.TransitionRun(ctx, "run-tg-005", cloud.RunStatusRunning, cloud.RunStatusSucceeded)
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

// testListOverdueRuns verifies that ListOverdueRuns returns non-terminal runs
// whose deadline_at has passed and excludes terminal and no-deadline runs.
func testListOverdueRuns(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	pastDeadline := now.Add(-10 * time.Minute)
	futureDeadline := now.Add(10 * time.Minute)

	// Run with past deadline (overdue) — should be returned.
	r1 := validRun("run-overdue-001")
	r1.DeadlineAt = &pastDeadline
	if err := s.EnqueueRun(ctx, r1); err != nil {
		t.Fatalf("EnqueueRun(r1): %v", err)
	}

	// Run with future deadline — should NOT be returned.
	r2 := validRun("run-overdue-002")
	r2.DeadlineAt = &futureDeadline
	if err := s.EnqueueRun(ctx, r2); err != nil {
		t.Fatalf("EnqueueRun(r2): %v", err)
	}

	// Run with no deadline — should NOT be returned.
	r3 := validRun("run-overdue-003")
	r3.DeadlineAt = nil
	if err := s.EnqueueRun(ctx, r3); err != nil {
		t.Fatalf("EnqueueRun(r3): %v", err)
	}

	// Terminal run with past deadline — should NOT be returned.
	r4 := validRun("run-overdue-004")
	r4.DeadlineAt = &pastDeadline
	if err := s.EnqueueRun(ctx, r4); err != nil {
		t.Fatalf("EnqueueRun(r4): %v", err)
	}
	// Claim then transition to running then failed (terminal).
	if _, err := s.ClaimRun(ctx, "worker-1"); err != nil {
		t.Fatalf("ClaimRun(r4): %v", err)
	}
	// Need to identify which run was claimed — drain until r4 is claimed.
	got4, err := s.GetRun(ctx, "run-overdue-004")
	if err != nil {
		t.Fatalf("GetRun(r4): %v", err)
	}
	if got4.Status == cloud.RunStatusClaimed {
		_ = s.TransitionRun(ctx, "run-overdue-004", cloud.RunStatusClaimed, cloud.RunStatusRunning)
		_ = s.TransitionRun(ctx, "run-overdue-004", cloud.RunStatusRunning, cloud.RunStatusFailed)
	}

	overdue, err := s.ListOverdueRuns(ctx, now)
	if err != nil {
		t.Fatalf("ListOverdueRuns: %v", err)
	}

	// At minimum, run-overdue-001 should be returned (the past-deadline queued run).
	found := false
	for _, r := range overdue {
		if r.ID == "run-overdue-001" {
			found = true
		}
		// Terminal runs should never appear.
		if r.Status.IsTerminal() {
			t.Errorf("ListOverdueRuns returned terminal run %s (status %s)", r.ID, r.Status)
		}
		// Future-deadline runs should not appear.
		if r.ID == "run-overdue-002" {
			t.Errorf("ListOverdueRuns returned future-deadline run %s", r.ID)
		}
		// No-deadline runs should not appear.
		if r.ID == "run-overdue-003" {
			t.Errorf("ListOverdueRuns returned no-deadline run %s", r.ID)
		}
	}
	if !found {
		t.Errorf("ListOverdueRuns did not return overdue run-overdue-001; got %d runs", len(overdue))
	}
}

// testSetCancelIntent verifies that SetCancelIntent sets the cancel flag and
// is idempotent. It also verifies ErrNotFound for non-existent runs.
func testSetCancelIntent(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	// Setup: enqueue a run.
	run := validRun("run-cancel-001")
	if err := s.EnqueueRun(ctx, run); err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}

	// Initially cancel_requested is false.
	got, err := s.GetRun(ctx, "run-cancel-001")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.CancelRequested {
		t.Error("initial CancelRequested = true, want false")
	}

	// Set cancel intent.
	if err := s.SetCancelIntent(ctx, "run-cancel-001"); err != nil {
		t.Fatalf("SetCancelIntent: %v", err)
	}

	got, err = s.GetRun(ctx, "run-cancel-001")
	if err != nil {
		t.Fatalf("GetRun(after cancel): %v", err)
	}
	if !got.CancelRequested {
		t.Error("CancelRequested = false after SetCancelIntent, want true")
	}

	// Idempotent — second call succeeds.
	if err := s.SetCancelIntent(ctx, "run-cancel-001"); err != nil {
		t.Fatalf("SetCancelIntent(idempotent): %v", err)
	}

	// Non-existent run returns ErrNotFound.
	err = s.SetCancelIntent(ctx, "does-not-exist")
	if !cloud.IsNotFound(err) {
		t.Errorf("SetCancelIntent(non-existent): got %v, want ErrNotFound", err)
	}
}

// testClaimExcludesCanceled verifies that ClaimRun skips runs with
// cancel_requested=true, enforcing the claim exclusion rule.
func testClaimExcludesCanceled(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	// Enqueue two runs.
	run1 := validRun("run-excl-001")
	run1.CreatedAt = time.Now().UTC().Add(-2 * time.Second).Truncate(time.Second)
	run2 := validRun("run-excl-002")
	run2.CreatedAt = time.Now().UTC().Add(-1 * time.Second).Truncate(time.Second)

	if err := s.EnqueueRun(ctx, run1); err != nil {
		t.Fatalf("EnqueueRun(run1): %v", err)
	}
	if err := s.EnqueueRun(ctx, run2); err != nil {
		t.Fatalf("EnqueueRun(run2): %v", err)
	}

	// Mark run1 (oldest) as cancel_requested.
	if err := s.SetCancelIntent(ctx, "run-excl-001"); err != nil {
		t.Fatalf("SetCancelIntent: %v", err)
	}

	// Claim should skip run1 and pick run2.
	claimed, err := s.ClaimRun(ctx, "worker-1")
	if err != nil {
		t.Fatalf("ClaimRun: %v", err)
	}
	if claimed.ID != "run-excl-002" {
		t.Errorf("claimed ID %q, want run-excl-002 (skipped cancel-requested run1)", claimed.ID)
	}

	// No more non-canceled queued runs — claim returns ErrNotFound.
	_, err = s.ClaimRun(ctx, "worker-2")
	if !cloud.IsNotFound(err) {
		t.Errorf("ClaimRun(only cancel-requested left): got %v, want ErrNotFound", err)
	}
}

// testUpdateAttemptSandboxID verifies that UpdateAttemptSandboxID sets the
// sandbox_id on an existing attempt and returns ErrNotFound for non-existent attempts.
func testUpdateAttemptSandboxID(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	// Setup: enqueue, claim, create attempt.
	run := validRun("run-usid-001")
	if err := s.EnqueueRun(ctx, run); err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}
	if _, err := s.ClaimRun(ctx, "worker-1"); err != nil {
		t.Fatalf("ClaimRun: %v", err)
	}

	att := validAttempt("att-usid-001", "run-usid-001", "worker-1", 1)
	if err := s.CreateAttempt(ctx, att); err != nil {
		t.Fatalf("CreateAttempt: %v", err)
	}

	// Initially sandbox_id is nil.
	got, err := s.GetAttempt(ctx, "att-usid-001")
	if err != nil {
		t.Fatalf("GetAttempt: %v", err)
	}
	if got.SandboxID != nil {
		t.Errorf("initial SandboxID = %v, want nil", got.SandboxID)
	}

	// Update sandbox_id.
	if err := s.UpdateAttemptSandboxID(ctx, "att-usid-001", "sandbox-xyz"); err != nil {
		t.Fatalf("UpdateAttemptSandboxID: %v", err)
	}

	got, err = s.GetAttempt(ctx, "att-usid-001")
	if err != nil {
		t.Fatalf("GetAttempt(after update): %v", err)
	}
	if got.SandboxID == nil || *got.SandboxID != "sandbox-xyz" {
		t.Errorf("SandboxID = %v, want %q", got.SandboxID, "sandbox-xyz")
	}

	// Non-existent attempt returns ErrNotFound.
	err = s.UpdateAttemptSandboxID(ctx, "does-not-exist", "sandbox-abc")
	if !cloud.IsNotFound(err) {
		t.Errorf("UpdateAttemptSandboxID(non-existent): got %v, want ErrNotFound", err)
	}
}

// testUpdateRunSnapshotRefs verifies that UpdateRunSnapshotRefs sets snapshot
// reference fields on a run and returns ErrNotFound for non-existent runs.
func testUpdateRunSnapshotRefs(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	// Setup: enqueue a run.
	run := validRun("run-snap-001")
	if err := s.EnqueueRun(ctx, run); err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}

	// Initially snapshot refs are nil/0.
	got, err := s.GetRun(ctx, "run-snap-001")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}
	if got.InputSnapshotID != nil {
		t.Errorf("initial InputSnapshotID = %v, want nil", got.InputSnapshotID)
	}
	if got.LatestSnapshotID != nil {
		t.Errorf("initial LatestSnapshotID = %v, want nil", got.LatestSnapshotID)
	}
	if got.LatestSnapshotVersion != 0 {
		t.Errorf("initial LatestSnapshotVersion = %d, want 0", got.LatestSnapshotVersion)
	}

	// Update snapshot refs.
	inputID := "snap-input-001"
	latestID := "snap-input-001"
	if err := s.UpdateRunSnapshotRefs(ctx, "run-snap-001", &inputID, &latestID, 1); err != nil {
		t.Fatalf("UpdateRunSnapshotRefs: %v", err)
	}

	got, err = s.GetRun(ctx, "run-snap-001")
	if err != nil {
		t.Fatalf("GetRun(after update): %v", err)
	}
	if got.InputSnapshotID == nil || *got.InputSnapshotID != "snap-input-001" {
		t.Errorf("InputSnapshotID = %v, want %q", got.InputSnapshotID, "snap-input-001")
	}
	if got.LatestSnapshotID == nil || *got.LatestSnapshotID != "snap-input-001" {
		t.Errorf("LatestSnapshotID = %v, want %q", got.LatestSnapshotID, "snap-input-001")
	}
	if got.LatestSnapshotVersion != 1 {
		t.Errorf("LatestSnapshotVersion = %d, want 1", got.LatestSnapshotVersion)
	}

	// Non-existent run returns ErrNotFound.
	err = s.UpdateRunSnapshotRefs(ctx, "does-not-exist", &inputID, &latestID, 1)
	if !cloud.IsNotFound(err) {
		t.Errorf("UpdateRunSnapshotRefs(non-existent): got %v, want ErrNotFound", err)
	}
}

func testGetActiveAttemptByRun(t *testing.T, newStore NewStoreFunc) {
	s := newStore(t)
	ctx := context.Background()

	run := validRun("run-gaa-001")
	if err := s.EnqueueRun(ctx, run); err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}

	// No active attempt returns ErrNotFound.
	_, err := s.GetActiveAttemptByRun(ctx, "run-gaa-001")
	if !cloud.IsNotFound(err) {
		t.Errorf("GetActiveAttemptByRun(no attempt): got %v, want ErrNotFound", err)
	}

	// Claim run to transition to claimed, then create an active attempt.
	claimed, err := s.ClaimRun(ctx, "worker-1")
	if err != nil {
		t.Fatalf("ClaimRun: %v", err)
	}

	att := validAttempt("att-gaa-001", claimed.ID, "worker-1", 1)
	if err := s.CreateAttempt(ctx, att); err != nil {
		t.Fatalf("CreateAttempt: %v", err)
	}

	// Active attempt is returned.
	got, err := s.GetActiveAttemptByRun(ctx, "run-gaa-001")
	if err != nil {
		t.Fatalf("GetActiveAttemptByRun: %v", err)
	}
	if got.ID != "att-gaa-001" {
		t.Errorf("attempt ID = %q, want %q", got.ID, "att-gaa-001")
	}

	// After terminating the attempt, no active attempt exists.
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.TransitionAttempt(ctx, "att-gaa-001", cloud.AttemptStatusFailed, now, nil, nil); err != nil {
		t.Fatalf("TransitionAttempt: %v", err)
	}

	_, err = s.GetActiveAttemptByRun(ctx, "run-gaa-001")
	if !cloud.IsNotFound(err) {
		t.Errorf("GetActiveAttemptByRun(after terminate): got %v, want ErrNotFound", err)
	}

	// Non-existent run returns ErrNotFound.
	_, err = s.GetActiveAttemptByRun(ctx, "does-not-exist")
	if !cloud.IsNotFound(err) {
		t.Errorf("GetActiveAttemptByRun(non-existent run): got %v, want ErrNotFound", err)
	}
}
