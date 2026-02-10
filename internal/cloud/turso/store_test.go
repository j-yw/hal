package turso

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/cloud/storetest"

	_ "modernc.org/sqlite"
)

// openTestDB creates a file-based SQLite database in t.TempDir().
// File-based databases are needed because :memory: creates a separate DB per
// connection, which breaks concurrent goroutine tests.
// PRAGMAs are set via DSN parameters so every connection from the pool inherits them.
func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", dbPath)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// newTestStore creates a fresh Store with an isolated SQLite database for each test.
func newTestStore(t *testing.T) cloud.Store {
	t.Helper()
	db := openTestDB(t)

	s := New(db)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

// newTestStoreWithDB creates a fresh Store and also returns the underlying
// *sql.DB for direct setup (e.g., inserting auth profiles).
func newTestStoreWithDB(t *testing.T) (cloud.Store, *sql.DB) {
	t.Helper()
	db := openTestDB(t)

	s := New(db)
	if err := s.Migrate(context.Background()); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s, db
}

// insertAuthProfile inserts an auth profile directly via SQL for test setup.
func insertAuthProfile(t *testing.T, db *sql.DB, id string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	_, err := db.ExecContext(context.Background(), `
		INSERT INTO auth_profiles (id, owner_id, provider, mode, status, max_concurrent_runs, version, created_at, updated_at)
		VALUES (?, 'owner-1', 'claude', 'api_key', 'linked', 1, 1, ?, ?)`,
		id, now, now)
	if err != nil {
		t.Fatalf("insertAuthProfile(%s): %v", id, err)
	}
}

// TestContractSuite runs the full adapter contract test suite against Turso/SQLite.
func TestContractSuite(t *testing.T) {
	storetest.Suite(t, newTestStore)
}

// --- Focused enqueue and claim tests ---

func TestEnqueueAndGet(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	run := &cloud.Run{
		ID:            "run-eq-001",
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

	if err := s.EnqueueRun(ctx, run); err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}

	got, err := s.GetRun(ctx, "run-eq-001")
	if err != nil {
		t.Fatalf("GetRun: %v", err)
	}

	if got.ID != "run-eq-001" {
		t.Errorf("ID = %q, want %q", got.ID, "run-eq-001")
	}
	if got.Status != cloud.RunStatusQueued {
		t.Errorf("Status = %q, want %q", got.Status, cloud.RunStatusQueued)
	}
	if got.Repo != "owner/repo" {
		t.Errorf("Repo = %q, want %q", got.Repo, "owner/repo")
	}
	if got.Engine != "claude" {
		t.Errorf("Engine = %q, want %q", got.Engine, "claude")
	}

	// GetRun for non-existent ID returns ErrNotFound.
	_, err = s.GetRun(ctx, "does-not-exist")
	if !cloud.IsNotFound(err) {
		t.Errorf("GetRun(non-existent): got %v, want ErrNotFound", err)
	}
}

func TestClaimPicksOldest(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)

	// Enqueue two runs with staggered created_at.
	run1 := &cloud.Run{
		ID: "run-oldest-001", Repo: "r", BaseBranch: "main", Engine: "e",
		AuthProfileID: "a", ScopeRef: "s", Status: cloud.RunStatusQueued,
		MaxAttempts: 3, CreatedAt: now.Add(-2 * time.Second), UpdatedAt: now,
	}
	run2 := &cloud.Run{
		ID: "run-oldest-002", Repo: "r", BaseBranch: "main", Engine: "e",
		AuthProfileID: "a", ScopeRef: "s", Status: cloud.RunStatusQueued,
		MaxAttempts: 3, CreatedAt: now.Add(-1 * time.Second), UpdatedAt: now,
	}

	if err := s.EnqueueRun(ctx, run1); err != nil {
		t.Fatalf("EnqueueRun(1): %v", err)
	}
	if err := s.EnqueueRun(ctx, run2); err != nil {
		t.Fatalf("EnqueueRun(2): %v", err)
	}

	// First claim gets the oldest.
	claimed, err := s.ClaimRun(ctx, "worker-1")
	if err != nil {
		t.Fatalf("ClaimRun: %v", err)
	}
	if claimed.ID != "run-oldest-001" {
		t.Errorf("first claim: got %q, want run-oldest-001", claimed.ID)
	}
	if claimed.Status != cloud.RunStatusClaimed {
		t.Errorf("first claim status = %q, want claimed", claimed.Status)
	}

	// Second claim gets the next.
	claimed2, err := s.ClaimRun(ctx, "worker-2")
	if err != nil {
		t.Fatalf("ClaimRun(second): %v", err)
	}
	if claimed2.ID != "run-oldest-002" {
		t.Errorf("second claim: got %q, want run-oldest-002", claimed2.ID)
	}

	// No more runs — ErrNotFound.
	_, err = s.ClaimRun(ctx, "worker-3")
	if !cloud.IsNotFound(err) {
		t.Errorf("ClaimRun(empty): got %v, want ErrNotFound", err)
	}
}

func TestClaimOneWinnerParallel(t *testing.T) {
	// SQLite serializes writes via its single-writer lock, so parallel claims
	// are effectively serialized. This test verifies exactly one winner.
	s := newTestStore(t)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Second)
	run := &cloud.Run{
		ID: "run-parallel-001", Repo: "r", BaseBranch: "main", Engine: "e",
		AuthProfileID: "a", ScopeRef: "s", Status: cloud.RunStatusQueued,
		MaxAttempts: 3, CreatedAt: now, UpdatedAt: now,
	}
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
			} else {
				t.Errorf("unexpected error from worker %s: %v", workerID, err)
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

func TestClaimEmptyReturnsNotFound(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	_, err := s.ClaimRun(ctx, "worker-1")
	if !cloud.IsNotFound(err) {
		t.Errorf("ClaimRun(empty store): got %v, want ErrNotFound", err)
	}
}

// --- Focused auth lock tests ---

func TestAcquireLockConflict(t *testing.T) {
	s, db := newTestStoreWithDB(t)
	ctx := context.Background()

	// Setup: create auth profile and two runs.
	insertAuthProfile(t, db, "auth-lock-001")
	now := time.Now().UTC().Truncate(time.Second)

	run1 := &cloud.Run{
		ID: "run-lock-001", Repo: "r", BaseBranch: "main", Engine: "e",
		AuthProfileID: "auth-lock-001", ScopeRef: "s", Status: cloud.RunStatusQueued,
		MaxAttempts: 3, CreatedAt: now, UpdatedAt: now,
	}
	run2 := &cloud.Run{
		ID: "run-lock-002", Repo: "r", BaseBranch: "main", Engine: "e",
		AuthProfileID: "auth-lock-001", ScopeRef: "s", Status: cloud.RunStatusQueued,
		MaxAttempts: 3, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.EnqueueRun(ctx, run1); err != nil {
		t.Fatalf("EnqueueRun(1): %v", err)
	}
	if err := s.EnqueueRun(ctx, run2); err != nil {
		t.Fatalf("EnqueueRun(2): %v", err)
	}

	// Acquire lock for run1 — should succeed.
	lock1 := &cloud.AuthProfileLock{
		AuthProfileID:  "auth-lock-001",
		RunID:          "run-lock-001",
		WorkerID:       "worker-1",
		AcquiredAt:     now,
		HeartbeatAt:    now,
		LeaseExpiresAt: now.Add(30 * time.Second),
	}
	if err := s.AcquireAuthLock(ctx, lock1); err != nil {
		t.Fatalf("AcquireAuthLock(first): %v", err)
	}

	// Duplicate lock for same (auth_profile_id, run_id) should conflict.
	lock1Dup := &cloud.AuthProfileLock{
		AuthProfileID:  "auth-lock-001",
		RunID:          "run-lock-001",
		WorkerID:       "worker-2",
		AcquiredAt:     now,
		HeartbeatAt:    now,
		LeaseExpiresAt: now.Add(30 * time.Second),
	}
	err := s.AcquireAuthLock(ctx, lock1Dup)
	if !cloud.IsConflict(err) {
		t.Errorf("AcquireAuthLock(duplicate): got %v, want ErrConflict", err)
	}

	// Different run_id on same auth profile should succeed.
	lock2 := &cloud.AuthProfileLock{
		AuthProfileID:  "auth-lock-001",
		RunID:          "run-lock-002",
		WorkerID:       "worker-2",
		AcquiredAt:     now,
		HeartbeatAt:    now,
		LeaseExpiresAt: now.Add(30 * time.Second),
	}
	if err := s.AcquireAuthLock(ctx, lock2); err != nil {
		t.Fatalf("AcquireAuthLock(different run): %v", err)
	}
}

func TestRenewLockExpired(t *testing.T) {
	s, db := newTestStoreWithDB(t)
	ctx := context.Background()

	insertAuthProfile(t, db, "auth-renew-001")
	now := time.Now().UTC().Truncate(time.Second)

	run := &cloud.Run{
		ID: "run-renew-001", Repo: "r", BaseBranch: "main", Engine: "e",
		AuthProfileID: "auth-renew-001", ScopeRef: "s", Status: cloud.RunStatusQueued,
		MaxAttempts: 3, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.EnqueueRun(ctx, run); err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}

	// Acquire lock with a lease that expires in the past (already expired).
	lock := &cloud.AuthProfileLock{
		AuthProfileID:  "auth-renew-001",
		RunID:          "run-renew-001",
		WorkerID:       "worker-1",
		AcquiredAt:     now.Add(-60 * time.Second),
		HeartbeatAt:    now.Add(-60 * time.Second),
		LeaseExpiresAt: now.Add(-30 * time.Second), // expired 30s ago
	}
	if err := s.AcquireAuthLock(ctx, lock); err != nil {
		t.Fatalf("AcquireAuthLock: %v", err)
	}

	// Renew should fail with ErrLeaseExpired because lease_expires_at < now.
	newHeartbeat := now
	newLease := now.Add(30 * time.Second)
	err := s.RenewAuthLock(ctx, "auth-renew-001", "run-renew-001", newHeartbeat, newLease)
	if !cloud.IsLeaseExpired(err) {
		t.Errorf("RenewAuthLock(expired): got %v, want ErrLeaseExpired", err)
	}
}

func TestRenewLockSuccess(t *testing.T) {
	s, db := newTestStoreWithDB(t)
	ctx := context.Background()

	insertAuthProfile(t, db, "auth-rs-001")
	now := time.Now().UTC().Truncate(time.Second)

	run := &cloud.Run{
		ID: "run-rs-001", Repo: "r", BaseBranch: "main", Engine: "e",
		AuthProfileID: "auth-rs-001", ScopeRef: "s", Status: cloud.RunStatusQueued,
		MaxAttempts: 3, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.EnqueueRun(ctx, run); err != nil {
		t.Fatalf("EnqueueRun: %v", err)
	}

	// Acquire lock with valid future lease.
	lock := &cloud.AuthProfileLock{
		AuthProfileID:  "auth-rs-001",
		RunID:          "run-rs-001",
		WorkerID:       "worker-1",
		AcquiredAt:     now,
		HeartbeatAt:    now,
		LeaseExpiresAt: now.Add(30 * time.Second),
	}
	if err := s.AcquireAuthLock(ctx, lock); err != nil {
		t.Fatalf("AcquireAuthLock: %v", err)
	}

	// Renew should succeed.
	newHeartbeat := now.Add(10 * time.Second)
	newLease := now.Add(40 * time.Second)
	if err := s.RenewAuthLock(ctx, "auth-rs-001", "run-rs-001", newHeartbeat, newLease); err != nil {
		t.Fatalf("RenewAuthLock: %v", err)
	}
}

func TestRenewLockNotFound(t *testing.T) {
	s, db := newTestStoreWithDB(t)
	ctx := context.Background()

	insertAuthProfile(t, db, "auth-rnf-001")
	now := time.Now().UTC().Truncate(time.Second)

	// Renew on non-existent lock returns ErrNotFound.
	err := s.RenewAuthLock(ctx, "auth-rnf-001", "run-does-not-exist", now, now.Add(30*time.Second))
	if !cloud.IsNotFound(err) {
		t.Errorf("RenewAuthLock(non-existent): got %v, want ErrNotFound", err)
	}
}

func TestStaleLockReclaim(t *testing.T) {
	s, db := newTestStoreWithDB(t)
	ctx := context.Background()

	insertAuthProfile(t, db, "auth-stale-001")
	now := time.Now().UTC().Truncate(time.Second)

	run1 := &cloud.Run{
		ID: "run-stale-001", Repo: "r", BaseBranch: "main", Engine: "e",
		AuthProfileID: "auth-stale-001", ScopeRef: "s", Status: cloud.RunStatusQueued,
		MaxAttempts: 3, CreatedAt: now, UpdatedAt: now,
	}
	run2 := &cloud.Run{
		ID: "run-stale-002", Repo: "r", BaseBranch: "main", Engine: "e",
		AuthProfileID: "auth-stale-001", ScopeRef: "s", Status: cloud.RunStatusQueued,
		MaxAttempts: 3, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.EnqueueRun(ctx, run1); err != nil {
		t.Fatalf("EnqueueRun(1): %v", err)
	}
	if err := s.EnqueueRun(ctx, run2); err != nil {
		t.Fatalf("EnqueueRun(2): %v", err)
	}

	// Acquire stale lock for run1 (expired lease).
	staleLock := &cloud.AuthProfileLock{
		AuthProfileID:  "auth-stale-001",
		RunID:          "run-stale-001",
		WorkerID:       "worker-1",
		AcquiredAt:     now.Add(-120 * time.Second),
		HeartbeatAt:    now.Add(-120 * time.Second),
		LeaseExpiresAt: now.Add(-60 * time.Second), // expired 60s ago
	}
	if err := s.AcquireAuthLock(ctx, staleLock); err != nil {
		t.Fatalf("AcquireAuthLock(stale): %v", err)
	}

	// Release the stale lock (simulating reconciler cleanup).
	releaseTime := now
	if err := s.ReleaseAuthLock(ctx, "auth-stale-001", "run-stale-001", releaseTime); err != nil {
		t.Fatalf("ReleaseAuthLock(stale): %v", err)
	}

	// After release, a new lock for a different run should succeed.
	newLock := &cloud.AuthProfileLock{
		AuthProfileID:  "auth-stale-001",
		RunID:          "run-stale-002",
		WorkerID:       "worker-2",
		AcquiredAt:     now,
		HeartbeatAt:    now,
		LeaseExpiresAt: now.Add(30 * time.Second),
	}
	if err := s.AcquireAuthLock(ctx, newLock); err != nil {
		t.Fatalf("AcquireAuthLock(after release): %v", err)
	}

	// The original run1 can also re-acquire since the old lock was released.
	reclaimLock := &cloud.AuthProfileLock{
		AuthProfileID:  "auth-stale-001",
		RunID:          "run-stale-001",
		WorkerID:       "worker-3",
		AcquiredAt:     now,
		HeartbeatAt:    now,
		LeaseExpiresAt: now.Add(30 * time.Second),
	}
	if err := s.AcquireAuthLock(ctx, reclaimLock); err != nil {
		t.Fatalf("AcquireAuthLock(reclaim after release): %v", err)
	}
}

func TestReleaseLockNotFound(t *testing.T) {
	s, db := newTestStoreWithDB(t)
	ctx := context.Background()

	insertAuthProfile(t, db, "auth-relnf-001")
	now := time.Now().UTC().Truncate(time.Second)

	// Release non-existent lock returns ErrNotFound.
	err := s.ReleaseAuthLock(ctx, "auth-relnf-001", "run-does-not-exist", now)
	if !cloud.IsNotFound(err) {
		t.Errorf("ReleaseAuthLock(non-existent): got %v, want ErrNotFound", err)
	}
}
