//go:build integration

package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/cloud/storetest"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// testDSN returns the Postgres connection string from environment, or skips the test.
func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("HAL_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("HAL_TEST_POSTGRES_DSN not set, skipping Postgres integration tests")
	}
	return dsn
}

// newTestStore creates a fresh Store with isolated schema for each test.
// It uses a unique schema per test to avoid table conflicts.
func newTestStore(t *testing.T) cloud.Store {
	t.Helper()
	dsn := testDSN(t)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	ctx := context.Background()

	// Create a unique schema for this test to isolate tables.
	schema := fmt.Sprintf("test_%d_%d", time.Now().UnixNano(), os.Getpid())
	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE SCHEMA %s", schema)); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, fmt.Sprintf("SET search_path TO %s", schema)); err != nil {
		t.Fatalf("set search_path: %v", err)
	}
	t.Cleanup(func() {
		db.ExecContext(ctx, fmt.Sprintf("DROP SCHEMA %s CASCADE", schema))
	})

	s := New(db)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

// TestContractSuite runs the full adapter contract test suite against Postgres.
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
