// Package storetest provides adapter-neutral contract tests and benchmarks
// for the cloud.Store interface.
package storetest

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
)

// BenchmarkResult contains the output of a single benchmark scenario run.
// Field names match the required JSON output contract exactly.
type BenchmarkResult struct {
	Scenario                 string  `json:"scenario"`
	Adapter                  string  `json:"adapter"`
	Runs                     int     `json:"runs"`
	Errors                   int     `json:"errors"`
	ClaimP95Ms               float64 `json:"claim_p95_ms"`
	HeartbeatP95Ms           float64 `json:"heartbeat_p95_ms"`
	DuplicateClaims          int     `json:"duplicate_claims"`
	LockOvercommitViolations int     `json:"lock_overcommit_violations"`
}

// JSON returns the indented JSON representation of the result.
func (r *BenchmarkResult) JSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// BenchmarkConfig controls the parameters of a benchmark run.
type BenchmarkConfig struct {
	// NumRuns is the number of runs to enqueue for the claim_contention scenario.
	NumRuns int
	// NumWorkers is the number of concurrent workers contending for claims.
	NumWorkers int
	// NumLockAttempts is the number of concurrent lock acquire attempts
	// for the auth_lock_contention scenario.
	NumLockAttempts int
}

// DefaultBenchmarkConfig returns sensible defaults for benchmark runs.
func DefaultBenchmarkConfig() BenchmarkConfig {
	return BenchmarkConfig{
		NumRuns:         20,
		NumWorkers:      10,
		NumLockAttempts: 10,
	}
}

// BenchmarkClaimContention runs the claim_contention scenario.
func BenchmarkClaimContention(newStore func() cloud.Store, adapter string, cfg BenchmarkConfig) *BenchmarkResult {
	ctx := context.Background()
	s := newStore()

	now := time.Now().UTC().Truncate(time.Second)

	// Enqueue runs with staggered created_at for deterministic ordering.
	for i := range cfg.NumRuns {
		run := &cloud.Run{
			ID:            fmt.Sprintf("bench-claim-%03d", i),
			Repo:          "bench/repo",
			BaseBranch:    "main",
			WorkflowKind:  cloud.WorkflowKindRun,
			Engine:        "claude",
			AuthProfileID: "bench-auth",
			ScopeRef:      "bench-scope",
			Status:        cloud.RunStatusQueued,
			MaxAttempts:   3,
			CreatedAt:     now.Add(-time.Duration(cfg.NumRuns-i) * time.Second),
			UpdatedAt:     now,
		}
		if err := s.EnqueueRun(ctx, run); err != nil {
			return &BenchmarkResult{
				Scenario: "claim_contention",
				Adapter:  adapter,
				Errors:   1,
			}
		}
	}

	var (
		mu              sync.Mutex
		claimLatencies  []float64
		winners         atomic.Int32
		notFound        atomic.Int32
		errors          atomic.Int32
		duplicateClaims atomic.Int32
		wg              sync.WaitGroup
	)

	// Track which runs were claimed to detect duplicate claims.
	claimedRuns := make(map[string]bool)
	var claimedMu sync.Mutex

	// Launch workers to race for claims.
	wg.Add(cfg.NumWorkers)
	for w := range cfg.NumWorkers {
		go func(workerID string) {
			defer wg.Done()
			// Each worker claims until no more runs are available.
			for {
				start := time.Now()
				claimed, err := s.ClaimRun(ctx, workerID)
				elapsed := time.Since(start)

				if err != nil {
					if cloud.IsNotFound(err) {
						notFound.Add(1)
						return
					}
					errors.Add(1)
					return
				}

				winners.Add(1)
				mu.Lock()
				claimLatencies = append(claimLatencies, float64(elapsed.Microseconds())/1000.0)
				mu.Unlock()

				claimedMu.Lock()
				if claimedRuns[claimed.ID] {
					duplicateClaims.Add(1)
				}
				claimedRuns[claimed.ID] = true
				claimedMu.Unlock()
			}
		}(fmt.Sprintf("worker-%d", w))
	}
	wg.Wait()

	// Also measure heartbeat latency: create attempts for claimed runs and heartbeat them.
	var heartbeatLatencies []float64
	claimedMu.Lock()
	claimedIDs := make([]string, 0, len(claimedRuns))
	for id := range claimedRuns {
		claimedIDs = append(claimedIDs, id)
	}
	claimedMu.Unlock()

	for i, runID := range claimedIDs {
		// Transition to running first.
		_ = s.TransitionRun(ctx, runID, cloud.RunStatusClaimed, cloud.RunStatusRunning)

		att := &cloud.Attempt{
			ID:             fmt.Sprintf("bench-att-%03d", i),
			RunID:          runID,
			AttemptNumber:  1,
			WorkerID:       "bench-worker",
			Status:         cloud.AttemptStatusActive,
			StartedAt:      now,
			HeartbeatAt:    now,
			LeaseExpiresAt: now.Add(30 * time.Second),
		}
		if err := s.CreateAttempt(ctx, att); err != nil {
			continue
		}

		start := time.Now()
		hbTime := time.Now().UTC().Truncate(time.Second)
		_ = s.HeartbeatAttempt(ctx, att.ID, hbTime, hbTime.Add(30*time.Second))
		elapsed := time.Since(start)
		heartbeatLatencies = append(heartbeatLatencies, float64(elapsed.Microseconds())/1000.0)
	}

	return &BenchmarkResult{
		Scenario:                 "claim_contention",
		Adapter:                  adapter,
		Runs:                     int(winners.Load()),
		Errors:                   int(errors.Load()),
		ClaimP95Ms:               percentile(claimLatencies, 95),
		HeartbeatP95Ms:           percentile(heartbeatLatencies, 95),
		DuplicateClaims:          int(duplicateClaims.Load()),
		LockOvercommitViolations: 0, // Not applicable to claim_contention scenario
	}
}

// BenchmarkAuthLockContention runs the auth_lock_contention scenario.
// It creates a single auth profile and has NumLockAttempts workers race to
// acquire a lock on it, measuring contention behavior.
func BenchmarkAuthLockContention(newStore func() cloud.Store, setupAuthProfile func(id string), adapter string, cfg BenchmarkConfig) *BenchmarkResult {
	ctx := context.Background()
	s := newStore()

	now := time.Now().UTC().Truncate(time.Second)
	profileID := "bench-lock-profile"

	// Setup the auth profile via caller-provided function (adapter-specific).
	setupAuthProfile(profileID)

	// Enqueue runs — one per lock attempt so each has a valid run_id FK.
	for i := range cfg.NumLockAttempts {
		run := &cloud.Run{
			ID:            fmt.Sprintf("bench-lock-run-%03d", i),
			Repo:          "bench/repo",
			BaseBranch:    "main",
			WorkflowKind:  cloud.WorkflowKindRun,
			Engine:        "claude",
			AuthProfileID: profileID,
			ScopeRef:      "bench-scope",
			Status:        cloud.RunStatusQueued,
			MaxAttempts:   3,
			CreatedAt:     now.Add(-time.Duration(cfg.NumLockAttempts-i) * time.Second),
			UpdatedAt:     now,
		}
		if err := s.EnqueueRun(ctx, run); err != nil {
			return &BenchmarkResult{
				Scenario: "auth_lock_contention",
				Adapter:  adapter,
				Errors:   1,
			}
		}
	}

	var (
		mu                       sync.Mutex
		claimLatencies           []float64
		heartbeatLatencies       []float64
		lockErrors               atomic.Int32
		lockWinners              atomic.Int32
		lockConflicts            atomic.Int32
		lockOvercommitViolations atomic.Int32
		wg                       sync.WaitGroup
	)

	// Track winners per auth profile to detect lock exclusivity violations.
	acquiredLocks := make(map[string]bool)
	var acquiredMu sync.Mutex

	// Each worker tries to acquire a lock on the same profile with different run IDs.
	wg.Add(cfg.NumLockAttempts)
	for i := range cfg.NumLockAttempts {
		go func(idx int) {
			defer wg.Done()
			runID := fmt.Sprintf("bench-lock-run-%03d", idx)
			workerID := fmt.Sprintf("lock-worker-%d", idx)

			lock := &cloud.AuthProfileLock{
				AuthProfileID:  profileID,
				RunID:          runID,
				WorkerID:       workerID,
				AcquiredAt:     now,
				HeartbeatAt:    now,
				LeaseExpiresAt: now.Add(30 * time.Second),
			}

			start := time.Now()
			err := s.AcquireAuthLock(ctx, lock)
			elapsed := time.Since(start)

			if err != nil {
				if cloud.IsConflict(err) {
					lockConflicts.Add(1)
				} else {
					lockErrors.Add(1)
				}
				return
			}

			lockWinners.Add(1)
			mu.Lock()
			claimLatencies = append(claimLatencies, float64(elapsed.Microseconds())/1000.0)
			mu.Unlock()

			acquiredMu.Lock()
			key := profileID
			if acquiredLocks[key] {
				lockOvercommitViolations.Add(1)
			}
			acquiredLocks[key] = true
			acquiredMu.Unlock()

			// Measure heartbeat (renew) latency.
			hbStart := time.Now()
			hbTime := time.Now().UTC().Truncate(time.Second)
			err = s.RenewAuthLock(ctx, profileID, runID, hbTime, hbTime.Add(30*time.Second))
			hbElapsed := time.Since(hbStart)

			if err == nil {
				mu.Lock()
				heartbeatLatencies = append(heartbeatLatencies, float64(hbElapsed.Microseconds())/1000.0)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	return &BenchmarkResult{
		Scenario:                 "auth_lock_contention",
		Adapter:                  adapter,
		Runs:                     int(lockWinners.Load()),
		Errors:                   int(lockErrors.Load()),
		ClaimP95Ms:               percentile(claimLatencies, 95),
		HeartbeatP95Ms:           percentile(heartbeatLatencies, 95),
		DuplicateClaims:          0, // Not applicable to auth_lock_contention
		LockOvercommitViolations: int(lockOvercommitViolations.Load()),
	}
}

// percentile computes the p-th percentile of a sorted float64 slice.
// Returns 0 if the slice is empty.
func percentile(data []float64, p float64) float64 {
	if len(data) == 0 {
		return 0
	}
	sorted := make([]float64, len(data))
	copy(sorted, data)
	sort.Float64s(sorted)

	rank := p / 100.0 * float64(len(sorted)-1)
	lower := int(math.Floor(rank))
	upper := int(math.Ceil(rank))

	if lower == upper {
		return sorted[lower]
	}
	// Linear interpolation between lower and upper bounds.
	frac := rank - float64(lower)
	return sorted[lower]*(1-frac) + sorted[upper]*frac
}
