//go:build integration

package postgres

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/cloud"
	"github.com/jywlabs/hal/internal/cloud/storetest"
)

func TestBenchmarkClaimContention(t *testing.T) {
	cfg := storetest.DefaultBenchmarkConfig()

	newStore := func() cloud.Store {
		return newTestStore(t)
	}

	result := storetest.BenchmarkClaimContention(newStore, "postgres", cfg)

	if result.Scenario != "claim_contention" {
		t.Errorf("scenario = %q, want %q", result.Scenario, "claim_contention")
	}
	if result.Adapter != "postgres" {
		t.Errorf("adapter = %q, want %q", result.Adapter, "postgres")
	}
	if result.Runs != cfg.NumRuns {
		t.Errorf("runs = %d, want %d", result.Runs, cfg.NumRuns)
	}
	if result.DuplicateClaims != 0 {
		t.Errorf("duplicate_claims = %d, want 0", result.DuplicateClaims)
	}
	if result.Errors != 0 {
		t.Errorf("errors = %d, want 0", result.Errors)
	}

	data, err := result.JSON()
	if err != nil {
		t.Fatalf("JSON marshal: %v", err)
	}
	assertBenchmarkJSONKeys(t, data)

	writeReportArtifact(t, "postgres_claim_contention", data)
}

func TestBenchmarkAuthLockContention(t *testing.T) {
	cfg := storetest.DefaultBenchmarkConfig()

	// Create store once with DB access for auth profile setup.
	s, db := newTestStoreWithDB(t)

	newStore := func() cloud.Store {
		return s
	}

	setupAuthProfile := func(id string) {
		insertAuthProfile(t, db, id)
	}

	result := storetest.BenchmarkAuthLockContention(newStore, setupAuthProfile, "postgres", cfg)

	if result.Scenario != "auth_lock_contention" {
		t.Errorf("scenario = %q, want %q", result.Scenario, "auth_lock_contention")
	}
	if result.Adapter != "postgres" {
		t.Errorf("adapter = %q, want %q", result.Adapter, "postgres")
	}
	if result.LockOvercommitViolations != 0 {
		t.Errorf("lock_overcommit_violations = %d, want 0", result.LockOvercommitViolations)
	}
	if result.Errors != 0 {
		t.Errorf("errors = %d, want 0", result.Errors)
	}

	data, err := result.JSON()
	if err != nil {
		t.Fatalf("JSON marshal: %v", err)
	}
	assertBenchmarkJSONKeys(t, data)

	writeReportArtifact(t, "postgres_auth_lock_contention", data)
}

// assertBenchmarkJSONKeys verifies that the JSON output contains exactly the
// required keys per the acceptance criteria.
func assertBenchmarkJSONKeys(t *testing.T, data []byte) {
	t.Helper()

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("JSON unmarshal: %v", err)
	}

	requiredKeys := []string{
		"scenario", "adapter", "runs", "errors",
		"claim_p95_ms", "heartbeat_p95_ms",
		"duplicate_claims", "lock_overcommit_violations",
	}

	for _, key := range requiredKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing required JSON key %q", key)
		}
	}

	if len(raw) != len(requiredKeys) {
		t.Errorf("JSON has %d keys, want exactly %d", len(raw), len(requiredKeys))
	}
}

// writeReportArtifact writes a benchmark report to a temp directory.
func writeReportArtifact(t *testing.T, name string, data []byte) {
	t.Helper()

	dir := filepath.Join(t.TempDir(), "reports")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	filename := filepath.Join(dir, name+"_"+time.Now().Format("2006-01-02T15-04-05")+".json")
	if err := os.WriteFile(filename, data, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Logf("Report artifact written to %s", filename)
}
