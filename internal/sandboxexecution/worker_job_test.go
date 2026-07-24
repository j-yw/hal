package sandboxexecution

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWorkerJobReferenceRoundTripsThroughManifestStore(t *testing.T) {
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	manifest := testManifest("exec-worker-job", now)
	manifest.WorkerJob = &WorkerJobReference{
		ContractVersion: WorkerJobContractVersion,
		JobID:           "job-safe",
		WorkerID:        "worker-safe",
		HostID:          "host-safe",
		RuntimeDriver:   "rootless_podman",
		RuntimeID:       "runtime-safe",
		State:           "running",
		SubmittedAt:     now,
		StartedAt:       &now,
		HeartbeatAt:     &now,
		LogCursor:       7,
	}
	store := NewStore(filepath.Join(t.TempDir(), "executions"))
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	loaded, err := store.LoadManifest(manifest.ID)
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if loaded.WorkerJob == nil || loaded.WorkerJob.JobID != "job-safe" || loaded.WorkerJob.LogCursor != 7 {
		t.Fatalf("loaded worker job = %#v, want durable safe reference", loaded.WorkerJob)
	}
}

func TestWorkerJobReferenceRejectsUnsafeMetadata(t *testing.T) {
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	for _, unsafe := range []string{
		"/tmp/private/job",
		"https://worker.example.test/job",
		"token=secret-value",
		"worker id with spaces",
	} {
		manifest := testManifest("exec-unsafe-"+strings.NewReplacer("/", "-", ":", "-", "=", "-", " ", "-").Replace(unsafe), now)
		manifest.WorkerJob = &WorkerJobReference{
			ContractVersion: WorkerJobContractVersion,
			JobID:           unsafe,
			WorkerID:        "worker-safe",
			RuntimeDriver:   "rootless_podman",
			State:           "running",
			SubmittedAt:     now,
		}
		store := NewStore(filepath.Join(t.TempDir(), "executions"))
		if err := store.SaveManifest(manifest); err == nil {
			t.Fatalf("SaveManifest() accepted unsafe worker job ID %q", unsafe)
		}
	}
}

func TestWorkerJobReferenceJSONContainsOnlySafeContractFields(t *testing.T) {
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	reference := &WorkerJobReference{
		ContractVersion: WorkerJobContractVersion,
		JobID:           "job-safe",
		WorkerID:        "worker-safe",
		RuntimeDriver:   "rootless_podman",
		State:           "queued",
		SubmittedAt:     now,
	}
	payload, err := json.Marshal(reference)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	content := string(payload)
	for _, forbidden := range []string{"command", "args", "env", "stdin", "pid", "path", "endpoint", "credential", "secret"} {
		if strings.Contains(strings.ToLower(content), forbidden) {
			t.Fatalf("worker job reference JSON contains forbidden field marker %q: %s", forbidden, content)
		}
	}
}
