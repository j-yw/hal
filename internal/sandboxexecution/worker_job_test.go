package sandboxexecution

import (
	"encoding/json"
	"os"
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

func TestWorkerJobReferenceLoadFailsClosedOnInvalidDurableMetadata(t *testing.T) {
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	store := NewStore(filepath.Join(t.TempDir(), "executions"))
	manifest := testManifest("exec-corrupt-worker-job", now)
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	path, err := store.ManifestPath(manifest.ID)
	if err != nil {
		t.Fatalf("ManifestPath() error: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error: %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal() error: %v", err)
	}
	raw["workerJob"] = map[string]any{
		"contractVersion": WorkerJobContractVersion,
		"jobId":           "/private/recovery/handle",
		"workerId":        "worker-safe",
		"runtimeDriver":   "rootless_podman",
		"state":           "running",
		"submittedAt":     now,
		"startedAt":       now,
	}
	data, err = json.Marshal(raw)
	if err != nil {
		t.Fatalf("json.Marshal() error: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	loaded, err := store.LoadManifest(manifest.ID)
	if err == nil {
		t.Fatalf("LoadManifest() = %#v, want invalid workerJob error", loaded)
	}
	if strings.Contains(err.Error(), "/private/recovery/handle") {
		t.Fatalf("LoadManifest() error exposed unsafe workerJob value: %v", err)
	}
}

func TestWorkerJobReferenceRejectsIncoherentLifecycle(t *testing.T) {
	now := time.Date(2026, time.July, 24, 12, 0, 0, 0, time.UTC)
	before := now.Add(-time.Second)
	after := now.Add(time.Second)
	tests := []struct {
		name      string
		state     string
		started   *time.Time
		heartbeat *time.Time
		finished  *time.Time
	}{
		{name: "queued with start", state: "queued", started: &now},
		{name: "running without start", state: "running"},
		{name: "running with finish", state: "running", started: &now, finished: &after},
		{name: "terminal without finish", state: "succeeded", started: &now},
		{name: "successful without start", state: "succeeded", finished: &after},
		{name: "start before submission", state: "running", started: &before},
		{name: "heartbeat before start", state: "running", started: &now, heartbeat: &before},
		{name: "finish before heartbeat", state: "failed", started: &now, heartbeat: &after, finished: &now},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := testManifest("exec-worker-job-lifecycle", now)
			manifest.WorkerJob = &WorkerJobReference{
				ContractVersion: WorkerJobContractVersion,
				JobID:           "job-safe",
				WorkerID:        "worker-safe",
				RuntimeDriver:   "rootless_podman",
				State:           test.state,
				SubmittedAt:     now,
				StartedAt:       test.started,
				HeartbeatAt:     test.heartbeat,
				FinishedAt:      test.finished,
			}
			store := NewStore(filepath.Join(t.TempDir(), "executions"))
			if err := store.SaveManifest(manifest); err == nil {
				t.Fatal("SaveManifest() accepted incoherent workerJob lifecycle")
			}
		})
	}
}
