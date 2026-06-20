package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
)

func TestFactoryQueueAddArgsValidationRejectsMissingOperands(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing run ID",
			wantErr: "factory run ID is required",
		},
		{
			name:    "missing executor mode",
			args:    []string{"run-queue-add"},
			wantErr: "factory executor mode is required",
		},
		{
			name:    "too many args",
			args:    []string{"run-queue-add", factory.ExecutorModeLocal, "extra"},
			wantErr: "accepts 2 arg(s), received 3",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			err := validateFactoryQueueAddArgs(nil, tt.args)
			if err == nil {
				t.Fatalf("validateFactoryQueueAddArgs() error = nil, want %q", tt.wantErr)
			}

			var exitErr *ExitCodeError
			if !errors.As(err, &exitErr) {
				t.Fatalf("validateFactoryQueueAddArgs() error type = %T, want *ExitCodeError", err)
			}
			if exitErr.Code != ExitCodeValidation {
				t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateFactoryQueueAddArgs() error = %q, want %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestRunFactoryQueueAddWithDepsCreatesQueueEntryAndRecordsRunState(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	queuedAt := createdAt.Add(5 * time.Minute)
	record := testFactoryRunRecord("run-queue-add", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.RunStatusPending
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var out bytes.Buffer
	err := runFactoryQueueAddWithDeps(&out, factoryQueueAddRequest{
		RunID:        record.RunID,
		ExecutorMode: factory.ExecutorModeLocal,
	}, queueAddTestDeps(store, queuedAt, "queue-add-001"))
	if err != nil {
		t.Fatalf("runFactoryQueueAddWithDeps() unexpected error: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "queued run run-queue-add" {
		t.Fatalf("output = %q, want queued summary", got)
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("queue entries len = %d, want 1: %#v", len(entries), entries)
	}
	entry := entries[0]
	if entry.QueueID != "queue-add-001" {
		t.Fatalf("queueId = %q, want queue-add-001", entry.QueueID)
	}
	if entry.RunID != record.RunID {
		t.Fatalf("runId = %q, want %q", entry.RunID, record.RunID)
	}
	if entry.ExecutorMode != factory.ExecutorModeLocal {
		t.Fatalf("executorMode = %q, want %q", entry.ExecutorMode, factory.ExecutorModeLocal)
	}
	if entry.Status != factory.QueueStatusQueued {
		t.Fatalf("queue status = %q, want %q", entry.Status, factory.QueueStatusQueued)
	}
	if !entry.CreatedAt.Equal(queuedAt) {
		t.Fatalf("createdAt = %s, want %s", entry.CreatedAt, queuedAt)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusPending {
		t.Fatalf("run status = %q, want %q", loaded.Status, factory.RunStatusPending)
	}
	if loaded.CurrentStep != factory.QueueStatusQueued {
		t.Fatalf("currentStep = %q, want %q", loaded.CurrentStep, factory.QueueStatusQueued)
	}
	if !loaded.UpdatedAt.Equal(queuedAt) {
		t.Fatalf("updatedAt = %s, want %s", loaded.UpdatedAt, queuedAt)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{factory.EventTypeCommandOutputSummary})
	if events[0].Summary != "Factory run queued" {
		t.Fatalf("event summary = %q, want queue summary", events[0].Summary)
	}
	if events[0].Metadata["queueId"] != "queue-add-001" {
		t.Fatalf("event queueId = %#v, want queue-add-001", events[0].Metadata["queueId"])
	}
	if events[0].Metadata["executorMode"] != factory.ExecutorModeLocal {
		t.Fatalf("event executorMode = %#v, want local", events[0].Metadata["executorMode"])
	}
	if events[0].Metadata["status"] != factory.QueueStatusQueued {
		t.Fatalf("event status = %#v, want queued", events[0].Metadata["status"])
	}
}

func TestRunFactoryQueueAddWithDepsJSONOutput(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 13, 0, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-queue-add-json", createdAt, createdAt)
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var out bytes.Buffer
	err := runFactoryQueueAddWithDeps(&out, factoryQueueAddRequest{
		RunID:        record.RunID,
		ExecutorMode: factory.ExecutorModeLocal,
		JSON:         true,
	}, queueAddTestDeps(store, createdAt, "queue-add-json-001"))
	if err != nil {
		t.Fatalf("runFactoryQueueAddWithDeps() unexpected error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal output error: %v\n%s", err, out.String())
	}
	requireExactKeys(t, raw, []string{"contractVersion", "entry", "summary"})
	if raw["contractVersion"] != FactoryQueueAddContractVersion {
		t.Fatalf("contractVersion = %v, want %q", raw["contractVersion"], FactoryQueueAddContractVersion)
	}

	var resp FactoryQueueAddResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v", err)
	}
	if resp.Summary != "queued run run-queue-add-json" {
		t.Fatalf("summary = %q, want queued summary", resp.Summary)
	}
	if resp.Entry.QueueID != "queue-add-json-001" {
		t.Fatalf("entry.queueId = %q, want queue-add-json-001", resp.Entry.QueueID)
	}
	if resp.Entry.Status != factory.QueueStatusQueued {
		t.Fatalf("entry.status = %q, want %q", resp.Entry.Status, factory.QueueStatusQueued)
	}
}

func TestRunFactoryQueueAddWithDepsRejectsInvalidExecutorMode(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 14, 0, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-invalid-queue-mode", createdAt, createdAt)
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	err := runFactoryQueueAddWithDeps(io.Discard, factoryQueueAddRequest{
		RunID:        record.RunID,
		ExecutorMode: "remote",
	}, queueAddTestDeps(store, createdAt, "queue-invalid-mode"))
	if err == nil {
		t.Fatal("runFactoryQueueAddWithDeps() error = nil, want invalid executor mode")
	}
	if !strings.Contains(err.Error(), `unsupported factory executor mode "remote" (supported: local)`) {
		t.Fatalf("runFactoryQueueAddWithDeps() error = %q, want unsupported mode", err.Error())
	}

	entries, loadErr := store.LoadQueue()
	if loadErr != nil {
		t.Fatalf("LoadQueue() error: %v", loadErr)
	}
	if len(entries) != 0 {
		t.Fatalf("queue entries len = %d, want 0: %#v", len(entries), entries)
	}
	events, loadErr := store.LoadEvents(record.RunID)
	if loadErr != nil {
		t.Fatalf("LoadEvents() error: %v", loadErr)
	}
	if len(events) != 0 {
		t.Fatalf("events len = %d, want 0: %#v", len(events), events)
	}
}

func queueAddTestDeps(store factory.Store, now time.Time, queueID string) factoryQueueAddDeps {
	return factoryQueueAddDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		newQueueID:   func() (string, error) { return queueID, nil },
	}
}
