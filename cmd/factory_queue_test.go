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

func TestRunFactoryQueueListWithDepsJSONOutputEmptyQueue(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))

	var out bytes.Buffer
	err := runFactoryQueueListWithDeps(&out, factoryQueueListRequest{JSON: true}, queueListTestDeps(store))
	if err != nil {
		t.Fatalf("runFactoryQueueListWithDeps() unexpected error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal output error: %v\n%s", err, out.String())
	}
	requireExactKeys(t, raw, []string{"contractVersion", "entries", "summary"})
	if raw["contractVersion"] != FactoryQueueListContractVersion {
		t.Fatalf("contractVersion = %v, want %q", raw["contractVersion"], FactoryQueueListContractVersion)
	}

	var resp FactoryQueueListResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v", err)
	}
	if len(resp.Entries) != 0 {
		t.Fatalf("entries len = %d, want 0: %#v", len(resp.Entries), resp.Entries)
	}
	if resp.Summary != "0 queue entries" {
		t.Fatalf("summary = %q, want empty queue summary", resp.Summary)
	}
}

func TestRunFactoryQueueListWithDepsJSONOutputIncludesFIFOEntries(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 15, 0, 0, 0, time.UTC)
	claimedAt := base.Add(5 * time.Minute)
	completedAt := base.Add(15 * time.Minute)
	entries := []factory.QueueEntry{
		testFactoryQueueEntry("queue-queued-new", "run-new", factory.QueueStatusQueued, base.Add(10*time.Minute)),
		testFactoryQueueEntry("queue-failed-old", "run-failed", factory.QueueStatusFailed, base.Add(-10*time.Minute)),
		testFactoryQueueEntry("queue-claimed-tie-b", "run-claimed-b", factory.QueueStatusClaimed, base),
		testFactoryQueueEntry("queue-queued-tie-a", "run-queued-a", factory.QueueStatusQueued, base),
	}
	entries[1].ClaimedAt = &claimedAt
	entries[1].CompletedAt = &completedAt
	entries[1].Claim = &factory.QueueClaim{WorkerID: "worker-list", PID: 4242, Hostname: "factory-host"}
	entries[1].AttemptCount = 1
	entries[1].LastError = "unit tests failed"
	entries[2].ClaimedAt = &claimedAt
	entries[2].Claim = &factory.QueueClaim{WorkerID: "worker-list", PID: 4243, Hostname: "factory-host"}
	entries[2].AttemptCount = 1
	if err := store.SaveQueue(entries); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	var out bytes.Buffer
	err := runFactoryQueueListWithDeps(&out, factoryQueueListRequest{JSON: true}, queueListTestDeps(store))
	if err != nil {
		t.Fatalf("runFactoryQueueListWithDeps() unexpected error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal output error: %v\n%s", err, out.String())
	}
	requireExactKeys(t, raw, []string{"contractVersion", "entries", "summary"})

	rawEntries, ok := raw["entries"].([]any)
	if !ok {
		t.Fatalf("entries should be array, got %T", raw["entries"])
	}
	if len(rawEntries) != 4 {
		t.Fatalf("entries len = %d, want 4", len(rawEntries))
	}
	var queuedEntry map[string]any
	for _, rawEntry := range rawEntries {
		entry, ok := rawEntry.(map[string]any)
		if !ok {
			t.Fatalf("entry should be object, got %T", rawEntry)
		}
		if entry["queueId"] == "queue-queued-new" {
			queuedEntry = entry
			break
		}
	}
	if queuedEntry == nil {
		t.Fatalf("raw entries missing queue-queued-new: %#v", rawEntries)
	}
	requireExactKeys(t, queuedEntry, []string{"queueId", "runId", "executorMode", "status", "createdAt", "attemptCount"})

	var resp FactoryQueueListResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v", err)
	}
	gotQueueIDs := []string{}
	gotStatuses := map[string]bool{}
	for _, entry := range resp.Entries {
		gotQueueIDs = append(gotQueueIDs, entry.QueueID)
		gotStatuses[entry.Status] = true
	}
	wantQueueIDs := []string{"queue-failed-old", "queue-claimed-tie-b", "queue-queued-tie-a", "queue-queued-new"}
	if strings.Join(gotQueueIDs, ",") != strings.Join(wantQueueIDs, ",") {
		t.Fatalf("queue IDs = %v, want FIFO %v", gotQueueIDs, wantQueueIDs)
	}
	for _, status := range []string{factory.QueueStatusQueued, factory.QueueStatusClaimed, factory.QueueStatusFailed} {
		if !gotStatuses[status] {
			t.Fatalf("entries missing status %q: %#v", status, resp.Entries)
		}
	}
	if resp.Summary != "4 queue entries" {
		t.Fatalf("summary = %q, want 4 queue entries", resp.Summary)
	}
}

func TestRunFactoryQueueListWithDepsHumanOutput(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 16, 0, 0, 0, time.UTC)
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-human-001", "run-human", factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	var out bytes.Buffer
	err := runFactoryQueueListWithDeps(&out, factoryQueueListRequest{}, queueListTestDeps(store))
	if err != nil {
		t.Fatalf("runFactoryQueueListWithDeps() unexpected error: %v", err)
	}

	got := out.String()
	for _, want := range []string{"1 queue entry", "queue-human-001\trun-human\tlocal\tqueued"} {
		if !strings.Contains(got, want) {
			t.Fatalf("output = %q, want fragment %q", got, want)
		}
	}
}

func queueAddTestDeps(store factory.Store, now time.Time, queueID string) factoryQueueAddDeps {
	return factoryQueueAddDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		newQueueID:   func() (string, error) { return queueID, nil },
	}
}

func queueListTestDeps(store factory.Store) factoryQueueListDeps {
	return factoryQueueListDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	}
}

func testFactoryQueueEntry(queueID, runID, status string, createdAt time.Time) factory.QueueEntry {
	return factory.QueueEntry{
		QueueID:      queueID,
		RunID:        runID,
		ExecutorMode: factory.ExecutorModeLocal,
		Status:       status,
		CreatedAt:    createdAt,
		AttemptCount: 0,
	}
}
