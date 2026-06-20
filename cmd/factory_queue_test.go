package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
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

func TestRunFactoryQueueWorkWithDepsJSONOutputNoWork(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	claimedAt := time.Date(2026, 6, 21, 17, 0, 0, 0, time.UTC)
	claim := factory.QueueClaim{WorkerID: "worker-noop", PID: 5252, Hostname: "factory-host"}

	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(&out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDeps(store, claimedAt, claim))
	if err != nil {
		t.Fatalf("runFactoryQueueWorkWithDeps() unexpected error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal output error: %v\n%s", err, out.String())
	}
	requireExactKeys(t, raw, []string{"contractVersion", "claimed", "entry", "summary"})
	if raw["contractVersion"] != FactoryQueueWorkContractVersion {
		t.Fatalf("contractVersion = %v, want %q", raw["contractVersion"], FactoryQueueWorkContractVersion)
	}
	if raw["claimed"] != false {
		t.Fatalf("claimed = %v, want false", raw["claimed"])
	}
	if raw["entry"] != nil {
		t.Fatalf("entry = %#v, want nil", raw["entry"])
	}

	var resp FactoryQueueWorkResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v", err)
	}
	if resp.Summary != "no queued factory work" {
		t.Fatalf("summary = %q, want no-work summary", resp.Summary)
	}
}

func TestRunFactoryQueueWorkWithDepsClaimsOneEntryAndRecordsRunState(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 18, 0, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-claim", PID: 5353, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-queue-work", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-work-001", record.RunID, factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(&out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDeps(store, claimedAt, claim))
	if err != nil {
		t.Fatalf("runFactoryQueueWorkWithDeps() unexpected error: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(out.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal output error: %v\n%s", err, out.String())
	}
	requireExactKeys(t, raw, []string{"contractVersion", "claimed", "entry", "summary"})
	if raw["claimed"] != true {
		t.Fatalf("claimed = %v, want true", raw["claimed"])
	}

	var resp FactoryQueueWorkResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v", err)
	}
	if resp.Summary != "claimed queue entry queue-work-001" {
		t.Fatalf("summary = %q, want claimed summary", resp.Summary)
	}
	if resp.Entry == nil {
		t.Fatal("entry = nil, want claimed entry")
	}
	if resp.Entry.Status != factory.QueueStatusClaimed {
		t.Fatalf("entry.status = %q, want %q", resp.Entry.Status, factory.QueueStatusClaimed)
	}
	if resp.Entry.ClaimedAt == nil || !resp.Entry.ClaimedAt.Equal(claimedAt) {
		t.Fatalf("entry.claimedAt = %v, want %s", resp.Entry.ClaimedAt, claimedAt)
	}
	if resp.Entry.Claim == nil || *resp.Entry.Claim != claim {
		t.Fatalf("entry.claim = %#v, want %#v", resp.Entry.Claim, claim)
	}
	if resp.Entry.AttemptCount != 1 {
		t.Fatalf("entry.attemptCount = %d, want 1", resp.Entry.AttemptCount)
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("queue entries len = %d, want 1: %#v", len(entries), entries)
	}
	if entries[0].Status != factory.QueueStatusClaimed {
		t.Fatalf("queue status = %q, want %q", entries[0].Status, factory.QueueStatusClaimed)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusPending {
		t.Fatalf("run status = %q, want %q", loaded.Status, factory.RunStatusPending)
	}
	if loaded.CurrentStep != factory.QueueStatusClaimed {
		t.Fatalf("currentStep = %q, want %q", loaded.CurrentStep, factory.QueueStatusClaimed)
	}
	if !loaded.UpdatedAt.Equal(claimedAt) {
		t.Fatalf("updatedAt = %s, want %s", loaded.UpdatedAt, claimedAt)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{factory.EventTypeCommandOutputSummary})
	if events[0].Summary != "Factory run claimed" {
		t.Fatalf("event summary = %q, want claim summary", events[0].Summary)
	}
	if events[0].Metadata["queueId"] != "queue-work-001" {
		t.Fatalf("event queueId = %#v, want queue-work-001", events[0].Metadata["queueId"])
	}
	if events[0].Metadata["executorMode"] != factory.ExecutorModeLocal {
		t.Fatalf("event executorMode = %#v, want local", events[0].Metadata["executorMode"])
	}
	if events[0].Metadata["status"] != factory.QueueStatusClaimed {
		t.Fatalf("event status = %#v, want claimed", events[0].Metadata["status"])
	}
	if events[0].Metadata["attemptCount"] != float64(1) && events[0].Metadata["attemptCount"] != 1 {
		t.Fatalf("event attemptCount = %#v, want 1", events[0].Metadata["attemptCount"])
	}
}

func TestRunFactoryQueueWorkWithDepsClaimsFIFOEntry(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 19, 0, 0, 0, time.UTC)
	claimedAt := base.Add(30 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-fifo", PID: 5454, Hostname: "factory-host"}
	for _, runID := range []string{"run-fifo-old", "run-fifo-new"} {
		record := testFactoryRunRecord(runID, base, base)
		record.Status = factory.RunStatusPending
		record.CurrentStep = factory.QueueStatusQueued
		if err := store.SaveRun(&record); err != nil {
			t.Fatalf("SaveRun(%s) error: %v", runID, err)
		}
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-fifo-new", "run-fifo-new", factory.QueueStatusQueued, base.Add(10*time.Minute)),
		testFactoryQueueEntry("queue-fifo-old", "run-fifo-old", factory.QueueStatusQueued, base),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(&out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDeps(store, claimedAt, claim))
	if err != nil {
		t.Fatalf("runFactoryQueueWorkWithDeps() unexpected error: %v", err)
	}

	var resp FactoryQueueWorkResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v\n%s", err, out.String())
	}
	if resp.Entry == nil || resp.Entry.QueueID != "queue-fifo-old" {
		t.Fatalf("claimed entry = %#v, want oldest FIFO entry", resp.Entry)
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	byQueueID := map[string]factory.QueueEntry{}
	for _, entry := range entries {
		byQueueID[entry.QueueID] = entry
	}
	if byQueueID["queue-fifo-old"].Status != factory.QueueStatusClaimed {
		t.Fatalf("old entry status = %q, want claimed", byQueueID["queue-fifo-old"].Status)
	}
	if byQueueID["queue-fifo-new"].Status != factory.QueueStatusQueued {
		t.Fatalf("new entry status = %q, want queued", byQueueID["queue-fifo-new"].Status)
	}
}

func TestRunFactoryQueueWorkWithDepsConcurrentClaimSafety(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 20, 0, 0, 0, time.UTC)
	claimedAt := createdAt.Add(10 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-concurrent", PID: 5555, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-concurrent-work", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-concurrent-001", record.RunID, factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	type workResult struct {
		err  error
		resp FactoryQueueWorkResponse
		raw  string
	}

	const workerCount = 8
	start := make(chan struct{})
	results := make(chan workResult, workerCount)
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			var out bytes.Buffer
			err := runFactoryQueueWorkWithDeps(&out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDeps(store, claimedAt, claim))
			result := workResult{err: err, raw: out.String()}
			if err == nil {
				result.err = json.Unmarshal(out.Bytes(), &result.resp)
			}
			results <- result
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	claimedCount := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("worker error: %v\nraw: %s", result.err, result.raw)
		}
		if result.resp.Claimed {
			claimedCount++
			if result.resp.Entry == nil || result.resp.Entry.QueueID != "queue-concurrent-001" {
				t.Fatalf("claimed response entry = %#v, want queue-concurrent-001", result.resp.Entry)
			}
		} else if result.resp.Entry != nil {
			t.Fatalf("noop response entry = %#v, want nil", result.resp.Entry)
		}
	}
	if claimedCount != 1 {
		t.Fatalf("claimed responses = %d, want 1", claimedCount)
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("queue entries len = %d, want 1: %#v", len(entries), entries)
	}
	if entries[0].Status != factory.QueueStatusClaimed {
		t.Fatalf("queue status = %q, want claimed", entries[0].Status)
	}
	if entries[0].AttemptCount != 1 {
		t.Fatalf("queue attemptCount = %d, want 1", entries[0].AttemptCount)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events len = %d, want 1: %#v", len(events), events)
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

func queueWorkTestDeps(store factory.Store, now time.Time, claim factory.QueueClaim) factoryQueueWorkDeps {
	return factoryQueueWorkDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		claim:        &claim,
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
