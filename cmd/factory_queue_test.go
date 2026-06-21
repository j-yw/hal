package cmd

import (
	"bytes"
	"context"
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

func TestRunFactoryQueueAddWithDepsRejectsNonPendingRun(t *testing.T) {
	tests := []struct {
		name   string
		status string
	}{
		{name: "running", status: factory.RunStatusRunning},
		{name: "succeeded", status: factory.RunStatusSucceeded},
		{name: "failed", status: factory.RunStatusFailed},
		{name: "canceled", status: factory.RunStatusCanceled},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
			createdAt := time.Date(2026, 6, 21, 12, 10, 0, 0, time.UTC)
			record := testFactoryRunRecord("run-queue-add-"+tt.status, createdAt, createdAt)
			record.Status = tt.status
			record.CurrentStep = tt.status
			if err := store.SaveRun(&record); err != nil {
				t.Fatalf("SaveRun() error: %v", err)
			}

			err := runFactoryQueueAddWithDeps(io.Discard, factoryQueueAddRequest{
				RunID:        record.RunID,
				ExecutorMode: factory.ExecutorModeLocal,
			}, queueAddTestDeps(store, createdAt.Add(time.Minute), "queue-add-001"))
			if err == nil {
				t.Fatalf("runFactoryQueueAddWithDeps() error = nil, want non-pending run error")
			}
			want := `factory run "` + record.RunID + `" is "` + tt.status + `", want "pending"`
			if err.Error() != want {
				t.Fatalf("runFactoryQueueAddWithDeps() error = %q, want %q", err.Error(), want)
			}

			entries, err := store.LoadQueue()
			if err != nil {
				t.Fatalf("LoadQueue() error: %v", err)
			}
			if len(entries) != 0 {
				t.Fatalf("queue entries len = %d, want 0: %#v", len(entries), entries)
			}
		})
	}
}

func TestRunFactoryQueueAddWithDepsJSONOutput(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 13, 0, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-queue-add-json", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.RunStatusPending
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
	if !strings.Contains(err.Error(), `unsupported factory executor mode "remote" (supported: local, sandbox)`) {
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
	executorCalled := false

	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
		executorCalled = true
		return errors.New("executor should not run when no queue entry is claimed")
	}))
	if err != nil {
		t.Fatalf("runFactoryQueueWorkWithDeps() unexpected error: %v", err)
	}
	if executorCalled {
		t.Fatal("executor was called for no-work queue response")
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

func TestRunFactoryQueueWorkWithDepsExecutesOneEntryAndRecordsRunState(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 18, 0, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-claim", PID: 5353, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-queue-work", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	record.Source = factory.SourceMetadata{Kind: factory.SourceKindMarkdown, Path: ".hal/prd-queue-work.md"}
	record.BaseBranch = "main"
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-work-001", record.RunID, factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	var gotPipelineReq factoryRunPipelineRequest
	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(ctx context.Context, req factoryRunPipelineRequest) error {
		gotPipelineReq = req
		return req.RecordProgress(factoryRunProgressEvent{
			Summary: "Queue worker progress",
			Metadata: map[string]any{
				"queueId": "queue-work-001",
			},
		})
	}))
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
	if resp.Summary != "completed queue entry queue-work-001" {
		t.Fatalf("summary = %q, want completed summary", resp.Summary)
	}
	if resp.Entry == nil {
		t.Fatal("entry = nil, want completed entry")
	}
	if resp.Entry.Status != factory.QueueStatusSucceeded {
		t.Fatalf("entry.status = %q, want %q", resp.Entry.Status, factory.QueueStatusSucceeded)
	}
	if resp.Entry.ClaimedAt == nil || !resp.Entry.ClaimedAt.Equal(claimedAt) {
		t.Fatalf("entry.claimedAt = %v, want %s", resp.Entry.ClaimedAt, claimedAt)
	}
	if resp.Entry.CompletedAt == nil || !resp.Entry.CompletedAt.Equal(claimedAt) {
		t.Fatalf("entry.completedAt = %v, want %s", resp.Entry.CompletedAt, claimedAt)
	}
	if resp.Entry.Claim == nil || *resp.Entry.Claim != claim {
		t.Fatalf("entry.claim = %#v, want %#v", resp.Entry.Claim, claim)
	}
	if resp.Entry.AttemptCount != 1 {
		t.Fatalf("entry.attemptCount = %d, want 1", resp.Entry.AttemptCount)
	}
	if gotPipelineReq.RunID != record.RunID {
		t.Fatalf("pipeline runID = %q, want %q", gotPipelineReq.RunID, record.RunID)
	}
	if gotPipelineReq.Request.MarkdownPath != ".hal/prd-queue-work.md" {
		t.Fatalf("pipeline markdown path = %q, want source markdown", gotPipelineReq.Request.MarkdownPath)
	}
	if gotPipelineReq.Request.BaseBranch != "main" {
		t.Fatalf("pipeline base branch = %q, want main", gotPipelineReq.Request.BaseBranch)
	}
	if gotPipelineReq.Record.Status != factory.RunStatusRunning {
		t.Fatalf("pipeline record status = %q, want running", gotPipelineReq.Record.Status)
	}
	if gotPipelineReq.Record.CurrentStep != "run" {
		t.Fatalf("pipeline record currentStep = %q, want run", gotPipelineReq.Record.CurrentStep)
	}
	if gotPipelineReq.Store.QueuePath() != store.QueuePath() {
		t.Fatalf("pipeline store queue path = %q, want %q", gotPipelineReq.Store.QueuePath(), store.QueuePath())
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("queue entries len = %d, want 1: %#v", len(entries), entries)
	}
	if entries[0].Status != factory.QueueStatusSucceeded {
		t.Fatalf("queue status = %q, want %q", entries[0].Status, factory.QueueStatusSucceeded)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusSucceeded {
		t.Fatalf("run status = %q, want %q", loaded.Status, factory.RunStatusSucceeded)
	}
	if loaded.CurrentStep != "done" {
		t.Fatalf("currentStep = %q, want done", loaded.CurrentStep)
	}
	if loaded.FinishedAt == nil || !loaded.FinishedAt.Equal(claimedAt) {
		t.Fatalf("finishedAt = %v, want %s", loaded.FinishedAt, claimedAt)
	}
	if !loaded.UpdatedAt.Equal(claimedAt) {
		t.Fatalf("updatedAt = %s, want %s", loaded.UpdatedAt, claimedAt)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeCommandOutputSummary,
		factory.EventTypeStepStarted,
		factory.EventTypeCommandOutputSummary,
		factory.EventTypeStepEnded,
	})
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
	if events[2].Summary != "Queue worker progress" {
		t.Fatalf("progress event summary = %q, want worker progress", events[2].Summary)
	}
	if events[3].Summary != "Local compound pipeline completed" {
		t.Fatalf("final event summary = %q, want pipeline completed", events[3].Summary)
	}
}

func TestRunFactoryQueueWorkWithDepsExecutesSandboxEntryThroughSandbox(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 18, 15, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-sandbox", PID: 5357, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-queue-sandbox", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	record.Source = factory.SourceMetadata{Kind: factory.SourceKindMarkdown, Path: ".hal/prd-queue-sandbox.md"}
	record.BaseBranch = "main"
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	entry := testFactoryQueueEntry("queue-sandbox-001", record.RunID, factory.QueueStatusQueued, createdAt)
	entry.ExecutorMode = factory.ExecutorModeSandbox
	if err := store.SaveQueue([]factory.QueueEntry{entry}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	policy := factory.DefaultFactoryPolicy()
	policy.SandboxRequired = true
	deps := queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
		t.Fatal("runPipeline should not be called for sandbox queue entries")
		return nil
	})
	deps.loadPolicy = func(string) (*factory.FactoryPolicy, error) {
		return &policy, nil
	}
	deps.loadEngine = func(string) (string, error) {
		return factory.PolicyEngineCodex, nil
	}
	var gotSandboxReq factorySandboxExecutorRequest
	deps.runSandbox = func(_ context.Context, req factorySandboxExecutorRequest) error {
		gotSandboxReq = req
		return nil
	}

	var out bytes.Buffer
	if err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, deps); err != nil {
		t.Fatalf("runFactoryQueueWorkWithDeps() unexpected error: %v", err)
	}
	if gotSandboxReq.RunRecord.RunID != record.RunID {
		t.Fatalf("sandbox runID = %q, want %q", gotSandboxReq.RunRecord.RunID, record.RunID)
	}
	if gotSandboxReq.RunRecord.ExecutorMode != factory.ExecutorModeSandbox {
		t.Fatalf("sandbox executorMode = %q, want %q", gotSandboxReq.RunRecord.ExecutorMode, factory.ExecutorModeSandbox)
	}
	if len(gotSandboxReq.RemoteAuto.Args) != 1 || gotSandboxReq.RemoteAuto.Args[0] != ".hal/prd-queue-sandbox.md" {
		t.Fatalf("sandbox args = %#v, want queued markdown source", gotSandboxReq.RemoteAuto.Args)
	}
	if gotSandboxReq.RemoteAuto.Engine != factory.PolicyEngineCodex {
		t.Fatalf("sandbox engine = %q, want %q", gotSandboxReq.RemoteAuto.Engine, factory.PolicyEngineCodex)
	}
}

func TestRunFactoryQueueWorkWithDepsRejectsCreationPolicyBeforeExecution(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 18, 30, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-policy", PID: 5354, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-queue-policy", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-policy-001", record.RunID, factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	policy := factory.DefaultFactoryPolicy()
	policy.SandboxRequired = true
	deps := queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
		t.Fatal("runPipeline should not be called when creation policy rejects queued work")
		return nil
	})
	deps.loadPolicy = func(string) (*factory.FactoryPolicy, error) {
		return &policy, nil
	}
	deps.loadEngine = func(string) (string, error) {
		return factory.PolicyEngineCodex, nil
	}

	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, deps)
	if err == nil {
		t.Fatal("runFactoryQueueWorkWithDeps() error = nil, want policy rejection")
	}
	if !strings.Contains(err.Error(), "factory.policy.sandboxRequired") {
		t.Fatalf("runFactoryQueueWorkWithDeps() error = %q, want sandboxRequired rejection", err.Error())
	}

	var resp FactoryQueueWorkResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v\n%s", err, out.String())
	}
	if resp.Entry == nil || resp.Entry.Status != factory.QueueStatusFailed {
		t.Fatalf("entry = %#v, want failed queue entry", resp.Entry)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusFailed {
		t.Fatalf("run status = %q, want failed", loaded.Status)
	}
	if loaded.Failure == nil || loaded.Failure.Step != "policy" {
		t.Fatalf("run failure = %+v, want policy failure", loaded.Failure)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	foundPolicyDecision := false
	for _, event := range events {
		if event.EventType == factory.EventTypePolicyDecision && event.Metadata["policyField"] == "factory.policy.sandboxRequired" {
			foundPolicyDecision = true
			break
		}
	}
	if !foundPolicyDecision {
		t.Fatalf("events = %#v, want sandboxRequired policy decision", events)
	}
}

func TestRunFactoryQueueWorkWithDepsUsesStoredPolicySnapshot(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 18, 40, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-policy-snapshot", PID: 5356, Hostname: "factory-host"}
	policySnapshot := factory.DefaultFactoryPolicy()
	policySnapshot.AllowedEngines = []string{factory.PolicyEngineCodex}
	policySnapshot.MaxRunAttempts = 3
	record := testFactoryRunRecord("run-queue-policy-snapshot", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	record.Policy = &policySnapshot
	record.Engine = factory.PolicyEngineCodex
	record.Source = factory.SourceMetadata{Kind: factory.SourceKindMarkdown, Path: ".hal/prd-policy-snapshot.md"}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-policy-snapshot-001", record.RunID, factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	var gotPipelineReq factoryRunPipelineRequest
	deps := queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(_ context.Context, req factoryRunPipelineRequest) error {
		gotPipelineReq = req
		return nil
	})
	deps.loadPolicy = func(string) (*factory.FactoryPolicy, error) {
		t.Fatal("loadPolicy should not be called when run record already has a policy snapshot")
		return nil, nil
	}
	deps.loadEngine = func(string) (string, error) {
		t.Fatal("loadEngine should not be called when run record already has an engine snapshot")
		return "", nil
	}

	var out bytes.Buffer
	if err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, deps); err != nil {
		t.Fatalf("runFactoryQueueWorkWithDeps() unexpected error: %v", err)
	}
	if gotPipelineReq.AttemptPolicy.MaxRunAttempts != 3 {
		t.Fatalf("pipeline max run attempts = %d, want snapshot value 3", gotPipelineReq.AttemptPolicy.MaxRunAttempts)
	}
	if gotPipelineReq.Engine != factory.PolicyEngineCodex {
		t.Fatalf("pipeline engine = %q, want stored snapshot %q", gotPipelineReq.Engine, factory.PolicyEngineCodex)
	}
	if gotPipelineReq.Record.Policy == nil || gotPipelineReq.Record.Policy.MaxRunAttempts != 3 {
		t.Fatalf("pipeline record policy = %#v, want stored snapshot", gotPipelineReq.Record.Policy)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Policy == nil || loaded.Policy.MaxRunAttempts != 3 {
		t.Fatalf("loaded policy = %#v, want stored snapshot", loaded.Policy)
	}
	if loaded.Engine != factory.PolicyEngineCodex {
		t.Fatalf("loaded engine = %q, want stored snapshot %q", loaded.Engine, factory.PolicyEngineCodex)
	}
}

func TestRunFactoryQueueWorkWithDepsMarksRunFailedWhenPolicyLoadFails(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 18, 45, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-policy-load", PID: 5355, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-queue-policy-load", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-policy-load-001", record.RunID, factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	deps := queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
		t.Fatal("runPipeline should not be called when policy loading fails")
		return nil
	})
	deps.loadPolicy = func(string) (*factory.FactoryPolicy, error) {
		return nil, errors.New("policy config unreadable")
	}

	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, deps)
	if err == nil {
		t.Fatal("runFactoryQueueWorkWithDeps() error = nil, want policy load error")
	}
	if !strings.Contains(err.Error(), "load factory policy: policy config unreadable") {
		t.Fatalf("runFactoryQueueWorkWithDeps() error = %q, want policy load context", err.Error())
	}

	var resp FactoryQueueWorkResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v\n%s", err, out.String())
	}
	if resp.Entry == nil || resp.Entry.Status != factory.QueueStatusFailed {
		t.Fatalf("entry = %#v, want failed queue entry", resp.Entry)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusFailed {
		t.Fatalf("run status = %q, want failed", loaded.Status)
	}
	if loaded.Failure == nil || !strings.Contains(loaded.Failure.Message, "load factory policy: policy config unreadable") {
		t.Fatalf("run failure = %+v, want policy load failure", loaded.Failure)
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
	err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDeps(store, claimedAt, claim))
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
	if byQueueID["queue-fifo-old"].Status != factory.QueueStatusSucceeded {
		t.Fatalf("old entry status = %q, want succeeded", byQueueID["queue-fifo-old"].Status)
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
			err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDeps(store, claimedAt, claim))
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
	if entries[0].Status != factory.QueueStatusSucceeded {
		t.Fatalf("queue status = %q, want succeeded", entries[0].Status)
	}
	if entries[0].AttemptCount != 1 {
		t.Fatalf("queue attemptCount = %d, want 1", entries[0].AttemptCount)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	if len(events) != 3 {
		t.Fatalf("events len = %d, want 3: %#v", len(events), events)
	}
}

func TestExecuteClaimedFactoryQueueEntryMarksMissingRunFailed(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 20, 30, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	completedAt := claimedAt.Add(2 * time.Minute)
	entry := testFactoryQueueEntry("queue-missing-run", "missing-run", factory.QueueStatusClaimed, createdAt)
	entry.AttemptCount = 1
	entry.ClaimedAt = &claimedAt
	if err := store.SaveQueue([]factory.QueueEntry{entry}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	finalEntry, err := executeClaimedFactoryQueueEntry(context.Background(), store, entry, factoryQueueWorkDeps{
		now: func() time.Time { return completedAt },
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			t.Fatal("runPipeline called for missing run")
			return nil
		},
	})
	if err == nil {
		t.Fatal("executeClaimedFactoryQueueEntry() error = nil, want missing run error")
	}
	if !strings.Contains(err.Error(), `load claimed factory run "missing-run"`) {
		t.Fatalf("executeClaimedFactoryQueueEntry() error = %q, want missing run context", err.Error())
	}
	if finalEntry.Status != factory.QueueStatusFailed {
		t.Fatalf("finalEntry.status = %q, want %q", finalEntry.Status, factory.QueueStatusFailed)
	}
	if finalEntry.CompletedAt == nil || !finalEntry.CompletedAt.Equal(completedAt) {
		t.Fatalf("finalEntry.completedAt = %v, want %s", finalEntry.CompletedAt, completedAt)
	}
	if !strings.Contains(finalEntry.LastError, `load claimed factory run "missing-run"`) {
		t.Fatalf("finalEntry.lastError = %q, want missing run context", finalEntry.LastError)
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("queue entries len = %d, want 1: %#v", len(entries), entries)
	}
	if entries[0].Status != factory.QueueStatusFailed {
		t.Fatalf("queue status = %q, want failed", entries[0].Status)
	}
	if !strings.Contains(entries[0].LastError, `load claimed factory run "missing-run"`) {
		t.Fatalf("queue lastError = %q, want missing run context", entries[0].LastError)
	}
}

func TestRunFactoryQueueWorkWithDepsRecordsExecutorFailure(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 21, 0, 0, 0, time.UTC)
	claimedAt := createdAt.Add(10 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-failure", PID: 5656, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-failed-work", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-failure-001", record.RunID, factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	pipelineErr := errors.New("executor failed during run")
	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
		return pipelineErr
	}))
	if err == nil {
		t.Fatal("runFactoryQueueWorkWithDeps() error = nil, want executor failure")
	}
	if !strings.Contains(err.Error(), pipelineErr.Error()) {
		t.Fatalf("runFactoryQueueWorkWithDeps() error = %q, want executor failure", err.Error())
	}

	var resp FactoryQueueWorkResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v\n%s", err, out.String())
	}
	if !resp.Claimed {
		t.Fatal("claimed = false, want true for failed claimed work")
	}
	if resp.Summary != "failed queue entry queue-failure-001" {
		t.Fatalf("summary = %q, want failed queue summary", resp.Summary)
	}
	if resp.Entry == nil {
		t.Fatal("entry = nil, want failed entry")
	}
	if resp.Entry.Status != factory.QueueStatusFailed {
		t.Fatalf("entry.status = %q, want %q", resp.Entry.Status, factory.QueueStatusFailed)
	}
	if resp.Entry.CompletedAt == nil || !resp.Entry.CompletedAt.Equal(claimedAt) {
		t.Fatalf("entry.completedAt = %v, want %s", resp.Entry.CompletedAt, claimedAt)
	}
	if resp.Entry.LastError != pipelineErr.Error() {
		t.Fatalf("entry.lastError = %q, want %q", resp.Entry.LastError, pipelineErr.Error())
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("queue entries len = %d, want 1: %#v", len(entries), entries)
	}
	if entries[0].Status != factory.QueueStatusFailed {
		t.Fatalf("queue status = %q, want failed", entries[0].Status)
	}
	if entries[0].LastError != pipelineErr.Error() {
		t.Fatalf("queue lastError = %q, want %q", entries[0].LastError, pipelineErr.Error())
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusFailed {
		t.Fatalf("run status = %q, want failed", loaded.Status)
	}
	if loaded.Failure == nil {
		t.Fatal("run failure = nil, want failure summary")
	}
	if loaded.Failure.Message != pipelineErr.Error() {
		t.Fatalf("run failure message = %q, want %q", loaded.Failure.Message, pipelineErr.Error())
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeCommandOutputSummary,
		factory.EventTypeStepStarted,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	if events[2].Summary != "Local compound pipeline failed" {
		t.Fatalf("failure event summary = %q, want pipeline failed", events[2].Summary)
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
	return queueWorkTestDepsWithExecutor(store, now, claim, func(context.Context, factoryRunPipelineRequest) error {
		return nil
	})
}

func queueWorkTestDepsWithExecutor(store factory.Store, now time.Time, claim factory.QueueClaim, runPipeline func(context.Context, factoryRunPipelineRequest) error) factoryQueueWorkDeps {
	return factoryQueueWorkDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		now:          func() time.Time { return now },
		claim:        &claim,
		runPipeline:  runPipeline,
		runSandbox: func(context.Context, factorySandboxExecutorRequest) error {
			return nil
		},
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
