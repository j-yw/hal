package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
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

func TestRunFactoryQueueAddWithDepsRejectsSandboxRunWithoutBaseBranch(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 12, 15, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-sandbox-missing-base", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.RunStatusPending
	record.BaseBranch = ""
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	err := runFactoryQueueAddWithDeps(io.Discard, factoryQueueAddRequest{
		RunID:        record.RunID,
		ExecutorMode: factory.ExecutorModeSandbox,
	}, queueAddTestDeps(store, createdAt.Add(5*time.Minute), "queue-sandbox-missing-base"))
	if err == nil {
		t.Fatal("runFactoryQueueAddWithDeps() error = nil, want missing base branch")
	}
	want := `sandbox factory run "run-sandbox-missing-base" requires a base branch`
	if err.Error() != want {
		t.Fatalf("runFactoryQueueAddWithDeps() error = %q, want %q", err.Error(), want)
	}
	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("queue entries = %#v, want none", entries)
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

func TestRunFactoryQueueAddWithDepsRollsBackQueueWhenRunStepAdvanced(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 12, 45, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-queue-add-advanced-step", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusClaimed
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	err := runFactoryQueueAddWithDeps(io.Discard, factoryQueueAddRequest{
		RunID:        record.RunID,
		ExecutorMode: factory.ExecutorModeLocal,
	}, queueAddTestDeps(store, createdAt.Add(time.Minute), "queue-advanced-step"))
	if err == nil {
		t.Fatalf("runFactoryQueueAddWithDeps() error = nil, want advanced step error")
	}
	want := `enqueue factory run "run-queue-add-advanced-step": factory run "run-queue-add-advanced-step" is at step "claimed", want "pending"`
	if err.Error() != want {
		t.Fatalf("runFactoryQueueAddWithDeps() error = %q, want %q", err.Error(), want)
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("queue entries len = %d, want rollback to empty: %#v", len(entries), entries)
	}
	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.CurrentStep != factory.QueueStatusClaimed {
		t.Fatalf("currentStep = %q, want claimed", loaded.CurrentStep)
	}
}

func TestRunFactoryQueueAddWithDepsRestoresRunWhenTimelineAppendFails(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 12, 50, 0, 0, time.UTC)
	queuedAt := createdAt.Add(time.Minute)
	record := testFactoryRunRecord("run-queue-add-timeline-failure", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.RunStatusPending
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := os.Mkdir(filepath.Join(store.TimelinesDir(), record.RunID+".json"), 0o700); err != nil {
		t.Fatalf("Mkdir(timeline path) error: %v", err)
	}

	err := runFactoryQueueAddWithDeps(io.Discard, factoryQueueAddRequest{
		RunID:        record.RunID,
		ExecutorMode: factory.ExecutorModeLocal,
	}, queueAddTestDeps(store, queuedAt, "queue-timeline-failure"))
	if err == nil {
		t.Fatalf("runFactoryQueueAddWithDeps() error = nil, want timeline append error")
	}
	if !strings.Contains(err.Error(), `enqueue factory run "run-queue-add-timeline-failure": load factory timeline "run-queue-add-timeline-failure"`) {
		t.Fatalf("runFactoryQueueAddWithDeps() error = %q, want timeline load error", err.Error())
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("queue entries len = %d, want rollback to empty: %#v", len(entries), entries)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.CurrentStep != factory.RunStatusPending {
		t.Fatalf("currentStep = %q, want pending", loaded.CurrentStep)
	}
	if !loaded.UpdatedAt.Equal(createdAt) {
		t.Fatalf("updatedAt = %s, want original %s", loaded.UpdatedAt, createdAt)
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
	if events[4].Summary != "Factory queue work succeeded" {
		t.Fatalf("queue success event summary = %q, want queue success", events[4].Summary)
	}
}

func TestRunFactoryQueueWorkWithDepsReconcilesPartiallyEnqueuedRun(t *testing.T) {
	tests := []struct {
		name        string
		currentStep string
	}{
		{name: "empty", currentStep: ""},
		{name: "pending", currentStep: factory.RunStatusPending},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
			createdAt := time.Date(2026, 6, 21, 18, 10, 0, 0, time.UTC)
			claimedAt := createdAt.Add(5 * time.Minute)
			claim := factory.QueueClaim{WorkerID: "worker-partial", PID: 5353, Hostname: "factory-host"}
			record := testFactoryRunRecord("run-partially-enqueued-"+tt.name, createdAt, createdAt)
			record.Status = factory.RunStatusPending
			record.CurrentStep = tt.currentStep
			record.Source = factory.SourceMetadata{Kind: factory.SourceKindMarkdown, Path: ".hal/prd-partial.md"}
			if err := store.SaveRun(&record); err != nil {
				t.Fatalf("SaveRun() error: %v", err)
			}
			if err := store.SaveQueue([]factory.QueueEntry{
				testFactoryQueueEntry("queue-partial-"+tt.name, record.RunID, factory.QueueStatusQueued, createdAt),
			}); err != nil {
				t.Fatalf("SaveQueue() error: %v", err)
			}

			executorCalled := false
			var out bytes.Buffer
			err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
				executorCalled = true
				return nil
			}))
			if err != nil {
				t.Fatalf("runFactoryQueueWorkWithDeps() unexpected error: %v", err)
			}
			if !executorCalled {
				t.Fatal("runPipeline was not called for partially enqueued run")
			}

			var resp FactoryQueueWorkResponse
			if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
				t.Fatalf("json.Unmarshal typed response error: %v", err)
			}
			if resp.Entry == nil {
				t.Fatal("entry = nil, want completed entry")
			}
			if resp.Entry.Status != factory.QueueStatusSucceeded {
				t.Fatalf("entry.status = %q, want succeeded", resp.Entry.Status)
			}

			loaded, err := store.LoadRun(record.RunID)
			if err != nil {
				t.Fatalf("LoadRun() error: %v", err)
			}
			if loaded.Status != factory.RunStatusSucceeded {
				t.Fatalf("run status = %q, want succeeded", loaded.Status)
			}

			events, err := store.LoadEvents(record.RunID)
			if err != nil {
				t.Fatalf("LoadEvents() error: %v", err)
			}
			if len(events) == 0 || events[0].Summary != "Factory run claimed" {
				t.Fatalf("first event = %#v, want claim summary", events)
			}
		})
	}
}

func TestRunFactoryQueueWorkWithDepsReclaimsExpiredClaimedRun(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 18, 20, 0, 0, time.UTC)
	oldClaimedAt := createdAt.Add(5 * time.Minute)
	reclaimedAt := oldClaimedAt.Add(25 * time.Hour)
	oldClaim := factory.QueueClaim{WorkerID: "worker-old", PID: 5353, Hostname: "factory-host"}
	newClaim := factory.QueueClaim{WorkerID: "worker-new", PID: 5354, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-queue-reclaim", createdAt, oldClaimedAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusClaimed
	record.Source = factory.SourceMetadata{Kind: factory.SourceKindMarkdown, Path: ".hal/prd-queue-reclaim.md"}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	entry := testFactoryQueueEntry("queue-reclaim-001", record.RunID, factory.QueueStatusClaimed, createdAt)
	entry.ClaimedAt = &oldClaimedAt
	entry.Claim = &oldClaim
	entry.AttemptCount = 1
	if err := store.SaveQueue([]factory.QueueEntry{entry}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	executorCalled := false
	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDepsWithExecutor(store, reclaimedAt, newClaim, func(ctx context.Context, req factoryRunPipelineRequest) error {
		executorCalled = true
		return nil
	}))
	if err != nil {
		t.Fatalf("runFactoryQueueWorkWithDeps() unexpected error: %v", err)
	}
	if !executorCalled {
		t.Fatal("runPipeline was not called for reclaimed queued work")
	}

	var resp FactoryQueueWorkResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v", err)
	}
	if resp.Entry == nil {
		t.Fatal("entry = nil, want completed entry")
	}
	if resp.Entry.Status != factory.QueueStatusSucceeded {
		t.Fatalf("entry.status = %q, want succeeded", resp.Entry.Status)
	}
	if resp.Entry.AttemptCount != 2 {
		t.Fatalf("entry.attemptCount = %d, want reclaimed attempt 2", resp.Entry.AttemptCount)
	}
	if resp.Entry.Claim == nil || *resp.Entry.Claim != newClaim {
		t.Fatalf("entry.claim = %#v, want %#v", resp.Entry.Claim, newClaim)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusSucceeded {
		t.Fatalf("run status = %q, want succeeded", loaded.Status)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	if len(events) == 0 || events[0].Summary != "Factory run claimed" {
		t.Fatalf("first event = %#v, want reclaimed claim event", events)
	}
	if events[0].Metadata["attemptCount"] != float64(2) && events[0].Metadata["attemptCount"] != 2 {
		t.Fatalf("event attemptCount = %#v, want 2", events[0].Metadata["attemptCount"])
	}
}

func TestRunFactoryQueueWorkWithDepsRequeuesRunWhenClaimTimelineAppendFails(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 18, 30, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-claim-failure", PID: 5453, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-claim-timeline-failure", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-claim-timeline-failure", record.RunID, factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}
	if err := os.Mkdir(filepath.Join(store.TimelinesDir(), record.RunID+".json"), 0o700); err != nil {
		t.Fatalf("Mkdir(timeline path) error: %v", err)
	}

	executorCalled := false
	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
		executorCalled = true
		return nil
	}))
	if err == nil {
		t.Fatalf("runFactoryQueueWorkWithDeps() error = nil, want timeline append error")
	}
	if !strings.Contains(err.Error(), `load factory timeline "run-claim-timeline-failure"`) {
		t.Fatalf("runFactoryQueueWorkWithDeps() error = %q, want timeline load error", err.Error())
	}
	if executorCalled {
		t.Fatal("executor was called after claim timeline append failed")
	}

	var resp FactoryQueueWorkResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v\n%s", err, out.String())
	}
	if resp.Entry == nil || resp.Entry.Status != factory.QueueStatusQueued {
		t.Fatalf("response entry = %#v, want requeued queue entry", resp.Entry)
	}
	if resp.Entry.LastError == "" {
		t.Fatalf("response entry lastError = empty, want timeline append error")
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() error: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("queue entries len = %d, want 1: %#v", len(entries), entries)
	}
	if entries[0].Status != factory.QueueStatusQueued {
		t.Fatalf("queue status = %q, want queued", entries[0].Status)
	}
	if !strings.Contains(entries[0].LastError, `load factory timeline "run-claim-timeline-failure"`) {
		t.Fatalf("queue lastError = %q, want timeline load error", entries[0].LastError)
	}
	if entries[0].ClaimedAt != nil {
		t.Fatalf("queue claimedAt = %v, want nil", entries[0].ClaimedAt)
	}
	if entries[0].Claim != nil {
		t.Fatalf("queue claim = %#v, want nil", entries[0].Claim)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.CurrentStep != factory.QueueStatusQueued {
		t.Fatalf("currentStep = %q, want queued", loaded.CurrentStep)
	}
	if !loaded.UpdatedAt.Equal(createdAt) {
		t.Fatalf("updatedAt = %s, want original %s", loaded.UpdatedAt, createdAt)
	}
}

func TestRunFactoryQueueWorkWithDepsKeepsQueueSucceededWhenSuccessEventAppendFails(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 18, 40, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-success-event-failure", PID: 5454, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-success-event-failure", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-success-event-failure", record.RunID, factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	poisonedTimeline := false
	deps := queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
		return nil
	})
	deps.now = func() time.Time {
		if !poisonedTimeline {
			if loaded, err := store.LoadRun(record.RunID); err == nil && loaded.Status == factory.RunStatusSucceeded {
				poisonedTimeline = true
				timelinePath := filepath.Join(store.TimelinesDir(), record.RunID+".json")
				if err := os.Remove(timelinePath); err != nil {
					t.Fatalf("Remove(timeline path) error: %v", err)
				}
				if err := os.Mkdir(timelinePath, 0o700); err != nil {
					t.Fatalf("Mkdir(timeline path) error: %v", err)
				}
			}
		}
		return claimedAt
	}

	var out bytes.Buffer
	err := runFactoryQueueWorkWithDeps(context.Background(), &out, factoryQueueWorkRequest{JSON: true}, deps)
	if err == nil {
		t.Fatal("runFactoryQueueWorkWithDeps() error = nil, want success event append error")
	}
	if !strings.Contains(err.Error(), `load factory timeline "run-success-event-failure"`) {
		t.Fatalf("runFactoryQueueWorkWithDeps() error = %q, want timeline load error", err.Error())
	}

	var resp FactoryQueueWorkResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal typed response error: %v\n%s", err, out.String())
	}
	if resp.Entry == nil || resp.Entry.Status != factory.QueueStatusSucceeded {
		t.Fatalf("response entry = %#v, want succeeded queue entry", resp.Entry)
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
	if entries[0].LastError != "" {
		t.Fatalf("queue lastError = %q, want empty", entries[0].LastError)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusSucceeded {
		t.Fatalf("run status = %q, want succeeded", loaded.Status)
	}
}

func TestExecuteClaimedFactoryQueueEntryMarksRunFailedWhenPipelineStartEventAppendFails(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 18, 42, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-start-event-failure", PID: 5455, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-start-event-failure", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusClaimed
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	entry := testFactoryQueueEntry("queue-start-event-failure", record.RunID, factory.QueueStatusClaimed, createdAt)
	entry.ClaimedAt = &claimedAt
	entry.AttemptCount = 1
	entry.Claim = &claim
	if err := store.SaveQueue([]factory.QueueEntry{entry}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}
	if err := os.Mkdir(filepath.Join(store.TimelinesDir(), record.RunID+".json"), 0o700); err != nil {
		t.Fatalf("Mkdir(timeline path) error: %v", err)
	}

	finalEntry, err := executeClaimedFactoryQueueEntry(context.Background(), store, entry, queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
		t.Fatal("runPipeline called after pipeline start event failed")
		return nil
	}))
	if err == nil {
		t.Fatal("executeClaimedFactoryQueueEntry() error = nil, want pipeline start event append error")
	}
	if !strings.Contains(err.Error(), `load factory timeline "run-start-event-failure"`) {
		t.Fatalf("executeClaimedFactoryQueueEntry() error = %q, want timeline load error", err.Error())
	}
	if finalEntry.Status != factory.QueueStatusFailed {
		t.Fatalf("final queue status = %q, want failed", finalEntry.Status)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusFailed {
		t.Fatalf("run status = %q, want failed", loaded.Status)
	}
	if loaded.Failure == nil || !strings.Contains(loaded.Failure.Message, `load factory timeline "run-start-event-failure"`) {
		t.Fatalf("run failure = %#v, want timeline load failure", loaded.Failure)
	}
}

func TestExecuteClaimedFactoryQueueEntryRoutesSandboxExecutor(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	repoDir := t.TempDir()
	createdAt := time.Date(2026, 6, 21, 19, 0, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-sandbox", PID: 5501, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-sandbox-queue", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusClaimed
	record.Source = factory.SourceMetadata{Kind: factory.SourceKindMarkdown, Path: ".hal/prd-feature.md", Title: "Factory Sandbox"}
	record.RepoPath = repoDir
	record.SandboxName = "factory-dev"
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	entry := testFactoryQueueEntry("queue-sandbox", record.RunID, factory.QueueStatusClaimed, createdAt)
	entry.ExecutorMode = factory.ExecutorModeSandbox
	entry.ClaimedAt = &claimedAt
	entry.AttemptCount = 1
	entry.Claim = &claim
	if err := store.SaveQueue([]factory.QueueEntry{entry}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	sandboxCalled := false
	var gotSandboxReq factorySandboxExecutorRequest
	deps := queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
		t.Fatal("runPipeline called for sandbox queue entry")
		return nil
	})
	deps.runSandbox = func(_ context.Context, req factorySandboxExecutorRequest) error {
		sandboxCalled = true
		gotSandboxReq = req
		return nil
	}
	deps.sandboxRequests = func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
		return nil
	}
	deps.currentBranch = func(string) (string, error) {
		return "hal/worker-left-on-other-branch", nil
	}

	finalEntry, err := executeClaimedFactoryQueueEntry(context.Background(), store, entry, deps)
	if err != nil {
		t.Fatalf("executeClaimedFactoryQueueEntry() error: %v", err)
	}
	if finalEntry.Status != factory.QueueStatusSucceeded {
		t.Fatalf("final queue status = %q, want succeeded", finalEntry.Status)
	}
	if !sandboxCalled {
		t.Fatal("runSandbox was not called")
	}
	if gotSandboxReq.SandboxName != "factory-dev" {
		t.Fatalf("sandbox name = %q, want factory-dev", gotSandboxReq.SandboxName)
	}
	if gotSandboxReq.RunRecord.ExecutorMode != factory.ExecutorModeSandbox {
		t.Fatalf("sandbox run executorMode = %q, want sandbox", gotSandboxReq.RunRecord.ExecutorMode)
	}
	if gotSandboxReq.RunRecord.RepoPath != repoDir {
		t.Fatalf("sandbox run repoPath = %q, want %q", gotSandboxReq.RunRecord.RepoPath, repoDir)
	}
	if len(gotSandboxReq.RemoteAuto.Args) != 1 || gotSandboxReq.RemoteAuto.Args[0] != ".hal/prd-feature.md" {
		t.Fatalf("sandbox remote auto args = %#v, want markdown source", gotSandboxReq.RemoteAuto.Args)
	}
	if gotSandboxReq.RemoteAuto.BaseBranch != "develop" {
		t.Fatalf("sandbox remote auto base = %q, want develop", gotSandboxReq.RemoteAuto.BaseBranch)
	}
}

func TestExecuteClaimedFactoryQueueEntryRejectsSandboxRunWithoutBaseBranch(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 19, 10, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	record := testFactoryRunRecord("run-sandbox-claimed-missing-base", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusClaimed
	record.BaseBranch = ""
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	entry := testFactoryQueueEntry("queue-sandbox-claimed-missing-base", record.RunID, factory.QueueStatusClaimed, createdAt)
	entry.ExecutorMode = factory.ExecutorModeSandbox
	entry.ClaimedAt = &claimedAt
	entry.AttemptCount = 1
	if err := store.SaveQueue([]factory.QueueEntry{entry}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	deps := queueWorkTestDepsWithExecutor(store, claimedAt, factory.QueueClaim{WorkerID: "worker-sandbox-base", PID: 5502, Hostname: "factory-host"}, func(context.Context, factoryRunPipelineRequest) error {
		t.Fatal("runPipeline called for invalid sandbox queue entry")
		return nil
	})
	deps.runSandbox = func(context.Context, factorySandboxExecutorRequest) error {
		t.Fatal("runSandbox called for invalid sandbox queue entry")
		return nil
	}

	finalEntry, err := executeClaimedFactoryQueueEntry(context.Background(), store, entry, deps)
	if err == nil {
		t.Fatal("executeClaimedFactoryQueueEntry() error = nil, want missing base branch")
	}
	want := `sandbox factory run "run-sandbox-claimed-missing-base" requires a base branch`
	if err.Error() != want {
		t.Fatalf("executeClaimedFactoryQueueEntry() error = %q, want %q", err.Error(), want)
	}
	if finalEntry.Status != factory.QueueStatusFailed {
		t.Fatalf("final queue status = %q, want failed", finalEntry.Status)
	}
	loaded, loadErr := store.LoadRun(record.RunID)
	if loadErr != nil {
		t.Fatalf("LoadRun() error: %v", loadErr)
	}
	if loaded.Status != factory.RunStatusFailed {
		t.Fatalf("run status = %q, want failed", loaded.Status)
	}
	if loaded.Failure == nil || loaded.Failure.Message != want {
		t.Fatalf("run failure = %#v, want %q", loaded.Failure, want)
	}
}

func TestRunFactoryQueueWorkWithDepsRejectsUnexpectedQueuedRunStateBeforePipeline(t *testing.T) {
	tests := []struct {
		name        string
		status      string
		currentStep string
		wantErr     string
	}{
		{
			name:        "running",
			status:      factory.RunStatusRunning,
			currentStep: "run",
			wantErr:     `factory run "run-unexpected-running" is "running", want "pending"`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
			createdAt := time.Date(2026, 6, 21, 18, 45, 0, 0, time.UTC)
			claimedAt := createdAt.Add(5 * time.Minute)
			claim := factory.QueueClaim{WorkerID: "worker-unexpected-state", PID: 5454, Hostname: "factory-host"}
			record := testFactoryRunRecord("run-unexpected-"+tt.name, createdAt, createdAt)
			record.Status = tt.status
			record.CurrentStep = tt.currentStep
			if err := store.SaveRun(&record); err != nil {
				t.Fatalf("SaveRun() error: %v", err)
			}
			if err := store.SaveQueue([]factory.QueueEntry{
				testFactoryQueueEntry("queue-unexpected-"+tt.name, record.RunID, factory.QueueStatusQueued, createdAt),
			}); err != nil {
				t.Fatalf("SaveQueue() error: %v", err)
			}

			executorCalled := false
			err := runFactoryQueueWorkWithDeps(context.Background(), io.Discard, factoryQueueWorkRequest{}, queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
				executorCalled = true
				return nil
			}))
			if err == nil || err.Error() != tt.wantErr {
				t.Fatalf("runFactoryQueueWorkWithDeps() error = %v, want %q", err, tt.wantErr)
			}
			if executorCalled {
				t.Fatal("runPipeline called for unexpected queued run state")
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

			loaded, err := store.LoadRun(record.RunID)
			if err != nil {
				t.Fatalf("LoadRun() error: %v", err)
			}
			if loaded.Status != tt.status || loaded.CurrentStep != tt.currentStep {
				t.Fatalf("loaded run = status %q step %q, want status %q step %q", loaded.Status, loaded.CurrentStep, tt.status, tt.currentStep)
			}
		})
	}
}

func TestRunFactoryQueueWorkWithDepsReconcilesTerminalQueuedRunState(t *testing.T) {
	tests := []struct {
		name            string
		status          string
		currentStep     string
		failureMessage  string
		wantQueueStatus string
		wantQueueError  string
		wantReturnedErr string
	}{
		{
			name:            "succeeded",
			status:          factory.RunStatusSucceeded,
			currentStep:     "done",
			wantQueueStatus: factory.QueueStatusSucceeded,
		},
		{
			name:            "failed",
			status:          factory.RunStatusFailed,
			currentStep:     "run",
			failureMessage:  "pipeline failed before retry",
			wantQueueStatus: factory.QueueStatusFailed,
			wantQueueError:  "pipeline failed before retry",
			wantReturnedErr: "pipeline failed before retry",
		},
		{
			name:            "canceled",
			status:          factory.RunStatusCanceled,
			currentStep:     "run",
			failureMessage:  "run canceled before retry",
			wantQueueStatus: factory.QueueStatusFailed,
			wantQueueError:  "run canceled before retry",
			wantReturnedErr: "run canceled before retry",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
			createdAt := time.Date(2026, 6, 21, 18, 46, 0, 0, time.UTC)
			claimedAt := createdAt.Add(5 * time.Minute)
			claim := factory.QueueClaim{WorkerID: "worker-terminal-state", PID: 5454, Hostname: "factory-host"}
			record := testFactoryRunRecord("run-terminal-"+tt.name, createdAt, createdAt)
			record.Status = tt.status
			record.CurrentStep = tt.currentStep
			if tt.failureMessage != "" {
				record.Failure = &factory.FailureSummary{Step: tt.currentStep, Message: tt.failureMessage}
			}
			if err := store.SaveRun(&record); err != nil {
				t.Fatalf("SaveRun() error: %v", err)
			}
			if err := store.SaveQueue([]factory.QueueEntry{
				testFactoryQueueEntry("queue-terminal-"+tt.name, record.RunID, factory.QueueStatusQueued, createdAt),
			}); err != nil {
				t.Fatalf("SaveQueue() error: %v", err)
			}

			executorCalled := false
			err := runFactoryQueueWorkWithDeps(context.Background(), io.Discard, factoryQueueWorkRequest{}, queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
				executorCalled = true
				return nil
			}))
			if tt.wantReturnedErr == "" {
				if err != nil {
					t.Fatalf("runFactoryQueueWorkWithDeps() error = %v, want nil", err)
				}
			} else if err == nil || err.Error() != tt.wantReturnedErr {
				t.Fatalf("runFactoryQueueWorkWithDeps() error = %v, want %q", err, tt.wantReturnedErr)
			}
			if executorCalled {
				t.Fatal("runPipeline called for terminal queued run state")
			}

			entries, err := store.LoadQueue()
			if err != nil {
				t.Fatalf("LoadQueue() error: %v", err)
			}
			if len(entries) != 1 {
				t.Fatalf("queue entries len = %d, want 1: %#v", len(entries), entries)
			}
			if entries[0].Status != tt.wantQueueStatus {
				t.Fatalf("queue status = %q, want %q", entries[0].Status, tt.wantQueueStatus)
			}
			if entries[0].LastError != tt.wantQueueError {
				t.Fatalf("queue lastError = %q, want %q", entries[0].LastError, tt.wantQueueError)
			}

			loaded, err := store.LoadRun(record.RunID)
			if err != nil {
				t.Fatalf("LoadRun() error: %v", err)
			}
			if loaded.Status != tt.status || loaded.CurrentStep != tt.currentStep {
				t.Fatalf("loaded run = status %q step %q, want status %q step %q", loaded.Status, loaded.CurrentStep, tt.status, tt.currentStep)
			}
		})
	}
}

func TestRunFactoryQueueWorkWithDepsMarksExpiredRunningClaimFailed(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 18, 50, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	reclaimedAt := claimedAt.Add(25 * time.Hour)
	oldClaim := factory.QueueClaim{WorkerID: "worker-stale", PID: 4545, Hostname: "factory-host"}
	newClaim := factory.QueueClaim{WorkerID: "worker-reclaimer", PID: 5454, Hostname: "factory-host"}

	record := testFactoryRunRecord("run-expired-running", createdAt, claimedAt)
	record.Status = factory.RunStatusRunning
	record.CurrentStep = "run"
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	entry := testFactoryQueueEntry("queue-expired-running", record.RunID, factory.QueueStatusClaimed, createdAt)
	entry.AttemptCount = 1
	entry.ClaimedAt = &claimedAt
	entry.Claim = &oldClaim
	if err := store.SaveQueue([]factory.QueueEntry{entry}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	executorCalled := false
	err := runFactoryQueueWorkWithDeps(context.Background(), io.Discard, factoryQueueWorkRequest{}, queueWorkTestDepsWithExecutor(store, reclaimedAt, newClaim, func(context.Context, factoryRunPipelineRequest) error {
		executorCalled = true
		return nil
	}))
	if err == nil || err.Error() != `factory run "run-expired-running" is "running", want "pending"` {
		t.Fatalf("runFactoryQueueWorkWithDeps() error = %v, want running state error", err)
	}
	if executorCalled {
		t.Fatal("runPipeline called for expired running claim")
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
	if entries[0].AttemptCount != 2 {
		t.Fatalf("queue attemptCount = %d, want reclaimed attempt 2", entries[0].AttemptCount)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusFailed {
		t.Fatalf("run status = %q, want failed", loaded.Status)
	}
	if loaded.CurrentStep != "run" {
		t.Fatalf("run currentStep = %q, want run", loaded.CurrentStep)
	}
	if loaded.FinishedAt == nil || !loaded.FinishedAt.Equal(reclaimedAt) {
		t.Fatalf("run finishedAt = %v, want %v", loaded.FinishedAt, reclaimedAt)
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
	if len(events) != 4 {
		t.Fatalf("events len = %d, want 4: %#v", len(events), events)
	}
}

func TestExecuteClaimedFactoryQueueEntryRejectsUnexpectedClaimedRunStateBeforePipeline(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 20, 15, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	completedAt := claimedAt.Add(2 * time.Minute)
	entry := testFactoryQueueEntry("queue-unexpected-claimed", "run-unexpected-claimed", factory.QueueStatusClaimed, createdAt)
	entry.AttemptCount = 1
	entry.ClaimedAt = &claimedAt
	record := testFactoryRunRecord(entry.RunID, createdAt, createdAt)
	record.Status = factory.RunStatusRunning
	record.CurrentStep = "run"
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{entry}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	finalEntry, err := executeClaimedFactoryQueueEntry(context.Background(), store, entry, factoryQueueWorkDeps{
		now: func() time.Time { return completedAt },
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			t.Fatal("runPipeline called for unexpected claimed run state")
			return nil
		},
	})
	if err == nil || err.Error() != `factory run "run-unexpected-claimed" is "running", want "pending"` {
		t.Fatalf("executeClaimedFactoryQueueEntry() error = %v, want running state error", err)
	}
	if finalEntry.Status != factory.QueueStatusFailed {
		t.Fatalf("finalEntry.status = %q, want failed", finalEntry.Status)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusRunning || loaded.CurrentStep != "run" {
		t.Fatalf("loaded run = status %q step %q, want running/run", loaded.Status, loaded.CurrentStep)
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

func TestRunFactoryQueueWorkWithDepsFailsBranchMismatchBeforePipeline(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 20, 45, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-branch", PID: 6767, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-branch-mismatch", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-branch-mismatch", record.RunID, factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	deps := queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
		t.Fatal("runPipeline called despite branch mismatch")
		return nil
	})
	deps.currentBranch = func(string) (string, error) {
		return "hal/other-branch", nil
	}

	err := runFactoryQueueWorkWithDeps(context.Background(), io.Discard, factoryQueueWorkRequest{}, deps)
	if err == nil {
		t.Fatal("runFactoryQueueWorkWithDeps() error = nil, want branch mismatch")
	}
	want := `queued factory run "run-branch-mismatch" is on branch "hal/other-branch", want "hal/factory"`
	if err.Error() != want {
		t.Fatalf("runFactoryQueueWorkWithDeps() error = %q, want %q", err.Error(), want)
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
	if entries[0].LastError != want {
		t.Fatalf("queue lastError = %q, want %q", entries[0].LastError, want)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.Status != factory.RunStatusFailed {
		t.Fatalf("run status = %q, want failed", loaded.Status)
	}
	if loaded.CurrentStep != factory.QueueStatusClaimed {
		t.Fatalf("run currentStep = %q, want claimed", loaded.CurrentStep)
	}
	if loaded.FinishedAt == nil || !loaded.FinishedAt.Equal(claimedAt) {
		t.Fatalf("run finishedAt = %v, want %s", loaded.FinishedAt, claimedAt)
	}
	if loaded.Failure == nil {
		t.Fatal("run failure = nil, want failure summary")
	}
	if loaded.Failure.Message != want {
		t.Fatalf("run failure message = %q, want %q", loaded.Failure.Message, want)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeCommandOutputSummary,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	if events[1].Summary != "Factory queue work failed" {
		t.Fatalf("failure event summary = %q, want queue failure", events[1].Summary)
	}
	if events[1].Metadata["queueId"] != "queue-branch-mismatch" {
		t.Fatalf("failure event queueId = %#v, want queue-branch-mismatch", events[1].Metadata["queueId"])
	}
}

func TestRunFactoryQueueWorkWithDepsRejectsRelativeRepoPathBeforePipeline(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 20, 50, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	claim := factory.QueueClaim{WorkerID: "worker-relative", PID: 6868, Hostname: "factory-host"}
	record := testFactoryRunRecord("run-relative-repo", createdAt, createdAt)
	record.Status = factory.RunStatusPending
	record.CurrentStep = factory.QueueStatusQueued
	record.RepoPath = "."
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	if err := store.SaveQueue([]factory.QueueEntry{
		testFactoryQueueEntry("queue-relative-repo", record.RunID, factory.QueueStatusQueued, createdAt),
	}); err != nil {
		t.Fatalf("SaveQueue() error: %v", err)
	}

	deps := queueWorkTestDepsWithExecutor(store, claimedAt, claim, func(context.Context, factoryRunPipelineRequest) error {
		t.Fatal("runPipeline called for relative repository path")
		return nil
	})
	deps.currentBranch = func(string) (string, error) {
		t.Fatal("currentBranch called for relative repository path")
		return "", nil
	}

	err := runFactoryQueueWorkWithDeps(context.Background(), io.Discard, factoryQueueWorkRequest{}, deps)
	want := `queued factory run "run-relative-repo" repository path "." is not absolute`
	if err == nil || err.Error() != want {
		t.Fatalf("runFactoryQueueWorkWithDeps() error = %v, want %q", err, want)
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
	if entries[0].LastError != want {
		t.Fatalf("queue lastError = %q, want %q", entries[0].LastError, want)
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
		factory.EventTypeStepEnded,
	})
	if events[2].Summary != "Local compound pipeline failed" {
		t.Fatalf("failure event summary = %q, want pipeline failed", events[2].Summary)
	}
	if events[4].Summary != "Factory queue work failed" {
		t.Fatalf("queue failure event summary = %q, want queue failure", events[4].Summary)
	}
	if events[4].Metadata["queueId"] != "queue-failure-001" {
		t.Fatalf("queue failure event queueId = %#v, want queue-failure-001", events[4].Metadata["queueId"])
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
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		runPipeline: runPipeline,
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
