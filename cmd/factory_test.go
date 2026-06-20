package cmd

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
)

func TestRunFactoryListJSONEmptyState(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	var buf bytes.Buffer

	err := runFactoryListWithDeps(&buf, true, factoryListDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryListWithDeps() unexpected error: %v", err)
	}

	var resp FactoryListResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
	}
	if resp.ContractVersion != FactoryListContractVersion {
		t.Fatalf("contractVersion = %q, want %q", resp.ContractVersion, FactoryListContractVersion)
	}
	if resp.Runs == nil {
		t.Fatal("runs should be an empty array, got nil")
	}
	if len(resp.Runs) != 0 {
		t.Fatalf("runs len = %d, want 0", len(resp.Runs))
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal(raw) error: %v", err)
	}
	requireExactKeys(t, raw, []string{"contractVersion", "runs"})
}

func TestRunFactoryListJSONOrdersAndSummarizesRuns(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 20, 16, 0, 0, 0, time.UTC)
	older := testFactoryRunRecord("run-old", base.Add(1*time.Minute), base.Add(2*time.Minute))
	newer := testFactoryRunRecord("run-new", base.Add(3*time.Minute), base.Add(5*time.Minute))
	newer.SandboxName = "factory-sandbox"
	newer.Artifacts = []factory.ArtifactReference{
		{Name: "report", Type: "markdown", Path: ".hal/reports/run-new.md"},
		{Name: "log", Type: "text", Path: ".hal/reports/run-new.log"},
	}
	newer.Failure = &factory.FailureSummary{
		Step:        "ci",
		Category:    "test",
		Message:     "unit tests failed",
		Recoverable: true,
	}

	for _, record := range []factory.RunRecord{older, newer} {
		record := record
		if err := store.SaveRun(&record); err != nil {
			t.Fatalf("SaveRun(%q) error: %v", record.RunID, err)
		}
	}
	if err := store.AppendEvent(&factory.EventRecord{
		Sequence:  1,
		RunID:     newer.RunID,
		EventType: factory.EventTypeRunCreated,
		Timestamp: base.Add(4 * time.Minute),
		Summary:   "created",
	}); err != nil {
		t.Fatalf("AppendEvent() error: %v", err)
	}

	var buf bytes.Buffer
	err := runFactoryListWithDeps(&buf, true, factoryListDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryListWithDeps() unexpected error: %v", err)
	}

	var resp FactoryListResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
	}
	gotRunIDs := make([]string, 0, len(resp.Runs))
	for _, run := range resp.Runs {
		gotRunIDs = append(gotRunIDs, run.RunID)
	}
	wantRunIDs := []string{"run-new", "run-old"}
	if !reflect.DeepEqual(gotRunIDs, wantRunIDs) {
		t.Fatalf("run IDs = %v, want %v", gotRunIDs, wantRunIDs)
	}
	if resp.Runs[0].ArtifactCount != 2 {
		t.Fatalf("artifactCount = %d, want 2", resp.Runs[0].ArtifactCount)
	}
	if resp.Runs[0].Failure == nil || resp.Runs[0].Failure.Step != "ci" {
		t.Fatalf("failure summary missing from first run: %#v", resp.Runs[0].Failure)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal(raw) error: %v", err)
	}
	runs, ok := raw["runs"].([]any)
	if !ok || len(runs) != 2 {
		t.Fatalf("runs should be an array of 2, got %T len %d", raw["runs"], len(resp.Runs))
	}
	first, ok := runs[0].(map[string]any)
	if !ok {
		t.Fatalf("first run should be an object, got %T", runs[0])
	}
	requireFactoryFields(t, "factory list run", first, []string{
		"runId", "status", "source", "repoPath", "repoRemote", "branchName",
		"baseBranch", "sandboxName", "currentStep", "createdAt", "updatedAt",
		"artifactCount", "failure",
	})
	for _, omitted := range []string{"artifacts", "events", "timeline"} {
		if _, ok := first[omitted]; ok {
			t.Fatalf("factory list summary should omit %q: %#v", omitted, first)
		}
	}
}

func TestFactoryListCommandRegisteredWithJSONFlag(t *testing.T) {
	cmd, err := commandAtPath(Root(), "factory", "list")
	if err != nil {
		t.Fatalf("factory list command missing: %v", err)
	}
	if cmd.Flags().Lookup("json") == nil {
		t.Fatal("factory list should expose --json flag")
	}
	if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
		t.Fatalf("factory list missing metadata fields: %v", missing)
	}
}

func testFactoryRunRecord(runID string, createdAt, updatedAt time.Time) factory.RunRecord {
	return factory.RunRecord{
		RunID:       runID,
		Status:      factory.RunStatusRunning,
		Source:      factory.SourceMetadata{Kind: "prd", Path: ".hal/prd.json", Title: "Factory"},
		RepoPath:    "/workspace/hal",
		RepoRemote:  "git@github.com:jywlabs/hal.git",
		BranchName:  "hal/factory",
		BaseBranch:  "develop",
		CurrentStep: "run",
		CreatedAt:   createdAt,
		UpdatedAt:   updatedAt,
	}
}

func requireExactKeys(t *testing.T, got map[string]any, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want exactly %v", mapKeys(got), want)
	}
	requireFactoryFields(t, "object", got, want)
}

func requireFactoryFields(t *testing.T, label string, got map[string]any, want []string) {
	t.Helper()
	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Fatalf("%s missing field %q; keys = %v", label, key, mapKeys(got))
		}
	}
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
