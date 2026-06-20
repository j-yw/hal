package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/spf13/cobra"
)

func TestFactoryCommandHelpMetadata(t *testing.T) {
	tests := []struct {
		name                 string
		cmd                  *cobra.Command
		requiredLongPhrases  []string
		requiredExampleLines []string
	}{
		{
			name: "factory root command",
			cmd:  factoryCmd,
			requiredLongPhrases: []string{
				"Run local factory workflows",
				"global factory store",
				"separate from per-project",
				"Factory run wraps the local auto pipeline",
			},
			requiredExampleLines: []string{
				"hal factory run .hal/prd-feature.md",
				"hal factory run --report .hal/reports/analysis.md --json",
				"hal factory list",
				"hal factory list --json",
				"hal factory status <run-id> --json",
			},
		},
		{
			name: "factory run command",
			cmd:  factoryRunCmd,
			requiredLongPhrases: []string{
				"existing hal auto compound",
				"positional PRD markdown path",
				"--report <path>",
				"--base <branch>",
				"--json",
				"factory-run-v1",
			},
			requiredExampleLines: []string{
				"hal factory run .hal/prd-feature.md",
				"hal factory run --report .hal/reports/analysis.md",
				"hal factory run .hal/prd-feature.md --base main --json",
			},
		},
		{
			name: "factory list command",
			cmd:  factoryListCmd,
			requiredLongPhrases: []string{
				"global factory store",
				"--json",
				"factory-list-v1 contract",
				"run summaries only",
				"timelines are intentionally omitted",
			},
			requiredExampleLines: []string{
				"hal factory list",
				"hal factory list --json",
			},
		},
		{
			name: "factory status command",
			cmd:  factoryStatusCmd,
			requiredLongPhrases: []string{
				"global factory store",
				"--json",
				"factory-status-v1 contract",
				"full run record",
				"timeline events in append order",
			},
			requiredExampleLines: []string{
				"hal factory status run-20260620-001",
				"hal factory status run-20260620-001 --json",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if tt.cmd == nil {
				t.Fatal("command is nil")
			}
			if missing := missingCommandMetadataFields(tt.cmd); len(missing) > 0 {
				t.Fatalf("command %q is missing metadata fields: %s", commandPathLabel(tt.cmd), strings.Join(missing, ", "))
			}

			commandPath := commandPathLabel(tt.cmd)
			if !strings.Contains(tt.cmd.Example, commandPath) {
				t.Fatalf("command %q example must include %q, got %q", commandPath, commandPath, tt.cmd.Example)
			}

			for _, phrase := range tt.requiredLongPhrases {
				if !strings.Contains(tt.cmd.Long, phrase) {
					t.Fatalf("command %q long help must include %q, got %q", commandPath, phrase, tt.cmd.Long)
				}
			}

			for _, line := range tt.requiredExampleLines {
				if !strings.Contains(tt.cmd.Example, line) {
					t.Fatalf("command %q example must include %q, got %q", commandPath, line, tt.cmd.Example)
				}
			}
		})
	}
}

func TestParseFactoryRunRequest(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		reportPath string
		baseBranch string
		jsonMode   bool
		want       factoryRunRequest
		wantErr    string
	}{
		{
			name: "no explicit source",
			want: factoryRunRequest{},
		},
		{
			name: "positional markdown path",
			args: []string{".hal/prd-feature.md"},
			want: factoryRunRequest{MarkdownPath: ".hal/prd-feature.md"},
		},
		{
			name:       "report path",
			reportPath: ".hal/reports/analysis.md",
			want:       factoryRunRequest{ReportPath: ".hal/reports/analysis.md"},
		},
		{
			name:       "base and json options",
			args:       []string{".hal/prd-feature.md"},
			baseBranch: "main",
			jsonMode:   true,
			want: factoryRunRequest{
				MarkdownPath: ".hal/prd-feature.md",
				BaseBranch:   "main",
				JSON:         true,
			},
		},
		{
			name:       "positional and report conflict",
			args:       []string{".hal/prd-feature.md"},
			reportPath: ".hal/reports/analysis.md",
			wantErr:    "--report cannot be used with a positional PRD markdown path",
		},
		{
			name:    "too many positional args",
			args:    []string{"one.md", "two.md"},
			wantErr: "accepts at most 1 arg(s), received 2",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseFactoryRunRequest(tt.args, tt.reportPath, tt.baseBranch, tt.jsonMode)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseFactoryRunRequest() error = nil, want %q", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseFactoryRunRequest() error = %q, want %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseFactoryRunRequest() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseFactoryRunRequest() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestFactoryRunCommandRegisteredWithInputFlags(t *testing.T) {
	cmd, err := commandAtPath(Root(), "factory", "run")
	if err != nil {
		t.Fatalf("factory run command missing: %v", err)
	}
	for _, flagName := range []string{"report", "base", "json"} {
		if cmd.Flags().Lookup(flagName) == nil {
			t.Fatalf("factory run should expose --%s flag", flagName)
		}
	}
	if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
		t.Fatalf("factory run missing metadata fields: %v", missing)
	}
}

func TestFactoryRunArgsValidationRejectsReportWithPositionalBeforeExecution(t *testing.T) {
	cmd := &cobra.Command{Use: "run", Args: validateFactoryRunArgs}
	cmd.Flags().String("report", "", "")
	if err := cmd.Flags().Set("report", ".hal/reports/analysis.md"); err != nil {
		t.Fatalf("Set(report) error: %v", err)
	}

	err := cmd.Args(cmd, []string{".hal/prd-feature.md"})
	if err == nil {
		t.Fatal("Args() error = nil, want validation error")
	}
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Args() error type = %T, want *ExitCodeError", err)
	}
	if exitErr.Code != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
	}
	if !strings.Contains(err.Error(), "--report cannot be used with a positional PRD markdown path") {
		t.Fatalf("Args() error = %q", err.Error())
	}
}

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

func TestRenderFactoryRunJSONLocksResultContract(t *testing.T) {
	base := time.Date(2026, 6, 20, 18, 30, 0, 0, time.UTC)
	events := []factory.EventRecord{
		{
			Sequence:  1,
			RunID:     "run-json-contract",
			EventType: factory.EventTypeRunCreated,
			Timestamp: base,
			Summary:   "Run created",
		},
		{
			Sequence:  2,
			RunID:     "run-json-contract",
			EventType: factory.EventTypeFailureClassification,
			Timestamp: base.Add(2 * time.Minute),
			Summary:   "Failure classified",
		},
	}
	resp := FactoryRunResponse{
		ContractVersion: FactoryRunContractVersion,
		Version:         "dev",
		RunID:           "run-json-contract",
		Status:          factory.RunStatusFailed,
		NextAction: &FactoryRunNextAction{
			ID:          "inspect_factory_run",
			Command:     "hal factory status run-json-contract --json",
			Description: "Inspect the durable run record and timeline.",
		},
		Artifacts: []factory.ArtifactReference{
			{Name: "run-record", Type: "json", Path: "factory/runs/run-json-contract.json"},
		},
		EventSummary: newFactoryRunEventSummary(events),
		Failure: &FactoryRunFailure{
			Classification:   "ci",
			ErrorMessage:     "unit tests failed",
			SuggestedCommand: "hal factory status run-json-contract --json",
		},
	}

	var buf bytes.Buffer
	if err := renderFactoryRunJSON(&buf, resp); err != nil {
		t.Fatalf("renderFactoryRunJSON() error: %v", err)
	}

	var decoded FactoryRunResponse
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
	}
	if decoded.ContractVersion != FactoryRunContractVersion {
		t.Fatalf("contractVersion = %q, want %q", decoded.ContractVersion, FactoryRunContractVersion)
	}
	if decoded.EventSummary.Total != len(events) {
		t.Fatalf("eventSummary.total = %d, want %d", decoded.EventSummary.Total, len(events))
	}
	if decoded.EventSummary.ByType[factory.EventTypeFailureClassification] != 1 {
		t.Fatalf("eventSummary.byType[%q] = %d, want 1", factory.EventTypeFailureClassification, decoded.EventSummary.ByType[factory.EventTypeFailureClassification])
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal(raw) error: %v", err)
	}
	requireExactKeys(t, raw, []string{
		"contractVersion", "version", "runId", "status", "nextAction",
		"artifacts", "eventSummary", "failure",
	})

	nextAction, ok := raw["nextAction"].(map[string]any)
	if !ok {
		t.Fatalf("nextAction should be an object, got %T", raw["nextAction"])
	}
	requireFactoryFields(t, "factory run nextAction", nextAction, []string{"id", "command", "description"})

	artifacts, ok := raw["artifacts"].([]any)
	if !ok || len(artifacts) != 1 {
		t.Fatalf("artifacts should be an array of 1, got %T len %d", raw["artifacts"], len(resp.Artifacts))
	}
	firstArtifact, ok := artifacts[0].(map[string]any)
	if !ok {
		t.Fatalf("artifacts[0] should be an object, got %T", artifacts[0])
	}
	requireFactoryFields(t, "factory run artifact", firstArtifact, []string{"name", "type", "path"})

	eventSummary, ok := raw["eventSummary"].(map[string]any)
	if !ok {
		t.Fatalf("eventSummary should be an object, got %T", raw["eventSummary"])
	}
	requireFactoryFields(t, "factory run eventSummary", eventSummary, []string{"total", "byType", "lastEventType", "lastSummary"})

	failure, ok := raw["failure"].(map[string]any)
	if !ok {
		t.Fatalf("failure should be an object, got %T", raw["failure"])
	}
	requireFactoryFields(t, "factory run failure", failure, []string{"classification", "errorMessage", "suggestedCommand"})
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

func TestRunFactoryStatusJSONIncludesRunAndOrderedTimeline(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 20, 17, 0, 0, 0, time.UTC)
	finishedAt := base.Add(20 * time.Minute)
	record := testFactoryRunRecord("run-status", base, base.Add(10*time.Minute))
	record.Status = factory.RunStatusSucceeded
	record.SandboxName = "factory-status"
	record.FinishedAt = &finishedAt
	record.Artifacts = []factory.ArtifactReference{
		{Name: "report", Type: "markdown", Path: ".hal/reports/run-status.md"},
	}
	record.Failure = &factory.FailureSummary{
		Step:     "review",
		Category: "validation",
		Message:  "review found issues",
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	events := []factory.EventRecord{
		{
			Sequence:  2,
			RunID:     record.RunID,
			EventType: factory.EventTypeStepEnded,
			Timestamp: base.Add(3 * time.Minute),
			Message:   "run step completed",
			Summary:   "completed run",
			Metadata:  map[string]any{"validIssues": float64(0)},
		},
		{
			Sequence:  1,
			RunID:     record.RunID,
			EventType: factory.EventTypeRunCreated,
			Timestamp: base.Add(1 * time.Minute),
			Summary:   "created run",
		},
	}
	for _, event := range events {
		event := event
		if err := store.AppendEvent(&event); err != nil {
			t.Fatalf("AppendEvent(%d) error: %v", event.Sequence, err)
		}
	}

	var buf bytes.Buffer
	err := runFactoryStatusWithDeps(&buf, record.RunID, true, factoryStatusDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryStatusWithDeps() unexpected error: %v", err)
	}

	var resp FactoryStatusResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
	}
	if resp.ContractVersion != FactoryStatusContractVersion {
		t.Fatalf("contractVersion = %q, want %q", resp.ContractVersion, FactoryStatusContractVersion)
	}
	if resp.Run.RunID != record.RunID {
		t.Fatalf("run.runId = %q, want %q", resp.Run.RunID, record.RunID)
	}
	if len(resp.Run.Artifacts) != 1 {
		t.Fatalf("run.artifacts len = %d, want 1", len(resp.Run.Artifacts))
	}
	gotSequence := make([]int64, 0, len(resp.Timeline))
	for _, event := range resp.Timeline {
		gotSequence = append(gotSequence, event.Sequence)
	}
	wantSequence := []int64{2, 1}
	if !reflect.DeepEqual(gotSequence, wantSequence) {
		t.Fatalf("timeline sequence order = %v, want append order %v", gotSequence, wantSequence)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal(raw) error: %v", err)
	}
	requireExactKeys(t, raw, []string{"contractVersion", "run", "timeline"})
	run, ok := raw["run"].(map[string]any)
	if !ok {
		t.Fatalf("run should be an object, got %T", raw["run"])
	}
	requireFactoryFields(t, "factory status run", run, []string{
		"runId", "status", "source", "repoPath", "repoRemote", "branchName",
		"baseBranch", "sandboxName", "currentStep", "createdAt", "updatedAt",
		"finishedAt", "artifacts", "failure",
	})
	timeline, ok := raw["timeline"].([]any)
	if !ok || len(timeline) != 2 {
		t.Fatalf("timeline should be an array of 2, got %T len %d", raw["timeline"], len(resp.Timeline))
	}
	firstEvent, ok := timeline[0].(map[string]any)
	if !ok {
		t.Fatalf("first timeline event should be an object, got %T", timeline[0])
	}
	requireFactoryFields(t, "factory status event", firstEvent, []string{
		"sequence", "runId", "eventType", "timestamp", "message", "summary", "metadata",
	})
}

func TestRunFactoryStatusJSONMissingRunReturnsErrorWithoutPayload(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	var buf bytes.Buffer

	err := runFactoryStatusWithDeps(&buf, "missing-run", true, factoryStatusDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err == nil {
		t.Fatal("runFactoryStatusWithDeps() error = nil, want missing-run error")
	}
	if !strings.Contains(err.Error(), `factory run "missing-run" not found`) {
		t.Fatalf("error = %q, want missing-run message", err.Error())
	}
	if buf.Len() != 0 {
		t.Fatalf("missing run should not write JSON payload, got %q", buf.String())
	}
}

func TestFactoryStatusCommandRegisteredWithJSONFlag(t *testing.T) {
	cmd, err := commandAtPath(Root(), "factory", "status")
	if err != nil {
		t.Fatalf("factory status command missing: %v", err)
	}
	if cmd.Flags().Lookup("json") == nil {
		t.Fatal("factory status should expose --json flag")
	}
	if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
		t.Fatalf("factory status missing metadata fields: %v", missing)
	}
}

func TestFactoryGeneratedCLIReferenceLinks(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		wantFragments []string
	}{
		{
			name: "root cli reference links factory command",
			path: "../docs/cli/hal.md",
			wantFragments: []string{
				"[hal factory](hal_factory.md)",
			},
		},
		{
			name: "factory cli reference links subcommands",
			path: "../docs/cli/hal_factory.md",
			wantFragments: []string{
				"[hal factory run](hal_factory_run.md)",
				"[hal factory list](hal_factory_list.md)",
				"[hal factory status](hal_factory_status.md)",
			},
		},
		{
			name: "factory run cli reference links parent",
			path: "../docs/cli/hal_factory_run.md",
			wantFragments: []string{
				"[hal factory](hal_factory.md)",
			},
		},
		{
			name: "factory list cli reference links parent",
			path: "../docs/cli/hal_factory_list.md",
			wantFragments: []string{
				"[hal factory](hal_factory.md)",
			},
		},
		{
			name: "factory status cli reference links parent",
			path: "../docs/cli/hal_factory_status.md",
			wantFragments: []string{
				"[hal factory](hal_factory.md)",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			data, err := os.ReadFile(tt.path)
			if err != nil {
				t.Fatalf("ReadFile(%q) error: %v", tt.path, err)
			}
			text := string(data)
			for _, fragment := range tt.wantFragments {
				if !strings.Contains(text, fragment) {
					t.Fatalf("%s missing %q", tt.path, fragment)
				}
			}
		})
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
