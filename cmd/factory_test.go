package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
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
				"managed sandbox",
				"positional PRD markdown path",
				"--report <path>",
				"--base <branch>",
				"--sandbox",
				"--json",
				"factory-run-v1",
			},
			requiredExampleLines: []string{
				"hal factory run .hal/prd-feature.md",
				"hal factory run --report .hal/reports/analysis.md",
				"hal factory run .hal/prd-feature.md --base main --json",
				"hal factory run .hal/prd-feature.md --sandbox --base main",
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
		sandbox    bool
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
			name:       "sandbox option",
			args:       []string{".hal/prd-feature.md"},
			baseBranch: "main",
			sandbox:    true,
			want: factoryRunRequest{
				MarkdownPath: ".hal/prd-feature.md",
				BaseBranch:   "main",
				Sandbox:      true,
			},
		},
		{
			name:    "sandbox requires base",
			args:    []string{".hal/prd-feature.md"},
			sandbox: true,
			wantErr: "--base is required when --sandbox is set",
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
			got, err := parseFactoryRunRequest(tt.args, tt.reportPath, tt.baseBranch, tt.jsonMode, tt.sandbox)
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
	for _, flagName := range []string{"report", "base", "sandbox", "json"} {
		if cmd.Flags().Lookup(flagName) == nil {
			t.Fatalf("factory run should expose --%s flag", flagName)
		}
	}
	if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
		t.Fatalf("factory run missing metadata fields: %v", missing)
	}
}

func TestRunFactoryRunJSONValidationErrorEmitsPayload(t *testing.T) {
	var buf bytes.Buffer
	cmd := &cobra.Command{Use: "run"}
	cmd.SetOut(&buf)
	cmd.Flags().String("report", "", "")
	cmd.Flags().String("base", "", "")
	cmd.Flags().Bool("json", true, "")
	cmd.Flags().Bool("sandbox", true, "")

	err := runFactoryRun(cmd, []string{".hal/prd-feature.md"})
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("runFactoryRun() error = %T, want ExitCodeError", err)
	}
	if exitErr.Code != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
	}

	var resp FactoryRunResponse
	if jsonErr := json.Unmarshal(buf.Bytes(), &resp); jsonErr != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", jsonErr, buf.String())
	}
	if resp.ContractVersion != FactoryRunContractVersion {
		t.Fatalf("contractVersion = %q, want %q", resp.ContractVersion, FactoryRunContractVersion)
	}
	if resp.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", resp.Status, factory.RunStatusFailed)
	}
	if resp.Failure == nil {
		t.Fatal("failure = nil, want validation failure")
	}
	if resp.Failure.Classification != factory.FailureCategoryValidation {
		t.Fatalf("failure.classification = %q, want %q", resp.Failure.Classification, factory.FailureCategoryValidation)
	}
	if resp.Failure.ErrorMessage != "--base is required when --sandbox is set" {
		t.Fatalf("failure.errorMessage = %q", resp.Failure.ErrorMessage)
	}
	if resp.Artifacts == nil || len(resp.Artifacts) != 0 {
		t.Fatalf("artifacts = %#v, want empty non-nil array", resp.Artifacts)
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

func TestSuppressFactoryJSONRenderedErrorReturnsSilentExitAfterPayload(t *testing.T) {
	writer := newFactoryCountingWriter(io.Discard)
	if _, err := writer.Write([]byte(`{"contractVersion":"factory-run-v1"}`)); err != nil {
		t.Fatalf("Write() error: %v", err)
	}

	err := suppressFactoryJSONRenderedError(errors.New("pipeline failed"), true, writer)
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("error = %T, want ExitCodeError", err)
	}
	if exitErr.Code != 1 {
		t.Fatalf("exit code = %d, want 1", exitErr.Code)
	}
	if exitErr.Err != nil {
		t.Fatalf("exit error payload = %v, want nil for silent stderr", exitErr.Err)
	}
}

func TestRunFactoryRunWithDepsDefaultsToLocalPipelineWithoutSandboxFlag(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	localCalled := false

	err := runFactoryRunWithDeps(context.Background(), ".", factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-local-default", nil },
		now:          func() time.Time { return time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC) },
		workingDir:   func() (string, error) { return "/workspace/hal", nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			localCalled = true
			if req.Record.ExecutorMode != factory.ExecutorModeLocal {
				t.Fatalf("local executorMode = %q, want %q", req.Record.ExecutorMode, factory.ExecutorModeLocal)
			}
			if req.Record.BaseBranch != "" {
				t.Fatalf("local baseBranch = %q, want empty default", req.Record.BaseBranch)
			}
			return nil
		},
		runSandbox: func(context.Context, factorySandboxExecutorRequest) error {
			t.Fatal("sandbox executor should not be called without --sandbox")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if !localCalled {
		t.Fatal("local pipeline was not called")
	}
}

func TestRunFactoryRunWithDepsSelectsSandboxExecutorWithSandboxFlag(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	sandboxCalled := false

	err := runFactoryRunWithDeps(context.Background(), "/workspace/hal", factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		Sandbox:      true,
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-selected", nil },
		now:          func() time.Time { return time.Date(2026, 6, 21, 10, 15, 0, 0, time.UTC) },
		workingDir:   func() (string, error) { return "/workspace/hal", nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			t.Fatal("local pipeline should not be called with --sandbox")
			return nil
		},
		runSandbox: func(_ context.Context, req factorySandboxExecutorRequest) error {
			sandboxCalled = true
			if req.ProjectDir != "/workspace/hal" {
				t.Fatalf("sandbox ProjectDir = %q, want /workspace/hal", req.ProjectDir)
			}
			if req.RunRecord.ExecutorMode != factory.ExecutorModeSandbox {
				t.Fatalf("sandbox executorMode = %q, want %q", req.RunRecord.ExecutorMode, factory.ExecutorModeSandbox)
			}
			wantAuto := factoryRunAutoRequest{
				Args:       []string{".hal/prd-feature.md"},
				BaseBranch: "main",
			}
			if !reflect.DeepEqual(req.RemoteAuto, wantAuto) {
				t.Fatalf("remote auto request = %#v, want %#v", req.RemoteAuto, wantAuto)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if !sandboxCalled {
		t.Fatal("sandbox executor was not called")
	}

	record, err := store.LoadRun("run-sandbox-selected")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.ExecutorMode != factory.ExecutorModeSandbox {
		t.Fatalf("persisted executorMode = %q, want %q", record.ExecutorMode, factory.ExecutorModeSandbox)
	}
}

func TestFactoryRunRecordCreateAndInProgressTransition(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 20, 19, 0, 0, 0, time.UTC)
	updatedAt := createdAt.Add(2 * time.Minute)
	record := factory.RunRecord{
		RunID:        "run-transition",
		Status:       factory.RunStatusPending,
		ExecutorMode: factory.ExecutorModeLocal,
		Source:       factory.SourceMetadata{Kind: factory.SourceKindMarkdown, Path: ".hal/prd-feature.md"},
		RepoPath:     "/workspace/hal",
		RepoRemote:   "git@github.com:jywlabs/hal.git",
		BranchName:   "hal/factory",
		BaseBranch:   "develop",
		CurrentStep:  factory.RunStatusPending,
		CreatedAt:    createdAt,
		UpdatedAt:    createdAt,
	}

	if err := createFactoryRunRecord(store, record); err != nil {
		t.Fatalf("createFactoryRunRecord() unexpected error: %v", err)
	}
	pending, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun(pending) error: %v", err)
	}
	if pending.Status != factory.RunStatusPending {
		t.Fatalf("pending status = %q, want %q", pending.Status, factory.RunStatusPending)
	}
	if pending.CurrentStep != factory.RunStatusPending {
		t.Fatalf("pending currentStep = %q, want %q", pending.CurrentStep, factory.RunStatusPending)
	}

	running, err := markFactoryRunInProgress(store, record, updatedAt)
	if err != nil {
		t.Fatalf("markFactoryRunInProgress() unexpected error: %v", err)
	}
	if running.Status != factory.RunStatusRunning {
		t.Fatalf("running status = %q, want %q", running.Status, factory.RunStatusRunning)
	}
	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun(running) error: %v", err)
	}
	if loaded.Status != factory.RunStatusRunning {
		t.Fatalf("loaded status = %q, want %q", loaded.Status, factory.RunStatusRunning)
	}
	if loaded.CurrentStep != "run" {
		t.Fatalf("loaded currentStep = %q, want run", loaded.CurrentStep)
	}
	if !loaded.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("loaded updatedAt = %s, want %s", loaded.UpdatedAt, updatedAt)
	}
}

func TestRunFactoryRunWithDepsCreatesMarkdownRunRecordBeforePipeline(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 20, 20, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	times := []time.Time{createdAt, startedAt}
	pipelineCalled := false

	err := runFactoryRunWithDeps(context.Background(), ".", factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "develop",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-markdown-record", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return startedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return "/workspace/hal", nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			pipelineCalled = true
			if req.RunID != "run-markdown-record" {
				t.Fatalf("pipeline RunID = %q, want run-markdown-record", req.RunID)
			}
			if req.Request.MarkdownPath != ".hal/prd-feature.md" {
				t.Fatalf("pipeline markdown path = %q", req.Request.MarkdownPath)
			}
			loaded, err := req.Store.LoadRun(req.RunID)
			if err != nil {
				t.Fatalf("pipeline LoadRun() error: %v", err)
			}
			assertFactoryRunRecordReadyForPipeline(t, *loaded, factory.SourceMetadata{
				Kind: factory.SourceKindMarkdown,
				Path: ".hal/prd-feature.md",
			})
			if loaded.BaseBranch != "develop" {
				t.Fatalf("baseBranch = %q, want develop", loaded.BaseBranch)
			}
			if !loaded.CreatedAt.Equal(createdAt) {
				t.Fatalf("createdAt = %s, want %s", loaded.CreatedAt, createdAt)
			}
			if !loaded.UpdatedAt.Equal(startedAt) {
				t.Fatalf("updatedAt = %s, want %s", loaded.UpdatedAt, startedAt)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if !pipelineCalled {
		t.Fatal("pipeline dependency was not invoked")
	}
}

func TestRunFactoryRunWithDepsCreatesReportRunRecordBeforePipeline(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 20, 21, 0, 0, 0, time.UTC)
	pipelineCalled := false

	err := runFactoryRunWithDeps(context.Background(), ".", factoryRunRequest{
		ReportPath: ".hal/reports/analysis.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-report-record", nil },
		now:          func() time.Time { return now },
		workingDir:   func() (string, error) { return "/workspace/hal", nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			pipelineCalled = true
			loaded, err := req.Store.LoadRun(req.RunID)
			if err != nil {
				t.Fatalf("pipeline LoadRun() error: %v", err)
			}
			assertFactoryRunRecordReadyForPipeline(t, *loaded, factory.SourceMetadata{
				Kind:       factory.SourceKindReport,
				Path:       ".hal/reports/analysis.md",
				ReportPath: ".hal/reports/analysis.md",
			})
			if loaded.BaseBranch != "" {
				t.Fatalf("baseBranch = %q, want empty default", loaded.BaseBranch)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if !pipelineCalled {
		t.Fatal("pipeline dependency was not invoked")
	}
}

func TestRunFactoryRunWithDepsRefreshesBranchAfterPipeline(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 20, 21, 30, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}
	branchName := "hal/factory"

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-final-branch", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return completedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return branchName, nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			branchName = "hal/generated-feature"
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	record, err := store.LoadRun("run-final-branch")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.BranchName != "hal/generated-feature" {
		t.Fatalf("branchName = %q, want hal/generated-feature", record.BranchName)
	}
	if record.Status != factory.RunStatusSucceeded {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusSucceeded)
	}
}

func TestRunFactoryRunWithDepsRecordsTimelineEventsForSuccess(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 20, 22, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	progressAt := createdAt.Add(2 * time.Minute)
	completedAt := createdAt.Add(3 * time.Minute)
	times := []time.Time{createdAt, startedAt, progressAt, completedAt}

	err := runFactoryRunWithDeps(context.Background(), ".", factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-timeline-success", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return completedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return "/workspace/hal", nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			events, err := req.Store.LoadEvents(req.RunID)
			if err != nil {
				t.Fatalf("LoadEvents(before progress) error: %v", err)
			}
			assertFactoryEventTypes(t, events, []string{
				factory.EventTypeRunCreated,
				factory.EventTypeStepStarted,
			})
			if req.RecordProgress == nil {
				t.Fatal("RecordProgress hook is nil")
			}
			return req.RecordProgress(factoryRunProgressEvent{
				Summary: "Auto validate step completed",
				Metadata: map[string]any{
					"step":   "validate",
					"status": "completed",
				},
			})
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	events, err := store.LoadEvents("run-timeline-success")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeCommandOutputSummary,
		factory.EventTypeStepEnded,
	})
	assertFactoryEventSequences(t, events)
	if !events[0].Timestamp.Equal(createdAt) {
		t.Fatalf("start timestamp = %s, want %s", events[0].Timestamp, createdAt)
	}
	if !events[1].Timestamp.Equal(startedAt) {
		t.Fatalf("pipeline start timestamp = %s, want %s", events[1].Timestamp, startedAt)
	}
	if !events[2].Timestamp.Equal(progressAt) {
		t.Fatalf("progress timestamp = %s, want %s", events[2].Timestamp, progressAt)
	}
	if !events[3].Timestamp.Equal(completedAt) {
		t.Fatalf("completion timestamp = %s, want %s", events[3].Timestamp, completedAt)
	}
	if events[2].Summary != "Auto validate step completed" {
		t.Fatalf("progress summary = %q", events[2].Summary)
	}
	if events[2].Metadata["step"] != "validate" {
		t.Fatalf("progress step metadata = %#v", events[2].Metadata)
	}
	if events[3].Metadata["status"] != factory.RunStatusSucceeded {
		t.Fatalf("completion status metadata = %#v", events[3].Metadata)
	}
}

func TestRunFactoryRunWithDepsRecordsTimelineEventsForFailure(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 20, 23, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	failedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, failedAt}
	pipelineErr := errors.New("pipeline stopped")

	err := runFactoryRunWithDeps(context.Background(), ".", factoryRunRequest{
		ReportPath: ".hal/reports/analysis.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-timeline-failure", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return failedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return "/workspace/hal", nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			events, err := req.Store.LoadEvents(req.RunID)
			if err != nil {
				t.Fatalf("LoadEvents(before failure) error: %v", err)
			}
			assertFactoryEventTypes(t, events, []string{
				factory.EventTypeRunCreated,
				factory.EventTypeStepStarted,
			})
			return pipelineErr
		},
	})
	if !errors.Is(err, pipelineErr) {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want pipeline error", err)
	}

	events, err := store.LoadEvents("run-timeline-failure")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	assertFactoryEventSequences(t, events)
	if !events[2].Timestamp.Equal(failedAt) {
		t.Fatalf("failure timestamp = %s, want %s", events[2].Timestamp, failedAt)
	}
	if events[2].Summary != "Local compound pipeline failed" {
		t.Fatalf("failure summary = %q", events[2].Summary)
	}
	if events[2].Metadata["status"] != factory.RunStatusFailed {
		t.Fatalf("failure status metadata = %#v", events[2].Metadata)
	}
	if events[2].Metadata["error"] != pipelineErr.Error() {
		t.Fatalf("failure error metadata = %#v", events[2].Metadata)
	}
	if !events[3].Timestamp.Equal(failedAt) {
		t.Fatalf("classification timestamp = %s, want %s", events[3].Timestamp, failedAt)
	}
	if events[3].Summary != "Failure classified" {
		t.Fatalf("classification summary = %q", events[3].Summary)
	}
	if events[3].Metadata["category"] != factory.FailureCategoryPipeline {
		t.Fatalf("classification category metadata = %#v", events[3].Metadata)
	}
}

func TestRunFactoryRunWithDepsRecordsMarkdownArtifacts(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	reportsDir := filepath.Join(halDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("MkdirAll(reportsDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-artifacts-markdown", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return completedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			writeFile(t, halDir, "auto-state.json", `{"step":"report","sourceMarkdown":".hal/prd-feature.md","reportPath":".hal/reports/review-20260621.md"}`)
			writeFile(t, reportsDir, "review-20260621.md", "# Review\n")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	record, err := store.LoadRun("run-artifacts-markdown")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd-feature.md")
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd.json")
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/auto-state.json")
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/reports/review-20260621.md")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-artifacts-markdown.json"))
	if got := len(record.Artifacts); got != 5 {
		t.Fatalf("artifacts len = %d, want 5: %#v", got, record.Artifacts)
	}
}

func TestRunFactoryRunWithDepsRecordsArchivedArtifacts(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	reportsDir := filepath.Join(halDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("MkdirAll(reportsDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}
	archiveRel := filepath.Join(".hal", "archive", "2026-06-21-factory")
	archiveDir := filepath.Join(dir, archiveRel)

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-archived-artifacts", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return completedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			writeFile(t, halDir, "auto-state.json", `{"step":"archive","sourceMarkdown":".hal/prd-feature.md","reportPath":".hal/reports/review-latest.md"}`)
			writeFile(t, reportsDir, "review-latest.md", "# Latest review\n")
			writeFile(t, reportsDir, "review-older.md", "# Older review\n")

			if err := os.MkdirAll(filepath.Join(archiveDir, "reports"), 0755); err != nil {
				t.Fatalf("MkdirAll(archive reports) error: %v", err)
			}
			for _, name := range []string{"prd.json", "auto-state.json", "prd-feature.md"} {
				if err := os.Rename(filepath.Join(halDir, name), filepath.Join(archiveDir, name)); err != nil {
					t.Fatalf("Rename(%s) error: %v", name, err)
				}
			}
			if err := os.Rename(filepath.Join(reportsDir, "review-older.md"), filepath.Join(archiveDir, "reports", "review-older.md")); err != nil {
				t.Fatalf("Rename(review-older.md) error: %v", err)
			}
			if err := os.Chtimes(filepath.Join(reportsDir, "review-latest.md"), completedAt, completedAt); err != nil {
				t.Fatalf("Chtimes(review-latest.md) error: %v", err)
			}
			if err := os.Chtimes(archiveDir, completedAt, completedAt); err != nil {
				t.Fatalf("Chtimes(archiveDir) error: %v", err)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	record, err := store.LoadRun("run-archived-artifacts")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	requireNoFactoryArtifactPath(t, record.Artifacts, ".hal/prd-feature.md")
	requireNoFactoryArtifactPath(t, record.Artifacts, ".hal/prd.json")
	requireNoFactoryArtifactPath(t, record.Artifacts, ".hal/auto-state.json")
	requireNoFactoryArtifactPath(t, record.Artifacts, ".hal/reports/review-older.md")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(archiveRel, "prd-feature.md"))
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(archiveRel, "prd.json"))
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(archiveRel, "auto-state.json"))
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(archiveRel, "reports", "review-older.md"))
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/reports/review-latest.md")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-archived-artifacts.json"))
}

func TestRunFactoryRunWithDepsExcludesUnchangedGeneratedStateArtifacts(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	reportsDir := filepath.Join(halDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("MkdirAll(reportsDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")
	writeFile(t, halDir, "prd.json", `{"project":"stale"}`)
	writeFile(t, halDir, "auto-state.json", `{"step":"report","sourceMarkdown":".hal/stale.md","reportPath":".hal/reports/stale.md"}`)
	writeFile(t, halDir, "stale.md", "# Stale\n")
	writeFile(t, reportsDir, "stale.md", "# Stale report\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 0, 0, 0, 0, time.UTC)
	staleAt := createdAt.Add(-1 * time.Hour)
	if err := os.Chtimes(filepath.Join(reportsDir, "stale.md"), staleAt, staleAt); err != nil {
		t.Fatalf("Chtimes(stale report) error: %v", err)
	}
	startedAt := createdAt.Add(1 * time.Minute)
	failedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, failedAt}
	pipelineErr := errors.New("pipeline failed before generating state")

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-stale-artifacts", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return failedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			return pipelineErr
		},
	})
	if !errors.Is(err, pipelineErr) {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want pipeline error", err)
	}

	record, err := store.LoadRun("run-stale-artifacts")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd-feature.md")
	requireNoFactoryArtifactPath(t, record.Artifacts, ".hal/prd.json")
	requireNoFactoryArtifactPath(t, record.Artifacts, ".hal/auto-state.json")
	requireNoFactoryArtifactPath(t, record.Artifacts, ".hal/stale.md")
	requireNoFactoryArtifactPath(t, record.Artifacts, ".hal/reports/stale.md")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-stale-artifacts.json"))
}

func TestRunFactoryRunWithDepsPersistsSuccessfulStatusAndResult(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 0, 30, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	progressAt := createdAt.Add(2 * time.Minute)
	completedAt := createdAt.Add(3 * time.Minute)
	times := []time.Time{createdAt, startedAt, progressAt, completedAt}
	var buf bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		JSON:         true,
	}, &buf, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-success-terminal", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return completedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			return req.RecordProgress(factoryRunProgressEvent{
				Summary: "Auto run step completed",
				Metadata: map[string]any{
					"step":   "run",
					"status": "completed",
				},
			})
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	record, err := store.LoadRun("run-success-terminal")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusSucceeded {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusSucceeded)
	}
	if record.CurrentStep != "done" {
		t.Fatalf("currentStep = %q, want done", record.CurrentStep)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(completedAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, completedAt)
	}
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd-feature.md")
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd.json")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-success-terminal.json"))

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeCommandOutputSummary,
		factory.EventTypeStepEnded,
	})

	var resp FactoryRunResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
	}
	if resp.Status != record.Status {
		t.Fatalf("result status = %q, want durable status %q", resp.Status, record.Status)
	}
	if resp.NextAction == nil {
		t.Fatal("nextAction should not be nil")
	}
	if resp.NextAction.Command != "hal factory status run-success-terminal --json" {
		t.Fatalf("nextAction.command = %q", resp.NextAction.Command)
	}
	if resp.EventSummary.Total != len(events) {
		t.Fatalf("eventSummary.total = %d, want %d", resp.EventSummary.Total, len(events))
	}
	if resp.EventSummary.ByType[factory.EventTypeStepEnded] != 1 {
		t.Fatalf("eventSummary.byType[%q] = %d, want 1", factory.EventTypeStepEnded, resp.EventSummary.ByType[factory.EventTypeStepEnded])
	}
	if resp.EventSummary.LastSummary != "Local compound pipeline completed" {
		t.Fatalf("eventSummary.lastSummary = %q", resp.EventSummary.LastSummary)
	}
	if resp.Failure != nil {
		t.Fatalf("failure = %#v, want nil", resp.Failure)
	}
	requireFactoryArtifactPath(t, resp.Artifacts, ".hal/prd-feature.md")
	requireFactoryArtifactPath(t, resp.Artifacts, ".hal/prd.json")
}

func TestRunFactoryRunWithDepsPersistsSuccessfulSandboxRunOutcome(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}
	var buf bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		Sandbox:      true,
	}, &buf, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-success", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return completedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory-sandbox-executor", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runSandbox: func(_ context.Context, req factorySandboxExecutorRequest) error {
			record := req.RunRecord
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = "factory-remote"
			record.Sandbox = &factory.SandboxMetadata{
				Name:           "factory-remote",
				Provider:       "daytona",
				Status:         sandbox.StatusRunning,
				Connection:     &factory.SandboxConnectionMetadata{PublicIP: "203.0.113.42"},
				SSHCommand:     "hal sandbox ssh factory-remote",
				CleanupCommand: "hal sandbox delete factory-remote",
				Handoff:        "Inspect sandbox with `hal sandbox ssh factory-remote`.",
			}
			if err := store.SaveRun(&record); err != nil {
				return err
			}
			if err := appendFactoryRunTimelineEvent(store, record.RunID, startedAt.Add(10*time.Second), factoryTimelineEvent{
				EventType: factory.EventTypeStepStarted,
				Summary:   "Remote sandbox execution started",
				Metadata: map[string]any{
					"source":      "remote_sandbox",
					"sandboxName": "factory-remote",
					"provider":    "daytona",
					"status":      factory.RunStatusRunning,
				},
			}); err != nil {
				return err
			}
			if _, err := io.WriteString(req.RemoteOutput, "remote ok\n"); err != nil {
				return err
			}
			if err := appendFactoryRunTimelineEvent(store, record.RunID, startedAt.Add(20*time.Second), factoryTimelineEvent{
				EventType: factory.EventTypeCommandOutputSummary,
				Message:   "remote ok",
				Summary:   "Remote sandbox output",
				Metadata: map[string]any{
					"source":      "remote_sandbox",
					"sandboxName": "factory-remote",
					"provider":    "daytona",
				},
			}); err != nil {
				return err
			}
			if err := appendFactoryRunTimelineEvent(store, record.RunID, startedAt.Add(30*time.Second), factoryTimelineEvent{
				EventType: factory.EventTypeStepEnded,
				Summary:   "Remote sandbox execution completed",
				Metadata: map[string]any{
					"source":      "remote_sandbox",
					"sandboxName": "factory-remote",
					"provider":    "daytona",
					"status":      factory.RunStatusSucceeded,
				},
			}); err != nil {
				return err
			}
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	record, err := store.LoadRun("run-sandbox-success")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusSucceeded || record.CurrentStep != "done" {
		t.Fatalf("terminal status/step = %s/%s, want succeeded/done", record.Status, record.CurrentStep)
	}
	if record.ExecutorMode != factory.ExecutorModeSandbox {
		t.Fatalf("executorMode = %q, want sandbox", record.ExecutorMode)
	}
	if record.SandboxName != "factory-remote" || record.Sandbox == nil {
		t.Fatalf("sandbox metadata = %#v", record.Sandbox)
	}
	if record.Sandbox.Provider != "daytona" || record.Sandbox.Status != sandbox.StatusRunning {
		t.Fatalf("sandbox provider/status = %#v", record.Sandbox)
	}
	if record.Sandbox.Connection == nil || record.Sandbox.Connection.PublicIP != "203.0.113.42" {
		t.Fatalf("sandbox connection = %#v", record.Sandbox.Connection)
	}
	if record.Sandbox.SSHCommand != "hal sandbox ssh factory-remote" || record.Sandbox.CleanupCommand != "hal sandbox delete factory-remote" {
		t.Fatalf("sandbox commands = %#v", record.Sandbox)
	}
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd-feature.md")
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd.json")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-sandbox-success.json"))

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeStepStarted,
		factory.EventTypeCommandOutputSummary,
		factory.EventTypeStepEnded,
		factory.EventTypeStepEnded,
	})
	assertFactoryEventSequences(t, events)
	if events[2].Summary != "Remote sandbox execution started" || events[2].Metadata["source"] != "remote_sandbox" {
		t.Fatalf("remote start event = %#v", events[2])
	}
	if events[3].Summary != "Remote sandbox output" || events[3].Message != "remote ok" {
		t.Fatalf("remote output event = %#v", events[3])
	}
	if events[4].Summary != "Remote sandbox execution completed" || events[4].Metadata["status"] != factory.RunStatusSucceeded {
		t.Fatalf("remote completion event = %#v", events[4])
	}
	if events[5].Summary != "Local compound pipeline completed" {
		t.Fatalf("terminal completion event = %#v", events[5])
	}

	output := buf.String()
	if !strings.Contains(output, "remote ok") || !strings.Contains(output, "Status: succeeded") {
		t.Fatalf("output = %q, want remote output and success summary", output)
	}
}

func TestRunFactoryRunWithDepsPreservesSandboxRecordedBranchOnSuccess(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	currentBranchCalls := 0
	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		Sandbox:      true,
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-remote-branch", nil },
		now:          func() time.Time { return time.Date(2026, 6, 21, 14, 0, 0, 0, time.UTC) },
		workingDir:   func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			currentBranchCalls++
			if currentBranchCalls > 1 {
				return "", fmt.Errorf("local branch refresh should be skipped for sandbox runs")
			}
			return "hal/local-base", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runSandbox: func(_ context.Context, req factorySandboxExecutorRequest) error {
			record := req.RunRecord
			record.BranchName = "hal/remote-feature"
			if err := store.SaveRun(&record); err != nil {
				return err
			}
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if currentBranchCalls != 1 {
		t.Fatalf("currentBranch calls = %d, want only initial run record resolution", currentBranchCalls)
	}
	record, err := store.LoadRun("run-sandbox-remote-branch")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.BranchName != "hal/remote-feature" {
		t.Fatalf("branchName = %q, want sandbox-recorded branch", record.BranchName)
	}
}

func TestRunFactoryRunWithDepsSuppressesSandboxRemoteOutputForJSON(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 30, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}
	var buf bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		Sandbox:      true,
		JSON:         true,
	}, &buf, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-json", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return completedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory-sandbox-executor", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runSandbox: func(_ context.Context, req factorySandboxExecutorRequest) error {
			if _, err := io.WriteString(req.RemoteOutput, "remote ok\n"); err != nil {
				return err
			}
			if err := appendFactoryRunTimelineEvent(store, req.RunRecord.RunID, startedAt.Add(10*time.Second), factoryTimelineEvent{
				EventType: factory.EventTypeCommandOutputSummary,
				Message:   "remote ok",
				Summary:   "Remote sandbox output",
				Metadata: map[string]any{
					"source": "remote_sandbox",
				},
			}); err != nil {
				return err
			}
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if strings.Contains(buf.String(), "remote ok") {
		t.Fatalf("output = %q, want JSON without streamed remote output", buf.String())
	}
	var resp FactoryRunResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
	}
	if resp.Status != factory.RunStatusSucceeded {
		t.Fatalf("status = %q, want %q", resp.Status, factory.RunStatusSucceeded)
	}
	events, err := store.LoadEvents("run-sandbox-json")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	if len(events) < 3 || events[2].Message != "remote ok" {
		t.Fatalf("events = %#v, want recorded remote output event", events)
	}
}

func TestRunFactoryRunWithDepsPreservesSandboxFailureHandoffCommand(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 2, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	failedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, failedAt}
	var buf bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		Sandbox:      true,
	}, &buf, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-failure", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return failedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory-sandbox-executor", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runSandbox: func(_ context.Context, req factorySandboxExecutorRequest) error {
			record := req.RunRecord
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = "factory-remote"
			record.Sandbox = &factory.SandboxMetadata{
				Name:           "factory-remote",
				Provider:       "daytona",
				Status:         sandbox.StatusRunning,
				SSHCommand:     "hal sandbox ssh factory-remote",
				CleanupCommand: "hal sandbox delete factory-remote",
				Handoff:        "Inspect sandbox with `hal sandbox ssh factory-remote`.",
			}
			record.Status = factory.RunStatusFailed
			record.CurrentStep = "run"
			record.Failure = &factory.FailureSummary{
				Step:             "run",
				Category:         factory.FailureCategoryPipeline,
				Message:          "remote pipeline failed",
				Recoverable:      true,
				SuggestedCommand: "hal sandbox ssh factory-remote",
			}
			if err := store.SaveRun(&record); err != nil {
				return err
			}
			return factorySandboxTestError("execute factory sandbox command: remote pipeline failed token=secret-token")
		},
	})
	if err == nil {
		t.Fatalf("runFactoryRunWithDeps() error = nil, want sandbox failure")
	}

	record, loadErr := store.LoadRun("run-sandbox-failure")
	if loadErr != nil {
		t.Fatalf("LoadRun() error: %v", loadErr)
	}
	if record.Failure == nil {
		t.Fatalf("failure summary = nil")
	}
	if record.Failure.Message != "remote pipeline failed" {
		t.Fatalf("failure message = %q, want sanitized sandbox message", record.Failure.Message)
	}
	if record.Failure.SuggestedCommand != "hal sandbox ssh factory-remote" {
		t.Fatalf("suggested command = %q", record.Failure.SuggestedCommand)
	}
	events, loadEventsErr := store.LoadEvents("run-sandbox-failure")
	if loadEventsErr != nil {
		t.Fatalf("LoadEvents() error: %v", loadEventsErr)
	}
	for _, event := range events {
		if errorText, ok := event.Metadata["error"].(string); ok && strings.Contains(errorText, "secret-token") {
			t.Fatalf("event leaked raw sandbox error: %#v", event)
		}
	}
	if !strings.Contains(buf.String(), "Suggested command: hal sandbox ssh factory-remote") {
		t.Fatalf("output = %q, want sandbox ssh handoff", buf.String())
	}
}

func TestRunFactoryRunWithDepsEmitsJSONForMarkdownAndReportFlows(t *testing.T) {
	tests := []struct {
		name       string
		runID      string
		sourcePath string
		req        factoryRunRequest
	}{
		{
			name:       "markdown",
			runID:      "run-json-markdown-success",
			sourcePath: ".hal/prd-feature.md",
			req: factoryRunRequest{
				MarkdownPath: ".hal/prd-feature.md",
				JSON:         true,
			},
		},
		{
			name:       "report",
			runID:      "run-json-report-success",
			sourcePath: ".hal/reports/analysis.md",
			req: factoryRunRequest{
				ReportPath: ".hal/reports/analysis.md",
				JSON:       true,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, ".hal")
			reportsDir := filepath.Join(halDir, "reports")
			if err := os.MkdirAll(reportsDir, 0755); err != nil {
				t.Fatalf("MkdirAll(reportsDir) error: %v", err)
			}
			writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")
			writeFile(t, reportsDir, "analysis.md", "# Analysis\n")

			store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
			createdAt := time.Date(2026, 6, 21, 1, 40, 0, 0, time.UTC)
			startedAt := createdAt.Add(1 * time.Minute)
			completedAt := createdAt.Add(2 * time.Minute)
			times := []time.Time{createdAt, startedAt, completedAt}
			var buf bytes.Buffer

			err := runFactoryRunWithDeps(context.Background(), dir, tt.req, &buf, factoryRunDeps{
				defaultStore: func() (factory.Store, error) { return store, nil },
				newRunID:     func() (string, error) { return tt.runID, nil },
				now: func() time.Time {
					if len(times) == 0 {
						return completedAt
					}
					next := times[0]
					times = times[1:]
					return next
				},
				workingDir: func() (string, error) { return dir, nil },
				currentBranch: func(string) (string, error) {
					return "hal/factory", nil
				},
				repoRemote: func(string) (string, error) {
					return "git@github.com:jywlabs/hal.git", nil
				},
				runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
					writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
					return nil
				},
			})
			if err != nil {
				t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
			}

			var resp FactoryRunResponse
			if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
				t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
			}
			if resp.ContractVersion != FactoryRunContractVersion {
				t.Fatalf("contractVersion = %q, want %q", resp.ContractVersion, FactoryRunContractVersion)
			}
			if resp.RunID != tt.runID {
				t.Fatalf("runId = %q, want %q", resp.RunID, tt.runID)
			}
			if resp.Status != factory.RunStatusSucceeded {
				t.Fatalf("status = %q, want %q", resp.Status, factory.RunStatusSucceeded)
			}
			if resp.NextAction == nil || resp.NextAction.Command != "hal factory status "+tt.runID+" --json" {
				t.Fatalf("nextAction = %#v", resp.NextAction)
			}
			if resp.EventSummary.Total != 3 {
				t.Fatalf("eventSummary.total = %d, want 3", resp.EventSummary.Total)
			}
			if resp.EventSummary.ByType[factory.EventTypeStepEnded] != 1 {
				t.Fatalf("eventSummary.byType[%q] = %d, want 1", factory.EventTypeStepEnded, resp.EventSummary.ByType[factory.EventTypeStepEnded])
			}
			if resp.EventSummary.LastSummary != "Local compound pipeline completed" {
				t.Fatalf("eventSummary.lastSummary = %q", resp.EventSummary.LastSummary)
			}
			if resp.Failure != nil {
				t.Fatalf("failure = %#v, want nil", resp.Failure)
			}
			requireFactoryArtifactPath(t, resp.Artifacts, tt.sourcePath)
			requireFactoryArtifactPath(t, resp.Artifacts, ".hal/prd.json")
			requireFactoryArtifactPath(t, resp.Artifacts, filepath.Join(store.RunsDir(), tt.runID+".json"))
		})
	}
}

func TestRunFactoryRunWithDepsEmitsFailureJSONForMarkdownAndReportFlows(t *testing.T) {
	tests := []struct {
		name       string
		runID      string
		sourcePath string
		req        factoryRunRequest
	}{
		{
			name:       "markdown",
			runID:      "run-json-markdown-failure",
			sourcePath: ".hal/prd-feature.md",
			req: factoryRunRequest{
				MarkdownPath: ".hal/prd-feature.md",
				JSON:         true,
			},
		},
		{
			name:       "report",
			runID:      "run-json-report-failure",
			sourcePath: ".hal/reports/analysis.md",
			req: factoryRunRequest{
				ReportPath: ".hal/reports/analysis.md",
				JSON:       true,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			halDir := filepath.Join(dir, ".hal")
			reportsDir := filepath.Join(halDir, "reports")
			if err := os.MkdirAll(reportsDir, 0755); err != nil {
				t.Fatalf("MkdirAll(reportsDir) error: %v", err)
			}
			writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")
			writeFile(t, reportsDir, "analysis.md", "# Analysis\n")

			store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
			createdAt := time.Date(2026, 6, 21, 1, 50, 0, 0, time.UTC)
			startedAt := createdAt.Add(1 * time.Minute)
			failedAt := createdAt.Add(2 * time.Minute)
			times := []time.Time{createdAt, startedAt, failedAt}
			pipelineErr := errors.New("step ci failed: workflow check failed")
			var buf bytes.Buffer

			err := runFactoryRunWithDeps(context.Background(), dir, tt.req, &buf, factoryRunDeps{
				defaultStore: func() (factory.Store, error) { return store, nil },
				newRunID:     func() (string, error) { return tt.runID, nil },
				now: func() time.Time {
					if len(times) == 0 {
						return failedAt
					}
					next := times[0]
					times = times[1:]
					return next
				},
				workingDir: func() (string, error) { return dir, nil },
				currentBranch: func(string) (string, error) {
					return "hal/factory", nil
				},
				repoRemote: func(string) (string, error) {
					return "git@github.com:jywlabs/hal.git", nil
				},
				runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
					writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
					return pipelineErr
				},
			})
			if !errors.Is(err, pipelineErr) {
				t.Fatalf("runFactoryRunWithDeps() error = %v, want pipeline error", err)
			}

			var resp FactoryRunResponse
			if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
				t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
			}
			if resp.ContractVersion != FactoryRunContractVersion {
				t.Fatalf("contractVersion = %q, want %q", resp.ContractVersion, FactoryRunContractVersion)
			}
			if resp.RunID != tt.runID {
				t.Fatalf("runId = %q, want %q", resp.RunID, tt.runID)
			}
			if resp.Status != factory.RunStatusFailed {
				t.Fatalf("status = %q, want %q", resp.Status, factory.RunStatusFailed)
			}
			if resp.NextAction == nil || resp.NextAction.Command != "hal factory status "+tt.runID+" --json" {
				t.Fatalf("nextAction = %#v", resp.NextAction)
			}
			if resp.Failure == nil {
				t.Fatal("failure should be emitted")
			}
			if resp.Failure.Classification != factory.FailureCategoryCI {
				t.Fatalf("failure.classification = %q, want %q", resp.Failure.Classification, factory.FailureCategoryCI)
			}
			if resp.Failure.ErrorMessage != pipelineErr.Error() {
				t.Fatalf("failure.errorMessage = %q, want %q", resp.Failure.ErrorMessage, pipelineErr.Error())
			}
			if resp.Failure.SuggestedCommand != "hal factory status "+tt.runID+" --json" {
				t.Fatalf("failure.suggestedCommand = %q", resp.Failure.SuggestedCommand)
			}
			if resp.EventSummary.Total != 4 {
				t.Fatalf("eventSummary.total = %d, want 4", resp.EventSummary.Total)
			}
			if resp.EventSummary.ByType[factory.EventTypeFailureClassification] != 1 {
				t.Fatalf("eventSummary.byType[%q] = %d, want 1", factory.EventTypeFailureClassification, resp.EventSummary.ByType[factory.EventTypeFailureClassification])
			}
			if resp.EventSummary.LastEventType != factory.EventTypeFailureClassification {
				t.Fatalf("eventSummary.lastEventType = %q", resp.EventSummary.LastEventType)
			}
			requireFactoryArtifactPath(t, resp.Artifacts, tt.sourcePath)
			requireFactoryArtifactPath(t, resp.Artifacts, ".hal/prd.json")
			requireFactoryArtifactPath(t, resp.Artifacts, filepath.Join(store.RunsDir(), tt.runID+".json"))
		})
	}
}

func TestRunFactoryRunWithDepsRendersHumanSummaryForSuccess(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 2, 40, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}
	var buf bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, &buf, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-human-success", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return completedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{
		"Run ID: run-human-success",
		"Status: succeeded",
		"Next action: hal factory status run-human-success --json",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("human output missing %q:\n%s", want, output)
		}
	}
	if json.Valid(bytes.TrimSpace(buf.Bytes())) {
		t.Fatalf("human output should not be JSON: %s", output)
	}
}

func TestRunFactoryRunWithDepsRendersHumanSummaryForFailure(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 2, 50, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	failedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, failedAt}
	pipelineErr := errors.New("step ci failed: workflow check failed")
	var buf bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, &buf, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-human-failure", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return failedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			return pipelineErr
		},
	})
	if !errors.Is(err, pipelineErr) {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want pipeline error", err)
	}

	output := buf.String()
	for _, want := range []string{
		"Run ID: run-human-failure",
		"Status: failed",
		"Error: step ci failed: workflow check failed",
		"Suggested command: hal factory status run-human-failure --json",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("human output missing %q:\n%s", want, output)
		}
	}
	if json.Valid(bytes.TrimSpace(buf.Bytes())) {
		t.Fatalf("human output should not be JSON: %s", output)
	}
}

func TestRunFactoryRunWithDepsRecordsReportArtifactsOnFailure(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	reportsDir := filepath.Join(halDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("MkdirAll(reportsDir) error: %v", err)
	}
	writeFile(t, reportsDir, "analysis.md", "# Analysis\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	failedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, failedAt}
	pipelineErr := errors.New("pipeline failed")

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		ReportPath: ".hal/reports/analysis.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-artifacts-report-failure", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return failedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			writeFile(t, halDir, "auto-state.json", `{"step":"run","reportPath":".hal/reports/analysis.md"}`)
			writeFile(t, reportsDir, "ci-output.log", "failed\n")
			ciOutputPath := filepath.Join(reportsDir, "ci-output.log")
			if err := os.Chtimes(ciOutputPath, failedAt, failedAt); err != nil {
				t.Fatalf("Chtimes(%q) error: %v", ciOutputPath, err)
			}
			return pipelineErr
		},
	})
	if !errors.Is(err, pipelineErr) {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want pipeline error", err)
	}

	record, err := store.LoadRun("run-artifacts-report-failure")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/reports/analysis.md")
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd.json")
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/auto-state.json")
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/reports/ci-output.log")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-artifacts-report-failure.json"))
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusFailed)
	}
	if record.CurrentStep != "run" {
		t.Fatalf("currentStep = %q, want run", record.CurrentStep)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(failedAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, failedAt)
	}
	if record.Failure == nil {
		t.Fatal("failure summary should be persisted")
	}
	if record.Failure.Category != factory.FailureCategoryPipeline {
		t.Fatalf("failure category = %q, want %q", record.Failure.Category, factory.FailureCategoryPipeline)
	}
	if record.Failure.Message != pipelineErr.Error() {
		t.Fatalf("failure message = %q, want %q", record.Failure.Message, pipelineErr.Error())
	}
	if record.Failure.SuggestedCommand != "hal factory status run-artifacts-report-failure --json" {
		t.Fatalf("failure suggestedCommand = %q", record.Failure.SuggestedCommand)
	}
}

func TestRunFactoryRunWithDepsPersistsFailedStatusAndDetails(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 20, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	failedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, failedAt}
	pipelineErr := errors.New("step ci failed: workflow check failed")

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-failed-terminal", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return failedAt
			}
			next := times[0]
			times = times[1:]
			return next
		},
		workingDir: func() (string, error) { return dir, nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			return pipelineErr
		},
	})
	if !errors.Is(err, pipelineErr) {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want pipeline error", err)
	}

	record, err := store.LoadRun("run-failed-terminal")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusFailed)
	}
	if record.CurrentStep != compound.StepCI {
		t.Fatalf("currentStep = %q, want %q", record.CurrentStep, compound.StepCI)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(failedAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, failedAt)
	}
	if record.Failure == nil {
		t.Fatal("failure summary should be persisted")
	}
	if record.Failure.Step != compound.StepCI {
		t.Fatalf("failure step = %q, want %q", record.Failure.Step, compound.StepCI)
	}
	if record.Failure.Category != factory.FailureCategoryCI {
		t.Fatalf("failure category = %q, want %q", record.Failure.Category, factory.FailureCategoryCI)
	}
	if record.Failure.Message != pipelineErr.Error() {
		t.Fatalf("failure message = %q, want %q", record.Failure.Message, pipelineErr.Error())
	}
	if !record.Failure.Recoverable {
		t.Fatal("failure should be recoverable")
	}
	if record.Failure.SuggestedCommand != "hal factory status run-failed-terminal --json" {
		t.Fatalf("failure suggestedCommand = %q", record.Failure.SuggestedCommand)
	}
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd-feature.md")
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd.json")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-failed-terminal.json"))

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	classification := events[3]
	if classification.Metadata["step"] != compound.StepCI {
		t.Fatalf("classification step metadata = %#v", classification.Metadata)
	}
	if classification.Metadata["category"] != factory.FailureCategoryCI {
		t.Fatalf("classification category metadata = %#v", classification.Metadata)
	}
	if classification.Metadata["suggestedCommand"] != "hal factory status run-failed-terminal --json" {
		t.Fatalf("classification suggestedCommand metadata = %#v", classification.Metadata)
	}
}

func TestClassifyFactoryRunFailure(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "validation exit code",
			err:  exitWithCode(nil, ExitCodeValidation, errors.New("invalid input")),
			want: factory.FailureCategoryValidation,
		},
		{
			name: "validate step",
			err:  errors.New("step validate failed: invalid PRD"),
			want: factory.FailureCategoryValidation,
		},
		{
			name: "ci step",
			err:  errors.New("step ci failed: workflow failed"),
			want: factory.FailureCategoryCI,
		},
		{
			name: "branch step",
			err:  errors.New("step branch failed: git checkout failed"),
			want: factory.FailureCategoryGit,
		},
		{
			name: "engine message",
			err:  errors.New("failed to create engine: codex unavailable"),
			want: factory.FailureCategoryEngine,
		},
		{
			name: "pipeline message",
			err:  errors.New("pipeline failed"),
			want: factory.FailureCategoryPipeline,
		},
		{
			name: "unknown message",
			err:  errors.New("boom"),
			want: factory.FailureCategoryUnknown,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyFactoryRunFailure(tt.err); got != tt.want {
				t.Fatalf("classifyFactoryRunFailure() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRunFactoryRunPipelineWithDepsPassesMarkdownEntryToAuto(t *testing.T) {
	ctx := context.WithValue(context.Background(), testContextKey("factory-run"), "markdown")
	var gotCtx context.Context
	var got factoryRunAutoRequest
	called := false

	err := runFactoryRunPipelineWithDeps(ctx, factoryRunPipelineRequest{
		Request: factoryRunRequest{
			MarkdownPath: " .hal/prd-feature.md ",
			BaseBranch:   " develop ",
		},
	}, factoryRunPipelineDeps{
		runAuto: func(ctx context.Context, req factoryRunAutoRequest) error {
			called = true
			gotCtx = ctx
			got = req
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunPipelineWithDeps() unexpected error: %v", err)
	}
	if !called {
		t.Fatal("auto dependency was not invoked")
	}
	if gotCtx != ctx {
		t.Fatal("auto dependency did not receive the original context")
	}
	want := factoryRunAutoRequest{
		Args:       []string{".hal/prd-feature.md"},
		BaseBranch: "develop",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("auto request = %#v, want %#v", got, want)
	}
}

func TestRunFactoryRunPipelineWithDepsPassesReportEntryToAuto(t *testing.T) {
	var got factoryRunAutoRequest

	err := runFactoryRunPipelineWithDeps(context.Background(), factoryRunPipelineRequest{
		Request: factoryRunRequest{
			ReportPath: ".hal/reports/analysis.md",
			BaseBranch: "release",
		},
	}, factoryRunPipelineDeps{
		runAuto: func(_ context.Context, req factoryRunAutoRequest) error {
			got = req
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunPipelineWithDeps() unexpected error: %v", err)
	}
	want := factoryRunAutoRequest{
		ReportPath: ".hal/reports/analysis.md",
		BaseBranch: "release",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("auto request = %#v, want %#v", got, want)
	}
}

func TestRunFactoryRunPipelineWithDepsUsesRecordBaseBranchFallback(t *testing.T) {
	var got factoryRunAutoRequest

	err := runFactoryRunPipelineWithDeps(context.Background(), factoryRunPipelineRequest{
		Request: factoryRunRequest{},
		Record: factory.RunRecord{
			BaseBranch: " hal/factory ",
		},
	}, factoryRunPipelineDeps{
		runAuto: func(_ context.Context, req factoryRunAutoRequest) error {
			got = req
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunPipelineWithDeps() unexpected error: %v", err)
	}
	want := factoryRunAutoRequest{
		BaseBranch: "hal/factory",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("auto request = %#v, want %#v", got, want)
	}
}

func TestRunFactoryRunPipelineWithDepsPassesProgressRecorderToAuto(t *testing.T) {
	var got []factoryRunProgressEvent

	err := runFactoryRunPipelineWithDeps(context.Background(), factoryRunPipelineRequest{
		RecordProgress: func(event factoryRunProgressEvent) error {
			got = append(got, event)
			return nil
		},
	}, factoryRunPipelineDeps{
		runAuto: func(_ context.Context, req factoryRunAutoRequest) error {
			if req.RecordProgress == nil {
				t.Fatal("RecordProgress was not passed to auto dependency")
			}
			return req.RecordProgress(factoryRunProgressEvent{
				Summary: "Auto validate step started",
				Metadata: map[string]any{
					"step":   "validate",
					"status": "started",
				},
			})
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunPipelineWithDeps() unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("progress events = %#v, want 1 event", got)
	}
	if got[0].Summary != "Auto validate step started" {
		t.Fatalf("progress summary = %q", got[0].Summary)
	}
	if got[0].Metadata["step"] != "validate" {
		t.Fatalf("progress metadata = %#v", got[0].Metadata)
	}
}

func TestFactoryRunProgressWriterRecordsStepLines(t *testing.T) {
	var got []factoryRunProgressEvent
	writer := &factoryRunProgressWriter{
		record: func(event factoryRunProgressEvent) error {
			got = append(got, event)
			return nil
		},
	}

	if _, err := writer.Write([]byte("   Step: validate\n   Step: validate\n   Step: run\n")); err != nil {
		t.Fatalf("Write() error: %v", err)
	}
	if err := writer.Flush(); err != nil {
		t.Fatalf("Flush() error: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("progress events = %#v, want 2 events", got)
	}
	if got[0].Summary != "Auto validate step started" || got[0].Metadata["step"] != "validate" {
		t.Fatalf("first progress event = %#v", got[0])
	}
	if got[1].Summary != "Auto run step started" || got[1].Metadata["step"] != "run" {
		t.Fatalf("second progress event = %#v", got[1])
	}
}

func TestRunAutoForFactoryRunKeepsDirectAutoBehaviorIsolated(t *testing.T) {
	chdirTemp(t)

	beforeFlagContract := snapshotAutoCommandFlagContract(t)
	restoreAutoPackageFlagDefaults(t)

	autoDryRunFlag = true
	autoResumeFlag = true
	autoNoCIFlag = true
	autoSkipPRFlag = true
	autoNoReviewFlag = true
	autoModeFlag = "strict"
	autoReviewStreakFlag = 3
	autoReviewMaxFlag = 15
	autoReportFlag = "leaked-report.md"
	autoEngineFlag = "claude"
	autoBaseFlag = "leaked-base"
	autoJSONFlag = true

	poisonedFlags := snapshotAutoCommandFlags(t)
	err := runAutoForFactoryRun(context.Background(), factoryRunAutoRequest{})
	if err == nil {
		t.Fatal("runAutoForFactoryRun() error = nil, want no-source error")
	}
	wantNoSource := "no auto source found (sourcePriority=report_first): looked for latest report in auto.reportsDir, then newest .hal/prd-*.md; provide 'hal auto <prd-path>' or '--report <path>'"
	if err.Error() != wantNoSource {
		t.Fatalf("runAutoForFactoryRun() error = %q, want %q", err.Error(), wantNoSource)
	}

	afterFlagContract := snapshotAutoCommandFlagContract(t)
	if !reflect.DeepEqual(afterFlagContract, beforeFlagContract) {
		t.Fatalf("factory auto wrapper mutated direct auto flag contract\nbefore: %#v\nafter: %#v", beforeFlagContract, afterFlagContract)
	}
	afterPoisonedFlags := snapshotAutoCommandFlags(t)
	if !reflect.DeepEqual(afterPoisonedFlags, poisonedFlags) {
		t.Fatalf("factory auto wrapper mutated package-bound auto flag values\nbefore: %#v\nafter: %#v", poisonedFlags, afterPoisonedFlags)
	}

	if err := autoCmd.Args(autoCmd, nil); err != nil {
		t.Fatalf("auto args validator rejected zero args after factory wrapper: %v", err)
	}
	if err := autoCmd.Args(autoCmd, []string{"feature.md"}); err != nil {
		t.Fatalf("auto args validator rejected one arg after factory wrapper: %v", err)
	}
	if err := autoCmd.Args(autoCmd, []string{"one.md", "two.md"}); err == nil {
		t.Fatal("auto args validator accepted two args after factory wrapper")
	}

	jsonCmd, jsonOut := newAutoTestCommand(t)
	if err := jsonCmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set json flag: %v", err)
	}
	if err := runAuto(jsonCmd, nil); err != nil {
		t.Fatalf("direct runAuto JSON returned error after factory wrapper: %v", err)
	}
	assertAutoJSONContractV2(t, jsonOut.Bytes())

	reportPath := filepath.Join(".", "report.md")
	if err := os.WriteFile(reportPath, []byte("# Report\n"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	textCmd, textOut := newAutoTestCommand(t)
	if err := textCmd.Flags().Set("dry-run", "true"); err != nil {
		t.Fatalf("set dry-run flag: %v", err)
	}
	if err := textCmd.Flags().Set("report", reportPath); err != nil {
		t.Fatalf("set report flag: %v", err)
	}
	if err := runAuto(textCmd, nil); err != nil {
		t.Fatalf("direct runAuto text dry-run returned error after factory wrapper: %v", err)
	}
	textOutput := textOut.String()
	if strings.Contains(textOutput, "factory") {
		t.Fatalf("direct auto text output should not mention factory wrapper: %q", textOutput)
	}
	if !strings.Contains(textOutput, "auto pipeline") {
		t.Fatalf("direct auto text output should keep auto pipeline header: %q", textOutput)
	}
	if json.Valid(bytes.TrimSpace(textOut.Bytes())) {
		t.Fatalf("direct auto text output should not be JSON: %q", textOutput)
	}
}

type testContextKey string

type autoCommandFlagSnapshot struct {
	Name       string
	Value      string
	DefValue   string
	Changed    bool
	Hidden     bool
	Deprecated string
}

func snapshotAutoCommandFlags(t *testing.T) []autoCommandFlagSnapshot {
	t.Helper()

	var flags []autoCommandFlagSnapshot
	autoCmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		flags = append(flags, autoCommandFlagSnapshot{
			Name:       flag.Name,
			Value:      flag.Value.String(),
			DefValue:   flag.DefValue,
			Changed:    flag.Changed,
			Hidden:     flag.Hidden,
			Deprecated: flag.Deprecated,
		})
	})
	return flags
}

type autoCommandFlagContract struct {
	Name       string
	DefValue   string
	Hidden     bool
	Deprecated string
}

func snapshotAutoCommandFlagContract(t *testing.T) []autoCommandFlagContract {
	t.Helper()

	var flags []autoCommandFlagContract
	autoCmd.LocalFlags().VisitAll(func(flag *pflag.Flag) {
		flags = append(flags, autoCommandFlagContract{
			Name:       flag.Name,
			DefValue:   flag.DefValue,
			Hidden:     flag.Hidden,
			Deprecated: flag.Deprecated,
		})
	})
	return flags
}

func restoreAutoPackageFlagDefaults(t *testing.T) {
	t.Helper()

	originalDryRun := autoDryRunFlag
	originalResume := autoResumeFlag
	originalNoCI := autoNoCIFlag
	originalSkipPR := autoSkipPRFlag
	originalNoReview := autoNoReviewFlag
	originalMode := autoModeFlag
	originalReviewStreak := autoReviewStreakFlag
	originalReviewMax := autoReviewMaxFlag
	originalReport := autoReportFlag
	originalEngine := autoEngineFlag
	originalBase := autoBaseFlag
	originalJSON := autoJSONFlag

	t.Cleanup(func() {
		autoDryRunFlag = originalDryRun
		autoResumeFlag = originalResume
		autoNoCIFlag = originalNoCI
		autoSkipPRFlag = originalSkipPR
		autoNoReviewFlag = originalNoReview
		autoModeFlag = originalMode
		autoReviewStreakFlag = originalReviewStreak
		autoReviewMaxFlag = originalReviewMax
		autoReportFlag = originalReport
		autoEngineFlag = originalEngine
		autoBaseFlag = originalBase
		autoJSONFlag = originalJSON
	})
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
		"runId", "status", "executorMode", "source", "repoPath", "repoRemote", "branchName",
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
				"managed sandbox",
				"hal factory run .hal/prd-feature.md --sandbox",
				"--sandbox",
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
		RunID:        runID,
		Status:       factory.RunStatusRunning,
		ExecutorMode: factory.ExecutorModeLocal,
		Source:       factory.SourceMetadata{Kind: factory.SourceKindPRD, Path: ".hal/prd.json", Title: "Factory"},
		RepoPath:     "/workspace/hal",
		RepoRemote:   "git@github.com:jywlabs/hal.git",
		BranchName:   "hal/factory",
		BaseBranch:   "develop",
		CurrentStep:  "run",
		CreatedAt:    createdAt,
		UpdatedAt:    updatedAt,
	}
}

func assertFactoryRunRecordReadyForPipeline(t *testing.T, record factory.RunRecord, wantSource factory.SourceMetadata) {
	t.Helper()

	if record.Status != factory.RunStatusRunning {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusRunning)
	}
	if record.ExecutorMode != factory.ExecutorModeLocal {
		t.Fatalf("executorMode = %q, want %q", record.ExecutorMode, factory.ExecutorModeLocal)
	}
	if !reflect.DeepEqual(record.Source, wantSource) {
		t.Fatalf("source = %#v, want %#v", record.Source, wantSource)
	}
	if record.RepoPath != "/workspace/hal" {
		t.Fatalf("repoPath = %q, want /workspace/hal", record.RepoPath)
	}
	if record.RepoRemote != "git@github.com:jywlabs/hal.git" {
		t.Fatalf("repoRemote = %q, want git@github.com:jywlabs/hal.git", record.RepoRemote)
	}
	if record.BranchName != "hal/factory" {
		t.Fatalf("branchName = %q, want hal/factory", record.BranchName)
	}
	if record.CurrentStep != "run" {
		t.Fatalf("currentStep = %q, want run", record.CurrentStep)
	}
}

func assertFactoryEventTypes(t *testing.T, events []factory.EventRecord, want []string) {
	t.Helper()

	got := make([]string, 0, len(events))
	for _, event := range events {
		got = append(got, event.EventType)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("event types = %v, want %v", got, want)
	}
}

func assertFactoryEventSequences(t *testing.T, events []factory.EventRecord) {
	t.Helper()

	for i, event := range events {
		want := int64(i + 1)
		if event.Sequence != want {
			t.Fatalf("event %d sequence = %d, want %d", i, event.Sequence, want)
		}
	}
}

func requireFactoryArtifactPath(t *testing.T, artifacts []factory.ArtifactReference, wantPath string) factory.ArtifactReference {
	t.Helper()
	for _, artifact := range artifacts {
		if artifact.Path == wantPath {
			return artifact
		}
	}
	t.Fatalf("artifact path %q missing from %#v", wantPath, artifacts)
	return factory.ArtifactReference{}
}

func requireNoFactoryArtifactPath(t *testing.T, artifacts []factory.ArtifactReference, wantPath string) {
	t.Helper()
	for _, artifact := range artifacts {
		if artifact.Path == wantPath {
			t.Fatalf("artifact path %q should not be present in %#v", wantPath, artifacts)
		}
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
