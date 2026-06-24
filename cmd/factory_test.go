package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	"github.com/jywlabs/hal/internal/verify"
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
				"Queue commands manage",
			},
			requiredExampleLines: []string{
				"hal factory run .hal/prd-feature.md",
				"hal factory run --report .hal/reports/analysis.md --json",
				"hal factory list",
				"hal factory list --json",
				"hal factory status <run-id> --json",
				"hal factory artifacts <run-id>",
				"hal factory trigger --repo . --prd .hal/prd-feature.md --json",
				"hal factory queue list --json",
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
		{
			name: "factory artifacts command",
			cmd:  factoryArtifactsCmd,
			requiredLongPhrases: []string{
				"collected artifacts",
				"global factory store",
				"display path",
				"store-backed path",
				"summary metadata",
			},
			requiredExampleLines: []string{
				"hal factory artifacts run-20260620-001",
				"hal factory artifacts run-20260620-001 --json",
			},
		},
		{
			name: "factory trigger command",
			cmd:  factoryTriggerCmd,
			requiredLongPhrases: []string{
				"external trigger context",
				"--prd <path>",
				"--report <path>",
				"--discover-report",
				"--repo <path>",
				"durable factory queue",
				"hal factory queue work",
			},
			requiredExampleLines: []string{
				"hal factory trigger --repo . --prd .hal/prd-feature.md",
				"hal factory trigger --repo /work/hal --report .hal/reports/analysis.md --json",
				"hal factory trigger --repo /work/hal --discover-report --json",
			},
		},
		{
			name: "factory queue command",
			cmd:  factoryQueueCmd,
			requiredLongPhrases: []string{
				"global factory queue",
				"enqueue existing factory runs",
				"claim one queued run",
				"survives CLI exits and restarts",
			},
			requiredExampleLines: []string{
				"hal factory queue add run-20260620-001 local",
				"hal factory queue list --json",
				"hal factory queue work --json",
			},
		},
		{
			name: "factory queue add command",
			cmd:  factoryQueueAddCmd,
			requiredLongPhrases: []string{
				"existing factory run",
				"executor mode",
				"--json",
				"factory-queue-add-v1",
			},
			requiredExampleLines: []string{
				"hal factory queue add run-20260620-001 local",
				"hal factory queue add run-20260620-001 local --json",
			},
		},
		{
			name: "factory queue list command",
			cmd:  factoryQueueListCmd,
			requiredLongPhrases: []string{
				"global factory store",
				"--json",
				"factory-queue-list-v1",
				"queued, claimed, and failed entries",
			},
			requiredExampleLines: []string{
				"hal factory queue list",
				"hal factory queue list --json",
			},
		},
		{
			name: "factory queue work command",
			cmd:  factoryQueueWorkCmd,
			requiredLongPhrases: []string{
				"at most one queued factory run",
				"atomically claim",
				"--json",
				"factory-queue-work-v1",
				"no-work response",
			},
			requiredExampleLines: []string{
				"hal factory queue work",
				"hal factory queue work --json",
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
		name        string
		args        []string
		reportPath  string
		baseBranch  string
		sandboxName string
		jsonMode    bool
		sandbox     bool
		want        factoryRunRequest
		wantErr     string
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
			name:        "sandbox name option",
			args:        []string{".hal/prd-feature.md"},
			baseBranch:  "main",
			sandboxName: "factory-dev",
			sandbox:     true,
			want: factoryRunRequest{
				MarkdownPath: ".hal/prd-feature.md",
				BaseBranch:   "main",
				SandboxName:  "factory-dev",
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
			name:        "sandbox name requires sandbox",
			args:        []string{".hal/prd-feature.md"},
			baseBranch:  "main",
			sandboxName: "factory-dev",
			wantErr:     "--sandbox-name requires --sandbox",
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
			got, err := parseFactoryRunRequest(tt.args, tt.reportPath, tt.baseBranch, tt.sandboxName, tt.jsonMode, tt.sandbox)
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
	for _, flagName := range []string{"report", "base", "sandbox-name", "sandbox", "json"} {
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

func TestFactoryRunArgsValidationJSONRejectsReportWithPositionalPayload(t *testing.T) {
	var buf bytes.Buffer
	cmd := &cobra.Command{Use: "run", Args: validateFactoryRunArgs}
	cmd.SetOut(&buf)
	cmd.Flags().String("report", ".hal/reports/analysis.md", "")
	cmd.Flags().Bool("json", true, "")

	err := cmd.Args(cmd, []string{".hal/prd-feature.md"})
	assertFactoryRunArgsValidationJSON(t, err, buf.Bytes(), "--report cannot be used with a positional PRD markdown path")
}

func TestFactoryRunArgsValidationJSONRejectsTooManyPositionalsPayload(t *testing.T) {
	var buf bytes.Buffer
	cmd := &cobra.Command{Use: "run", Args: validateFactoryRunArgs}
	cmd.SetOut(&buf)
	cmd.Flags().String("report", "", "")
	cmd.Flags().Bool("json", true, "")

	err := cmd.Args(cmd, []string{"one.md", "two.md"})
	assertFactoryRunArgsValidationJSON(t, err, buf.Bytes(), "accepts at most 1 arg(s), received 2")
}

func assertFactoryRunArgsValidationJSON(t *testing.T, err error, data []byte, wantMessage string) {
	t.Helper()

	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("Args() error type = %T, want *ExitCodeError", err)
	}
	if exitErr.Code != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitErr.Code, ExitCodeValidation)
	}
	if exitErr.Err != nil {
		t.Fatalf("exit error payload = %v, want nil after JSON render", exitErr.Err)
	}

	var resp FactoryRunResponse
	if jsonErr := json.Unmarshal(data, &resp); jsonErr != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", jsonErr, data)
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
	if resp.Failure.ErrorMessage != wantMessage {
		t.Fatalf("failure.errorMessage = %q, want %q", resp.Failure.ErrorMessage, wantMessage)
	}
	if resp.Artifacts == nil || len(resp.Artifacts) != 0 {
		t.Fatalf("artifacts = %#v, want empty non-nil array", resp.Artifacts)
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
		SandboxName:  "factory-dev",
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
			if req.SandboxName != "factory-dev" {
				t.Fatalf("sandbox name = %q, want factory-dev", req.SandboxName)
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
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
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

func TestRunFactoryRunWithDepsStripsCredentialsFromPersistedRepoRemote(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 20, 20, 30, 0, 0, time.UTC)
	rawRemote := "https://token-user:super-secret@github.com/example/private.git"
	wantRemote := "https://github.com/example/private.git"

	err := runFactoryRunWithDeps(context.Background(), ".", factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "develop",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-redacted-remote", nil },
		now:          func() time.Time { return now },
		workingDir:   func() (string, error) { return "/workspace/private", nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return rawRemote, nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			loaded, err := req.Store.LoadRun(req.RunID)
			if err != nil {
				t.Fatalf("pipeline LoadRun() error: %v", err)
			}
			if loaded.RepoRemote != wantRemote {
				t.Fatalf("pipeline repoRemote = %q, want %q", loaded.RepoRemote, wantRemote)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	loaded, err := store.LoadRun("run-redacted-remote")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if loaded.RepoRemote != wantRemote {
		t.Fatalf("persisted repoRemote = %q, want %q", loaded.RepoRemote, wantRemote)
	}

	var listBuf bytes.Buffer
	if err := runFactoryListWithDeps(&listBuf, true, factoryListDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	}); err != nil {
		t.Fatalf("runFactoryListWithDeps() unexpected error: %v", err)
	}
	assertFactoryOutputExcludesRemoteCredentials(t, listBuf.String(), wantRemote)

	var statusBuf bytes.Buffer
	if err := runFactoryStatusWithDeps(&statusBuf, "run-redacted-remote", true, factoryStatusDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	}); err != nil {
		t.Fatalf("runFactoryStatusWithDeps() unexpected error: %v", err)
	}
	assertFactoryOutputExcludesRemoteCredentials(t, statusBuf.String(), wantRemote)
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

func TestNewFactoryRunRecordStoresAbsoluteRepoPath(t *testing.T) {
	wantRepoPath, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("filepath.Abs() error: %v", err)
	}

	record, _, err := newFactoryRunRecord(".", factoryRunRequest{}, factoryRunDeps{
		newRunID:   func() (string, error) { return "run-absolute-repo", nil },
		now:        func() time.Time { return time.Date(2026, 6, 21, 22, 0, 0, 0, time.UTC) },
		workingDir: func() (string, error) { return ".", nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
	})
	if err != nil {
		t.Fatalf("newFactoryRunRecord() unexpected error: %v", err)
	}
	if record.RepoPath != wantRepoPath {
		t.Fatalf("repoPath = %q, want %q", record.RepoPath, wantRepoPath)
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

func TestRunFactoryRunWithDepsMarksRunFailedWhenArtifactCollectionFails(t *testing.T) {
	dir := t.TempDir()
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 4, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}
	artifactErr := errors.New("status snapshot failed")

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-artifact-collection-failed", nil },
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
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) {
			return factorySnapshotArtifact{}, artifactErr
		},
	})
	if !errors.Is(err, artifactErr) {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want artifact error", err)
	}

	record, err := store.LoadRun("run-artifact-collection-failed")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusFailed)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(completedAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, completedAt)
	}
	if record.Failure == nil || !strings.Contains(record.Failure.Message, "record factory artifacts") {
		t.Fatalf("failure summary = %#v, want artifact collection failure", record.Failure)
	}
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-artifact-collection-failed.json"))

	events, err := store.LoadEvents("run-artifact-collection-failed")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeFailureClassification,
	})
	if events[2].RunID != "run-artifact-collection-failed" {
		t.Fatalf("failure classification runID = %q", events[2].RunID)
	}
}

func TestRunFactoryRunWithDepsPreservesPartialArtifactsWhenArtifactCollectionFails(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	reportsDir := filepath.Join(halDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("MkdirAll(reportsDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 5, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}
	reportPath := filepath.Join(".hal", "reports", "blocked.log")

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-partial-artifact-failed", nil },
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
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			writeFile(t, reportsDir, "blocked.log", "blocked\n")
			ref := factory.ArtifactReference{
				Name: factoryGeneratedReportArtifactName("blocked.log"),
				Type: factoryArtifactTypeForPath(reportPath),
				Path: filepath.Clean(reportPath),
			}
			ref.ID = factoryArtifactID(ref)
			blockedArtifactPath := filepath.Join(store.ArtifactsDir(), "run-partial-artifact-failed", strings.Trim(ref.ID, "."))
			if err := os.MkdirAll(blockedArtifactPath, 0755); err != nil {
				t.Fatalf("MkdirAll(blocked artifact path) error: %v", err)
			}
			if err := os.MkdirAll(filepath.Join(blockedArtifactPath+".bak", "child"), 0755); err != nil {
				t.Fatalf("MkdirAll(blocked artifact backup path) error: %v", err)
			}
			return nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "record factory artifacts") {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want artifact collection error", err)
	}

	record, err := store.LoadRun("run-partial-artifact-failed")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusFailed)
	}
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd-feature.md")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-partial-artifact-failed.json"))
}

func TestRunFactoryRunWithDepsPreservesPartialArtifactsWhenPipelineAndArtifactCollectionFail(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	reportsDir := filepath.Join(halDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("MkdirAll(reportsDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 5, 10, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	failedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, failedAt}
	reportPath := filepath.Join(".hal", "reports", "blocked.log")
	pipelineErr := errors.New("pipeline failed after writing partial evidence")

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-pipeline-partial-artifact-failed", nil },
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
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			writeFile(t, reportsDir, "blocked.log", "blocked\n")
			ref := factory.ArtifactReference{
				Name: factoryGeneratedReportArtifactName("blocked.log"),
				Type: factoryArtifactTypeForPath(reportPath),
				Path: filepath.Clean(reportPath),
			}
			ref.ID = factoryArtifactID(ref)
			blockedArtifactPath := filepath.Join(store.ArtifactsDir(), "run-pipeline-partial-artifact-failed", strings.Trim(ref.ID, "."))
			if err := os.MkdirAll(blockedArtifactPath, 0755); err != nil {
				t.Fatalf("MkdirAll(blocked artifact path) error: %v", err)
			}
			if err := os.MkdirAll(filepath.Join(blockedArtifactPath+".bak", "child"), 0755); err != nil {
				t.Fatalf("MkdirAll(blocked artifact backup path) error: %v", err)
			}
			return pipelineErr
		},
	})
	if !errors.Is(err, pipelineErr) || !strings.Contains(err.Error(), "record factory artifacts") {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want pipeline and artifact collection errors", err)
	}

	record, err := store.LoadRun("run-pipeline-partial-artifact-failed")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusFailed)
	}
	requireFactoryArtifactPath(t, record.Artifacts, ".hal/prd-feature.md")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-pipeline-partial-artifact-failed.json"))
}

func TestRunFactoryRunWithDepsRecordsMarkdownArtifacts(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	reportsDir := filepath.Join(halDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		t.Fatalf("MkdirAll(reportsDir) error: %v", err)
	}
	factoryDir := filepath.Join(dir, "factory")
	if err := os.MkdirAll(factoryDir, 0755); err != nil {
		t.Fatalf("MkdirAll(factoryDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")
	writeFile(t, factoryDir, "pr-outcome.json", `{"unrelated":"pr"}`+"\n")
	writeFile(t, factoryDir, "ci-outcome.json", `{"unrelated":"ci"}`+"\n")

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
	requireFactoryArtifactPath(t, record.Artifacts, "factory/status-snapshot.json")
	requireFactoryArtifactPath(t, record.Artifacts, "factory/doctor-snapshot.json")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-artifacts-markdown.json"))
	prOutcome := requireFactoryArtifactPath(t, record.Artifacts, "factory/pr-outcome.json")
	if !prOutcome.Partial || prOutcome.StoredPath != "" || len(prOutcome.Warnings) == 0 {
		t.Fatalf("PR outcome should record missing warning: %#v", prOutcome)
	}
	ciOutcome := requireFactoryArtifactPath(t, record.Artifacts, "factory/ci-outcome.json")
	if !ciOutcome.Partial || ciOutcome.StoredPath != "" || len(ciOutcome.Warnings) == 0 {
		t.Fatalf("CI outcome should record missing warning: %#v", ciOutcome)
	}
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/reports/review-20260621.md")
	if got := len(record.Artifacts); got != 9 {
		t.Fatalf("artifacts len = %d, want 9: %#v", got, record.Artifacts)
	}
}

func TestRunFactoryRunWithDepsRecordsPROutcomeAndCIStatusArtifacts(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 3, 30, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-outcome-artifacts", nil },
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
			writeFile(t, halDir, "auto-state.json", `{
  "step": "report",
  "branchName": "hal/factory",
  "sourceMarkdown": ".hal/prd-feature.md",
  "ci": {
    "status": "passed",
    "prUrl": "https://github.com/acme/hal/pull/42",
    "prNumber": 42,
    "prTitle": "Factory artifacts",
    "prHeadRef": "hal/factory",
    "prBaseRef": "main",
    "fixAttempts": 1,
    "fixesApplied": 1
  }
}`)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	record, err := store.LoadRun("run-outcome-artifacts")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	prArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, "factory/pr-outcome.json")
	if prArtifact.Summary["pullRequestUrl"] != "https://github.com/acme/hal/pull/42" {
		t.Fatalf("pr summary = %#v", prArtifact.Summary)
	}
	ciArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, "factory/ci-outcome.json")
	if ciArtifact.Summary["status"] != "passed" {
		t.Fatalf("ci summary = %#v", ciArtifact.Summary)
	}

	prData := readStoredFactoryArtifact(t, store, record.RunID, prArtifact)
	if !strings.Contains(prData, `"pullRequestUrl": "https://github.com/acme/hal/pull/42"`) {
		t.Fatalf("PR artifact data missing URL:\n%s", prData)
	}
	if strings.Contains(prData, "token") {
		t.Fatalf("PR artifact should not contain secret-like raw data:\n%s", prData)
	}
	ciData := readStoredFactoryArtifact(t, store, record.RunID, ciArtifact)
	if !strings.Contains(ciData, `"status": "passed"`) || !strings.Contains(ciData, `"fixAttempts": 1`) {
		t.Fatalf("CI artifact data missing status/fix attempts:\n%s", ciData)
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
			writeFile(t, halDir, "auto-state.json", `{
  "step": "archive",
  "branchName": "hal/factory",
  "sourceMarkdown": ".hal/prd-feature.md",
  "reportPath": ".hal/reports/review-latest.md",
  "ci": {
    "status": "passed",
    "prUrl": "https://github.com/acme/hal/pull/84",
    "prNumber": 84,
    "prTitle": "Archived factory artifacts",
    "prHeadRef": "hal/factory",
    "prBaseRef": "main"
  }
}`)
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
	prArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, "factory/pr-outcome.json")
	if prArtifact.Summary["pullRequestUrl"] != "https://github.com/acme/hal/pull/84" {
		t.Fatalf("archived pr summary = %#v", prArtifact.Summary)
	}
	ciArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, "factory/ci-outcome.json")
	if ciArtifact.Summary["status"] != "passed" {
		t.Fatalf("archived ci summary = %#v", ciArtifact.Summary)
	}
}

func TestCollectFactoryRunReportArtifactsSkipsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	reportsDir := filepath.Join(dir, ".hal", "reports")
	if err := os.MkdirAll(reportsDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(reportsDir) error: %v", err)
	}
	regularPath := filepath.Join(reportsDir, "report.txt")
	if err := os.WriteFile(regularPath, []byte("report\n"), 0o600); err != nil {
		t.Fatalf("write regular report: %v", err)
	}
	targetPath := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(targetPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(targetPath, filepath.Join(reportsDir, "secret-link.txt")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	artifacts := collectFactoryRunReportArtifacts(dir, time.Time{})
	if len(artifacts) != 1 {
		t.Fatalf("artifacts = %#v, want only regular report", artifacts)
	}
	if artifacts[0].Path != filepath.Join(".hal", "reports", "report.txt") {
		t.Fatalf("artifact path = %q, want regular report", artifacts[0].Path)
	}
}

func TestRunFactoryRunWithDepsCopiesLocalReportLogAndVerificationArtifacts(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	reportsDir := filepath.Join(halDir, "reports")
	verifyDir := filepath.Join(reportsDir, "verify")
	collisionDir := filepath.Join(reportsDir, "test")
	if err := os.MkdirAll(verifyDir, 0755); err != nil {
		t.Fatalf("MkdirAll(verifyDir) error: %v", err)
	}
	if err := os.MkdirAll(collisionDir, 0755); err != nil {
		t.Fatalf("MkdirAll(collisionDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 3, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-local-artifact-copy", nil },
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
			writeFile(t, halDir, "auto-state.json", `{"step":"verify","sourceMarkdown":".hal/prd-feature.md","reportPath":".hal/reports/review-20260621.md"}`)
			writeFile(t, reportsDir, "review-20260621.md", "# Review\n")
			writeFile(t, reportsDir, "factory.log", "pipeline log\n")
			writeFile(t, reportsDir, "auto-result.json", `{"status":"ok"}`)
			writeFile(t, verifyDir, "test-stdout.txt", "verification stdout\n")
			writeFile(t, reportsDir, "test-stdout.txt", "flat stdout\n")
			writeFile(t, collisionDir, "stdout.txt", "nested stdout\n")
			for _, path := range []string{
				filepath.Join(reportsDir, "review-20260621.md"),
				filepath.Join(reportsDir, "factory.log"),
				filepath.Join(reportsDir, "auto-result.json"),
				filepath.Join(verifyDir, "test-stdout.txt"),
				filepath.Join(reportsDir, "test-stdout.txt"),
				filepath.Join(collisionDir, "stdout.txt"),
			} {
				if err := os.Chtimes(path, completedAt, completedAt); err != nil {
					t.Fatalf("Chtimes(%q) error: %v", path, err)
				}
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	record, err := store.LoadRun("run-local-artifact-copy")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	for _, wantPath := range []string{
		".hal/reports/review-20260621.md",
		".hal/reports/factory.log",
		".hal/reports/auto-result.json",
		".hal/reports/verify/test-stdout.txt",
		".hal/reports/test-stdout.txt",
		".hal/reports/test/stdout.txt",
	} {
		artifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, wantPath)
		if artifact.SourcePath == "" {
			t.Fatalf("artifact %q SourcePath should be set", wantPath)
		}
		if artifact.SizeBytes == nil || *artifact.SizeBytes == 0 {
			t.Fatalf("artifact %q SizeBytes = %v, want non-zero", wantPath, artifact.SizeBytes)
		}
	}
	flatArtifact := requireFactoryArtifactPath(t, record.Artifacts, ".hal/reports/test-stdout.txt")
	nestedArtifact := requireFactoryArtifactPath(t, record.Artifacts, ".hal/reports/test/stdout.txt")
	if flatArtifact.ID == nestedArtifact.ID {
		t.Fatalf("colliding report artifact IDs = %q", flatArtifact.ID)
	}
	if got := readStoredFactoryArtifact(t, store, record.RunID, flatArtifact); got != "flat stdout\n" {
		t.Fatalf("flat report payload = %q, want flat stdout", got)
	}
	if got := readStoredFactoryArtifact(t, store, record.RunID, nestedArtifact); got != "nested stdout\n" {
		t.Fatalf("nested report payload = %q, want nested stdout", got)
	}
	if _, err := os.Stat(filepath.Join(halDir, "artifacts")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("artifact collection should not create project .hal artifacts, stat error = %v", err)
	}
}

func TestRunFactoryRunWithDepsCollectsSandboxArtifactsOnSuccess(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 4, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}
	copier := &fakeFactorySandboxArtifactCopier{
		files: map[string]string{
			"/workspace/.hal/auto-state.json": `{
  "step": "done",
  "branchName": "hal/factory",
  "ci": {
    "status": "passed",
    "prUrl": "https://github.com/acme/hal/pull/77",
    "prNumber": 77,
    "prTitle": "Sandbox factory artifacts",
    "prHeadRef": "hal/factory",
    "prBaseRef": "main",
    "fixAttempts": 2,
    "fixesApplied": 1
  }
}` + "\n",
		},
		dirs: map[string]map[string]string{
			"/workspace/.hal/reports": {
				"review.md":          "# Review\n",
				"verify/stdout.txt":  "ok\n",
				"verify/result.json": `{"status":"pass"}` + "\n",
			},
		},
	}
	requestCalls := 0

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{}, io.Discard, factoryRunDeps{
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
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "git@github.com:jywlabs/hal.git", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			record, err := req.Store.LoadRun(req.RunID)
			if err != nil {
				t.Fatalf("LoadRun() during pipeline error: %v", err)
			}
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = "factory-sandbox"
			if err := req.Store.SaveRun(record); err != nil {
				t.Fatalf("SaveRun() sandbox record error: %v", err)
			}
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) {
			return factorySnapshotArtifact{
				Name: "status-snapshot",
				Path: filepath.ToSlash(filepath.Join("factory", "status-snapshot.json")),
				Data: []byte(`{"state":"ready"}` + "\n"),
			}, nil
		},
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) {
			return factorySnapshotArtifact{
				Name: "doctor-snapshot",
				Path: filepath.ToSlash(filepath.Join("factory", "doctor-snapshot.json")),
				Data: []byte(`{"overallStatus":"pass"}` + "\n"),
			}, nil
		},
		sandboxCopier: copier,
		sandboxRequests: func(_ string, record factory.RunRecord) []factory.SandboxArtifactRequest {
			requestCalls++
			if record.ExecutorMode != factory.ExecutorModeSandbox {
				t.Fatalf("sandbox requests saw executorMode = %q", record.ExecutorMode)
			}
			if record.SandboxName != "factory-sandbox" {
				t.Fatalf("sandbox requests saw sandboxName = %q", record.SandboxName)
			}
			return []factory.SandboxArtifactRequest{
				{
					ID:         "sandbox-auto-state",
					Name:       "sandbox-auto-state",
					Type:       "json",
					RemotePath: "/workspace/.hal/auto-state.json",
					Path:       ".hal/auto-state.json",
					Optional:   true,
					Summary: map[string]any{
						"executorMode": factory.ExecutorModeSandbox,
						"sandboxName":  record.SandboxName,
					},
				},
				{
					ID:         "sandbox-reports",
					Name:       "sandbox-reports",
					Type:       "directory",
					RemotePath: "/workspace/.hal/reports",
					Path:       ".hal/reports",
					Directory:  true,
					Optional:   true,
					Summary: map[string]any{
						"executorMode": factory.ExecutorModeSandbox,
						"sandboxName":  record.SandboxName,
					},
				},
			}
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if requestCalls != 1 {
		t.Fatalf("sandboxRequests calls = %d, want 1", requestCalls)
	}
	if len(copier.fileCalls) != 1 || copier.fileCalls[0] != "/workspace/.hal/auto-state.json" {
		t.Fatalf("file copy calls = %#v", copier.fileCalls)
	}
	if len(copier.dirCalls) != 1 || copier.dirCalls[0] != "/workspace/.hal/reports" {
		t.Fatalf("dir copy calls = %#v", copier.dirCalls)
	}

	record, err := store.LoadRun("run-sandbox-success")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusSucceeded {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusSucceeded)
	}
	autoState := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/auto-state.json")
	if autoState.SourcePath != "" {
		t.Fatalf("sandbox artifact SourcePath = %q, want empty", autoState.SourcePath)
	}
	if autoState.Summary["sandboxName"] != "factory-sandbox" {
		t.Fatalf("sandbox artifact summary = %#v", autoState.Summary)
	}
	prArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, "factory/pr-outcome.json")
	if prArtifact.Summary["pullRequestUrl"] != "https://github.com/acme/hal/pull/77" {
		t.Fatalf("sandbox PR outcome summary = %#v", prArtifact.Summary)
	}
	ciArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, "factory/ci-outcome.json")
	if ciArtifact.Summary["status"] != "passed" {
		t.Fatalf("sandbox CI outcome summary = %#v", ciArtifact.Summary)
	}
	if got := readStoredFactoryArtifact(t, store, record.RunID, ciArtifact); !strings.Contains(got, `"fixAttempts": 2`) {
		t.Fatalf("sandbox CI outcome payload missing remote state data:\n%s", got)
	}
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, "factory/status-snapshot.json")
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, "factory/doctor-snapshot.json")
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/reports/review.md")
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/reports/verify/stdout.txt")
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/reports/verify/result.json")
	if _, err := os.Stat(filepath.Join(halDir, "artifacts")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("sandbox artifact collection should not create project .hal artifacts, stat error = %v", err)
	}
}

func TestRunFactoryRunWithDepsCollectsSandboxWarningsOnFailure(t *testing.T) {
	dir := t.TempDir()
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 4, 10, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	failedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, failedAt}
	pipelineErr := errors.New("step run failed: engine unavailable")

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-failed", nil },
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
			record, err := req.Store.LoadRun(req.RunID)
			if err != nil {
				t.Fatalf("LoadRun() during pipeline error: %v", err)
			}
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = "factory-sandbox"
			if err := req.Store.SaveRun(record); err != nil {
				t.Fatalf("SaveRun() sandbox record error: %v", err)
			}
			return pipelineErr
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		sandboxCopier: &fakeFactorySandboxArtifactCopier{
			missing: map[string]bool{"/workspace/.hal/reports": true},
		},
		sandboxRequests: func(_ string, record factory.RunRecord) []factory.SandboxArtifactRequest {
			return []factory.SandboxArtifactRequest{
				{
					ID:         "sandbox-reports",
					Name:       "sandbox-reports",
					Type:       "directory",
					RemotePath: "/workspace/.hal/reports",
					Path:       ".hal/reports",
					Directory:  true,
					Optional:   true,
					Summary: map[string]any{
						"executorMode": factory.ExecutorModeSandbox,
						"sandboxName":  record.SandboxName,
					},
				},
			}
		},
	})
	if !errors.Is(err, pipelineErr) {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want pipeline error", err)
	}

	record, err := store.LoadRun("run-sandbox-failed")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusFailed)
	}
	missing := requireFactoryArtifactPath(t, record.Artifacts, ".hal/reports")
	if !missing.Partial {
		t.Fatalf("missing sandbox artifact Partial = false, want true")
	}
	if missing.StoredPath != "" {
		t.Fatalf("missing sandbox artifact StoredPath = %q, want empty", missing.StoredPath)
	}
	if len(missing.Warnings) != 1 || !strings.Contains(missing.Warnings[0], "optional sandbox artifact not found") {
		t.Fatalf("missing sandbox artifact warnings = %#v", missing.Warnings)
	}
	if missing.Summary["sandboxName"] != "factory-sandbox" || missing.Summary["collectionStatus"] != "missing" {
		t.Fatalf("missing sandbox artifact summary = %#v", missing.Summary)
	}
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
	writeFile(t, halDir, "auto-state.json", `{
  "step": "report",
  "branchName": "hal/stale",
  "sourceMarkdown": ".hal/stale.md",
  "reportPath": ".hal/reports/stale.md",
  "ci": {
    "status": "passed",
    "prUrl": "https://github.com/acme/hal/pull/99",
    "prNumber": 99,
    "prTitle": "Stale factory artifacts",
    "prHeadRef": "hal/stale",
    "prBaseRef": "main"
  }
}`)
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
	prOutcome := requireFactoryArtifactPath(t, record.Artifacts, "factory/pr-outcome.json")
	if !prOutcome.Partial || prOutcome.StoredPath != "" || len(prOutcome.Warnings) == 0 {
		t.Fatalf("stale PR outcome should be recorded as missing: %#v", prOutcome)
	}
	ciOutcome := requireFactoryArtifactPath(t, record.Artifacts, "factory/ci-outcome.json")
	if !ciOutcome.Partial || ciOutcome.StoredPath != "" || len(ciOutcome.Warnings) == 0 {
		t.Fatalf("stale CI outcome should be recorded as missing: %#v", ciOutcome)
	}
}

func TestRunFactoryRunWithDepsCollectsStatusAndDoctorSnapshots(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 3, 10, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}
	statusCalls := 0
	doctorCalls := 0

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-snapshot-artifacts", nil },
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
		statusSnapshot: func(gotDir string) (factorySnapshotArtifact, error) {
			statusCalls++
			if gotDir != dir {
				t.Fatalf("status snapshot dir = %q, want %q", gotDir, dir)
			}
			return factorySnapshotArtifact{
				Name: "status-snapshot",
				Path: "factory/status-snapshot.json",
				Data: []byte(`{"state":"auto_active","summary":"Auto pipeline is active."}` + "\n"),
				Summary: map[string]any{
					"snapshotKind": "status",
					"state":        "auto_active",
					"summary":      "Auto pipeline is active.",
				},
			}, nil
		},
		doctorSnapshot: func(gotDir string) (factorySnapshotArtifact, error) {
			doctorCalls++
			if gotDir != dir {
				t.Fatalf("doctor snapshot dir = %q, want %q", gotDir, dir)
			}
			return factorySnapshotArtifact{
				Name: "doctor-snapshot",
				Path: "factory/doctor-snapshot.json",
				Data: []byte(`{"overallStatus":"pass","summary":"Hal is ready to use."}` + "\n"),
				Summary: map[string]any{
					"snapshotKind":  "doctor",
					"overallStatus": "pass",
					"summary":       "Hal is ready to use.",
				},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if statusCalls != 1 {
		t.Fatalf("status snapshot calls = %d, want 1", statusCalls)
	}
	if doctorCalls != 1 {
		t.Fatalf("doctor snapshot calls = %d, want 1", doctorCalls)
	}

	record, err := store.LoadRun("run-snapshot-artifacts")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	statusArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, "factory/status-snapshot.json")
	if statusArtifact.Summary["snapshotKind"] != "status" || statusArtifact.Summary["state"] != "auto_active" {
		t.Fatalf("status artifact summary = %#v", statusArtifact.Summary)
	}
	doctorArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, "factory/doctor-snapshot.json")
	if doctorArtifact.Summary["snapshotKind"] != "doctor" || doctorArtifact.Summary["overallStatus"] != "pass" {
		t.Fatalf("doctor artifact summary = %#v", doctorArtifact.Summary)
	}

	statusPath, err := store.ResolveArtifactPath(record.RunID, statusArtifact.StoredPath)
	if err != nil {
		t.Fatalf("ResolveArtifactPath(status) error: %v", err)
	}
	statusData, err := os.ReadFile(statusPath)
	if err != nil {
		t.Fatalf("ReadFile(status snapshot) error: %v", err)
	}
	if !strings.Contains(string(statusData), `"state":"auto_active"`) {
		t.Fatalf("status snapshot data = %s", statusData)
	}
	doctorPath, err := store.ResolveArtifactPath(record.RunID, doctorArtifact.StoredPath)
	if err != nil {
		t.Fatalf("ResolveArtifactPath(doctor) error: %v", err)
	}
	doctorData, err := os.ReadFile(doctorPath)
	if err != nil {
		t.Fatalf("ReadFile(doctor snapshot) error: %v", err)
	}
	if !strings.Contains(string(doctorData), `"overallStatus":"pass"`) {
		t.Fatalf("doctor snapshot data = %s", doctorData)
	}
}

func TestRunFactoryRunWithDepsRecordsMissingOptionalArtifactWarnings(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 3, 20, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/missing-prd.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-missing-artifact-warning", nil },
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

	record, err := store.LoadRun("run-missing-artifact-warning")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	missing := requireFactoryArtifactPath(t, record.Artifacts, ".hal/missing-prd.md")
	if !missing.Partial {
		t.Fatalf("missing artifact Partial = false, want true")
	}
	if len(missing.Warnings) != 1 || !strings.Contains(missing.Warnings[0], "optional artifact not found") {
		t.Fatalf("missing artifact warnings = %#v", missing.Warnings)
	}
	if missing.StoredPath != "" {
		t.Fatalf("missing artifact StoredPath = %q, want empty", missing.StoredPath)
	}
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/prd.json")
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
	requireFactoryRunArtifactPath(t, resp.Artifacts, ".hal/prd-feature.md")
	requireFactoryRunArtifactPath(t, resp.Artifacts, ".hal/prd.json")
}

func TestRunFactoryRunWithDepsRecordsVerificationMetadata(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	verifiedAt := createdAt.Add(4 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, verifiedAt}
	verifyCfg := &verify.Config{
		Checks: []verify.ShellCheck{
			{ID: "test", Name: "Go tests", Command: "go test ./cmd", TimeoutSeconds: 120, Required: true},
		},
	}

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-verification-record", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return verifiedAt
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
		loadVerify: func(gotDir string) (*verify.Config, error) {
			if gotDir != dir {
				t.Fatalf("loadVerify dir = %q, want %q", gotDir, dir)
			}
			return verifyCfg, nil
		},
		runVerify: func(_ context.Context, gotCfg *verify.Config) (*verify.Result, error) {
			if gotCfg != verifyCfg {
				t.Fatalf("runVerify cfg = %#v, want fixture", gotCfg)
			}
			record, err := store.LoadRun("run-verification-record")
			if err != nil {
				t.Fatalf("LoadRun() during verification error: %v", err)
			}
			if record.CurrentStep != "verify" {
				t.Fatalf("currentStep during verification = %q, want verify", record.CurrentStep)
			}
			if !record.UpdatedAt.Equal(verifyingAt) {
				t.Fatalf("updatedAt during verification = %s, want %s", record.UpdatedAt, verifyingAt)
			}
			verifyDir := filepath.Join(halDir, "reports", "verify")
			if err := os.MkdirAll(verifyDir, 0755); err != nil {
				t.Fatalf("MkdirAll(verifyDir) error: %v", err)
			}
			writeFile(t, verifyDir, "test-stdout.txt", "verification stdout\n")
			return &verify.Result{
				Status: verify.StatusPass,
				Summary: verify.Summary{
					Total:  1,
					Passed: 1,
				},
				Artifacts: []verify.ArtifactReference{
					{CheckID: "test", Kind: verify.ArtifactKindStdout, Path: ".hal/reports/verify/test-stdout.txt"},
				},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	record, err := store.LoadRun("run-verification-record")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Verification == nil {
		t.Fatal("verification should be persisted")
	}
	if record.Verification.Summary.Total != 1 || record.Verification.Summary.Passed != 1 {
		t.Fatalf("verification summary = %#v", record.Verification.Summary)
	}
	if got := len(record.Verification.Artifacts); got != 1 {
		t.Fatalf("verification artifacts len = %d, want 1", got)
	}
	if record.Verification.Artifacts[0].Path != ".hal/reports/verify/test-stdout.txt" {
		t.Fatalf("verification artifact path = %q", record.Verification.Artifacts[0].Path)
	}
	verificationArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/reports/verify/test-stdout.txt")
	if verificationArtifact.Summary["checkId"] != "test" || verificationArtifact.Summary["kind"] != verify.ArtifactKindStdout {
		t.Fatalf("verification artifact summary = %#v", verificationArtifact.Summary)
	}
	if got := readStoredFactoryArtifact(t, store, record.RunID, verificationArtifact); got != "verification stdout\n" {
		t.Fatalf("stored verification artifact = %q", got)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(verifiedAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, verifiedAt)
	}
	runRecordArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, factoryRunRecordArtifactPath(store, record.RunID))
	var storedRunRecord factory.RunRecord
	if err := json.Unmarshal([]byte(readStoredFactoryArtifact(t, store, record.RunID, runRecordArtifact)), &storedRunRecord); err != nil {
		t.Fatalf("Unmarshal(factory run record artifact) error: %v", err)
	}
	if storedRunRecord.Status != factory.RunStatusSucceeded || storedRunRecord.CurrentStep != "done" {
		t.Fatalf("stored run record status/currentStep = %q/%q, want %q/done", storedRunRecord.Status, storedRunRecord.CurrentStep, factory.RunStatusSucceeded)
	}
	if storedRunRecord.FinishedAt == nil || !storedRunRecord.FinishedAt.Equal(verifiedAt) {
		t.Fatalf("stored run record finishedAt = %v, want %s", storedRunRecord.FinishedAt, verifiedAt)
	}
	if storedRunRecord.Verification == nil || storedRunRecord.Verification.Summary.Total != 1 {
		t.Fatalf("stored run record verification = %#v", storedRunRecord.Verification)
	}
	for _, artifact := range storedRunRecord.Artifacts {
		if artifact.SourcePath != "" {
			t.Fatalf("stored run record artifact %q SourcePath = %q, want empty", artifact.Name, artifact.SourcePath)
		}
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeVerificationResult,
		factory.EventTypeStepEnded,
	})
	if events[2].Summary != "Verification passed" {
		t.Fatalf("verification event summary = %q", events[2].Summary)
	}
	if !events[2].Timestamp.Equal(verifiedAt) {
		t.Fatalf("verification event timestamp = %s, want %s", events[2].Timestamp, verifiedAt)
	}
	if events[2].Metadata["status"] != verify.StatusPass {
		t.Fatalf("verification event status metadata = %#v", events[2].Metadata)
	}
	if !events[3].Timestamp.Equal(verifiedAt) {
		t.Fatalf("completion event timestamp = %s, want %s", events[3].Timestamp, verifiedAt)
	}
}

func TestRunFactoryRunWithDepsRecordsMissingVerificationArtifacts(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 5, 20, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	verifiedAt := createdAt.Add(4 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, verifiedAt}

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-missing-verification-artifact", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return verifiedAt
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
		loadVerify: func(string) (*verify.Config, error) {
			return &verify.Config{Checks: []verify.ShellCheck{
				{ID: "test", Name: "Go tests", Command: "go test ./cmd", TimeoutSeconds: 120, Required: true},
			}}, nil
		},
		runVerify: func(context.Context, *verify.Config) (*verify.Result, error) {
			return &verify.Result{
				Status: verify.StatusPass,
				Summary: verify.Summary{
					Total:  1,
					Passed: 1,
				},
				Artifacts: []verify.ArtifactReference{
					{CheckID: "test", Kind: verify.ArtifactKindStdout, Path: ".hal/reports/verify/missing-stdout.txt"},
				},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	record, err := store.LoadRun("run-missing-verification-artifact")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusSucceeded {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusSucceeded)
	}
	missing := requireFactoryArtifactPath(t, record.Artifacts, ".hal/reports/verify/missing-stdout.txt")
	if !missing.Partial {
		t.Fatalf("missing verification artifact Partial = false: %#v", missing)
	}
	if missing.StoredPath != "" {
		t.Fatalf("missing verification artifact StoredPath = %q, want empty", missing.StoredPath)
	}
	if len(missing.Warnings) == 0 || !strings.Contains(missing.Warnings[0], "verification artifact not found") {
		t.Fatalf("missing verification artifact warnings = %#v", missing.Warnings)
	}
	if missing.Summary["collectionStatus"] != "missing" || missing.Summary["checkId"] != "test" || missing.Summary["kind"] != verify.ArtifactKindStdout {
		t.Fatalf("missing verification artifact summary = %#v", missing.Summary)
	}
}

func TestRunFactoryRunWithDepsFailsWhenVerificationFails(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 10, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	verifiedAt := createdAt.Add(4 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, verifiedAt}

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-verification-failed", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return verifiedAt
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
		loadVerify: func(string) (*verify.Config, error) {
			return &verify.Config{Checks: []verify.ShellCheck{
				{ID: "test", Name: "Go tests", Command: "go test ./cmd", TimeoutSeconds: 120, Required: true},
			}}, nil
		},
		runVerify: func(context.Context, *verify.Config) (*verify.Result, error) {
			record, err := store.LoadRun("run-verification-failed")
			if err != nil {
				t.Fatalf("LoadRun() during verification error: %v", err)
			}
			if record.CurrentStep != "verify" {
				t.Fatalf("currentStep during verification = %q, want verify", record.CurrentStep)
			}
			if !record.UpdatedAt.Equal(verifyingAt) {
				t.Fatalf("updatedAt during verification = %s, want %s", record.UpdatedAt, verifyingAt)
			}
			return &verify.Result{
				Status: verify.StatusFail,
				Summary: verify.Summary{
					Total:  1,
					Failed: 1,
				},
			}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want verification failure", err)
	}

	record, err := store.LoadRun("run-verification-failed")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusFailed)
	}
	if record.Verification == nil || record.Verification.Summary.Failed != 1 {
		t.Fatalf("verification = %#v", record.Verification)
	}
	if record.Failure == nil {
		t.Fatal("failure summary should be persisted")
	}
	if record.Failure.Step != "verify" {
		t.Fatalf("failure step = %q, want verify", record.Failure.Step)
	}
	if record.Failure.Category != factory.FailureCategoryValidation {
		t.Fatalf("failure category = %q, want %q", record.Failure.Category, factory.FailureCategoryValidation)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(verifiedAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, verifiedAt)
	}
	runRecordArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, factoryRunRecordArtifactPath(store, record.RunID))
	var storedRunRecord factory.RunRecord
	if err := json.Unmarshal([]byte(readStoredFactoryArtifact(t, store, record.RunID, runRecordArtifact)), &storedRunRecord); err != nil {
		t.Fatalf("Unmarshal(factory run record artifact) error: %v", err)
	}
	if storedRunRecord.Status != factory.RunStatusFailed || storedRunRecord.CurrentStep != "verify" {
		t.Fatalf("stored run record status/currentStep = %q/%q, want %q/verify", storedRunRecord.Status, storedRunRecord.CurrentStep, factory.RunStatusFailed)
	}
	if storedRunRecord.Failure == nil || storedRunRecord.Failure.Step != "verify" {
		t.Fatalf("stored run record failure = %#v", storedRunRecord.Failure)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeVerificationResult,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	if events[3].Metadata["step"] != "verify" {
		t.Fatalf("verification failure event step = %#v, want verify", events[3].Metadata["step"])
	}
	if events[3].Metadata["status"] != factory.RunStatusFailed {
		t.Fatalf("verification failure event status = %#v, want %q", events[3].Metadata["status"], factory.RunStatusFailed)
	}
	if !events[2].Timestamp.Equal(verifiedAt) {
		t.Fatalf("verification result timestamp = %s, want %s", events[2].Timestamp, verifiedAt)
	}
	if !events[3].Timestamp.Equal(verifiedAt) {
		t.Fatalf("verification failure timestamp = %s, want %s", events[3].Timestamp, verifiedAt)
	}
	if got, ok := events[3].Metadata["error"].(string); !ok || !strings.Contains(got, "verification failed") {
		t.Fatalf("verification failure event error = %#v, want verification failure", events[3].Metadata["error"])
	}
}

func TestRunFactoryRunWithDepsMarksRunFailedWhenVerificationArtifactStorageFails(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	verifyDir := filepath.Join(halDir, "reports", "verify")
	if err := os.MkdirAll(verifyDir, 0755); err != nil {
		t.Fatalf("MkdirAll(verifyDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 4, 30, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	verifiedAt := createdAt.Add(4 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, verifiedAt}

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-verification-artifact-failed", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return verifiedAt
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
		loadVerify: func(string) (*verify.Config, error) {
			return &verify.Config{Checks: []verify.ShellCheck{
				{ID: "test", Name: "Go tests", Command: "go test ./cmd", TimeoutSeconds: 120, Required: true},
			}}, nil
		},
		runVerify: func(context.Context, *verify.Config) (*verify.Result, error) {
			verificationPath := "verify-output.txt"
			writeFile(t, dir, "verify-output.txt", "ok\n")
			ref := factory.ArtifactReference{
				Name: "verification-test-stdout",
				Type: factoryArtifactTypeForPath(verificationPath),
				Path: filepath.Clean(verificationPath),
			}
			ref.ID = factoryArtifactID(ref)
			blockedArtifactPath := filepath.Join(store.ArtifactsDir(), "run-verification-artifact-failed", strings.Trim(ref.ID, "."))
			if err := os.MkdirAll(blockedArtifactPath, 0755); err != nil {
				t.Fatalf("MkdirAll(blocked artifact path) error: %v", err)
			}
			if err := os.MkdirAll(filepath.Join(blockedArtifactPath+".bak", "child"), 0755); err != nil {
				t.Fatalf("MkdirAll(blocked artifact backup path) error: %v", err)
			}
			return &verify.Result{
				Status: verify.StatusPass,
				Summary: verify.Summary{
					Total:  1,
					Passed: 1,
				},
				Artifacts: []verify.ArtifactReference{
					{CheckID: "test", Kind: "stdout", Path: verificationPath},
				},
			}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "store factory verification artifact") {
		record, loadErr := store.LoadRun("run-verification-artifact-failed")
		if loadErr != nil {
			t.Fatalf("runFactoryRunWithDeps() error = %v, want verification artifact storage error; LoadRun error: %v", err, loadErr)
		}
		t.Fatalf("runFactoryRunWithDeps() error = %v, want verification artifact storage error; artifacts: %#v", err, record.Artifacts)
	}

	record, err := store.LoadRun("run-verification-artifact-failed")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusFailed)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(verifiedAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, verifiedAt)
	}
	if record.Verification == nil || record.Verification.Summary.Passed != 1 {
		t.Fatalf("verification = %#v", record.Verification)
	}
	if record.Failure == nil || record.Failure.Step != "verify" {
		t.Fatalf("failure summary = %#v, want verify failure", record.Failure)
	}
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-verification-artifact-failed.json"))

	events, err := store.LoadEvents("run-verification-artifact-failed")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	if events[2].RunID != "run-verification-artifact-failed" || events[3].RunID != "run-verification-artifact-failed" {
		t.Fatalf("failure events should use real run ID: %#v", events)
	}
}

func TestRunFactoryRunWithDepsPreservesPartialVerificationArtifactsWhenStorageFails(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 5, 40, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	verifiedAt := createdAt.Add(4 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, verifiedAt}

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-partial-verification-artifact-failed", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return verifiedAt
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
		loadVerify: func(string) (*verify.Config, error) {
			return &verify.Config{Checks: []verify.ShellCheck{
				{ID: "test", Name: "Go tests", Command: "go test ./cmd", TimeoutSeconds: 120, Required: true},
			}}, nil
		},
		runVerify: func(context.Context, *verify.Config) (*verify.Result, error) {
			writeFile(t, dir, "verify-ok.txt", "ok\n")
			blockedPath := "verify-blocked.txt"
			writeFile(t, dir, blockedPath, "blocked\n")
			ref := factory.ArtifactReference{
				Name: "verification-test-stderr",
				Type: factoryArtifactTypeForPath(blockedPath),
				Path: filepath.Clean(blockedPath),
			}
			ref.ID = factoryArtifactID(ref)
			blockedArtifactPath := filepath.Join(store.ArtifactsDir(), "run-partial-verification-artifact-failed", strings.Trim(ref.ID, "."))
			if err := os.MkdirAll(blockedArtifactPath, 0755); err != nil {
				t.Fatalf("MkdirAll(blocked artifact path) error: %v", err)
			}
			if err := os.MkdirAll(filepath.Join(blockedArtifactPath+".bak", "child"), 0755); err != nil {
				t.Fatalf("MkdirAll(blocked artifact backup path) error: %v", err)
			}
			return &verify.Result{
				Status: verify.StatusPass,
				Summary: verify.Summary{
					Total:  1,
					Passed: 1,
				},
				Artifacts: []verify.ArtifactReference{
					{CheckID: "test", Kind: verify.ArtifactKindStdout, Path: "verify-ok.txt"},
					{CheckID: "test", Kind: verify.ArtifactKindStderr, Path: blockedPath},
				},
			}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "store factory verification artifact") {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want verification artifact storage error", err)
	}

	record, err := store.LoadRun("run-partial-verification-artifact-failed")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusFailed)
	}
	requireFactoryArtifactPath(t, record.Artifacts, "verify-ok.txt")
	if record.Failure == nil || record.Failure.Step != "verify" {
		t.Fatalf("failure summary = %#v, want verify failure", record.Failure)
	}
}

func TestRunFactoryRunWithDepsMarksRunFailedWhenFinalRunRecordArtifactFails(t *testing.T) {
	dir := t.TempDir()
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 5, 30, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	completedAt := createdAt.Add(4 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, completedAt}

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-final-artifact-failed", nil },
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
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			blockedArtifactPath := filepath.Join(store.ArtifactsDir(), "run-final-artifact-failed", "factory-run-record.json")
			if err := os.MkdirAll(blockedArtifactPath, 0755); err != nil {
				t.Fatalf("MkdirAll(blocked artifact path) error: %v", err)
			}
			if err := os.MkdirAll(filepath.Join(blockedArtifactPath+".bak", "child"), 0755); err != nil {
				t.Fatalf("MkdirAll(blocked artifact backup path) error: %v", err)
			}
			return nil
		},
		loadVerify: func(string) (*verify.Config, error) {
			return nil, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "record factory run artifact") {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want final run record artifact error", err)
	}
	runErr := err

	record, err := store.LoadRun("run-final-artifact-failed")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q; command error: %v; failure: %#v", record.Status, factory.RunStatusFailed, runErr, record.Failure)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(completedAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, completedAt)
	}
	if record.Failure == nil || !strings.Contains(record.Failure.Message, "record factory run artifact") {
		t.Fatalf("failure summary = %#v, want final artifact failure", record.Failure)
	}

	events, err := store.LoadEvents("run-final-artifact-failed")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	if events[3].RunID != "run-final-artifact-failed" {
		t.Fatalf("failure classification runID = %q", events[3].RunID)
	}
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
		loadVerify: func(string) (*verify.Config, error) {
			t.Fatal("loadVerify called for sandbox run")
			return nil, nil
		},
		runVerify: func(context.Context, *verify.Config) (*verify.Result, error) {
			t.Fatal("runVerify called for sandbox run")
			return nil, nil
		},
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
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
	runRecordPath := factoryRunRecordArtifactPath(store, record.RunID)
	requireFactoryArtifactPath(t, record.Artifacts, runRecordPath)
	requireNoFactoryArtifactPath(t, record.Artifacts, ".hal/prd.json")
	runRecordArtifacts := 0
	for _, artifact := range record.Artifacts {
		if artifact.Name != "factory-run-record" && artifact.Path != runRecordPath {
			continue
		}
		runRecordArtifacts++
		if artifact.ID != "factory-run-record" {
			t.Fatalf("factory run record artifact ID = %q, want factory-run-record", artifact.ID)
		}
	}
	if runRecordArtifacts != 1 {
		t.Fatalf("factory run record artifacts = %d, want 1: %#v", runRecordArtifacts, record.Artifacts)
	}

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
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
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
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
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
			if err := store.AppendEvent(&factory.EventRecord{
				Sequence:  3,
				RunID:     record.RunID,
				EventType: factory.EventTypeFailureClassification,
				Timestamp: failedAt,
				Summary:   "Sandbox factory executor failed",
				Metadata: map[string]any{
					"step":        "run",
					"category":    factory.FailureCategoryPipeline,
					"recoverable": true,
					"source":      "remote_sandbox",
				},
			}); err != nil {
				return err
			}
			return factorySandboxTestError("execute factory sandbox command: remote pipeline failed token=secret-token")
		},
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
			return nil
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
	classificationEvents := 0
	for _, event := range events {
		if event.EventType == factory.EventTypeFailureClassification {
			classificationEvents++
		}
	}
	if classificationEvents != 1 {
		t.Fatalf("failure classification events = %d, want 1: %#v", classificationEvents, events)
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
			requireFactoryRunArtifactPath(t, resp.Artifacts, tt.sourcePath)
			requireFactoryRunArtifactPath(t, resp.Artifacts, ".hal/prd.json")
			requireFactoryRunArtifactPath(t, resp.Artifacts, tt.runID+".json")
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
			requireFactoryRunArtifactPath(t, resp.Artifacts, tt.sourcePath)
			requireFactoryRunArtifactPath(t, resp.Artifacts, ".hal/prd.json")
			requireFactoryRunArtifactPath(t, resp.Artifacts, tt.runID+".json")
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

func TestRunFactoryRunPipelineWithDepsPassesWorkDirToAuto(t *testing.T) {
	var got factoryRunAutoRequest

	err := runFactoryRunPipelineWithDeps(context.Background(), factoryRunPipelineRequest{
		WorkDir: " /workspace/hal ",
		Record: factory.RunRecord{
			RepoPath: "/fallback/repo",
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
	if got.WorkDir != "/workspace/hal" {
		t.Fatalf("auto workDir = %q, want /workspace/hal", got.WorkDir)
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

func TestRunInFactoryRunDirChangesAndRestores(t *testing.T) {
	startDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error: %v", err)
	}
	targetDir := t.TempDir()
	sentinel := errors.New("sentinel")
	var duringDir string

	err = runInFactoryRunDir(targetDir, func() error {
		var err error
		duringDir, err = os.Getwd()
		if err != nil {
			t.Fatalf("Getwd() during run error: %v", err)
		}
		return sentinel
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("runInFactoryRunDir() error = %v, want sentinel", err)
	}
	assertSameDir(t, duringDir, targetDir)

	restoredDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() after run error: %v", err)
	}
	assertSameDir(t, restoredDir, startDir)
}

func assertSameDir(t *testing.T, got, want string) {
	t.Helper()
	gotInfo, err := os.Stat(got)
	if err != nil {
		t.Fatalf("stat got dir %q: %v", got, err)
	}
	wantInfo, err := os.Stat(want)
	if err != nil {
		t.Fatalf("stat want dir %q: %v", want, err)
	}
	if !os.SameFile(gotInfo, wantInfo) {
		t.Fatalf("dir = %q, want %q", got, want)
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
		Artifacts: []FactoryRunArtifactReference{
			{
				ID:         "factory-runs-run-json-contract.json",
				Name:       "run-record",
				Type:       "json",
				SourcePath: "run-json-contract.json",
				Path:       "factory/runs/run-json-contract.json",
				StoredPath: "artifacts/run-json-contract/factory-runs-run-json-contract.json",
				URL:        "https://github.com/acme/repo/actions/runs/123",
			},
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
	requireFactoryFields(t, "factory run artifact", firstArtifact, []string{"id", "name", "type", "sourcePath", "path", "storedPath", "url"})
	if firstArtifact["url"] != "https://github.com/acme/repo/actions/runs/123" {
		t.Fatalf("factory run artifact url = %v, want preserved URL", firstArtifact["url"])
	}

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
		{
			Name:       "report",
			Type:       "markdown",
			SourcePath: "/tmp/workspace/.hal/reports/run-status.md",
			Path:       ".hal/reports/run-status.md",
		},
		{
			Name: "pr",
			Type: "url",
			URL:  "https://github.com/acme/hal/pull/1",
		},
		{
			Name: "internal-url",
			Type: "url",
			URL:  "http://192.0.2.42/pull/1",
		},
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
	if len(resp.Run.Artifacts) != 3 {
		t.Fatalf("run.artifacts len = %d, want 3", len(resp.Run.Artifacts))
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
	artifacts, ok := run["artifacts"].([]any)
	if !ok || len(artifacts) != 3 {
		t.Fatalf("run.artifacts should be an array of 3, got %T len %d", run["artifacts"], len(resp.Run.Artifacts))
	}
	firstArtifact, ok := artifacts[0].(map[string]any)
	if !ok {
		t.Fatalf("first artifact should be an object, got %T", artifacts[0])
	}
	if _, ok := firstArtifact["sourcePath"]; ok {
		t.Fatalf("status artifact should not expose sourcePath: %#v", firstArtifact)
	}
	secondArtifact, ok := artifacts[1].(map[string]any)
	if !ok {
		t.Fatalf("second artifact should be an object, got %T", artifacts[1])
	}
	if secondArtifact["url"] != "https://github.com/acme/hal/pull/1" {
		t.Fatalf("status artifact url = %v, want preserved sanitized URL", secondArtifact["url"])
	}
	if _, ok := secondArtifact["path"]; ok {
		t.Fatalf("url status artifact should not synthesize a path when URL is preserved: %#v", secondArtifact)
	}
	thirdArtifact, ok := artifacts[2].(map[string]any)
	if !ok {
		t.Fatalf("third artifact should be an object, got %T", artifacts[2])
	}
	if _, ok := thirdArtifact["url"]; ok {
		t.Fatalf("unsafe status artifact should not expose url: %#v", thirdArtifact)
	}
	if thirdArtifact["path"] != "[redacted]" {
		t.Fatalf("unsafe url-only status artifact path = %v, want [redacted]", thirdArtifact["path"])
	}
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

func TestRunFactoryArtifactsListsCollectedArtifacts(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 8, 0, 0, 0, time.UTC)
	size := int64(2048)
	createdAt := base.Add(2 * time.Minute)
	record := testFactoryRunRecord("run-artifact-list", base, base.Add(5*time.Minute))
	record.Artifacts = []factory.ArtifactReference{
		{
			ID:         "status-snapshot",
			Name:       "status-snapshot",
			Type:       "json",
			Path:       "factory/status-snapshot.json",
			StoredPath: "artifacts/run-artifact-list/status-snapshot.json",
			SizeBytes:  &size,
			CreatedAt:  &createdAt,
			Summary: map[string]any{
				"snapshotKind": "status",
				"state":        "auto_active",
			},
		},
		{
			ID:       "missing-report",
			Name:     "missing-report",
			Type:     "markdown",
			Path:     ".hal/reports/missing.md",
			Warnings: []string{"optional artifact not found"},
			Partial:  true,
			Summary: map[string]any{
				"missing": true,
			},
		},
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var buf bytes.Buffer
	err := runFactoryArtifactsWithDeps(&buf, record.RunID, false, factoryArtifactsDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryArtifactsWithDeps() unexpected error: %v", err)
	}

	output := buf.String()
	for _, want := range []string{
		"Run ID: run-artifact-list",
		"NAME",
		"status-snapshot",
		"factory/status-snapshot.json",
		"artifacts/run-artifact-list/status-snapshot.json",
		"snapshotKind=\"status\"",
		"state=\"auto_active\"",
		"missing-report",
		".hal/reports/missing.md",
		"missing=true",
		"optional artifact not found",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestRunFactoryArtifactsTableEmitsSafeArtifactMetadata(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 8, 5, 0, 0, time.UTC)
	rawPath := filepath.Join(t.TempDir(), "workspace", "secret-report.md")
	record := testFactoryRunRecord("run-artifact-table-safe", base, base.Add(time.Minute))
	record.Artifacts = []factory.ArtifactReference{
		{
			ID:         "unsafe-report",
			Name:       "unsafe-report",
			Type:       "markdown",
			Path:       rawPath,
			StoredPath: rawPath,
			Summary: map[string]any{
				"apiToken": "secret-token",
				"endpoint": "http://192.0.2.10/status",
			},
			Warnings: []string{"optional artifact not found at 198.51.100.2"},
			Partial:  true,
		},
		{
			ID:      "unsafe-url",
			Name:    "unsafe-url",
			Type:    "link",
			URL:     "https://example.com/artifact?token=secret",
			Partial: true,
		},
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var buf bytes.Buffer
	err := runFactoryArtifactsWithDeps(&buf, record.RunID, false, factoryArtifactsDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryArtifactsWithDeps() unexpected error: %v", err)
	}

	output := buf.String()
	for _, leaked := range []string{
		rawPath,
		filepath.Dir(rawPath),
		"secret-token",
		"192.0.2.10",
		"198.51.100.2",
		"token=secret",
	} {
		if strings.Contains(output, leaked) {
			t.Fatalf("artifact table leaked %q:\n%s", leaked, output)
		}
	}
	for _, want := range []string{"secret-report.md", "[redacted]", "apiToken=\"[redacted]\"", "endpoint=\"[redacted]\""} {
		if !strings.Contains(output, want) {
			t.Fatalf("artifact table missing %q:\n%s", want, output)
		}
	}
}

func TestRunFactoryArtifactsMissingRunReturnsError(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	var buf bytes.Buffer

	err := runFactoryArtifactsWithDeps(&buf, "missing-run", false, factoryArtifactsDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err == nil {
		t.Fatal("runFactoryArtifactsWithDeps() error = nil, want missing-run error")
	}
	if !strings.Contains(err.Error(), `factory run "missing-run" not found`) {
		t.Fatalf("error = %q, want missing-run message", err.Error())
	}
	if buf.Len() != 0 {
		t.Fatalf("missing run should not write output, got %q", buf.String())
	}
}

func TestRunFactoryArtifactsEmptyState(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 8, 10, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-no-artifacts", base, base.Add(1*time.Minute))
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var buf bytes.Buffer
	err := runFactoryArtifactsWithDeps(&buf, record.RunID, false, factoryArtifactsDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryArtifactsWithDeps() unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Run ID: run-no-artifacts") {
		t.Fatalf("output missing run ID:\n%s", output)
	}
	if !strings.Contains(output, "No artifacts collected for factory run run-no-artifacts.") {
		t.Fatalf("output missing empty-state message:\n%s", output)
	}
}

func TestRunFactoryArtifactsJSONEmitsSafePayload(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 8, 20, 0, 0, time.UTC)
	size := int64(512)
	createdAt := base.Add(time.Minute)
	record := testFactoryRunRecord("run-artifacts-json", base, base.Add(3*time.Minute))
	record.Artifacts = []factory.ArtifactReference{
		{
			ID:         "status-snapshot",
			Name:       "status-snapshot",
			Type:       "json",
			SourcePath: "/tmp/workspace/status-snapshot.json",
			Path:       "factory/status-snapshot.json",
			StoredPath: "artifacts/run-artifacts-json/status-snapshot.json",
			SizeBytes:  &size,
			CreatedAt:  &createdAt,
			Summary: map[string]any{
				"snapshotKind": "status",
				"state":        "auto_active",
				"apiToken":     "secret-token",
				"endpoint":     "http://192.0.2.10:8080/status",
			},
		},
		{
			ID:       "missing-report",
			Name:     "missing-report",
			Type:     "markdown",
			Path:     ".hal/reports/missing.md",
			URL:      "http://192.0.2.20/report",
			Warnings: []string{"optional artifact not found at 198.51.100.2"},
			Partial:  true,
			Summary: map[string]any{
				"collectionStatus": "missing",
			},
		},
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var buf bytes.Buffer
	err := runFactoryArtifactsWithDeps(&buf, record.RunID, true, factoryArtifactsDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryArtifactsWithDeps() unexpected error: %v", err)
	}

	var resp FactoryArtifactsResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
	}
	if resp.ContractVersion != FactoryArtifactsContractVersion {
		t.Fatalf("contractVersion = %q, want %q", resp.ContractVersion, FactoryArtifactsContractVersion)
	}
	if resp.RunID != record.RunID {
		t.Fatalf("runId = %q, want %q", resp.RunID, record.RunID)
	}
	if len(resp.Artifacts) != 2 {
		t.Fatalf("artifacts len = %d, want 2", len(resp.Artifacts))
	}
	if resp.Summary.Total != 2 || resp.Summary.Partial != 1 || resp.Summary.Warnings != 1 {
		t.Fatalf("summary = %#v, want total=2 partial=1 warnings=1", resp.Summary)
	}
	first := resp.Artifacts[0]
	if first.Path != "factory/status-snapshot.json" || first.StoredPath != "artifacts/run-artifacts-json/status-snapshot.json" {
		t.Fatalf("first artifact paths = path %q storedPath %q", first.Path, first.StoredPath)
	}
	if first.Summary["snapshotKind"] != "status" || first.Summary["state"] != "auto_active" {
		t.Fatalf("first summary preserved safe fields: %#v", first.Summary)
	}
	if first.Summary["apiToken"] != "[redacted]" || first.Summary["endpoint"] != "[redacted]" {
		t.Fatalf("first summary should redact secret/network values: %#v", first.Summary)
	}
	if resp.Artifacts[1].Warnings[0] != "[redacted]" {
		t.Fatalf("warning should be redacted, got %#v", resp.Artifacts[1].Warnings)
	}
	if len(resp.Warnings) != 1 || resp.Warnings[0] != "[redacted]" {
		t.Fatalf("top-level warnings = %#v, want redacted warning", resp.Warnings)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("json.Unmarshal(raw) error: %v", err)
	}
	requireExactKeys(t, raw, []string{"contractVersion", "runId", "artifacts", "warnings", "summary"})
	artifacts, ok := raw["artifacts"].([]any)
	if !ok || len(artifacts) != 2 {
		t.Fatalf("artifacts should be array of 2, got %T", raw["artifacts"])
	}
	firstRaw, ok := artifacts[0].(map[string]any)
	if !ok {
		t.Fatalf("artifacts[0] should be object, got %T", artifacts[0])
	}
	requireFactoryFields(t, "factory artifacts entry", firstRaw, []string{
		"id", "name", "type", "path", "storedPath", "sizeBytes", "createdAt", "summary",
	})
	if _, ok := firstRaw["sourcePath"]; ok {
		t.Fatalf("artifact JSON must not expose sourcePath: %#v", firstRaw)
	}
	if _, ok := firstRaw["url"]; ok {
		t.Fatalf("artifact JSON must not expose url: %#v", firstRaw)
	}
	summary, ok := raw["summary"].(map[string]any)
	if !ok {
		t.Fatalf("summary should be object, got %T", raw["summary"])
	}
	requireExactKeys(t, summary, []string{"total", "partial", "warnings"})
}

func TestFactoryArtifactJSONSurfacesSanitizeAbsolutePaths(t *testing.T) {
	base := time.Date(2026, 6, 21, 8, 25, 0, 0, time.UTC)
	rawPath := filepath.Join(t.TempDir(), "external-prds", "secret-feature.md")
	rawVerificationPath := filepath.Join(t.TempDir(), "verify-artifacts", "secret-output.log")
	record := testFactoryRunRecord("run-absolute-artifact-path", base, base.Add(time.Minute))
	record.Artifacts = []factory.ArtifactReference{
		{
			Name:       "source-markdown",
			Type:       "markdown",
			SourcePath: rawPath,
			Path:       rawPath,
			StoredPath: rawPath,
			Warnings: []string{
				"optional artifact not found: " + rawPath,
				"artifact metadata api_key=super-secret",
			},
			Partial: true,
		},
	}
	record.Verification = &factory.VerificationRecord{
		Summary: verify.Summary{Total: 1, Passed: 1},
		Artifacts: []verify.ArtifactReference{
			{CheckID: "test", Kind: verify.ArtifactKindStdout, Path: rawVerificationPath},
		},
	}

	summary := newFactoryArtifactSummaries(record.Artifacts)[0]
	if summary.Path != "secret-feature.md" {
		t.Fatalf("sanitized path = %q, want basename only", summary.Path)
	}
	if summary.StoredPath != "secret-feature.md" {
		t.Fatalf("sanitized storedPath = %q, want basename only", summary.StoredPath)
	}

	payloads := map[string]any{
		"factory-run":        newFactoryRunResponse(record, nil),
		"factory-run-record": scrubFactoryRunRecordForArtifact(record),
		"factory-status":     FactoryStatusResponse{ContractVersion: FactoryStatusContractVersion, Run: newFactoryStatusRun(record), Timeline: []factory.EventRecord{}},
		"factory-artifacts":  newFactoryArtifactsResponse(record),
	}
	for name, payload := range payloads {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error: %v", name, err)
		}
		raw := string(data)
		if strings.Contains(raw, rawPath) || strings.Contains(raw, filepath.Dir(rawPath)) || strings.Contains(raw, rawVerificationPath) || strings.Contains(raw, filepath.Dir(rawVerificationPath)) || strings.Contains(raw, "super-secret") {
			t.Fatalf("%s JSON leaked raw artifact warning content: %s", name, raw)
		}
	}
}

func TestSanitizeFactoryArtifactSummaryRedactsSignedURLStrings(t *testing.T) {
	summary := sanitizeFactoryArtifactSummary(map[string]any{
		"downloadURL": "https://storage.example.com/artifact.json?sig=abc123",
		"nested": map[string]any{
			"awsURL": "https://storage.example.com/artifact.json?X-Amz-Signature=abc123",
		},
	})

	if summary["downloadURL"] != "[redacted]" {
		t.Fatalf("signed URL summary value = %#v, want [redacted]", summary["downloadURL"])
	}
	nested, ok := summary["nested"].(map[string]any)
	if !ok {
		t.Fatalf("nested summary = %#v, want map[string]any", summary["nested"])
	}
	if nested["awsURL"] != "[redacted]" {
		t.Fatalf("signed nested URL summary value = %#v, want [redacted]", nested["awsURL"])
	}

	warnings := sanitizeFactoryArtifactWarnings([]string{
		"https://storage.example.com/artifact.json?X-Goog-Signature=abc123",
	})
	if len(warnings) != 1 || warnings[0] != "[redacted]" {
		t.Fatalf("signed URL warnings = %#v, want [redacted]", warnings)
	}
}

func TestSanitizeFactoryArtifactSummaryRedactsTypedContainers(t *testing.T) {
	type nestedSummary struct {
		Header string `json:"header"`
		Token  string `json:"apiToken"`
		Safe   string `json:"safe"`
	}

	summary := sanitizeFactoryArtifactSummary(map[string]any{
		"headers": []string{
			"Authorization: Bearer secret",
			"cache-control: no-store",
		},
		"metadata": map[string][]string{
			"links": {"https://storage.example.com/artifact.json?sig=abc123"},
		},
		"struct": nestedSummary{
			Header: "Authorization: Bearer secret",
			Token:  "secret-token",
			Safe:   "ok",
		},
	})

	headers, ok := summary["headers"].([]any)
	if !ok {
		t.Fatalf("typed string slice summary = %#v, want []any", summary["headers"])
	}
	if headers[0] != "[redacted]" || headers[1] != "cache-control: no-store" {
		t.Fatalf("typed string slice summary = %#v, want first value redacted", headers)
	}
	metadata, ok := summary["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("typed map summary = %#v, want map[string]any", summary["metadata"])
	}
	links, ok := metadata["links"].([]any)
	if !ok {
		t.Fatalf("typed map string slice value = %#v, want []any", metadata["links"])
	}
	if links[0] != "[redacted]" {
		t.Fatalf("typed map signed URL value = %#v, want [redacted]", links[0])
	}
	structValue, ok := summary["struct"].(map[string]any)
	if !ok {
		t.Fatalf("typed struct summary = %#v, want map[string]any", summary["struct"])
	}
	if structValue["header"] != "[redacted]" || structValue["apiToken"] != "[redacted]" || structValue["safe"] != "ok" {
		t.Fatalf("typed struct summary = %#v, want secret fields redacted", structValue)
	}
}

func TestSafeFactoryPRURLRejectsSecretURLParts(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "safe pr url",
			raw:  "https://github.com/resciencelab/hal/pull/11",
			want: "https://github.com/resciencelab/hal/pull/11",
		},
		{
			name: "safe fragment",
			raw:  "https://github.com/resciencelab/hal/pull/11#discussion_r123",
			want: "https://github.com/resciencelab/hal/pull/11#discussion_r123",
		},
		{
			name: "token query",
			raw:  "https://github.com/resciencelab/hal/pull/11?token=secret",
			want: "",
		},
		{
			name: "api key query",
			raw:  "https://github.com/resciencelab/hal/pull/11?api_key=secret",
			want: "",
		},
		{
			name: "signature query",
			raw:  "https://storage.example.com/artifact.json?signature=abc123",
			want: "",
		},
		{
			name: "short signature query",
			raw:  "https://storage.example.com/artifact.json?sig=abc123",
			want: "",
		},
		{
			name: "aws signature query",
			raw:  "https://storage.example.com/artifact.json?X-Amz-Signature=abc123",
			want: "",
		},
		{
			name: "google signature query",
			raw:  "https://storage.example.com/artifact.json?X-Goog-Signature=abc123",
			want: "",
		},
		{
			name: "azure signature query",
			raw:  "https://storage.example.com/artifact.json?X-Ms-Signature=abc123",
			want: "",
		},
		{
			name: "access token fragment",
			raw:  "https://github.com/resciencelab/hal/pull/11#access_token=secret",
			want: "",
		},
		{
			name: "auth fragment",
			raw:  "https://github.com/resciencelab/hal/pull/11#auth:bearer",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := safeFactoryPRURL(tt.raw); got != tt.want {
				t.Fatalf("safeFactoryPRURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestSanitizeFactoryArtifactPathRedactsParentRelativePaths(t *testing.T) {
	tests := []string{
		"..",
		"../private/report.md",
		"reports/../../private/report.md",
		`..\private\report.md`,
	}

	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if got := sanitizeFactoryArtifactPath(raw); got != "[redacted]" {
				t.Fatalf("sanitizeFactoryArtifactPath(%q) = %q, want [redacted]", raw, got)
			}
		})
	}
}

func TestSanitizeFactoryArtifactPathRedactsWindowsAbsolutePaths(t *testing.T) {
	tests := []string{
		`C:\Users\name\secret.md`,
		`C:/Users/name/secret.md`,
		`\\server\share\secret.md`,
		`//server/share/secret.md`,
	}

	for _, raw := range tests {
		t.Run(raw, func(t *testing.T) {
			if got := sanitizeFactoryArtifactPath(raw); got != "[redacted]" {
				t.Fatalf("sanitizeFactoryArtifactPath(%q) = %q, want [redacted]", raw, got)
			}
		})
	}
}

func TestRunFactoryArtifactsJSONEmptyState(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 8, 30, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-artifacts-json-empty", base, base.Add(time.Minute))
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var buf bytes.Buffer
	err := runFactoryArtifactsWithDeps(&buf, record.RunID, true, factoryArtifactsDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryArtifactsWithDeps() unexpected error: %v", err)
	}

	var resp FactoryArtifactsResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
	}
	if resp.Artifacts == nil || len(resp.Artifacts) != 0 {
		t.Fatalf("artifacts = %#v, want empty non-nil array", resp.Artifacts)
	}
	if resp.Warnings == nil || len(resp.Warnings) != 0 {
		t.Fatalf("warnings = %#v, want empty non-nil array", resp.Warnings)
	}
	if resp.Summary.Total != 0 || resp.Summary.Partial != 0 || resp.Summary.Warnings != 0 {
		t.Fatalf("summary = %#v, want zero counts", resp.Summary)
	}
}

func TestFactoryArtifactsCommandRegistered(t *testing.T) {
	cmd, err := commandAtPath(Root(), "factory", "artifacts")
	if err != nil {
		t.Fatalf("factory artifacts command missing: %v", err)
	}
	if cmd.Flags().Lookup("json") == nil {
		t.Fatal("factory artifacts should expose --json flag")
	}
	if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
		t.Fatalf("factory artifacts missing metadata fields: %v", missing)
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
				"[hal factory queue](hal_factory_queue.md)",
			},
		},
		{
			name: "factory queue cli reference links parent and subcommands",
			path: "../docs/cli/hal_factory_queue.md",
			wantFragments: []string{
				"[hal factory](hal_factory.md)",
				"[hal factory queue add](hal_factory_queue_add.md)",
				"[hal factory queue list](hal_factory_queue_list.md)",
				"[hal factory queue work](hal_factory_queue_work.md)",
			},
		},
		{
			name: "factory queue add cli reference links parent",
			path: "../docs/cli/hal_factory_queue_add.md",
			wantFragments: []string{
				"[hal factory queue](hal_factory_queue.md)",
			},
		},
		{
			name: "factory queue list cli reference links parent",
			path: "../docs/cli/hal_factory_queue_list.md",
			wantFragments: []string{
				"[hal factory queue](hal_factory_queue.md)",
			},
		},
		{
			name: "factory queue work cli reference links parent",
			path: "../docs/cli/hal_factory_queue_work.md",
			wantFragments: []string{
				"[hal factory queue](hal_factory_queue.md)",
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

func assertFactoryOutputExcludesRemoteCredentials(t *testing.T, output, wantRemote string) {
	t.Helper()

	if !strings.Contains(output, wantRemote) {
		t.Fatalf("output missing sanitized remote %q\n%s", wantRemote, output)
	}
	for _, secret := range []string{"token-user", "super-secret"} {
		if strings.Contains(output, secret) {
			t.Fatalf("output contains credential %q\n%s", secret, output)
		}
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

func requireFactoryArtifactSummaryPath(t *testing.T, artifacts []FactoryArtifactSummary, wantPath string) FactoryArtifactSummary {
	t.Helper()
	for _, artifact := range artifacts {
		if artifact.Path == wantPath {
			return artifact
		}
	}
	t.Fatalf("artifact path %q missing from %#v", wantPath, artifacts)
	return FactoryArtifactSummary{}
}

func requireFactoryRunArtifactPath(t *testing.T, artifacts []FactoryRunArtifactReference, wantPath string) FactoryRunArtifactReference {
	t.Helper()
	for _, artifact := range artifacts {
		if artifact.Path == wantPath {
			return artifact
		}
	}
	t.Fatalf("missing factory run artifact path %q in %#v", wantPath, artifacts)
	return FactoryRunArtifactReference{}
}

func requireStoredFactoryArtifactPath(t *testing.T, store factory.Store, runID string, artifacts []factory.ArtifactReference, wantPath string) factory.ArtifactReference {
	t.Helper()
	artifact := requireFactoryArtifactPath(t, artifacts, wantPath)
	if artifact.StoredPath == "" {
		t.Fatalf("artifact %q StoredPath should be set", wantPath)
	}
	storedPath, err := store.ResolveArtifactPath(runID, artifact.StoredPath)
	if err != nil {
		t.Fatalf("ResolveArtifactPath(%q) error: %v", artifact.StoredPath, err)
	}
	if _, err := os.Stat(storedPath); err != nil {
		t.Fatalf("stored artifact %q missing: %v", storedPath, err)
	}
	if !strings.HasPrefix(storedPath, store.ArtifactsDir()+string(filepath.Separator)) {
		t.Fatalf("stored artifact %q should be under %q", storedPath, store.ArtifactsDir())
	}
	return artifact
}

func readStoredFactoryArtifact(t *testing.T, store factory.Store, runID string, artifact factory.ArtifactReference) string {
	t.Helper()
	if artifact.StoredPath == "" {
		t.Fatalf("artifact %q StoredPath should be set", artifact.Path)
	}
	storedPath, err := store.ResolveArtifactPath(runID, artifact.StoredPath)
	if err != nil {
		t.Fatalf("ResolveArtifactPath(%q) error: %v", artifact.StoredPath, err)
	}
	data, err := os.ReadFile(storedPath)
	if err != nil {
		t.Fatalf("ReadFile(%q) error: %v", storedPath, err)
	}
	return string(data)
}

type fakeFactorySandboxArtifactCopier struct {
	files     map[string]string
	dirs      map[string]map[string]string
	missing   map[string]bool
	fileCalls []string
	dirCalls  []string
}

func (f *fakeFactorySandboxArtifactCopier) CopyFile(_ context.Context, remotePath, localPath string) error {
	f.fileCalls = append(f.fileCalls, remotePath)
	if f.missing[remotePath] {
		return factory.ErrSandboxArtifactNotFound
	}
	content, ok := f.files[remotePath]
	if !ok {
		return factory.ErrSandboxArtifactNotFound
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		return err
	}
	return os.WriteFile(localPath, []byte(content), 0644)
}

func (f *fakeFactorySandboxArtifactCopier) CopyDir(_ context.Context, remotePath, localPath string) error {
	f.dirCalls = append(f.dirCalls, remotePath)
	if f.missing[remotePath] {
		return factory.ErrSandboxArtifactNotFound
	}
	files, ok := f.dirs[remotePath]
	if !ok {
		return factory.ErrSandboxArtifactNotFound
	}
	for relPath, content := range files {
		target := filepath.Join(localPath, relPath)
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(target, []byte(content), 0644); err != nil {
			return err
		}
	}
	return nil
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
