package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
				"hal factory open <run-id>",
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
			name: "factory open command",
			cmd:  factoryOpenCmd,
			requiredLongPhrases: []string{
				"handoff guidance",
				"global factory",
				"prints the best inspection",
				"Failed sandbox runs",
				"Failed local runs",
				"--exec",
				"--json",
				"factory-open-v1 contract",
			},
			requiredExampleLines: []string{
				"hal factory open run-20260620-001",
				"hal factory open run-20260620-001 --exec",
				"hal factory open run-20260620-001 --json",
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
				"executor mode requires --base",
			},
			requiredExampleLines: []string{
				"hal factory trigger --repo . --prd .hal/prd-feature.md",
				"hal factory trigger --repo /work/hal --report .hal/reports/analysis.md --json",
				"hal factory trigger --repo /work/hal --discover-report --json",
				"hal factory trigger --repo /work/hal --prd .hal/prd-feature.md --executor sandbox --base main",
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
				"base branch",
				"--json",
				"factory-queue-add-v1",
			},
			requiredExampleLines: []string{
				"hal factory queue add run-20260620-001 local",
				"hal factory queue add run-20260620-001 local --json",
				"hal factory queue add run-20260620-001 sandbox",
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
	for _, flagName := range []string{"report", "base", "secret-env", "sandbox", "json"} {
		if cmd.Flags().Lookup(flagName) == nil {
			t.Fatalf("factory run should expose --%s flag", flagName)
		}
	}
	if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
		t.Fatalf("factory run missing metadata fields: %v", missing)
	}
}

func TestFactoryRunRequestFromCommandParsesSecretEnvFlags(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("report", "", "")
	cmd.Flags().String("base", "", "")
	cmd.Flags().StringArray("secret-env", nil, "")
	cmd.Flags().Bool("sandbox", false, "")
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("secret-env", "GITHUB_TOKEN"); err != nil {
		t.Fatalf("Set(secret-env) error: %v", err)
	}
	if err := cmd.Flags().Set("secret-env", "NPM_TOKEN"); err != nil {
		t.Fatalf("Set(secret-env) error: %v", err)
	}

	req, err := factoryRunRequestFromCommand(cmd, []string{".hal/prd-feature.md"})
	if err != nil {
		t.Fatalf("factoryRunRequestFromCommand() unexpected error: %v", err)
	}

	wantSecrets := []factory.RunSecretInput{
		{Name: "GITHUB_TOKEN", Source: factory.RunSecretSourceEnv, Required: true},
		{Name: "NPM_TOKEN", Source: factory.RunSecretSourceEnv, Required: true},
	}
	if !reflect.DeepEqual(req.Secrets, wantSecrets) {
		t.Fatalf("secrets = %#v, want %#v", req.Secrets, wantSecrets)
	}
}

func TestFactoryRunRequestFromCommandRejectsSecretEnvAssignments(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("report", "", "")
	cmd.Flags().String("base", "", "")
	cmd.Flags().StringArray("secret-env", nil, "")
	cmd.Flags().Bool("sandbox", false, "")
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("secret-env", "GITHUB_TOKEN=ghp_secret"); err != nil {
		t.Fatalf("Set(secret-env) error: %v", err)
	}

	_, err := factoryRunRequestFromCommand(cmd, []string{".hal/prd-feature.md"})
	if err == nil {
		t.Fatal("factoryRunRequestFromCommand() expected error")
	}
	if strings.Contains(err.Error(), "ghp_secret") || strings.Contains(err.Error(), "GITHUB_TOKEN=ghp_secret") {
		t.Fatalf("error should not echo secret-env value: %v", err)
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

func TestRunFactoryRunWithDepsDefaultsToLocalPipelineWithoutSandboxFlag(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	localCalled := false
	policy := factory.DefaultFactoryPolicy()
	policy.AllowedEngines = []string{factory.PolicyEngineClaude}

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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		loadEngine: func(string) (string, error) {
			return " Claude ", nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			localCalled = true
			if req.Record.ExecutorMode != factory.ExecutorModeLocal {
				t.Fatalf("local executorMode = %q, want %q", req.Record.ExecutorMode, factory.ExecutorModeLocal)
			}
			if req.Engine != factory.PolicyEngineClaude {
				t.Fatalf("pipeline engine = %q, want %q", req.Engine, factory.PolicyEngineClaude)
			}
			if req.Record.Engine != factory.PolicyEngineClaude {
				t.Fatalf("record engine = %q, want %q", req.Record.Engine, factory.PolicyEngineClaude)
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
	record, err := store.LoadRun("run-local-default")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Engine != factory.PolicyEngineClaude {
		t.Fatalf("stored engine = %q, want %q", record.Engine, factory.PolicyEngineClaude)
	}
}

func TestRunFactoryRunWithDepsSelectsSandboxExecutorWithSandboxFlag(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	target := &sandbox.SandboxState{
		Name:     "factory-selected",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
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
		loadEngine: func(string) (string, error) {
			return factory.PolicyEngineCodex, nil
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
				Engine:     factory.PolicyEngineCodex,
			}
			if !reflect.DeepEqual(req.RemoteAuto, wantAuto) {
				t.Fatalf("remote auto request = %#v, want %#v", req.RemoteAuto, wantAuto)
			}
			record := req.RunRecord
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = target.Name
			record.Sandbox = &factory.SandboxMetadata{Name: target.Name, Provider: target.Provider, Status: target.Status}
			return store.SaveRun(&record)
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			data, err := json.Marshal(verify.Result{
				SchemaVersion: verify.SchemaVersion,
				Status:        verify.StatusPass,
				Summary:       verify.Summary{},
				Checks:        []verify.CheckResult{},
			})
			if err != nil {
				t.Fatalf("Marshal(verify result) error: %v", err)
			}
			if _, err := out.Write(append(data, '\n')); err != nil {
				t.Fatalf("write remote verify JSON error: %v", err)
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

func TestRunFactoryRunWithDepsResolvesRequiredEnvSecretsBeforePipeline(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	secretValue := "ghp_factory_secret_value_123"
	pipelineCalled := false
	policy := factory.DefaultFactoryPolicy()

	err := runFactoryRunWithDeps(context.Background(), ".", factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		Secrets: []factory.RunSecretInput{
			{Name: "GITHUB_TOKEN", Source: factory.RunSecretSourceEnv, Required: true},
		},
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-secret-success", nil },
		now:          func() time.Time { return time.Date(2026, 6, 21, 10, 30, 0, 0, time.UTC) },
		workingDir:   func() (string, error) { return "/workspace/hal", nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "https://x:" + secretValue + "@github.com/jywlabs/hal.git", nil
		},
		lookupEnv: func(name string) (string, bool) {
			if name != "GITHUB_TOKEN" {
				t.Fatalf("lookup env name = %q, want GITHUB_TOKEN", name)
			}
			return secretValue, true
		},
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		loadEngine: func(string) (string, error) {
			return factory.PolicyEngineCodex, nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			pipelineCalled = true
			if len(req.Request.ResolvedSecrets) != 1 {
				t.Fatalf("resolved secrets = %#v, want one", req.Request.ResolvedSecrets)
			}
			if req.Request.ResolvedSecrets[0].Value != secretValue {
				t.Fatalf("resolved secret value = %q, want injected value", req.Request.ResolvedSecrets[0].Value)
			}
			loaded, err := req.Store.LoadRun(req.RunID)
			if err != nil {
				t.Fatalf("LoadRun() error: %v", err)
			}
			wantMetadata := []factory.RunSecretMetadata{{
				Name:     "GITHUB_TOKEN",
				Source:   factory.RunSecretSourceEnv,
				Required: true,
				Present:  true,
			}}
			if !reflect.DeepEqual(loaded.Secrets, wantMetadata) {
				t.Fatalf("stored secrets = %#v, want %#v", loaded.Secrets, wantMetadata)
			}
			data, err := json.Marshal(loaded)
			if err != nil {
				t.Fatalf("json.Marshal(run record) error: %v", err)
			}
			if strings.Contains(string(data), secretValue) {
				t.Fatalf("run record JSON leaked secret value: %s", string(data))
			}
			if loaded.RepoRemote != "https://"+factory.RunSecretRedactionPlaceholder+"@github.com/jywlabs/hal.git" {
				t.Fatalf("stored repo remote = %q, want redacted secret value", loaded.RepoRemote)
			}
			return nil
		},
		loadVerify:     func(string) (*verify.Config, error) { return nil, nil },
		statusSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if !pipelineCalled {
		t.Fatal("pipeline dependency was not invoked")
	}
	record, err := store.LoadRun("run-secret-success")
	if err != nil {
		t.Fatalf("LoadRun() final record error: %v", err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal(final run record) error: %v", err)
	}
	if strings.Contains(string(data), secretValue) {
		t.Fatalf("final run record JSON leaked secret value: %s", string(data))
	}
	if record.RepoRemote != "https://"+factory.RunSecretRedactionPlaceholder+"@github.com/jywlabs/hal.git" {
		t.Fatalf("final repo remote = %q, want redacted secret value", record.RepoRemote)
	}
}

func TestRunFactoryRunWithDepsRedactsCredentialedRemoteWithoutDeclaredSecrets(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	credential := "ghp_factory_remote_credential_123"
	wantRemote := "https://" + factory.RunSecretRedactionPlaceholder + "@github.com/jywlabs/hal.git"
	pipelineCalled := false
	policy := factory.DefaultFactoryPolicy()

	err := runFactoryRunWithDeps(context.Background(), ".", factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-credentialed-remote", nil },
		now:          func() time.Time { return time.Date(2026, 6, 21, 10, 35, 0, 0, time.UTC) },
		workingDir:   func() (string, error) { return "/workspace/hal", nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "https://x:" + credential + "@github.com/jywlabs/hal.git", nil
		},
		lookupEnv: func(name string) (string, bool) {
			t.Fatalf("lookupEnv(%q) called without declared secrets", name)
			return "", false
		},
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		loadEngine: func(string) (string, error) {
			return factory.PolicyEngineCodex, nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			pipelineCalled = true
			loaded, err := req.Store.LoadRun(req.RunID)
			if err != nil {
				t.Fatalf("LoadRun() error: %v", err)
			}
			data, err := json.Marshal(loaded)
			if err != nil {
				t.Fatalf("json.Marshal(run record) error: %v", err)
			}
			if strings.Contains(string(data), credential) {
				t.Fatalf("run record JSON leaked credentialed remote secret: %s", string(data))
			}
			if loaded.RepoRemote != wantRemote {
				t.Fatalf("stored repo remote = %q, want %q", loaded.RepoRemote, wantRemote)
			}
			return nil
		},
		loadVerify:     func(string) (*verify.Config, error) { return nil, nil },
		statusSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if !pipelineCalled {
		t.Fatal("pipeline dependency was not invoked")
	}
	record, err := store.LoadRun("run-credentialed-remote")
	if err != nil {
		t.Fatalf("LoadRun() final record error: %v", err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal(final run record) error: %v", err)
	}
	if strings.Contains(string(data), credential) {
		t.Fatalf("final run record JSON leaked credentialed remote secret: %s", string(data))
	}
	if record.RepoRemote != wantRemote {
		t.Fatalf("final repo remote = %q, want %q", record.RepoRemote, wantRemote)
	}
	if len(record.Secrets) != 0 {
		t.Fatalf("secrets metadata = %#v, want none", record.Secrets)
	}
}

func TestSanitizeCredentialedRemoteRedactsCredentialQueryAndFragmentValues(t *testing.T) {
	placeholder := factory.RunSecretRedactionPlaceholder
	tests := []struct {
		name   string
		remote string
		want   string
	}{
		{
			name:   "query token",
			remote: "https://github.com/org/repo.git?token=ghp_secret_123&ref=main",
			want:   "https://github.com/org/repo.git?token=" + placeholder + "&ref=main",
		},
		{
			name:   "fragment credential",
			remote: "https://github.com/org/repo.git?ref=main#access_token=ghp_secret_123",
			want:   "https://github.com/org/repo.git?ref=main#access_token=" + placeholder,
		},
		{
			name:   "userinfo and query credential",
			remote: "https://x:ghp_secret_123@github.com/org/repo.git?api_key=abc123",
			want:   "https://" + placeholder + "@github.com/org/repo.git?api_key=" + placeholder,
		},
		{
			name:   "non credential query",
			remote: "https://github.com/org/repo.git?ref=main#readme",
			want:   "https://github.com/org/repo.git?ref=main#readme",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeCredentialedRemote(tt.remote); got != tt.want {
				t.Fatalf("sanitizeCredentialedRemote() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedactFactoryRunErrorRedactsCredentialedRemoteWithoutDeclaredSecrets(t *testing.T) {
	credential := "ghp_factory_error_credential_123"
	err := errors.New("clone failed: https://x:" + credential + "@github.com/jywlabs/hal.git")

	safeErr := redactFactoryRunError(err, factory.RunSecretRedactor{})
	if safeErr == nil {
		t.Fatal("redactFactoryRunError() = nil, want redacted error")
	}
	if strings.Contains(safeErr.Error(), credential) {
		t.Fatalf("redactFactoryRunError() leaked credential: %s", safeErr.Error())
	}
	if !strings.Contains(safeErr.Error(), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("redactFactoryRunError() = %q, want redaction placeholder", safeErr.Error())
	}
	if !errors.Is(safeErr, err) {
		t.Fatalf("redactFactoryRunError() did not preserve original cause")
	}
}

func TestMarkFactoryRunFailedRedactsCredentialedRemoteWithoutDeclaredSecrets(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 10, 40, 0, 0, time.UTC)
	credential := "ghp_factory_failure_credential_123"

	record, err := markFactoryRunFailedWithRedactor(store, factory.RunRecord{
		RunID:        "run-credentialed-failure",
		Status:       factory.RunStatusRunning,
		ExecutorMode: factory.ExecutorModeLocal,
		CurrentStep:  "run",
		CreatedAt:    now,
		UpdatedAt:    now,
	}, now, errors.New("git fetch failed: https://x:"+credential+"@github.com/jywlabs/hal.git"), factory.RunSecretRedactor{})
	if err != nil {
		t.Fatalf("markFactoryRunFailedWithRedactor() unexpected error: %v", err)
	}
	if record.Failure == nil {
		t.Fatal("record.Failure = nil, want failure summary")
	}
	if strings.Contains(record.Failure.Message, credential) {
		t.Fatalf("failure message leaked credential: %s", record.Failure.Message)
	}
	if !strings.Contains(record.Failure.Message, factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("failure message = %q, want redaction placeholder", record.Failure.Message)
	}

	loaded, err := store.LoadRun("run-credentialed-failure")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	data, err := json.Marshal(loaded)
	if err != nil {
		t.Fatalf("json.Marshal(run record) error: %v", err)
	}
	if strings.Contains(string(data), credential) {
		t.Fatalf("stored run record leaked credential: %s", string(data))
	}
}

func TestAppendFactoryRunTimelineEventRedactsCredentialedRemoteWithoutDeclaredSecrets(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	credential := "ghp_factory_timeline_credential_123"

	if err := appendFactoryRunTimelineEvent(store, "run-credentialed-timeline", time.Date(2026, 6, 21, 10, 41, 0, 0, time.UTC), factoryTimelineEvent{
		EventType: factory.EventTypeStepEnded,
		Summary:   "Factory run failed",
		Metadata: map[string]any{
			"error": "clone failed: https://x:" + credential + "@github.com/jywlabs/hal.git",
		},
	}); err != nil {
		t.Fatalf("appendFactoryRunTimelineEvent() unexpected error: %v", err)
	}

	events, err := store.LoadEvents("run-credentialed-timeline")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	data, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("json.Marshal(events) error: %v", err)
	}
	payload := string(data)
	if strings.Contains(payload, credential) {
		t.Fatalf("timeline event leaked credential: %s", payload)
	}
	if !strings.Contains(payload, factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("timeline event missing redaction placeholder: %s", payload)
	}
}

func TestRunFactoryRunWithDepsMissingRequiredEnvSecretFailsBeforeSandbox(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	now := time.Date(2026, 6, 21, 10, 45, 0, 0, time.UTC)
	credential := "factory-secret-12345"
	policy := factory.DefaultFactoryPolicy()

	err := runFactoryRunWithDeps(context.Background(), "/workspace/hal", factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		Sandbox:      true,
		Secrets: []factory.RunSecretInput{
			{Name: "GITHUB_TOKEN", Source: factory.RunSecretSourceEnv, Required: true},
			{Name: "NPM_TOKEN", Source: factory.RunSecretSourceEnv, Required: true},
		},
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-secret-missing", nil },
		now:          func() time.Time { return now },
		workingDir:   func() (string, error) { return "/workspace/hal", nil },
		currentBranch: func(string) (string, error) {
			return "hal/factory", nil
		},
		repoRemote: func(string) (string, error) {
			return "https://" + credential + ":x-oauth-basic@github.com/jywlabs/hal.git", nil
		},
		lookupEnv: func(name string) (string, bool) {
			switch name {
			case "GITHUB_TOKEN":
				return " \t ", true
			case "NPM_TOKEN":
				return "npm_factory_secret_value", true
			default:
				t.Fatalf("lookup env name = %q, want configured secret env", name)
			}
			return "", false
		},
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		loadEngine: func(string) (string, error) {
			return factory.PolicyEngineCodex, nil
		},
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			t.Fatal("local pipeline should not be called when required secret is missing")
			return nil
		},
		runSandbox: func(context.Context, factorySandboxExecutorRequest) error {
			t.Fatal("sandbox executor should not be called when required secret is missing")
			return nil
		},
	})
	if err == nil {
		t.Fatal("runFactoryRunWithDeps() error = nil, want missing secret error")
	}
	if !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("runFactoryRunWithDeps() error = %q, want env var name", err.Error())
	}

	record, loadErr := store.LoadRun("run-secret-missing")
	if loadErr != nil {
		t.Fatalf("LoadRun() error: %v", loadErr)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("record status = %q, want failed", record.Status)
	}
	if record.Failure == nil || record.Failure.Category != factory.FailureCategoryPRD {
		t.Fatalf("record failure = %#v, want PRD validation failure", record.Failure)
	}
	data, marshalErr := json.Marshal(record)
	if marshalErr != nil {
		t.Fatalf("json.Marshal(run record) error: %v", marshalErr)
	}
	for _, leaked := range []string{credential, "npm_factory_secret_value"} {
		if strings.Contains(string(data), leaked) {
			t.Fatalf("run record JSON leaked secret %q: %s", leaked, string(data))
		}
	}
	if record.RepoRemote != "https://"+factory.RunSecretRedactionPlaceholder+"@github.com/jywlabs/hal.git" {
		t.Fatalf("repo remote = %q, want redacted credential", record.RepoRemote)
	}
	wantMetadata := []factory.RunSecretMetadata{{
		Name:     "GITHUB_TOKEN",
		Source:   factory.RunSecretSourceEnv,
		Required: true,
		Present:  false,
	}, {
		Name:     "NPM_TOKEN",
		Source:   factory.RunSecretSourceEnv,
		Required: true,
		Present:  false,
	}}
	if !reflect.DeepEqual(record.Secrets, wantMetadata) {
		t.Fatalf("stored secrets = %#v, want %#v", record.Secrets, wantMetadata)
	}

	events, loadErr := store.LoadEvents("run-secret-missing")
	if loadErr != nil {
		t.Fatalf("LoadEvents() error: %v", loadErr)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	for _, event := range events {
		if event.EventType == factory.EventTypeStepStarted {
			t.Fatalf("unexpected step-started event before secret resolution: %#v", events)
		}
	}
}

func TestRunFactoryRunWithDepsRejectsLocalWhenPolicyRequiresSandbox(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 10, 30, 0, 0, time.UTC)
	rejectedAt := createdAt.Add(1 * time.Minute)
	times := []time.Time{createdAt, rejectedAt}
	policy := factory.DefaultFactoryPolicy()
	policy.SandboxRequired = true

	err := runFactoryRunWithDeps(context.Background(), ".", factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-policy-sandbox-required", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return rejectedAt
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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		loadEngine: func(string) (string, error) {
			return factory.PolicyEngineCodex, nil
		},
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			t.Fatal("local pipeline should not be called when sandboxRequired rejects creation")
			return nil
		},
		runSandbox: func(context.Context, factorySandboxExecutorRequest) error {
			t.Fatal("sandbox executor should not be called for a rejected local run")
			return nil
		},
	})
	if err == nil {
		t.Fatal("runFactoryRunWithDeps() error = nil, want policy rejection")
	}
	if !strings.Contains(err.Error(), "factory.policy.sandboxRequired") || !strings.Contains(err.Error(), "requires sandbox executor") {
		t.Fatalf("runFactoryRunWithDeps() error = %q, want sandboxRequired rejection", err.Error())
	}

	record, err := store.LoadRun("run-policy-sandbox-required")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want failed", record.Status)
	}
	if record.CurrentStep != "policy" {
		t.Fatalf("currentStep = %q, want policy", record.CurrentStep)
	}
	if record.Failure == nil {
		t.Fatal("failure summary is nil")
	}
	if record.Failure.Category != factory.FailureCategoryPRD {
		t.Fatalf("failure category = %q, want %q", record.Failure.Category, factory.FailureCategoryPRD)
	}

	events, err := store.LoadEvents("run-policy-sandbox-required")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypePolicyDecision,
		factory.EventTypeFailureClassification,
	})
	assertFactoryEventSequences(t, events)
	assertPolicyDecisionMetadata(t, events[1].Metadata, factory.PolicyDecisionMetadata{
		PolicyField: "factory.policy.sandboxRequired",
		Decision:    factory.PolicyDecisionRejectedExecution,
		Outcome:     factory.PolicyOutcomeRejected,
		Reason:      "requires sandbox executor (requested local)",
	})
	if !events[1].Timestamp.Equal(rejectedAt) {
		t.Fatalf("policy event timestamp = %s, want %s", events[1].Timestamp, rejectedAt)
	}
}

func TestRunFactoryRunWithDepsRejectsDisallowedPolicyEngineBeforeSandboxExecution(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 10, 45, 0, 0, time.UTC)
	rejectedAt := createdAt.Add(1 * time.Minute)
	times := []time.Time{createdAt, rejectedAt}
	policy := factory.DefaultFactoryPolicy()
	policy.AllowedEngines = []string{factory.PolicyEngineClaude}

	err := runFactoryRunWithDeps(context.Background(), "/workspace/hal", factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		Sandbox:      true,
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-policy-disallowed-engine", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return rejectedAt
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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		loadEngine: func(string) (string, error) {
			return factory.PolicyEngineCodex, nil
		},
		runPipeline: func(context.Context, factoryRunPipelineRequest) error {
			t.Fatal("local pipeline should not be called for a sandbox request")
			return nil
		},
		runSandbox: func(context.Context, factorySandboxExecutorRequest) error {
			t.Fatal("sandbox executor should not be called when allowedEngines rejects creation")
			return nil
		},
	})
	if err == nil {
		t.Fatal("runFactoryRunWithDeps() error = nil, want policy rejection")
	}
	if !strings.Contains(err.Error(), "factory.policy.allowedEngines") || !strings.Contains(err.Error(), `engine "codex"`) {
		t.Fatalf("runFactoryRunWithDeps() error = %q, want allowedEngines rejection", err.Error())
	}

	record, err := store.LoadRun("run-policy-disallowed-engine")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want failed", record.Status)
	}
	if record.ExecutorMode != factory.ExecutorModeSandbox {
		t.Fatalf("executorMode = %q, want sandbox", record.ExecutorMode)
	}
	if record.CurrentStep != "policy" {
		t.Fatalf("currentStep = %q, want policy", record.CurrentStep)
	}
	if record.Failure == nil || record.Failure.Category != factory.FailureCategoryPRD {
		t.Fatalf("failure = %#v, want PRD validation failure", record.Failure)
	}

	events, err := store.LoadEvents("run-policy-disallowed-engine")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypePolicyDecision,
		factory.EventTypeFailureClassification,
	})
	assertFactoryEventSequences(t, events)
	assertPolicyDecisionMetadata(t, events[1].Metadata, factory.PolicyDecisionMetadata{
		PolicyField: "factory.policy.allowedEngines",
		Decision:    factory.PolicyDecisionRejectedExecution,
		Outcome:     factory.PolicyOutcomeRejected,
		Reason:      `does not allow engine "codex"`,
	})
}

func TestRunFactoryRunWithDepsRecordsAttemptLimitPolicyDecision(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	failedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, failedAt}
	policy := factory.DefaultFactoryPolicy()
	policy.MaxRunAttempts = 1
	limitErr := &compound.PolicyLimitError{
		PolicyField: "factory.policy.maxRunAttempts",
		Step:        compound.StepRun,
		Attempts:    1,
		Limit:       1,
	}

	err := runFactoryRunWithDeps(context.Background(), ".", factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-policy-attempt-limit", nil },
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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		loadEngine: func(string) (string, error) {
			return factory.PolicyEngineCodex, nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			if req.AttemptPolicy.MaxRunAttempts != 1 {
				t.Fatalf("pipeline attempt policy = %+v, want maxRunAttempts 1", req.AttemptPolicy)
			}
			return limitErr
		},
	})
	if !errors.Is(err, limitErr) {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want policy limit error", err)
	}

	record, err := store.LoadRun("run-policy-attempt-limit")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want failed", record.Status)
	}
	if record.CurrentStep != "policy" {
		t.Fatalf("currentStep = %q, want policy", record.CurrentStep)
	}
	if record.Failure == nil || record.Failure.Category != factory.FailureCategoryRun {
		t.Fatalf("failure = %#v, want run failure", record.Failure)
	}

	events, err := store.LoadEvents("run-policy-attempt-limit")
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypePolicyDecision,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	assertFactoryEventSequences(t, events)
	assertPolicyDecisionMetadata(t, events[2].Metadata, factory.PolicyDecisionMetadata{
		PolicyField: "factory.policy.maxRunAttempts",
		Decision:    factory.PolicyDecisionBlockedGate,
		Outcome:     factory.PolicyOutcomeBlocked,
		Reason:      "reached attempt limit 1 before run step (attempts=1)",
	})
	if !events[2].Timestamp.Equal(failedAt) {
		t.Fatalf("policy event timestamp = %s, want %s", events[2].Timestamp, failedAt)
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
	if events[3].Metadata["category"] != factory.FailureCategoryRun {
		t.Fatalf("classification category metadata = %#v", events[3].Metadata)
	}
}

func TestRecordFactoryPolicyDecisionRecordsAllowedAndBlockedEvents(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	runID := "run-policy-decisions"
	createdAt := time.Date(2026, 6, 21, 9, 15, 0, 0, time.UTC)
	allowedAt := createdAt.Add(1 * time.Minute)
	blockedAt := createdAt.Add(2 * time.Minute)

	if err := appendFactoryRunTimelineEvent(store, runID, createdAt, factoryTimelineEvent{
		EventType: factory.EventTypeRunCreated,
		Summary:   "Factory run started",
	}); err != nil {
		t.Fatalf("appendFactoryRunTimelineEvent() unexpected error: %v", err)
	}

	allowed := factory.PolicyDecisionMetadata{
		PolicyField: "factory.policy.allowedEngines",
		Decision:    factory.PolicyDecisionAllowedExecution,
		Outcome:     factory.PolicyOutcomeAllowed,
		Reason:      "requested engine codex is allowed",
	}
	if err := recordFactoryPolicyDecision(store, runID, allowedAt, allowed); err != nil {
		t.Fatalf("recordFactoryPolicyDecision(allowed) unexpected error: %v", err)
	}

	blocked := factory.PolicyDecisionMetadata{
		PolicyField: "factory.policy.verificationRequired",
		Decision:    factory.PolicyDecisionBlockedGate,
		Outcome:     factory.PolicyOutcomeBlocked,
		Reason:      "latest verification result failed",
	}
	if err := recordFactoryPolicyDecision(store, runID, blockedAt, blocked); err != nil {
		t.Fatalf("recordFactoryPolicyDecision(blocked) unexpected error: %v", err)
	}

	events, err := store.LoadEvents(runID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypePolicyDecision,
		factory.EventTypePolicyDecision,
	})
	assertFactoryEventSequences(t, events)
	if !events[1].Timestamp.Equal(allowedAt) {
		t.Fatalf("allowed event timestamp = %s, want %s", events[1].Timestamp, allowedAt)
	}
	if !events[2].Timestamp.Equal(blockedAt) {
		t.Fatalf("blocked event timestamp = %s, want %s", events[2].Timestamp, blockedAt)
	}
	if events[1].Summary != "Policy decision allowed_execution: allowed" {
		t.Fatalf("allowed summary = %q", events[1].Summary)
	}
	if events[2].Summary != "Policy decision blocked_gate: blocked" {
		t.Fatalf("blocked summary = %q", events[2].Summary)
	}
	assertPolicyDecisionMetadata(t, events[1].Metadata, allowed)
	assertPolicyDecisionMetadata(t, events[2].Metadata, blocked)
}

func TestAppendFactoryRunTimelineEventWithRedactorRedactsStructMetadata(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	runID := "run-struct-redaction"
	secret := "ghp_struct_timeline_secret_12345"
	redactor := factory.NewRunSecretRedactor([]factory.ResolvedRunSecret{{
		Name:  "GITHUB_TOKEN",
		Value: secret,
	}})

	if err := appendFactoryRunTimelineEventWithRedactor(store, runID, time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC), factoryTimelineEvent{
		EventType: factory.EventTypeVerificationResult,
		Summary:   "Verification completed",
		Metadata: map[string]any{
			"checks": []verify.CheckResult{{
				ID:      "checkout",
				Command: "git fetch https://" + secret + "@github.com/example/repo.git",
				Message: "checkout failed with token " + secret,
			}},
		},
	}, redactor); err != nil {
		t.Fatalf("appendFactoryRunTimelineEventWithRedactor() unexpected error: %v", err)
	}

	events, err := store.LoadEvents(runID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	data, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("Marshal(events) error: %v", err)
	}
	payload := string(data)
	if strings.Contains(payload, secret) {
		t.Fatalf("timeline event leaked struct metadata secret: %s", payload)
	}
	if !strings.Contains(payload, factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("timeline event missing redaction placeholder: %s", payload)
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
	requireFactoryArtifactPath(t, record.Artifacts, "factory/status-snapshot.json")
	requireFactoryArtifactPath(t, record.Artifacts, "factory/doctor-snapshot.json")
	requireFactoryArtifactPath(t, record.Artifacts, filepath.Join(store.RunsDir(), "run-artifacts-markdown.json"))
	prOutcome := requireFactoryArtifactPath(t, record.Artifacts, "factory/pr-outcome.json")
	if !prOutcome.Partial || len(prOutcome.Warnings) == 0 {
		t.Fatalf("PR outcome should record missing warning: %#v", prOutcome)
	}
	ciOutcome := requireFactoryArtifactPath(t, record.Artifacts, "factory/ci-outcome.json")
	if !ciOutcome.Partial || len(ciOutcome.Warnings) == 0 {
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
			"/workspace/.hal/auto-state.json": `{"step":"done"}` + "\n",
		},
		dirs: map[string]map[string]string{
			"/workspace/.hal/reports": {
				"review.md":          "# Review\n",
				"verify/stdout.txt":  "ok\n",
				"verify/result.json": `{"status":"pass"}` + "\n",
			},
		},
	}
	target := &sandbox.SandboxState{
		Name:     "factory-sandbox",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
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
			record.SandboxName = target.Name
			if err := req.Store.SaveRun(record); err != nil {
				t.Fatalf("SaveRun() sandbox record error: %v", err)
			}
			return nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			data, err := json.Marshal(verify.Result{
				SchemaVersion: verify.SchemaVersion,
				Status:        verify.StatusPass,
				Summary:       verify.Summary{},
				Checks:        []verify.CheckResult{},
			})
			if err != nil {
				t.Fatalf("Marshal(verify result) error: %v", err)
			}
			if _, err := out.Write(append(data, '\n')); err != nil {
				t.Fatalf("write remote verify JSON error: %v", err)
			}
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		sandboxCopier:  copier,
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
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/reports/review.md")
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/reports/verify/stdout.txt")
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/reports/verify/result.json")
	if _, err := os.Stat(filepath.Join(halDir, "artifacts")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("sandbox artifact collection should not create project .hal artifacts, stat error = %v", err)
	}
}

func TestRunFactoryRunWithDepsCollectsSandboxArtifactsBeforeSandboxCleanup(t *testing.T) {
	dir := t.TempDir()
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 4, 5, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	completedAt := createdAt.Add(2 * time.Minute)
	times := []time.Time{createdAt, startedAt, completedAt}
	copier := &fakeFactorySandboxArtifactCopier{
		files: map[string]string{
			"/workspace/.hal/auto-state.json": `{"step":"done"}` + "\n",
		},
	}
	target := &sandbox.SandboxState{
		Name:     "factory-sandbox",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
	cleanupStarted := false

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{BaseBranch: "main", Sandbox: true}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-cleanup-order", nil },
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
		runSandbox: func(ctx context.Context, req factorySandboxExecutorRequest) error {
			record := req.RunRecord
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = target.Name
			if err := store.SaveRun(&record); err != nil {
				return err
			}
			if req.BeforeCleanup == nil {
				t.Fatal("BeforeCleanup was not configured for sandbox runs")
			}
			if err := req.BeforeCleanup(ctx, record); err != nil {
				return err
			}
			cleanupStarted = true
			delete(copier.files, "/workspace/.hal/auto-state.json")
			return nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			data, err := json.Marshal(verify.Result{
				SchemaVersion: verify.SchemaVersion,
				Status:        verify.StatusPass,
				Summary:       verify.Summary{},
				Checks:        []verify.CheckResult{},
			})
			if err != nil {
				t.Fatalf("Marshal(verify result) error: %v", err)
			}
			if _, err := out.Write(append(data, '\n')); err != nil {
				t.Fatalf("write remote verify JSON error: %v", err)
			}
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		sandboxCopier:  copier,
		sandboxRequests: func(_ string, record factory.RunRecord) []factory.SandboxArtifactRequest {
			if cleanupStarted {
				t.Fatal("sandbox artifacts were requested after sandbox cleanup started")
			}
			return []factory.SandboxArtifactRequest{{
				ID:         "sandbox-auto-state",
				Name:       "sandbox-auto-state",
				Type:       "json",
				RemotePath: "/workspace/.hal/auto-state.json",
				Path:       ".hal/auto-state.json",
			}}
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	record, err := store.LoadRun("run-sandbox-cleanup-order")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/auto-state.json")
	if len(copier.fileCalls) != 1 {
		t.Fatalf("sandbox artifact copy calls = %d, want 1 before cleanup", len(copier.fileCalls))
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

func TestRunFactoryRunWithDepsMarksRunFailedWhenArtifactCollectionFails(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 3, 15, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	pipelineCompletedAt := createdAt.Add(2 * time.Minute)
	failedAt := createdAt.Add(3 * time.Minute)
	times := []time.Time{createdAt, startedAt, pipelineCompletedAt, failedAt}
	artifactErr := errors.New("status snapshot unavailable")
	var out bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		JSON:         true,
	}, &out, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-artifact-collection-failed", nil },
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
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) {
			return factorySnapshotArtifact{}, artifactErr
		},
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) {
			t.Fatal("doctor snapshot should not run after status snapshot fails")
			return factorySnapshotArtifact{}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), artifactErr.Error()) {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want artifact error", err)
	}
	if !strings.Contains(out.String(), `"status": "failed"`) {
		t.Fatalf("rendered output = %s, want failed status", out.String())
	}

	record, err := store.LoadRun("run-artifact-collection-failed")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusFailed)
	}
	if record.CurrentStep != factory.RunDurationStepArtifactCollect {
		t.Fatalf("currentStep = %q, want %q", record.CurrentStep, factory.RunDurationStepArtifactCollect)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(failedAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, failedAt)
	}
	if record.Failure == nil || record.Failure.Step != factory.RunDurationStepArtifactCollect {
		t.Fatalf("failure = %#v, want artifact collection failure", record.Failure)
	}

	runRecordArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, factoryRunRecordArtifactPath(store, record.RunID))
	var storedRunRecord factory.RunRecord
	if err := json.Unmarshal([]byte(readStoredFactoryArtifact(t, store, record.RunID, runRecordArtifact)), &storedRunRecord); err != nil {
		t.Fatalf("Unmarshal(factory run record artifact) error: %v", err)
	}
	if storedRunRecord.Status != factory.RunStatusFailed || storedRunRecord.CurrentStep != factory.RunDurationStepArtifactCollect {
		t.Fatalf("stored run record status/currentStep = %q/%q, want failed/%q", storedRunRecord.Status, storedRunRecord.CurrentStep, factory.RunDurationStepArtifactCollect)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeStepEnded,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	if events[3].Metadata["step"] != factory.RunDurationStepArtifactCollect {
		t.Fatalf("artifact failure event step = %#v, want %q", events[3].Metadata["step"], factory.RunDurationStepArtifactCollect)
	}
	if events[3].Metadata["status"] != factory.RunStatusFailed {
		t.Fatalf("artifact failure event status = %#v, want %q", events[3].Metadata["status"], factory.RunStatusFailed)
	}
	if got, ok := events[3].Metadata["error"].(string); !ok || !strings.Contains(got, artifactErr.Error()) {
		t.Fatalf("artifact failure event error = %#v, want artifact error", events[3].Metadata["error"])
	}
}

func TestRunFactoryRunWithDepsPreservesOnSuccessSandboxWhenArtifactCollectionFails(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")
	localVerifyDir := filepath.Join(halDir, "reports", "verify")
	if err := os.MkdirAll(localVerifyDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(localVerifyDir) error: %v", err)
	}
	writeFile(t, localVerifyDir, "remote-test-stdout.txt", "local stale verification stdout\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 3, 16, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	pipelineCompletedAt := createdAt.Add(2 * time.Minute)
	failedAt := createdAt.Add(3 * time.Minute)
	times := []time.Time{createdAt, startedAt, pipelineCompletedAt, failedAt}
	policy := factory.DefaultFactoryPolicy()
	policy.CleanupBehavior = factory.CleanupBehaviorOnSuccess
	policy.VerificationRequired = true
	artifactErr := errors.New("status snapshot unavailable")
	target := &sandbox.SandboxState{
		Name:     "factory-artifact-failed",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
	var cleanupCalls int

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		Sandbox:      true,
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-artifact-collection-failed", nil },
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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		runSandbox: func(_ context.Context, req factorySandboxExecutorRequest) error {
			if !req.DeferSuccessCleanup {
				t.Fatal("DeferSuccessCleanup = false, want true for on_success cleanup")
			}
			record := req.RunRecord
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = target.Name
			record.Sandbox = &factory.SandboxMetadata{
				Name:           target.Name,
				Provider:       target.Provider,
				Status:         target.Status,
				Connection:     &factory.SandboxConnectionMetadata{Address: target.IP, PublicIP: target.IP},
				SSHCommand:     "hal sandbox ssh " + target.Name,
				CleanupCommand: "hal sandbox delete " + target.Name,
				Handoff:        "Inspect sandbox with `hal sandbox ssh " + target.Name + "`.",
			}
			return store.SaveRun(&record)
		},
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
			cleanupCalls++
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) {
			return factorySnapshotArtifact{}, artifactErr
		},
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) {
			t.Fatal("doctor snapshot should not run after status snapshot fails")
			return factorySnapshotArtifact{}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), artifactErr.Error()) {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want artifact error", err)
	}
	if cleanupCalls != 0 {
		t.Fatalf("cleanup calls = %d, want 0 for on_success artifact failure", cleanupCalls)
	}
	record, err := store.LoadRun("run-sandbox-artifact-collection-failed")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want failed", record.Status)
	}
	if record.Sandbox == nil {
		t.Fatal("sandbox metadata = nil, want preserved metadata")
	}
	if record.Sandbox.Status != sandbox.StatusRunning || record.Sandbox.SSHCommand == "" || record.Sandbox.CleanupCommand == "" || record.Sandbox.Handoff == "" {
		t.Fatalf("sandbox metadata = %#v, want preserved running handoff", record.Sandbox)
	}
	if record.Failure == nil || record.Failure.Step != factory.RunDurationStepArtifactCollect {
		t.Fatalf("failure = %#v, want artifact collection failure", record.Failure)
	}
}

func TestFactoryRunDefersSandboxSuccessCleanup(t *testing.T) {
	tests := []struct {
		name     string
		behavior string
		want     bool
	}{
		{name: "preserve", behavior: factory.CleanupBehaviorPreserve},
		{name: "on success", behavior: factory.CleanupBehaviorOnSuccess, want: true},
		{name: "always", behavior: factory.CleanupBehaviorAlways, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := factory.DefaultFactoryPolicy()
			policy.CleanupBehavior = tt.behavior
			if got := factoryRunDefersSandboxSuccessCleanup(policy); got != tt.want {
				t.Fatalf("factoryRunDefersSandboxSuccessCleanup() = %v, want %v", got, tt.want)
			}
		})
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
	policy := factory.DefaultFactoryPolicy()
	policy.VerificationRequired = true

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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
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

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeStepEnded,
		factory.EventTypeStepStarted,
		factory.EventTypeVerificationResult,
		factory.EventTypePolicyDecision,
		factory.EventTypeStepEnded,
	})
	if events[1].Metadata["step"] != factory.RunDurationStepEngineRun {
		t.Fatalf("pipeline start event step = %#v, want %q", events[1].Metadata["step"], factory.RunDurationStepEngineRun)
	}
	if events[2].Metadata["step"] != factory.RunDurationStepEngineRun {
		t.Fatalf("pipeline completion event step = %#v, want %q", events[2].Metadata["step"], factory.RunDurationStepEngineRun)
	}
	if events[3].Metadata["step"] != factory.RunDurationStepVerification {
		t.Fatalf("verification start event step = %#v, want %q", events[3].Metadata["step"], factory.RunDurationStepVerification)
	}
	if events[4].Summary != "Verification passed" {
		t.Fatalf("verification event summary = %q", events[4].Summary)
	}
	if !events[4].Timestamp.Equal(verifiedAt) {
		t.Fatalf("verification event timestamp = %s, want %s", events[4].Timestamp, verifiedAt)
	}
	if events[4].Metadata["status"] != verify.StatusPass {
		t.Fatalf("verification event status metadata = %#v", events[4].Metadata)
	}
	assertPolicyDecisionMetadata(t, events[5].Metadata, factory.PolicyDecisionMetadata{
		PolicyField: "factory.policy.verificationRequired",
		Decision:    factory.PolicyDecisionPassedGate,
		Outcome:     factory.PolicyOutcomePassed,
		Reason:      "verification passed",
	})
	if events[6].Metadata["step"] != factory.RunDurationStepVerification {
		t.Fatalf("verification completion event step = %#v, want %q", events[6].Metadata["step"], factory.RunDurationStepVerification)
	}
	if !events[6].Timestamp.Equal(verifiedAt) {
		t.Fatalf("completion event timestamp = %s, want %s", events[6].Timestamp, verifiedAt)
	}
	telemetry := factory.DeriveRunTelemetry(*record, events)
	if telemetry == nil || len(telemetry.StepDurations) != 2 {
		t.Fatalf("derived telemetry stepDurations = %#v, want engine and verification durations", telemetry)
	}
	if telemetry.StepDurations[0].Step != factory.RunDurationStepEngineRun || telemetry.StepDurations[1].Step != factory.RunDurationStepVerification {
		t.Fatalf("derived telemetry steps = %#v, want engine_run then verification", telemetry.StepDurations)
	}
}

func TestRunFactoryRunWithDepsCleansDeferredSandboxAfterVerificationPasses(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 2, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	verifiedAt := createdAt.Add(4 * time.Minute)
	cleanedAt := createdAt.Add(5 * time.Minute)
	succeededAt := createdAt.Add(6 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, verifiedAt, cleanedAt, succeededAt}
	policy := factory.DefaultFactoryPolicy()
	policy.CleanupBehavior = factory.CleanupBehaviorOnSuccess
	policy.VerificationRequired = true
	copier := &fakeFactorySandboxArtifactCopier{
		files: map[string]string{
			"/workspace/.hal/auto-state.json": `{"step":"done"}` + "\n",
		},
	}
	target := &sandbox.SandboxState{
		Name:     "factory-verified",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
	var verificationCalled bool
	var remoteVerifyArgs []string
	var remoteArtifactCopied bool
	var cleanupCalls int

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		Sandbox:      true,
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-deferred-cleanup", nil },
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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		runSandbox: func(_ context.Context, req factorySandboxExecutorRequest) error {
			if !req.DeferSuccessCleanup {
				t.Fatal("DeferSuccessCleanup = false, want true for on_success cleanup with required verification")
			}
			if req.BeforeCleanup == nil {
				t.Fatal("BeforeCleanup should still be configured")
			}
			record := req.RunRecord
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = target.Name
			record.Sandbox = &factory.SandboxMetadata{
				Name:           target.Name,
				Provider:       target.Provider,
				Status:         target.Status,
				Connection:     &factory.SandboxConnectionMetadata{Address: target.IP, PublicIP: target.IP},
				SSHCommand:     "hal sandbox ssh " + target.Name,
				CleanupCommand: "hal sandbox delete " + target.Name,
				Handoff:        "Inspect sandbox with `hal sandbox ssh " + target.Name + "`.",
			}
			return store.SaveRun(&record)
		},
		loadVerify: func(string) (*verify.Config, error) {
			t.Fatal("loadVerify should not run for sandbox verification")
			return nil, nil
		},
		runVerify: func(context.Context, *verify.Config) (*verify.Result, error) {
			t.Fatal("runVerify should not run for sandbox verification")
			return nil, nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, info *sandbox.ConnectInfo, args []string, out io.Writer) error {
			if info == nil || info.Name != target.Name || info.IP != target.IP {
				t.Fatalf("connect info = %#v, want sandbox %q at %q", info, target.Name, target.IP)
			}
			command := strings.Join(args, " ")
			if strings.Contains(command, "'hal' 'verify' '--json'") {
				verificationCalled = true
				remoteVerifyArgs = append([]string(nil), args...)
				data, err := json.Marshal(verify.Result{
					SchemaVersion: verify.SchemaVersion,
					Status:        verify.StatusPass,
					Summary: verify.Summary{
						Total:  1,
						Passed: 1,
					},
					Checks: []verify.CheckResult{{
						ID:             "remote-test",
						Name:           "Remote tests",
						Status:         verify.CheckStatusPass,
						Required:       true,
						StdoutArtifact: ".hal/reports/verify/remote-test-stdout.txt",
					}},
					Artifacts: []verify.ArtifactReference{{
						CheckID: "remote-test",
						Kind:    verify.ArtifactKindStdout,
						Path:    ".hal/reports/verify/remote-test-stdout.txt",
					}},
				})
				if err != nil {
					t.Fatalf("Marshal(verify result) error: %v", err)
				}
				if _, err := out.Write(append(data, '\n')); err != nil {
					t.Fatalf("write remote verify JSON error: %v", err)
				}
				return nil
			}
			if strings.Contains(command, "base64 < '/workspace/hal/.hal/reports/verify/remote-test-stdout.txt'") {
				remoteArtifactCopied = true
				if _, err := io.WriteString(out, base64.StdEncoding.EncodeToString([]byte("verification stdout\n"))); err != nil {
					t.Fatalf("write remote artifact error: %v", err)
				}
				return nil
			}
			t.Fatalf("unexpected provider exec args = %#v", args)
			return nil
		},
		cleanupSandbox: func(_ context.Context, req factorySandboxCleanupRequest) error {
			cleanupCalls++
			if !verificationCalled {
				t.Fatal("cleanup ran before verification passed")
			}
			if len(copier.fileCalls) != 1 {
				t.Fatalf("cleanup ran before sandbox artifact collection; fileCalls = %#v", copier.fileCalls)
			}
			if !remoteArtifactCopied {
				t.Fatal("cleanup ran before remote verification artifact copy")
			}
			currentRecord, err := store.LoadRun("run-sandbox-deferred-cleanup")
			if err != nil {
				t.Fatalf("LoadRun() during cleanup error: %v", err)
			}
			artifact := requireStoredFactoryArtifactPath(t, store, currentRecord.RunID, currentRecord.Artifacts, ".hal/reports/verify/remote-test-stdout.txt")
			if got := readStoredFactoryArtifact(t, store, currentRecord.RunID, artifact); got != "verification stdout\n" {
				t.Fatalf("stored verification artifact before cleanup = %q", got)
			}
			if req.Target == nil || req.Target.Name != target.Name {
				t.Fatalf("cleanup target = %#v, want %q", req.Target, target.Name)
			}
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		sandboxCopier:  copier,
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
			return []factory.SandboxArtifactRequest{{
				ID:         "sandbox-auto-state",
				Name:       "sandbox-auto-state",
				Type:       "json",
				RemotePath: "/workspace/.hal/auto-state.json",
				Path:       ".hal/auto-state.json",
			}}
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1 after verification passes", cleanupCalls)
	}
	wantArgs := []string{"sh", "-lc", "cd '/workspace/hal' && exec 'hal' 'verify' '--json' 2>/tmp/hal-factory-verify-stderr"}
	if !reflect.DeepEqual(remoteVerifyArgs, wantArgs) {
		t.Fatalf("remote verify args = %#v, want %#v", remoteVerifyArgs, wantArgs)
	}
	record, err := store.LoadRun("run-sandbox-deferred-cleanup")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusSucceeded {
		t.Fatalf("status = %q, want succeeded", record.Status)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(succeededAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, succeededAt)
	}
	if record.Sandbox == nil {
		t.Fatal("sandbox metadata = nil, want cleaned metadata")
	}
	if record.Sandbox.Status != sandbox.StatusUnknown {
		t.Fatalf("sandbox status = %q, want unknown after cleanup", record.Sandbox.Status)
	}
	if record.Sandbox.Connection != nil || record.Sandbox.SSHCommand != "" || record.Sandbox.CleanupCommand != "" || record.Sandbox.Handoff != "" {
		t.Fatalf("sandbox handoff metadata = %#v, want cleared after cleanup", record.Sandbox)
	}
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/auto-state.json")
	verificationArtifact := requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/reports/verify/remote-test-stdout.txt")
	if got := readStoredFactoryArtifact(t, store, record.RunID, verificationArtifact); got != "verification stdout\n" {
		t.Fatalf("stored verification artifact = %q", got)
	}
	var verificationArtifactCount int
	for _, artifact := range record.Artifacts {
		if artifact.Path == ".hal/reports/verify/remote-test-stdout.txt" {
			verificationArtifactCount++
		}
	}
	if verificationArtifactCount != 1 {
		t.Fatalf("verification artifact count = %d, want 1; artifacts = %#v", verificationArtifactCount, record.Artifacts)
	}
}

func TestCleanupFactoryRunDeferredSandboxCopiesArtifactsWithProviderExecBeforeCleanup(t *testing.T) {
	dir := t.TempDir()
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	policy := factory.DefaultFactoryPolicy()
	policy.CleanupBehavior = factory.CleanupBehaviorOnSuccess
	target := &sandbox.SandboxState{
		Name:     "factory-copy-before-cleanup",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
	record := factory.RunRecord{
		RunID:        "run-copy-before-cleanup",
		Status:       factory.RunStatusRunning,
		ExecutorMode: factory.ExecutorModeSandbox,
		RepoRemote:   "git@github.com:jywlabs/hal.git",
		SandboxName:  target.Name,
		Sandbox:      &factory.SandboxMetadata{Name: target.Name, Provider: target.Provider, Status: target.Status},
		CreatedAt:    time.Date(2026, 6, 21, 1, 7, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2026, 6, 21, 1, 7, 0, 0, time.UTC),
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var copied bool
	var cleanupCalls int
	updated, cleaned, err := cleanupFactoryRunDeferredSandbox(context.Background(), store, dir, factoryRunRequest{BaseBranch: "main", Sandbox: true}, io.Discard, record, factoryRunDeps{
		now: func() time.Time {
			return time.Date(2026, 6, 21, 1, 8, 0, 0, time.UTC)
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, args []string, out io.Writer) error {
			command := strings.Join(args, " ")
			if !strings.Contains(command, "base64 < '/workspace/hal/.hal/auto-state.json'") {
				t.Fatalf("provider exec args = %#v, want auto-state copy", args)
			}
			copied = true
			if _, err := io.WriteString(out, base64.StdEncoding.EncodeToString([]byte(`{"step":"done"}`+"\n"))); err != nil {
				t.Fatalf("write remote artifact error: %v", err)
			}
			return nil
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
			cleanupCalls++
			if !copied {
				t.Fatal("cleanup ran before provider-exec artifact copy")
			}
			currentRecord, err := store.LoadRun(record.RunID)
			if err != nil {
				t.Fatalf("LoadRun() during cleanup error: %v", err)
			}
			artifact := requireStoredFactoryArtifactPath(t, store, currentRecord.RunID, currentRecord.Artifacts, ".hal/auto-state.json")
			if got := readStoredFactoryArtifact(t, store, currentRecord.RunID, artifact); got != `{"step":"done"}`+"\n" {
				t.Fatalf("stored auto-state artifact before cleanup = %q", got)
			}
			return nil
		},
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
			return []factory.SandboxArtifactRequest{{
				ID:         "sandbox-auto-state",
				Name:       "sandbox-auto-state",
				Type:       "json",
				RemotePath: ".hal/auto-state.json",
				Path:       ".hal/auto-state.json",
			}}
		},
	}, policy, "success")
	if err != nil {
		t.Fatalf("cleanupFactoryRunDeferredSandbox() unexpected error: %v", err)
	}
	if !cleaned || cleanupCalls != 1 {
		t.Fatalf("cleaned=%v cleanupCalls=%d, want one cleanup", cleaned, cleanupCalls)
	}
	if updated.Sandbox == nil || updated.Sandbox.Status != sandbox.StatusUnknown {
		t.Fatalf("updated sandbox = %#v, want cleaned unknown status", updated.Sandbox)
	}
	artifact := requireStoredFactoryArtifactPath(t, store, updated.RunID, updated.Artifacts, ".hal/auto-state.json")
	if got := readStoredFactoryArtifact(t, store, updated.RunID, artifact); got != `{"step":"done"}`+"\n" {
		t.Fatalf("stored auto-state artifact = %q", got)
	}
}

func TestRunFactoryRunWithDepsCleansOnSuccessSandboxAfterFinalSuccessWithoutVerification(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 4, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	verificationDoneAt := createdAt.Add(4 * time.Minute)
	cleanedAt := createdAt.Add(5 * time.Minute)
	succeededAt := createdAt.Add(6 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, verificationDoneAt, cleanedAt, succeededAt}
	policy := factory.DefaultFactoryPolicy()
	policy.CleanupBehavior = factory.CleanupBehaviorOnSuccess
	policy.VerificationRequired = false
	copier := &fakeFactorySandboxArtifactCopier{
		files: map[string]string{
			"/workspace/.hal/auto-state.json": `{"step":"done"}` + "\n",
		},
	}
	target := &sandbox.SandboxState{
		Name:     "factory-final-success",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
	var remoteVerified bool
	var cleanupCalls int

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		Sandbox:      true,
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-final-success-cleanup", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return succeededAt
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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		runSandbox: func(_ context.Context, req factorySandboxExecutorRequest) error {
			if !req.DeferSuccessCleanup {
				t.Fatal("DeferSuccessCleanup = false, want true for on_success cleanup until final success")
			}
			record := req.RunRecord
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = target.Name
			record.Sandbox = &factory.SandboxMetadata{
				Name:           target.Name,
				Provider:       target.Provider,
				Status:         target.Status,
				Connection:     &factory.SandboxConnectionMetadata{Address: target.IP, PublicIP: target.IP},
				SSHCommand:     "hal sandbox ssh " + target.Name,
				CleanupCommand: "hal sandbox delete " + target.Name,
				Handoff:        "Inspect sandbox with `hal sandbox ssh " + target.Name + "`.",
			}
			return store.SaveRun(&record)
		},
		loadVerify: func(string) (*verify.Config, error) {
			t.Fatal("loadVerify should not run for sandbox verification")
			return nil, nil
		},
		runVerify: func(context.Context, *verify.Config) (*verify.Result, error) {
			t.Fatal("runVerify should not run for sandbox verification")
			return nil, nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			remoteVerified = true
			data, err := json.Marshal(verify.Result{
				SchemaVersion: verify.SchemaVersion,
				Status:        verify.StatusPass,
				Summary:       verify.Summary{},
				Checks:        []verify.CheckResult{},
			})
			if err != nil {
				t.Fatalf("Marshal(verify result) error: %v", err)
			}
			if _, err := out.Write(append(data, '\n')); err != nil {
				t.Fatalf("write remote verify JSON error: %v", err)
			}
			return nil
		},
		cleanupSandbox: func(_ context.Context, req factorySandboxCleanupRequest) error {
			cleanupCalls++
			if !remoteVerified {
				t.Fatal("cleanup ran before remote verification completed")
			}
			if len(copier.fileCalls) != 1 {
				t.Fatalf("cleanup ran before sandbox artifact collection; fileCalls = %#v", copier.fileCalls)
			}
			if req.Target == nil || req.Target.Name != target.Name {
				t.Fatalf("cleanup target = %#v, want %q", req.Target, target.Name)
			}
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		sandboxCopier:  copier,
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
			return []factory.SandboxArtifactRequest{{
				ID:         "sandbox-auto-state",
				Name:       "sandbox-auto-state",
				Type:       "json",
				RemotePath: "/workspace/.hal/auto-state.json",
				Path:       ".hal/auto-state.json",
			}}
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1 after final factory success", cleanupCalls)
	}
	record, err := store.LoadRun("run-sandbox-final-success-cleanup")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusSucceeded {
		t.Fatalf("status = %q, want succeeded", record.Status)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(succeededAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, succeededAt)
	}
	if record.Sandbox == nil || record.Sandbox.Status != sandbox.StatusUnknown {
		t.Fatalf("sandbox metadata = %#v, want cleaned unknown status", record.Sandbox)
	}
	if record.Sandbox.Connection != nil || record.Sandbox.SSHCommand != "" || record.Sandbox.CleanupCommand != "" || record.Sandbox.Handoff != "" {
		t.Fatalf("sandbox handoff metadata = %#v, want cleared after cleanup", record.Sandbox)
	}
	requireStoredFactoryArtifactPath(t, store, record.RunID, record.Artifacts, ".hal/auto-state.json")
}

func TestRunFactoryRunWithDepsPreservesDeferredSandboxWhenVerificationFails(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 3, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	verifiedAt := createdAt.Add(4 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, verifiedAt}
	policy := factory.DefaultFactoryPolicy()
	policy.CleanupBehavior = factory.CleanupBehaviorOnSuccess
	policy.VerificationRequired = true
	target := &sandbox.SandboxState{
		Name:     "factory-verification-failed",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
	var cleanupCalls int

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		Sandbox:      true,
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-preserve-verification-failure", nil },
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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		runSandbox: func(_ context.Context, req factorySandboxExecutorRequest) error {
			if !req.DeferSuccessCleanup {
				t.Fatal("DeferSuccessCleanup = false, want true for on_success cleanup with required verification")
			}
			record := req.RunRecord
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = target.Name
			record.Sandbox = &factory.SandboxMetadata{Name: target.Name, Provider: target.Provider, Status: target.Status}
			return store.SaveRun(&record)
		},
		loadVerify: func(string) (*verify.Config, error) {
			t.Fatal("loadVerify should not run for sandbox verification")
			return nil, nil
		},
		runVerify: func(context.Context, *verify.Config) (*verify.Result, error) {
			t.Fatal("runVerify should not run for sandbox verification")
			return nil, nil
		},
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			data, err := json.Marshal(verify.Result{
				SchemaVersion: verify.SchemaVersion,
				Status:        verify.StatusFail,
				Summary: verify.Summary{
					Total:  1,
					Failed: 1,
				},
				Checks: []verify.CheckResult{{
					ID:       "remote-test",
					Name:     "Remote tests",
					Status:   verify.CheckStatusFail,
					Required: true,
				}},
			})
			if err != nil {
				t.Fatalf("Marshal(verify result) error: %v", err)
			}
			if _, err := out.Write(append(data, '\n')); err != nil {
				t.Fatalf("write remote verify JSON error: %v", err)
			}
			return errors.New("remote verify exited 1")
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
			cleanupCalls++
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
	})
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want verification failure", err)
	}
	if cleanupCalls != 0 {
		t.Fatalf("cleanup calls = %d, want 0 when verification fails", cleanupCalls)
	}
	record, err := store.LoadRun("run-sandbox-preserve-verification-failure")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want failed", record.Status)
	}
	if record.Failure == nil || record.Failure.Step != "verify" {
		t.Fatalf("failure = %#v, want verify failure", record.Failure)
	}
	if record.Verification == nil || record.Verification.Summary.Failed != 1 {
		t.Fatalf("verification = %#v, want persisted remote failure result", record.Verification)
	}
}

func TestRunFactorySandboxRemoteVerificationUsesResolvedSecretsAndRedactsArtifacts(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	secret := "ghp_verify_secret_12345"
	record := factory.RunRecord{
		RunID:        "run-sandbox-verify-secrets",
		Status:       factory.RunStatusRunning,
		ExecutorMode: factory.ExecutorModeSandbox,
		RepoRemote:   "git@github.com:example/hal.git",
		SandboxName:  "factory-secret-verify",
		CreatedAt:    time.Date(2026, 6, 25, 1, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2026, 6, 25, 1, 0, 0, 0, time.UTC),
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	target := &sandbox.SandboxState{
		Name:     record.SandboxName,
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
	resolvedSecrets := []factory.ResolvedRunSecret{{
		Name:     "GITHUB_TOKEN",
		Source:   factory.RunSecretSourceEnv,
		Required: true,
		Value:    secret,
	}}
	var gotEnv map[string]string
	deps := factoryRunDeps{
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExecWithEnv: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, env map[string]string, out io.Writer) error {
			gotEnv = map[string]string{}
			for key, value := range env {
				gotEnv[key] = value
			}
			data, err := json.Marshal(verify.Result{
				SchemaVersion: verify.SchemaVersion,
				Status:        verify.StatusPass,
				Summary:       verify.Summary{Total: 1, Passed: 1},
				Checks: []verify.CheckResult{{
					ID:       "remote-secret-check",
					Name:     "Remote secret check",
					Status:   verify.CheckStatusPass,
					Required: true,
				}},
				Artifacts: []verify.ArtifactReference{{
					CheckID: "remote-secret-check",
					Kind:    "stdout",
					Path:    ".hal/reports/verify-secret.txt",
				}},
			})
			if err != nil {
				t.Fatalf("Marshal(verify result) error: %v", err)
			}
			_, err = out.Write(append(data, '\n'))
			return err
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			_, err := out.Write([]byte(base64.StdEncoding.EncodeToString([]byte("token=" + secret + "\n"))))
			return err
		},
	}

	result, updated, err := runFactorySandboxRemoteVerification(context.Background(), store, ".", record, deps, resolvedSecrets, factory.NewRunSecretRedactor(resolvedSecrets))
	if err != nil {
		t.Fatalf("runFactorySandboxRemoteVerification() unexpected error: %v", err)
	}
	if gotEnv["GITHUB_TOKEN"] != secret {
		t.Fatalf("GITHUB_TOKEN env = %q, want secret", gotEnv["GITHUB_TOKEN"])
	}
	if result == nil || result.Status != verify.StatusPass {
		t.Fatalf("result = %#v, want pass", result)
	}
	if len(updated.Artifacts) != 1 {
		t.Fatalf("artifacts = %#v, want one verification artifact", updated.Artifacts)
	}
	artifactPath, err := store.ResolveArtifactPath(record.RunID, updated.Artifacts[0].StoredPath)
	if err != nil {
		t.Fatalf("ResolveArtifactPath() error: %v", err)
	}
	payload, err := os.ReadFile(artifactPath)
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", artifactPath, err)
	}
	if strings.Contains(string(payload), secret) {
		t.Fatalf("stored verification artifact payload contains raw secret")
	}
	if !strings.Contains(string(payload), factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("stored verification artifact payload = %q, want redaction placeholder", payload)
	}
}

func TestRunFactoryRunWithDepsRecordsAlwaysCleanupWhenFailureArtifactCopyErrors(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 9, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	verifiedAt := createdAt.Add(4 * time.Minute)
	cleanedAt := createdAt.Add(5 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, verifiedAt, cleanedAt}
	policy := factory.DefaultFactoryPolicy()
	policy.CleanupBehavior = factory.CleanupBehaviorAlways
	policy.VerificationRequired = true
	target := &sandbox.SandboxState{
		Name:     "factory-always-cleanup-copy-error",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
	var cleanupCalls int

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		Sandbox:      true,
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-always-cleanup-copy-error", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return cleanedAt
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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		runSandbox: func(_ context.Context, req factorySandboxExecutorRequest) error {
			if !req.DeferSuccessCleanup {
				t.Fatal("DeferSuccessCleanup = false, want true for always cleanup until factory finalization")
			}
			record := req.RunRecord
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = target.Name
			record.Sandbox = &factory.SandboxMetadata{
				Name:           target.Name,
				Provider:       target.Provider,
				Status:         target.Status,
				Connection:     &factory.SandboxConnectionMetadata{Address: target.IP, PublicIP: target.IP},
				SSHCommand:     "hal sandbox ssh " + target.Name,
				CleanupCommand: "hal sandbox delete " + target.Name,
				Handoff:        "Inspect sandbox with `hal sandbox ssh " + target.Name + "`.",
			}
			return store.SaveRun(&record)
		},
		loadVerify: func(string) (*verify.Config, error) {
			t.Fatal("loadVerify should not run for sandbox verification")
			return nil, nil
		},
		runVerify: func(context.Context, *verify.Config) (*verify.Result, error) {
			t.Fatal("runVerify should not run for sandbox verification")
			return nil, nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, args []string, out io.Writer) error {
			command := strings.Join(args, " ")
			if strings.Contains(command, "'hal' 'verify' '--json'") {
				data, err := json.Marshal(verify.Result{
					SchemaVersion: verify.SchemaVersion,
					Status:        verify.StatusFail,
					Summary: verify.Summary{
						Total:  1,
						Failed: 1,
					},
					Checks: []verify.CheckResult{{
						ID:       "remote-test",
						Name:     "Remote tests",
						Status:   verify.CheckStatusFail,
						Required: true,
					}},
				})
				if err != nil {
					t.Fatalf("Marshal(verify result) error: %v", err)
				}
				if _, err := out.Write(append(data, '\n')); err != nil {
					t.Fatalf("write remote verify JSON error: %v", err)
				}
				return errors.New("remote verify exited 1")
			}
			if strings.Contains(command, "base64 < '/workspace/hal/.hal/auto-state.json'") {
				return errors.New("copy sandbox artifact failed")
			}
			t.Fatalf("unexpected provider exec args = %#v", args)
			return nil
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
			cleanupCalls++
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
			return []factory.SandboxArtifactRequest{{
				ID:         "sandbox-auto-state",
				Name:       "sandbox-auto-state",
				Type:       "json",
				RemotePath: "/workspace/hal/.hal/auto-state.json",
				Path:       ".hal/auto-state.json",
			}}
		},
	})
	if err == nil {
		t.Fatal("runFactoryRunWithDeps() error = nil, want verification and artifact-copy errors")
	}
	for _, want := range []string{"verification failed", "collect sandbox factory artifacts before cleanup", "copy sandbox artifact failed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("runFactoryRunWithDeps() error = %q, want %q", err.Error(), want)
		}
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup calls = %d, want 1 for always cleanup after verification failure", cleanupCalls)
	}
	record, err := store.LoadRun("run-sandbox-always-cleanup-copy-error")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want failed", record.Status)
	}
	if record.Sandbox == nil || record.Sandbox.Status != sandbox.StatusUnknown {
		t.Fatalf("sandbox metadata = %#v, want cleaned unknown status despite artifact-copy error", record.Sandbox)
	}
	if record.Sandbox.Connection != nil || record.Sandbox.SSHCommand != "" || record.Sandbox.CleanupCommand != "" || record.Sandbox.Handoff != "" {
		t.Fatalf("sandbox handoff metadata = %#v, want cleared after cleanup", record.Sandbox)
	}
}

func TestRunFactoryRunWithDepsBlocksRequiredSandboxVerificationWithNoRemoteChecks(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 6, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	missingAt := createdAt.Add(4 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, missingAt}
	policy := factory.DefaultFactoryPolicy()
	policy.CleanupBehavior = factory.CleanupBehaviorOnSuccess
	policy.VerificationRequired = true
	target := &sandbox.SandboxState{
		Name:     "factory-no-remote-checks",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
	var cleanupCalls int

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
		Sandbox:      true,
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-sandbox-no-remote-checks", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return missingAt
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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		runSandbox: func(_ context.Context, req factorySandboxExecutorRequest) error {
			if !req.DeferSuccessCleanup {
				t.Fatal("DeferSuccessCleanup = false, want true for on_success cleanup with required verification")
			}
			record := req.RunRecord
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = target.Name
			record.Sandbox = &factory.SandboxMetadata{Name: target.Name, Provider: target.Provider, Status: target.Status}
			return store.SaveRun(&record)
		},
		loadVerify: func(string) (*verify.Config, error) {
			t.Fatal("loadVerify should not run for sandbox verification")
			return nil, nil
		},
		runVerify: func(context.Context, *verify.Config) (*verify.Result, error) {
			t.Fatal("runVerify should not run for sandbox verification")
			return nil, nil
		},
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			data, err := json.Marshal(verify.Result{
				SchemaVersion: verify.SchemaVersion,
				Status:        verify.StatusPass,
				Summary:       verify.Summary{},
				Checks:        []verify.CheckResult{},
			})
			if err != nil {
				t.Fatalf("Marshal(verify result) error: %v", err)
			}
			if _, err := out.Write(append(data, '\n')); err != nil {
				t.Fatalf("write remote verify JSON error: %v", err)
			}
			return nil
		},
		cleanupSandbox: func(context.Context, factorySandboxCleanupRequest) error {
			cleanupCalls++
			return nil
		},
		statusSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
		doctorSnapshot: func(string) (factorySnapshotArtifact, error) { return factorySnapshotArtifact{}, nil },
	})
	if err == nil || !strings.Contains(err.Error(), "verification required but no checks configured") {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want missing verification gate failure", err)
	}
	if cleanupCalls != 0 {
		t.Fatalf("cleanup calls = %d, want 0 when required verification has no checks", cleanupCalls)
	}
	record, err := store.LoadRun("run-sandbox-no-remote-checks")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want failed", record.Status)
	}
	if record.Verification != nil {
		t.Fatalf("verification = %#v, want nil for no configured checks", record.Verification)
	}
	if record.Failure == nil || record.Failure.Step != "verify" {
		t.Fatalf("failure = %#v, want verify failure", record.Failure)
	}
}

func TestRunFactoryRunWithDepsBlocksWhenVerificationRequiredAndMissing(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 5, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	missingAt := createdAt.Add(4 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, missingAt}
	policy := factory.DefaultFactoryPolicy()
	policy.VerificationRequired = true

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-verification-missing", nil },
		now: func() time.Time {
			if len(times) == 0 {
				return missingAt
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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
		},
		runPipeline: func(_ context.Context, req factoryRunPipelineRequest) error {
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			return nil
		},
		loadVerify: func(string) (*verify.Config, error) {
			record, err := store.LoadRun("run-verification-missing")
			if err != nil {
				t.Fatalf("LoadRun() during verification error: %v", err)
			}
			if record.CurrentStep != "verify" {
				t.Fatalf("currentStep during verification = %q, want verify", record.CurrentStep)
			}
			if !record.UpdatedAt.Equal(verifyingAt) {
				t.Fatalf("updatedAt during verification = %s, want %s", record.UpdatedAt, verifyingAt)
			}
			return nil, nil
		},
		runVerify: func(context.Context, *verify.Config) (*verify.Result, error) {
			t.Fatal("runVerify should not be called when no verification config is available")
			return nil, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "verification required but no checks configured") {
		t.Fatalf("runFactoryRunWithDeps() error = %v, want missing verification gate failure", err)
	}

	record, err := store.LoadRun("run-verification-missing")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusFailed {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusFailed)
	}
	if record.Verification != nil {
		t.Fatalf("verification = %#v, want nil", record.Verification)
	}
	if record.Failure == nil {
		t.Fatal("failure summary should be persisted")
	}
	if record.Failure.Step != "verify" {
		t.Fatalf("failure step = %q, want verify", record.Failure.Step)
	}
	if record.Failure.Category != factory.FailureCategoryVerification {
		t.Fatalf("failure category = %q, want %q", record.Failure.Category, factory.FailureCategoryVerification)
	}
	if record.FinishedAt == nil || !record.FinishedAt.Equal(missingAt) {
		t.Fatalf("finishedAt = %v, want %s", record.FinishedAt, missingAt)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeStepEnded,
		factory.EventTypePolicyDecision,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	if events[2].Metadata["step"] != factory.RunDurationStepEngineRun {
		t.Fatalf("pipeline completion event step = %#v, want %q", events[2].Metadata["step"], factory.RunDurationStepEngineRun)
	}
	assertPolicyDecisionMetadata(t, events[3].Metadata, factory.PolicyDecisionMetadata{
		PolicyField: "factory.policy.verificationRequired",
		Decision:    factory.PolicyDecisionBlockedGate,
		Outcome:     factory.PolicyOutcomeBlocked,
		Reason:      "verification required but no checks configured",
	})
	if !events[3].Timestamp.Equal(missingAt) {
		t.Fatalf("policy event timestamp = %s, want %s", events[3].Timestamp, missingAt)
	}
	if events[4].Metadata["step"] != factory.RunDurationStepVerification {
		t.Fatalf("verification failure event step = %#v, want %q", events[4].Metadata["step"], factory.RunDurationStepVerification)
	}
	if events[4].Metadata["status"] != factory.RunStatusFailed {
		t.Fatalf("verification failure event status = %#v, want %q", events[4].Metadata["status"], factory.RunStatusFailed)
	}
	if got, ok := events[4].Metadata["error"].(string); !ok || !strings.Contains(got, "verification required") {
		t.Fatalf("verification failure event error = %#v, want verification required", events[4].Metadata["error"])
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
	policy := factory.DefaultFactoryPolicy()
	policy.VerificationRequired = true

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
		loadPolicy: func(string) (*factory.FactoryPolicy, error) {
			return &policy, nil
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
	if record.Failure.Category != factory.FailureCategoryVerification {
		t.Fatalf("failure category = %q, want %q", record.Failure.Category, factory.FailureCategoryVerification)
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
		factory.EventTypeStepEnded,
		factory.EventTypeStepStarted,
		factory.EventTypeVerificationResult,
		factory.EventTypePolicyDecision,
		factory.EventTypeStepEnded,
		factory.EventTypeFailureClassification,
	})
	if events[3].Metadata["step"] != factory.RunDurationStepVerification {
		t.Fatalf("verification start event step = %#v, want %q", events[3].Metadata["step"], factory.RunDurationStepVerification)
	}
	if !events[4].Timestamp.Equal(verifiedAt) {
		t.Fatalf("verification result timestamp = %s, want %s", events[4].Timestamp, verifiedAt)
	}
	if events[4].Metadata["status"] != verify.StatusFail {
		t.Fatalf("verification result status = %#v, want %q", events[4].Metadata["status"], verify.StatusFail)
	}
	assertPolicyDecisionMetadata(t, events[5].Metadata, factory.PolicyDecisionMetadata{
		PolicyField: "factory.policy.verificationRequired",
		Decision:    factory.PolicyDecisionBlockedGate,
		Outcome:     factory.PolicyOutcomeBlocked,
		Reason:      "verification failed",
	})
	if events[6].Metadata["step"] != factory.RunDurationStepVerification {
		t.Fatalf("verification failure event step = %#v, want %q", events[6].Metadata["step"], factory.RunDurationStepVerification)
	}
	if events[6].Metadata["status"] != factory.RunStatusFailed {
		t.Fatalf("verification failure event status = %#v, want %q", events[6].Metadata["status"], factory.RunStatusFailed)
	}
	if !events[6].Timestamp.Equal(verifiedAt) {
		t.Fatalf("verification failure timestamp = %s, want %s", events[6].Timestamp, verifiedAt)
	}
	if got, ok := events[6].Metadata["error"].(string); !ok || !strings.Contains(got, "verification failed") {
		t.Fatalf("verification failure event error = %#v, want verification failure", events[6].Metadata["error"])
	}
	telemetry := factory.DeriveRunTelemetry(*record, events)
	if telemetry == nil || len(telemetry.StepDurations) != 2 {
		t.Fatalf("derived telemetry stepDurations = %#v, want engine and verification durations", telemetry)
	}
}

func TestRunFactoryRunWithDepsTreatsVerificationFailureAsAdvisoryByDefault(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(halDir) error: %v", err)
	}
	writeFile(t, halDir, "prd-feature.md", "# PRD: Feature\n")

	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 1, 20, 0, 0, time.UTC)
	startedAt := createdAt.Add(1 * time.Minute)
	artifactAt := createdAt.Add(2 * time.Minute)
	verifyingAt := createdAt.Add(3 * time.Minute)
	verifiedAt := createdAt.Add(4 * time.Minute)
	times := []time.Time{createdAt, startedAt, artifactAt, verifyingAt, verifiedAt}

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
	}, io.Discard, factoryRunDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		newRunID:     func() (string, error) { return "run-verification-advisory", nil },
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
				Status: verify.StatusFail,
				Summary: verify.Summary{
					Total:  1,
					Failed: 1,
				},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunWithDeps() unexpected error: %v", err)
	}

	record, err := store.LoadRun("run-verification-advisory")
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	if record.Status != factory.RunStatusSucceeded {
		t.Fatalf("status = %q, want %q", record.Status, factory.RunStatusSucceeded)
	}
	if record.Verification == nil || record.Verification.Summary.Failed != 1 {
		t.Fatalf("verification = %#v", record.Verification)
	}
	if record.Failure != nil {
		t.Fatalf("failure = %#v, want nil", record.Failure)
	}

	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error: %v", err)
	}
	assertFactoryEventTypes(t, events, []string{
		factory.EventTypeRunCreated,
		factory.EventTypeStepStarted,
		factory.EventTypeStepEnded,
		factory.EventTypeStepStarted,
		factory.EventTypeVerificationResult,
		factory.EventTypePolicyDecision,
		factory.EventTypeStepEnded,
	})
	if events[4].Metadata["status"] != verify.StatusFail {
		t.Fatalf("verification result status = %#v, want %q", events[4].Metadata["status"], verify.StatusFail)
	}
	assertPolicyDecisionMetadata(t, events[5].Metadata, factory.PolicyDecisionMetadata{
		PolicyField: "factory.policy.verificationRequired",
		Decision:    factory.PolicyDecisionAllowedExecution,
		Outcome:     factory.PolicyOutcomeAllowed,
		Reason:      "verification not required; advisory failure did not block",
	})
	if events[6].Metadata["step"] != factory.RunDurationStepVerification {
		t.Fatalf("advisory verification failure event step = %#v, want %q", events[6].Metadata["step"], factory.RunDurationStepVerification)
	}
	if events[6].Metadata["status"] != factory.RunStatusFailed {
		t.Fatalf("advisory verification failure event status = %#v, want %q", events[6].Metadata["status"], factory.RunStatusFailed)
	}
	if events[6].Metadata["advisory"] != true {
		t.Fatalf("advisory verification failure event advisory = %#v, want true", events[6].Metadata["advisory"])
	}
	if events[6].Metadata["blocking"] != false {
		t.Fatalf("advisory verification failure event blocking = %#v, want false", events[6].Metadata["blocking"])
	}
	if got, ok := events[6].Metadata["error"].(string); !ok || !strings.Contains(got, "verification failed") {
		t.Fatalf("advisory verification failure event error = %#v, want verification failure", events[6].Metadata["error"])
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
	target := &sandbox.SandboxState{
		Name:     "factory-remote",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "203.0.113.42",
	}
	var buf bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
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
			record.SandboxName = target.Name
			record.Sandbox = &factory.SandboxMetadata{
				Name:           target.Name,
				Provider:       target.Provider,
				Status:         target.Status,
				Connection:     &factory.SandboxConnectionMetadata{PublicIP: target.IP},
				SSHCommand:     "hal sandbox ssh " + target.Name,
				CleanupCommand: "hal sandbox delete " + target.Name,
				Handoff:        "Inspect sandbox with `hal sandbox ssh " + target.Name + "`.",
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
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			data, err := json.Marshal(verify.Result{
				SchemaVersion: verify.SchemaVersion,
				Status:        verify.StatusPass,
				Summary:       verify.Summary{},
				Checks:        []verify.CheckResult{},
			})
			if err != nil {
				t.Fatalf("Marshal(verify result) error: %v", err)
			}
			if _, err := out.Write(append(data, '\n')); err != nil {
				t.Fatalf("write remote verify JSON error: %v", err)
			}
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
	target := &sandbox.SandboxState{
		Name:     "factory-json",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
		IP:       "127.0.0.1",
	}
	var buf bytes.Buffer

	err := runFactoryRunWithDeps(context.Background(), dir, factoryRunRequest{
		MarkdownPath: ".hal/prd-feature.md",
		BaseBranch:   "main",
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
			record := req.RunRecord
			record.ExecutorMode = factory.ExecutorModeSandbox
			record.SandboxName = target.Name
			record.Sandbox = &factory.SandboxMetadata{Name: target.Name, Provider: target.Provider, Status: target.Status}
			if err := store.SaveRun(&record); err != nil {
				return err
			}
			writeFile(t, halDir, "prd.json", `{"project":"factory"}`)
			return nil
		},
		loadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loadSandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
		resolveProvider: func(string, string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		runProviderExec: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, out io.Writer) error {
			data, err := json.Marshal(verify.Result{
				SchemaVersion: verify.SchemaVersion,
				Status:        verify.StatusPass,
				Summary:       verify.Summary{},
				Checks:        []verify.CheckResult{},
			})
			if err != nil {
				t.Fatalf("Marshal(verify result) error: %v", err)
			}
			if _, err := out.Write(append(data, '\n')); err != nil {
				t.Fatalf("write remote verify JSON error: %v", err)
			}
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
		BaseBranch:   "main",
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
				Category:         factory.FailureCategoryRun,
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
			if resp.Failure.Classification != "ci" {
				t.Fatalf("failure.classification = %q, want %q", resp.Failure.Classification, "ci")
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

func TestRenderFactoryStatusTelemetryPreservesLegacyFailureCategory(t *testing.T) {
	tests := []string{"validation", "pipeline", "git", "ci"}

	for _, category := range tests {
		category := category
		t.Run(category, func(t *testing.T) {
			var buf bytes.Buffer
			renderFactoryStatusTelemetry(&buf, factory.RunRecord{
				RunID: "run-legacy-failure",
				Failure: &factory.FailureSummary{
					Category: category,
					Message:  "failed",
				},
			}, nil)

			output := buf.String()
			if !strings.Contains(output, "Failure category: "+category+"\n") {
				t.Fatalf("legacy failure category not preserved in output:\n%s", output)
			}
			if strings.Contains(output, "Failure category: "+factory.FailureCategoryUnknown+"\n") {
				t.Fatalf("legacy failure category rendered as unknown:\n%s", output)
			}
		})
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
	if record.Failure.Category != factory.FailureCategoryRun {
		t.Fatalf("failure category = %q, want %q", record.Failure.Category, factory.FailureCategoryRun)
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
			want: factory.FailureCategoryPRD,
		},
		{
			name: "validate step",
			err:  errors.New("step validate failed: invalid PRD"),
			want: factory.FailureCategoryPRD,
		},
		{
			name: "policy limit validate step",
			err: &compound.PolicyLimitError{
				PolicyField: "factory.policy.maxValidationFixAttempts",
				Step:        compound.StepValidate,
				Attempts:    1,
				Limit:       1,
			},
			want: factory.FailureCategoryPRD,
		},
		{
			name: "policy limit run step",
			err: &compound.PolicyLimitError{
				PolicyField: "factory.policy.maxRunAttempts",
				Step:        compound.StepRun,
				Attempts:    1,
				Limit:       1,
			},
			want: factory.FailureCategoryRun,
		},
		{
			name: "policy limit review step",
			err: &compound.PolicyLimitError{
				PolicyField: "factory.policy.maxReviewFixAttempts",
				Step:        compound.StepReview,
				Attempts:    1,
				Limit:       1,
			},
			want: factory.FailureCategoryReview,
		},
		{
			name: "policy limit ci step",
			err: &compound.PolicyLimitError{
				PolicyField: "factory.policy.maxCiFixAttempts",
				Step:        compound.StepCI,
				Attempts:    1,
				Limit:       1,
			},
			want: factory.FailureCategoryCI,
		},
		{
			name: "ci step",
			err:  errors.New("step ci failed: workflow failed"),
			want: factory.FailureCategoryCI,
		},
		{
			name: "branch step",
			err:  errors.New("step branch failed: git checkout failed"),
			want: factory.FailureCategorySetup,
		},
		{
			name: "engine message",
			err:  errors.New("failed to create engine: codex unavailable"),
			want: factory.FailureCategoryEngine,
		},
		{
			name: "pipeline message",
			err:  errors.New("pipeline failed"),
			want: factory.FailureCategoryRun,
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

func TestNewFactoryRunFailureNormalizesClassification(t *testing.T) {
	tests := []struct {
		category string
		want     string
	}{
		{category: factory.FailureCategorySetup, want: "git"},
		{category: factory.FailureCategoryEngine, want: "engine"},
		{category: factory.FailureCategoryPRD, want: "validation"},
		{category: factory.FailureCategoryRun, want: "pipeline"},
		{category: factory.FailureCategoryReview, want: "pipeline"},
		{category: factory.FailureCategoryVerification, want: "validation"},
		{category: factory.FailureCategoryCI, want: "ci"},
		{category: factory.FailureCategorySandbox, want: "pipeline"},
		{category: factory.FailureCategoryQueue, want: "pipeline"},
		{category: factory.FailureCategoryUnknown, want: factory.FailureCategoryUnknown},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.category, func(t *testing.T) {
			record := factory.RunRecord{
				RunID: "run-normalize-category",
				Failure: &factory.FailureSummary{
					Category: tt.category,
					Message:  "failed",
				},
			}

			failure := newFactoryRunFailure(record)
			if failure == nil {
				t.Fatal("newFactoryRunFailure() = nil, want failure")
			}
			if failure.Classification != tt.want {
				t.Fatalf("classification = %q, want %q", failure.Classification, tt.want)
			}
		})
	}

	invalidTests := []struct {
		name     string
		category string
	}{
		{name: "empty", category: ""},
		{name: "invalid", category: "database"},
	}

	for _, tt := range invalidTests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			record := factory.RunRecord{
				RunID: "run-normalize-category",
				Failure: &factory.FailureSummary{
					Category: tt.category,
					Message:  "failed",
				},
			}

			failure := newFactoryRunFailure(record)
			if failure == nil {
				t.Fatal("newFactoryRunFailure() = nil, want failure")
			}
			if failure.Classification != factory.FailureCategoryUnknown {
				t.Fatalf("classification = %q, want %q", failure.Classification, factory.FailureCategoryUnknown)
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
		Engine: " claude ",
		AttemptPolicy: autoFactoryAttemptPolicy{
			MaxRunAttempts:       1,
			MaxReviewFixAttempts: 2,
			MaxCIFixAttempts:     3,
		},
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
		Engine:     "claude",
		AttemptPolicy: autoFactoryAttemptPolicy{
			MaxRunAttempts:       1,
			MaxReviewFixAttempts: 2,
			MaxCIFixAttempts:     3,
		},
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

func TestFactoryRunAutoCommandMarksProvidedEngineExplicit(t *testing.T) {
	cmd, err := factoryRunAutoCommand(context.Background(), factoryRunAutoRequest{
		Engine: " claude ",
	})
	if err != nil {
		t.Fatalf("factoryRunAutoCommand() unexpected error: %v", err)
	}

	value, err := cmd.Flags().GetString("engine")
	if err != nil {
		t.Fatalf("engine flag lookup failed: %v", err)
	}
	if value != factory.PolicyEngineClaude {
		t.Fatalf("engine flag = %q, want %q", value, factory.PolicyEngineClaude)
	}
	if !cmd.Flags().Changed("engine") {
		t.Fatal("engine flag should be marked changed when factory supplies an engine snapshot")
	}
}

func TestFactoryRunAutoCommandKeepsEmptyEngineImplicit(t *testing.T) {
	cmd, err := factoryRunAutoCommand(context.Background(), factoryRunAutoRequest{})
	if err != nil {
		t.Fatalf("factoryRunAutoCommand() unexpected error: %v", err)
	}

	value, err := cmd.Flags().GetString("engine")
	if err != nil {
		t.Fatalf("engine flag lookup failed: %v", err)
	}
	if value != factory.PolicyEngineCodex {
		t.Fatalf("engine flag = %q, want %q", value, factory.PolicyEngineCodex)
	}
	if cmd.Flags().Changed("engine") {
		t.Fatal("engine flag should remain unchanged when factory has no engine snapshot")
	}
}

func TestRunFactoryRunPipelineWithDepsUsesInjectedClockForLogChunks(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	startedAt := time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(2 * time.Minute)
	times := []time.Time{startedAt, completedAt}

	err := runFactoryRunPipelineWithDeps(context.Background(), factoryRunPipelineRequest{
		RunID: "run-log-clock",
		Store: store,
		Now: func() time.Time {
			if len(times) == 0 {
				t.Fatal("unexpected clock call")
			}
			next := times[0]
			times = times[1:]
			return next
		},
	}, factoryRunPipelineDeps{
		runAuto: func(context.Context, factoryRunAutoRequest) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryRunPipelineWithDeps() unexpected error: %v", err)
	}

	chunks, err := store.LoadLogChunks("run-log-clock")
	if err != nil {
		t.Fatalf("LoadLogChunks() unexpected error: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("log chunks = %d, want 2: %#v", len(chunks), chunks)
	}
	if !chunks[0].CreatedAt.Equal(startedAt) {
		t.Fatalf("start chunk createdAt = %s, want %s", chunks[0].CreatedAt, startedAt)
	}
	if !chunks[1].CreatedAt.Equal(completedAt) {
		t.Fatalf("completion chunk createdAt = %s, want %s", chunks[1].CreatedAt, completedAt)
	}
}

func TestRunFactoryRunPipelineWithDepsUsesInjectedClockForFailureLogChunk(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	startedAt := time.Date(2026, 6, 21, 11, 5, 0, 0, time.UTC)
	failedAt := startedAt.Add(30 * time.Second)
	times := []time.Time{startedAt, failedAt}
	wantErr := errors.New("auto failed")

	err := runFactoryRunPipelineWithDeps(context.Background(), factoryRunPipelineRequest{
		RunID: "run-log-clock-failure",
		Store: store,
		Now: func() time.Time {
			if len(times) == 0 {
				t.Fatal("unexpected clock call")
			}
			next := times[0]
			times = times[1:]
			return next
		},
	}, factoryRunPipelineDeps{
		runAuto: func(context.Context, factoryRunAutoRequest) error {
			return wantErr
		},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("runFactoryRunPipelineWithDeps() error = %v, want %v", err, wantErr)
	}

	chunks, err := store.LoadLogChunks("run-log-clock-failure")
	if err != nil {
		t.Fatalf("LoadLogChunks() unexpected error: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("log chunks = %d, want 2: %#v", len(chunks), chunks)
	}
	if !chunks[0].CreatedAt.Equal(startedAt) {
		t.Fatalf("start chunk createdAt = %s, want %s", chunks[0].CreatedAt, startedAt)
	}
	if !chunks[1].CreatedAt.Equal(failedAt) {
		t.Fatalf("failure chunk createdAt = %s, want %s", chunks[1].CreatedAt, failedAt)
	}
}

func TestRunFactoryRunPipelineWithDepsRedactsResolvedSecretsFromFailureLogChunk(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	secretValue := "ghp_local_pipeline_secret_12345"
	wantErr := errors.New("auto failed with token " + secretValue)

	err := runFactoryRunPipelineWithDeps(context.Background(), factoryRunPipelineRequest{
		RunID: "run-log-secret-failure",
		Store: store,
		Request: factoryRunRequest{
			ResolvedSecrets: []factory.ResolvedRunSecret{{
				Name:     "GITHUB_TOKEN",
				Source:   factory.RunSecretSourceEnv,
				Required: true,
				Value:    secretValue,
			}},
		},
	}, factoryRunPipelineDeps{
		runAuto: func(context.Context, factoryRunAutoRequest) error {
			return wantErr
		},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("runFactoryRunPipelineWithDeps() error = %v, want %v", err, wantErr)
	}

	chunks, err := store.LoadLogChunks("run-log-secret-failure")
	if err != nil {
		t.Fatalf("LoadLogChunks() unexpected error: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("log chunks = %d, want 2: %#v", len(chunks), chunks)
	}
	if strings.Contains(chunks[1].Text, secretValue) {
		t.Fatalf("failure log chunk text contains secret: %q", chunks[1].Text)
	}
	if !strings.Contains(chunks[1].Text, factory.RunSecretRedactionPlaceholder) {
		t.Fatalf("failure log chunk text = %q, want redaction placeholder", chunks[1].Text)
	}
}

func TestRunFactoryRunPipelineWithDepsRedactsCredentialedRemoteFromFailureLogChunk(t *testing.T) {
	store := factory.NewStore(t.TempDir())
	credential := "ghp_local_remote_credential_12345"
	wantErr := errors.New("auto failed cloning https://x:" + credential + "@github.com/org/repo.git")

	err := runFactoryRunPipelineWithDeps(context.Background(), factoryRunPipelineRequest{
		RunID: "run-log-credentialed-remote-failure",
		Store: store,
	}, factoryRunPipelineDeps{
		runAuto: func(context.Context, factoryRunAutoRequest) error {
			return wantErr
		},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("runFactoryRunPipelineWithDeps() error = %v, want %v", err, wantErr)
	}

	chunks, err := store.LoadLogChunks("run-log-credentialed-remote-failure")
	if err != nil {
		t.Fatalf("LoadLogChunks() unexpected error: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("log chunks = %d, want 2: %#v", len(chunks), chunks)
	}
	if strings.Contains(chunks[1].Text, credential) {
		t.Fatalf("failure log chunk text contains credential: %q", chunks[1].Text)
	}
	if !strings.Contains(chunks[1].Text, "https://"+factory.RunSecretRedactionPlaceholder+"@github.com/org/repo.git") {
		t.Fatalf("failure log chunk text = %q, want credentialed remote redaction", chunks[1].Text)
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
	totalDurationMs := int64(720000)
	artifactCount := 2
	newer.SandboxName = "factory-sandbox"
	newer.Artifacts = []factory.ArtifactReference{
		{Name: "report", Type: "markdown", Path: ".hal/reports/run-new.md"},
		{Name: "log", Type: "text", Path: ".hal/reports/run-new.log"},
	}
	newer.Telemetry = &factory.RunTelemetry{
		TotalDurationMs: &totalDurationMs,
		Engine: &factory.EngineTelemetry{
			Name:  "codex",
			Model: "gpt-5",
		},
		Sandbox: &factory.RunSandboxTelemetry{
			Provider: "hetzner",
			Size:     "cx22",
		},
		CIOutcome:       "failed",
		ArtifactCount:   &artifactCount,
		FailureCategory: factory.FailureCategoryCI,
		StepDurations:   []factory.RunStepDuration{{Step: "run", StartedAt: base.Add(4 * time.Minute), FinishedAt: base.Add(5 * time.Minute), DurationMs: 60000}},
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
	if resp.Runs[0].Telemetry == nil || resp.Runs[0].Telemetry.TotalDurationMs == nil || *resp.Runs[0].Telemetry.TotalDurationMs != totalDurationMs {
		t.Fatalf("telemetry missing from first run: %#v", resp.Runs[0].Telemetry)
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
		"artifactCount", "telemetry", "failure",
	})
	telemetry, ok := first["telemetry"].(map[string]any)
	if !ok {
		t.Fatalf("factory list telemetry should be an object, got %T", first["telemetry"])
	}
	requireFactoryFields(t, "factory list telemetry", telemetry, []string{
		"totalDurationMs", "stepDurations", "engine", "sandbox",
		"ciOutcome", "artifactCount", "failureCategory",
	})
	for _, omitted := range []string{"artifacts", "events", "timeline"} {
		if _, ok := first[omitted]; ok {
			t.Fatalf("factory list summary should omit %q: %#v", omitted, first)
		}
	}
}

func TestRunFactoryListJSONDerivesTotalDuration(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	finishedAt := base.Add(9 * time.Minute)
	record := testFactoryRunRecord("run-list-derived-duration", base, finishedAt)
	record.Status = factory.RunStatusSucceeded
	record.FinishedAt = &finishedAt
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
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
	if len(resp.Runs) != 1 {
		t.Fatalf("runs len = %d, want 1", len(resp.Runs))
	}
	telemetry := resp.Runs[0].Telemetry
	if telemetry == nil || telemetry.TotalDurationMs == nil {
		t.Fatalf("telemetry = %#v, want derived total duration", telemetry)
	}
	if *telemetry.TotalDurationMs != finishedAt.Sub(base).Milliseconds() {
		t.Fatalf("totalDurationMs = %d, want %d", *telemetry.TotalDurationMs, finishedAt.Sub(base).Milliseconds())
	}
	if len(telemetry.StepDurations) != 0 {
		t.Fatalf("list telemetry stepDurations = %#v, want none without timeline load", telemetry.StepDurations)
	}
}

func TestRenderFactoryRunJSONLocksResultContract(t *testing.T) {
	base := time.Date(2026, 6, 20, 18, 30, 0, 0, time.UTC)
	totalDurationMs := int64(900000)
	artifactCount := 1
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
		Telemetry: &factory.RunTelemetry{
			TotalDurationMs: &totalDurationMs,
			StepDurations: []factory.RunStepDuration{
				{
					Step:       "ci",
					StartedAt:  base.Add(1 * time.Minute),
					FinishedAt: base.Add(2 * time.Minute),
					DurationMs: 60000,
				},
			},
			Engine: &factory.EngineTelemetry{
				Name:  "codex",
				Model: "gpt-5",
			},
			Sandbox: &factory.RunSandboxTelemetry{
				Provider: "digitalocean",
				Size:     "s-2vcpu-4gb",
			},
			EstimatedSandboxCost: &factory.SandboxCostEstimate{
				AmountUSD: 0.12,
				Estimated: true,
			},
			CIOutcome:           "failed",
			VerificationOutcome: "passed",
			ArtifactCount:       &artifactCount,
			FailureCategory:     factory.FailureCategoryCI,
		},
		Failure: &FactoryRunFailure{
			Classification:   factory.FailureCategoryCI,
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
		"artifacts", "telemetry", "eventSummary", "failure",
	})

	nextAction, ok := raw["nextAction"].(map[string]any)
	if !ok {
		t.Fatalf("nextAction should be an object, got %T", raw["nextAction"])
	}
	requireExactKeys(t, nextAction, []string{"id", "command", "description"})

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

	telemetry, ok := raw["telemetry"].(map[string]any)
	if !ok {
		t.Fatalf("telemetry should be an object, got %T", raw["telemetry"])
	}
	requireFactoryFields(t, "factory run telemetry", telemetry, []string{
		"totalDurationMs", "stepDurations", "engine", "sandbox",
		"estimatedSandboxCost", "ciOutcome", "verificationOutcome",
		"artifactCount", "failureCategory",
	})

	failure, ok := raw["failure"].(map[string]any)
	if !ok {
		t.Fatalf("failure should be an object, got %T", raw["failure"])
	}
	requireFactoryFields(t, "factory run failure", failure, []string{"classification", "errorMessage", "suggestedCommand"})
}

func TestNewFactoryRunResponseDerivesTelemetryDurations(t *testing.T) {
	base := time.Date(2026, 6, 21, 13, 0, 0, 0, time.UTC)
	finishedAt := base.Add(15 * time.Minute)
	record := testFactoryRunRecord("run-result-derived-duration", base, finishedAt)
	record.Status = factory.RunStatusSucceeded
	record.FinishedAt = &finishedAt
	events := []factory.EventRecord{
		{
			Sequence:  1,
			RunID:     record.RunID,
			EventType: factory.EventTypeStepStarted,
			Timestamp: base.Add(2 * time.Minute),
			Metadata:  map[string]any{"step": factory.RunDurationStepEngineRun},
		},
		{
			Sequence:  2,
			RunID:     record.RunID,
			EventType: factory.EventTypeStepEnded,
			Timestamp: base.Add(7 * time.Minute),
			Metadata:  map[string]any{"step": factory.RunDurationStepEngineRun},
		},
		{
			Sequence:  3,
			RunID:     record.RunID,
			EventType: factory.EventTypeStepEnded,
			Timestamp: base.Add(8 * time.Minute),
			Metadata:  map[string]any{"step": "run"},
		},
	}

	resp := newFactoryRunResponse(record, events)
	if resp.Telemetry == nil || resp.Telemetry.TotalDurationMs == nil {
		t.Fatalf("telemetry = %#v, want derived durations", resp.Telemetry)
	}
	if *resp.Telemetry.TotalDurationMs != finishedAt.Sub(base).Milliseconds() {
		t.Fatalf("totalDurationMs = %d, want %d", *resp.Telemetry.TotalDurationMs, finishedAt.Sub(base).Milliseconds())
	}
	if len(resp.Telemetry.StepDurations) != 1 {
		t.Fatalf("stepDurations len = %d, want 1: %#v", len(resp.Telemetry.StepDurations), resp.Telemetry.StepDurations)
	}
	duration := resp.Telemetry.StepDurations[0]
	if duration.Step != factory.RunDurationStepEngineRun {
		t.Fatalf("step = %q, want %q", duration.Step, factory.RunDurationStepEngineRun)
	}
	if duration.DurationMs != 300000 {
		t.Fatalf("durationMs = %d, want 300000", duration.DurationMs)
	}
}

func TestNewFactoryRunNextActionUsesInspectCommandForSandboxFailures(t *testing.T) {
	record := factory.RunRecord{
		RunID:        "run-handoff",
		Status:       factory.RunStatusFailed,
		ExecutorMode: factory.ExecutorModeSandbox,
		RepoPath:     "/workspace/hal",
		BranchName:   "hal/factory-handoff",
		SandboxName:  "fallback-sandbox",
		Sandbox: &factory.SandboxMetadata{
			Name:       "factory-handoff",
			Provider:   "daytona",
			Status:     sandbox.StatusRunning,
			SSHCommand: "ssh root@203.0.113.10",
			Connection: &factory.SandboxConnectionMetadata{
				Address:           "100.64.0.10",
				PublicIP:          "203.0.113.10",
				TailscaleIP:       "100.64.0.10",
				TailscaleHostname: "factory-handoff.tailnet.ts.net",
			},
		},
		CurrentStep: "ci",
		Artifacts: []factory.ArtifactReference{
			{
				Name:       "prd",
				Type:       "json",
				Path:       ".hal/prd.json",
				StoredPath: "artifacts/run-handoff/hal-prd.json",
			},
			{
				Name:       "ci-log",
				Type:       "text",
				Path:       ".hal/reports/ci-output.log",
				StoredPath: "artifacts/run-handoff/hal-reports-ci-output.log",
			},
			{
				Name: "pr-outcome",
				Type: "json",
				Path: "factory/pr-outcome.json",
				Summary: map[string]any{
					"pullRequestUrl": "https://github.com/jywlabs/hal/pull/42",
				},
			},
		},
		Failure: &factory.FailureSummary{
			Step:    "ci",
			Message: "unit tests failed",
		},
	}

	action := newFactoryRunNextAction(record)
	if action == nil {
		t.Fatal("next action should be present")
	}
	if action.ID != "inspect_factory_run" {
		t.Fatalf("id = %q, want inspect_factory_run", action.ID)
	}
	if action.Command != "hal factory status run-handoff --json" {
		t.Fatalf("command = %q", action.Command)
	}

	data, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	raw := parseFactoryJSON(t, data)
	requireExactKeys(t, raw, []string{"id", "command", "description"})
	for _, forbidden := range []string{"203.0.113.10", "100.64.0.10", "tailnet.ts.net", "root@"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("nextAction should not expose %q: %s", forbidden, string(data))
		}
	}
}

func TestNewFactoryRunNextActionDoesNotExposeFailureReason(t *testing.T) {
	action := newFactoryRunNextAction(factory.RunRecord{
		RunID:        "run-sensitive-handoff",
		Status:       factory.RunStatusFailed,
		ExecutorMode: factory.ExecutorModeSandbox,
		SandboxName:  "factory-handoff",
		Failure: &factory.FailureSummary{
			Step:    "ci",
			Message: "remote failed at 203.0.113.10 with token=secret-value",
		},
	})

	if action == nil {
		t.Fatal("next action should be present")
	}
	data, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	raw := parseFactoryJSON(t, data)
	requireExactKeys(t, raw, []string{"id", "command", "description"})
	for _, forbidden := range []string{"203.0.113.10", "token=secret-value", "remote failed"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("nextAction should not expose %q: %s", forbidden, string(data))
		}
	}
}

func TestNewFactoryRunNextActionRejectsUnsafeCommandInputs(t *testing.T) {
	action := newFactoryRunNextAction(factory.RunRecord{
		RunID:        "run-handoff",
		Status:       factory.RunStatusFailed,
		ExecutorMode: factory.ExecutorModeSandbox,
		SandboxName:  "factory;rm",
		Failure: &factory.FailureSummary{
			Message: "remote execution failed",
		},
	})
	if action == nil {
		t.Fatal("next action should fall back to inspect")
	}
	if action.ID != "inspect_factory_run" || action.Command != "hal factory status run-handoff --json" {
		t.Fatalf("action = %#v, want inspect fallback", action)
	}

	action = newFactoryRunNextAction(factory.RunRecord{
		RunID:  "run;rm",
		Status: factory.RunStatusSucceeded,
	})
	if action != nil {
		t.Fatalf("next action = %#v, want nil for unsafe run ID", action)
	}
}

func TestNewFactoryRunNextActionFallsBackToInspectWhenSandboxNotRunning(t *testing.T) {
	action := newFactoryRunNextAction(factory.RunRecord{
		RunID:        "run-stopped-sandbox",
		Status:       factory.RunStatusFailed,
		ExecutorMode: factory.ExecutorModeSandbox,
		SandboxName:  "factory-handoff",
		Sandbox: &factory.SandboxMetadata{
			Name:   "factory-handoff",
			Status: sandbox.StatusStopped,
		},
		Failure: &factory.FailureSummary{
			Message: "remote execution failed",
		},
	})
	if action == nil {
		t.Fatal("next action should be present")
	}
	if action.ID != "inspect_factory_run" || action.Command != "hal factory status run-stopped-sandbox --json" {
		t.Fatalf("action = %#v, want inspect fallback", action)
	}
}

func TestNewFactoryRunNextActionUsesCompletedDescriptionForSucceededRuns(t *testing.T) {
	action := newFactoryRunNextAction(factory.RunRecord{
		RunID:       "run-complete",
		Status:      factory.RunStatusSucceeded,
		CurrentStep: "done",
	})
	if action == nil {
		t.Fatal("next action should be present")
	}
	if action.ID != "inspect_factory_run" {
		t.Fatalf("id = %q, want inspect_factory_run", action.ID)
	}
	if action.Command != "hal factory status run-complete --json" {
		t.Fatalf("command = %q", action.Command)
	}
	if action.Description != "Inspect the completed durable run record and timeline." {
		t.Fatalf("description = %q", action.Description)
	}
}

func TestNewFactoryRunNextActionDoesNotExposeArtifactLocations(t *testing.T) {
	action := newFactoryRunNextAction(factory.RunRecord{
		RunID:  "run-url-locations",
		Status: factory.RunStatusFailed,
		Artifacts: []factory.ArtifactReference{
			{
				Name:       "report",
				Type:       "json",
				Path:       "http://192.0.2.42/report.json?token=secret",
				StoredPath: "artifacts/run-url-locations/report.json",
			},
			{
				Name:       "stderr-log",
				Type:       "text",
				Path:       "https://example.com/stderr.log?api_key=secret",
				StoredPath: "artifacts/run-url-locations/stderr.log",
			},
		},
	})
	if action == nil {
		t.Fatal("next action should be present")
	}

	data, err := json.Marshal(action)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	raw := parseFactoryJSON(t, data)
	requireExactKeys(t, raw, []string{"id", "command", "description"})
	for _, forbidden := range []string{"192.0.2.42", "token=secret", "api_key=secret", "https://example.com"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("nextAction should not expose %q: %s", forbidden, string(data))
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

func TestRunFactoryStatusJSONIncludesRunAndOrderedTimeline(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 20, 17, 0, 0, 0, time.UTC)
	finishedAt := base.Add(20 * time.Minute)
	totalDurationMs := int64(finishedAt.Sub(base).Milliseconds())
	artifactCount := 2
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
			URL:  "http://192.0.2.42/pull/1",
		},
	}
	record.Telemetry = &factory.RunTelemetry{
		TotalDurationMs: &totalDurationMs,
		StepDurations: []factory.RunStepDuration{
			{
				Step:       "run",
				StartedAt:  base.Add(1 * time.Minute),
				FinishedAt: base.Add(3 * time.Minute),
				DurationMs: 120000,
			},
		},
		Engine: &factory.EngineTelemetry{
			Name:  "codex",
			Model: "gpt-5",
		},
		Sandbox: &factory.RunSandboxTelemetry{
			Provider: "daytona",
			Size:     "medium",
		},
		EstimatedSandboxCost: &factory.SandboxCostEstimate{
			AmountUSD: 0.42,
			Estimated: true,
		},
		CIOutcome:           "skipped",
		VerificationOutcome: "passed",
		ArtifactCount:       &artifactCount,
		FailureCategory:     factory.FailureCategoryReview,
	}
	record.Failure = &factory.FailureSummary{
		Step:     "review",
		Category: factory.FailureCategoryReview,
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
	if len(resp.Run.Artifacts) != 2 {
		t.Fatalf("run.artifacts len = %d, want 2", len(resp.Run.Artifacts))
	}
	if resp.Run.Telemetry == nil || resp.Run.Telemetry.Engine == nil || resp.Run.Telemetry.Engine.Name != "codex" {
		t.Fatalf("run.telemetry = %#v, want engine metadata", resp.Run.Telemetry)
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
		"finishedAt", "artifacts", "telemetry", "failure",
	})
	telemetry, ok := run["telemetry"].(map[string]any)
	if !ok {
		t.Fatalf("run.telemetry should be an object, got %T", run["telemetry"])
	}
	requireFactoryFields(t, "factory status telemetry", telemetry, []string{
		"totalDurationMs", "stepDurations", "engine", "sandbox",
		"estimatedSandboxCost", "ciOutcome", "verificationOutcome",
		"artifactCount", "failureCategory",
	})
	if _, ok := run["handoff"]; ok {
		t.Fatalf("run.handoff should be omitted when there is no actionable handoff: %#v", run["handoff"])
	}
	artifacts, ok := run["artifacts"].([]any)
	if !ok || len(artifacts) != 2 {
		t.Fatalf("run.artifacts should be an array of 2, got %T len %d", run["artifacts"], len(resp.Run.Artifacts))
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
	if _, ok := secondArtifact["url"]; ok {
		t.Fatalf("status artifact should not expose url: %#v", secondArtifact)
	}
	if secondArtifact["path"] != "[redacted]" {
		t.Fatalf("url-only status artifact path = %v, want [redacted]", secondArtifact["path"])
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

func TestRunFactoryStatusJSONDerivesTelemetryDurations(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 14, 0, 0, 0, time.UTC)
	finishedAt := base.Add(30 * time.Minute)
	record := testFactoryRunRecord("run-status-derived-duration", base, base.Add(12*time.Minute))
	record.Status = factory.RunStatusSucceeded
	record.FinishedAt = &finishedAt
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	events := []factory.EventRecord{
		{
			Sequence:  1,
			RunID:     record.RunID,
			EventType: factory.EventTypeStepStarted,
			Timestamp: base.Add(4 * time.Minute),
			Metadata:  map[string]any{"step": factory.RunDurationStepVerification},
		},
		{
			Sequence:  2,
			RunID:     record.RunID,
			EventType: factory.EventTypeStepEnded,
			Timestamp: base.Add(6 * time.Minute),
			Metadata:  map[string]any{"step": factory.RunDurationStepVerification},
		},
		{
			Sequence:  3,
			RunID:     record.RunID,
			EventType: factory.EventTypeStepStarted,
			Timestamp: base.Add(8 * time.Minute),
			Metadata:  map[string]any{"step": factory.RunDurationStepCI},
		},
		{
			Sequence:  4,
			RunID:     record.RunID,
			EventType: factory.EventTypeStepEnded,
			Timestamp: base.Add(7 * time.Minute),
			Metadata:  map[string]any{"step": factory.RunDurationStepCI},
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
	telemetry := resp.Run.Telemetry
	if telemetry == nil || telemetry.TotalDurationMs == nil {
		t.Fatalf("telemetry = %#v, want derived durations", telemetry)
	}
	if *telemetry.TotalDurationMs != finishedAt.Sub(base).Milliseconds() {
		t.Fatalf("totalDurationMs = %d, want %d", *telemetry.TotalDurationMs, finishedAt.Sub(base).Milliseconds())
	}
	if len(telemetry.StepDurations) != 1 {
		t.Fatalf("stepDurations len = %d, want 1: %#v", len(telemetry.StepDurations), telemetry.StepDurations)
	}
	if telemetry.StepDurations[0].Step != factory.RunDurationStepVerification {
		t.Fatalf("stepDurations[0].step = %q, want %q", telemetry.StepDurations[0].Step, factory.RunDurationStepVerification)
	}
	if telemetry.StepDurations[0].DurationMs != 120000 {
		t.Fatalf("stepDurations[0].durationMs = %d, want 120000", telemetry.StepDurations[0].DurationMs)
	}
}

func TestRunFactoryStatusJSONIncludesStructuredHandoffNextAction(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 9, 0, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-status-handoff", base, base.Add(time.Minute))
	record.Status = factory.RunStatusFailed
	record.ExecutorMode = factory.ExecutorModeSandbox
	record.BranchName = "hal/factory-handoff"
	record.SandboxName = "factory-remote"
	record.Sandbox = &factory.SandboxMetadata{
		Name:       "factory-remote",
		Status:     sandbox.StatusRunning,
		SSHCommand: "ssh root@203.0.113.10",
		Connection: &factory.SandboxConnectionMetadata{
			Address:  "203.0.113.10",
			PublicIP: "203.0.113.10",
		},
	}
	record.CurrentStep = "run"
	record.Failure = &factory.FailureSummary{
		Step:        "run",
		Category:    factory.FailureCategoryRun,
		Message:     "remote execution failed",
		Recoverable: true,
	}
	record.Artifacts = []factory.ArtifactReference{
		{Name: "sandbox-report", Type: "markdown", Path: ".hal/reports/factory.md"},
		{Name: "sandbox-log", Type: "text", Path: ".hal/reports/stdout.log", StoredPath: "artifacts/run-status-handoff/stdout.log"},
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
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
	if resp.Run.Handoff == nil || resp.Run.Handoff.NextAction == nil {
		t.Fatalf("handoff nextAction missing: %#v", resp.Run.Handoff)
	}
	if resp.Run.Handoff.NextAction.Type != factory.NextActionTypeTakeover {
		t.Fatalf("nextAction.type = %q, want takeover", resp.Run.Handoff.NextAction.Type)
	}
	if resp.Run.Handoff.NextAction.Command != "hal sandbox ssh factory-remote" {
		t.Fatalf("nextAction.command = %q", resp.Run.Handoff.NextAction.Command)
	}
	if len(resp.Run.Handoff.ArtifactLocations) != 1 || len(resp.Run.Handoff.LogLocations) != 1 {
		t.Fatalf("handoff locations = artifacts %#v logs %#v", resp.Run.Handoff.ArtifactLocations, resp.Run.Handoff.LogLocations)
	}
	handoffJSON, err := json.Marshal(resp.Run.Handoff)
	if err != nil {
		t.Fatalf("json.Marshal(handoff) error: %v", err)
	}
	for _, forbidden := range []string{"203.0.113.10", "root@"} {
		if strings.Contains(string(handoffJSON), forbidden) {
			t.Fatalf("status handoff should not expose %q:\n%s", forbidden, string(handoffJSON))
		}
	}
}

func TestRunFactoryStatusHumanIncludesHandoffDetails(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 9, 30, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-status-human-handoff", base, base.Add(time.Minute))
	record.Status = factory.RunStatusFailed
	record.ExecutorMode = factory.ExecutorModeLocal
	record.RepoPath = "/workspace/hal"
	record.BranchName = "hal/factory-handoff"
	record.CurrentStep = "ci"
	record.Failure = &factory.FailureSummary{
		Step:        "ci",
		Category:    factory.FailureCategoryCI,
		Message:     "ci failed",
		Recoverable: true,
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	saveFactoryCommandArtifact(t, store, record.RunID, factory.ArtifactReference{
		ID:   "auto-state",
		Name: "auto-state",
		Type: "json",
		Path: ".hal/auto-state.json",
	}, `{"step":"ci"}`)
	saveFactoryCommandArtifact(t, store, record.RunID, factory.ArtifactReference{
		ID:   "ci-log",
		Name: "ci-log",
		Type: "text",
		Path: ".hal/reports/ci.log",
	}, "ci failed")

	var buf bytes.Buffer
	err := runFactoryStatusWithDeps(&buf, record.RunID, false, factoryStatusDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryStatusWithDeps() unexpected error: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"Handoff required: true",
		"Repo path: /workspace/hal",
		"Branch: hal/factory-handoff",
		"Current step: ci",
		"Failure reason: ci failed",
		"Suggested command: hal auto --resume",
		"Logs:",
		".hal/reports/ci.log",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("status output missing %q:\n%s", want, output)
		}
	}
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

func TestRunFactoryLogsEmptyState(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 7, 45, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-no-logs", base, base.Add(time.Minute))
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var buf bytes.Buffer
	err := runFactoryLogsWithDeps(&buf, record.RunID, false, factoryLogsDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryLogsWithDeps() unexpected error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "Run ID: run-no-logs") {
		t.Fatalf("output missing run ID:\n%s", output)
	}
	if !strings.Contains(output, "No logs stored for factory run run-no-logs.") {
		t.Fatalf("output missing empty-state message:\n%s", output)
	}

	buf.Reset()
	err = runFactoryLogsWithDeps(&buf, record.RunID, true, factoryLogsDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryLogsWithDeps() JSON unexpected error: %v", err)
	}

	var resp FactoryLogsResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
	}
	if resp.ContractVersion != FactoryLogsContractVersion {
		t.Fatalf("contractVersion = %q, want %q", resp.ContractVersion, FactoryLogsContractVersion)
	}
	if resp.RunID != record.RunID {
		t.Fatalf("runId = %q, want %q", resp.RunID, record.RunID)
	}
	if resp.Chunks == nil || len(resp.Chunks) != 0 {
		t.Fatalf("chunks = %#v, want empty non-nil array", resp.Chunks)
	}
}

func TestFactoryOpenCommandRegistered(t *testing.T) {
	cmd, err := commandAtPath(Root(), "factory", "open")
	if err != nil {
		t.Fatalf("factory open command missing: %v", err)
	}
	if cmd.Flags().Lookup("exec") == nil {
		t.Fatal("factory open should expose --exec flag")
	}
	if cmd.Flags().Lookup("json") == nil {
		t.Fatal("factory open should expose --json flag")
	}
	if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
		t.Fatalf("factory open missing metadata fields: %v", missing)
	}
}

func TestRunFactoryOpenFailedSandboxPrintsSSHCommand(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-open-sandbox", base, base.Add(time.Minute))
	record.Status = factory.RunStatusFailed
	record.ExecutorMode = factory.ExecutorModeSandbox
	record.BranchName = "hal/factory-handoff"
	record.SandboxName = "factory-remote"
	record.Sandbox = &factory.SandboxMetadata{
		Name:       "factory-remote",
		Status:     sandbox.StatusRunning,
		SSHCommand: "ssh root@203.0.113.10",
		Connection: &factory.SandboxConnectionMetadata{
			Address:  "203.0.113.10",
			PublicIP: "203.0.113.10",
		},
	}
	record.CurrentStep = "run"
	record.Failure = &factory.FailureSummary{
		Step:        "run",
		Category:    factory.FailureCategoryRun,
		Message:     "remote execution failed",
		Recoverable: true,
	}
	record.Artifacts = []factory.ArtifactReference{
		{Name: "sandbox-report", Type: "markdown", Path: ".hal/reports/factory.md"},
		{Name: "sandbox-log", Type: "text", Path: ".hal/reports/stdout.log", StoredPath: "artifacts/run-open-sandbox/stdout.log"},
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var buf bytes.Buffer
	err := runFactoryOpenWithDeps(context.Background(), nil, &buf, io.Discard, record.RunID, false, factoryOpenDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryOpenWithDeps() unexpected error: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"Run ID: run-open-sandbox",
		"Handoff required: true",
		"Sandbox: factory-remote",
		"Branch: hal/factory-handoff",
		"Failure reason: remote execution failed",
		"Suggested command: hal sandbox ssh factory-remote",
		"Artifacts:",
		".hal/reports/factory.md",
		"Logs:",
		".hal/reports/stdout.log",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("open output missing %q:\n%s", want, output)
		}
	}
	for _, forbidden := range []string{"203.0.113.10", "root@"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("open output should not expose %q:\n%s", forbidden, output)
		}
	}
}

func TestRunFactoryOpenJSONEmitsHandoffSummary(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 10, 15, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-open-json", base, base.Add(time.Minute))
	record.Status = factory.RunStatusFailed
	record.ExecutorMode = factory.ExecutorModeSandbox
	record.BranchName = "hal/factory-handoff"
	record.SandboxName = "factory-remote"
	record.Sandbox = &factory.SandboxMetadata{
		Name:   "factory-remote",
		Status: sandbox.StatusRunning,
	}
	record.Failure = &factory.FailureSummary{
		Step:        "run",
		Category:    factory.FailureCategoryRun,
		Message:     "remote execution failed",
		Recoverable: true,
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var buf bytes.Buffer
	err := runFactoryOpenWithOptions(context.Background(), nil, &buf, io.Discard, factoryOpenRequest{
		RunID: record.RunID,
		JSON:  true,
	}, factoryOpenDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryOpenWithOptions() unexpected error: %v", err)
	}

	var resp FactoryOpenResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
	}
	if resp.ContractVersion != FactoryOpenContractVersion {
		t.Fatalf("contractVersion = %q, want %q", resp.ContractVersion, FactoryOpenContractVersion)
	}
	if resp.Handoff == nil || resp.Handoff.NextAction == nil {
		t.Fatalf("handoff nextAction missing: %#v", resp.Handoff)
	}
	if resp.Handoff.NextAction.Command != "hal sandbox ssh factory-remote" {
		t.Fatalf("nextAction command = %q", resp.Handoff.NextAction.Command)
	}
}

func TestRunFactoryOpenJSONMissingRunReturnsJSONError(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))

	var buf bytes.Buffer
	err := runFactoryOpenWithOptions(context.Background(), nil, &buf, io.Discard, factoryOpenRequest{
		RunID: "missing-run",
		JSON:  true,
	}, factoryOpenDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) || exitErr.Code != ExitCodeExpectedNonZero {
		t.Fatalf("runFactoryOpenWithOptions() error = %v, want silent non-zero exit", err)
	}

	var resp FactoryOpenResponse
	if err := json.Unmarshal(buf.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal() error: %v\nraw: %s", err, buf.String())
	}
	if resp.Error != `factory run "missing-run" not found` {
		t.Fatalf("error = %q", resp.Error)
	}
}

func TestRunFactoryOpenFailedLocalExecutesResumeWhenResumable(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 10, 30, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-open-local", base, base.Add(time.Minute))
	record.Status = factory.RunStatusFailed
	record.ExecutorMode = factory.ExecutorModeLocal
	record.RepoPath = "/workspace/hal"
	record.BranchName = "hal/factory-handoff"
	record.CurrentStep = "review"
	record.Failure = &factory.FailureSummary{
		Step:        "review",
		Category:    factory.FailureCategoryReview,
		Message:     "review gate blocked",
		Recoverable: true,
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	saveFactoryCommandArtifact(t, store, record.RunID, factory.ArtifactReference{
		ID:   "auto-state",
		Name: "auto-state",
		Type: "json",
		Path: ".hal/auto-state.json",
	}, `{"step":"review"}`)

	var gotReq factoryOpenExecRequest
	var buf bytes.Buffer
	stdin := strings.NewReader("takeover\n")
	err := runFactoryOpenWithDeps(context.Background(), stdin, &buf, io.Discard, record.RunID, true, factoryOpenDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		execute: func(_ context.Context, req factoryOpenExecRequest) error {
			gotReq = req
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryOpenWithDeps() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(gotReq.Args, []string{"hal", "auto", "--resume"}) {
		t.Fatalf("exec args = %#v", gotReq.Args)
	}
	if gotReq.Stdin != stdin {
		t.Fatalf("exec stdin = %#v, want injected stdin", gotReq.Stdin)
	}
	if gotReq.Dir != "/workspace/hal" {
		t.Fatalf("exec dir = %q, want /workspace/hal", gotReq.Dir)
	}
	output := buf.String()
	for _, want := range []string{
		"Repo path: /workspace/hal",
		"Branch: hal/factory-handoff",
		"Suggested command: hal auto --resume",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("open output missing %q:\n%s", want, output)
		}
	}
}

func TestExecuteFactoryOpenCommandPreservesChildExitCode(t *testing.T) {
	t.Setenv("HAL_FACTORY_OPEN_EXIT_HELPER", "1")

	err := executeFactoryOpenCommand(context.Background(), factoryOpenExecRequest{
		Args: []string{os.Args[0], "-test.run=TestFactoryOpenExecExitHelper"},
	})
	var exitErr *ExitCodeError
	if !errors.As(err, &exitErr) {
		t.Fatalf("executeFactoryOpenCommand() error = %T %v, want ExitCodeError", err, err)
	}
	if exitErr.Code != 7 {
		t.Fatalf("exit code = %d, want 7", exitErr.Code)
	}
}

func TestFactoryOpenExecExitHelper(t *testing.T) {
	if os.Getenv("HAL_FACTORY_OPEN_EXIT_HELPER") != "1" {
		return
	}
	os.Exit(7)
}

func TestFactoryOpenExecRejectsResumeWithoutRepoPath(t *testing.T) {
	_, err := factoryOpenExecRequestFromSummary(&factory.HandoffSummary{
		RunID: "run-open-local-no-repo",
		NextAction: &factory.NextAction{
			Type:    factory.NextActionTypeContinue,
			Command: "hal auto --resume",
		},
	}, nil, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("factoryOpenExecRequestFromSummary() error = nil, want missing repo path error")
	}
	if !strings.Contains(err.Error(), "cannot resume without a recorded repo path") {
		t.Fatalf("error = %q, want missing repo path message", err.Error())
	}
}

func TestRunFactoryOpenCompletedRunHasNoTakeoverCommand(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-open-complete", base, base.Add(time.Minute))
	record.Status = factory.RunStatusSucceeded
	record.CurrentStep = "done"
	record.Failure = nil
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var buf bytes.Buffer
	err := runFactoryOpenWithDeps(context.Background(), nil, &buf, io.Discard, record.RunID, false, factoryOpenDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
	})
	if err != nil {
		t.Fatalf("runFactoryOpenWithDeps() unexpected error: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"Status: succeeded",
		"Handoff required: false",
		"Handoff: no takeover required.",
		"Inspection command: hal factory status run-open-complete --json",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("completed open output missing %q:\n%s", want, output)
		}
	}
	for _, forbidden := range []string{"hal sandbox ssh", "hal auto --resume", "Suggested command:"} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("completed open output should not contain %q:\n%s", forbidden, output)
		}
	}
}

func TestRunFactoryOpenExecCompletedRunExecutesInspectionCommand(t *testing.T) {
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 11, 30, 0, 0, time.UTC)
	record := testFactoryRunRecord("run-open-complete-exec", base, base.Add(time.Minute))
	record.Status = factory.RunStatusSucceeded
	record.CurrentStep = "done"
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}

	var gotReq factoryOpenExecRequest
	err := runFactoryOpenWithDeps(context.Background(), nil, io.Discard, io.Discard, record.RunID, true, factoryOpenDeps{
		defaultStore: func() (factory.Store, error) { return store, nil },
		execute: func(_ context.Context, req factoryOpenExecRequest) error {
			gotReq = req
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runFactoryOpenWithDeps() unexpected error: %v", err)
	}
	wantArgs := []string{"hal", "factory", "status", "run-open-complete-exec", "--json"}
	if !reflect.DeepEqual(gotReq.Args, wantArgs) {
		t.Fatalf("exec args = %#v, want %#v", gotReq.Args, wantArgs)
	}
	if gotReq.Dir != "" {
		t.Fatalf("exec dir = %q, want empty", gotReq.Dir)
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
	record := testFactoryRunRecord("run-absolute-artifact-path", base, base.Add(time.Minute))
	record.Artifacts = []factory.ArtifactReference{
		{
			Name:       "source-markdown",
			Type:       "markdown",
			SourcePath: rawPath,
			Path:       rawPath,
			StoredPath: "artifacts/run-absolute-artifact-path/secret-feature.md",
			Warnings: []string{
				"optional artifact not found: " + rawPath,
				"artifact metadata api_key=super-secret",
			},
			Partial: true,
		},
	}

	summary := newFactoryArtifactSummaries(record.Artifacts)[0]
	if summary.Path != "secret-feature.md" {
		t.Fatalf("sanitized path = %q, want basename only", summary.Path)
	}

	payloads := map[string]any{
		"factory-run":       newFactoryRunResponse(record, nil),
		"factory-status":    FactoryStatusResponse{ContractVersion: FactoryStatusContractVersion, Run: newFactoryStatusRun(record, []factory.EventRecord{}, nil), Timeline: []factory.EventRecord{}},
		"factory-artifacts": newFactoryArtifactsResponse(record),
	}
	for name, payload := range payloads {
		data, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("json.Marshal(%s) error: %v", name, err)
		}
		raw := string(data)
		if strings.Contains(raw, rawPath) || strings.Contains(raw, filepath.Dir(rawPath)) || strings.Contains(raw, "super-secret") {
			t.Fatalf("%s JSON leaked raw artifact warning content: %s", name, raw)
		}
	}
}

func TestSafeFactoryPRURLRejectsSecretQueryKeys(t *testing.T) {
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
			name: "token query",
			raw:  "https://github.com/resciencelab/hal/pull/11?token=secret",
			want: "",
		},
		{
			name: "api key query",
			raw:  "https://github.com/resciencelab/hal/pull/11?api_key=secret",
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
				"[hal factory open](hal_factory_open.md)",
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
		{
			name: "factory open cli reference links parent",
			path: "../docs/cli/hal_factory_open.md",
			wantFragments: []string{
				"handoff guidance",
				"--exec",
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

func saveFactoryCommandArtifact(t *testing.T, store factory.Store, runID string, artifact factory.ArtifactReference, content string) factory.ArtifactReference {
	t.Helper()
	sourcePath := filepath.Join(t.TempDir(), strings.Trim(strings.ReplaceAll(artifact.Path, "/", "-"), "-"))
	if sourcePath == filepath.Dir(sourcePath) {
		sourcePath = filepath.Join(t.TempDir(), "artifact")
	}
	if err := os.WriteFile(sourcePath, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error: %v", sourcePath, err)
	}
	stored, err := store.SaveArtifactFile(runID, artifact, sourcePath)
	if err != nil {
		t.Fatalf("SaveArtifactFile(%s) error: %v", artifact.Name, err)
	}
	return stored
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

func assertPolicyDecisionMetadata(t *testing.T, got map[string]any, want factory.PolicyDecisionMetadata) {
	t.Helper()

	requireExactKeys(t, got, []string{"policyField", "decision", "outcome", "reason"})
	if got["policyField"] != want.PolicyField {
		t.Fatalf("policyField = %#v, want %q", got["policyField"], want.PolicyField)
	}
	if got["decision"] != want.Decision {
		t.Fatalf("decision = %#v, want %q", got["decision"], want.Decision)
	}
	if got["outcome"] != want.Outcome {
		t.Fatalf("outcome = %#v, want %q", got["outcome"], want.Outcome)
	}
	if got["reason"] != want.Reason {
		t.Fatalf("reason = %#v, want %q", got["reason"], want.Reason)
	}
	for _, forbidden := range []string{"token", "secret", "credential", "env", "sourcePath", "provider", "apiKey"} {
		if _, ok := got[forbidden]; ok {
			t.Fatalf("policy decision metadata should not include unsafe field %q: %#v", forbidden, got)
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

func parseFactoryJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(raw) error: %v\nraw: %s", err, string(data))
	}
	return raw
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
