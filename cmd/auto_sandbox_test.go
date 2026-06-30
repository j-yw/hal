package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/spf13/cobra"
)

func TestParseAutoSandboxRequestArgumentContract(t *testing.T) {
	req, err := parseAutoSandboxRequest([]string{".hal/prd-feature.md"}, autoSandboxOptions{
		SandboxName:        "auto-box",
		SandboxNameChanged: true,
		JSON:               true,
		JSONChanged:        true,
	})
	if err != nil {
		t.Fatalf("parseAutoSandboxRequest() unexpected error: %v", err)
	}
	if req.SandboxName != "auto-box" {
		t.Fatalf("SandboxName = %q, want auto-box", req.SandboxName)
	}
	if !reflect.DeepEqual(req.Args, []string{".hal/prd-feature.md"}) {
		t.Fatalf("Args = %#v, want markdown path", req.Args)
	}
	if strings.Contains(strings.Join(req.RemoteCommand, " "), "--sandbox") {
		t.Fatalf("RemoteCommand contains sandbox-only flag: %#v", req.RemoteCommand)
	}

	unnamed, err := parseAutoSandboxRequest([]string{"dev-box"}, autoSandboxOptions{})
	if err != nil {
		t.Fatalf("parseAutoSandboxRequest() unexpected error for positional arg: %v", err)
	}
	if unnamed.SandboxName != "" {
		t.Fatalf("positional auto arg became sandbox name %q", unnamed.SandboxName)
	}
	if !reflect.DeepEqual(unnamed.Args, []string{"dev-box"}) {
		t.Fatalf("Args = %#v, want positional PRD path preserved", unnamed.Args)
	}
}

func TestBuildAutoSandboxRemoteCommandPreservesAutoFlags(t *testing.T) {
	req, err := parseAutoSandboxRequest([]string{"/repo/.hal/prd-feature.md"}, autoSandboxOptions{
		DryRun:              true,
		DryRunChanged:       true,
		NoCI:                true,
		NoCIChanged:         true,
		Mode:                "strict",
		ModeChanged:         true,
		ReviewStreak:        3,
		ReviewStreakChanged: true,
		ReviewMax:           9,
		ReviewMaxChanged:    true,
		Report:              "/repo/.hal/reports/report.md",
		ReportChanged:       true,
		Engine:              "codex",
		EngineChanged:       true,
		Base:                "main",
		BaseChanged:         true,
		JSON:                true,
		JSONChanged:         true,
		SandboxName:         "auto-box",
		SandboxNameChanged:  true,
	})
	if err != nil {
		t.Fatalf("parseAutoSandboxRequest() unexpected error: %v", err)
	}
	req.ProjectDir = "/repo"
	req.RemoteCommand = buildAutoSandboxRemoteCommand(req)

	want := []string{
		"hal", "auto", ".hal/prd-feature.md",
		"--dry-run", "--no-ci",
		"--mode", "strict",
		"--review-streak", "3",
		"--review-max", "9",
		"--report", ".hal/reports/report.md",
		"--engine", "codex",
		"--base", "main",
		"--json",
	}
	if !reflect.DeepEqual(req.RemoteCommand, want) {
		t.Fatalf("RemoteCommand = %#v, want %#v", req.RemoteCommand, want)
	}
	joined := strings.Join(req.RemoteCommand, " ")
	for _, disallowed := range []string{"--sandbox", "--sandbox-name", "auto-box"} {
		if strings.Contains(joined, disallowed) {
			t.Fatalf("RemoteCommand %q should not contain sandbox-only value %q", joined, disallowed)
		}
	}

	req, err = parseAutoSandboxRequest(nil, autoSandboxOptions{
		ModeChanged: true,
	})
	if err != nil {
		t.Fatalf("parseAutoSandboxRequest() unexpected error for empty mode: %v", err)
	}
	req.RemoteCommand = buildAutoSandboxRemoteCommand(req)
	want = []string{"hal", "auto", "--mode", ""}
	if !reflect.DeepEqual(req.RemoteCommand, want) {
		t.Fatalf("RemoteCommand with explicit empty mode = %#v, want %#v", req.RemoteCommand, want)
	}
}

func TestAutoSandboxDepsUseRuntimeDriverForRemoteExecution(t *testing.T) {
	depsType := reflect.TypeOf(autoSandboxDeps{})
	if _, ok := depsType.FieldByName("runProviderCommand"); ok {
		t.Fatal("autoSandboxDeps exposes direct provider command execution; use runtime-driver execution")
	}
	field, ok := depsType.FieldByName("resolveRuntimeDriver")
	if !ok {
		t.Fatal("autoSandboxDeps missing resolveRuntimeDriver")
	}
	want := reflect.TypeOf((func(string) (sandboxruntime.Driver, error))(nil))
	if field.Type != want {
		t.Fatalf("resolveRuntimeDriver type = %v, want %v", field.Type, want)
	}
}

func TestRunAutoWithDirSandboxFlagDispatchesToSandboxExecutor(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 12, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "auto-box", Provider: "test-provider", Status: sandbox.StatusRunning}
	var captured autoSandboxRequest
	var out bytes.Buffer
	var errOut bytes.Buffer

	originalDeps := defaultAutoSandboxDeps
	defaultAutoSandboxDeps = autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-flag-dispatch"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return autoSandboxTestPlan(projectDir), nil
		},
		execute: func(_ context.Context, req autoSandboxRequest, _ io.Writer, _ io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
			captured = req
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return autoSandboxExecutionResult{}, err
				}
			}
			return autoSandboxExecutionResult{Result: &sandboxexec.Result{Target: sandboxruntime.Target{Name: target.Name, Provider: target.Provider, Status: target.Status}}}, nil
		},
	}
	t.Cleanup(func() {
		defaultAutoSandboxDeps = originalDeps
	})

	cmd := newAutoSandboxTestCommand(&out, &errOut)
	for flag, value := range map[string]string{
		"sandbox":      "true",
		"sandbox-name": "auto-box",
		"json":         "true",
		"dry-run":      "true",
		"no-ci":        "true",
		"engine":       "codex-test",
		"base":         "main",
	} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("set %s: %v", flag, err)
		}
	}

	if err := runAutoWithDir(cmd, []string{".hal/prd-feature.md"}, projectDir); err != nil {
		t.Fatalf("runAutoWithDir() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if captured.SandboxName != "auto-box" {
		t.Fatalf("SandboxName = %q, want auto-box", captured.SandboxName)
	}
	wantCommand := []string{"hal", "auto", ".hal/prd-feature.md", "--dry-run", "--no-ci", "--engine", "codex-test", "--base", "main", "--json"}
	if !reflect.DeepEqual(captured.RemoteCommand, wantCommand) {
		t.Fatalf("RemoteCommand = %#v, want %#v", captured.RemoteCommand, wantCommand)
	}
	manifest, err := store.LoadManifest("auto-flag-dispatch")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Purpose != sandboxexecution.PurposeAuto || manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("manifest purpose/status = %q/%q, want auto/succeeded", manifest.Purpose, manifest.Status)
	}
}

func TestRunAutoSandboxWithWriterJSONWorkspacePreflightFailure(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 12, 15, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer
	var errOut bytes.Buffer
	executeCalled := false

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-workspace-preflight"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(ctx context.Context, req sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			status := sandboxworkspace.GitStatus{
				IsGitWorktree: true,
				Repository:    "git@example.com:org/repo.git",
				Branch:        "feature/dirty-auto",
				Dirty:         sandboxworkspace.DirtyState{Untracked: true},
			}
			return sandboxworkspace.Planner{Git: fakeRunSandboxGitInspector{status: status}}.Plan(ctx, req)
		},
		execute: func(context.Context, autoSandboxRequest, io.Writer, io.Writer, autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
			executeCalled = true
			return autoSandboxExecutionResult{}, errors.New("execute should not run")
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() error = %v, want nil JSON error result", err)
	}
	if executeCalled {
		t.Fatal("execute should not run after workspace preflight failure")
	}
	assertAutoJSONContractV2(t, out.Bytes())
	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal AutoResult: %v", err)
	}
	if !strings.Contains(result.Error, "dirty worktree") {
		t.Fatalf("Error = %q, want dirty worktree", result.Error)
	}
	manifest, err := store.LoadManifest("auto-workspace-preflight")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("Status = %q, want failed", manifest.Status)
	}
}

func TestRunAutoSandboxWithWriterPreflightFailureNormalizesManifestCommand(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 12, 18, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	projectDir := t.TempDir()
	prdPath := filepath.Join(projectDir, "prd.md")
	reportPath := filepath.Join(projectDir, ".hal", "reports", "report.md")
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	var out bytes.Buffer

	err := runAutoSandboxWithWriter(context.Background(), nil, []string{prdPath}, projectDir, autoSandboxOptions{
		Report:        reportPath,
		ReportChanged: true,
		JSON:          true,
		JSONChanged:   true,
	}, &out, io.Discard, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-preflight-normalized-command"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return sandboxworkspace.Plan{}, errors.New("workspace plan failed")
		},
		execute: func(context.Context, autoSandboxRequest, io.Writer, io.Writer, autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
			t.Fatal("execute should not run after workspace preflight failure")
			return autoSandboxExecutionResult{}, nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() error = %v, want nil JSON error result", err)
	}
	manifest, err := store.LoadManifest("auto-preflight-normalized-command")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	wantCommand := []string{"hal", "auto", "prd.md", "--report", ".hal/reports/report.md", "--json"}
	if !reflect.DeepEqual(manifest.Command, wantCommand) {
		t.Fatalf("Command = %#v, want %#v", manifest.Command, wantCommand)
	}
	joinedCommand := strings.Join(manifest.Command, "\x00")
	if strings.Contains(joinedCommand, projectDir) || strings.Contains(joinedCommand, prdPath) || strings.Contains(joinedCommand, reportPath) {
		t.Fatalf("manifest command leaks host path: %#v", manifest.Command)
	}
}

func TestRunAutoSandboxWithWriterRejectsResumeUntilStateRewriteExists(t *testing.T) {
	var out bytes.Buffer
	err := runAutoSandboxWithWriter(context.Background(), nil, nil, t.TempDir(), autoSandboxOptions{
		Resume:        true,
		ResumeChanged: true,
		JSON:          true,
		JSONChanged:   true,
	}, &out, io.Discard, autoSandboxDeps{})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() error = %v, want nil JSON error result", err)
	}
	assertAutoJSONContractV2(t, out.Bytes())
	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal AutoResult: %v", err)
	}
	if !strings.Contains(result.Error, "resume state path rewriting is required") {
		t.Fatalf("Error = %q, want resume rewrite guidance", result.Error)
	}
}

func TestRunAutoSandboxWithWriterSuccessfulExecutorUpdatesManifest(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 12, 30, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:     "auto-ready",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host:     &sandbox.SandboxHost{ID: "host-auto", Name: "worker-auto"},
		Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine, RuntimeID: "runtime-auto"},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
			},
		},
	}

	var captured autoSandboxRequest
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runAutoSandboxWithWriter(context.Background(), nil, []string{".hal/prd-feature.md"}, projectDir, autoSandboxOptions{
		Base:        "main",
		BaseChanged: true,
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-success-manifest"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return autoSandboxTestPlan(projectDir), nil
		},
		execute: func(_ context.Context, req autoSandboxRequest, _ io.Writer, _ io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
			running, err := store.LoadManifest("auto-success-manifest")
			if err != nil {
				t.Fatalf("LoadManifest() before executor target ready: %v", err)
			}
			if running.Status != sandboxexecution.StatusRunning {
				t.Fatalf("pre-execute Status = %q, want running", running.Status)
			}
			captured = req
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return autoSandboxExecutionResult{}, err
				}
			}
			return autoSandboxExecutionResult{Result: &sandboxexec.Result{Target: sandboxruntime.Target{Name: target.Name, Provider: target.Provider, Status: target.Status}}}, nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}

	manifest, err := store.LoadManifest("auto-success-manifest")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Purpose != sandboxexecution.PurposeAuto {
		t.Fatalf("Purpose = %q, want auto", manifest.Purpose)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if manifest.SandboxName != "auto-ready" {
		t.Fatalf("SandboxName = %q, want auto-ready", manifest.SandboxName)
	}
	wantCommand := []string{"hal", "auto", ".hal/prd-feature.md", "--base", "main", "--json"}
	if !reflect.DeepEqual(manifest.Command, wantCommand) {
		t.Fatalf("Command = %#v, want %#v", manifest.Command, wantCommand)
	}
	if manifest.WorkDir == "" || manifest.WorkDir != captured.WorkDir {
		t.Fatalf("WorkDir = %q, captured %q", manifest.WorkDir, captured.WorkDir)
	}
	if manifest.Workspace == nil || manifest.Workspace.Mode != sandbox.SandboxWorkspaceModeClone {
		t.Fatalf("Workspace = %#v, want clone metadata", manifest.Workspace)
	}
	if manifest.Host == nil || manifest.Host.ID != "host-auto" {
		t.Fatalf("Host = %#v, want target host metadata", manifest.Host)
	}
	if manifest.Runtime == nil || manifest.Runtime.RuntimeID != "runtime-auto" {
		t.Fatalf("Runtime = %#v, want target runtime metadata", manifest.Runtime)
	}
	if manifest.Security == nil || manifest.Security.Network == nil {
		t.Fatalf("Security = %#v, want target security metadata", manifest.Security)
	}
	if manifest.FinishedAt == nil || !manifest.FinishedAt.Equal(finishedAt) {
		t.Fatalf("FinishedAt = %v, want %v", manifest.FinishedAt, finishedAt)
	}
}

func TestRunAutoSandboxWithWriterManifestRecordsCopiedInputCommand(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 12, 40, 0, 0, time.UTC)
	finishedAt := startedAt.Add(3 * time.Second)
	projectDir := t.TempDir()
	prdPath := filepath.Join(projectDir, "prd.md")
	if err := os.WriteFile(prdPath, []byte("# PRD\n"), 0644); err != nil {
		t.Fatalf("write prd: %v", err)
	}
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "auto-copy", Provider: "test-provider", Status: sandbox.StatusRunning}
	provider := &capturingAutoSandboxProvider{}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runAutoSandboxWithWriter(context.Background(), nil, []string{prdPath}, projectDir, autoSandboxOptions{
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-copied-input-manifest"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return autoSandboxTestPlan(projectDir), nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return provider, nil
		},
		resolveRuntimeDriver: func(string) (sandboxruntime.Driver, error) {
			return fakeRunSandboxRuntimeDriver{
				exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					_, _ = io.WriteString(got.Stdout, `{"contractVersion":2,"ok":true,"entryMode":"markdown_path","resumed":false,"steps":{},"summary":"ok"}`+"\n")
					return &sandboxruntime.ExecResult{ExitCode: 0}, nil
				},
			}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, script string, _ io.Writer) error {
			provider.scripts = append(provider.scripts, script)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	manifest, err := store.LoadManifest("auto-copied-input-manifest")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	joinedCommand := strings.Join(manifest.Command, "\x00")
	if !strings.Contains(joinedCommand, ".hal/factory-inputs/prd.md") {
		t.Fatalf("manifest command = %#v, want copied input path", manifest.Command)
	}
	if strings.Contains(joinedCommand, prdPath) {
		t.Fatalf("manifest command leaks host input path: %#v", manifest.Command)
	}
}

func TestExecuteAutoSandboxCopiesExplicitInputsBeforeRemoteCommand(t *testing.T) {
	projectDir := t.TempDir()
	workspaceDir := "/workspace/repo"
	if err := os.WriteFile(filepath.Join(projectDir, "prd.md"), []byte("# PRD\n"), 0644); err != nil {
		t.Fatalf("write prd: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(projectDir, ".hal", "reports"), 0755); err != nil {
		t.Fatalf("mkdir reports: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectDir, ".hal", "reports", "report.md"), []byte("# Report\n"), 0644); err != nil {
		t.Fatalf("write report: %v", err)
	}

	target := &sandbox.SandboxState{Name: "auto-copy", Provider: "test-provider", Status: sandbox.StatusRunning}
	provider := &capturingAutoSandboxProvider{}
	var execReq sandboxruntime.ExecRequest
	prdPath := filepath.Join(projectDir, "prd.md")
	reportPath := filepath.Join(projectDir, ".hal", "reports", "report.md")
	req, err := parseAutoSandboxRequest([]string{prdPath}, autoSandboxOptions{
		Report:        reportPath,
		ReportChanged: true,
		JSON:          true,
		JSONChanged:   true,
	})
	if err != nil {
		t.Fatalf("parseAutoSandboxRequest() error: %v", err)
	}
	req.ProjectDir = projectDir
	req.WorkDir = workspaceDir
	req.RepoRemote = "git@example.com:org/repo.git"
	req.BaseBranch = "main"
	req.RunBranch = "feature/auto-copy"
	req.Workspace = &sandbox.SandboxWorkspace{Mode: sandbox.SandboxWorkspaceModeClone}

	result, err := autoSandboxDeps{
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return provider, nil
		},
		resolveRuntimeDriver: func(string) (sandboxruntime.Driver, error) {
			return fakeRunSandboxRuntimeDriver{
				exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					execReq = got
					_, _ = io.WriteString(got.Stdout, `{"contractVersion":2,"ok":true,"entryMode":"markdown_path","resumed":false,"steps":{},"summary":"ok"}`+"\n")
					return &sandboxruntime.ExecResult{ExitCode: 0}, nil
				},
			}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, script string, _ io.Writer) error {
			provider.scripts = append(provider.scripts, script)
			return nil
		},
	}.executeAutoSandbox(context.Background(), req, io.Discard, io.Discard, autoSandboxExecutionHooks{})
	if err != nil {
		t.Fatalf("executeAutoSandbox() unexpected error: %v", err)
	}
	if result.Result == nil {
		t.Fatal("Result = nil")
	}
	joinedArgs := strings.Join(execReq.Args, "\x00")
	if !strings.Contains(joinedArgs, ".hal/factory-inputs/prd.md") {
		t.Fatalf("runtime exec args %q do not include copied PRD input", strings.Join(execReq.Args, " "))
	}
	if !strings.Contains(joinedArgs, ".hal/factory-inputs/report.md") {
		t.Fatalf("runtime exec args %q do not include copied report input", strings.Join(execReq.Args, " "))
	}
	if strings.Contains(joinedArgs, prdPath) || strings.Contains(joinedArgs, reportPath) {
		t.Fatalf("runtime exec args still contain local input paths: %q", strings.Join(execReq.Args, " "))
	}
	if !provider.sawPayload("# PRD\n") {
		t.Fatal("copy scripts did not include PRD payload")
	}
	if !provider.sawPayload("# Report\n") {
		t.Fatal("copy scripts did not include report payload")
	}
}

func TestRunAutoSandboxWithWriterForwardsFactoryAttemptPolicyEnv(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 12, 42, 0, 0, time.UTC)
	finishedAt := startedAt.Add(3 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "auto-env", Provider: "test-provider", Status: sandbox.StatusRunning}
	var gotEnv map[string]string
	var out bytes.Buffer
	var errOut bytes.Buffer

	ctx := contextWithAutoFactoryAttemptPolicy(context.Background(), autoFactoryAttemptPolicy{
		MaxRunAttempts:       2,
		MaxReviewFixAttempts: 3,
		MaxCIFixAttempts:     4,
	})
	err := runAutoSandboxWithWriter(ctx, nil, nil, projectDir, autoSandboxOptions{
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-attempt-policy-env"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return autoSandboxTestPlan(projectDir), nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(string) (sandboxruntime.Driver, error) {
			return fakeRunSandboxRuntimeDriver{
				exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					gotEnv = map[string]string{}
					for key, value := range got.Env {
						gotEnv[key] = value
					}
					_, _ = io.WriteString(got.Stdout, `{"contractVersion":2,"ok":true,"entryMode":"report_discovery","resumed":false,"steps":{},"summary":"ok"}`+"\n")
					return &sandboxruntime.ExecResult{ExitCode: 0}, nil
				},
			}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	want := map[string]string{
		autoFactoryMaxRunAttemptsEnv:       "2",
		autoFactoryMaxReviewFixAttemptsEnv: "3",
		autoFactoryMaxCIFixAttemptsEnv:     "4",
	}
	if !reflect.DeepEqual(gotEnv, want) {
		t.Fatalf("remote env = %#v, want %#v", gotEnv, want)
	}
}

func TestRunAutoSandboxWithWriterJSONRemoteOutputPassesThroughAfterStdout(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 12, 45, 0, 0, time.UTC)
	finishedAt := startedAt.Add(3 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "auto-ready", Provider: "test-provider", Status: sandbox.StatusRunning}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-remote-json-pass-through"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return autoSandboxTestPlan(projectDir), nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(string) (sandboxruntime.Driver, error) {
			return fakeRunSandboxRuntimeDriver{
				exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					_, _ = io.WriteString(got.Stdout, `{"contractVersion":2,"ok":false,"entryMode":"report_discovery","resumed":false,"steps":{},"summary":"remote"}`+"\n")
					return nil, errors.New("remote auto failed after writing json")
				},
			}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			return nil
		},
	})
	if err == nil {
		t.Fatal("expected remote command error after stdout pass-through, got nil")
	}
	if !strings.Contains(err.Error(), "remote auto failed after writing json") {
		t.Fatalf("error = %q, want remote failure", err.Error())
	}
	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not parseable remote AutoResult JSON: %v\n%s", err, out.String())
	}
	if result.Summary != "remote" {
		t.Fatalf("Summary = %q, want remote", result.Summary)
	}
	if strings.Contains(out.String(), "remote auto failed") {
		t.Fatalf("stdout contains synthesized local error: %s", out.String())
	}
}

func newAutoSandboxTestCommand(out, errOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "auto"}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().Bool("resume", false, "")
	cmd.Flags().Bool("no-ci", false, "")
	cmd.Flags().Bool("skip-pr", false, "")
	cmd.Flags().Bool("no-review", false, "")
	cmd.Flags().String("mode", "", "")
	cmd.Flags().Int("review-streak", 0, "")
	cmd.Flags().Int("review-max", 0, "")
	cmd.Flags().String("report", "", "")
	cmd.Flags().String("engine", "codex", "")
	cmd.Flags().String("base", "", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("sandbox", false, "")
	cmd.Flags().String("sandbox-name", "", "")
	return cmd
}

func autoSandboxTestPlan(projectDir string) sandboxworkspace.Plan {
	return sandboxworkspace.Plan{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		ProjectDir:  projectDir,
		Repository:  "git@example.com:org/repo.git",
		Branch:      "feature/auto-sandbox",
		Upstream:    "origin/feature/auto-sandbox",
		SyncRef:     "refs/remotes/origin/feature/auto-sandbox",
	}
}

type capturingAutoSandboxProvider struct {
	scripts   []string
	finalArgs []string
}

func (p *capturingAutoSandboxProvider) Create(context.Context, string, map[string]string, io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (p *capturingAutoSandboxProvider) Stop(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (p *capturingAutoSandboxProvider) Start(context.Context, *sandbox.ConnectInfo, io.Writer) (*sandbox.LifecycleResult, error) {
	return &sandbox.LifecycleResult{Status: sandbox.StatusRunning}, nil
}

func (p *capturingAutoSandboxProvider) Delete(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (p *capturingAutoSandboxProvider) SSH(*sandbox.ConnectInfo) (*exec.Cmd, error) {
	return nil, nil
}

func (p *capturingAutoSandboxProvider) Exec(*sandbox.ConnectInfo, []string) (*exec.Cmd, error) {
	return nil, nil
}

func (p *capturingAutoSandboxProvider) Status(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (p *capturingAutoSandboxProvider) sawPayload(payload string) bool {
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	for _, script := range p.scripts {
		if strings.Contains(script, encoded) {
			return true
		}
	}
	return false
}
