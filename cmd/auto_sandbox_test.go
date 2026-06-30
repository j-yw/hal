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
	want := reflect.TypeOf((func(sandboxruntime.Target) (sandboxruntime.Driver, error))(nil))
	if field.Type != want {
		t.Fatalf("resolveRuntimeDriver type = %v, want %v", field.Type, want)
	}
}

func TestAutoSandboxDefaultRuntimeDriverResolverSelectsRootlessPodmanFromTargetMetadata(t *testing.T) {
	deps := normalizeAutoSandboxDeps(autoSandboxDeps{
		resolveProvider: func(string) (sandbox.Provider, error) {
			t.Fatal("resolveProvider should not run for explicit rootless Podman runtime metadata")
			return nil, nil
		},
	})
	driver, err := deps.resolveRuntimeDriver(sandboxruntime.Target{
		Provider: "local",
		Runtime: sandboxruntime.RuntimeState{
			Driver: sandboxruntime.DriverRootlessPodman,
		},
	})
	if err != nil {
		t.Fatalf("resolveRuntimeDriver() error = %v", err)
	}
	if driver == nil || driver.ID() != sandboxruntime.DriverRootlessPodman {
		t.Fatalf("driver = %#v, want rootless Podman driver", driver)
	}
}

func TestAutoSandboxDefaultRuntimeDriverResolverKeepsSSHMachineForAbsentOrExplicitSSHMetadata(t *testing.T) {
	tests := []struct {
		name          string
		runtimeDriver string
	}{
		{name: "absent runtime driver"},
		{name: "explicit SSH-machine runtime driver", runtimeDriver: sandboxruntime.DriverSSHMachine},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var providerName string
			deps := normalizeAutoSandboxDeps(autoSandboxDeps{
				resolveProvider: func(name string) (sandbox.Provider, error) {
					providerName = name
					return fakeFactorySandboxProvider{}, nil
				},
			})
			driver, err := deps.resolveRuntimeDriver(sandboxruntime.Target{
				Provider: "test-provider",
				Runtime: sandboxruntime.RuntimeState{
					Driver: tt.runtimeDriver,
				},
			})
			if err != nil {
				t.Fatalf("resolveRuntimeDriver() error = %v", err)
			}
			if providerName != "test-provider" {
				t.Fatalf("providerName = %q, want test-provider", providerName)
			}
			if driver == nil || driver.ID() != sandboxruntime.DriverSSHMachine {
				t.Fatalf("driver = %#v, want SSH-machine driver", driver)
			}
		})
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
			if req.WorkspaceMode != sandbox.SandboxWorkspaceModeClone || req.DirectOptIn {
				t.Fatalf("workspace planning request = %#v, want clone mode without direct opt-in", req)
			}
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
	if result.OK {
		t.Fatalf("AutoResult.OK = true, want false for workspace preflight failure")
	}
	if !strings.Contains(result.Error, "dirty worktree") {
		t.Fatalf("Error = %q, want dirty worktree", result.Error)
	}
	if strings.TrimSpace(errOut.String()) != "" {
		t.Fatalf("stderr = %q, want empty for JSON workspace preflight failure", errOut.String())
	}
	manifest, err := store.LoadManifest("auto-workspace-preflight")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("Status = %q, want failed", manifest.Status)
	}
	if manifest.FinishedAt == nil || !manifest.FinishedAt.Equal(finishedAt) {
		t.Fatalf("FinishedAt = %v, want %v", manifest.FinishedAt, finishedAt)
	}
}

func TestRunAutoSandboxWithWriterGitBundlePlanMaterializesAndExecutes(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 12, 16, 0, 0, time.UTC)
	finishedAt := startedAt.Add(4 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "auto-bundle", Provider: "test-provider", Status: sandbox.StatusRunning}
	plan := sandboxworkspace.Plan{
		Mode:           sandbox.SandboxWorkspaceModeClone,
		InputSource:    sandbox.SandboxWorkspaceInputSourceGitBundle,
		ProjectDir:     projectDir,
		Repository:     "git@example.com:org/repo.git",
		Branch:         "feature/unpushed-auto",
		Upstream:       "origin/main",
		SyncRef:        "abc123",
		RequiresBundle: true,
	}
	var order []string
	var materialized bool
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
			return "auto-git-bundle-exec"
		},
		now: runSandboxTestClock(startedAt, finishedAt),
		planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
			return plan, nil
		},
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeRunSandboxRuntimeDriver{
				exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					script := ""
					if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
						script = got.Args[2]
					}
					switch {
					case strings.Contains(script, "workspace.patch"):
						order = append(order, "recovery_generation")
					case strings.Contains(script, "reports.tar"):
						order = append(order, "reports_generation")
					default:
						order = append(order, "runtime_exec")
						_, _ = io.WriteString(got.Stdout, autoSandboxRemoteSuccessJSON("remote")+"\n")
					}
					return &sandboxruntime.ExecResult{ExitCode: 0}, nil
				},
			}, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			t.Fatal("legacy bootstrap should not run for git-bundle workspace")
			return factory.BootstrapResult{}, nil
		},
		materializeWorkspace: func(_ context.Context, _ sandboxexec.PrepareContext, got sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			order = append(order, "materialize_workspace")
			materialized = true
			if got.Plan == nil {
				t.Fatal("materialization plan = nil, want original workspace plan")
			}
			if got.Plan.Upstream != "origin/main" {
				t.Fatalf("plan upstream = %q, want origin/main", got.Plan.Upstream)
			}
			if got.Plan.ProjectDir != projectDir || got.ProjectDir != projectDir {
				t.Fatalf("materialization dirs plan=%q request=%q, want %q", got.Plan.ProjectDir, got.ProjectDir, projectDir)
			}
			if got.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle || got.Workspace.SyncRef != "abc123" {
				t.Fatalf("workspace metadata = %#v, want git-bundle metadata", got.Workspace)
			}
			return sandboxworkspace.MaterializationResult{InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			order = append(order, "auth")
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			t.Fatal("provider script should not run without explicit inputs or auth files")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runAutoSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}
	if !materialized {
		t.Fatal("materializeWorkspace was not called")
	}
	wantOrder := []string{"materialize_workspace", "auth", "runtime_exec", "recovery_generation", "reports_generation"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("order = %#v, want %#v", order, wantOrder)
	}
	assertAutoJSONContractV2(t, out.Bytes())
	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("unmarshal AutoResult: %v", err)
	}
	if !result.OK || result.Summary != "remote" {
		t.Fatalf("AutoResult = %#v, want successful remote result", result)
	}
	if strings.Contains(out.String(), "git bundle workspace input is not implemented") {
		t.Fatalf("stdout contains old implementation guard: %s", out.String())
	}
	manifest, err := store.LoadManifest("auto-git-bundle-exec")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	wantWorkspace := sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
		Repo:        "git@example.com:org/repo.git",
		Branch:      "feature/unpushed-auto",
		SyncRef:     "abc123",
	}
	if manifest.Workspace == nil || *manifest.Workspace != wantWorkspace {
		t.Fatalf("Workspace = %#v, want %#v", manifest.Workspace, wantWorkspace)
	}
	encodedWorkspace, err := json.Marshal(manifest.Workspace)
	if err != nil {
		t.Fatalf("Marshal(workspace) error: %v", err)
	}
	if strings.Contains(string(encodedWorkspace), projectDir) || strings.Contains(string(encodedWorkspace), "origin/main") {
		t.Fatalf("workspace metadata leaks transient plan details: %s", encodedWorkspace)
	}
	if manifest.Command == nil || !reflect.DeepEqual(manifest.Command, []string{"hal", "auto", "--json"}) {
		t.Fatalf("Command = %#v, want remote auto json command", manifest.Command)
	}
	if manifest.FinishedAt == nil || !manifest.FinishedAt.Equal(finishedAt) {
		t.Fatalf("FinishedAt = %v, want %v", manifest.FinishedAt, finishedAt)
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
	if manifest.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceRemoteRef ||
		manifest.Workspace.Repo != "git@example.com:org/repo.git" ||
		manifest.Workspace.Branch != "feature/auto-sandbox" ||
		manifest.Workspace.SyncRef != "refs/remotes/origin/feature/auto-sandbox" {
		t.Fatalf("Workspace = %#v, want remote-ref clone metadata", manifest.Workspace)
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

func TestRunAutoSandboxWithWriterCollectsCoreStateArtifacts(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 13, 15, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:     "auto-core-state-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
	}
	repoRemote := "git@example.com:org/repo.git"
	expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
		RunID:      "auto-core-state",
		RepoPath:   projectDir,
		RepoRemote: repoRemote,
		BranchName: "feature/auto-sandbox",
		BaseBranch: "main",
	})
	expectedSources := []string{
		expectedWorkspace + "/.hal/prd.json",
		expectedWorkspace + "/.hal/progress.txt",
		expectedWorkspace + "/.hal/auto-state.json",
		expectedWorkspace + "/.hal/recovery/workspace.patch",
		expectedWorkspace + "/.hal/reports.tar",
	}
	var copyOutSources []string
	var order []string
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			script := ""
			if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
				script = got.Args[2]
			}
			switch {
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "workspace.patch"):
				order = append(order, "recovery_generation")
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "reports.tar"):
				order = append(order, "reports_generation")
			default:
				order = append(order, "runtime_exec")
				if got.Target.Name != "auto-core-state-box" {
					t.Fatalf("Exec target = %#v, want auto-core-state-box", got.Target)
				}
				_, _ = io.WriteString(got.Stdout, autoSandboxRemoteSuccessJSON("remote")+"\n")
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
		copyOut: func(_ context.Context, got sandboxruntime.CopyRequest) error {
			order = append(order, "copy_out")
			copyOutSources = append(copyOutSources, got.SourcePath)
			if err := os.MkdirAll(filepath.Dir(got.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(got.DestinationPath, []byte("payload for "+got.SourcePath), 0o600)
		},
	}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		Base:        "main",
		BaseChanged: true,
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-core-state"
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
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
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
	if !reflect.DeepEqual(order, []string{"runtime_exec", "copy_out", "copy_out", "copy_out", "recovery_generation", "copy_out", "reports_generation", "copy_out"}) {
		t.Fatalf("order = %#v, want runtime exec before core state copy out", order)
	}
	if !reflect.DeepEqual(copyOutSources, expectedSources) {
		t.Fatalf("CopyOut sources = %#v, want %#v", copyOutSources, expectedSources)
	}
	var result AutoResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not parseable remote AutoResult JSON: %v\n%s", err, out.String())
	}
	if !result.OK {
		t.Fatalf("AutoResult = %#v, want ok", result)
	}

	manifest, err := store.LoadManifest("auto-core-state")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if len(manifest.Artifacts) != 0 {
		t.Fatalf("legacy Artifacts = %#v, want unchanged empty top-level artifacts", manifest.Artifacts)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil, want collected core state metadata")
	}
	if len(manifest.ArtifactMetadata.Collected) != 6 {
		t.Fatalf("collected = %#v, want core state, generated artifacts, and stdout summary", manifest.ArtifactMetadata.Collected)
	}
	collected := map[string]sandboxexecution.ArtifactMetadataEntry{}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		collected[artifact.Path] = artifact
	}
	assertRunSandboxCollectedArtifact(t, collected[".hal/prd.json"], ".hal/prd.json", "auto-core-state/artifacts/core/hal-prd.json")
	assertRunSandboxCollectedArtifact(t, collected[".hal/progress.txt"], ".hal/progress.txt", "auto-core-state/artifacts/core/hal-progress.txt")
	assertRunSandboxCollectedArtifact(t, collected[".hal/auto-state.json"], ".hal/auto-state.json", "auto-core-state/artifacts/core/hal-auto-state.json")
	assertRunSandboxCollectedArtifact(t, collected[".hal/recovery/workspace.patch"], ".hal/recovery/workspace.patch", "auto-core-state/recovery/workspace.patch")
	assertRunSandboxCollectedArtifact(t, collected[".hal/reports.tar"], ".hal/reports.tar", "auto-core-state/artifacts/reports/reports.tar")
	assertRunSandboxCollectedArtifact(t, collected["output/stdout-summary.txt"], "output/stdout-summary.txt", "auto-core-state/artifacts/output/stdout-summary.txt")
	if len(manifest.ArtifactMetadata.Partial) != 0 || len(manifest.ArtifactMetadata.Warnings) != 0 {
		t.Fatalf("partial/warnings = %#v/%#v, want none", manifest.ArtifactMetadata.Partial, manifest.ArtifactMetadata.Warnings)
	}
}

func TestRunAutoSandboxWithWriterCollectsGeneratedArtifacts(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 13, 20, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:     "auto-generated-artifacts-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
	}
	repoRemote := "git@example.com:org/repo.git"
	expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
		RunID:      "auto-generated-artifacts",
		RepoPath:   projectDir,
		RepoRemote: repoRemote,
		BranchName: "feature/auto-sandbox",
		BaseBranch: "main",
	})
	expectedSources := []string{
		expectedWorkspace + "/.hal/prd.json",
		expectedWorkspace + "/.hal/progress.txt",
		expectedWorkspace + "/.hal/auto-state.json",
		expectedWorkspace + "/.hal/recovery/workspace.patch",
		expectedWorkspace + "/.hal/reports.tar",
	}
	var execCalls []string
	var copyOutSources []string
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			script := ""
			if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
				script = got.Args[2]
			}
			switch {
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "workspace.patch"):
				execCalls = append(execCalls, "recovery_generation")
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "reports.tar"):
				execCalls = append(execCalls, "reports_generation")
			default:
				execCalls = append(execCalls, "remote_auto")
				if got.Target.Name != "auto-generated-artifacts-box" {
					t.Fatalf("Exec target = %#v, want auto-generated-artifacts-box", got.Target)
				}
				_, _ = io.WriteString(got.Stdout, autoSandboxRemoteSuccessJSON("remote")+"\n")
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
		copyOut: func(_ context.Context, got sandboxruntime.CopyRequest) error {
			copyOutSources = append(copyOutSources, got.SourcePath)
			if got.SourcePath == expectedWorkspace+"/.hal/reports.tar" {
				return os.ErrNotExist
			}
			if err := os.MkdirAll(filepath.Dir(got.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(got.DestinationPath, []byte("payload for "+got.SourcePath), 0o600)
		},
	}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		Base:        "main",
		BaseChanged: true,
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-generated-artifacts"
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
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
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
	if !reflect.DeepEqual(execCalls, []string{"remote_auto", "recovery_generation", "reports_generation"}) {
		t.Fatalf("exec calls = %#v, want remote command followed by generated artifact commands", execCalls)
	}
	if !reflect.DeepEqual(copyOutSources, expectedSources) {
		t.Fatalf("CopyOut sources = %#v, want %#v", copyOutSources, expectedSources)
	}
	var result AutoResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if !result.OK || result.Summary != "remote" {
		t.Fatalf("AutoResult = %#v, want ok remote result", result)
	}
	for _, disallowed := range []string{"missing", ".hal/reports.tar", "artifact warning"} {
		if strings.Contains(out.String(), disallowed) {
			t.Fatalf("stdout contains collection warning text %q outside remote JSON document: %s", disallowed, out.String())
		}
	}

	manifest, err := store.LoadManifest("auto-generated-artifacts")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if len(manifest.Artifacts) != 0 {
		t.Fatalf("legacy Artifacts = %#v, want unchanged empty top-level artifacts", manifest.Artifacts)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil, want generated artifact metadata")
	}
	collected := map[string]sandboxexecution.ArtifactMetadataEntry{}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		collected[artifact.Path] = artifact
	}
	assertRunSandboxCollectedArtifact(t, collected[".hal/prd.json"], ".hal/prd.json", "auto-generated-artifacts/artifacts/core/hal-prd.json")
	assertRunSandboxCollectedArtifact(t, collected[".hal/progress.txt"], ".hal/progress.txt", "auto-generated-artifacts/artifacts/core/hal-progress.txt")
	assertRunSandboxCollectedArtifact(t, collected[".hal/auto-state.json"], ".hal/auto-state.json", "auto-generated-artifacts/artifacts/core/hal-auto-state.json")
	assertRunSandboxCollectedArtifact(t, collected[".hal/recovery/workspace.patch"], ".hal/recovery/workspace.patch", "auto-generated-artifacts/recovery/workspace.patch")
	if len(manifest.ArtifactMetadata.Partial) != 1 {
		t.Fatalf("partial = %#v, want missing reports archive partial", manifest.ArtifactMetadata.Partial)
	}
	if manifest.ArtifactMetadata.Partial[0].Path != ".hal/reports.tar" || manifest.ArtifactMetadata.Partial[0].StoredPath != "" {
		t.Fatalf("reports partial = %#v, want safe display path without stored path", manifest.ArtifactMetadata.Partial[0])
	}
	if len(manifest.ArtifactMetadata.Warnings) != 1 {
		t.Fatalf("warnings = %#v, want missing reports archive warning", manifest.ArtifactMetadata.Warnings)
	}
	warning := manifest.ArtifactMetadata.Warnings[0]
	if warning.Artifact.Path != ".hal/reports.tar" || !strings.Contains(warning.Message, "missing") {
		t.Fatalf("reports warning = %#v, want missing reports archive warning", warning)
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
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
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
	req.Workspace = &sandbox.SandboxWorkspace{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		Repo:        "git@example.com:org/repo.git",
		Branch:      "feature/auto-copy",
		SyncRef:     "refs/remotes/origin/feature/auto-copy",
	}
	bootstrapped := false

	result, err := autoSandboxDeps{
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return provider, nil
		},
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeRunSandboxRuntimeDriver{
				exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					execReq = got
					_, _ = io.WriteString(got.Stdout, `{"contractVersion":2,"ok":true,"entryMode":"markdown_path","resumed":false,"steps":{},"summary":"ok"}`+"\n")
					return &sandboxruntime.ExecResult{ExitCode: 0}, nil
				},
			}, nil
		},
		bootstrap: func(_ context.Context, got factory.BootstrapRequest, _ factory.BootstrapDeps) (factory.BootstrapResult, error) {
			bootstrapped = true
			if got.RepositoryURL != req.RepoRemote || got.BaseBranch != req.BaseBranch || got.RunBranch != req.RunBranch || got.WorkspaceDir != req.WorkDir {
				t.Fatalf("bootstrap request = %#v, want remote-ref workspace request", got)
			}
			return factory.BootstrapResult{}, nil
		},
		materializeWorkspace: func(context.Context, sandboxexec.PrepareContext, sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			t.Fatal("materializeWorkspace should not run for remote-ref workspace")
			return sandboxworkspace.MaterializationResult{}, nil
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
	if !bootstrapped {
		t.Fatal("bootstrap was not called for remote-ref workspace")
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

func TestExecuteAutoSandboxGitBundleWorkspaceUsesSharedMaterializer(t *testing.T) {
	target := &sandbox.SandboxState{
		Name:        "auto-ready",
		Provider:    "local",
		Status:      sandbox.StatusRunning,
		TailscaleIP: "100.64.0.11",
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: sandbox.SandboxIsolationLevelContainer,
		},
	}
	req := autoSandboxRequest{
		JSON:          true,
		ProjectDir:    t.TempDir(),
		SandboxName:   "auto-ready",
		RepoRemote:    "git@example.com:org/repo.git",
		BaseBranch:    "main",
		RunBranch:     "feature/bundle-auto",
		WorkDir:       "/root/workspace/repo",
		RemoteCommand: []string{"hal", "auto", "--json"},
		Flags: autoSandboxOptions{
			JSON:        true,
			JSONChanged: true,
		},
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
			Repo:        "git@example.com:org/repo.git",
			Branch:      "feature/bundle-auto",
			SyncRef:     "refs/hal/workspace-sync/bundle-auto",
		},
		Security: runSandboxSecurityRequest(),
	}
	var order []string
	var materialized bool
	driver := &fakeRunSandboxRuntimeDriver{
		id: sandboxruntime.DriverRootlessPodman,
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			order = append(order, "runtime_exec")
			if got.Target.Name != "auto-ready" || got.Target.Provider != "local" || got.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || got.Target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
				t.Fatalf("runtime exec target = %#v, want prepared rootless runtime target", got.Target)
			}
			_, _ = io.WriteString(got.Stdout, `{"contractVersion":2,"ok":true,"entryMode":"report_discovery","resumed":false,"steps":{},"summary":"ok"}`+"\n")
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
	}

	var out bytes.Buffer
	var errOut bytes.Buffer
	result, err := (autoSandboxDeps{
		loadSandbox: func(string) (*sandbox.SandboxState, error) {
			return target, nil
		},
		startSandbox: func(context.Context, *sandbox.SandboxState, io.Writer) (*sandbox.SandboxState, error) {
			t.Fatal("startSandbox should not run for a running target")
			return nil, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
		},
		resolveRuntimeDriver: func(target sandboxruntime.Target) (sandboxruntime.Driver, error) {
			order = append(order, "resolve_runtime_driver")
			if target.Provider != "local" || target.Runtime.Driver != sandboxruntime.DriverRootlessPodman {
				t.Fatalf("runtime target = %#v, want local rootless Podman target", target)
			}
			return driver, nil
		},
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			t.Fatal("legacy bootstrap should not run for git-bundle workspace")
			return factory.BootstrapResult{}, nil
		},
		materializeWorkspace: func(_ context.Context, prep sandboxexec.PrepareContext, got sandboxexec.WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
			order = append(order, "materialize_workspace")
			materialized = true
			if prep.Driver != driver {
				t.Fatalf("prep driver = %#v, want resolved runtime driver", prep.Driver)
			}
			if prep.Target.Name != "auto-ready" || prep.Target.Provider != "local" || prep.Target.Connection.TailscaleIP != "100.64.0.11" || prep.Target.Runtime.Driver != sandboxruntime.DriverRootlessPodman || prep.Target.Runtime.IsolationLevel != sandbox.SandboxIsolationLevelContainer {
				t.Fatalf("prep target = %#v, want rootless runtime target metadata", prep.Target)
			}
			if got.ProjectDir != req.ProjectDir || got.WorkspaceDir != req.WorkDir {
				t.Fatalf("materialize request = %#v, want project/work dirs from request", got)
			}
			if got.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle || got.Workspace.SyncRef != req.Workspace.SyncRef {
				t.Fatalf("workspace metadata = %#v, want git-bundle metadata", got.Workspace)
			}
			return sandboxworkspace.MaterializationResult{InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile {
			order = append(order, "auth")
			return nil
		},
		runProviderScript: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, string, io.Writer) error {
			t.Fatal("provider script should not run without explicit inputs or auth files")
			return nil
		},
	}).executeAutoSandbox(context.Background(), req, &out, &errOut, autoSandboxExecutionHooks{})
	if err != nil {
		t.Fatalf("executeAutoSandbox() unexpected error: %v", err)
	}
	if result.Result == nil {
		t.Fatal("Result = nil")
	}
	if !result.RemoteStarted {
		t.Fatal("RemoteStarted = false, want true after runtime stdout")
	}
	if !reflect.DeepEqual(result.PreparedCommand, req.RemoteCommand) {
		t.Fatalf("PreparedCommand = %#v, want %#v", result.PreparedCommand, req.RemoteCommand)
	}
	if !materialized {
		t.Fatal("materializeWorkspace was not called")
	}
	wantOrder := []string{"resolve_runtime_driver", "materialize_workspace", "auth", "runtime_exec"}
	if !reflect.DeepEqual(order, wantOrder) {
		t.Fatalf("order = %#v, want %#v", order, wantOrder)
	}
	if out.String() == "" {
		t.Fatal("stdout is empty, want remote auto output")
	}
	if errOut.String() != "" {
		t.Fatalf("stderr = %q, want empty", errOut.String())
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
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeRunSandboxRuntimeDriver{
				exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
					script := ""
					if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
						script = got.Args[2]
					}
					if strings.Contains(script, "exec 'hal' 'auto'") || strings.Contains(script, "exec hal auto") || (len(got.Args) >= 2 && got.Args[0] == "hal" && got.Args[1] == "auto") {
						gotEnv = map[string]string{}
						for key, value := range got.Env {
							gotEnv[key] = value
						}
						_, _ = io.WriteString(got.Stdout, `{"contractVersion":2,"ok":true,"entryMode":"report_discovery","resumed":false,"steps":{},"summary":"ok"}`+"\n")
					}
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
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
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
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if result.Summary != "remote" {
		t.Fatalf("Summary = %q, want remote", result.Summary)
	}
	if strings.Contains(out.String(), "remote auto failed") {
		t.Fatalf("stdout contains synthesized local error: %s", out.String())
	}
}

func TestRunAutoSandboxWithWriterSavesOutputSummaryArtifacts(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 13, 25, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:        "auto-summary-box",
		Provider:    "test-provider",
		Status:      sandbox.StatusRunning,
		IP:          "203.0.113.42",
		TailscaleIP: "100.64.0.42",
		Runtime:     &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
	}
	repoRemote := "git@example.com:org/repo.git"
	expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
		RunID:      "auto-output-summary",
		RepoPath:   projectDir,
		RepoRemote: repoRemote,
		BranchName: "feature/auto-sandbox",
		BaseBranch: "main",
	})
	driver := fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			script := ""
			if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
				script = got.Args[2]
			}
			switch {
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "workspace.patch"):
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "reports.tar"):
			default:
				_, _ = io.WriteString(got.Stdout, `{"contractVersion":2,"ok":true,"entryMode":"report_discovery","resumed":false,"steps":{},"summary":"remote"}`+"\n")
				_, _ = io.WriteString(got.Stderr, "warning from 203.0.113.42\n")
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
		copyOut: func(_ context.Context, got sandboxruntime.CopyRequest) error {
			if err := os.MkdirAll(filepath.Dir(got.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(got.DestinationPath, []byte("payload for "+got.SourcePath), 0o600)
		},
	}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
		Base:        "main",
		BaseChanged: true,
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, autoSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "auto-output-summary"
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
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return driver, nil
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
	var result AutoResult
	decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
	if !result.OK || result.Summary != "remote" {
		t.Fatalf("AutoResult = %#v, want ok remote summary", result)
	}

	manifest, err := store.LoadManifest("auto-output-summary")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want succeeded", manifest.Status)
	}
	if len(manifest.Artifacts) != 0 {
		t.Fatalf("legacy Artifacts = %#v, want unchanged empty top-level artifacts", manifest.Artifacts)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil, want output summary metadata")
	}
	collected := map[string]sandboxexecution.ArtifactMetadataEntry{}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		collected[artifact.Path] = artifact
	}
	assertRunSandboxCollectedArtifact(t, collected["output/stdout-summary.txt"], "output/stdout-summary.txt", "auto-output-summary/artifacts/output/stdout-summary.txt")
	assertRunSandboxCollectedArtifact(t, collected["output/stderr-summary.txt"], "output/stderr-summary.txt", "auto-output-summary/artifacts/output/stderr-summary.txt")
	stdoutPayload := readRunSandboxStoreFile(t, store, collected["output/stdout-summary.txt"].StoredPath)
	if stdoutPayload != `{"contractVersion":2,"ok":true,"entryMode":"report_discovery","resumed":false,"steps":{},"summary":"remote"}`+"\n" {
		t.Fatalf("stdout summary payload = %q, want remote JSON summary", stdoutPayload)
	}
	stderrPayload := readRunSandboxStoreFile(t, store, collected["output/stderr-summary.txt"].StoredPath)
	if strings.Contains(stderrPayload, "203.0.113.42") {
		t.Fatalf("stderr summary payload leaked sandbox address: %q", stderrPayload)
	}
	if !strings.Contains(stderrPayload, "<address redacted>") {
		t.Fatalf("stderr summary payload = %q, want redacted address marker", stderrPayload)
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

func autoSandboxRemoteSuccessJSON(summary string) string {
	return `{"contractVersion":2,"ok":true,"entryMode":"report_discovery","resumed":false,"steps":{"analyze":{"status":"completed"},"spec":{"status":"completed"},"branch":{"status":"completed"},"convert":{"status":"completed"},"validate":{"status":"completed"},"run":{"status":"completed"},"review":{"status":"skipped"},"report":{"status":"completed"},"ci":{"status":"skipped"},"archive":{"status":"skipped"}},"summary":"` + summary + `"}`
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
