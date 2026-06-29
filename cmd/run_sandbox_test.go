package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/spf13/cobra"
)

func TestParseRunSandboxRequestArgumentContract(t *testing.T) {
	tests := []struct {
		name            string
		args            []string
		opts            runSandboxOptions
		wantIterations  int
		wantSandboxName string
		wantErr         string
	}{
		{
			name:           "no args uses default iterations",
			wantIterations: 10,
		},
		{
			name:           "numeric positional means iterations",
			args:           []string{"3"},
			wantIterations: 3,
		},
		{
			name:            "non-numeric positional means sandbox name",
			args:            []string{"dev-box"},
			wantIterations:  10,
			wantSandboxName: "dev-box",
		},
		{
			name: "sandbox-name flag sets sandbox name",
			opts: runSandboxOptions{
				SandboxName:        "named-box",
				SandboxNameChanged: true,
			},
			wantIterations:  10,
			wantSandboxName: "named-box",
		},
		{
			name: "positional name conflicts with sandbox-name flag",
			args: []string{"dev-box"},
			opts: runSandboxOptions{
				SandboxName:        "named-box",
				SandboxNameChanged: true,
			},
			wantErr: "sandbox name provided both positionally and via --sandbox-name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseRunSandboxRequest(tt.args, tt.opts)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatal("parseRunSandboxRequest() error = nil")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseRunSandboxRequest() error = %q, want %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRunSandboxRequest() unexpected error: %v", err)
			}
			if got.Iterations != tt.wantIterations {
				t.Fatalf("Iterations = %d, want %d", got.Iterations, tt.wantIterations)
			}
			if got.SandboxName != tt.wantSandboxName {
				t.Fatalf("SandboxName = %q, want %q", got.SandboxName, tt.wantSandboxName)
			}
		})
	}
}

func TestBuildRunSandboxRemoteCommandPreservesRunFlags(t *testing.T) {
	req, err := parseRunSandboxRequest([]string{"7"}, runSandboxOptions{
		Engine:             "codex",
		EngineChanged:      true,
		Base:               "main",
		BaseChanged:        true,
		JSON:               true,
		JSONChanged:        true,
		SandboxName:        "local-box",
		SandboxNameChanged: true,
	})
	if err != nil {
		t.Fatalf("parseRunSandboxRequest() unexpected error: %v", err)
	}

	want := []string{"hal", "run", "--json", "--engine", "codex", "--base", "main", "7"}
	if !reflect.DeepEqual(req.RemoteCommand, want) {
		t.Fatalf("RemoteCommand = %#v, want %#v", req.RemoteCommand, want)
	}

	joined := strings.Join(req.RemoteCommand, " ")
	for _, disallowed := range []string{"--sandbox", "--sandbox-name", "local-box"} {
		if strings.Contains(joined, disallowed) {
			t.Fatalf("RemoteCommand %q should not contain sandbox-only value %q", joined, disallowed)
		}
	}
}

func TestParseRunSandboxRequestRejectsEmptyExplicitEngine(t *testing.T) {
	_, err := parseRunSandboxRequest(nil, runSandboxOptions{
		EngineChanged: true,
		Engine:        " ",
	})
	if err == nil {
		t.Fatal("parseRunSandboxRequest() error = nil")
	}
	if !strings.Contains(err.Error(), "--engine must not be empty") {
		t.Fatalf("error = %q, want empty engine validation", err.Error())
	}
}

func TestRunRunSandboxWithWriterJSONPreRemotePreflightFailures(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 9, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)

	tests := []struct {
		name          string
		repoRemote    func(string) (string, error)
		currentBranch func(string) (string, error)
		wantError     string
	}{
		{
			name: "missing repository remote",
			repoRemote: func(string) (string, error) {
				return "", nil
			},
			currentBranch: func(string) (string, error) {
				t.Fatal("currentBranch should not run when repository remote is missing")
				return "", nil
			},
			wantError: "remote.origin.url is required for sandbox execution",
		},
		{
			name: "missing base branch",
			repoRemote: func(string) (string, error) {
				return "git@example.com:org/repo.git", nil
			},
			currentBranch: func(string) (string, error) {
				return "", nil
			},
			wantError: "current branch is required for sandbox execution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
			now := runSandboxTestClock(startedAt, finishedAt)
			var out bytes.Buffer
			var errOut bytes.Buffer
			executeCalled := false

			err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
				JSON:        true,
				JSONChanged: true,
			}, &out, &errOut, runSandboxDeps{
				defaultStore: func() (sandboxexecution.Store, error) {
					return store, nil
				},
				newExecutionID: func(time.Time) string {
					return "run-json-preflight"
				},
				now:           now,
				workingDir:    func() (string, error) { return t.TempDir(), nil },
				repoRemote:    tt.repoRemote,
				currentBranch: tt.currentBranch,
				execute: func(context.Context, runSandboxRequest, io.Writer, io.Writer, runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
					executeCalled = true
					return runSandboxExecutionResult{}, errors.New("execute should not run")
				},
			})
			if err != nil {
				t.Fatalf("runRunSandboxWithWriter() error = %v, want nil JSON error result", err)
			}
			if executeCalled {
				t.Fatal("execute should not be called for pre-remote preflight failure")
			}

			var result RunResult
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatalf("stdout is not parseable RunResult JSON: %v\n%s", err, out.String())
			}
			if result.ContractVersion != 1 || result.OK {
				t.Fatalf("RunResult = %#v, want contractVersion 1 and ok false", result)
			}
			if !strings.Contains(result.Error, tt.wantError) {
				t.Fatalf("RunResult.Error = %q, want %q", result.Error, tt.wantError)
			}
			if strings.TrimSpace(errOut.String()) != "" {
				t.Fatalf("stderr = %q, want empty for JSON preflight failure", errOut.String())
			}

			manifest, err := store.LoadManifest("run-json-preflight")
			if err != nil {
				t.Fatalf("LoadManifest() error: %v", err)
			}
			if manifest.Purpose != sandboxexecution.PurposeRun {
				t.Fatalf("Purpose = %q, want %q", manifest.Purpose, sandboxexecution.PurposeRun)
			}
			if manifest.Status != sandboxexecution.StatusFailed {
				t.Fatalf("Status = %q, want %q", manifest.Status, sandboxexecution.StatusFailed)
			}
			if manifest.FinishedAt == nil || !manifest.FinishedAt.Equal(finishedAt) {
				t.Fatalf("FinishedAt = %v, want %v", manifest.FinishedAt, finishedAt)
			}
		})
	}
}

func TestRunRunSandboxWithWriterWorkspacePlannerPreflightFailures(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 9, 15, 0, 0, time.UTC)
	finishedAt := startedAt.Add(2 * time.Second)

	tests := []struct {
		name      string
		status    sandboxworkspace.GitStatus
		wantError string
	}{
		{
			name: "dirty clone workspace",
			status: sandboxworkspace.GitStatus{
				IsGitWorktree: true,
				Repository:    "git@example.com:org/repo.git",
				Branch:        "feature/dirty",
				Dirty:         sandboxworkspace.DirtyState{Unstaged: true},
			},
			wantError: "dirty worktree",
		},
		{
			name: "git bundle required",
			status: sandboxworkspace.GitStatus{
				IsGitWorktree: true,
				Repository:    "git@example.com:org/repo.git",
				Branch:        "feature/unpushed",
				HeadRef:       "abc123",
			},
			wantError: "git bundle workspace input is not implemented",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
			var out bytes.Buffer
			var errOut bytes.Buffer
			executeCalled := false

			err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
				JSON:        true,
				JSONChanged: true,
			}, &out, &errOut, runSandboxDeps{
				defaultStore: func() (sandboxexecution.Store, error) {
					return store, nil
				},
				newExecutionID: func(time.Time) string {
					return "run-workspace-preflight"
				},
				now:        runSandboxTestClock(startedAt, finishedAt),
				workingDir: func() (string, error) { return t.TempDir(), nil },
				planWorkspace: func(ctx context.Context, req sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
					return sandboxworkspace.Planner{Git: fakeRunSandboxGitInspector{status: tt.status}}.Plan(ctx, req)
				},
				execute: func(context.Context, runSandboxRequest, io.Writer, io.Writer, runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
					executeCalled = true
					return runSandboxExecutionResult{}, errors.New("execute should not run")
				},
			})
			if err != nil {
				t.Fatalf("runRunSandboxWithWriter() error = %v, want nil JSON error result", err)
			}
			if executeCalled {
				t.Fatal("execute should not run after workspace preflight failure")
			}
			var result RunResult
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatalf("stdout is not parseable RunResult JSON: %v\n%s", err, out.String())
			}
			if !strings.Contains(result.Error, tt.wantError) {
				t.Fatalf("RunResult.Error = %q, want %q", result.Error, tt.wantError)
			}
			manifest, err := store.LoadManifest("run-workspace-preflight")
			if err != nil {
				t.Fatalf("LoadManifest() error: %v", err)
			}
			if manifest.Status != sandboxexecution.StatusFailed {
				t.Fatalf("Status = %q, want failed", manifest.Status)
			}
		})
	}
}

func TestRunRunSandboxWithWriterJSONPreRemoteExecutionFailureIncludesTargetMetadata(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 9, 30, 0, 0, time.UTC)
	finishedAt := startedAt.Add(3 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		Name:     "stopped-box",
		Provider: "test-provider",
		Status:   sandbox.StatusStopped,
		Host:     &sandbox.SandboxHost{ID: "host-start", Name: "worker-start"},
		Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine, RuntimeID: "runtime-start"},
	}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-start-failure"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/start-failure", nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		startSandbox: func(_ context.Context, got *sandbox.SandboxState, stdout io.Writer) (*sandbox.SandboxState, error) {
			if got != target {
				t.Fatalf("start target = %#v, want original target", got)
			}
			if _, err := io.WriteString(stdout, "starting sandbox\n"); err != nil {
				return nil, err
			}
			return nil, errors.New("start failed")
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			t.Fatal("resolveProvider should not run after start failure")
			return nil, nil
		},
		runProviderCommand: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer, io.Writer) error {
			t.Fatal("runProviderCommand should not run after start failure")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() error = %v, want nil JSON error result", err)
	}
	var result RunResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not parseable RunResult JSON: %v\n%s", err, out.String())
	}
	if !strings.Contains(result.Error, "start failed") {
		t.Fatalf("RunResult.Error = %q, want start failure", result.Error)
	}
	if !strings.Contains(errOut.String(), "starting sandbox") {
		t.Fatalf("stderr = %q, want start output routed to stderr", errOut.String())
	}

	manifest, err := store.LoadManifest("run-start-failure")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("Status = %q, want failed", manifest.Status)
	}
	if manifest.SandboxName != "stopped-box" {
		t.Fatalf("SandboxName = %q, want stopped-box", manifest.SandboxName)
	}
	if manifest.Host == nil || manifest.Host.ID != "host-start" {
		t.Fatalf("Host = %#v, want phase-error target host metadata", manifest.Host)
	}
	if manifest.Runtime == nil || manifest.Runtime.RuntimeID != "runtime-start" {
		t.Fatalf("Runtime = %#v, want phase-error target runtime metadata", manifest.Runtime)
	}
}

func TestRunRunSandboxWithWriterJSONProviderSetupFailureSynthesizesRunResult(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 9, 45, 0, 0, time.UTC)
	finishedAt := startedAt.Add(3 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "ready-box", Provider: "test-provider", Status: sandbox.StatusRunning}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-provider-setup-failure"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/provider-setup-failure", nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
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
		runProviderCommand: func(context.Context, sandbox.Provider, *sandbox.ConnectInfo, []string, map[string]string, io.Writer, io.Writer) error {
			return errors.New("provider exec setup failed")
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() error = %v, want nil JSON error result", err)
	}
	var result RunResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not parseable RunResult JSON: %v\n%s", err, out.String())
	}
	if !strings.Contains(result.Error, "provider exec setup failed") {
		t.Fatalf("RunResult.Error = %q, want provider setup failure", result.Error)
	}
}

func TestRunRunSandboxWithWriterJSONRemoteOutputPassesThroughAfterStdout(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 9, 50, 0, 0, time.UTC)
	finishedAt := startedAt.Add(3 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "ready-box", Provider: "test-provider", Status: sandbox.StatusRunning}
	var out bytes.Buffer
	var errOut bytes.Buffer

	err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-remote-json-pass-through"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/remote-json", nil },
		resolveDefault: func(func(*sandbox.SandboxState) bool) (*sandbox.SandboxState, string, error) {
			return target, target.Name, nil
		},
		resolveProvider: func(string) (sandbox.Provider, error) {
			return fakeFactorySandboxProvider{}, nil
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
		runProviderCommand: func(_ context.Context, _ sandbox.Provider, _ *sandbox.ConnectInfo, _ []string, _ map[string]string, stdout, _ io.Writer) error {
			_, _ = io.WriteString(stdout, `{"contractVersion":1,"ok":false,"summary":"remote"}`+"\n")
			return errors.New("remote failed after writing json")
		},
	})
	if err == nil {
		t.Fatal("expected remote command error after stdout pass-through, got nil")
	}
	if !strings.Contains(err.Error(), "remote failed after writing json") {
		t.Fatalf("error = %q, want remote failure", err.Error())
	}
	var result RunResult
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not parseable remote RunResult JSON: %v\n%s", err, out.String())
	}
	if result.Summary != "remote" {
		t.Fatalf("Summary = %q, want remote", result.Summary)
	}
	if strings.Contains(out.String(), "remote failed after writing json") {
		t.Fatalf("stdout contains synthesized local error: %s", out.String())
	}
}

func TestRunRunSandboxWithWriterSuccessfulExecutorUpdatesManifest(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 10, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(5 * time.Second)
	projectDir := t.TempDir()
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{
		ID:       "sandbox-123",
		Name:     "ready-box",
		Provider: "test-provider",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:   "host-1",
			Name: "worker-1",
			Kind: sandbox.SandboxHostKindSSH,
			Labels: map[string]string{
				"role": "test",
			},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverSSHMachine,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "runtime-1",
			Image:          "hal:test",
			WorkerID:       "worker-1",
		},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeBestEffort,
			},
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
				ActiveModes:    []string{sandbox.SandboxSecretModeHTTPProxy},
			},
		},
	}

	var captured runSandboxRequest
	var out bytes.Buffer
	var errOut bytes.Buffer
	err := runRunSandboxWithWriter(context.Background(), nil, []string{"2"}, runSandboxOptions{
		Base:        "main",
		BaseChanged: true,
		JSON:        true,
		JSONChanged: true,
	}, &out, &errOut, runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-success-manifest"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return projectDir, nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/sandbox-run", nil },
		execute: func(_ context.Context, req runSandboxRequest, _ io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			running, err := store.LoadManifest("run-success-manifest")
			if err != nil {
				t.Fatalf("LoadManifest() before executor target ready: %v", err)
			}
			if running.Status != sandboxexecution.StatusRunning {
				t.Fatalf("pre-execute Status = %q, want running", running.Status)
			}
			if running.Workspace == nil || running.Workspace.Mode != sandbox.SandboxWorkspaceModeClone {
				t.Fatalf("pre-execute Workspace = %#v, want clone metadata", running.Workspace)
			}
			captured = req
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return runSandboxExecutionResult{}, err
				}
			}
			return runSandboxExecutionResult{
				Result: &sandboxexec.Result{Target: target},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}

	manifest, err := store.LoadManifest("run-success-manifest")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Purpose != sandboxexecution.PurposeRun {
		t.Fatalf("Purpose = %q, want %q", manifest.Purpose, sandboxexecution.PurposeRun)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want %q", manifest.Status, sandboxexecution.StatusSucceeded)
	}
	if manifest.SandboxName != "ready-box" {
		t.Fatalf("SandboxName = %q, want ready-box", manifest.SandboxName)
	}
	if manifest.ProjectDir != projectDir {
		t.Fatalf("ProjectDir = %q, want %q", manifest.ProjectDir, projectDir)
	}
	wantCommand := []string{"hal", "run", "--json", "--base", "main", "2"}
	if !reflect.DeepEqual(manifest.Command, wantCommand) {
		t.Fatalf("Command = %#v, want %#v", manifest.Command, wantCommand)
	}
	if manifest.WorkDir == "" || manifest.WorkDir != captured.WorkDir {
		t.Fatalf("WorkDir = %q, captured %q", manifest.WorkDir, captured.WorkDir)
	}
	if manifest.FinishedAt == nil || !manifest.FinishedAt.Equal(finishedAt) {
		t.Fatalf("FinishedAt = %v, want %v", manifest.FinishedAt, finishedAt)
	}
	if manifest.Workspace == nil {
		t.Fatal("Workspace = nil")
	}
	if manifest.Workspace.Mode != sandbox.SandboxWorkspaceModeClone ||
		manifest.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceRemoteRef ||
		manifest.Workspace.Repo != "git@example.com:org/repo.git" ||
		manifest.Workspace.Branch != "feature/sandbox-run" ||
		manifest.Workspace.SyncRef != "main" {
		t.Fatalf("Workspace = %#v, want remote clone of feature/sandbox-run from main", manifest.Workspace)
	}
	if manifest.Host == nil || manifest.Host.ID != "host-1" || manifest.Host.Labels["role"] != "test" {
		t.Fatalf("Host = %#v, want copied target host metadata", manifest.Host)
	}
	if manifest.Runtime == nil || manifest.Runtime.RuntimeID != "runtime-1" {
		t.Fatalf("Runtime = %#v, want copied target runtime metadata", manifest.Runtime)
	}
	if manifest.Security == nil || manifest.Security.Network == nil || manifest.Security.Secrets == nil {
		t.Fatalf("Security = %#v, want copied target security metadata", manifest.Security)
	}
	if !reflect.DeepEqual(manifest.Security.Secrets.ActiveModes, []string{sandbox.SandboxSecretModeHTTPProxy}) {
		t.Fatalf("ActiveModes = %#v, want http_proxy", manifest.Security.Secrets.ActiveModes)
	}
}

func TestRunRunWithWriterSandboxFlagDispatchesToSandboxExecutor(t *testing.T) {
	startedAt := time.Date(2026, 6, 30, 11, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Second)
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	target := &sandbox.SandboxState{Name: "flag-box", Provider: "test-provider", Status: sandbox.StatusRunning}
	var captured runSandboxRequest
	var out bytes.Buffer
	var errOut bytes.Buffer

	originalDeps := defaultRunSandboxDeps
	defaultRunSandboxDeps = runSandboxDeps{
		defaultStore: func() (sandboxexecution.Store, error) {
			return store, nil
		},
		newExecutionID: func(time.Time) string {
			return "run-flag-dispatch"
		},
		now:           runSandboxTestClock(startedAt, finishedAt),
		workingDir:    func() (string, error) { return t.TempDir(), nil },
		repoRemote:    func(string) (string, error) { return "git@example.com:org/repo.git", nil },
		currentBranch: func(string) (string, error) { return "feature/flag-dispatch", nil },
		execute: func(_ context.Context, req runSandboxRequest, _ io.Writer, _ io.Writer, hooks runSandboxExecutionHooks) (runSandboxExecutionResult, error) {
			captured = req
			if hooks.OnTargetReady != nil {
				if err := hooks.OnTargetReady(target); err != nil {
					return runSandboxExecutionResult{}, err
				}
			}
			return runSandboxExecutionResult{Result: &sandboxexec.Result{Target: target}}, nil
		},
	}
	t.Cleanup(func() {
		defaultRunSandboxDeps = originalDeps
	})

	cmd := newRunSandboxTestCommand(&out, &errOut)
	for flag, value := range map[string]string{
		"sandbox":      "true",
		"sandbox-name": "flag-box",
		"json":         "true",
		"engine":       "codex-test",
		"base":         "main",
		"dry-run":      "true",
	} {
		if err := cmd.Flags().Set(flag, value); err != nil {
			t.Fatalf("set %s: %v", flag, err)
		}
	}

	if err := runRunWithWriter(cmd, []string{"4"}, &errOut); err != nil {
		t.Fatalf("runRunWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
	}

	if captured.SandboxName != "flag-box" {
		t.Fatalf("SandboxName = %q, want flag-box", captured.SandboxName)
	}
	wantCommand := []string{"hal", "run", "--json", "--engine", "codex-test", "--dry-run", "--base", "main", "4"}
	if !reflect.DeepEqual(captured.RemoteCommand, wantCommand) {
		t.Fatalf("RemoteCommand = %#v, want %#v", captured.RemoteCommand, wantCommand)
	}
	manifest, err := store.LoadManifest("run-flag-dispatch")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("Status = %q, want %q", manifest.Status, sandboxexecution.StatusSucceeded)
	}
}

func TestRunSandboxCmdContextSplitsStdoutAndStderr(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err := runSandboxCmdContext(context.Background(), exec.Command("sh", "-c", "printf stdout; printf stderr >&2"), &stdout, &stderr)
	if err != nil {
		t.Fatalf("runSandboxCmdContext() unexpected error: %v", err)
	}
	if stdout.String() != "stdout" {
		t.Fatalf("stdout = %q, want stdout", stdout.String())
	}
	if stderr.String() != "stderr" {
		t.Fatalf("stderr = %q, want stderr", stderr.String())
	}
}

func newRunSandboxTestCommand(out, errOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{Use: "run"}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.Flags().String("engine", "codex", "")
	cmd.Flags().Int("iterations", 10, "")
	cmd.Flags().String("base", "", "")
	cmd.Flags().Int("retries", 3, "")
	cmd.Flags().Duration("retry-delay", 5*time.Second, "")
	cmd.Flags().Duration("timeout", 0, "")
	cmd.Flags().Bool("dry-run", false, "")
	cmd.Flags().String("story", "", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().Bool("sandbox", false, "")
	cmd.Flags().String("sandbox-name", "", "")
	return cmd
}

func runSandboxTestClock(times ...time.Time) func() time.Time {
	return func() time.Time {
		if len(times) == 0 {
			return time.Time{}
		}
		next := times[0]
		if len(times) > 1 {
			times = times[1:]
		}
		return next
	}
}

type fakeRunSandboxGitInspector struct {
	status sandboxworkspace.GitStatus
	err    error
}

func (f fakeRunSandboxGitInspector) InspectGit(context.Context, string) (sandboxworkspace.GitStatus, error) {
	return f.status, f.err
}
