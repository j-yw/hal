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
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/spf13/cobra"
)

func TestSandboxRunAutoDefaultDoesNotMutateHostWorktree(t *testing.T) {
	t.Run("default deps leave apply hook disabled", func(t *testing.T) {
		if apply := normalizeRunSandboxDeps(runSandboxDeps{}).applySyncOut; apply != nil {
			t.Fatal("run sandbox default applySyncOut is non-nil, want disabled until explicit opt-in")
		}
		if apply := normalizeAutoSandboxDeps(autoSandboxDeps{}).applySyncOut; apply != nil {
			t.Fatal("auto sandbox default applySyncOut is non-nil, want disabled until explicit opt-in")
		}
	})

	t.Run("injected apply hook still requires explicit sync-out intent", func(t *testing.T) {
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
		fatalApply := func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
			t.Fatal("applySyncOut ran without explicit sync-out/apply intent")
			return sandboxworkspace.SafeApplyResult{}, nil
		}
		if err := applyRunSandboxSyncOut(context.Background(), store, runSandboxRequest{}, runSandboxDeps{applySyncOut: fatalApply}); err != nil {
			t.Fatalf("applyRunSandboxSyncOut() error = %v, want nil", err)
		}
		if err := applyAutoSandboxSyncOut(context.Background(), store, autoSandboxRequest{}, autoSandboxDeps{applySyncOut: fatalApply}); err != nil {
			t.Fatalf("applyAutoSandboxSyncOut() error = %v, want nil", err)
		}
	})

	t.Run("run", func(t *testing.T) {
		startedAt := time.Date(2026, 7, 2, 1, 10, 0, 0, time.UTC)
		finishedAt := startedAt.Add(5 * time.Second)
		projectDir := t.TempDir()
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
		target := &sandbox.SandboxState{
			Name:     "default-no-apply-run",
			Provider: "test-provider",
			Status:   sandbox.StatusRunning,
			Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
		}
		plan := sandboxworkspace.Plan{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			ProjectDir:  projectDir,
			Repository:  "git@example.com:org/repo.git",
			Branch:      "feature/default-no-apply-run",
			Upstream:    "origin/feature/default-no-apply-run",
			SyncRef:     "refs/remotes/origin/feature/default-no-apply-run",
		}
		expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
			RunID:      "run-default-no-apply",
			RepoPath:   projectDir,
			RepoRemote: plan.Repository,
			BranchName: plan.Branch,
			BaseBranch: "main",
		})
		var order []string
		driver := sandboxApplyOrderRuntimeDriver(t, expectedWorkspace, &order, `{"contractVersion":1,"ok":true,"summary":"remote"}`+"\n")
		var out bytes.Buffer
		var errOut bytes.Buffer

		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			Base:        "main",
			BaseChanged: true,
			JSON:        true,
			JSONChanged: true,
		}, &out, &errOut, runSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) {
				return store, nil
			},
			newExecutionID: func(time.Time) string {
				return "run-default-no-apply"
			},
			now:        runSandboxTestClock(startedAt, finishedAt),
			workingDir: func() (string, error) { return projectDir, nil },
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
				return driver, nil
			},
			bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
				return factory.BootstrapResult{}, nil
			},
			engineAuthFiles: func() []factorySandboxAuthFile {
				return nil
			},
		})
		if err != nil {
			t.Fatalf("runRunSandboxWithWriter() unexpected error: %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
		}
		assertSandboxApplyOrder(t, order, []string{
			"remote_run",
			"copy_core_prd",
			"copy_core_progress",
			"recovery_generation",
			"copy_recovery",
			"reports_generation",
			"copy_reports",
		})
		manifest := mustLoadSandboxExecutionManifest(t, store, "run-default-no-apply")
		assertDefaultSandboxManifestArtifacts(t, manifest, []string{
			".hal/prd.json",
			".hal/progress.txt",
			".hal/recovery/workspace.patch",
			".hal/reports.tar",
			"output/stdout-summary.txt",
		})
		assertDefaultSandboxManifestOmitsSyncOutApplyFields(t, manifest)
	})

	t.Run("auto", func(t *testing.T) {
		startedAt := time.Date(2026, 7, 2, 1, 15, 0, 0, time.UTC)
		finishedAt := startedAt.Add(5 * time.Second)
		projectDir := t.TempDir()
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
		target := &sandbox.SandboxState{
			Name:     "default-no-apply-auto",
			Provider: "test-provider",
			Status:   sandbox.StatusRunning,
			Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
		}
		plan := autoSandboxTestPlan(projectDir)
		expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
			RunID:      "auto-default-no-apply",
			RepoPath:   projectDir,
			RepoRemote: plan.Repository,
			BranchName: plan.Branch,
			BaseBranch: "main",
		})
		var order []string
		driver := sandboxApplyOrderRuntimeDriver(t, expectedWorkspace, &order, autoSandboxRemoteSuccessJSON("remote")+"\n")
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
				return "auto-default-no-apply"
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
		assertSandboxApplyOrder(t, order, []string{
			"remote_run",
			"copy_core_prd",
			"copy_core_progress",
			"copy_core_auto_state",
			"recovery_generation",
			"copy_recovery",
			"reports_generation",
			"copy_reports",
		})
		manifest := mustLoadSandboxExecutionManifest(t, store, "auto-default-no-apply")
		assertDefaultSandboxManifestArtifacts(t, manifest, []string{
			".hal/prd.json",
			".hal/progress.txt",
			".hal/auto-state.json",
			".hal/recovery/workspace.patch",
			".hal/reports.tar",
			"output/stdout-summary.txt",
		})
		assertDefaultSandboxManifestOmitsSyncOutApplyFields(t, manifest)
	})
}

func TestSandboxSyncOutApplyFlagsAreExplicitAndScoped(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command *cobra.Command
	}{
		{name: "run", command: runCmd},
		{name: "auto", command: autoCmd},
	} {
		t.Run(tc.name+" flags", func(t *testing.T) {
			syncOutFlag := tc.command.Flags().Lookup(sandboxSyncOutFlagName)
			if syncOutFlag == nil {
				t.Fatalf("%s command missing --%s flag", tc.name, sandboxSyncOutFlagName)
			}
			if !strings.Contains(syncOutFlag.Usage, "sync-out") || !strings.Contains(syncOutFlag.Usage, "without applying") {
				t.Fatalf("--%s usage = %q, want sync-out without apply guidance", sandboxSyncOutFlagName, syncOutFlag.Usage)
			}

			applyFlag := tc.command.Flags().Lookup(sandboxApplyFlagName)
			if applyFlag == nil {
				t.Fatalf("%s command missing --%s flag", tc.name, sandboxApplyFlagName)
			}
			if !strings.Contains(applyFlag.Usage, "explicit opt-in") || !strings.Contains(applyFlag.Usage, "host worktree") {
				t.Fatalf("--%s usage = %q, want explicit opt-in host apply guidance", sandboxApplyFlagName, applyFlag.Usage)
			}
		})
	}

	t.Run("factory run remains decoupled", func(t *testing.T) {
		if flag := factoryRunCmd.Flags().Lookup(sandboxSyncOutFlagName); flag != nil {
			t.Fatalf("factory run unexpectedly has --%s flag", sandboxSyncOutFlagName)
		}
		if flag := factoryRunCmd.Flags().Lookup(sandboxApplyFlagName); flag != nil {
			t.Fatalf("factory run unexpectedly has --%s flag", sandboxApplyFlagName)
		}
	})

	t.Run("flags require sandbox mode", func(t *testing.T) {
		err := validateSandboxSyncOutFlagsRequireSandbox(false, sandboxSyncOutFlagValues{
			SyncOutChanged: true,
			ApplyChanged:   true,
		})
		if err == nil {
			t.Fatal("validateSandboxSyncOutFlagsRequireSandbox() error = nil")
		}
		if want := "--sandbox-sync-out and --sandbox-apply require --sandbox"; !strings.Contains(err.Error(), want) {
			t.Fatalf("validation error = %q, want %q", err.Error(), want)
		}
		if err := validateSandboxSyncOutFlagsRequireSandbox(true, sandboxSyncOutFlagValues{ApplyChanged: true}); err != nil {
			t.Fatalf("validateSandboxSyncOutFlagsRequireSandbox() with sandbox error = %v, want nil", err)
		}
	})

	t.Run("run request records local intent without forwarding it", func(t *testing.T) {
		req, err := parseRunSandboxRequest([]string{"2"}, runSandboxOptions{
			Base:                  "main",
			BaseChanged:           true,
			SandboxName:           "sync-run",
			SandboxNameChanged:    true,
			SandboxSyncOut:        true,
			SandboxSyncOutChanged: true,
			SandboxApply:          true,
			SandboxApplyChanged:   true,
		})
		if err != nil {
			t.Fatalf("parseRunSandboxRequest() unexpected error: %v", err)
		}
		if !req.SyncOut.Enabled || !req.SyncOut.Apply {
			t.Fatalf("run sync-out options = %#v, want enabled apply intent", req.SyncOut)
		}
		assertSandboxRemoteCommandOmitsSyncOutApplyFlags(t, req.RemoteCommand)
	})

	t.Run("auto request records local intent without forwarding it", func(t *testing.T) {
		req, err := parseAutoSandboxRequest([]string{".hal/prd.md"}, autoSandboxOptions{
			Base:                  "main",
			BaseChanged:           true,
			SandboxName:           "sync-auto",
			SandboxNameChanged:    true,
			SandboxSyncOut:        true,
			SandboxSyncOutChanged: true,
			SandboxApply:          true,
			SandboxApplyChanged:   true,
		})
		if err != nil {
			t.Fatalf("parseAutoSandboxRequest() unexpected error: %v", err)
		}
		if !req.SyncOut.Enabled || !req.SyncOut.Apply {
			t.Fatalf("auto sync-out options = %#v, want enabled apply intent", req.SyncOut)
		}
		assertSandboxRemoteCommandOmitsSyncOutApplyFlags(t, req.RemoteCommand)
	})
}

func TestSandboxApplyPersistsRecoveryBeforeHostMutation(t *testing.T) {
	t.Run("run", func(t *testing.T) {
		startedAt := time.Date(2026, 7, 2, 1, 0, 0, 0, time.UTC)
		finishedAt := startedAt.Add(5 * time.Second)
		projectDir := t.TempDir()
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
		target := &sandbox.SandboxState{
			Name:     "apply-order-run",
			Provider: "test-provider",
			Status:   sandbox.StatusRunning,
			Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
		}
		plan := sandboxworkspace.Plan{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			ProjectDir:  projectDir,
			Repository:  "git@example.com:org/repo.git",
			Branch:      "feature/apply-order-run",
			Upstream:    "origin/feature/apply-order-run",
			SyncRef:     "refs/remotes/origin/feature/apply-order-run",
		}
		expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
			RunID:      "run-apply-order",
			RepoPath:   projectDir,
			RepoRemote: plan.Repository,
			BranchName: plan.Branch,
			BaseBranch: "main",
		})
		applyErr := errors.New("host apply failed")
		var order []string
		driver := sandboxApplyOrderRuntimeDriver(t, expectedWorkspace, &order, `{"contractVersion":1,"ok":true,"summary":"remote"}`+"\n")
		var out bytes.Buffer
		var errOut bytes.Buffer

		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			Base:                "main",
			BaseChanged:         true,
			JSON:                true,
			JSONChanged:         true,
			SandboxApply:        true,
			SandboxApplyChanged: true,
		}, &out, &errOut, runSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) {
				return store, nil
			},
			newExecutionID: func(time.Time) string {
				return "run-apply-order"
			},
			now:        runSandboxTestClock(startedAt, finishedAt),
			workingDir: func() (string, error) { return projectDir, nil },
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
				return driver, nil
			},
			bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
				return factory.BootstrapResult{}, nil
			},
			engineAuthFiles: func() []factorySandboxAuthFile {
				return nil
			},
			applySyncOut: func(_ context.Context, got sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
				order = append(order, "host_apply")
				assertSandboxSyncOutApplyRequestHasDurableArtifacts(t, got, store, "run-apply-order", sandboxexecution.PurposeRun, projectDir, []string{
					".hal/prd.json",
					".hal/progress.txt",
				})
				return sandboxworkspace.SafeApplyResult{Status: sandboxworkspace.SafeApplyStatusHandoffRequired}, applyErr
			},
		})
		if !errors.Is(err, applyErr) {
			t.Fatalf("runRunSandboxWithWriter() error = %v, want apply error", err)
		}
		wantOrder := []string{"remote_run", "copy_core_prd", "copy_core_progress", "recovery_generation", "copy_recovery", "reports_generation", "copy_reports", "host_apply"}
		assertSandboxApplyOrder(t, order, wantOrder)
		assertSandboxFinalManifestRetainsRecovery(t, store, "run-apply-order")
	})

	t.Run("auto", func(t *testing.T) {
		startedAt := time.Date(2026, 7, 2, 1, 5, 0, 0, time.UTC)
		finishedAt := startedAt.Add(5 * time.Second)
		projectDir := t.TempDir()
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
		target := &sandbox.SandboxState{
			Name:     "apply-order-auto",
			Provider: "test-provider",
			Status:   sandbox.StatusRunning,
			Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
		}
		plan := autoSandboxTestPlan(projectDir)
		expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
			RunID:      "auto-apply-order",
			RepoPath:   projectDir,
			RepoRemote: plan.Repository,
			BranchName: plan.Branch,
			BaseBranch: "main",
		})
		applyErr := errors.New("host apply failed")
		var order []string
		driver := sandboxApplyOrderRuntimeDriver(t, expectedWorkspace, &order, autoSandboxRemoteSuccessJSON("remote")+"\n")
		var out bytes.Buffer
		var errOut bytes.Buffer

		err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			Base:                "main",
			BaseChanged:         true,
			JSON:                true,
			JSONChanged:         true,
			SandboxApply:        true,
			SandboxApplyChanged: true,
		}, &out, &errOut, autoSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) {
				return store, nil
			},
			newExecutionID: func(time.Time) string {
				return "auto-apply-order"
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
			applySyncOut: func(_ context.Context, got sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
				order = append(order, "host_apply")
				assertSandboxSyncOutApplyRequestHasDurableArtifacts(t, got, store, "auto-apply-order", sandboxexecution.PurposeAuto, projectDir, []string{
					".hal/prd.json",
					".hal/progress.txt",
					".hal/auto-state.json",
				})
				return sandboxworkspace.SafeApplyResult{Status: sandboxworkspace.SafeApplyStatusHandoffRequired}, applyErr
			},
		})
		if !errors.Is(err, applyErr) {
			t.Fatalf("runAutoSandboxWithWriter() error = %v, want apply error", err)
		}
		wantOrder := []string{"remote_run", "copy_core_prd", "copy_core_progress", "copy_core_auto_state", "recovery_generation", "copy_recovery", "reports_generation", "copy_reports", "host_apply"}
		assertSandboxApplyOrder(t, order, wantOrder)
		assertSandboxFinalManifestRetainsRecovery(t, store, "auto-apply-order")
	})
}

func assertSandboxRemoteCommandOmitsSyncOutApplyFlags(t *testing.T, command []string) {
	t.Helper()
	joined := strings.Join(command, " ")
	for _, disallowed := range []string{"--" + sandboxSyncOutFlagName, "--" + sandboxApplyFlagName} {
		if strings.Contains(joined, disallowed) {
			t.Fatalf("RemoteCommand %q should not contain sandbox sync-out/apply flag %q", joined, disallowed)
		}
	}
}

func sandboxApplyOrderRuntimeDriver(t *testing.T, expectedWorkspace string, order *[]string, remoteStdout string) fakeRunSandboxRuntimeDriver {
	t.Helper()
	return fakeRunSandboxRuntimeDriver{
		exec: func(_ context.Context, got sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
			script := ""
			if len(got.Args) >= 3 && got.Args[0] == "sh" && got.Args[1] == "-c" {
				script = got.Args[2]
			}
			switch {
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "workspace.patch"):
				*order = append(*order, "recovery_generation")
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "reports.tar"):
				*order = append(*order, "reports_generation")
			default:
				*order = append(*order, "remote_run")
				if _, err := io.WriteString(got.Stdout, remoteStdout); err != nil {
					return nil, err
				}
			}
			return &sandboxruntime.ExecResult{ExitCode: 0}, nil
		},
		copyOut: func(_ context.Context, got sandboxruntime.CopyRequest) error {
			*order = append(*order, sandboxApplyOrderCopyLabel(got.SourcePath))
			if err := os.MkdirAll(filepath.Dir(got.DestinationPath), 0o700); err != nil {
				return err
			}
			return os.WriteFile(got.DestinationPath, []byte("payload for "+got.SourcePath), 0o600)
		},
	}
}

func sandboxApplyOrderCopyLabel(sourcePath string) string {
	switch {
	case strings.HasSuffix(sourcePath, "/.hal/prd.json"):
		return "copy_core_prd"
	case strings.HasSuffix(sourcePath, "/.hal/progress.txt"):
		return "copy_core_progress"
	case strings.HasSuffix(sourcePath, "/.hal/auto-state.json"):
		return "copy_core_auto_state"
	case strings.HasSuffix(sourcePath, "/.hal/recovery/workspace.patch"):
		return "copy_recovery"
	case strings.HasSuffix(sourcePath, "/.hal/reports.tar"):
		return "copy_reports"
	default:
		return "copy_unknown"
	}
}

func assertSandboxSyncOutApplyRequestHasDurableArtifacts(t *testing.T, got sandboxSyncOutApplyRequest, store sandboxexecution.Store, executionID string, purpose sandboxexecution.Purpose, projectDir string, corePaths []string) {
	t.Helper()
	if got.ExecutionID != executionID {
		t.Fatalf("apply request ExecutionID = %q, want %q", got.ExecutionID, executionID)
	}
	if got.Purpose != purpose {
		t.Fatalf("apply request Purpose = %q, want %q", got.Purpose, purpose)
	}
	if got.ProjectDir != projectDir {
		t.Fatalf("apply request ProjectDir = %q, want project dir", got.ProjectDir)
	}
	if !got.Options.Enabled || !got.Options.Apply {
		t.Fatalf("apply request Options = %#v, want explicit apply intent", got.Options)
	}
	if got.Store.Root() != store.Root() {
		t.Fatalf("apply request Store root = %q, want %q", got.Store.Root(), store.Root())
	}
	if got.Manifest == nil {
		t.Fatal("apply request Manifest = nil, want durable manifest")
	}
	if got.Manifest.Status != sandboxexecution.StatusRunning {
		t.Fatalf("apply request manifest Status = %q, want running before final command status", got.Manifest.Status)
	}
	if got.Manifest.ArtifactMetadata == nil {
		t.Fatal("apply request ArtifactMetadata = nil, want persisted core and recovery metadata")
	}
	for _, path := range corePaths {
		if !sandboxManifestHasCollectedPath(got.Manifest, path) {
			t.Fatalf("apply request manifest missing collected core path %q: %#v", path, got.Manifest.ArtifactMetadata.Collected)
		}
	}
	if !sandboxManifestHasCollectedPath(got.Manifest, ".hal/recovery/workspace.patch") {
		t.Fatalf("apply request manifest missing recovery patch: %#v", got.Manifest.ArtifactMetadata.Collected)
	}
	if got.Summary.Recovery.Status != sandboxworkspace.SyncOutRecoveryStatusCollected {
		t.Fatalf("sync-out recovery status = %q, want collected", got.Summary.Recovery.Status)
	}
	if len(got.Summary.Recovery.Artifacts) != 1 || got.Summary.Recovery.Artifacts[0].StoredPath == "" {
		t.Fatalf("sync-out recovery artifacts = %#v, want one durable recovery artifact", got.Summary.Recovery.Artifacts)
	}
	for _, path := range corePaths {
		if !sandboxSyncOutSummaryHasCorePath(got.Summary, path) {
			t.Fatalf("sync-out summary missing core path %q: %#v", path, got.Summary.CoreArtifacts)
		}
	}
}

func assertSandboxApplyOrder(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("order = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order = %#v, want %#v", got, want)
		}
	}
}

func assertSandboxFinalManifestRetainsRecovery(t *testing.T, store sandboxexecution.Store, executionID string) {
	t.Helper()
	manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
	if manifest.Status != sandboxexecution.StatusFailed {
		t.Fatalf("final manifest Status = %q, want failed after apply error", manifest.Status)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("final manifest ArtifactMetadata = nil, want durable recovery metadata retained")
	}
	if !sandboxManifestHasCollectedPath(manifest, ".hal/recovery/workspace.patch") {
		t.Fatalf("final manifest missing recovery patch: %#v", manifest.ArtifactMetadata.Collected)
	}
}

func mustLoadSandboxExecutionManifest(t *testing.T, store sandboxexecution.Store, executionID string) *sandboxexecution.Manifest {
	t.Helper()
	manifest, err := store.LoadManifest(executionID)
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	return manifest
}

func assertDefaultSandboxManifestArtifacts(t *testing.T, manifest *sandboxexecution.Manifest, paths []string) {
	t.Helper()
	if manifest.Status != sandboxexecution.StatusSucceeded {
		t.Fatalf("final manifest Status = %q, want succeeded", manifest.Status)
	}
	if len(manifest.Artifacts) != 0 {
		t.Fatalf("legacy Artifacts = %#v, want unchanged empty top-level artifacts", manifest.Artifacts)
	}
	if manifest.ArtifactMetadata == nil {
		t.Fatal("ArtifactMetadata = nil, want default core/recovery artifact metadata")
	}
	if len(manifest.ArtifactMetadata.Collected) != len(paths) {
		t.Fatalf("collected = %#v, want exactly %d default artifacts", manifest.ArtifactMetadata.Collected, len(paths))
	}
	for _, path := range paths {
		if !sandboxManifestHasCollectedPath(manifest, path) {
			t.Fatalf("manifest missing default artifact %q: %#v", path, manifest.ArtifactMetadata.Collected)
		}
	}
	if len(manifest.ArtifactMetadata.Partial) != 0 || len(manifest.ArtifactMetadata.Warnings) != 0 {
		t.Fatalf("partial/warnings = %#v/%#v, want none", manifest.ArtifactMetadata.Partial, manifest.ArtifactMetadata.Warnings)
	}
}

func assertDefaultSandboxManifestOmitsSyncOutApplyFields(t *testing.T, manifest *sandboxexecution.Manifest) {
	t.Helper()
	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("Unmarshal(manifest fields) error: %v", err)
	}
	for _, field := range []string{"syncOut", "syncOutApply", "apply", "applyResult"} {
		if _, ok := fields[field]; ok {
			t.Fatalf("default manifest unexpectedly includes %q field: %s", field, string(encoded))
		}
	}
}

func sandboxManifestHasCollectedPath(manifest *sandboxexecution.Manifest, path string) bool {
	if manifest == nil || manifest.ArtifactMetadata == nil {
		return false
	}
	for _, artifact := range manifest.ArtifactMetadata.Collected {
		if artifact.Path == path && artifact.StoredPath != "" {
			return true
		}
	}
	return false
}

func sandboxSyncOutSummaryHasCorePath(summary sandboxworkspace.SyncOutSummary, path string) bool {
	for _, artifact := range summary.CoreArtifacts {
		if artifact.DisplayPath == path && artifact.StoredPath != "" {
			return true
		}
	}
	return false
}
