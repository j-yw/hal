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

func TestSandboxApplyOnlyUsesEligibleSyncOutArtifacts(t *testing.T) {
	t.Run("selects eligible committed patch only", func(t *testing.T) {
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
		executionID := "eligible-apply"
		projectDir := t.TempDir()
		saveSandboxSyncOutApplyManifest(t, store, executionID, sandboxexecution.PurposeRun, sandboxexecution.ArtifactMetadata{
			Collected: []sandboxexecution.ArtifactMetadataEntry{
				sandboxSyncOutApplyCollected("untracked-archive", ".hal/sync/untracked.tar", executionID+"/artifacts/sync/untracked.tar"),
				sandboxSyncOutApplyCollected("recovery-patch", ".hal/recovery/workspace.patch", executionID+"/recovery/workspace.patch"),
				sandboxSyncOutApplyCollected("committed-patch", ".hal/sync/committed.patch", executionID+"/artifacts/sync/committed.patch"),
			},
		})

		var called bool
		result, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
			ExecutionID: executionID,
			Purpose:     sandboxexecution.PurposeRun,
			ProjectDir:  projectDir,
			Options: sandboxSyncOutOptions{
				Enabled: true,
				Apply:   true,
			},
		}, func(_ context.Context, got sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
			called = true
			if got.Artifact == nil {
				t.Fatal("apply request Artifact = nil, want selected eligible artifact")
			}
			if got.Artifact.ID != "committed-patch" || got.Artifact.Kind != sandboxworkspace.SyncOutArtifactKindPatch {
				t.Fatalf("apply request Artifact = %#v, want eligible committed patch", got.Artifact)
			}
			if got.Artifact.ApplyEligibility == nil || !got.Artifact.ApplyEligibility.Eligible ||
				got.Artifact.ApplyEligibility.Mode != sandboxworkspace.SyncOutApplyModePatch {
				t.Fatalf("selected artifact eligibility = %#v, want explicit eligible patch", got.Artifact.ApplyEligibility)
			}
			wantPayload := filepath.Join(store.Root(), filepath.FromSlash(executionID+"/artifacts/sync/committed.patch"))
			if got.PayloadPath != wantPayload {
				t.Fatalf("apply request PayloadPath = %q, want %q", got.PayloadPath, wantPayload)
			}
			if got.Summary.Untracked.Archive == nil || got.Summary.Recovery.Status != sandboxworkspace.SyncOutRecoveryStatusCollected {
				t.Fatalf("sync-out summary = %#v, want non-eligible artifacts preserved for handoff metadata", got.Summary)
			}
			return sandboxworkspace.SafeApplyResult{
				Status:     sandboxworkspace.SafeApplyStatusApplied,
				Applied:    true,
				ArtifactID: got.Artifact.ID,
				Mode:       sandboxworkspace.SyncOutApplyModePatch,
			}, nil
		})
		if err != nil {
			t.Fatalf("applySandboxSyncOut() error = %v", err)
		}
		if !called {
			t.Fatal("apply hook was not called for eligible committed patch")
		}
		if result.Status != sandboxworkspace.SafeApplyStatusApplied || !result.Applied || result.ArtifactID != "committed-patch" {
			t.Fatalf("apply result = %#v, want committed patch applied result", result)
		}
	})

	t.Run("hands off outputs without eligible patch or bundle", func(t *testing.T) {
		for _, tc := range []struct {
			name       string
			metadata   sandboxexecution.ArtifactMetadata
			wantReason sandboxworkspace.SyncOutApplyEligibilityReason
		}{
			{
				name: "untracked archive",
				metadata: sandboxexecution.ArtifactMetadata{Collected: []sandboxexecution.ArtifactMetadataEntry{
					sandboxSyncOutApplyCollected("untracked-archive", ".hal/sync/untracked.tar", "exec-case/artifacts/sync/untracked.tar"),
					sandboxSyncOutApplyCollected("untracked-list", ".hal/sync/untracked.txt", "exec-case/artifacts/sync/untracked.txt"),
				}},
				wantReason: sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact,
			},
			{
				name: "recovery bundle",
				metadata: sandboxexecution.ArtifactMetadata{Collected: []sandboxexecution.ArtifactMetadataEntry{
					sandboxSyncOutApplyCollected("recovery-patch", ".hal/recovery/workspace.patch", "exec-case/recovery/workspace.patch"),
				}},
				wantReason: sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact,
			},
			{
				name: "raw artifact directory metadata",
				metadata: sandboxexecution.ArtifactMetadata{Collected: []sandboxexecution.ArtifactMetadataEntry{
					sandboxSyncOutApplyCollected("raw-artifacts", "output/raw-artifacts", "exec-case/artifacts/output/raw-artifacts"),
				}},
				wantReason: sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact,
			},
			{
				name: "warning only",
				metadata: sandboxexecution.ArtifactMetadata{Warnings: []sandboxexecution.ArtifactWarning{{
					Phase:   "copy_out",
					Message: "artifact collection failed",
					Artifact: sandboxexecution.ArtifactMetadataEntry{
						ID:   "untracked-archive",
						Name: "Untracked archive",
						Path: ".hal/sync/untracked.tar",
					},
				}}},
				wantReason: sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact,
			},
			{
				name: "ineligible committed patch",
				metadata: sandboxexecution.ArtifactMetadata{Partial: []sandboxexecution.ArtifactMetadataEntry{{
					ID:   "committed-patch",
					Name: "Committed patch",
					Path: ".hal/sync/committed.patch",
				}}},
				wantReason: sandboxworkspace.SyncOutApplyEligibilityReasonUnsafeArtifact,
			},
		} {
			t.Run(tc.name, func(t *testing.T) {
				store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
				projectDir := t.TempDir()
				executionID := "exec-case"
				saveSandboxSyncOutApplyManifest(t, store, executionID, sandboxexecution.PurposeRun, tc.metadata)

				var called bool
				result, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
					ExecutionID: executionID,
					Purpose:     sandboxexecution.PurposeRun,
					ProjectDir:  projectDir,
					Options: sandboxSyncOutOptions{
						Enabled: true,
						Apply:   true,
					},
				}, func(_ context.Context, got sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
					called = true
					if got.Artifact != nil {
						t.Fatalf("apply request Artifact = %#v, want no selected artifact", got.Artifact)
					}
					if got.PayloadPath != "" {
						t.Fatalf("apply request PayloadPath = %q, want empty handoff payload", got.PayloadPath)
					}
					if got.Handoff.Status != sandboxworkspace.SafeApplyStatusHandoffRequired || got.Handoff.Applied {
						t.Fatalf("apply request Handoff = %#v, want handoff-required result", got.Handoff)
					}
					if !sandboxApplyReasonsContain(got.Handoff.Reasons, tc.wantReason) {
						t.Fatalf("handoff reasons = %#v, want %q", got.Handoff.Reasons, tc.wantReason)
					}
					return got.Handoff, nil
				})
				if err != nil {
					t.Fatalf("applySandboxSyncOut() error = %v", err)
				}
				if !called {
					t.Fatal("apply hook was not called to receive handoff metadata")
				}
				if result.Status != sandboxworkspace.SafeApplyStatusHandoffRequired || result.Applied || result.DryRunPassed {
					t.Fatalf("apply result = %#v, want handoff without mutation", result)
				}
			})
		}
	})
}

func TestSandboxSyncOutHandoffInstructions(t *testing.T) {
	for _, tc := range []struct {
		name            string
		options         sandboxSyncOutOptions
		metadata        sandboxexecution.ArtifactMetadata
		applyResult     func(t *testing.T, got sandboxSyncOutApplyRequest) sandboxworkspace.SafeApplyResult
		wantReason      sandboxworkspace.SyncOutApplyEligibilityReason
		wantArtifactIDs []string
	}{
		{
			name: "apply disabled",
			options: sandboxSyncOutOptions{
				Enabled: true,
				Apply:   false,
			},
			metadata: sandboxexecution.ArtifactMetadata{Collected: []sandboxexecution.ArtifactMetadataEntry{
				sandboxSyncOutApplyCollected("committed-patch", ".hal/sync/committed.patch", "handoff-case/artifacts/sync/committed.patch"),
				sandboxSyncOutApplyCollected("untracked-archive", ".hal/sync/untracked.tar", "handoff-case/artifacts/sync/untracked.tar"),
				sandboxSyncOutApplyCollected("recovery-patch", ".hal/recovery/workspace.patch", "handoff-case/recovery/workspace.patch"),
			}},
			applyResult: func(t *testing.T, got sandboxSyncOutApplyRequest) sandboxworkspace.SafeApplyResult {
				t.Helper()
				if got.Artifact != nil || got.PayloadPath != "" {
					t.Fatalf("apply disabled selected artifact=%#v payload=%q, want handoff only", got.Artifact, got.PayloadPath)
				}
				return got.Handoff
			},
			wantReason:      sandboxworkspace.SyncOutApplyEligibilityReasonApplyDisabled,
			wantArtifactIDs: []string{"committed-patch", "untracked-archive", "recovery-patch"},
		},
		{
			name: "dirty worktree",
			options: sandboxSyncOutOptions{
				Enabled: true,
				Apply:   true,
			},
			metadata: sandboxexecution.ArtifactMetadata{Collected: []sandboxexecution.ArtifactMetadataEntry{
				sandboxSyncOutApplyCollected("committed-patch", ".hal/sync/committed.patch", "handoff-case/artifacts/sync/committed.patch"),
				sandboxSyncOutApplyCollected("recovery-patch", ".hal/recovery/workspace.patch", "handoff-case/recovery/workspace.patch"),
			}},
			applyResult: func(t *testing.T, got sandboxSyncOutApplyRequest) sandboxworkspace.SafeApplyResult {
				t.Helper()
				if got.Artifact == nil || got.Artifact.ID != "committed-patch" {
					t.Fatalf("apply artifact = %#v, want committed patch", got.Artifact)
				}
				return sandboxworkspace.SafeApplyResult{
					Status:      sandboxworkspace.SafeApplyStatusHandoffRequired,
					ArtifactID:  got.Artifact.ID,
					DisplayName: got.Artifact.DisplayName,
					DisplayPath: got.Artifact.DisplayPath,
					Mode:        sandboxworkspace.SyncOutApplyModePatch,
					Reasons:     []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonDirtyWorktree},
				}
			},
			wantReason:      sandboxworkspace.SyncOutApplyEligibilityReasonDirtyWorktree,
			wantArtifactIDs: []string{"committed-patch", "recovery-patch"},
		},
		{
			name: "dry-run failed",
			options: sandboxSyncOutOptions{
				Enabled: true,
				Apply:   true,
			},
			metadata: sandboxexecution.ArtifactMetadata{Collected: []sandboxexecution.ArtifactMetadataEntry{
				sandboxSyncOutApplyCollected("committed-patch", ".hal/sync/committed.patch", "handoff-case/artifacts/sync/committed.patch"),
				sandboxSyncOutApplyCollected("uncommitted-diff", ".hal/sync/uncommitted.diff", "handoff-case/artifacts/sync/uncommitted.diff"),
				sandboxSyncOutApplyCollected("recovery-patch", ".hal/recovery/workspace.patch", "handoff-case/recovery/workspace.patch"),
			}},
			applyResult: func(t *testing.T, got sandboxSyncOutApplyRequest) sandboxworkspace.SafeApplyResult {
				t.Helper()
				if got.Artifact == nil || got.PayloadPath == "" {
					t.Fatalf("apply artifact=%#v payload=%q, want eligible artifact payload", got.Artifact, got.PayloadPath)
				}
				return sandboxworkspace.SafeApplyResult{
					Status:      sandboxworkspace.SafeApplyStatusHandoffRequired,
					ArtifactID:  got.Artifact.ID,
					DisplayName: got.Artifact.DisplayName,
					DisplayPath: got.Artifact.DisplayPath,
					Mode:        sandboxworkspace.SyncOutApplyModePatch,
					Reasons:     []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonDryRunFailed},
				}
			},
			wantReason:      sandboxworkspace.SyncOutApplyEligibilityReasonDryRunFailed,
			wantArtifactIDs: []string{"committed-patch", "uncommitted-diff", "recovery-patch"},
		},
		{
			name: "eligible artifacts missing",
			options: sandboxSyncOutOptions{
				Enabled: true,
				Apply:   true,
			},
			metadata: sandboxexecution.ArtifactMetadata{Collected: []sandboxexecution.ArtifactMetadataEntry{
				sandboxSyncOutApplyCollected("untracked-list", ".hal/sync/untracked.txt", "handoff-case/artifacts/sync/untracked.txt"),
				sandboxSyncOutApplyCollected("recovery-patch", ".hal/recovery/workspace.patch", "handoff-case/recovery/workspace.patch"),
			}},
			applyResult: func(t *testing.T, got sandboxSyncOutApplyRequest) sandboxworkspace.SafeApplyResult {
				t.Helper()
				if got.Artifact != nil || got.PayloadPath != "" {
					t.Fatalf("missing eligible selected artifact=%#v payload=%q, want handoff only", got.Artifact, got.PayloadPath)
				}
				return got.Handoff
			},
			wantReason:      sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact,
			wantArtifactIDs: []string{"untracked-list", "recovery-patch"},
		},
		{
			name: "otherwise unsafe",
			options: sandboxSyncOutOptions{
				Enabled: true,
				Apply:   true,
			},
			metadata: sandboxexecution.ArtifactMetadata{Partial: []sandboxexecution.ArtifactMetadataEntry{{
				ID:   "committed-patch",
				Name: "Committed patch token=secret",
				Path: ".hal/sync/committed.patch",
			}}},
			applyResult: func(t *testing.T, got sandboxSyncOutApplyRequest) sandboxworkspace.SafeApplyResult {
				t.Helper()
				if got.Artifact != nil || got.PayloadPath != "" {
					t.Fatalf("unsafe artifact selected artifact=%#v payload=%q, want handoff only", got.Artifact, got.PayloadPath)
				}
				return got.Handoff
			},
			wantReason:      sandboxworkspace.SyncOutApplyEligibilityReasonUnsafeArtifact,
			wantArtifactIDs: []string{"committed-patch"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
			executionID := "handoff-case"
			saveSandboxSyncOutApplyManifest(t, store, executionID, sandboxexecution.PurposeRun, tc.metadata)

			result, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
				ExecutionID: executionID,
				Purpose:     sandboxexecution.PurposeRun,
				ProjectDir:  t.TempDir(),
				Options:     tc.options,
			}, func(_ context.Context, got sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
				return tc.applyResult(t, got), nil
			})
			if err != nil {
				t.Fatalf("applySandboxSyncOut() error = %v", err)
			}
			assertSandboxSyncOutHandoffInstructions(t, result, tc.wantReason, tc.wantArtifactIDs, []string{
				"token=secret",
				"/tmp/",
				"unix://",
				"/workspace/",
				"https://deploy:secret@example.test/repo.git",
				"providerSecret",
			})
		})
	}
}

func TestSandboxSyncOutApplyRedaction(t *testing.T) {
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	executionID := "sync-out-redaction"
	saveSandboxSyncOutApplyManifest(t, store, executionID, sandboxexecution.PurposeRun, sandboxexecution.ArtifactMetadata{
		Collected: []sandboxexecution.ArtifactMetadataEntry{
			sandboxSyncOutApplyCollected("committed-patch", ".hal/sync/committed.patch", executionID+"/artifacts/sync/committed.patch"),
			sandboxSyncOutApplyCollected("recovery-patch", ".hal/recovery/workspace.patch", executionID+"/recovery/workspace.patch"),
		},
	})

	result, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
		ExecutionID: executionID,
		Purpose:     sandboxexecution.PurposeRun,
		ProjectDir:  t.TempDir(),
		Options: sandboxSyncOutOptions{
			Enabled: true,
			Apply:   true,
		},
	}, func(_ context.Context, got sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
		if got.Artifact == nil || got.PayloadPath == "" {
			t.Fatalf("apply request artifact=%#v payload=%q, want eligible committed patch", got.Artifact, got.PayloadPath)
		}
		return sandboxworkspace.SafeApplyResult{
			Status:      sandboxworkspace.SafeApplyStatusHandoffRequired,
			Mode:        sandboxworkspace.SyncOutApplyModePatch,
			ArtifactID:  "committed-patch",
			DisplayName: "Patch from https://deploy:secret@example.test/repo.git?token=secret",
			DisplayPath: "/tmp/private/committed.patch",
			Reasons:     []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonDryRunFailed},
			Warnings: []sandboxworkspace.SyncOutWarning{{
				Code:       "dry_run_failed",
				Message:    "dry-run failed from unix:///tmp/private/worker-1.sock at /workspace/.hal/tmp/session TOKEN=secret ghp_sync_secret_123 https://deploy:secret@example.test/repo.git?client_secret=provider-secret",
				ArtifactID: "committed-patch",
			}},
		}, nil
	})
	if err != nil {
		t.Fatalf("applySandboxSyncOut() error = %v", err)
	}

	forbidden := []string{
		"unix://",
		"/tmp/private",
		"/workspace/.hal",
		"TOKEN=secret",
		"ghp_sync_secret_123",
		"deploy:secret",
		"token=secret",
		"client_secret=provider-secret",
	}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error: %v", err)
	}
	assertSandboxSyncOutApplyRedaction(t, string(resultJSON), forbidden)

	manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal(manifest) error: %v", err)
	}
	assertSandboxSyncOutApplyRedaction(t, string(manifestJSON), forbidden)
	if manifest.SyncOutApply == nil || len(manifest.SyncOutApply.HandoffInstructions) == 0 {
		t.Fatalf("manifest SyncOutApply = %#v, want sanitized handoff instructions", manifest.SyncOutApply)
	}

	var out bytes.Buffer
	if err := outputSandboxSyncOutAugmentedJSON(&out, []byte(`{"contractVersion":1,"ok":true}`+"\n"), store, executionID); err != nil {
		t.Fatalf("outputSandboxSyncOutAugmentedJSON() error = %v", err)
	}
	assertSandboxSyncOutApplyRedaction(t, out.String(), forbidden)
}

func TestSandboxSyncOutManifestJSONAdditiveContract(t *testing.T) {
	t.Run("manifest persists optional sync-out fields and decodes legacy records", func(t *testing.T) {
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
		executionID := "manifest-additive"
		saveSandboxSyncOutApplyManifest(t, store, executionID, sandboxexecution.PurposeRun, sandboxexecution.ArtifactMetadata{
			Collected: []sandboxexecution.ArtifactMetadataEntry{
				sandboxSyncOutApplyCollected("committed-patch", ".hal/sync/committed.patch", executionID+"/artifacts/sync/committed.patch"),
				sandboxSyncOutApplyCollected("recovery-patch", ".hal/recovery/workspace.patch", executionID+"/recovery/workspace.patch"),
			},
		})

		result, err := applySandboxSyncOut(context.Background(), store, sandboxSyncOutApplyRequest{
			ExecutionID: executionID,
			Purpose:     sandboxexecution.PurposeRun,
			ProjectDir:  t.TempDir(),
			Options: sandboxSyncOutOptions{
				Enabled: true,
				Apply:   false,
			},
		}, func(_ context.Context, got sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
			return got.Handoff, nil
		})
		if err != nil {
			t.Fatalf("applySandboxSyncOut() error = %v", err)
		}
		if result.Status != sandboxworkspace.SafeApplyStatusHandoffRequired {
			t.Fatalf("apply result = %#v, want handoff-required", result)
		}

		manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
		if manifest.SyncOut == nil {
			t.Fatal("manifest SyncOut = nil, want additive sync-out summary")
		}
		if manifest.SyncOut.Committed.Patch == nil || manifest.SyncOut.Committed.Patch.ID != "committed-patch" {
			t.Fatalf("manifest SyncOut committed patch = %#v, want committed patch metadata", manifest.SyncOut.Committed.Patch)
		}
		if manifest.SyncOutApply == nil {
			t.Fatal("manifest SyncOutApply = nil, want additive apply result")
		}
		if !sandboxApplyReasonsContain(manifest.SyncOutApply.Reasons, sandboxworkspace.SyncOutApplyEligibilityReasonApplyDisabled) {
			t.Fatalf("manifest SyncOutApply reasons = %#v, want apply_disabled", manifest.SyncOutApply.Reasons)
		}

		encoded, err := json.Marshal(manifest)
		if err != nil {
			t.Fatalf("Marshal(manifest) error: %v", err)
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &fields); err != nil {
			t.Fatalf("Unmarshal(manifest fields) error: %v", err)
		}
		for _, field := range []string{"syncOut", "syncOutApply"} {
			if _, ok := fields[field]; !ok {
				t.Fatalf("manifest JSON missing %q field: %s", field, string(encoded))
			}
		}

		var decoded sandboxexecution.Manifest
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatalf("Unmarshal(manifest with sync-out fields) error: %v", err)
		}
		if decoded.SyncOut == nil || decoded.SyncOutApply == nil {
			t.Fatalf("decoded sync-out fields = %#v/%#v, want populated", decoded.SyncOut, decoded.SyncOutApply)
		}

		var legacy sandboxexecution.Manifest
		if err := json.Unmarshal([]byte(`{"id":"legacy","purpose":"run","status":"running","startedAt":"2026-07-02T02:00:00Z"}`), &legacy); err != nil {
			t.Fatalf("Unmarshal(legacy manifest) error: %v", err)
		}
		if legacy.SyncOut != nil || legacy.SyncOutApply != nil {
			t.Fatalf("legacy sync-out fields = %#v/%#v, want nil optional fields", legacy.SyncOut, legacy.SyncOutApply)
		}
	})

	t.Run("run sandbox JSON includes sync-out metadata when explicit", func(t *testing.T) {
		startedAt := time.Date(2026, 7, 2, 2, 10, 0, 0, time.UTC)
		finishedAt := startedAt.Add(5 * time.Second)
		projectDir := t.TempDir()
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
		target := &sandbox.SandboxState{
			Name:     "run-json-sync-out",
			Provider: "test-provider",
			Status:   sandbox.StatusRunning,
			Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
		}
		plan := sandboxworkspace.Plan{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			ProjectDir:  projectDir,
			Repository:  "git@example.com:org/repo.git",
			Branch:      "feature/run-json-sync-out",
			Upstream:    "origin/feature/run-json-sync-out",
			SyncRef:     "refs/remotes/origin/feature/run-json-sync-out",
		}
		expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
			RunID:      "run-json-sync-out",
			RepoPath:   projectDir,
			RepoRemote: plan.Repository,
			BranchName: plan.Branch,
			BaseBranch: "main",
		})
		var order []string
		driver := sandboxApplyOrderRuntimeDriver(t, expectedWorkspace, &order, `{"contractVersion":1,"ok":true,"iterations":1,"complete":false,"summary":"remote run"}`+"\n")
		var out bytes.Buffer
		var errOut bytes.Buffer

		err := runRunSandboxWithWriter(context.Background(), nil, nil, runSandboxOptions{
			Base:                  "main",
			BaseChanged:           true,
			JSON:                  true,
			JSONChanged:           true,
			SandboxSyncOut:        true,
			SandboxSyncOutChanged: true,
		}, &out, &errOut, runSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) {
				return store, nil
			},
			newExecutionID: func(time.Time) string {
				return "run-json-sync-out"
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

		var result RunResult
		decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
		if result.Summary != "remote run" {
			t.Fatalf("RunResult.Summary = %q, want remote run", result.Summary)
		}
		assertRunAutoSyncOutJSONFields(t, result.SyncOut, result.SyncOutApply)
		manifest := mustLoadSandboxExecutionManifest(t, store, "run-json-sync-out")
		assertRunAutoSyncOutJSONFields(t, manifest.SyncOut, manifest.SyncOutApply)
	})

	t.Run("auto sandbox JSON includes sync-out metadata when explicit", func(t *testing.T) {
		startedAt := time.Date(2026, 7, 2, 2, 15, 0, 0, time.UTC)
		finishedAt := startedAt.Add(5 * time.Second)
		projectDir := t.TempDir()
		store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
		target := &sandbox.SandboxState{
			Name:     "auto-json-sync-out",
			Provider: "test-provider",
			Status:   sandbox.StatusRunning,
			Runtime:  &sandbox.SandboxRuntimeState{Driver: sandbox.SandboxRuntimeDriverSSHMachine},
		}
		plan := autoSandboxTestPlan(projectDir)
		expectedWorkspace := factorySandboxRemoteWorkspaceDir(factory.RunRecord{
			RunID:      "auto-json-sync-out",
			RepoPath:   projectDir,
			RepoRemote: plan.Repository,
			BranchName: plan.Branch,
			BaseBranch: "main",
		})
		var order []string
		driver := sandboxApplyOrderRuntimeDriver(t, expectedWorkspace, &order, autoSandboxRemoteSuccessJSON("remote auto")+"\n")
		var out bytes.Buffer
		var errOut bytes.Buffer

		err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
			Base:                  "main",
			BaseChanged:           true,
			JSON:                  true,
			JSONChanged:           true,
			SandboxSyncOut:        true,
			SandboxSyncOutChanged: true,
		}, &out, &errOut, autoSandboxDeps{
			defaultStore: func() (sandboxexecution.Store, error) {
				return store, nil
			},
			newExecutionID: func(time.Time) string {
				return "auto-json-sync-out"
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

		var result AutoResult
		decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
		if result.Summary != "remote auto" {
			t.Fatalf("AutoResult.Summary = %q, want remote auto", result.Summary)
		}
		assertRunAutoSyncOutJSONFields(t, result.SyncOut, result.SyncOutApply)
		manifest := mustLoadSandboxExecutionManifest(t, store, "auto-json-sync-out")
		assertRunAutoSyncOutJSONFields(t, manifest.SyncOut, manifest.SyncOutApply)
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
		wantOrder := []string{"remote_run", "copy_core_prd", "copy_core_progress", "recovery_generation", "copy_recovery", "uncommitted_generation", "copy_uncommitted", "committed_generation", "copy_committed", "reports_generation", "copy_reports", "host_apply"}
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
		wantOrder := []string{"remote_run", "copy_core_prd", "copy_core_progress", "copy_core_auto_state", "recovery_generation", "copy_recovery", "uncommitted_generation", "copy_uncommitted", "committed_generation", "copy_committed", "reports_generation", "copy_reports", "host_apply"}
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
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "uncommitted.diff"):
				*order = append(*order, "uncommitted_generation")
			case got.WorkDir == expectedWorkspace && strings.Contains(script, "committed.patch"):
				*order = append(*order, "committed_generation")
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
	case strings.HasSuffix(sourcePath, "/.hal/sync/uncommitted.diff"):
		return "copy_uncommitted"
	case strings.HasSuffix(sourcePath, "/.hal/sync/committed.patch"):
		return "copy_committed"
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
	if got.Summary.Committed.Patch == nil || got.Summary.Committed.Patch.StoredPath == "" || !got.Summary.Apply.Eligible {
		t.Fatalf("sync-out committed artifacts = %#v, want eligible durable committed patch", got.Summary.Committed)
	}
	if got.Summary.Uncommitted.Diff == nil || got.Summary.Uncommitted.Diff.StoredPath == "" || got.Summary.Uncommitted.Diff.ApplyEligibility == nil || got.Summary.Uncommitted.Diff.ApplyEligibility.Eligible {
		t.Fatalf("sync-out uncommitted artifacts = %#v, want durable handoff-only diff", got.Summary.Uncommitted)
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

func saveSandboxSyncOutApplyManifest(t *testing.T, store sandboxexecution.Store, executionID string, purpose sandboxexecution.Purpose, metadata sandboxexecution.ArtifactMetadata) {
	t.Helper()
	if err := store.SaveManifest(&sandboxexecution.Manifest{
		ID:               executionID,
		Purpose:          purpose,
		Status:           sandboxexecution.StatusRunning,
		StartedAt:        time.Date(2026, 7, 2, 2, 0, 0, 0, time.UTC),
		ArtifactMetadata: &metadata,
	}); err != nil {
		t.Fatalf("SaveManifest() error = %v", err)
	}
}

func sandboxSyncOutApplyCollected(id, path, storedPath string) sandboxexecution.ArtifactMetadataEntry {
	return sandboxexecution.ArtifactMetadataEntry{
		ID:         id,
		Name:       id,
		Path:       path,
		StoredPath: storedPath,
	}
}

func sandboxApplyReasonsContain(reasons []sandboxworkspace.SyncOutApplyEligibilityReason, want sandboxworkspace.SyncOutApplyEligibilityReason) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func assertSandboxSyncOutApplyRedaction(t *testing.T, payload string, forbidden []string) {
	t.Helper()
	for _, unsafe := range forbidden {
		if strings.Contains(payload, unsafe) {
			t.Fatalf("sync-out apply payload leaked unsafe fragment %q: %s", unsafe, payload)
		}
	}
}

func assertSandboxSyncOutHandoffInstructions(t *testing.T, result sandboxworkspace.SafeApplyResult, wantReason sandboxworkspace.SyncOutApplyEligibilityReason, wantArtifactIDs []string, forbidden []string) {
	t.Helper()
	if result.Status != sandboxworkspace.SafeApplyStatusHandoffRequired || result.Applied {
		t.Fatalf("apply result = %#v, want handoff-required without mutation", result)
	}
	if len(result.HandoffInstructions) == 0 {
		t.Fatalf("handoff instructions missing: %#v", result)
	}
	instruction := result.HandoffInstructions[0]
	if instruction.Reason != wantReason {
		t.Fatalf("handoff reason = %q, want %q", instruction.Reason, wantReason)
	}
	if strings.TrimSpace(instruction.Message) == "" {
		t.Fatalf("handoff message is empty: %#v", instruction)
	}
	gotArtifactIDs := map[string]bool{}
	for _, artifact := range instruction.Artifacts {
		if artifact.ID != "" {
			gotArtifactIDs[artifact.ID] = true
		}
		if artifact.DisplayPath != "" {
			if filepath.IsAbs(artifact.DisplayPath) || strings.Contains(artifact.DisplayPath, "\\") || strings.Contains(artifact.DisplayPath, "..") {
				t.Fatalf("handoff artifact display path is unsafe: %#v", artifact)
			}
		}
	}
	for _, want := range wantArtifactIDs {
		if !gotArtifactIDs[want] {
			t.Fatalf("handoff artifact IDs = %#v, want %q in %#v", gotArtifactIDs, want, instruction.Artifacts)
		}
	}
	encoded, err := json.Marshal(result.HandoffInstructions)
	if err != nil {
		t.Fatalf("Marshal(handoff instructions) error: %v", err)
	}
	payload := string(encoded)
	for _, value := range forbidden {
		if strings.Contains(payload, value) {
			t.Fatalf("handoff instructions leaked %q: %s", value, payload)
		}
	}
}

func assertRunAutoSyncOutJSONFields(t *testing.T, summary *sandboxworkspace.SyncOutSummary, apply *sandboxworkspace.SafeApplyResult) {
	t.Helper()
	if summary == nil {
		t.Fatal("syncOut = nil, want additive sync-out summary")
	}
	if summary.Recovery.Status != sandboxworkspace.SyncOutRecoveryStatusCollected {
		t.Fatalf("syncOut.recovery.status = %q, want collected", summary.Recovery.Status)
	}
	if len(summary.CoreArtifacts) == 0 {
		t.Fatalf("syncOut.coreArtifacts = %#v, want durable core artifact references", summary.CoreArtifacts)
	}
	if apply == nil {
		t.Fatal("syncOutApply = nil, want additive apply/handoff result")
	}
	if apply.Status != sandboxworkspace.SafeApplyStatusHandoffRequired || apply.Applied {
		t.Fatalf("syncOutApply = %#v, want handoff-required without apply", apply)
	}
	if !sandboxApplyReasonsContain(apply.Reasons, sandboxworkspace.SyncOutApplyEligibilityReasonApplyDisabled) {
		t.Fatalf("syncOutApply.reasons = %#v, want apply_disabled", apply.Reasons)
	}
	if len(apply.HandoffInstructions) == 0 {
		t.Fatalf("syncOutApply.handoffInstructions = %#v, want safe handoff guidance", apply.HandoffInstructions)
	}
}
