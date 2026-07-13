package cmd

import (
	"bytes"
	"context"
	"io"
	"path/filepath"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/securedefaultfixtures"
)

func TestUS010AutoSandboxJSONAndManifestUseSharedSecureDefaultDecision(t *testing.T) {
	tests := []struct {
		name       string
		fixture    securedefaultfixtures.EvidenceSet
		wantOK     bool
		wantStatus sandboxexecution.Status
	}{
		{
			name:       "accepted complete evidence",
			fixture:    securedefaultfixtures.CompleteAcceptedEvidenceSet(),
			wantOK:     true,
			wantStatus: sandboxexecution.StatusSucceeded,
		},
		{
			name: "rejected missing network proof",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(
				securedefaultfixtures.OmitProof(securedefaultfixtures.ProofProxyFirewallEnforcement),
			),
			wantOK:     false,
			wantStatus: sandboxexecution.StatusFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("HAL_CONFIG_HOME", t.TempDir())

			startedAt := time.Date(2026, 7, 4, 18, 45, 0, 0, time.UTC)
			finishedAt := startedAt.Add(time.Second)
			projectDir := filepath.Join(t.TempDir(), "repo")
			writeStrictOnlyRunAutoReadinessGateConfig(t, projectDir)
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "auto-executions"))
			executionID := "auto-us010-" + us009RunSurfaceSlug(tt.name)
			target := us010AutoSurfaceTarget(executionID, tt.fixture)

			var out bytes.Buffer
			var errOut bytes.Buffer
			err := runAutoSandboxWithWriter(context.Background(), nil, nil, projectDir, autoSandboxOptions{
				JSON:        true,
				JSONChanged: true,
				Base:        "main",
				BaseChanged: true,
			}, &out, &errOut, autoSandboxDeps{
				defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
				newExecutionID: func(time.Time) string {
					return executionID
				},
				now: runSandboxTestClock(startedAt, finishedAt),
				planWorkspace: func(context.Context, sandboxworkspace.Request) (sandboxworkspace.Plan, error) {
					return us010AutoSurfaceWorkspacePlan(projectDir)
				},
				execute: func(_ context.Context, _ autoSandboxRequest, stdout io.Writer, _ io.Writer, hooks autoSandboxExecutionHooks) (autoSandboxExecutionResult, error) {
					if hooks.OnTargetReady != nil {
						if err := hooks.OnTargetReady(target); err != nil {
							return autoSandboxExecutionResult{}, err
						}
					}
					if _, err := io.WriteString(stdout, autoSandboxRemoteSuccessJSON("us010 auto surface")+"\n"); err != nil {
						return autoSandboxExecutionResult{}, err
					}
					return autoSandboxExecutionResult{
						Result:        &sandboxexec.Result{Target: sandboxRuntimeTargetFromState(target)},
						RemoteStarted: true,
					}, nil
				},
			})
			if tt.wantOK {
				if err != nil {
					t.Fatalf("runAutoSandboxWithWriter() error = %v\nstdout=%s\nstderr=%s", err, out.String(), errOut.String())
				}
			} else {
				requireRenderedJSONExitCode(t, err, ExitCodeValidation)
			}

			var result AutoResult
			decodeExactlyOneJSONDocument(t, out.Bytes(), &result)
			if result.OK != tt.wantOK {
				t.Fatalf("AutoResult.OK = %v, want %v\nstdout=%s", result.OK, tt.wantOK, out.String())
			}
			us009AssertRunSurfaceGateMatchesFixture(t, "auto JSON", result.SecurityReadinessGate, tt.fixture.Gate)
			us009AssertRunSurfaceSafe(t, "auto JSON", out.String())

			manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
			if manifest.Status != tt.wantStatus {
				t.Fatalf("manifest status = %q, want %q", manifest.Status, tt.wantStatus)
			}
			if manifest.Security == nil {
				t.Fatal("manifest security = nil, want secure-default decision metadata")
			}
			us009AssertRunSurfaceGateMatchesFixture(t, "auto manifest", manifest.Security.SecurityReadinessGate, tt.fixture.Gate)
			us009AssertRunSurfaceSafe(t, "auto manifest security", manifest.Security)
		})
	}
}

func us010AutoSurfaceTarget(name string, fixture securedefaultfixtures.EvidenceSet) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		ID:       name + "-target",
		Name:     name,
		Provider: "phase60",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:                "us010-host",
			Name:              "us010 host",
			Kind:              sandbox.SandboxHostKindLocal,
			SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverMicroVM},
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverMicroVM,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			TemplateLock:   fixture.WorkerRuntime.TemplateLock,
		},
		Workspace: fixture.WorkerRuntime.Workspace,
		Security:  fixture.Security(),
	}
}

func us010AutoSurfaceWorkspacePlan(projectDir string) (sandboxworkspace.Plan, error) {
	return sandboxworkspace.Plan{
		Mode:        sandbox.SandboxWorkspaceModeClone,
		InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
		ProjectDir:  projectDir,
		Repository:  "git@example.invalid:org/repo.git",
		Branch:      "phase60-secure-default",
		Upstream:    "origin/phase60-secure-default",
		SyncRef:     "refs/remotes/origin/phase60-secure-default",
	}, nil
}
