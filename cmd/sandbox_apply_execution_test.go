package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

const sandboxApplyTestRevision = "0123456789abcdef0123456789abcdef01234567"

func TestRunSandboxApplyExecutionAppliesCompletedStoredRunWithoutSandboxExecution(t *testing.T) {
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	executionID := "run-completed-apply"
	projectDir := t.TempDir()
	saveSandboxApplyExecutionFixture(t, store, sandboxApplyExecutionFixture{
		ExecutionID:     executionID,
		Status:          sandboxexecution.StatusSucceeded,
		PRD:             `{"project":"keyboard","userStories":[{"id":"US-001","passes":true},{"id":"US-002","passes":true}]}`,
		ProjectDir:      projectDir,
		Branch:          "hal/keyboard-remapping",
		SyncRef:         sandboxApplyTestRevision,
		UncommittedDiff: true,
	})
	var applied bool
	var out bytes.Buffer

	err := runSandboxApplyExecution(context.Background(), executionID, &out, sandboxApplyExecutionDeps{
		defaultStore:    func() (sandboxexecution.Store, error) { return store, nil },
		workingDir:      func() (string, error) { return projectDir, nil },
		currentBranch:   func(string) (string, error) { return "hal/keyboard-remapping", nil },
		currentRevision: func(context.Context, string) (string, error) { return sandboxApplyTestRevision, nil },
		applySyncOut: func(_ context.Context, got sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
			applied = true
			if got.ExecutionID != executionID || got.ProjectDir != projectDir {
				t.Fatalf("apply request execution/project = %q/%q, want %q/%q", got.ExecutionID, got.ProjectDir, executionID, projectDir)
			}
			if got.Manifest == nil || got.Manifest.Status != sandboxexecution.StatusSucceeded {
				t.Fatalf("apply request manifest = %#v, want succeeded durable execution", got.Manifest)
			}
			if got.Artifact == nil || got.Artifact.ID != "committed-patch" || got.PayloadPath == "" {
				t.Fatalf("apply request artifact/payload = %#v/%q, want stored committed patch", got.Artifact, got.PayloadPath)
			}
			return sandboxworkspace.SafeApplyResult{
				Status:     sandboxworkspace.SafeApplyStatusApplied,
				Applied:    true,
				ArtifactID: "committed-patch",
				Mode:       sandboxworkspace.SyncOutApplyModePatch,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("runSandboxApplyExecution() error = %v", err)
	}
	if !applied {
		t.Fatal("completed execution apply hook was not called")
	}
	if !strings.Contains(out.String(), executionID) || !strings.Contains(out.String(), "Applied") {
		t.Fatalf("output = %q, want applied execution summary", out.String())
	}
	if !strings.Contains(out.String(), "Tracked uncommitted sandbox output remains manual-review-only") {
		t.Fatalf("output = %q, want manual uncommitted handoff guidance", out.String())
	}
	manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
	if manifest.SyncOutApply == nil || !manifest.SyncOutApply.Applied {
		t.Fatalf("persisted SyncOutApply = %#v, want applied result", manifest.SyncOutApply)
	}
}

func TestRunSandboxApplyExecutionRejectsWrongHostWorktreeIdentity(t *testing.T) {
	projectDir := t.TempDir()
	tests := []struct {
		name            string
		fixture         sandboxApplyExecutionFixture
		workingDir      string
		currentBranch   string
		currentRevision string
		wantError       string
	}{
		{
			name: "missing stored project",
			fixture: sandboxApplyExecutionFixture{
				ExecutionID: "run-missing-project",
				Status:      sandboxexecution.StatusSucceeded,
				PRD:         `{"project":"keyboard","userStories":[{"id":"US-001","passes":true}]}`,
				Branch:      "hal/keyboard-remapping",
			},
			workingDir:      projectDir,
			currentBranch:   "hal/keyboard-remapping",
			currentRevision: sandboxApplyTestRevision,
			wantError:       `sandbox execution "run-missing-project" has no stored host project identity`,
		},
		{
			name: "different project",
			fixture: sandboxApplyExecutionFixture{
				ExecutionID: "run-wrong-project",
				Status:      sandboxexecution.StatusSucceeded,
				PRD:         `{"project":"keyboard","userStories":[{"id":"US-001","passes":true}]}`,
				ProjectDir:  projectDir,
				Branch:      "hal/keyboard-remapping",
			},
			workingDir:      t.TempDir(),
			currentBranch:   "hal/keyboard-remapping",
			currentRevision: sandboxApplyTestRevision,
			wantError:       `sandbox execution "run-wrong-project" does not belong to the current host worktree`,
		},
		{
			name: "different branch",
			fixture: sandboxApplyExecutionFixture{
				ExecutionID: "run-wrong-branch",
				Status:      sandboxexecution.StatusSucceeded,
				PRD:         `{"project":"keyboard","userStories":[{"id":"US-001","passes":true}]}`,
				ProjectDir:  projectDir,
				Branch:      "hal/keyboard-remapping",
			},
			workingDir:      projectDir,
			currentBranch:   "hal/keyboard-help-overlay",
			currentRevision: sandboxApplyTestRevision,
			wantError:       `sandbox execution "run-wrong-branch" targets branch "hal/keyboard-remapping" but the current host worktree is on "hal/keyboard-help-overlay"`,
		},
		{
			name: "detached worktree",
			fixture: sandboxApplyExecutionFixture{
				ExecutionID: "run-detached",
				Status:      sandboxexecution.StatusSucceeded,
				PRD:         `{"project":"keyboard","userStories":[{"id":"US-001","passes":true}]}`,
				ProjectDir:  projectDir,
				Branch:      "hal/keyboard-remapping",
			},
			workingDir: projectDir,
			wantError:  `sandbox execution "run-detached" cannot apply to a detached host worktree`,
		},
		{
			name: "different revision",
			fixture: sandboxApplyExecutionFixture{
				ExecutionID: "run-wrong-revision",
				Status:      sandboxexecution.StatusSucceeded,
				PRD:         `{"project":"keyboard","userStories":[{"id":"US-001","passes":true}]}`,
				ProjectDir:  projectDir,
				Branch:      "hal/keyboard-remapping",
				SyncRef:     sandboxApplyTestRevision,
			},
			workingDir:      projectDir,
			currentBranch:   "hal/keyboard-remapping",
			currentRevision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			wantError:       `sandbox execution "run-wrong-revision" stored workspace revision does not match the current host HEAD`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
			saveSandboxApplyExecutionFixture(t, store, tt.fixture)
			applyCalled := false
			err := runSandboxApplyExecution(context.Background(), tt.fixture.ExecutionID, &bytes.Buffer{}, sandboxApplyExecutionDeps{
				defaultStore:    func() (sandboxexecution.Store, error) { return store, nil },
				workingDir:      func() (string, error) { return tt.workingDir, nil },
				currentBranch:   func(string) (string, error) { return tt.currentBranch, nil },
				currentRevision: func(context.Context, string) (string, error) { return tt.currentRevision, nil },
				applySyncOut: func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
					applyCalled = true
					return sandboxworkspace.SafeApplyResult{}, nil
				},
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("runSandboxApplyExecution() error = %v, want containing %q", err, tt.wantError)
			}
			if applyCalled {
				t.Fatal("apply hook ran for mismatched host worktree identity")
			}
		})
	}
}

func TestRunSandboxApplyExecutionRejectsUnsafeStoredRunsBeforeApply(t *testing.T) {
	tests := []struct {
		name      string
		fixture   sandboxApplyExecutionFixture
		wantError string
	}{
		{
			name: "running execution",
			fixture: sandboxApplyExecutionFixture{
				ExecutionID: "run-still-running",
				Status:      sandboxexecution.StatusRunning,
				PRD:         `{"project":"keyboard","userStories":[{"id":"US-001","passes":true}]}`,
			},
			wantError: `sandbox execution "run-still-running" has status "running"; completed apply requires status "succeeded"`,
		},
		{
			name: "incomplete PRD",
			fixture: sandboxApplyExecutionFixture{
				ExecutionID: "run-incomplete",
				Status:      sandboxexecution.StatusSucceeded,
				PRD:         `{"project":"keyboard","userStories":[{"id":"US-001","passes":true},{"id":"US-002","passes":false}]}`,
			},
			wantError: `sandbox execution "run-incomplete" is incomplete (1/2 stories passed)`,
		},
		{
			name: "missing PRD",
			fixture: sandboxApplyExecutionFixture{
				ExecutionID: "run-missing-prd",
				Status:      sandboxexecution.StatusSucceeded,
				OmitPRD:     true,
			},
			wantError: `sandbox execution "run-missing-prd" has no collected .hal/prd.json completion artifact`,
		},
		{
			name: "invalid PRD",
			fixture: sandboxApplyExecutionFixture{
				ExecutionID: "run-invalid-prd",
				Status:      sandboxexecution.StatusSucceeded,
				PRD:         `{`,
			},
			wantError: `parse sandbox execution "run-invalid-prd" PRD completion artifact`,
		},
		{
			name: "empty PRD",
			fixture: sandboxApplyExecutionFixture{
				ExecutionID: "run-empty-prd",
				Status:      sandboxexecution.StatusSucceeded,
				PRD:         `{}`,
			},
			wantError: `sandbox execution "run-empty-prd" PRD completion artifact has no stories`,
		},
		{
			name: "already applied",
			fixture: sandboxApplyExecutionFixture{
				ExecutionID:    "run-already-applied",
				Status:         sandboxexecution.StatusSucceeded,
				PRD:            `{"project":"keyboard","userStories":[{"id":"US-001","passes":true}]}`,
				AlreadyApplied: true,
			},
			wantError: `sandbox execution "run-already-applied" already records a successful host apply`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
			saveSandboxApplyExecutionFixture(t, store, tt.fixture)
			applyCalled := false
			err := runSandboxApplyExecution(context.Background(), tt.fixture.ExecutionID, &bytes.Buffer{}, sandboxApplyExecutionDeps{
				defaultStore: func() (sandboxexecution.Store, error) { return store, nil },
				workingDir:   func() (string, error) { return t.TempDir(), nil },
				applySyncOut: func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
					applyCalled = true
					return sandboxworkspace.SafeApplyResult{}, errors.New("apply should not run")
				},
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("runSandboxApplyExecution() error = %v, want containing %q", err, tt.wantError)
			}
			if applyCalled {
				t.Fatal("apply hook ran for unsafe stored execution")
			}
		})
	}
}

func TestRunSandboxApplyExecutionReturnsErrorWhenSafeApplyRequiresHandoff(t *testing.T) {
	store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "sandbox-executions"))
	executionID := "run-apply-handoff"
	projectDir := t.TempDir()
	saveSandboxApplyExecutionFixture(t, store, sandboxApplyExecutionFixture{
		ExecutionID: executionID,
		Status:      sandboxexecution.StatusSucceeded,
		PRD:         `{"project":"keyboard","userStories":[{"id":"US-001","passes":true}]}`,
		ProjectDir:  projectDir,
		Branch:      "hal/keyboard-remapping",
		SyncRef:     sandboxApplyTestRevision,
	})

	err := runSandboxApplyExecution(context.Background(), executionID, &bytes.Buffer{}, sandboxApplyExecutionDeps{
		defaultStore:    func() (sandboxexecution.Store, error) { return store, nil },
		workingDir:      func() (string, error) { return projectDir, nil },
		currentBranch:   func(string) (string, error) { return "hal/keyboard-remapping", nil },
		currentRevision: func(context.Context, string) (string, error) { return sandboxApplyTestRevision, nil },
		applySyncOut: func(context.Context, sandboxSyncOutApplyRequest) (sandboxworkspace.SafeApplyResult, error) {
			return sandboxworkspace.SafeApplyResult{
				Status:  sandboxworkspace.SafeApplyStatusHandoffRequired,
				Reasons: []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonDirtyWorktree},
			}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), `sandbox execution "run-apply-handoff" was not applied: dirty_worktree`) {
		t.Fatalf("runSandboxApplyExecution() error = %v, want non-applied handoff error", err)
	}
	manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
	if manifest.SyncOutApply == nil || manifest.SyncOutApply.Status != sandboxworkspace.SafeApplyStatusHandoffRequired {
		t.Fatalf("persisted SyncOutApply = %#v, want durable handoff result", manifest.SyncOutApply)
	}
}

func TestSandboxAugmentedJSONExposesStoredExecutionIDForLaterApply(t *testing.T) {
	manifest := &sandboxexecution.Manifest{
		ID:      "run-json-apply-later",
		SyncOut: &sandboxworkspace.SyncOutSummary{},
	}
	got, ok := sandboxAugmentJSON([]byte(`{"contractVersion":1,"ok":true}`), manifest)
	if !ok {
		t.Fatal("sandboxAugmentJSON() ok = false")
	}
	if !bytes.Contains(got, []byte(`"sandboxExecutionId": "run-json-apply-later"`)) {
		t.Fatalf("augmented JSON = %s, want sandboxExecutionId", got)
	}
}

type sandboxApplyExecutionFixture struct {
	ExecutionID     string
	Status          sandboxexecution.Status
	PRD             string
	OmitPRD         bool
	AlreadyApplied  bool
	ProjectDir      string
	Branch          string
	SyncRef         string
	UncommittedDiff bool
}

func saveSandboxApplyExecutionFixture(t *testing.T, store sandboxexecution.Store, fixture sandboxApplyExecutionFixture) {
	t.Helper()
	startedAt := time.Date(2026, 7, 16, 1, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Minute)
	metadata := sandboxexecution.ArtifactMetadata{}
	if !fixture.OmitPRD {
		stored, err := store.WriteArtifactPayload(fixture.ExecutionID, "core/hal-prd.json", []byte(fixture.PRD))
		if err != nil {
			t.Fatalf("WriteArtifactPayload(PRD) error: %v", err)
		}
		metadata.Collected = append(metadata.Collected, sandboxexecution.ArtifactMetadataEntry{
			ID:         "prd",
			Name:       "PRD",
			Type:       "json",
			Path:       ".hal/prd.json",
			StoredPath: stored.Path,
		})
	}
	patch, err := store.WriteArtifactPayload(fixture.ExecutionID, "sync/committed.patch", []byte("patch payload"))
	if err != nil {
		t.Fatalf("WriteArtifactPayload(committed patch) error: %v", err)
	}
	metadata.Collected = append(metadata.Collected, sandboxexecution.ArtifactMetadataEntry{
		ID:         "committed-patch",
		Name:       "Committed Patch",
		Type:       "patch",
		Path:       ".hal/sync/committed.patch",
		StoredPath: patch.Path,
	})
	if fixture.UncommittedDiff {
		diff, err := store.WriteArtifactPayload(fixture.ExecutionID, "sync/uncommitted.diff", []byte("review-only diff"))
		if err != nil {
			t.Fatalf("WriteArtifactPayload(uncommitted diff) error: %v", err)
		}
		metadata.Collected = append(metadata.Collected, sandboxexecution.ArtifactMetadataEntry{
			ID:         "uncommitted-diff",
			Name:       "Uncommitted Diff",
			Type:       "diff",
			Path:       ".hal/sync/uncommitted.diff",
			StoredPath: diff.Path,
		})
	}
	manifest := &sandboxexecution.Manifest{
		ID:               fixture.ExecutionID,
		Purpose:          sandboxexecution.PurposeRun,
		ProjectDir:       fixture.ProjectDir,
		Status:           fixture.Status,
		StartedAt:        startedAt,
		ArtifactMetadata: &metadata,
		Workspace: &sandbox.SandboxWorkspace{
			Branch:  fixture.Branch,
			SyncRef: fixture.SyncRef,
		},
	}
	if fixture.Status != sandboxexecution.StatusRunning {
		manifest.FinishedAt = &finishedAt
	}
	if fixture.AlreadyApplied {
		manifest.SyncOutApply = &sandboxworkspace.SafeApplyResult{
			Status:  sandboxworkspace.SafeApplyStatusApplied,
			Applied: true,
		}
	}
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
}
