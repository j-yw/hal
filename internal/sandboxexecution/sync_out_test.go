package sandboxexecution

import (
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

func TestBuildSyncOutSummaryFromArtifacts(t *testing.T) {
	manifest := &Manifest{
		ID:      "exec-1",
		Purpose: PurposeRun,
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
			Repo:        "https://token-secret@example.com/org/repo.git",
			Branch:      "phase/workspace",
			SyncRef:     "refs/hal/workspace-sync/abc123",
		},
		ArtifactMetadata: &ArtifactMetadata{
			Collected: []ArtifactMetadataEntry{
				{
					ID:         "committed-patch",
					Name:       "Committed Patch",
					Type:       "patch",
					Path:       ".hal/sync/committed.patch",
					StoredPath: "exec-1/artifacts/sync/committed.patch",
				},
				{
					ID:         "committed-bundle",
					Name:       "Committed Bundle",
					Type:       "bundle",
					Path:       ".hal/sync/committed.bundle",
					StoredPath: "exec-1/artifacts/sync/committed.bundle",
				},
				{
					ID:         "uncommitted-diff",
					Name:       "Uncommitted Diff",
					Type:       "diff",
					Path:       ".hal/sync/uncommitted.diff",
					StoredPath: "exec-1/artifacts/sync/uncommitted.diff",
				},
				{
					ID:         "untracked-archive",
					Name:       "Untracked Files Archive",
					Type:       "tar",
					Path:       ".hal/sync/untracked.tar",
					StoredPath: "exec-1/artifacts/sync/untracked.tar",
				},
				{
					ID:         "untracked-list",
					Name:       "Untracked Files",
					Type:       "text",
					Path:       ".hal/sync/untracked.txt",
					StoredPath: "exec-1/artifacts/sync/untracked.txt",
				},
				{
					ID:         "prd",
					Name:       "PRD",
					Type:       "json",
					Path:       ".hal/prd.json",
					StoredPath: "exec-1/artifacts/core/hal-prd.json",
				},
				{
					ID:         "reports-archive",
					Name:       "Reports Archive",
					Type:       "tar",
					Path:       ".hal/reports.tar",
					StoredPath: "exec-1/artifacts/reports/reports.tar",
				},
				{
					ID:         "recovery-patch",
					Name:       "Recovery Patch",
					Type:       "patch",
					Path:       ".hal/recovery/workspace.patch",
					StoredPath: "exec-1/recovery/workspace.patch",
				},
			},
			Partial: []ArtifactMetadataEntry{
				{
					ID:   "stdout-summary",
					Name: "Stdout Summary",
					Type: "text",
					Path: "output/stdout-summary.txt",
				},
			},
			Warnings: []ArtifactWarning{
				{
					Phase:   "copy_out",
					Message: "optional sandbox execution artifact is missing",
					Artifact: ArtifactMetadataEntry{
						ID:   "stdout-summary",
						Name: "Stdout Summary",
						Type: "text",
						Path: "output/stdout-summary.txt",
					},
				},
			},
		},
	}

	summary := BuildSyncOutSummaryFromArtifacts(manifest)

	if summary.Workspace.Mode != sandbox.SandboxWorkspaceModeClone ||
		summary.Workspace.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle ||
		summary.Workspace.Branch != "phase/workspace" ||
		summary.Workspace.SyncRef != "refs/hal/workspace-sync/abc123" {
		t.Fatalf("workspace summary = %#v, want redaction-safe workspace metadata", summary.Workspace)
	}

	if summary.Committed.Patch == nil ||
		summary.Committed.Patch.ID != "committed-patch" ||
		summary.Committed.Patch.Kind != sandboxworkspace.SyncOutArtifactKindPatch ||
		summary.Committed.Patch.ApplyEligibility == nil ||
		!summary.Committed.Patch.ApplyEligibility.Eligible ||
		summary.Committed.Patch.ApplyEligibility.Mode != sandboxworkspace.SyncOutApplyModePatch {
		t.Fatalf("committed patch = %#v, want eligible patch artifact", summary.Committed.Patch)
	}
	if summary.Committed.Bundle == nil ||
		summary.Committed.Bundle.ID != "committed-bundle" ||
		summary.Committed.Bundle.Kind != sandboxworkspace.SyncOutArtifactKindBundle ||
		summary.Committed.Bundle.ApplyEligibility == nil ||
		!summary.Committed.Bundle.ApplyEligibility.Eligible ||
		summary.Committed.Bundle.ApplyEligibility.Mode != sandboxworkspace.SyncOutApplyModeBundle {
		t.Fatalf("committed bundle = %#v, want eligible bundle artifact", summary.Committed.Bundle)
	}
	if summary.Uncommitted.Diff == nil ||
		summary.Uncommitted.Diff.ID != "uncommitted-diff" ||
		summary.Uncommitted.Diff.Kind != sandboxworkspace.SyncOutArtifactKindDiff ||
		summary.Uncommitted.Diff.ApplyEligibility == nil ||
		summary.Uncommitted.Diff.ApplyEligibility.Eligible {
		t.Fatalf("uncommitted diff = %#v, want ineligible manual-review artifact", summary.Uncommitted.Diff)
	}
	if summary.Untracked.Archive == nil ||
		summary.Untracked.Archive.ID != "untracked-archive" ||
		summary.Untracked.Archive.Kind != sandboxworkspace.SyncOutArtifactKindArchive ||
		summary.Untracked.List == nil ||
		summary.Untracked.List.ID != "untracked-list" ||
		summary.Untracked.List.Kind != sandboxworkspace.SyncOutArtifactKindFileList {
		t.Fatalf("untracked artifacts = %#v, want archive and list", summary.Untracked)
	}

	if len(summary.CoreArtifacts) != 3 {
		t.Fatalf("core artifacts = %#v, want PRD, reports archive, and partial stdout summary", summary.CoreArtifacts)
	}
	if got, want := summary.CoreArtifacts[0].ID, "prd"; got != want {
		t.Fatalf("first core artifact ID = %q, want %q", got, want)
	}
	if got, want := summary.CoreArtifacts[2].ID, "stdout-summary"; got != want {
		t.Fatalf("third core artifact ID = %q, want partial artifact %q", got, want)
	}
	if summary.Recovery.Status != sandboxworkspace.SyncOutRecoveryStatusCollected ||
		len(summary.Recovery.Artifacts) != 1 ||
		summary.Recovery.Artifacts[0].ID != "recovery-patch" ||
		summary.Recovery.Artifacts[0].Kind != sandboxworkspace.SyncOutArtifactKindRecovery {
		t.Fatalf("recovery = %#v, want collected recovery patch", summary.Recovery)
	}
	if !summary.Apply.Eligible ||
		summary.Apply.Mode != sandboxworkspace.SyncOutApplyModePatch ||
		summary.Apply.ArtifactID != "committed-patch" ||
		len(summary.Apply.Reasons) != 1 ||
		summary.Apply.Reasons[0] != sandboxworkspace.SyncOutApplyEligibilityReasonEligiblePatch {
		t.Fatalf("apply = %#v, want committed patch selected", summary.Apply)
	}
	if len(summary.Warnings) != 1 ||
		summary.Warnings[0].Code != "copy_out" ||
		summary.Warnings[0].Message != "optional sandbox execution artifact is missing" ||
		summary.Warnings[0].ArtifactID != "stdout-summary" {
		t.Fatalf("warnings = %#v, want safe artifact warning", summary.Warnings)
	}

	encoded := string(mustJSONBytes(t, summary))
	for _, forbidden := range []string{
		"https://token-secret@example.com/org/repo.git",
		"token-secret",
		`"repo"`,
		"sourcePath",
		"destinationPath",
		"remotePath",
		"tempPath",
		"endpoint",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("sync-out summary leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestBuildSyncOutSummaryFromArtifactsMissingOptionalCategories(t *testing.T) {
	summary := BuildSyncOutSummaryFromArtifacts(&Manifest{})

	if summary.Committed.Patch != nil || summary.Committed.Bundle != nil {
		t.Fatalf("committed artifacts = %#v, want explicit empty committed state", summary.Committed)
	}
	if summary.Uncommitted.Diff != nil {
		t.Fatalf("uncommitted artifacts = %#v, want explicit empty uncommitted state", summary.Uncommitted)
	}
	if summary.Untracked.Archive != nil || summary.Untracked.List != nil {
		t.Fatalf("untracked artifacts = %#v, want explicit empty untracked state", summary.Untracked)
	}
	if summary.Recovery.Status != sandboxworkspace.SyncOutRecoveryStatusUnavailable {
		t.Fatalf("recovery status = %q, want unavailable", summary.Recovery.Status)
	}
	if summary.Apply.Eligible ||
		len(summary.Apply.Reasons) != 1 ||
		summary.Apply.Reasons[0] != sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact {
		t.Fatalf("apply = %#v, want no eligible artifact decision", summary.Apply)
	}
}
