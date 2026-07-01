package sandboxexecution

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

const (
	syncOutCommittedPatchID   = "committed-patch"
	syncOutCommittedBundleID  = "committed-bundle"
	syncOutUncommittedDiffID  = "uncommitted-diff"
	syncOutUntrackedArchiveID = "untracked-archive"
	syncOutUntrackedListID    = "untracked-list"

	syncOutDefaultWarningCode = "artifact_warning"
)

// BuildSyncOutSummaryFromArtifacts converts the command-owned, redaction-safe
// execution artifact metadata into the shared workspace sync-out contract.
func BuildSyncOutSummaryFromArtifacts(manifest *Manifest) sandboxworkspace.SyncOutSummary {
	summary := sandboxworkspace.SyncOutSummary{
		Recovery: sandboxworkspace.SyncOutRecoveryState{
			Status: sandboxworkspace.SyncOutRecoveryStatusUnavailable,
		},
		Apply: sandboxworkspace.SyncOutApplyDecision{
			Eligible: false,
			Reasons:  []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact},
		},
	}
	if manifest == nil {
		return summary
	}
	summary.Workspace = syncOutWorkspaceRef(manifest.Workspace)

	recoveryPartial := false
	if manifest.ArtifactMetadata != nil {
		for _, entry := range manifest.ArtifactMetadata.Collected {
			addSyncOutArtifact(&summary, entry, true, &recoveryPartial)
		}
		for _, entry := range manifest.ArtifactMetadata.Partial {
			addSyncOutArtifact(&summary, entry, false, &recoveryPartial)
		}
		for _, warning := range manifest.ArtifactMetadata.Warnings {
			summary.Warnings = append(summary.Warnings, syncOutWarning(warning))
		}
	}

	if recoveryPartial {
		summary.Recovery.Status = sandboxworkspace.SyncOutRecoveryStatusPartial
	} else if len(summary.Recovery.Artifacts) > 0 {
		summary.Recovery.Status = sandboxworkspace.SyncOutRecoveryStatusCollected
	}
	summary.Apply = syncOutApplyDecision(summary)
	return summary
}

func syncOutWorkspaceRef(workspace *sandbox.SandboxWorkspace) sandboxworkspace.SyncOutWorkspaceRef {
	if workspace == nil {
		return sandboxworkspace.SyncOutWorkspaceRef{}
	}
	return sandboxworkspace.SyncOutWorkspaceRef{
		Mode:        strings.TrimSpace(workspace.Mode),
		InputSource: strings.TrimSpace(workspace.InputSource),
		Branch:      strings.TrimSpace(workspace.Branch),
		SyncRef:     strings.TrimSpace(workspace.SyncRef),
	}
}

func addSyncOutArtifact(summary *sandboxworkspace.SyncOutSummary, entry ArtifactMetadataEntry, collected bool, recoveryPartial *bool) {
	kind := syncOutArtifactKind(entry)
	artifact := syncOutArtifact(entry, kind)
	switch kind {
	case sandboxworkspace.SyncOutArtifactKindPatch:
		artifact.ApplyEligibility = syncOutEligibleArtifactEligibility(collected && artifact.StoredPath != "", sandboxworkspace.SyncOutApplyModePatch)
		chooseSyncOutArtifact(&summary.Committed.Patch, artifact)
	case sandboxworkspace.SyncOutArtifactKindBundle:
		artifact.ApplyEligibility = syncOutEligibleArtifactEligibility(collected && artifact.StoredPath != "", sandboxworkspace.SyncOutApplyModeBundle)
		chooseSyncOutArtifact(&summary.Committed.Bundle, artifact)
	case sandboxworkspace.SyncOutArtifactKindDiff:
		artifact.ApplyEligibility = &sandboxworkspace.SyncOutApplyEligibility{
			Eligible: false,
			Reasons:  []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonManualReviewRequired},
		}
		chooseSyncOutArtifact(&summary.Uncommitted.Diff, artifact)
	case sandboxworkspace.SyncOutArtifactKindArchive:
		chooseSyncOutArtifact(&summary.Untracked.Archive, artifact)
	case sandboxworkspace.SyncOutArtifactKindFileList:
		chooseSyncOutArtifact(&summary.Untracked.List, artifact)
	case sandboxworkspace.SyncOutArtifactKindRecovery:
		if collected && strings.TrimSpace(entry.StoredPath) != "" {
			summary.Recovery.Artifacts = append(summary.Recovery.Artifacts, artifact)
		} else if recoveryPartial != nil {
			*recoveryPartial = true
		}
	default:
		summary.CoreArtifacts = append(summary.CoreArtifacts, artifact)
	}
}

func syncOutArtifact(entry ArtifactMetadataEntry, kind sandboxworkspace.SyncOutArtifactKind) sandboxworkspace.SyncOutArtifact {
	return sandboxworkspace.SyncOutArtifact{
		ID:          strings.TrimSpace(entry.ID),
		DisplayName: strings.TrimSpace(entry.Name),
		Kind:        kind,
		DisplayPath: strings.TrimSpace(entry.Path),
		StoredPath:  strings.TrimSpace(entry.StoredPath),
	}
}

func chooseSyncOutArtifact(current **sandboxworkspace.SyncOutArtifact, candidate sandboxworkspace.SyncOutArtifact) {
	if current == nil {
		return
	}
	if *current == nil || ((*current).StoredPath == "" && candidate.StoredPath != "") {
		candidateCopy := candidate
		*current = &candidateCopy
	}
}

func syncOutArtifactKind(entry ArtifactMetadataEntry) sandboxworkspace.SyncOutArtifactKind {
	id := strings.TrimSpace(entry.ID)
	path := strings.TrimSpace(entry.Path)
	switch {
	case id == syncOutCommittedPatchID || syncOutPathLooksLike(path, "committed", ".patch"):
		return sandboxworkspace.SyncOutArtifactKindPatch
	case id == syncOutCommittedBundleID || syncOutPathLooksLike(path, "committed", ".bundle"):
		return sandboxworkspace.SyncOutArtifactKindBundle
	case id == syncOutUncommittedDiffID || syncOutPathLooksLike(path, "uncommitted", ".diff"):
		return sandboxworkspace.SyncOutArtifactKindDiff
	case id == syncOutUntrackedArchiveID || syncOutPathLooksLike(path, "untracked", ".tar") || syncOutPathLooksLike(path, "untracked", ".tgz"):
		return sandboxworkspace.SyncOutArtifactKindArchive
	case id == syncOutUntrackedListID || syncOutPathLooksLike(path, "untracked", ".txt"):
		return sandboxworkspace.SyncOutArtifactKindFileList
	case id == recoveryArtifactID || strings.HasPrefix(path, ".hal/recovery/"):
		return sandboxworkspace.SyncOutArtifactKindRecovery
	default:
		return sandboxworkspace.SyncOutArtifactKindCore
	}
}

func syncOutPathLooksLike(path, marker, suffix string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	return strings.Contains(path, marker) && strings.HasSuffix(path, suffix)
}

func syncOutEligibleArtifactEligibility(collected bool, mode sandboxworkspace.SyncOutApplyMode) *sandboxworkspace.SyncOutApplyEligibility {
	if !collected {
		return &sandboxworkspace.SyncOutApplyEligibility{
			Eligible: false,
			Mode:     mode,
			Reasons:  []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonUnsafeArtifact},
		}
	}
	switch mode {
	case sandboxworkspace.SyncOutApplyModeBundle:
		return &sandboxworkspace.SyncOutApplyEligibility{
			Eligible: true,
			Mode:     mode,
			Reasons:  []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonEligibleBundle},
		}
	default:
		return &sandboxworkspace.SyncOutApplyEligibility{
			Eligible: true,
			Mode:     sandboxworkspace.SyncOutApplyModePatch,
			Reasons:  []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonEligiblePatch},
		}
	}
}

func syncOutApplyDecision(summary sandboxworkspace.SyncOutSummary) sandboxworkspace.SyncOutApplyDecision {
	if summary.Committed.Patch != nil &&
		summary.Committed.Patch.ApplyEligibility != nil &&
		summary.Committed.Patch.ApplyEligibility.Eligible {
		return sandboxworkspace.SyncOutApplyDecision{
			Eligible:   true,
			Mode:       sandboxworkspace.SyncOutApplyModePatch,
			ArtifactID: summary.Committed.Patch.ID,
			Reasons:    append([]sandboxworkspace.SyncOutApplyEligibilityReason(nil), summary.Committed.Patch.ApplyEligibility.Reasons...),
		}
	}
	if summary.Committed.Bundle != nil &&
		summary.Committed.Bundle.ApplyEligibility != nil &&
		summary.Committed.Bundle.ApplyEligibility.Eligible {
		return sandboxworkspace.SyncOutApplyDecision{
			Eligible:   true,
			Mode:       sandboxworkspace.SyncOutApplyModeBundle,
			ArtifactID: summary.Committed.Bundle.ID,
			Reasons:    append([]sandboxworkspace.SyncOutApplyEligibilityReason(nil), summary.Committed.Bundle.ApplyEligibility.Reasons...),
		}
	}
	return sandboxworkspace.SyncOutApplyDecision{
		Eligible: false,
		Reasons:  []sandboxworkspace.SyncOutApplyEligibilityReason{sandboxworkspace.SyncOutApplyEligibilityReasonNoEligibleArtifact},
	}
}

func syncOutWarning(warning ArtifactWarning) sandboxworkspace.SyncOutWarning {
	code := strings.TrimSpace(warning.Phase)
	if code == "" {
		code = syncOutDefaultWarningCode
	}
	return sandboxworkspace.SyncOutWarning{
		Code:       code,
		Message:    strings.TrimSpace(warning.Message),
		ArtifactID: strings.TrimSpace(warning.Artifact.ID),
	}
}
