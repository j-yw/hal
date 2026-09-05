package sandboxworkspace

// SyncOutSummary is a command-agnostic, redaction-safe description of sandbox
// workspace output. Paths carried here are display or store-relative paths, not
// raw host temp paths, sandbox temp paths, endpoints, or credentials.
type SyncOutSummary struct {
	Workspace     SyncOutWorkspaceRef         `json:"workspace"`
	Committed     SyncOutCommittedArtifacts   `json:"committed"`
	Uncommitted   SyncOutUncommittedArtifacts `json:"uncommitted"`
	Untracked     SyncOutUntrackedArtifacts   `json:"untracked"`
	CoreArtifacts []SyncOutArtifact           `json:"coreArtifacts,omitempty"`
	Recovery      SyncOutRecoveryState        `json:"recovery"`
	Warnings      []SyncOutWarning            `json:"warnings,omitempty"`
	Apply         SyncOutApplyDecision        `json:"apply"`
}

// SyncOutWorkspaceRef identifies the materialized workspace state without
// storing repository URLs, endpoints, hostnames, or filesystem roots.
type SyncOutWorkspaceRef struct {
	Mode        string `json:"mode,omitempty"`
	InputSource string `json:"inputSource,omitempty"`
	Branch      string `json:"branch,omitempty"`
	SyncRef     string `json:"syncRef,omitempty"`
}

// SyncOutCommittedArtifacts describes committed sandbox changes that can be
// represented as a patch or bundle for a future apply step.
type SyncOutCommittedArtifacts struct {
	Patch  *SyncOutArtifact `json:"patch,omitempty"`
	Bundle *SyncOutArtifact `json:"bundle,omitempty"`
}

// SyncOutUncommittedArtifacts describes uncommitted sandbox worktree changes.
type SyncOutUncommittedArtifacts struct {
	Diff *SyncOutArtifact `json:"diff,omitempty"`
}

// SyncOutUntrackedArtifacts describes untracked sandbox files as an archive and
// a safe file-list artifact for manual inspection.
type SyncOutUntrackedArtifacts struct {
	Archive *SyncOutArtifact `json:"archive,omitempty"`
	List    *SyncOutArtifact `json:"list,omitempty"`
}

// SyncOutArtifact identifies a durable output payload by safe names and
// relative display/store paths.
type SyncOutArtifact struct {
	ID               string                   `json:"id,omitempty"`
	DisplayName      string                   `json:"displayName,omitempty"`
	Kind             SyncOutArtifactKind      `json:"kind,omitempty"`
	DisplayPath      string                   `json:"displayPath,omitempty"`
	StoredPath       string                   `json:"storedPath,omitempty"`
	ApplyEligibility *SyncOutApplyEligibility `json:"applyEligibility,omitempty"`
}

// SyncOutArtifactKind classifies sync-out payloads without binding them to a
// command manifest, factory record, runtime driver, or provider.
type SyncOutArtifactKind string

const (
	SyncOutArtifactKindPatch    SyncOutArtifactKind = "patch"
	SyncOutArtifactKindBundle   SyncOutArtifactKind = "bundle"
	SyncOutArtifactKindDiff     SyncOutArtifactKind = "diff"
	SyncOutArtifactKindArchive  SyncOutArtifactKind = "archive"
	SyncOutArtifactKindFileList SyncOutArtifactKind = "file_list"
	SyncOutArtifactKindCore     SyncOutArtifactKind = "core"
	SyncOutArtifactKindRecovery SyncOutArtifactKind = "recovery"
)

// SyncOutRecoveryState records whether durable recovery payloads are available
// before any future host apply step attempts mutation.
type SyncOutRecoveryState struct {
	Status    SyncOutRecoveryStatus `json:"status,omitempty"`
	Artifacts []SyncOutArtifact     `json:"artifacts,omitempty"`
}

// SyncOutRecoveryStatus summarizes recovery artifact availability.
type SyncOutRecoveryStatus string

const (
	SyncOutRecoveryStatusUnavailable SyncOutRecoveryStatus = "unavailable"
	SyncOutRecoveryStatusCollected   SyncOutRecoveryStatus = "collected"
	SyncOutRecoveryStatusPartial     SyncOutRecoveryStatus = "partial"
)

// SyncOutWarning records non-fatal sync-out issues using safe messages and
// artifact IDs instead of raw command output or paths.
type SyncOutWarning struct {
	Code       string `json:"code,omitempty"`
	Message    string `json:"message,omitempty"`
	ArtifactID string `json:"artifactId,omitempty"`
}

// SyncOutHandoffInstruction gives callers safe manual follow-up guidance when
// automatic apply is disabled, unavailable, or unsafe.
type SyncOutHandoffInstruction struct {
	Reason    SyncOutApplyEligibilityReason `json:"reason,omitempty"`
	Message   string                        `json:"message,omitempty"`
	Artifacts []SyncOutHandoffArtifactRef   `json:"artifacts,omitempty"`
}

// SyncOutHandoffArtifactRef identifies a durable artifact using only safe
// command-facing names and display paths.
type SyncOutHandoffArtifactRef struct {
	ID          string `json:"id,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
	DisplayPath string `json:"displayPath,omitempty"`
}

// SyncOutApplyDecision summarizes whether automatic host apply is safe for the
// sync-out result and which durable artifact is the candidate.
type SyncOutApplyDecision struct {
	Eligible   bool                            `json:"eligible"`
	Mode       SyncOutApplyMode                `json:"mode,omitempty"`
	ArtifactID string                          `json:"artifactId,omitempty"`
	Reasons    []SyncOutApplyEligibilityReason `json:"reasons,omitempty"`
}

// SyncOutApplyEligibility records per-artifact eligibility for future safe
// apply selection.
type SyncOutApplyEligibility struct {
	Eligible bool                            `json:"eligible"`
	Mode     SyncOutApplyMode                `json:"mode,omitempty"`
	Reasons  []SyncOutApplyEligibilityReason `json:"reasons,omitempty"`
}

// SyncOutApplyMode identifies the supported automatic apply payload shape.
type SyncOutApplyMode string

const (
	SyncOutApplyModePatch  SyncOutApplyMode = "patch"
	SyncOutApplyModeBundle SyncOutApplyMode = "bundle"
)

// SyncOutApplyEligibilityReason gives callers stable, safe reasons for apply
// selection or handoff.
type SyncOutApplyEligibilityReason string

const (
	SyncOutApplyEligibilityReasonEligiblePatch        SyncOutApplyEligibilityReason = "eligible_patch"
	SyncOutApplyEligibilityReasonEligibleBundle       SyncOutApplyEligibilityReason = "eligible_bundle"
	SyncOutApplyEligibilityReasonManualReviewRequired SyncOutApplyEligibilityReason = "manual_review_required"
	SyncOutApplyEligibilityReasonNoEligibleArtifact   SyncOutApplyEligibilityReason = "no_eligible_artifact"
	SyncOutApplyEligibilityReasonApplyDisabled        SyncOutApplyEligibilityReason = "apply_disabled"
	SyncOutApplyEligibilityReasonDirtyWorktree        SyncOutApplyEligibilityReason = "dirty_worktree"
	SyncOutApplyEligibilityReasonDryRunFailed         SyncOutApplyEligibilityReason = "dry_run_failed"
	SyncOutApplyEligibilityReasonUnsafeArtifact       SyncOutApplyEligibilityReason = "unsafe_artifact"
	SyncOutApplyEligibilityReasonApplyOutcomeUnknown  SyncOutApplyEligibilityReason = "apply_outcome_unknown"
)
