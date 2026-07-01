package sandboxworkspace

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SafeApplier validates sync-out artifacts before applying them to a host
// worktree.
type SafeApplier struct {
	Git   SafeApplyGit
	Locks SafeApplyLockProvider
}

// SafeApplyGit is the narrow host-side Git boundary used by safe apply.
type SafeApplyGit interface {
	CheckCleanWorktree(context.Context, SafeApplyGitRequest) (DirtyState, error)
	CheckPatch(context.Context, SafeApplyGitRequest) error
	ApplyPatch(context.Context, SafeApplyGitRequest) error
	CheckBundle(context.Context, SafeApplyGitRequest) error
}

// SafeApplyGitRequest identifies the host worktree and local payload for a Git
// validation or apply operation. These paths are never copied into results.
type SafeApplyGitRequest struct {
	ProjectDir  string
	PayloadPath string
}

// SafeApplyLockProvider acquires the host workspace lock used to serialize a
// safe apply attempt.
type SafeApplyLockProvider interface {
	AcquireSafeApplyLock(resourceKey string) (SafeApplyLock, error)
}

// SafeApplyLock is an acquired host workspace lock.
type SafeApplyLock interface {
	Release() error
}

type directSafeApplyLockProvider struct {
	manager LockManager
}

func (p directSafeApplyLockProvider) AcquireSafeApplyLock(resourceKey string) (SafeApplyLock, error) {
	return p.manager.Acquire(resourceKey)
}

// GitCLIHostApplier validates and applies payloads with local Git commands.
type GitCLIHostApplier struct{}

// CheckCleanWorktree reports whether the host worktree has local changes.
func (GitCLIHostApplier) CheckCleanWorktree(ctx context.Context, req SafeApplyGitRequest) (DirtyState, error) {
	raw, err := gitOutputSafe(ctx, req.ProjectDir, "git status --porcelain", "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return DirtyState{}, err
	}
	return parsePorcelainDirty(raw), nil
}

// CheckPatch runs the patch dry-run boundary.
func (GitCLIHostApplier) CheckPatch(ctx context.Context, req SafeApplyGitRequest) error {
	return gitRunSafe(ctx, req.ProjectDir, "git apply --check", "apply", "--check", req.PayloadPath)
}

// ApplyPatch applies a patch after the caller has completed dry-run checks.
func (GitCLIHostApplier) ApplyPatch(ctx context.Context, req SafeApplyGitRequest) error {
	return gitRunSafe(ctx, req.ProjectDir, "git apply", "apply", req.PayloadPath)
}

// CheckBundle verifies a bundle payload as the bundle dry-run boundary.
func (GitCLIHostApplier) CheckBundle(ctx context.Context, req SafeApplyGitRequest) error {
	return gitRunSafe(ctx, req.ProjectDir, "git bundle verify", "bundle", "verify", req.PayloadPath)
}

// SafeApplyRequest describes an explicit host apply attempt for one sync-out
// artifact. ProjectDir and PayloadPath are command-local inputs and are omitted
// from the structured result.
type SafeApplyRequest struct {
	ProjectDir  string
	PayloadPath string
	ResourceKey string
	LockDir     string
	Artifact    SyncOutArtifact
	Mutate      bool
}

// SafeApplyStatus classifies the host apply outcome without leaking paths or
// command output.
type SafeApplyStatus string

const (
	SafeApplyStatusDryRunPassed    SafeApplyStatus = "dry_run_passed"
	SafeApplyStatusApplied         SafeApplyStatus = "applied"
	SafeApplyStatusHandoffRequired SafeApplyStatus = "handoff_required"
)

// SafeApplyResult is the redaction-safe outcome of a host apply attempt.
type SafeApplyResult struct {
	Status              SafeApplyStatus                 `json:"status"`
	Applied             bool                            `json:"applied"`
	DryRunPassed        bool                            `json:"dryRunPassed"`
	Mode                SyncOutApplyMode                `json:"mode,omitempty"`
	ArtifactID          string                          `json:"artifactId,omitempty"`
	DisplayName         string                          `json:"displayName,omitempty"`
	DisplayPath         string                          `json:"displayPath,omitempty"`
	Reasons             []SyncOutApplyEligibilityReason `json:"reasons,omitempty"`
	Warnings            []SyncOutWarning                `json:"warnings,omitempty"`
	HandoffInstructions []SyncOutHandoffInstruction     `json:"handoffInstructions,omitempty"`
}

const (
	safeApplyDirtyWorktreeWarningCode        = "dirty_worktree"
	safeApplyWorktreeCheckFailedWarningCode  = "worktree_check_failed"
	safeApplyWorkspaceLockFailedWarningCode  = "workspace_lock_failed"
	safeApplyWorkspaceLockReleaseWarningCode = "workspace_lock_release_failed"
	safeApplyDryRunFailedWarningCode         = "dry_run_failed"
	safeApplyApplyFailedWarningCode          = "apply_failed"
)

// SafeApply validates an eligible sync-out artifact and, when requested,
// applies it only after dry-run validation passes.
func SafeApply(ctx context.Context, req SafeApplyRequest) (SafeApplyResult, error) {
	return (SafeApplier{}).Apply(ctx, req)
}

// Apply validates an eligible sync-out artifact and, when requested, applies it
// only after dry-run validation passes.
func (a SafeApplier) Apply(ctx context.Context, req SafeApplyRequest) (SafeApplyResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	mode := safeApplyMode(req.Artifact)
	result := SafeApplyResult{
		Status:      SafeApplyStatusHandoffRequired,
		Mode:        mode,
		ArtifactID:  strings.TrimSpace(req.Artifact.ID),
		DisplayName: strings.TrimSpace(req.Artifact.DisplayName),
		DisplayPath: strings.TrimSpace(req.Artifact.DisplayPath),
	}

	if err := validateSafeApplyRequest(req); err != nil {
		return result, err
	}
	if !safeApplyArtifactEligible(req.Artifact) {
		result.Reasons = safeApplyEligibilityReasons(req.Artifact, SyncOutApplyEligibilityReasonUnsafeArtifact)
		return result, nil
	}
	if !safeApplySupportedMode(mode) {
		result.Reasons = []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonUnsafeArtifact}
		return result, nil
	}

	git := a.Git
	if git == nil {
		git = GitCLIHostApplier{}
	}
	gitReq := SafeApplyGitRequest{
		ProjectDir:  strings.TrimSpace(req.ProjectDir),
		PayloadPath: strings.TrimSpace(req.PayloadPath),
	}

	lock, lockErr := safeApplyLockProvider(a, req).AcquireSafeApplyLock(safeApplyResourceKey(req))
	if lockErr != nil {
		result.Reasons = []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonManualReviewRequired}
		result.Warnings = []SyncOutWarning{safeApplyWarning(safeApplyWorkspaceLockFailedWarningCode, req.Artifact, lockErr)}
		return result, nil
	}
	releaseLock := func(result SafeApplyResult) (SafeApplyResult, error) {
		if err := lock.Release(); err != nil {
			result.Warnings = append(result.Warnings, safeApplyWarning(safeApplyWorkspaceLockReleaseWarningCode, req.Artifact, err))
		}
		return result, nil
	}

	if dirty, err := git.CheckCleanWorktree(ctx, gitReq); err != nil {
		result.Reasons = []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonManualReviewRequired}
		result.Warnings = []SyncOutWarning{safeApplyWarning(safeApplyWorktreeCheckFailedWarningCode, req.Artifact, err)}
		return releaseLock(result)
	} else if dirty.Any() {
		result.Reasons = []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonDirtyWorktree}
		result.Warnings = []SyncOutWarning{safeApplyDirtyWorktreeWarning(req.Artifact, dirty)}
		return releaseLock(result)
	}
	if err := safeApplyDryRun(ctx, git, mode, gitReq); err != nil {
		result.Reasons = []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonDryRunFailed}
		result.Warnings = []SyncOutWarning{safeApplyWarning(safeApplyDryRunFailedWarningCode, req.Artifact, err)}
		return releaseLock(result)
	}

	result.DryRunPassed = true
	if !req.Mutate {
		result.Status = SafeApplyStatusDryRunPassed
		result.Reasons = safeApplyEligibilityReasons(req.Artifact, safeApplyEligibleReason(mode))
		return releaseLock(result)
	}

	switch mode {
	case SyncOutApplyModePatch:
		if err := git.ApplyPatch(ctx, gitReq); err != nil {
			result.Reasons = []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonManualReviewRequired}
			result.Warnings = []SyncOutWarning{safeApplyWarning(safeApplyApplyFailedWarningCode, req.Artifact, err)}
			return releaseLock(result)
		}
		result.Status = SafeApplyStatusApplied
		result.Applied = true
		result.Reasons = safeApplyEligibilityReasons(req.Artifact, SyncOutApplyEligibilityReasonEligiblePatch)
		return releaseLock(result)
	case SyncOutApplyModeBundle:
		result.Reasons = []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonManualReviewRequired}
		return releaseLock(result)
	default:
		result.Reasons = []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonUnsafeArtifact}
		return releaseLock(result)
	}
}

func validateSafeApplyRequest(req SafeApplyRequest) error {
	if strings.TrimSpace(req.ProjectDir) == "" {
		return fmt.Errorf("safe apply: project directory is required")
	}
	if strings.TrimSpace(req.PayloadPath) == "" {
		return fmt.Errorf("safe apply: payload path is required")
	}
	return nil
}

func safeApplySupportedMode(mode SyncOutApplyMode) bool {
	switch mode {
	case SyncOutApplyModePatch, SyncOutApplyModeBundle:
		return true
	default:
		return false
	}
}

func safeApplyDryRun(ctx context.Context, git SafeApplyGit, mode SyncOutApplyMode, req SafeApplyGitRequest) error {
	switch mode {
	case SyncOutApplyModePatch:
		return git.CheckPatch(ctx, req)
	case SyncOutApplyModeBundle:
		return git.CheckBundle(ctx, req)
	default:
		return fmt.Errorf("safe apply dry-run: unsupported apply mode %q", mode)
	}
}

func safeApplyLockProvider(applier SafeApplier, req SafeApplyRequest) SafeApplyLockProvider {
	if applier.Locks != nil {
		return applier.Locks
	}
	lockDir := strings.TrimSpace(req.LockDir)
	if lockDir == "" {
		lockDir = defaultSafeApplyLockDir()
	}
	return directSafeApplyLockProvider{manager: NewLockManager(lockDir)}
}

func defaultSafeApplyLockDir() string {
	return filepath.Join(os.TempDir(), "hal-workspace-locks")
}

func safeApplyResourceKey(req SafeApplyRequest) string {
	if resourceKey := strings.TrimSpace(req.ResourceKey); resourceKey != "" {
		return resourceKey
	}
	return directResourceKey(strings.TrimSpace(req.ProjectDir))
}

func safeApplyArtifactEligible(artifact SyncOutArtifact) bool {
	return artifact.ApplyEligibility != nil && artifact.ApplyEligibility.Eligible
}

func safeApplyMode(artifact SyncOutArtifact) SyncOutApplyMode {
	if artifact.ApplyEligibility != nil && artifact.ApplyEligibility.Mode != "" {
		return artifact.ApplyEligibility.Mode
	}
	switch artifact.Kind {
	case SyncOutArtifactKindPatch:
		return SyncOutApplyModePatch
	case SyncOutArtifactKindBundle:
		return SyncOutApplyModeBundle
	default:
		return ""
	}
}

func safeApplyEligibleReason(mode SyncOutApplyMode) SyncOutApplyEligibilityReason {
	if mode == SyncOutApplyModeBundle {
		return SyncOutApplyEligibilityReasonEligibleBundle
	}
	return SyncOutApplyEligibilityReasonEligiblePatch
}

func safeApplyEligibilityReasons(artifact SyncOutArtifact, fallback SyncOutApplyEligibilityReason) []SyncOutApplyEligibilityReason {
	if artifact.ApplyEligibility != nil && len(artifact.ApplyEligibility.Reasons) > 0 {
		return append([]SyncOutApplyEligibilityReason(nil), artifact.ApplyEligibility.Reasons...)
	}
	return []SyncOutApplyEligibilityReason{fallback}
}

func safeApplyWarning(code string, artifact SyncOutArtifact, err error) SyncOutWarning {
	return SyncOutWarning{
		Code:       code,
		Message:    sanitizeSafeApplyMessage(err),
		ArtifactID: strings.TrimSpace(artifact.ID),
	}
}

func safeApplyDirtyWorktreeWarning(artifact SyncOutArtifact, dirty DirtyState) SyncOutWarning {
	return SyncOutWarning{
		Code:       safeApplyDirtyWorktreeWarningCode,
		Message:    safeApplyDirtyWorktreeMessage(dirty),
		ArtifactID: strings.TrimSpace(artifact.ID),
	}
}

func safeApplyDirtyWorktreeMessage(dirty DirtyState) string {
	categories := make([]string, 0, 3)
	if dirty.Staged {
		categories = append(categories, "staged")
	}
	if dirty.Unstaged {
		categories = append(categories, "unstaged")
	}
	if dirty.Untracked {
		categories = append(categories, "untracked")
	}
	if len(categories) == 0 {
		return "host worktree has local changes"
	}
	return "host worktree has local changes: " + strings.Join(categories, ", ")
}

func sanitizeSafeApplyMessage(err error) string {
	if err == nil {
		return ""
	}
	return sanitizePathDetail(err.Error())
}
