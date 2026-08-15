package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

type sandboxApplyExecutionDeps struct {
	defaultStore    func() (sandboxexecution.Store, error)
	workingDir      func() (string, error)
	currentBranch   func(string) (string, error)
	currentRevision func(context.Context, string) (string, error)
	applySyncOut    sandboxSyncOutApplier
}

const sandboxExecutionPRDDisplayPath = template.HalDir + "/" + template.PRDFile

var sandboxApplyExecutionCmd = newSandboxApplyExecutionCommand(sandboxApplyExecutionDeps{})

func init() {
	sandboxCmd.AddCommand(sandboxApplyExecutionCmd)
}

func newSandboxApplyExecutionCommand(deps sandboxApplyExecutionDeps) *cobra.Command {
	return &cobra.Command{
		Use:   "apply EXECUTION_ID",
		Short: "Apply a completed sandbox execution to the current worktree",
		Args:  exactArgsValidation(1),
		Long: `Apply durable sync-out artifacts from one completed sandbox execution to
the current host worktree.

This is an apply-only path. It does not resolve, provision, start, materialize,
or execute a sandbox. The execution must have succeeded, its collected
.hal/prd.json must show every story complete, and it must contain an eligible
committed patch or bundle. Its stored host project and workspace branch must
match the current worktree; a commit-valued sync ref must also match host HEAD.
Host mutation still uses the standard clean-worktree, workspace-lock, and Git
dry-run safety checks.

Use the sandboxExecutionId emitted by a prior sandbox run with --json and
--sandbox-sync-out. An execution that already records a successful apply is
rejected to prevent accidental double application. Tracked uncommitted output,
including PRD completion metadata, remains a separate manual-review handoff.`,
		Example: `  hal run --sandbox --sandbox-sync-out --json
  hal sandbox apply run-1784128525446734264`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSandboxCobra(cmd, "Sandbox execution apply failed", func() error {
				return runSandboxApplyExecution(cmd.Context(), args[0], cmd.OutOrStdout(), deps)
			})
		},
	}
}

func runSandboxApplyExecution(ctx context.Context, executionID string, out io.Writer, deps sandboxApplyExecutionDeps) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if out == nil {
		out = io.Discard
	}
	if deps.defaultStore == nil {
		deps.defaultStore = sandboxexecution.DefaultStore
	}
	if deps.workingDir == nil {
		deps.workingDir = os.Getwd
	}
	if deps.currentBranch == nil {
		deps.currentBranch = compound.CurrentBranchOptionalInDir
	}
	if deps.currentRevision == nil {
		deps.currentRevision = sandboxApplyCurrentRevision
	}
	if deps.applySyncOut == nil {
		deps.applySyncOut = defaultSandboxSyncOutApplier
	}

	store, err := deps.defaultStore()
	if err != nil {
		return fmt.Errorf("open sandbox execution store: %w", err)
	}
	manifest, err := store.LoadManifest(executionID)
	if err != nil {
		return fmt.Errorf("load sandbox execution for completed apply: %w", err)
	}
	if err := validateSandboxExecutionReadyForCompletedApply(store, manifest); err != nil {
		return err
	}
	projectDir, err := deps.workingDir()
	if err != nil {
		return fmt.Errorf("resolve host worktree for sandbox execution apply: %w", err)
	}
	projectDir = strings.TrimSpace(projectDir)
	if projectDir == "" {
		return fmt.Errorf("resolve host worktree for sandbox execution apply: working directory is required")
	}
	projectDir, err = canonicalSandboxApplyProjectDir(projectDir)
	if err != nil {
		return fmt.Errorf("resolve host worktree for sandbox execution apply: %w", err)
	}
	if err := validateSandboxExecutionHostIdentity(ctx, manifest, projectDir, deps.currentBranch, deps.currentRevision); err != nil {
		return err
	}

	result, err := applySandboxSyncOut(ctx, store, sandboxSyncOutApplyRequest{
		ExecutionID: manifest.ID,
		Purpose:     manifest.Purpose,
		ProjectDir:  projectDir,
		Options: sandboxSyncOutOptions{
			Enabled: true,
			Apply:   true,
		},
		Authorize: func(locked sandboxexecution.Store, current *sandboxexecution.Manifest) error {
			if err := validateSandboxExecutionReadyForCompletedApply(locked, current); err != nil {
				return err
			}
			return validateSandboxExecutionHostIdentity(ctx, current, projectDir, deps.currentBranch, deps.currentRevision)
		},
	}, deps.applySyncOut)
	if err != nil {
		return fmt.Errorf("apply completed sandbox execution %q: %w", manifest.ID, err)
	}
	if result.Applied && result.Status == sandboxworkspace.SafeApplyStatusApplied {
		message := fmt.Sprintf("Applied sandbox execution %s to the current host worktree.\n", manifest.ID)
		if summary := sandboxexecution.BuildSyncOutSummaryFromArtifacts(manifest); summary.Uncommitted.Diff != nil {
			message += "Tracked uncommitted sandbox output remains manual-review-only; inspect syncOut.uncommitted in the stored execution manifest.\n"
		}
		_, err = fmt.Fprint(out, message)
		return err
	}
	reasons := sandboxApplyExecutionReasonSummary(result.Reasons)
	if reasons == "" {
		reasons = "manual handoff required"
	}
	return fmt.Errorf("sandbox execution %q was not applied: %s", manifest.ID, reasons)
}

func validateSandboxExecutionHostIdentity(ctx context.Context, manifest *sandboxexecution.Manifest, projectDir string, currentBranch func(string) (string, error), currentRevision func(context.Context, string) (string, error)) error {
	storedProjectDir := strings.TrimSpace(manifest.ProjectDir)
	if storedProjectDir == "" {
		return fmt.Errorf("sandbox execution %q has no stored host project identity", manifest.ID)
	}
	storedProjectDir, err := canonicalSandboxApplyProjectDir(storedProjectDir)
	if err != nil {
		return fmt.Errorf("resolve sandbox execution %q stored host project identity: %w", manifest.ID, err)
	}
	projectDir, err = canonicalSandboxApplyProjectDir(projectDir)
	if err != nil {
		return fmt.Errorf("resolve current host project identity: %w", err)
	}
	if storedProjectDir != projectDir {
		return fmt.Errorf("sandbox execution %q does not belong to the current host worktree", manifest.ID)
	}

	expectedBranch := ""
	if manifest.Workspace != nil {
		expectedBranch = strings.TrimSpace(manifest.Workspace.Branch)
	}
	if expectedBranch == "" {
		return fmt.Errorf("sandbox execution %q has no stored workspace branch identity", manifest.ID)
	}
	if currentBranch == nil {
		return fmt.Errorf("resolve current host branch: dependency is required")
	}
	branch, err := currentBranch(projectDir)
	if err != nil {
		return fmt.Errorf("resolve current host branch for sandbox execution apply: %w", err)
	}
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return fmt.Errorf("sandbox execution %q cannot apply to a detached host worktree", manifest.ID)
	}
	if branch != expectedBranch {
		return fmt.Errorf("sandbox execution %q targets branch %q but the current host worktree is on %q", manifest.ID, expectedBranch, branch)
	}
	expectedRevision := strings.TrimSpace(manifest.Workspace.SyncRef)
	if sandboxApplyCommitRevision(expectedRevision) {
		if currentRevision == nil {
			return fmt.Errorf("resolve current host revision: dependency is required")
		}
		revision, err := currentRevision(ctx, projectDir)
		if err != nil {
			return fmt.Errorf("resolve current host revision for sandbox execution apply: %w", err)
		}
		if !strings.EqualFold(strings.TrimSpace(revision), expectedRevision) {
			return fmt.Errorf("sandbox execution %q stored workspace revision does not match the current host HEAD", manifest.ID)
		}
	}
	return nil
}

func sandboxApplyCurrentRevision(ctx context.Context, projectDir string) (string, error) {
	status, err := (sandboxworkspace.GitCLIInspector{}).InspectGit(ctx, projectDir)
	if err != nil {
		return "", err
	}
	if !status.IsGitWorktree || strings.TrimSpace(status.HeadRef) == "" {
		return "", fmt.Errorf("current host worktree has no Git HEAD revision")
	}
	return strings.TrimSpace(status.HeadRef), nil
}

func sandboxApplyCommitRevision(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func canonicalSandboxApplyProjectDir(projectDir string) (string, error) {
	abs, err := filepath.Abs(strings.TrimSpace(projectDir))
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func validateSandboxExecutionReadyForCompletedApply(store sandboxexecution.Store, manifest *sandboxexecution.Manifest) error {
	if manifest == nil {
		return fmt.Errorf("sandbox execution manifest is required for completed apply")
	}
	if manifest.Status != sandboxexecution.StatusSucceeded {
		return fmt.Errorf("sandbox execution %q has status %q; completed apply requires status %q", manifest.ID, manifest.Status, sandboxexecution.StatusSucceeded)
	}
	if manifest.SyncOutApply != nil && (manifest.SyncOutApply.Applied || manifest.SyncOutApply.Status == sandboxworkspace.SafeApplyStatusApplied) {
		return fmt.Errorf("sandbox execution %q already records a successful host apply", manifest.ID)
	}

	prdArtifact := sandboxExecutionCollectedArtifactByPath(manifest, sandboxExecutionPRDDisplayPath)
	if prdArtifact == nil || strings.TrimSpace(prdArtifact.StoredPath) == "" {
		return fmt.Errorf("sandbox execution %q has no collected %s completion artifact", manifest.ID, sandboxExecutionPRDDisplayPath)
	}
	prdFile, err := store.OpenStoredFile(manifest.ID, prdArtifact.StoredPath)
	if err != nil {
		return fmt.Errorf("open sandbox execution %q PRD completion artifact: %w", manifest.ID, err)
	}
	data, err := io.ReadAll(prdFile)
	closeErr := prdFile.Close()
	if err != nil {
		return fmt.Errorf("read sandbox execution %q PRD completion artifact: %w", manifest.ID, err)
	}
	if closeErr != nil {
		return fmt.Errorf("close sandbox execution %q PRD completion artifact", manifest.ID)
	}
	var prd engine.PRD
	if err := json.Unmarshal(data, &prd); err != nil {
		return fmt.Errorf("parse sandbox execution %q PRD completion artifact: %w", manifest.ID, err)
	}
	completed, total := prd.Progress()
	if total == 0 {
		return fmt.Errorf("sandbox execution %q PRD completion artifact has no stories", manifest.ID)
	}
	if completed != total {
		return fmt.Errorf("sandbox execution %q is incomplete (%d/%d stories passed); completed apply requires every stored PRD story to pass", manifest.ID, completed, total)
	}
	return nil
}

func sandboxExecutionCollectedArtifactByPath(manifest *sandboxexecution.Manifest, displayPath string) *sandboxexecution.ArtifactMetadataEntry {
	if manifest == nil || manifest.ArtifactMetadata == nil {
		return nil
	}
	for i := range manifest.ArtifactMetadata.Collected {
		artifact := &manifest.ArtifactMetadata.Collected[i]
		if strings.TrimSpace(artifact.Path) == strings.TrimSpace(displayPath) {
			return artifact
		}
	}
	return nil
}

func sandboxApplyExecutionReasonSummary(reasons []sandboxworkspace.SyncOutApplyEligibilityReason) string {
	values := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		if value := strings.TrimSpace(string(reason)); value != "" {
			values = append(values, value)
		}
	}
	return strings.Join(values, ", ")
}
