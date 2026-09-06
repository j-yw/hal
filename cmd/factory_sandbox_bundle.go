package cmd

import (
	"context"
	"errors"
	"io"
	"strings"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

// The source branch is exported, not the factory run branch (which need not
// exist locally). SyncRef pins the measured source HEAD. The local base must
// be contained in that history; this path never fetches a missing base.
type factorySandboxBundlePlan struct {
	Workspace                         sandboxworkspace.Plan
	BaseBranch, BaseCommit, RunBranch string
}

type factoryBundleGitSnapshot struct{ status sandboxworkspace.GitStatus }

func (s factoryBundleGitSnapshot) InspectGit(context.Context, string) (sandboxworkspace.GitStatus, error) {
	return s.status, nil
}

func planFactorySandboxBundle(ctx context.Context, projectDir string, record factory.RunRecord) (*factorySandboxBundlePlan, error) {
	status, err := (sandboxworkspace.GitCLIInspector{}).InspectGit(ctx, projectDir)
	if err != nil {
		return nil, errors.New("factory local workspace inspection failed")
	}
	plan, err := (sandboxworkspace.Planner{Git: factoryBundleGitSnapshot{status}}).Plan(ctx, sandboxworkspace.Request{ProjectDir: projectDir, WorkspaceMode: sandbox.SandboxWorkspaceModeClone})
	if err != nil || !factoryBundleCommitID(status.HeadRef) || plan.Branch == "" || plan.Repository != record.RepoRemote {
		return nil, errors.New("factory local workspace requires a clean named branch and matching repository")
	}
	base, run := strings.TrimSpace(record.BaseBranch), strings.TrimSpace(record.BranchName)
	for _, branch := range []string{base, run, plan.Branch} {
		if branch == "" || strings.HasPrefix(branch, "-") || strings.HasPrefix(branch, "refs/") {
			return nil, errors.New("factory local workspace requires valid base and run branches")
		}
		canonical, err := runFactoryGitInDir(ctx, projectDir, "check-ref-format", "--branch", branch)
		// --branch expands checkout expressions such as @{-1}; only exact
		// branch names are admissible as persisted base/run identities.
		if err != nil || canonical != branch {
			return nil, errors.New("factory local workspace requires valid base and run branches")
		}
	}
	if base == run {
		return nil, errors.New("factory local base and run branches must differ")
	}
	baseCommit, err := runFactoryGitInDir(ctx, projectDir, "rev-parse", "--verify", "--end-of-options", "refs/heads/"+base+"^{commit}")
	baseCommit = strings.TrimSpace(baseCommit)
	if err != nil || !factoryBundleCommitID(baseCommit) {
		return nil, errors.New("factory local base branch is unavailable; no remote fetch was attempted")
	}
	if _, err := runFactoryGitInDir(ctx, projectDir, "merge-base", "--is-ancestor", baseCommit, status.HeadRef); err != nil {
		return nil, errors.New("factory local base must be contained in source history")
	}
	plan.InputSource, plan.RequiresBundle, plan.SyncRef = sandbox.SandboxWorkspaceInputSourceGitBundle, true, status.HeadRef
	return &factorySandboxBundlePlan{Workspace: plan, BaseBranch: base, BaseCommit: baseCommit, RunBranch: run}, nil
}

func factoryBundleCommitID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for _, char := range value {
		if !(char >= '0' && char <= '9' || char >= 'a' && char <= 'f') {
			return false
		}
	}
	return true
}

type factorySandboxBundleGit struct {
	sandboxworkspace.LocalGit
	check func(context.Context) error
}

func (g factorySandboxBundleGit) CreateBundle(ctx context.Context, req sandboxworkspace.CreateBundleRequest) (sandboxworkspace.CreateBundleResult, error) {
	if err := g.check(ctx); err != nil {
		return sandboxworkspace.CreateBundleResult{}, err
	}
	return g.LocalGit.CreateBundle(ctx, req)
}

func prepareFactorySandboxBundle(ctx context.Context, deps factorySandboxExecutorDeps, req factorySandboxExecutorRequest, prep sandboxexec.PrepareContext, bundle *factorySandboxBundlePlan) error {
	workspaceDir := factorySandboxRemoteWorkspaceDir(req.RunRecord)
	workspace := sandboxworkspace.ToSandboxWorkspace(bundle.Workspace)
	_, err := deps.materializeWorkspace(ctx, prep, sandboxexec.WorkspaceMaterializationRequest{
		Workspace: workspace, Plan: &bundle.Workspace, ProjectDir: req.ProjectDir, WorkspaceDir: workspaceDir,
		LocalGit: factorySandboxBundleGit{LocalGit: sandboxworkspace.GitCLIInspector{}, check: func(ctx context.Context) error {
			current, err := deps.planBundle(ctx, req.ProjectDir, req.RunRecord)
			if err != nil || current == nil || *current != *bundle {
				return errors.New("factory local workspace changed before bundle export")
			}
			return nil
		}},
	})
	if err != nil {
		return err
	}
	if err := prepareFactorySandboxBundleBranches(ctx, prep, workspaceDir, bundle); err != nil {
		return err
	}
	_, err = deps.prepareCommandContext(ctx, prep, req.ProjectDir, workspaceDir, req.RemoteOutput)
	return err
}

func prepareFactorySandboxBundleBranches(ctx context.Context, prep sandboxexec.PrepareContext, workspaceDir string, bundle *factorySandboxBundlePlan) error {
	// Check the exported source and base object before creating either branch.
	// Neither branch name is evidence until these commands complete.
	script := "set -eu\ncd " + shellQuote(workspaceDir) + "\n" +
		"test \"$(git rev-parse HEAD)\" = " + shellQuote(bundle.Workspace.SyncRef) + "\n" +
		"git cat-file -e " + shellQuote(bundle.BaseCommit+"^{commit}") + "\n" +
		"git update-ref " + shellQuote("refs/heads/"+bundle.BaseBranch) + " " + shellQuote(bundle.BaseCommit) + "\n" +
		"git checkout -B " + shellQuote(bundle.RunBranch) + " " + shellQuote(bundle.Workspace.SyncRef)
	result, err := prep.Driver.Exec(ctx, sandboxruntime.ExecRequest{Target: prep.Target, Args: []string{"sh", "-c", script}, Stdout: io.Discard, Stderr: io.Discard})
	if err != nil || result == nil || result.ExitCode != 0 {
		return errors.New("factory local workspace branch preparation failed")
	}
	return nil
}

func factorySandboxImageCommandArgs(record factory.RunRecord, req factoryRunAutoRequest) []string {
	// Keep the same policy assignments and quoting as the legacy script while
	// selecting the image's Hal, as run/auto do. No per-user install is required.
	script := factorySandboxHalScriptWithEnv(factorySandboxRemoteAutoArgs(req), factorySandboxRemoteAutoEnv(req), true)
	return []string{"sh", "-c", "set -eu\ncd " + shellQuote(factorySandboxRemoteWorkspaceDir(record)) + "\n" + script}
}
