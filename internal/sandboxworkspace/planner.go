package sandboxworkspace

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
)

const workingTreeSyncRef = "working_tree"

// GitInspector inspects local Git worktree state for workspace planning.
type GitInspector interface {
	InspectGit(ctx context.Context, projectDir string) (GitStatus, error)
}

// Planner makes pure workspace strategy decisions from a request and inspected
// Git state. Runtime materialization is intentionally outside this package.
type Planner struct {
	Git GitInspector
}

// Plan returns a workspace plan without creating, copying, cloning, or mounting
// any workspace resources.
func (p Planner) Plan(ctx context.Context, req Request) (Plan, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	projectDir, err := normalizeProjectDir(req.ProjectDir)
	if err != nil {
		return Plan{}, err
	}
	req.ProjectDir = projectDir

	switch req.WorkspaceMode {
	case sandbox.SandboxWorkspaceModeClone:
		status, err := p.inspectGit(ctx, projectDir)
		if err != nil {
			return Plan{}, fmt.Errorf("inspect git workspace: %w", err)
		}
		return planClone(req, status)
	case sandbox.SandboxWorkspaceModeCopy:
		status, err := p.inspectGit(ctx, projectDir)
		if err != nil {
			return Plan{}, fmt.Errorf("inspect git workspace: %w", err)
		}
		return planCopy(req, status), nil
	case sandbox.SandboxWorkspaceModeDirect:
		if !req.DirectOptIn {
			return Plan{}, planningError(ErrDirectOptInRequired, req, DirtyState{}, nil)
		}
		status, err := p.inspectGit(ctx, projectDir)
		if err != nil {
			return Plan{}, fmt.Errorf("inspect git workspace: %w", err)
		}
		return planDirect(req, status), nil
	default:
		return Plan{}, fmt.Errorf("workspace planning: unsupported workspace mode %q", req.WorkspaceMode)
	}
}

func (p Planner) inspectGit(ctx context.Context, projectDir string) (GitStatus, error) {
	inspector := p.Git
	if inspector == nil {
		inspector = GitCLIInspector{}
	}
	return inspector.InspectGit(ctx, projectDir)
}

func normalizeProjectDir(projectDir string) (string, error) {
	projectDir = strings.TrimSpace(projectDir)
	if projectDir == "" {
		return "", fmt.Errorf("workspace planning: project directory is required")
	}
	abs, err := filepath.Abs(projectDir)
	if err != nil {
		return "", fmt.Errorf("workspace planning: resolve project directory: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return "", fmt.Errorf("workspace planning: stat project directory: %w", err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("workspace planning: project directory is not a directory: %s", abs)
	}
	return filepath.Clean(abs), nil
}

func planClone(req Request, status GitStatus) (Plan, error) {
	if !status.IsGitWorktree {
		return Plan{}, planningError(ErrNonGitWorktree, req, DirtyState{}, nil)
	}
	if status.Dirty.Any() {
		return Plan{}, planningError(ErrDirtyWorktree, req, status.Dirty, nil)
	}

	plan := basePlan(req, status)
	plan.Mode = sandbox.SandboxWorkspaceModeClone
	if status.HeadContainedInUpstream && strings.TrimSpace(plan.Upstream) != "" {
		plan.InputSource = sandbox.SandboxWorkspaceInputSourceRemoteRef
		plan.SyncRef = upstreamSyncRef(status)
		return plan, nil
	}

	plan.InputSource = sandbox.SandboxWorkspaceInputSourceGitBundle
	plan.RequiresBundle = true
	plan.SyncRef = bundleSyncRef(status, plan.Branch)
	return plan, nil
}

func planCopy(req Request, status GitStatus) Plan {
	plan := basePlan(req, status)
	plan.Mode = sandbox.SandboxWorkspaceModeCopy
	plan.InputSource = sandbox.SandboxWorkspaceInputSourceCopy
	plan.SyncRef = workingTreeSyncRef
	return plan
}

func planDirect(req Request, status GitStatus) Plan {
	plan := basePlan(req, status)
	plan.Mode = sandbox.SandboxWorkspaceModeDirect
	plan.InputSource = sandbox.SandboxWorkspaceInputSourceCopy
	plan.SyncRef = workingTreeSyncRef
	if plan.ResourceKey == "" {
		plan.ResourceKey = directResourceKey(req.ProjectDir)
	}
	return plan
}

func basePlan(req Request, status GitStatus) Plan {
	branch := firstNonEmpty(status.Branch, req.PreferredBranch)
	upstream := firstNonEmpty(status.Upstream, req.PreferredUpstream)
	return Plan{
		ProjectDir:  req.ProjectDir,
		Repository:  strings.TrimSpace(status.Repository),
		Branch:      branch,
		Upstream:    upstream,
		Dirty:       status.Dirty,
		ResourceKey: strings.TrimSpace(req.ResourceKey),
	}
}

func directResourceKey(projectDir string) string {
	return "workspace:" + projectDir
}

func upstreamSyncRef(status GitStatus) string {
	if ref := strings.TrimSpace(status.UpstreamRef); ref != "" {
		return ref
	}
	upstream := strings.TrimSpace(status.Upstream)
	if upstream == "" || strings.HasPrefix(upstream, "refs/") {
		return upstream
	}
	if strings.Contains(upstream, "/") {
		return "refs/remotes/" + upstream
	}
	return upstream
}

func bundleSyncRef(status GitStatus, branch string) string {
	if ref := strings.TrimSpace(status.HeadRef); ref != "" {
		return ref
	}
	if branch = strings.TrimSpace(branch); branch != "" {
		if strings.HasPrefix(branch, "refs/") {
			return branch
		}
		return "refs/heads/" + branch
	}
	return "HEAD"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
