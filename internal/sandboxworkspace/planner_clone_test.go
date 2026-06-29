package sandboxworkspace

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestPlannerClonePlansRemoteRefForCleanHeadContainedInUpstream(t *testing.T) {
	projectDir := t.TempDir()
	git := &fakeGitInspector{
		status: GitStatus{
			IsGitWorktree:           true,
			Repository:              "git@github.com:jywlabs/hal.git",
			Branch:                  "phase/workspace",
			Upstream:                "origin/phase/workspace",
			UpstreamRef:             "refs/remotes/origin/phase/workspace",
			HeadRef:                 "abc123",
			HeadContainedInUpstream: true,
		},
	}

	plan, err := (Planner{Git: git}).Plan(context.Background(), Request{
		ProjectDir:    projectDir,
		WorkspaceMode: sandbox.SandboxWorkspaceModeClone,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	wantProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	if git.projectDir != wantProjectDir {
		t.Fatalf("inspected project dir = %q, want %q", git.projectDir, wantProjectDir)
	}
	if plan.Mode != sandbox.SandboxWorkspaceModeClone {
		t.Fatalf("Mode = %q, want %q", plan.Mode, sandbox.SandboxWorkspaceModeClone)
	}
	if plan.InputSource != sandbox.SandboxWorkspaceInputSourceRemoteRef {
		t.Fatalf("InputSource = %q, want %q", plan.InputSource, sandbox.SandboxWorkspaceInputSourceRemoteRef)
	}
	if plan.ProjectDir != wantProjectDir {
		t.Fatalf("ProjectDir = %q, want %q", plan.ProjectDir, wantProjectDir)
	}
	if plan.Repository != "git@github.com:jywlabs/hal.git" {
		t.Fatalf("Repository = %q", plan.Repository)
	}
	if plan.Branch != "phase/workspace" || plan.Upstream != "origin/phase/workspace" {
		t.Fatalf("branch/upstream = %q/%q", plan.Branch, plan.Upstream)
	}
	if plan.SyncRef != "refs/remotes/origin/phase/workspace" {
		t.Fatalf("SyncRef = %q", plan.SyncRef)
	}
	if plan.RequiresBundle {
		t.Fatal("RequiresBundle = true, want false")
	}
	if plan.Dirty.Any() {
		t.Fatalf("Dirty = %#v, want clean", plan.Dirty)
	}
}

func TestPlannerCloneRejectsDirtyWorktreeStates(t *testing.T) {
	tests := []struct {
		name  string
		dirty DirtyState
	}{
		{name: "staged", dirty: DirtyState{Staged: true}},
		{name: "unstaged", dirty: DirtyState{Unstaged: true}},
		{name: "untracked", dirty: DirtyState{Untracked: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projectDir := t.TempDir()
			plan, err := (Planner{Git: &fakeGitInspector{status: GitStatus{
				IsGitWorktree: true,
				Dirty:         tt.dirty,
			}}}).Plan(context.Background(), Request{
				ProjectDir:    projectDir,
				WorkspaceMode: sandbox.SandboxWorkspaceModeClone,
			})

			if !errors.Is(err, ErrDirtyWorktree) {
				t.Fatalf("Plan() error = %v, want ErrDirtyWorktree", err)
			}
			if plan != (Plan{}) {
				t.Fatalf("Plan() = %#v, want zero plan", plan)
			}
			var planningErr *PlanningError
			if !errors.As(err, &planningErr) {
				t.Fatalf("errors.As(%T) = false", planningErr)
			}
			if planningErr.Dirty != tt.dirty {
				t.Fatalf("PlanningError.Dirty = %#v, want %#v", planningErr.Dirty, tt.dirty)
			}
		})
	}
}

func TestPlannerCloneRejectsNonGitProjectDirectory(t *testing.T) {
	projectDir := t.TempDir()
	plan, err := (Planner{Git: &fakeGitInspector{status: GitStatus{
		IsGitWorktree: false,
	}}}).Plan(context.Background(), Request{
		ProjectDir:    projectDir,
		WorkspaceMode: sandbox.SandboxWorkspaceModeClone,
	})

	if !errors.Is(err, ErrNonGitWorktree) {
		t.Fatalf("Plan() error = %v, want ErrNonGitWorktree", err)
	}
	if plan != (Plan{}) {
		t.Fatalf("Plan() = %#v, want zero plan", plan)
	}
}

func TestPlannerClonePlansGitBundleForCleanCommittedLocalWork(t *testing.T) {
	projectDir := t.TempDir()
	plan, err := (Planner{Git: &fakeGitInspector{status: GitStatus{
		IsGitWorktree:           true,
		Repository:              "git@github.com:jywlabs/hal.git",
		Branch:                  "phase/workspace",
		Upstream:                "origin/phase/workspace",
		UpstreamRef:             "refs/remotes/origin/phase/workspace",
		HeadRef:                 "abc123",
		HeadContainedInUpstream: false,
	}}}).Plan(context.Background(), Request{
		ProjectDir:    projectDir,
		WorkspaceMode: sandbox.SandboxWorkspaceModeClone,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if plan.Mode != sandbox.SandboxWorkspaceModeClone {
		t.Fatalf("Mode = %q, want clone", plan.Mode)
	}
	if plan.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle {
		t.Fatalf("InputSource = %q, want git bundle", plan.InputSource)
	}
	if !plan.RequiresBundle {
		t.Fatal("RequiresBundle = false, want true")
	}
	if plan.Branch != "phase/workspace" || plan.Upstream != "origin/phase/workspace" {
		t.Fatalf("branch/upstream = %q/%q", plan.Branch, plan.Upstream)
	}
	if plan.SyncRef != "abc123" {
		t.Fatalf("SyncRef = %q, want HEAD ref", plan.SyncRef)
	}
}

func TestPlannerClonePlansGitBundleWithoutUpstream(t *testing.T) {
	projectDir := t.TempDir()
	plan, err := (Planner{Git: &fakeGitInspector{status: GitStatus{
		IsGitWorktree: true,
		Repository:    "git@github.com:jywlabs/hal.git",
		Branch:        "phase/workspace",
		HeadRef:       "abc123",
	}}}).Plan(context.Background(), Request{
		ProjectDir:    projectDir,
		WorkspaceMode: sandbox.SandboxWorkspaceModeClone,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if plan.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle {
		t.Fatalf("InputSource = %q, want git bundle", plan.InputSource)
	}
	if !plan.RequiresBundle {
		t.Fatal("RequiresBundle = false, want true")
	}
	if plan.Upstream != "" {
		t.Fatalf("Upstream = %q, want empty", plan.Upstream)
	}
	if plan.SyncRef != "abc123" {
		t.Fatalf("SyncRef = %q, want HEAD ref", plan.SyncRef)
	}
}

type fakeGitInspector struct {
	status     GitStatus
	err        error
	projectDir string
}

func (f *fakeGitInspector) InspectGit(_ context.Context, projectDir string) (GitStatus, error) {
	f.projectDir = projectDir
	return f.status, f.err
}
