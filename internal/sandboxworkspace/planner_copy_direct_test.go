package sandboxworkspace

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestPlannerCopyPlansDirtyGitWorktree(t *testing.T) {
	projectDir := t.TempDir()
	dirty := DirtyState{Staged: true, Unstaged: true, Untracked: true}
	plan, err := (Planner{Git: &fakeGitInspector{status: GitStatus{
		IsGitWorktree: true,
		Repository:    "git@github.com:jywlabs/hal.git",
		Branch:        "phase/workspace",
		Upstream:      "origin/phase/workspace",
		Dirty:         dirty,
	}}}).Plan(context.Background(), Request{
		ProjectDir:    projectDir,
		WorkspaceMode: sandbox.SandboxWorkspaceModeCopy,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	if plan.Mode != sandbox.SandboxWorkspaceModeCopy {
		t.Fatalf("Mode = %q, want copy", plan.Mode)
	}
	if plan.InputSource != sandbox.SandboxWorkspaceInputSourceCopy {
		t.Fatalf("InputSource = %q, want copy", plan.InputSource)
	}
	if plan.SyncRef != workingTreeSyncRef {
		t.Fatalf("SyncRef = %q, want working tree marker", plan.SyncRef)
	}
	if plan.RequiresBundle {
		t.Fatal("RequiresBundle = true, want false")
	}
	if plan.Dirty != dirty {
		t.Fatalf("Dirty = %#v, want %#v", plan.Dirty, dirty)
	}
	if plan.Repository != "git@github.com:jywlabs/hal.git" || plan.Branch != "phase/workspace" || plan.Upstream != "origin/phase/workspace" {
		t.Fatalf("git metadata = repo:%q branch:%q upstream:%q", plan.Repository, plan.Branch, plan.Upstream)
	}
}

func TestPlannerCopyPlansNonGitProjectDirectory(t *testing.T) {
	projectDir := t.TempDir()
	plan, err := (Planner{Git: &fakeGitInspector{status: GitStatus{
		IsGitWorktree: false,
	}}}).Plan(context.Background(), Request{
		ProjectDir:    projectDir,
		WorkspaceMode: sandbox.SandboxWorkspaceModeCopy,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	wantProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != sandbox.SandboxWorkspaceModeCopy {
		t.Fatalf("Mode = %q, want copy", plan.Mode)
	}
	if plan.InputSource != sandbox.SandboxWorkspaceInputSourceCopy {
		t.Fatalf("InputSource = %q, want copy", plan.InputSource)
	}
	if plan.ProjectDir != wantProjectDir {
		t.Fatalf("ProjectDir = %q, want %q", plan.ProjectDir, wantProjectDir)
	}
	if plan.Repository != "" || plan.Branch != "" || plan.Upstream != "" {
		t.Fatalf("git metadata = repo:%q branch:%q upstream:%q, want empty", plan.Repository, plan.Branch, plan.Upstream)
	}
}

func TestPlannerDirectRequiresExplicitOptIn(t *testing.T) {
	projectDir := t.TempDir()
	plan, err := (Planner{Git: &fakeGitInspector{status: GitStatus{
		IsGitWorktree: true,
	}}}).Plan(context.Background(), Request{
		ProjectDir:    projectDir,
		WorkspaceMode: sandbox.SandboxWorkspaceModeDirect,
		DirectOptIn:   false,
	})

	if !errors.Is(err, ErrDirectOptInRequired) {
		t.Fatalf("Plan() error = %v, want ErrDirectOptInRequired", err)
	}
	if plan != (Plan{}) {
		t.Fatalf("Plan() = %#v, want zero plan", plan)
	}
}

func TestPlannerDirectPlansWithExplicitOptIn(t *testing.T) {
	projectDir := t.TempDir()
	plan, err := (Planner{Git: &fakeGitInspector{status: GitStatus{
		IsGitWorktree: true,
		Repository:    "git@github.com:jywlabs/hal.git",
		Branch:        "phase/workspace",
		Dirty:         DirtyState{Untracked: true},
	}}}).Plan(context.Background(), Request{
		ProjectDir:    projectDir,
		WorkspaceMode: sandbox.SandboxWorkspaceModeDirect,
		DirectOptIn:   true,
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}

	wantProjectDir, err := filepath.Abs(projectDir)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Mode != sandbox.SandboxWorkspaceModeDirect {
		t.Fatalf("Mode = %q, want direct", plan.Mode)
	}
	if plan.InputSource != sandbox.SandboxWorkspaceInputSourceCopy {
		t.Fatalf("InputSource = %q, want existing copy input source", plan.InputSource)
	}
	if plan.SyncRef != workingTreeSyncRef {
		t.Fatalf("SyncRef = %q, want working tree marker", plan.SyncRef)
	}
	if plan.ProjectDir != wantProjectDir {
		t.Fatalf("ProjectDir = %q, want %q", plan.ProjectDir, wantProjectDir)
	}
	if plan.ResourceKey != "workspace:"+wantProjectDir {
		t.Fatalf("ResourceKey = %q, want default workspace resource key", plan.ResourceKey)
	}
}

func TestPlannerDirectPreservesExplicitResourceKey(t *testing.T) {
	projectDir := t.TempDir()
	plan, err := (Planner{Git: &fakeGitInspector{status: GitStatus{
		IsGitWorktree: false,
	}}}).Plan(context.Background(), Request{
		ProjectDir:    projectDir,
		WorkspaceMode: sandbox.SandboxWorkspaceModeDirect,
		DirectOptIn:   true,
		ResourceKey:   "workspace:custom",
	})
	if err != nil {
		t.Fatalf("Plan() error = %v", err)
	}
	if plan.ResourceKey != "workspace:custom" {
		t.Fatalf("ResourceKey = %q, want explicit key", plan.ResourceKey)
	}
}
