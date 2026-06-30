package sandboxworkspace

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestPrepareLocalBundlePlansCreationForCleanGitBundlePlan(t *testing.T) {
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
	if plan.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle {
		t.Fatalf("InputSource = %q, want git_bundle", plan.InputSource)
	}

	bundleDir := t.TempDir()
	git := &recordingLocalGit{}
	result, err := PrepareLocalBundle(context.Background(), git, PrepareLocalBundleRequest{
		Plan:      plan,
		BundleDir: bundleDir,
	})
	if err != nil {
		t.Fatalf("PrepareLocalBundle() error = %v", err)
	}

	wantPath := filepath.Join(bundleDir, "abc123.bundle")
	if len(git.createRequests) != 1 {
		t.Fatalf("CreateBundle calls = %d, want 1", len(git.createRequests))
	}
	if got := git.createRequests[0].Plan; got != plan {
		t.Fatalf("CreateBundle plan = %#v, want %#v", got, plan)
	}
	if got := git.createRequests[0].DestinationPath; got != wantPath {
		t.Fatalf("CreateBundle destination = %q, want %q", got, wantPath)
	}
	if len(git.verifyRequests) != 1 {
		t.Fatalf("VerifyBundle calls = %d, want 1", len(git.verifyRequests))
	}
	if got := git.verifyRequests[0].Plan; got != plan {
		t.Fatalf("VerifyBundle plan = %#v, want %#v", got, plan)
	}
	if got := git.verifyRequests[0].Path; got != wantPath {
		t.Fatalf("VerifyBundle path = %q, want %q", got, wantPath)
	}
	if got := git.verifyRequests[0].SyncRef; got != "abc123" {
		t.Fatalf("VerifyBundle sync ref = %q, want abc123", got)
	}
	if result.LocalPath != wantPath {
		t.Fatalf("LocalPath = %q, want %q", result.LocalPath, wantPath)
	}
	if result.ID != "abc123" || result.SyncRef != "abc123" {
		t.Fatalf("result id/syncRef = %q/%q, want abc123/abc123", result.ID, result.SyncRef)
	}
	if result.Bundle == nil || result.Bundle.ID != "abc123" || result.Bundle.SyncRef != "abc123" || result.Bundle.RemotePath != "" {
		t.Fatalf("Bundle = %#v, want safe local bundle identifiers without remote path", result.Bundle)
	}
	if len(result.Operations) != 2 ||
		result.Operations[0].Phase != MaterializationPhaseBundleCreate ||
		result.Operations[1].Phase != MaterializationPhaseBundleVerify {
		t.Fatalf("Operations = %#v, want create and verify phases", result.Operations)
	}
}

func TestPrepareLocalBundleMetadataDoesNotLeakLocalPath(t *testing.T) {
	bundleDir := t.TempDir()
	plan := Plan{
		Mode:           sandbox.SandboxWorkspaceModeClone,
		InputSource:    sandbox.SandboxWorkspaceInputSourceGitBundle,
		ProjectDir:     t.TempDir(),
		Repository:     "git@github.com:jywlabs/hal.git",
		Branch:         "phase/workspace",
		SyncRef:        "refs/heads/phase/workspace",
		RequiresBundle: true,
	}

	result, err := PrepareLocalBundle(context.Background(), &recordingLocalGit{}, PrepareLocalBundleRequest{
		Plan:      plan,
		BundleDir: bundleDir,
	})
	if err != nil {
		t.Fatalf("PrepareLocalBundle() error = %v", err)
	}
	metadata := NewMaterializationResult(plan, MaterializationDetails{
		Bundle:     result.Bundle,
		Operations: result.Operations,
	})

	encoded, err := json.Marshal(struct {
		Bundle   LocalBundleResult     `json:"bundle"`
		Metadata MaterializationResult `json:"metadata"`
	}{
		Bundle:   result,
		Metadata: metadata,
	})
	if err != nil {
		t.Fatalf("Marshal(metadata) error = %v", err)
	}
	if strings.Contains(string(encoded), result.LocalPath) || strings.Contains(string(encoded), bundleDir) {
		t.Fatalf("bundle metadata leaked local path: %s", encoded)
	}
	if metadata.InputSource != sandbox.SandboxWorkspaceInputSourceGitBundle ||
		metadata.Branch != "phase/workspace" ||
		metadata.SyncRef != "refs/heads/phase/workspace" {
		t.Fatalf("metadata = %#v, want plan branch/input source/sync ref", metadata)
	}
}

func TestPrepareLocalBundleRejectsDirtyPlanBeforeBundleCreation(t *testing.T) {
	git := &recordingLocalGit{}
	_, err := PrepareLocalBundle(context.Background(), git, PrepareLocalBundleRequest{
		Plan: Plan{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle,
			ProjectDir:  t.TempDir(),
			Dirty:       DirtyState{Unstaged: true},
		},
		BundleDir: t.TempDir(),
	})
	if !errors.Is(err, ErrDirtyWorktree) {
		t.Fatalf("PrepareLocalBundle() error = %v, want ErrDirtyWorktree", err)
	}
	if len(git.createRequests) != 0 || len(git.verifyRequests) != 0 {
		t.Fatalf("git calls = create %d verify %d, want zero", len(git.createRequests), len(git.verifyRequests))
	}
}

func TestPrepareLocalBundleRejectsNonBundlePlanBeforeBundleCreation(t *testing.T) {
	git := &recordingLocalGit{}
	_, err := PrepareLocalBundle(context.Background(), git, PrepareLocalBundleRequest{
		Plan: Plan{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			ProjectDir:  t.TempDir(),
		},
		BundleDir: t.TempDir(),
	})
	if !errors.Is(err, ErrGitBundlePlanRequired) {
		t.Fatalf("PrepareLocalBundle() error = %v, want ErrGitBundlePlanRequired", err)
	}
	if len(git.createRequests) != 0 || len(git.verifyRequests) != 0 {
		t.Fatalf("git calls = create %d verify %d, want zero", len(git.createRequests), len(git.verifyRequests))
	}
}

type recordingLocalGit struct {
	createRequests []CreateBundleRequest
	verifyRequests []VerifyBundleRequest
	createErr      error
	verifyErr      error
}

func (g *recordingLocalGit) CreateBundle(_ context.Context, req CreateBundleRequest) (CreateBundleResult, error) {
	g.createRequests = append(g.createRequests, req)
	if g.createErr != nil {
		return CreateBundleResult{}, g.createErr
	}
	return CreateBundleResult{}, nil
}

func (g *recordingLocalGit) VerifyBundle(_ context.Context, req VerifyBundleRequest) error {
	g.verifyRequests = append(g.verifyRequests, req)
	return g.verifyErr
}
