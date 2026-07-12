package sandboxworkspace

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

func TestCopyLocalBundleInvokesRemoteCopyForGitBundlePlan(t *testing.T) {
	bundleDir := t.TempDir()
	plan := Plan{
		Mode:           sandbox.SandboxWorkspaceModeClone,
		InputSource:    sandbox.SandboxWorkspaceInputSourceGitBundle,
		ProjectDir:     t.TempDir(),
		Repository:     "git@github.com:jywlabs/hal.git",
		Branch:         "phase/workspace",
		SyncRef:        "abc123",
		RequiresBundle: true,
	}
	localBundle, err := PrepareLocalBundle(context.Background(), &recordingLocalGit{}, PrepareLocalBundleRequest{
		Plan:      plan,
		BundleDir: bundleDir,
	})
	if err != nil {
		t.Fatalf("PrepareLocalBundle() error = %v", err)
	}

	remote := &recordingRemoteCopier{}
	target := RemoteTarget{ID: "sandbox-1", Provider: "test-provider", RuntimeDriver: "test-driver"}
	result, err := CopyLocalBundle(context.Background(), remote, CopyLocalBundleRequest{
		Plan:                 plan,
		Target:               target,
		Bundle:               localBundle,
		BundleDestinationDir: "/tmp/hal/bundles",
	})
	if err != nil {
		t.Fatalf("CopyLocalBundle() error = %v", err)
	}

	wantRemotePath := "/tmp/hal/bundles/abc123.bundle"
	if len(remote.copyRequests) != 1 {
		t.Fatalf("CopyIn calls = %d, want 1", len(remote.copyRequests))
	}
	if got := remote.copyRequests[0].Target; got != target {
		t.Fatalf("CopyIn target = %#v, want %#v", got, target)
	}
	if got := remote.copyRequests[0].SourcePath; got != localBundle.LocalPath {
		t.Fatalf("CopyIn source = %q, want local bundle path %q", got, localBundle.LocalPath)
	}
	if got := remote.copyRequests[0].DestinationPath; got != wantRemotePath {
		t.Fatalf("CopyIn destination = %q, want %q", got, wantRemotePath)
	}
	if result.Bundle == nil || result.Bundle.ID != "abc123" || result.Bundle.SyncRef != "abc123" || result.Bundle.RemotePath != wantRemotePath {
		t.Fatalf("Bundle = %#v, want safe copied bundle metadata", result.Bundle)
	}
	if len(result.Operations) != 3 ||
		result.Operations[0].Phase != MaterializationPhaseBundleCreate ||
		result.Operations[1].Phase != MaterializationPhaseBundleVerify ||
		result.Operations[2].Phase != MaterializationPhaseBundleCopy {
		t.Fatalf("Operations = %#v, want create, verify, and copy phases", result.Operations)
	}

	metadata := NewMaterializationResult(plan, MaterializationDetails{
		Bundle:     result.Bundle,
		Operations: result.Operations,
	})
	encoded, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("Marshal(metadata) error = %v", err)
	}
	if strings.Contains(string(encoded), localBundle.LocalPath) || strings.Contains(string(encoded), bundleDir) {
		t.Fatalf("copied bundle metadata leaked local path: %s", encoded)
	}
	if !strings.Contains(string(encoded), wantRemotePath) {
		t.Fatalf("copied bundle metadata = %s, want remote path", encoded)
	}
}

func TestCopyLocalBundleFailureIsPhaseSpecificAndPathSafe(t *testing.T) {
	bundleDir := t.TempDir()
	localPath := filepath.Join(bundleDir, "abc123.bundle")
	remote := &recordingRemoteCopier{
		copyErr: fmt.Errorf("copy %s to /tmp/hal/bundles/abc123.bundle failed", localPath),
	}

	_, err := CopyLocalBundle(context.Background(), remote, CopyLocalBundleRequest{
		Plan: Plan{
			Mode:           sandbox.SandboxWorkspaceModeClone,
			InputSource:    sandbox.SandboxWorkspaceInputSourceGitBundle,
			Repository:     "git@github.com:jywlabs/hal.git",
			Branch:         "phase/workspace",
			SyncRef:        "abc123",
			RequiresBundle: true,
		},
		Target:               RemoteTarget{ID: "sandbox-1"},
		Bundle:               LocalBundleResult{LocalPath: localPath, ID: "abc123", SyncRef: "abc123"},
		BundleDestinationDir: "/tmp/hal/bundles",
	})
	if err == nil {
		t.Fatal("CopyLocalBundle() error = nil, want copy failure")
	}
	if !strings.Contains(err.Error(), "workspace bundle copy") {
		t.Fatalf("CopyLocalBundle() error = %q, want bundle copy phase", err)
	}
	if strings.Contains(err.Error(), localPath) || strings.Contains(err.Error(), bundleDir) {
		t.Fatalf("CopyLocalBundle() error leaked local path: %q", err)
	}
	if len(remote.copyRequests) != 1 {
		t.Fatalf("CopyIn calls = %d, want 1", len(remote.copyRequests))
	}
}

func TestBundleMaterializerCopiesThenAppliesRemoteBundle(t *testing.T) {
	bundleDir := t.TempDir()
	workspaceDir := "/root/workspace/hal"
	target := RemoteTarget{ID: "sandbox-1", Provider: "test-provider", RuntimeDriver: "test-driver"}
	plan := Plan{
		Mode:           sandbox.SandboxWorkspaceModeClone,
		InputSource:    sandbox.SandboxWorkspaceInputSourceGitBundle,
		ProjectDir:     t.TempDir(),
		Repository:     "git@github.com:jywlabs/hal.git",
		Branch:         "phase/workspace",
		SyncRef:        "abc123",
		RequiresBundle: true,
	}
	remote := &recordingRemoteClient{}
	result, err := (BundleMaterializer{
		LocalGit:  &recordingLocalGit{},
		Remote:    remote,
		BundleDir: bundleDir,
	}).MaterializeWorkspace(context.Background(), MaterializeRequest{
		Plan:                 plan,
		Target:               target,
		WorkspaceDir:         workspaceDir,
		BundleDestinationDir: "/tmp/hal/bundles",
	})
	if err != nil {
		t.Fatalf("MaterializeWorkspace() error = %v", err)
	}

	wantRemotePath := "/tmp/hal/bundles/abc123.bundle"
	wantLocalRef := "refs/hal/workspace-sync/abc123"
	if got, want := eventKinds(remote.events), []string{"copy", "exec", "exec", "exec"}; !stringSlicesEqual(got, want) {
		t.Fatalf("remote events = %#v, want %#v", got, want)
	}
	if got := remote.copyRequests[0].DestinationPath; got != wantRemotePath {
		t.Fatalf("CopyIn destination = %q, want %q", got, wantRemotePath)
	}
	if len(remote.execRequests) != 3 {
		t.Fatalf("Exec calls = %d, want 3", len(remote.execRequests))
	}
	assertRemoteArgs(t, remote.execRequests[0].Args, []string{
		"sh",
		"-lc",
		remoteWorkspaceInitScript,
		"hal-workspace-apply",
		workspaceDir,
		"git@github.com:jywlabs/hal.git",
	})
	assertRemoteArgs(t, remote.execRequests[1].Args, []string{
		"git",
		"-C",
		workspaceDir,
		"fetch",
		wantRemotePath,
		"abc123:" + wantLocalRef,
	})
	assertRemoteArgs(t, remote.execRequests[2].Args, []string{
		"git",
		"-C",
		workspaceDir,
		"checkout",
		"-B",
		"phase/workspace",
		wantLocalRef,
	})
	for i, req := range remote.execRequests {
		if req.Target != target {
			t.Fatalf("Exec[%d] target = %#v, want %#v", i, req.Target, target)
		}
	}

	if result.WorkspaceDir != workspaceDir {
		t.Fatalf("WorkspaceDir = %q, want %q", result.WorkspaceDir, workspaceDir)
	}
	if result.Bundle == nil || result.Bundle.RemotePath != wantRemotePath || result.Bundle.ID != "abc123" || result.Bundle.SyncRef != "abc123" {
		t.Fatalf("Bundle = %#v, want copied bundle metadata", result.Bundle)
	}
	assertOperationPhases(t, result.Operations, []MaterializationPhase{
		MaterializationPhaseBundleCreate,
		MaterializationPhaseBundleVerify,
		MaterializationPhaseBundleCopy,
		MaterializationPhaseBundleApply,
	})
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error = %v", err)
	}
	if strings.Contains(string(encoded), bundleDir) || strings.Contains(string(encoded), filepath.Join(bundleDir, "abc123.bundle")) {
		t.Fatalf("materialization metadata leaked host bundle path: %s", encoded)
	}
}

func TestRemoteWorkspaceInitInitializesRepositoryWithoutContactingOrigin(t *testing.T) {
	workspaceDir := filepath.Join(t.TempDir(), "workspace")
	repository := "network-forbidden://private.example/repo.git"

	runRemoteWorkspaceInitTest(t, workspaceDir, repository)

	if got := gitOutputWorkspaceTest(t, workspaceDir, "remote", "get-url", "origin"); got != repository {
		t.Fatalf("origin URL = %q, want %q", got, repository)
	}
}

func TestRemoteWorkspaceInitReusesRepositoryWithoutContactingOrigin(t *testing.T) {
	workspaceDir := filepath.Join(t.TempDir(), "workspace")
	runGitWorkspaceTest(t, "init", workspaceDir)
	runGitWorkspaceTest(t, "-C", workspaceDir, "remote", "add", "origin", "network-forbidden://old.example/repo.git")
	markerPath := filepath.Join(workspaceDir, "keep.txt")
	if err := os.WriteFile(markerPath, []byte("keep"), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error = %v", markerPath, err)
	}
	repository := "network-forbidden://private.example/repo.git"

	runRemoteWorkspaceInitTest(t, workspaceDir, repository)

	if got := gitOutputWorkspaceTest(t, workspaceDir, "remote", "get-url", "origin"); got != repository {
		t.Fatalf("origin URL = %q, want %q", got, repository)
	}
	if _, err := os.Stat(markerPath); err != nil {
		t.Fatalf("reused workspace marker error = %v", err)
	}
}

func TestApplyRemoteBundleFailureIsPhaseSpecificAndSanitized(t *testing.T) {
	workspaceDir := "/root/workspace/hal"
	remote := &recordingRemoteClient{
		execErrAt: 2,
		execErr:   fmt.Errorf("fatal: clone https://user:secret@example.test/repo.git failed\n/Users/v/work/repo/bundle.bundle\nGITHUB_TOKEN=ghp_secret"),
	}
	_, err := ApplyRemoteBundle(context.Background(), remote, ApplyRemoteBundleRequest{
		Plan: Plan{
			Mode:           sandbox.SandboxWorkspaceModeClone,
			InputSource:    sandbox.SandboxWorkspaceInputSourceGitBundle,
			Repository:     "https://user:secret@example.test/repo.git",
			Branch:         "phase/workspace",
			SyncRef:        "abc123",
			RequiresBundle: true,
		},
		Target: RemoteTarget{ID: "sandbox-1"},
		Bundle: RemoteBundleResult{
			Bundle: &BundleMaterialization{
				ID:         "abc123",
				RemotePath: "/tmp/hal/bundles/abc123.bundle",
				SyncRef:    "abc123",
			},
			Operations: []MaterializationOperation{
				{Phase: MaterializationPhaseBundleCreate},
				{Phase: MaterializationPhaseBundleVerify},
				{Phase: MaterializationPhaseBundleCopy},
			},
		},
		WorkspaceDir: workspaceDir,
	})
	if err == nil {
		t.Fatal("ApplyRemoteBundle() error = nil, want apply failure")
	}
	errText := err.Error()
	if !strings.Contains(errText, "workspace bundle apply") || !strings.Contains(errText, "remote apply") {
		t.Fatalf("ApplyRemoteBundle() error = %q, want bundle apply phase", err)
	}
	for _, unsafe := range []string{"secret", "ghp_secret", "/Users/v", "fatal:", "https://user:secret@example.test"} {
		if strings.Contains(errText, unsafe) {
			t.Fatalf("ApplyRemoteBundle() error leaked unsafe detail %q: %q", unsafe, errText)
		}
	}
	if len(remote.execRequests) != 2 {
		t.Fatalf("Exec calls = %d, want stop after failed fetch", len(remote.execRequests))
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

func TestBundleMaterializerRejectsDirtyClonePlansBeforeCreateCopyApply(t *testing.T) {
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
			git := &recordingLocalGit{}
			remote := &recordingRemoteClient{}
			_, err := (BundleMaterializer{
				LocalGit:  git,
				Remote:    remote,
				BundleDir: t.TempDir(),
			}).MaterializeWorkspace(context.Background(), MaterializeRequest{
				Plan: Plan{
					Mode:           sandbox.SandboxWorkspaceModeClone,
					InputSource:    sandbox.SandboxWorkspaceInputSourceGitBundle,
					ProjectDir:     t.TempDir(),
					Repository:     "git@example.com:org/repo.git",
					Branch:         "feature/dirty",
					SyncRef:        "abc123",
					RequiresBundle: true,
					Dirty:          tt.dirty,
				},
				Target:       RemoteTarget{ID: "sandbox-1"},
				WorkspaceDir: "/workspace/repo",
			})
			if !errors.Is(err, ErrDirtyWorktree) {
				t.Fatalf("MaterializeWorkspace() error = %v, want ErrDirtyWorktree", err)
			}
			if len(git.createRequests) != 0 || len(git.verifyRequests) != 0 {
				t.Fatalf("git calls = create %d verify %d, want zero", len(git.createRequests), len(git.verifyRequests))
			}
			if len(remote.copyRequests) != 0 || len(remote.execRequests) != 0 || len(remote.events) != 0 {
				t.Fatalf("remote calls = copy %d exec %d events %d, want zero", len(remote.copyRequests), len(remote.execRequests), len(remote.events))
			}
		})
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

type recordingRemoteCopier struct {
	copyRequests []RemoteCopyRequest
	copyErr      error
}

func (r *recordingRemoteCopier) CopyIn(_ context.Context, req RemoteCopyRequest) error {
	r.copyRequests = append(r.copyRequests, req)
	return r.copyErr
}

type remoteEvent struct {
	kind string
}

type recordingRemoteClient struct {
	copyRequests []RemoteCopyRequest
	execRequests []RemoteCommandRequest
	events       []remoteEvent
	copyErr      error
	execErr      error
	execErrAt    int
	execResults  []RemoteCommandResult
}

func (r *recordingRemoteClient) CopyIn(_ context.Context, req RemoteCopyRequest) error {
	r.copyRequests = append(r.copyRequests, req)
	r.events = append(r.events, remoteEvent{kind: "copy"})
	return r.copyErr
}

func (r *recordingRemoteClient) Exec(_ context.Context, req RemoteCommandRequest) (RemoteCommandResult, error) {
	r.execRequests = append(r.execRequests, req)
	r.events = append(r.events, remoteEvent{kind: "exec"})
	call := len(r.execRequests)
	if r.execErr != nil && (r.execErrAt == 0 || r.execErrAt == call) {
		return RemoteCommandResult{}, r.execErr
	}
	if call <= len(r.execResults) {
		return r.execResults[call-1], nil
	}
	return RemoteCommandResult{}, nil
}

func eventKinds(events []remoteEvent) []string {
	kinds := make([]string, 0, len(events))
	for _, event := range events {
		kinds = append(kinds, event.kind)
	}
	return kinds
}

func assertRemoteArgs(t *testing.T, got []string, want []string) {
	t.Helper()
	if !stringSlicesEqual(got, want) {
		t.Fatalf("Args = %#v, want %#v", got, want)
	}
}

func assertOperationPhases(t *testing.T, operations []MaterializationOperation, want []MaterializationPhase) {
	t.Helper()
	if len(operations) != len(want) {
		t.Fatalf("Operations = %#v, want phases %#v", operations, want)
	}
	for i, phase := range want {
		if operations[i].Phase != phase {
			t.Fatalf("Operations[%d].Phase = %q, want %q; operations = %#v", i, operations[i].Phase, phase, operations)
		}
	}
}

func stringSlicesEqual(a []string, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func runRemoteWorkspaceInitTest(t *testing.T, workspaceDir string, repository string) {
	t.Helper()
	cmd := exec.Command("sh", "-lc", remoteWorkspaceInitScript, "hal-workspace-apply", workspaceDir, repository)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("remote workspace init error = %v; output = %s", err, output)
	}
}

func runGitWorkspaceTest(t *testing.T, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s error = %v; output = %s", strings.Join(args, " "), err, output)
	}
}

func gitOutputWorkspaceTest(t *testing.T, workspaceDir string, args ...string) string {
	t.Helper()
	gitArgs := append([]string{"-C", workspaceDir}, args...)
	cmd := exec.Command("git", gitArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s error = %v; output = %s", strings.Join(gitArgs, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}
