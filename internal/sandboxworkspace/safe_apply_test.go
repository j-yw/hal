package sandboxworkspace

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafeApplyRunsDryRunBeforePatchMutation(t *testing.T) {
	git := &recordingSafeApplyGit{}

	result, err := (SafeApplier{Git: git}).Apply(context.Background(), SafeApplyRequest{
		ProjectDir:  "/tmp/host-worktree",
		PayloadPath: "/tmp/committed.patch",
		Mutate:      true,
		Artifact:    safeApplyPatchArtifact(),
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Status != SafeApplyStatusApplied || !result.DryRunPassed || !result.Applied {
		t.Fatalf("result = %#v, want applied after dry-run", result)
	}
	if got, want := strings.Join(git.calls, ","), "check_worktree,check_patch,apply_patch"; got != want {
		t.Fatalf("git call order = %q, want %q", got, want)
	}
}

func TestSafeApplyDryRunValidatesEligibleBundle(t *testing.T) {
	git := &recordingSafeApplyGit{}

	result, err := (SafeApplier{Git: git}).Apply(context.Background(), SafeApplyRequest{
		ProjectDir:  "/tmp/host-worktree",
		PayloadPath: "/tmp/committed.bundle",
		Artifact:    safeApplyBundleArtifact(),
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Status != SafeApplyStatusDryRunPassed || !result.DryRunPassed || result.Applied {
		t.Fatalf("result = %#v, want dry-run bundle validation only", result)
	}
	if got, want := strings.Join(git.calls, ","), "check_worktree,check_bundle"; got != want {
		t.Fatalf("git call order = %q, want %q", got, want)
	}
	if !safeApplyReasonsContain(result.Reasons, SyncOutApplyEligibilityReasonEligibleBundle) {
		t.Fatalf("Reasons = %#v, want eligible_bundle", result.Reasons)
	}
}

func TestSafeApplyRefusesDirtyWorktreeByDefault(t *testing.T) {
	git := &recordingSafeApplyGit{
		dirty: DirtyState{Staged: true, Unstaged: true, Untracked: true},
	}

	result, err := (SafeApplier{Git: git}).Apply(context.Background(), SafeApplyRequest{
		ProjectDir:  "/tmp/host-worktree",
		PayloadPath: "/tmp/committed.patch",
		Mutate:      true,
		Artifact:    safeApplyPatchArtifact(),
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Status != SafeApplyStatusHandoffRequired {
		t.Fatalf("Status = %q, want handoff_required; result = %#v", result.Status, result)
	}
	if result.Applied || result.DryRunPassed {
		t.Fatalf("result applied/dryRunPassed = %t/%t, want no apply after dirty worktree", result.Applied, result.DryRunPassed)
	}
	if !safeApplyReasonsContain(result.Reasons, SyncOutApplyEligibilityReasonDirtyWorktree) {
		t.Fatalf("Reasons = %#v, want dirty_worktree", result.Reasons)
	}
	if got, want := strings.Join(git.calls, ","), "check_worktree"; got != want {
		t.Fatalf("git call order = %q, want %q", got, want)
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "dirty_worktree" {
		t.Fatalf("Warnings = %#v, want dirty_worktree warning", result.Warnings)
	}
	message := result.Warnings[0].Message
	for _, want := range []string{"staged", "unstaged", "untracked"} {
		if !strings.Contains(message, want) {
			t.Fatalf("warning message = %q, want safe category %q", message, want)
		}
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error = %v", err)
	}
	for _, unsafe := range []string{"/tmp/host-worktree", "/tmp/committed.patch", "secret.txt", "https://user:secret@example.test/repo.git"} {
		if strings.Contains(string(encoded), unsafe) {
			t.Fatalf("safe apply result leaked unsafe fragment %q: %s", unsafe, encoded)
		}
	}
}

func TestSafeApplyUsesWorkspaceLock(t *testing.T) {
	var calls []string
	git := &recordingSafeApplyGit{sharedCalls: &calls}
	locks := &recordingSafeApplyLocks{calls: &calls}

	result, err := (SafeApplier{Git: git, Locks: locks}).Apply(context.Background(), SafeApplyRequest{
		ProjectDir:  "/tmp/host-worktree",
		PayloadPath: "/tmp/committed.patch",
		ResourceKey: "workspace:test-repo",
		Mutate:      true,
		Artifact:    safeApplyPatchArtifact(),
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Status != SafeApplyStatusApplied || !result.DryRunPassed || !result.Applied {
		t.Fatalf("result = %#v, want applied after locked dry-run", result)
	}
	if got, want := strings.Join(calls, ","), "acquire_lock,check_worktree,check_patch,apply_patch,release_lock"; got != want {
		t.Fatalf("call order = %q, want %q", got, want)
	}
	if len(locks.acquiredKeys) != 1 || locks.acquiredKeys[0] != "workspace:test-repo" {
		t.Fatalf("acquired lock keys = %#v, want workspace:test-repo", locks.acquiredKeys)
	}
}

func TestSafeApplyLockFailurePreventsApply(t *testing.T) {
	git := &recordingSafeApplyGit{}
	locks := &recordingSafeApplyLocks{
		acquireErr: errors.New("lock held for /tmp/private/repo TOKEN=secret https://user:secret@example.test/repo.git"),
	}

	result, err := (SafeApplier{Git: git, Locks: locks}).Apply(context.Background(), SafeApplyRequest{
		ProjectDir:  "/tmp/private/repo",
		PayloadPath: "/tmp/private/committed.patch",
		ResourceKey: "workspace:/tmp/private/repo",
		Mutate:      true,
		Artifact:    safeApplyPatchArtifact(),
	})
	if err != nil {
		t.Fatalf("Apply() error = %v", err)
	}
	if result.Status != SafeApplyStatusHandoffRequired || result.Applied || result.DryRunPassed {
		t.Fatalf("result = %#v, want handoff without apply after lock failure", result)
	}
	if !safeApplyReasonsContain(result.Reasons, SyncOutApplyEligibilityReasonManualReviewRequired) {
		t.Fatalf("Reasons = %#v, want manual_review_required", result.Reasons)
	}
	if len(git.calls) != 0 {
		t.Fatalf("git calls = %#v, want none after lock failure", git.calls)
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "workspace_lock_failed" {
		t.Fatalf("Warnings = %#v, want workspace_lock_failed warning", result.Warnings)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error = %v", err)
	}
	for _, unsafe := range []string{"/tmp/private/repo", "/tmp/private/committed.patch", "TOKEN=secret", "user:secret"} {
		if strings.Contains(string(encoded), unsafe) {
			t.Fatalf("safe apply lock failure leaked unsafe fragment %q: %s", unsafe, encoded)
		}
	}
}

func TestSafeApplyDryRunRejectsIncompatiblePatch(t *testing.T) {
	requireGitCLI(t)
	repo := setupSafeApplyRepo(t, "host base\n")
	patchPath := filepath.Join(t.TempDir(), "committed.patch")
	if err := os.WriteFile(patchPath, []byte(`diff --git a/README.md b/README.md
index 0000000..1111111 100644
--- a/README.md
+++ b/README.md
@@ -1 +1 @@
-sandbox base
+sandbox output
`), 0o600); err != nil {
		t.Fatalf("write patch: %v", err)
	}

	result, err := SafeApply(context.Background(), SafeApplyRequest{
		ProjectDir:  repo,
		PayloadPath: patchPath,
		Mutate:      true,
		Artifact:    safeApplyPatchArtifact(),
	})
	if err != nil {
		t.Fatalf("SafeApply() error = %v", err)
	}
	if result.Status != SafeApplyStatusHandoffRequired {
		t.Fatalf("Status = %q, want handoff_required; result = %#v", result.Status, result)
	}
	if result.Applied || result.DryRunPassed {
		t.Fatalf("result applied/dryRunPassed = %t/%t, want no mutation after dry-run failure", result.Applied, result.DryRunPassed)
	}
	if !safeApplyReasonsContain(result.Reasons, SyncOutApplyEligibilityReasonDryRunFailed) {
		t.Fatalf("Reasons = %#v, want dry_run_failed", result.Reasons)
	}
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "dry_run_failed" || result.Warnings[0].ArtifactID != "committed-patch" {
		t.Fatalf("Warnings = %#v, want safe dry-run warning for committed patch", result.Warnings)
	}

	content, err := os.ReadFile(filepath.Join(repo, "README.md"))
	if err != nil {
		t.Fatalf("read README: %v", err)
	}
	if string(content) != "host base\n" {
		t.Fatalf("README changed after failed dry-run: %q", content)
	}

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(result) error = %v", err)
	}
	for _, unsafe := range []string{repo, patchPath, "TOKEN=secret", "https://user:secret@example.test/repo.git"} {
		if strings.Contains(string(encoded), unsafe) {
			t.Fatalf("safe apply result leaked unsafe fragment %q: %s", unsafe, encoded)
		}
	}
}

func setupSafeApplyRepo(t *testing.T, readme string) string {
	t.Helper()
	repo := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	runGitTest(t, repo, "init")
	runGitTest(t, repo, "config", "user.email", "test@example.com")
	runGitTest(t, repo, "config", "user.name", "Test User")
	if err := os.WriteFile(filepath.Join(repo, "README.md"), []byte(readme), 0o600); err != nil {
		t.Fatalf("write README: %v", err)
	}
	runGitTest(t, repo, "add", "README.md")
	runGitTest(t, repo, "commit", "-m", "base")
	return repo
}

func safeApplyPatchArtifact() SyncOutArtifact {
	return SyncOutArtifact{
		ID:          "committed-patch",
		DisplayName: "Committed Patch",
		Kind:        SyncOutArtifactKindPatch,
		DisplayPath: ".hal/sync/committed.patch",
		StoredPath:  "exec-1/artifacts/sync/committed.patch",
		ApplyEligibility: &SyncOutApplyEligibility{
			Eligible: true,
			Mode:     SyncOutApplyModePatch,
			Reasons:  []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonEligiblePatch},
		},
	}
}

func safeApplyBundleArtifact() SyncOutArtifact {
	return SyncOutArtifact{
		ID:          "committed-bundle",
		DisplayName: "Committed Bundle",
		Kind:        SyncOutArtifactKindBundle,
		DisplayPath: ".hal/sync/committed.bundle",
		StoredPath:  "exec-1/artifacts/sync/committed.bundle",
		ApplyEligibility: &SyncOutApplyEligibility{
			Eligible: true,
			Mode:     SyncOutApplyModeBundle,
			Reasons:  []SyncOutApplyEligibilityReason{SyncOutApplyEligibilityReasonEligibleBundle},
		},
	}
}

func safeApplyReasonsContain(reasons []SyncOutApplyEligibilityReason, want SyncOutApplyEligibilityReason) bool {
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

type recordingSafeApplyGit struct {
	calls       []string
	sharedCalls *[]string
	dirty       DirtyState
}

func (g *recordingSafeApplyGit) record(call string) {
	g.calls = append(g.calls, call)
	if g.sharedCalls != nil {
		*g.sharedCalls = append(*g.sharedCalls, call)
	}
}

func (g *recordingSafeApplyGit) CheckCleanWorktree(context.Context, SafeApplyGitRequest) (DirtyState, error) {
	g.record("check_worktree")
	return g.dirty, nil
}

func (g *recordingSafeApplyGit) CheckPatch(context.Context, SafeApplyGitRequest) error {
	g.record("check_patch")
	return nil
}

func (g *recordingSafeApplyGit) ApplyPatch(context.Context, SafeApplyGitRequest) error {
	g.record("apply_patch")
	return nil
}

func (g *recordingSafeApplyGit) CheckBundle(context.Context, SafeApplyGitRequest) error {
	g.record("check_bundle")
	return nil
}

type recordingSafeApplyLocks struct {
	calls        *[]string
	acquiredKeys []string
	acquireErr   error
	releaseErr   error
}

func (l *recordingSafeApplyLocks) AcquireSafeApplyLock(resourceKey string) (SafeApplyLock, error) {
	if l.calls != nil {
		*l.calls = append(*l.calls, "acquire_lock")
	}
	l.acquiredKeys = append(l.acquiredKeys, resourceKey)
	if l.acquireErr != nil {
		return nil, l.acquireErr
	}
	return &recordingSafeApplyLock{calls: l.calls, releaseErr: l.releaseErr}, nil
}

type recordingSafeApplyLock struct {
	calls      *[]string
	releaseErr error
}

func (l *recordingSafeApplyLock) Release() error {
	if l.calls != nil {
		*l.calls = append(*l.calls, "release_lock")
	}
	return l.releaseErr
}
