//go:build linux && integration

package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

type factoryRecoverySafetyGitFixture struct {
	host, guest, input, output string
	store                      factory.Store
	record                     factory.RunRecord
}

func newFactoryRecoverySafetyGitFixture(t *testing.T) factoryRecoverySafetyGitFixture {
	t.Helper()
	host, record := factoryBundleGitFixture(t)
	if err := os.WriteFile(filepath.Join(host, "input.txt"), []byte("original input\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	factoryBundleGit(t, host, "add", "input.txt")
	factoryBundleGit(t, host, "commit", "-m", "tracked input")
	input := factoryBundleGit(t, host, "rev-parse", "HEAD")
	guest := filepath.Join(t.TempDir(), "guest")
	factoryBundleGit(t, host, "clone", "--no-hardlinks", "--", host, guest)
	if err := os.WriteFile(filepath.Join(guest, "result.txt"), []byte("completed output\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	factoryBundleGit(t, guest, "add", "result.txt")
	factoryBundleGit(t, guest, "commit", "-m", "completed output")
	output := factoryBundleGit(t, guest, "rev-parse", "HEAD")
	record.RunID = "recovery-real-git"
	record.ExecutorMode = factory.ExecutorModeSandbox
	record.Sandbox = &factory.SandboxMetadata{Workspace: &factory.SandboxWorkspaceMetadata{Mode: sandbox.SandboxWorkspaceModeClone, InputSource: sandbox.SandboxWorkspaceInputSourceGitBundle, SyncRef: input}}
	store := factory.NewStore(filepath.Join(t.TempDir(), "factory"))
	if err := store.SaveRun(&record); err != nil {
		t.Fatal(err)
	}
	f := factoryRecoverySafetyGitFixture{host: host, guest: guest, input: input, output: output, store: store, record: record}
	f.storeBundle(t, "HEAD")
	return f
}

func (f *factoryRecoverySafetyGitFixture) storeBundle(t *testing.T, refs ...string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "recovery.bundle")
	factoryBundleGit(t, f.guest, append([]string{"bundle", "create", path}, refs...)...)
	if _, err := f.store.SaveArtifactFile(f.record.RunID, factory.ArtifactReference{ID: "sandbox-recovery-bundle", Name: "sandbox-recovery-bundle", Type: "bundle", Summary: map[string]any{"outcomeKind": "recovery_bundle"}}, path); err != nil {
		t.Fatal(err)
	}
	record, err := f.store.LoadRun(f.record.RunID)
	if err != nil {
		t.Fatal(err)
	}
	f.record.Artifacts = record.Artifacts
}

func TestFactoryRecoverySafetyRealGitRejectsWithoutHostMutation(t *testing.T) {
	for _, scenario := range []string{"staged", "unstaged", "untracked", "ignored collision", "checkout expression", "option-like branch", "full ref branch", "revision expression", "corrupt bundle", "missing bundle", "symlink bundle", "unrelated output", "missing pin", "worker symbolic pin", "missing input history", "divergent destination", "ambiguous bundle", "legacy missing base", "legacy moved base"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			f := newFactoryRecoverySafetyGitFixture(t)
			switch scenario {
			case "staged", "unstaged":
				if err := os.WriteFile(filepath.Join(f.host, "input.txt"), []byte("private-dirty-canary\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if scenario == "staged" {
					factoryBundleGit(t, f.host, "add", "input.txt")
				}
			case "untracked":
				if err := os.WriteFile(filepath.Join(f.host, "private-dirty-canary"), []byte("keep\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "ignored collision":
				if err := os.WriteFile(filepath.Join(f.host, ".git", "info", "exclude"), []byte("result.txt\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(f.host, "result.txt"), []byte("private-ignored-canary\x00keep exactly\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "checkout expression":
				f.record.BranchName = "@{-1}"
			case "option-like branch":
				f.record.BranchName = "--orphan"
			case "full ref branch":
				f.record.BranchName = "refs/heads/hal/output"
			case "revision expression":
				f.record.BranchName = "hal/output~1"
			case "corrupt bundle":
				path := mustFactoryRecoveryBundleStoredPath(t, f.store, f.record)
				if err := os.WriteFile(path, []byte("not a bundle"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing bundle":
				if err := os.Remove(mustFactoryRecoveryBundleStoredPath(t, f.store, f.record)); err != nil {
					t.Fatal(err)
				}
			case "symlink bundle":
				path := mustFactoryRecoveryBundleStoredPath(t, f.store, f.record)
				outside := filepath.Join(t.TempDir(), "outside.bundle")
				if err := os.Rename(path, outside); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, path); err != nil {
					t.Fatal(err)
				}
			case "unrelated output":
				factoryBundleGit(t, f.guest, "checkout", "--orphan", "unrelated")
				factoryBundleGit(t, f.guest, "commit", "-m", "unrelated root")
				f.output = factoryBundleGit(t, f.guest, "rev-parse", "HEAD")
				f.storeBundle(t, "HEAD")
			case "missing pin":
				f.record.Sandbox.Workspace.SyncRef = ""
			case "worker symbolic pin":
				f.record.Sandbox.Workspace.SyncRef = "origin/main"
			case "missing input history":
				f.record.Sandbox.Workspace.SyncRef = strings.Repeat("f", 40)
			case "divergent destination":
				factoryBundleGit(t, f.host, "checkout", "-b", f.record.BranchName)
				factoryBundleGit(t, f.host, "commit", "--allow-empty", "-m", "divergent host output")
				factoryBundleGit(t, f.host, "checkout", "local-source")
			case "ambiguous bundle":
				f.storeBundle(t, "HEAD", "refs/remotes/origin/local-base")
			case "legacy missing base":
				f.record.Sandbox = nil
				f.record.BaseBranch = "missing-local-base"
			case "legacy moved base":
				f.record.Sandbox = nil
				factoryBundleGit(t, f.host, "checkout", "local-base")
				factoryBundleGit(t, f.host, "commit", "--allow-empty", "-m", "advanced unrelated local base")
				factoryBundleGit(t, f.host, "checkout", "local-source")
			}
			before := factoryRecoverySafetyHostSnapshot(t, f.host)
			_, _, err := applyFactorySandboxRecoveryBundle(ctx, f.store, f.host, f.record, factoryRunDeps{runGit: runFactoryGitInDir})
			if err == nil {
				t.Error("unsafe recovery accepted")
			}
			if after := factoryRecoverySafetyHostSnapshot(t, f.host); before != after {
				t.Error("rejected recovery changed host HEAD, refs, index or worktree")
			}
			if _, objectErr := runFactoryGitInDir(ctx, f.host, "cat-file", "-e", f.output+"^{commit}"); objectErr == nil {
				t.Error("rejected recovery imported output objects into host")
			}
			if err != nil && (strings.Contains(err.Error(), "private-dirty-canary") || strings.Contains(err.Error(), f.host)) {
				t.Error("recovery error leaked local details")
			}
			if scenario == "ignored collision" {
				data, err := os.ReadFile(filepath.Join(f.host, "result.txt"))
				if err != nil || string(data) != "private-ignored-canary\x00keep exactly\n" {
					t.Error("ignored canary bytes were changed")
				}
			}
			assertFactoryRecoverySafetyLockReleased(t, f.host)
		})
	}
}

func factoryRecoverySafetyHostSnapshot(t *testing.T, dir string) string {
	t.Helper()
	return factoryBundleGit(t, dir, "rev-parse", "HEAD") + "\n" + factoryBundleGit(t, dir, "symbolic-ref", "HEAD") + "\n" + factoryBundleGit(t, dir, "show-ref") + "\n" + factoryBundleGit(t, dir, "status", "--porcelain=v1", "--untracked-files=all") + "\n" + factoryBundleGit(t, dir, "diff", "HEAD")
}

func TestFactoryRecoverySafetyRealGitCleanAndRepeated(t *testing.T) {
	for _, scenario := range []string{"recorded worker pin", "legacy local base compatibility", "legacy symbolic SyncRef compatibility"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			f := newFactoryRecoverySafetyGitFixture(t)
			if scenario == "legacy local base compatibility" {
				f.record.Sandbox = nil
			}
			if scenario == "legacy symbolic SyncRef compatibility" {
				f.record.Sandbox.Workspace.InputSource = "clone"
				f.record.Sandbox.Workspace.SyncRef = "origin/main"
			}
			for attempt := 0; attempt < 2; attempt++ {
				branch, bundle, err := applyFactorySandboxRecoveryBundle(ctx, f.store, f.host, f.record, factoryRunDeps{runGit: runFactoryGitInDir})
				if err != nil || branch != f.record.BranchName || bundle == "" {
					t.Fatalf("clean recovery %d: branch=%q error=%v", attempt, branch, err)
				}
				if head := factoryBundleGit(t, f.host, "rev-parse", "HEAD"); head != f.output {
					t.Fatalf("recovery head=%s, want %s", head, f.output)
				}
				factoryBundleGit(t, f.host, "merge-base", "--is-ancestor", f.input, "HEAD")
				if status := factoryBundleGit(t, f.host, "status", "--porcelain=v1"); status != "" {
					t.Fatalf("recovery dirty: %s", status)
				}
				assertFactoryRecoverySafetyLockReleased(t, f.host)
			}
		})
	}
}

func assertFactoryRecoverySafetyLockReleased(t *testing.T, dir string) {
	t.Helper()
	lock, err := sandboxworkspace.NewLockManager(filepath.Join(os.TempDir(), "hal-workspace-locks")).Acquire("workspace:" + dir)
	if err != nil {
		t.Fatalf("recovery left workspace lock active: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestFactoryRecoverySafetyRealGitRejectsChangedPreflight(t *testing.T) {
	for _, scenario := range []string{"destination ref changed", "cancelled after analysis", "Git failure", "current ref changed during host fetch", "cancelled during host fetch", "current ref changed after checkout"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			f := newFactoryRecoverySafetyGitFixture(t)
			if scenario == "current ref changed after checkout" {
				factoryBundleGit(t, f.host, "branch", f.record.BranchName, f.input)
			}
			cause := errors.New("private-git-failure-canary")
			expected := factoryRecoverySafetyHostSnapshot(t, f.host)
			triggered := false
			_, _, err := applyFactorySandboxRecoveryBundle(ctx, f.store, f.host, f.record, factoryRunDeps{runGit: func(ctx context.Context, dir string, args ...string) (string, error) {
				if args[0] == "clone" && scenario == "Git failure" {
					triggered = true
					return "", cause
				}
				out, err := runFactoryGitInDir(ctx, dir, args...)
				if dir != f.host && args[0] == "diff-tree" && err == nil && (scenario == "destination ref changed" || scenario == "cancelled after analysis") {
					triggered = true
					if scenario == "destination ref changed" {
						factoryBundleGit(t, f.host, "update-ref", "refs/heads/"+f.record.BranchName, f.input)
						expected = factoryRecoverySafetyHostSnapshot(t, f.host)
					} else {
						cancel()
					}
				}
				if dir == f.host && err == nil && (args[0] == "fetch" && strings.Contains(scenario, "host fetch") || args[0] == "checkout" && scenario == "current ref changed after checkout") {
					triggered = true
					if scenario == "cancelled during host fetch" {
						cancel()
					} else {
						factoryBundleGit(t, f.host, "checkout", "local-base")
						expected = factoryRecoverySafetyHostSnapshot(t, f.host)
					}
				}
				return out, err
			}})
			if !triggered || err == nil {
				t.Fatalf("changed preflight was not rejected: triggered=%t err=%v", triggered, err)
			}
			if scenario == "Git failure" && !errors.Is(err, cause) || strings.HasPrefix(scenario, "cancelled") && !errors.Is(err, context.Canceled) {
				t.Error("original failure identity lost")
			}
			if strings.Contains(err.Error(), "private-git-failure-canary") {
				t.Error("raw Git error leaked")
			}
			if factoryRecoverySafetyHostSnapshot(t, f.host) != expected {
				t.Error("recovery changed host after rejected preflight")
			}
			if _, err := runFactoryGitInDir(context.Background(), f.host, "cat-file", "-e", f.output+"^{commit}"); err == nil && !strings.Contains(scenario, "host fetch") && !strings.Contains(scenario, "after checkout") {
				t.Error("rejected preflight imported host objects")
			}
			assertFactoryRecoverySafetyLockReleased(t, f.host)
		})
	}
}

func TestFactoryRecoverySafetyRealGitPinsSnapshotAfterStoredPathReplacement(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	f := newFactoryRecoverySafetyGitFixture(t)
	replaced := false
	_, _, err := applyFactorySandboxRecoveryBundle(ctx, f.store, f.host, f.record, factoryRunDeps{runGit: func(ctx context.Context, dir string, args ...string) (string, error) {
		if args[0] == "bundle" && args[1] == "verify" {
			replaced = true
			if err := os.WriteFile(mustFactoryRecoveryBundleStoredPath(t, f.store, f.record), []byte("replaced stored path"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return runFactoryGitInDir(ctx, dir, args...)
	}})
	if !replaced || err != nil || factoryBundleGit(t, f.host, "rev-parse", "HEAD") != f.output {
		t.Fatalf("verified snapshot not retained: replaced=%t err=%v", replaced, err)
	}
}
