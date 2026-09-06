package compound

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGitCommitInDirUsesFallbackIdentityWhenRepositoryHasNone(t *testing.T) {
	requireGitCLI(t)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	t.Setenv("GIT_CONFIG_GLOBAL", filepath.Join(t.TempDir(), "global.gitconfig"))
	repoDir := t.TempDir()
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "commit.gpgsign", "false")

	writeFileInRepo(t, repoDir, "checkpoint.txt", "checkpoint\n")
	runGit(t, repoDir, "add", "checkpoint.txt")
	if err := GitCommitInDir(context.Background(), repoDir, "chore: checkpoint"); err != nil {
		t.Fatalf("GitCommitInDir() error = %v", err)
	}

	if got := gitOutput(t, repoDir, "log", "-1", "--format=%an|%ae"); got != "Hal Factory|hal-factory@localhost" {
		t.Fatalf("commit identity = %q, want Hal Factory fallback", got)
	}
}

func TestGitCommitInDirPreservesConfiguredRepositoryIdentity(t *testing.T) {
	requireGitCLI(t)
	repoDir := t.TempDir()
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.name", "Repository Owner")
	runGit(t, repoDir, "config", "user.email", "owner@example.com")
	runGit(t, repoDir, "config", "commit.gpgsign", "false")

	writeFileInRepo(t, repoDir, "checkpoint.txt", "checkpoint\n")
	runGit(t, repoDir, "add", "checkpoint.txt")
	if err := GitCommitInDir(context.Background(), repoDir, "chore: checkpoint"); err != nil {
		t.Fatalf("GitCommitInDir() error = %v", err)
	}

	if got := gitOutput(t, repoDir, "log", "-1", "--format=%an|%ae"); got != "Repository Owner|owner@example.com" {
		t.Fatalf("commit identity = %q, want configured repository identity", got)
	}
}

func gitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func TestWorkingTreeChangesInDir_CleanRepo_ReturnsNil(t *testing.T) {
	requireGitCLI(t)
	repoDir := initGitRepoForWorkingTreeTest(t)

	changes, err := WorkingTreeChangesInDir(repoDir)
	if err != nil {
		t.Fatalf("WorkingTreeChangesInDir() error = %v", err)
	}
	if changes != nil {
		t.Fatalf("WorkingTreeChangesInDir() = %v, want nil", changes)
	}
}

func TestWorkingTreeChangesInDir_DirtyRepo_ReturnsSortedUniquePaths(t *testing.T) {
	requireGitCLI(t)
	repoDir := initGitRepoForWorkingTreeTest(t)

	writeFileInRepo(t, repoDir, "mid.txt", "mid\n")
	writeFileInRepo(t, repoDir, "z.txt", "z\n")
	runGit(t, repoDir, "add", "mid.txt", "z.txt")
	runGit(t, repoDir, "commit", "-m", "add files")

	writeFileInRepo(t, repoDir, "a.txt", "new\n")
	writeFileInRepo(t, repoDir, "z.txt", "changed\n")
	runGit(t, repoDir, "mv", "mid.txt", "mid-renamed.txt")

	changes, err := WorkingTreeChangesInDir(repoDir)
	if err != nil {
		t.Fatalf("WorkingTreeChangesInDir() error = %v", err)
	}
	want := []string{"a.txt", "mid-renamed.txt", "z.txt"}
	if len(changes) != len(want) {
		t.Fatalf("WorkingTreeChangesInDir() len = %d, want %d (%v)", len(changes), len(want), changes)
	}
	for i := range want {
		if changes[i] != want[i] {
			t.Fatalf("WorkingTreeChangesInDir()[%d] = %q, want %q (all=%v)", i, changes[i], want[i], changes)
		}
	}
}

func TestHashUntrackedFilesInDirStreamsLargeRegularFiles(t *testing.T) {
	dir := t.TempDir()
	content := bytes.Repeat([]byte("a"), 2*1024*1024)
	path := filepath.Join(dir, "large.bin")
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	got, err := hashUntrackedFilesInDir(dir, "large.bin\x00")
	if err != nil {
		t.Fatalf("hashUntrackedFilesInDir() error = %v", err)
	}
	sum := sha256.Sum256(content)
	wantHash := fmt.Sprintf("%x", sum)
	if !strings.Contains(got, "file:"+wantHash) {
		t.Fatalf("hashUntrackedFilesInDir() = %q, want file hash %s", got, wantHash)
	}
}

func initGitRepoForWorkingTreeTest(t *testing.T) string {
	t.Helper()

	repoDir := t.TempDir()
	runGit(t, repoDir, "init")
	runGit(t, repoDir, "config", "user.name", "hal-test")
	runGit(t, repoDir, "config", "user.email", "hal-test@example.com")
	runGit(t, repoDir, "config", "commit.gpgsign", "false")
	runGit(t, repoDir, "config", "tag.gpgsign", "false")

	writeFileInRepo(t, repoDir, "README.md", "# test repo\n")
	runGit(t, repoDir, "add", "README.md")
	runGit(t, repoDir, "commit", "-m", "initial commit")
	return repoDir
}
