package compound

import "testing"

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
