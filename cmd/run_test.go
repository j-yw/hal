package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunRun_DryRun_AllowsMissingGitRepoWithoutBase(t *testing.T) {
	dir := t.TempDir()

	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "prompt.md"), []byte("Base: {{BASE_BRANCH}}\n"), 0644); err != nil {
		t.Fatalf("write prompt.md: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "progress.txt"), []byte("## Codebase Patterns\n"), 0644); err != nil {
		t.Fatalf("write progress.txt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halDir, "prd.json"), []byte(`{
  "project": "test",
  "branchName": "hal/test",
  "description": "desc",
  "userStories": [
    {
      "id": "US-001",
      "title": "Story",
      "description": "Do thing",
      "acceptanceCriteria": ["works"],
      "priority": 1,
      "passes": false
    }
  ]
}`), 0644); err != nil {
		t.Fatalf("write prd.json: %v", err)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
		dryRunFlag = false
		storyFlag = ""
		runBaseFlag = ""
		engineFlag = "claude"
		maxRetries = 3
		retryDelay = 5 * time.Second
	})
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	dryRunFlag = true
	storyFlag = ""
	runBaseFlag = ""
	engineFlag = "claude"
	maxRetries = 1
	retryDelay = 10 * time.Millisecond

	if err := runRun(nil, nil); err != nil {
		t.Fatalf("runRun should succeed without git repo in dry-run mode, got: %v", err)
	}
}

func TestRunRun_DryRun_AllowsDetachedHeadWithoutBase(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not found")
	}

	dir := t.TempDir()
	writeFile := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}
	}

	runGit := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, string(out))
		}
		return strings.TrimSpace(string(out))
	}

	runGit("init")
	runGit("config", "user.name", "tester")
	runGit("config", "user.email", "tester@example.com")
	runGit("config", "commit.gpgsign", "false")

	writeFile(filepath.Join(dir, "README.md"), "seed\n")
	runGit("add", "README.md")
	runGit("commit", "-m", "init")
	commit := runGit("rev-parse", "HEAD")
	runGit("checkout", "--detach", commit)

	halDir := filepath.Join(dir, ".hal")
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("mkdir .hal: %v", err)
	}
	writeFile(filepath.Join(halDir, "prompt.md"), "Base: {{BASE_BRANCH}}\n")
	writeFile(filepath.Join(halDir, "progress.txt"), "## Codebase Patterns\n")
	writeFile(filepath.Join(halDir, "prd.json"), `{
  "project": "test",
  "branchName": "hal/test",
  "description": "desc",
  "userStories": [
    {
      "id": "US-001",
      "title": "Story",
      "description": "Do thing",
      "acceptanceCriteria": ["works"],
      "priority": 1,
      "passes": false
    }
  ]
}`)

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origDir)
		dryRunFlag = false
		storyFlag = ""
		runBaseFlag = ""
		engineFlag = "claude"
		maxRetries = 3
		retryDelay = 5 * time.Second
	})
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	dryRunFlag = true
	storyFlag = ""
	runBaseFlag = ""
	engineFlag = "claude"
	maxRetries = 1
	retryDelay = 10 * time.Millisecond

	if err := runRun(nil, nil); err != nil {
		t.Fatalf("runRun should succeed on detached HEAD without --base, got: %v", err)
	}
}
