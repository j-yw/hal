package integrator

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestIntegratorIntegratesWorkerCommitAndCommitsBookkeeping(t *testing.T) {
	repo := initTestRepo(t)
	writeFile(t, repo, ".hal/prd.json", `{
  "project": "parallel",
  "tasks": [
    {"id": "T-001", "title": "One", "priority": 1, "passes": false},
    {"id": "T-002", "title": "Two", "priority": 2, "passes": false}
  ]
}
`)
	writeFile(t, repo, ".hal/progress.txt", "## Progress\n")
	writeFile(t, repo, "app.txt", "base\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	git(t, repo, "checkout", "-b", "worker/t-001")
	writeFile(t, repo, "app.txt", "worker change\n")
	git(t, repo, "commit", "-am", "feat: worker t-001")
	workerCommit := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))
	git(t, repo, "checkout", "main")

	in := New()
	result, err := in.Integrate(context.Background(), Request{
		RepoDir:         repo,
		TaskID:          "T-001",
		WorkerBranch:    "worker/t-001",
		WorkerCommit:    workerCommit,
		CanonicalBranch: "main",
		PRDPath:         ".hal/prd.json",
		ProgressPath:    ".hal/progress.txt",
		ProgressEntry:   "- T-001 integrated",
		CheckCommands: []CheckCommand{{
			Name: "git",
			Args: []string{"rev-parse", "--verify", "HEAD"},
		}},
		Bookkeeping: BookkeepingConfig{
			Commit:  true,
			Message: "chore: mark T-001 integrated",
		},
	})
	if err != nil {
		t.Fatalf("Integrate() error = %v", err)
	}
	if result.IntegratedCommit == "" {
		t.Fatal("IntegratedCommit is empty")
	}
	if result.BookkeepingCommit == "" || !result.BookkeepingCreated {
		t.Fatalf("bookkeeping result not recorded: %#v", result)
	}
	if len(result.Checks) != 1 {
		t.Fatalf("checks = %d, want 1", len(result.Checks))
	}
	if got := strings.TrimSpace(git(t, repo, "branch", "--show-current")); got != "main" {
		t.Fatalf("current branch = %q, want main", got)
	}
	if got := readFile(t, repo, "app.txt"); got != "worker change\n" {
		t.Fatalf("app.txt = %q", got)
	}
	requireTaskPasses(t, filepath.Join(repo, ".hal/prd.json"), "T-001", true)
	requireTaskPasses(t, filepath.Join(repo, ".hal/prd.json"), "T-002", false)
	if got := readFile(t, repo, ".hal/progress.txt"); !strings.Contains(got, "- T-001 integrated\n") {
		t.Fatalf("progress missing entry: %q", got)
	}
	if got := strings.TrimSpace(git(t, repo, "status", "--short")); got != "" {
		t.Fatalf("git status = %q, want clean", got)
	}
	if got := strings.TrimSpace(git(t, repo, "log", "-1", "--pretty=%s")); got != "chore: mark T-001 integrated" {
		t.Fatalf("last commit subject = %q", got)
	}
}

func TestIntegratorRejectsWorkerCommitTouchingCanonicalHalState(t *testing.T) {
	repo := initTestRepo(t)
	writeFile(t, repo, ".hal/prd.json", `{
  "project": "parallel",
  "tasks": [
    {"id": "T-001", "title": "One", "priority": 1, "passes": false},
    {"id": "T-002", "title": "Two", "priority": 2, "passes": false}
  ]
}
`)
	writeFile(t, repo, ".hal/progress.txt", "## Progress\n")
	writeFile(t, repo, "app.txt", "base\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	originalHead := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))

	git(t, repo, "checkout", "-b", "worker/t-001")
	writeFile(t, repo, "app.txt", "worker change\n")
	writeFile(t, repo, ".hal/prd.json", `{
  "project": "parallel",
  "tasks": [
    {"id": "T-001", "title": "One", "priority": 1, "passes": true},
    {"id": "T-002", "title": "Two", "priority": 2, "passes": true}
  ]
}
`)
	writeFile(t, repo, ".hal/progress.txt", "## Progress\n- forged progress\n")
	git(t, repo, "add", "app.txt", ".hal/prd.json", ".hal/progress.txt")
	git(t, repo, "commit", "-m", "feat: worker with canonical state")
	workerCommit := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))
	git(t, repo, "checkout", "main")

	_, err := New().Integrate(context.Background(), Request{
		RepoDir:         repo,
		TaskID:          "T-001",
		WorkerBranch:    "worker/t-001",
		WorkerCommit:    workerCommit,
		CanonicalBranch: "main",
		PRDPath:         ".hal/prd.json",
		ProgressPath:    ".hal/progress.txt",
		ProgressEntry:   "- T-001 integrated",
	})
	if err == nil {
		t.Fatal("Integrate() error = nil, want canonical state rejection")
	}
	var integrationErr *IntegrationError
	if !errors.As(err, &integrationErr) {
		t.Fatalf("error type = %T, want *IntegrationError", err)
	}
	if integrationErr.Stage != StageValidate {
		t.Fatalf("stage = %s, want %s", integrationErr.Stage, StageValidate)
	}
	if !strings.Contains(integrationErr.Error(), "touches canonical Hal state") || !strings.Contains(integrationErr.Error(), ".hal/prd.json") || !strings.Contains(integrationErr.Error(), ".hal/progress.txt") {
		t.Fatalf("error = %v, want canonical state paths", integrationErr)
	}
	if got := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD")); got != originalHead {
		t.Fatalf("HEAD = %s, want %s", got, originalHead)
	}
	if got := readFile(t, repo, "app.txt"); got != "base\n" {
		t.Fatalf("app.txt = %q, want base content", got)
	}
	requireTaskPasses(t, filepath.Join(repo, ".hal/prd.json"), "T-001", false)
	requireTaskPasses(t, filepath.Join(repo, ".hal/prd.json"), "T-002", false)
	if got := readFile(t, repo, ".hal/progress.txt"); strings.Contains(got, "forged") || strings.Contains(got, "integrated") {
		t.Fatalf("progress was updated on rejected worker commit: %q", got)
	}
	if got := strings.TrimSpace(git(t, repo, "status", "--short")); got != "" {
		t.Fatalf("git status = %q, want clean", got)
	}
}

func TestIntegratorRejectsMultiCommitWorkerBranch(t *testing.T) {
	repo := initTestRepo(t)
	writeFile(t, repo, ".hal/prd.json", `{
  "project": "parallel",
  "tasks": [
    {"id": "T-001", "title": "One", "priority": 1, "passes": false}
  ]
}
`)
	writeFile(t, repo, ".hal/progress.txt", "## Progress\n")
	writeFile(t, repo, "app.txt", "base\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	originalHead := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))

	git(t, repo, "checkout", "-b", "worker/t-001")
	writeFile(t, repo, "first.txt", "first\n")
	git(t, repo, "add", "first.txt")
	git(t, repo, "commit", "-m", "feat: first part")
	writeFile(t, repo, "second.txt", "second\n")
	git(t, repo, "add", "second.txt")
	git(t, repo, "commit", "-m", "feat: second part")
	workerCommit := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))
	git(t, repo, "checkout", "main")

	_, err := New().Integrate(context.Background(), Request{
		RepoDir:         repo,
		TaskID:          "T-001",
		WorkerBranch:    "worker/t-001",
		WorkerCommit:    workerCommit,
		CanonicalBranch: "main",
		PRDPath:         ".hal/prd.json",
		ProgressPath:    ".hal/progress.txt",
		ProgressEntry:   "- T-001 integrated",
	})
	if err == nil {
		t.Fatal("Integrate() error = nil, want multi-commit branch rejection")
	}
	var integrationErr *IntegrationError
	if !errors.As(err, &integrationErr) {
		t.Fatalf("error type = %T, want *IntegrationError", err)
	}
	if integrationErr.Stage != StageValidate {
		t.Fatalf("stage = %s, want %s", integrationErr.Stage, StageValidate)
	}
	if !strings.Contains(integrationErr.Error(), "has 2 commits") || !strings.Contains(integrationErr.Error(), "requires a single worker commit") {
		t.Fatalf("error = %v, want multi-commit rejection", integrationErr)
	}
	if got := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD")); got != originalHead {
		t.Fatalf("HEAD = %s, want %s", got, originalHead)
	}
	if _, err := os.Stat(filepath.Join(repo, "first.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("first.txt err = %v, want not exist", err)
	}
	if _, err := os.Stat(filepath.Join(repo, "second.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second.txt err = %v, want not exist", err)
	}
	requireTaskPasses(t, filepath.Join(repo, ".hal/prd.json"), "T-001", false)
	if got := readFile(t, repo, ".hal/progress.txt"); strings.Contains(got, "integrated") {
		t.Fatalf("progress was updated on rejected worker branch: %q", got)
	}
	if got := strings.TrimSpace(git(t, repo, "status", "--short")); got != "" {
		t.Fatalf("git status = %q, want clean", got)
	}
}

func TestIntegratorReturnsStructuredErrorAndAbortsCherryPickConflict(t *testing.T) {
	repo := initTestRepo(t)
	writeFile(t, repo, ".hal/prd.json", `{"tasks":[{"id":"T-001","passes":false}]}`)
	writeFile(t, repo, ".hal/progress.txt", "progress\n")
	writeFile(t, repo, "conflict.txt", "base\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")

	git(t, repo, "checkout", "-b", "worker/t-001")
	writeFile(t, repo, "conflict.txt", "worker\n")
	git(t, repo, "commit", "-am", "worker change")
	workerCommit := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))

	git(t, repo, "checkout", "main")
	writeFile(t, repo, "conflict.txt", "canonical\n")
	git(t, repo, "commit", "-am", "canonical change")
	originalHead := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))

	_, err := New().Integrate(context.Background(), Request{
		RepoDir:         repo,
		TaskID:          "T-001",
		WorkerBranch:    "worker/t-001",
		WorkerCommit:    workerCommit,
		CanonicalBranch: "main",
		PRDPath:         ".hal/prd.json",
		ProgressPath:    ".hal/progress.txt",
		ProgressEntry:   "- T-001 integrated",
	})
	if err == nil {
		t.Fatal("Integrate() error = nil, want conflict")
	}
	var integrationErr *IntegrationError
	if !errors.As(err, &integrationErr) {
		t.Fatalf("error type = %T, want *IntegrationError", err)
	}
	if integrationErr.Stage != StageCherryPick {
		t.Fatalf("stage = %s, want %s", integrationErr.Stage, StageCherryPick)
	}
	if integrationErr.RollbackErr != nil {
		t.Fatalf("rollback error = %v", integrationErr.RollbackErr)
	}
	if got := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD")); got != originalHead {
		t.Fatalf("HEAD = %s, want %s", got, originalHead)
	}
	if got := readFile(t, repo, "conflict.txt"); got != "canonical\n" {
		t.Fatalf("conflict.txt = %q", got)
	}
	requireTaskPasses(t, filepath.Join(repo, ".hal/prd.json"), "T-001", false)
	if got := readFile(t, repo, ".hal/progress.txt"); strings.Contains(got, "integrated") {
		t.Fatalf("progress was updated on conflict: %q", got)
	}
	if got := strings.TrimSpace(git(t, repo, "status", "--short")); got != "" {
		t.Fatalf("git status = %q, want clean", got)
	}
}

func TestIntegratorReturnsStructuredErrorAndRollsBackCheckFailure(t *testing.T) {
	repo := initTestRepo(t)
	writeFile(t, repo, ".hal/prd.json", `{"tasks":[{"id":"T-001","passes":false}]}`)
	writeFile(t, repo, ".hal/progress.txt", "progress\n")
	writeFile(t, repo, "app.txt", "base\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	originalHead := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))

	git(t, repo, "checkout", "-b", "worker/t-001")
	writeFile(t, repo, "app.txt", "worker\n")
	git(t, repo, "commit", "-am", "worker change")
	workerCommit := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))
	git(t, repo, "checkout", "main")

	_, err := New().Integrate(context.Background(), Request{
		RepoDir:         repo,
		TaskID:          "T-001",
		WorkerBranch:    "worker/t-001",
		WorkerCommit:    workerCommit,
		CanonicalBranch: "main",
		PRDPath:         ".hal/prd.json",
		ProgressPath:    ".hal/progress.txt",
		ProgressEntry:   "- T-001 integrated",
		CheckCommands: []CheckCommand{{
			Name: "git",
			Args: []string{"config", "--get", "hal.test.missing"},
		}},
	})
	if err == nil {
		t.Fatal("Integrate() error = nil, want check failure")
	}
	var integrationErr *IntegrationError
	if !errors.As(err, &integrationErr) {
		t.Fatalf("error type = %T, want *IntegrationError", err)
	}
	if integrationErr.Stage != StageCheck {
		t.Fatalf("stage = %s, want %s", integrationErr.Stage, StageCheck)
	}
	if integrationErr.RollbackErr != nil {
		t.Fatalf("rollback error = %v", integrationErr.RollbackErr)
	}
	if got := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD")); got != originalHead {
		t.Fatalf("HEAD = %s, want %s", got, originalHead)
	}
	if got := readFile(t, repo, "app.txt"); got != "base\n" {
		t.Fatalf("app.txt = %q", got)
	}
	requireTaskPasses(t, filepath.Join(repo, ".hal/prd.json"), "T-001", false)
	if got := readFile(t, repo, ".hal/progress.txt"); strings.Contains(got, "integrated") {
		t.Fatalf("progress was updated on check failure: %q", got)
	}
	if got := strings.TrimSpace(git(t, repo, "status", "--short")); got != "" {
		t.Fatalf("git status = %q, want clean", got)
	}
}

func TestIntegratorReturnsStructuredErrorAndRollsBackMissingProgressFile(t *testing.T) {
	repo := initTestRepo(t)
	writeFile(t, repo, ".hal/prd.json", `{"tasks":[{"id":"T-001","passes":false}]}`)
	writeFile(t, repo, "app.txt", "base\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-m", "initial")
	originalHead := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))

	git(t, repo, "checkout", "-b", "worker/t-001")
	writeFile(t, repo, "app.txt", "worker\n")
	git(t, repo, "commit", "-am", "worker change")
	workerCommit := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD"))
	git(t, repo, "checkout", "main")

	_, err := New().Integrate(context.Background(), Request{
		RepoDir:         repo,
		TaskID:          "T-001",
		WorkerBranch:    "worker/t-001",
		WorkerCommit:    workerCommit,
		CanonicalBranch: "main",
		PRDPath:         ".hal/prd.json",
		ProgressPath:    ".hal/progress.txt",
		ProgressEntry:   "- T-001 integrated",
	})
	if err == nil {
		t.Fatal("Integrate() error = nil, want missing progress failure")
	}
	var integrationErr *IntegrationError
	if !errors.As(err, &integrationErr) {
		t.Fatalf("error type = %T, want *IntegrationError", err)
	}
	if integrationErr.Stage != StageProgress {
		t.Fatalf("stage = %s, want %s", integrationErr.Stage, StageProgress)
	}
	if integrationErr.RollbackErr != nil {
		t.Fatalf("rollback error = %v", integrationErr.RollbackErr)
	}
	if got := strings.TrimSpace(git(t, repo, "rev-parse", "HEAD")); got != originalHead {
		t.Fatalf("HEAD = %s, want %s", got, originalHead)
	}
	if got := readFile(t, repo, "app.txt"); got != "base\n" {
		t.Fatalf("app.txt = %q", got)
	}
	requireTaskPasses(t, filepath.Join(repo, ".hal/prd.json"), "T-001", false)
	if _, err := os.Stat(filepath.Join(repo, ".hal/progress.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("progress stat error = %v, want not exist", err)
	}
	if got := strings.TrimSpace(git(t, repo, "status", "--short")); got != "" {
		t.Fatalf("git status = %q, want clean", got)
	}
}

func initTestRepo(t *testing.T) string {
	t.Helper()
	repo := t.TempDir()
	git(t, repo, "init", "-b", "main")
	git(t, repo, "config", "user.name", "Hal Test")
	git(t, repo, "config", "user.email", "hal-test@example.com")
	return repo
}

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(out))
	}
	return string(out)
}

func writeFile(t *testing.T, dir, rel, content string) {
	t.Helper()
	path := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func readFile(t *testing.T, dir, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(data)
}

func requireTaskPasses(t *testing.T, path, taskID string, want bool) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read PRD: %v", err)
	}
	var doc struct {
		UserStories []struct {
			ID     string `json:"id"`
			Passes bool   `json:"passes"`
		} `json:"userStories"`
		Tasks []struct {
			ID     string `json:"id"`
			Passes bool   `json:"passes"`
		} `json:"tasks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("parse PRD: %v\n%s", err, string(data))
	}
	for _, item := range doc.UserStories {
		if item.ID == taskID {
			if item.Passes != want {
				t.Fatalf("%s passes = %v, want %v", taskID, item.Passes, want)
			}
			return
		}
	}
	for _, item := range doc.Tasks {
		if item.ID == taskID {
			if item.Passes != want {
				t.Fatalf("%s passes = %v, want %v", taskID, item.Passes, want)
			}
			return
		}
	}
	t.Fatalf("task %s not found", taskID)
}
