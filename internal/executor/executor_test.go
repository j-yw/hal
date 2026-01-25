package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/jywlabs/goralph/internal/claude"
)

// mockEngine is a mock Claude engine for testing.
type mockEngine struct {
	results []claude.Result // Results to return for each call
	calls   []string        // Prompts received
	index   int
}

func (m *mockEngine) Execute(prompt string) claude.Result {
	m.calls = append(m.calls, prompt)
	if m.index < len(m.results) {
		result := m.results[m.index]
		m.index++
		return result
	}
	return claude.Result{Success: false, Error: errors.New("no more mock results")}
}

func TestRun_NoTasks(t *testing.T) {
	// Create temp PRD file with no pending tasks
	dir := t.TempDir()
	prdPath := filepath.Join(dir, "prd.md")
	content := `# PRD
- [x] Completed task 1
- [x] Completed task 2
`
	if err := os.WriteFile(prdPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write PRD: %v", err)
	}

	// Initialize git repo
	initTestRepo(t, dir)

	engine := &mockEngine{}
	exec := NewWithEngine(Config{
		PRDFile:  prdPath,
		RepoPath: dir,
	}, engine)

	result := exec.Run(context.Background())

	if !result.Success {
		t.Errorf("expected success, got error: %v", result.Error)
	}
	if result.TotalTasks != 0 {
		t.Errorf("expected 0 tasks, got %d", result.TotalTasks)
	}
	if result.CompletedTasks != 0 {
		t.Errorf("expected 0 completed, got %d", result.CompletedTasks)
	}
}

func TestRun_SingleTask_Success(t *testing.T) {
	// Create temp PRD file with one pending task
	dir := t.TempDir()
	prdPath := filepath.Join(dir, "prd.md")
	content := `# PRD
- [ ] Implement feature X
`
	if err := os.WriteFile(prdPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write PRD: %v", err)
	}

	// Initialize git repo
	initTestRepo(t, dir)

	engine := &mockEngine{
		results: []claude.Result{
			{Success: true, Output: "Task completed"},
		},
	}
	var logBuf bytes.Buffer
	exec := NewWithEngine(Config{
		PRDFile:  prdPath,
		RepoPath: dir,
		Logger:   &logBuf,
	}, engine)

	result := exec.Run(context.Background())

	if !result.Success {
		t.Errorf("expected success, got error: %v", result.Error)
	}
	if result.TotalTasks != 1 {
		t.Errorf("expected 1 task, got %d", result.TotalTasks)
	}
	if result.CompletedTasks != 1 {
		t.Errorf("expected 1 completed, got %d", result.CompletedTasks)
	}

	// Verify task was marked complete
	updatedContent, _ := os.ReadFile(prdPath)
	if !strings.Contains(string(updatedContent), "- [x] Implement feature X") {
		t.Errorf("task not marked complete in PRD")
	}

	// Verify engine was called with prompt containing task description
	if len(engine.calls) != 1 {
		t.Errorf("expected 1 engine call, got %d", len(engine.calls))
	}
	if !strings.Contains(engine.calls[0], "Implement feature X") {
		t.Errorf("prompt doesn't contain task description")
	}
}

func TestRun_MultipleTasks_AllSuccess(t *testing.T) {
	dir := t.TempDir()
	prdPath := filepath.Join(dir, "prd.md")
	content := `# PRD
- [ ] Task 1
- [ ] Task 2
- [ ] Task 3
`
	if err := os.WriteFile(prdPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write PRD: %v", err)
	}

	initTestRepo(t, dir)

	engine := &mockEngine{
		results: []claude.Result{
			{Success: true, Output: "Task 1 done"},
			{Success: true, Output: "Task 2 done"},
			{Success: true, Output: "Task 3 done"},
		},
	}
	exec := NewWithEngine(Config{
		PRDFile:  prdPath,
		RepoPath: dir,
	}, engine)

	result := exec.Run(context.Background())

	if !result.Success {
		t.Errorf("expected success, got error: %v", result.Error)
	}
	if result.TotalTasks != 3 {
		t.Errorf("expected 3 tasks, got %d", result.TotalTasks)
	}
	if result.CompletedTasks != 3 {
		t.Errorf("expected 3 completed, got %d", result.CompletedTasks)
	}
}

func TestRun_TaskFailure_NonRetryable(t *testing.T) {
	dir := t.TempDir()
	prdPath := filepath.Join(dir, "prd.md")
	content := `# PRD
- [ ] Task 1
- [ ] Task 2
`
	if err := os.WriteFile(prdPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write PRD: %v", err)
	}

	initTestRepo(t, dir)

	engine := &mockEngine{
		results: []claude.Result{
			{Success: false, Error: errors.New("syntax error in code")},
		},
	}
	exec := NewWithEngine(Config{
		PRDFile:  prdPath,
		RepoPath: dir,
	}, engine)

	result := exec.Run(context.Background())

	if result.Success {
		t.Error("expected failure, got success")
	}
	if result.CompletedTasks != 0 {
		t.Errorf("expected 0 completed, got %d", result.CompletedTasks)
	}
	if result.Error == nil {
		t.Error("expected error, got nil")
	}
}

func TestRun_TaskFailure_RetryableSuccess(t *testing.T) {
	dir := t.TempDir()
	prdPath := filepath.Join(dir, "prd.md")
	content := `# PRD
- [ ] Task 1
`
	if err := os.WriteFile(prdPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write PRD: %v", err)
	}

	initTestRepo(t, dir)

	// First call fails with retryable error, second succeeds
	engine := &mockEngine{
		results: []claude.Result{
			{Success: false, Error: errors.New("rate limit exceeded")},
			{Success: true, Output: "Task done"},
		},
	}
	exec := NewWithEngine(Config{
		PRDFile:    prdPath,
		RepoPath:   dir,
		MaxRetries: 3,
	}, engine)

	// Use a context with short timeout to prevent long waits
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result := exec.Run(ctx)

	if !result.Success {
		t.Errorf("expected success after retry, got error: %v", result.Error)
	}
	if result.CompletedTasks != 1 {
		t.Errorf("expected 1 completed, got %d", result.CompletedTasks)
	}
	if len(engine.calls) < 2 {
		t.Errorf("expected at least 2 engine calls (retry), got %d", len(engine.calls))
	}
}

func TestRun_InvalidPRDFile(t *testing.T) {
	exec := NewWithEngine(Config{
		PRDFile:  "/nonexistent/path/prd.md",
		RepoPath: ".",
	}, &mockEngine{})

	result := exec.Run(context.Background())

	if result.Success {
		t.Error("expected failure for nonexistent file")
	}
	if result.Error == nil {
		t.Error("expected error, got nil")
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	prdPath := filepath.Join(dir, "prd.md")
	content := `# PRD
- [ ] Task 1
`
	if err := os.WriteFile(prdPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write PRD: %v", err)
	}

	initTestRepo(t, dir)

	// Engine that always returns retryable error
	engine := &mockEngine{
		results: []claude.Result{
			{Success: false, Error: errors.New("rate limit exceeded")},
			{Success: false, Error: errors.New("rate limit exceeded")},
			{Success: false, Error: errors.New("rate limit exceeded")},
			{Success: false, Error: errors.New("rate limit exceeded")},
		},
	}

	exec := NewWithEngine(Config{
		PRDFile:    prdPath,
		RepoPath:   dir,
		MaxRetries: 3,
	}, engine)

	// Cancel context immediately
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result := exec.Run(ctx)

	if result.Success {
		t.Error("expected failure due to cancellation")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		maxLen   int
		expected string
	}{
		{"short", 10, "short"},
		{"exactly10!", 10, "exactly10!"},
		{"this is a long string", 10, "this is..."},
		{"abc", 3, "abc"},
		{"abcd", 3, "abc"},
		{"", 5, ""},
	}

	for _, tt := range tests {
		result := truncate(tt.input, tt.maxLen)
		if result != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.maxLen, result, tt.expected)
		}
	}
}

func TestNew_DefaultConfig(t *testing.T) {
	exec := New(Config{PRDFile: "test.md"})
	if exec.config.RepoPath != "." {
		t.Errorf("expected default RepoPath '.', got %q", exec.config.RepoPath)
	}
	if exec.config.MaxRetries != 3 {
		t.Errorf("expected default MaxRetries 3, got %d", exec.config.MaxRetries)
	}
}

// initTestRepo creates an initialized git repository for testing.
func initTestRepo(t *testing.T, dir string) {
	t.Helper()

	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("failed to init git repo: %v", err)
	}

	// Create initial commit (required for some git operations)
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatalf("failed to get worktree: %v", err)
	}

	// Create a dummy file and commit
	dummyPath := filepath.Join(dir, ".gitkeep")
	if err := os.WriteFile(dummyPath, []byte(""), 0644); err != nil {
		t.Fatalf("failed to write dummy file: %v", err)
	}

	_, err = worktree.Add(".gitkeep")
	if err != nil {
		t.Fatalf("failed to add dummy file: %v", err)
	}

	_, err = worktree.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@example.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("failed to create initial commit: %v", err)
	}
}
