package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestFormatCommitMessage(t *testing.T) {
	tests := []struct {
		name            string
		taskDescription string
		want            string
	}{
		{
			name:            "short description",
			taskDescription: "Fix bug",
			want:            "goralph: Fix bug",
		},
		{
			name:            "exactly 50 chars",
			taskDescription: "12345678901234567890123456789012345678901234567890",
			want:            "goralph: 12345678901234567890123456789012345678901234567890",
		},
		{
			name:            "truncate long description",
			taskDescription: "This is a very long task description that should be truncated to 50 characters",
			want:            "goralph: This is a very long task description that should b",
		},
		{
			name:            "empty description",
			taskDescription: "",
			want:            "goralph: ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatCommitMessage(tt.taskDescription)
			if got != tt.want {
				t.Errorf("formatCommitMessage() = %q, want %q", got, tt.want)
			}
		})
	}
}

// createTestRepo creates a temporary git repository for testing.
func createTestRepo(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()

	// Initialize git repository
	repo, err := git.PlainInit(tmpDir, false)
	if err != nil {
		t.Fatalf("Failed to init repo: %v", err)
	}

	// Create an initial commit so we have a HEAD
	worktree, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Failed to get worktree: %v", err)
	}

	// Create a file and commit it
	initialFile := filepath.Join(tmpDir, "README.md")
	err = os.WriteFile(initialFile, []byte("# Test Repo\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to create initial file: %v", err)
	}

	_, err = worktree.Add("README.md")
	if err != nil {
		t.Fatalf("Failed to add file: %v", err)
	}

	_, err = worktree.Commit("Initial commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "Test",
			Email: "test@test.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		t.Fatalf("Failed to create initial commit: %v", err)
	}

	return tmpDir
}

func TestAutoCommit_WithChanges(t *testing.T) {
	repoPath := createTestRepo(t)

	// Create a new file to have changes
	newFile := filepath.Join(repoPath, "newfile.txt")
	err := os.WriteFile(newFile, []byte("New content\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to create new file: %v", err)
	}

	result, err := AutoCommit(repoPath, "Add new file")
	if err != nil {
		t.Fatalf("AutoCommit() unexpected error: %v", err)
	}

	if !result.Committed {
		t.Error("AutoCommit() Committed = false, want true")
	}

	if result.Hash == "" {
		t.Error("AutoCommit() Hash is empty")
	}

	if result.Message != "goralph: Add new file" {
		t.Errorf("AutoCommit() Message = %q, want %q", result.Message, "goralph: Add new file")
	}

	// Verify the commit was actually made
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		t.Fatalf("Failed to open repo: %v", err)
	}

	head, err := repo.Head()
	if err != nil {
		t.Fatalf("Failed to get HEAD: %v", err)
	}

	commit, err := repo.CommitObject(head.Hash())
	if err != nil {
		t.Fatalf("Failed to get commit: %v", err)
	}

	if commit.Message != "goralph: Add new file" {
		t.Errorf("Commit message = %q, want %q", commit.Message, "goralph: Add new file")
	}
}

func TestAutoCommit_NoChanges(t *testing.T) {
	repoPath := createTestRepo(t)

	// Don't make any changes
	result, err := AutoCommit(repoPath, "Nothing to commit")
	if err != nil {
		t.Fatalf("AutoCommit() unexpected error: %v", err)
	}

	if result.Committed {
		t.Error("AutoCommit() Committed = true, want false (no changes)")
	}

	if result.Hash != "" {
		t.Errorf("AutoCommit() Hash = %q, want empty", result.Hash)
	}
}

func TestAutoCommit_ModifiedFile(t *testing.T) {
	repoPath := createTestRepo(t)

	// Modify the existing file
	existingFile := filepath.Join(repoPath, "README.md")
	err := os.WriteFile(existingFile, []byte("# Test Repo\n\nModified content.\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to modify file: %v", err)
	}

	result, err := AutoCommit(repoPath, "Update README")
	if err != nil {
		t.Fatalf("AutoCommit() unexpected error: %v", err)
	}

	if !result.Committed {
		t.Error("AutoCommit() Committed = false, want true")
	}
}

func TestAutoCommit_DeletedFile(t *testing.T) {
	repoPath := createTestRepo(t)

	// Delete the existing file
	existingFile := filepath.Join(repoPath, "README.md")
	err := os.Remove(existingFile)
	if err != nil {
		t.Fatalf("Failed to delete file: %v", err)
	}

	result, err := AutoCommit(repoPath, "Delete README")
	if err != nil {
		t.Fatalf("AutoCommit() unexpected error: %v", err)
	}

	if !result.Committed {
		t.Error("AutoCommit() Committed = false, want true")
	}
}

func TestAutoCommit_LongTaskDescription(t *testing.T) {
	repoPath := createTestRepo(t)

	// Create a new file
	newFile := filepath.Join(repoPath, "newfile.txt")
	err := os.WriteFile(newFile, []byte("content\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	longDesc := "This is a very long task description that exceeds the 50 character limit and should be truncated"
	result, err := AutoCommit(repoPath, longDesc)
	if err != nil {
		t.Fatalf("AutoCommit() unexpected error: %v", err)
	}

	if !result.Committed {
		t.Error("AutoCommit() Committed = false, want true")
	}

	// Check that the message was truncated properly (50 chars from description)
	expectedMsg := "goralph: This is a very long task description that exceeds "
	if result.Message != expectedMsg {
		t.Errorf("AutoCommit() Message = %q, want %q", result.Message, expectedMsg)
	}
}

func TestAutoCommit_InvalidRepoPath(t *testing.T) {
	_, err := AutoCommit("/nonexistent/path", "Test")
	if err == nil {
		t.Error("AutoCommit() expected error for invalid path, got nil")
	}

	if !strings.Contains(err.Error(), "failed to open repository") {
		t.Errorf("AutoCommit() error = %v, want error containing 'failed to open repository'", err)
	}
}

func TestAutoCommit_NotARepo(t *testing.T) {
	tmpDir := t.TempDir()
	// Don't initialize as git repo

	_, err := AutoCommit(tmpDir, "Test")
	if err == nil {
		t.Error("AutoCommit() expected error for non-repo directory, got nil")
	}
}

func TestHasChanges(t *testing.T) {
	repoPath := createTestRepo(t)

	// Initially no changes
	hasChanges, err := HasChanges(repoPath)
	if err != nil {
		t.Fatalf("HasChanges() unexpected error: %v", err)
	}
	if hasChanges {
		t.Error("HasChanges() = true, want false (clean repo)")
	}

	// Create a new file
	newFile := filepath.Join(repoPath, "newfile.txt")
	err = os.WriteFile(newFile, []byte("content\n"), 0644)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Now should have changes
	hasChanges, err = HasChanges(repoPath)
	if err != nil {
		t.Fatalf("HasChanges() unexpected error: %v", err)
	}
	if !hasChanges {
		t.Error("HasChanges() = false, want true (new file)")
	}
}

func TestHasChanges_InvalidPath(t *testing.T) {
	_, err := HasChanges("/nonexistent/path")
	if err == nil {
		t.Error("HasChanges() expected error for invalid path, got nil")
	}
}
