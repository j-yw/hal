package git

import (
	"errors"
	"fmt"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"time"
)

// ErrNoChanges is returned when there are no changes to commit.
var ErrNoChanges = errors.New("no changes to commit")

// maxMessageLen is the maximum length for the task description in commit messages.
const maxMessageLen = 50

// CommitResult represents the outcome of a commit operation.
type CommitResult struct {
	Committed bool   // Whether a commit was made
	Hash      string // The commit hash (if committed)
	Message   string // The commit message (if committed)
}

// AutoCommit stages all changes and commits them with a formatted message.
// The commit message format is: "goralph: <task description truncated to 50 chars>"
// Returns ErrNoChanges if there are no changes to commit.
func AutoCommit(repoPath, taskDescription string) (*CommitResult, error) {
	// Open the repository
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open repository: %w", err)
	}

	// Get the worktree
	worktree, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("failed to get worktree: %w", err)
	}

	// Stage all changes (equivalent to git add -A)
	err = worktree.AddWithOptions(&git.AddOptions{All: true})
	if err != nil {
		return nil, fmt.Errorf("failed to stage changes: %w", err)
	}

	// Check if there are any staged changes
	status, err := worktree.Status()
	if err != nil {
		return nil, fmt.Errorf("failed to get status: %w", err)
	}

	if status.IsClean() {
		return &CommitResult{Committed: false}, nil
	}

	// Check if there are actually staged changes (not just untracked files that weren't staged)
	hasStagedChanges := false
	for _, s := range status {
		if s.Staging != git.Unmodified && s.Staging != git.Untracked {
			hasStagedChanges = true
			break
		}
	}

	if !hasStagedChanges {
		return &CommitResult{Committed: false}, nil
	}

	// Build commit message
	message := formatCommitMessage(taskDescription)

	// Create the commit
	hash, err := worktree.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "GoRalph",
			Email: "goralph@jywlabs.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to commit: %w", err)
	}

	return &CommitResult{
		Committed: true,
		Hash:      hash.String(),
		Message:   message,
	}, nil
}

// formatCommitMessage creates a commit message with the format:
// "goralph: <task description truncated to 50 chars>"
func formatCommitMessage(taskDescription string) string {
	desc := taskDescription
	if len(desc) > maxMessageLen {
		desc = desc[:maxMessageLen]
	}
	return fmt.Sprintf("goralph: %s", desc)
}

// HasChanges checks if the repository has any uncommitted changes.
func HasChanges(repoPath string) (bool, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return false, fmt.Errorf("failed to open repository: %w", err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return false, fmt.Errorf("failed to get worktree: %w", err)
	}

	status, err := worktree.Status()
	if err != nil {
		return false, fmt.Errorf("failed to get status: %w", err)
	}

	return !status.IsClean(), nil
}
