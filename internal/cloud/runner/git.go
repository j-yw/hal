// Package runner defines the sandbox lifecycle interface and types for
// communicating with a Daytona sandbox service.
//
// git.go defines the GitOps interface — a focused contract for Git operations
// inside a sandbox. It is implemented by SDKClient using Daytona's native Git
// API and can be independently mocked for service-layer tests.
package runner

import "context"

// GitCloneRequest contains the parameters for cloning a repository.
type GitCloneRequest struct {
	// URL is the repository URL (HTTPS or SSH).
	URL string
	// Path is the destination directory inside the sandbox.
	Path string
	// Branch is the branch to clone. Empty means the default branch.
	Branch string
	// Username is the HTTPS auth username (optional).
	Username string
	// Password is the HTTPS auth password or token (optional).
	Password string
}

// GitCommitRequest contains the parameters for creating a commit.
type GitCommitRequest struct {
	// Path is the repository directory inside the sandbox.
	Path string
	// Message is the commit message.
	Message string
	// Author is the author name for the commit.
	Author string
	// Email is the author email for the commit.
	Email string
	// AllowEmpty allows creating a commit with no staged changes.
	AllowEmpty bool
}

// GitCommitResult holds the outcome of a commit operation.
type GitCommitResult struct {
	// SHA is the commit hash.
	SHA string
}

// GitPushRequest contains the parameters for pushing to a remote.
type GitPushRequest struct {
	// Path is the repository directory inside the sandbox.
	Path string
	// Username is the HTTPS auth username (optional).
	Username string
	// Password is the HTTPS auth password or token (optional).
	Password string
}

// GitOps defines Git operations inside a sandbox. Services that need
// structured Git access (clone, commit, push) depend on this interface
// rather than shelling out via Runner.Exec.
//
// SDKClient implements both Runner and GitOps. Test mocks can implement
// GitOps independently without touching the Runner interface.
type GitOps interface {
	// GitClone clones a repository into the sandbox.
	GitClone(ctx context.Context, sandboxID string, req *GitCloneRequest) error

	// GitAdd stages files for the next commit. Use []string{"."} to stage all.
	GitAdd(ctx context.Context, sandboxID, path string, files []string) error

	// GitCommit creates a commit with the staged changes.
	GitCommit(ctx context.Context, sandboxID string, req *GitCommitRequest) (*GitCommitResult, error)

	// GitPush pushes local commits to the remote.
	GitPush(ctx context.Context, sandboxID string, req *GitPushRequest) error

	// GitCreateBranch creates a new branch at the current HEAD.
	GitCreateBranch(ctx context.Context, sandboxID, path, branch string) error

	// GitCheckout switches to a branch.
	GitCheckout(ctx context.Context, sandboxID, path, branch string) error

	// GitListBranches returns the branch names in the repository.
	GitListBranches(ctx context.Context, sandboxID, path string) ([]string, error)
}
