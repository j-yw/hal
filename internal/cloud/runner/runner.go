// Package runner defines the sandbox lifecycle interface and an HTTP client
// implementation that communicates with a Daytona runner service.
package runner

import (
	"context"
	"io"
	"time"
)

// CreateSandboxRequest contains the parameters for creating a new sandbox.
type CreateSandboxRequest struct {
	// Image is the container image or Daytona template to use.
	Image string `json:"image"`
	// Repo is the repository URL to clone into the sandbox.
	Repo string `json:"repo,omitempty"`
	// Branch is the branch to checkout after cloning.
	Branch string `json:"branch,omitempty"`
	// EnvVars are environment variables to set in the sandbox.
	EnvVars map[string]string `json:"env_vars,omitempty"`
}

// Sandbox represents a created sandbox instance.
type Sandbox struct {
	// ID is the unique identifier of the sandbox.
	ID string `json:"id"`
	// Status is the current sandbox status (e.g., "running", "stopped").
	Status string `json:"status"`
	// CreatedAt is the sandbox creation timestamp.
	CreatedAt time.Time `json:"created_at"`
}

// ExecRequest contains the parameters for executing a command in a sandbox.
type ExecRequest struct {
	// Command is the shell command to execute.
	Command string `json:"command"`
	// WorkDir is the working directory for command execution.
	WorkDir string `json:"work_dir,omitempty"`
	// Timeout is the maximum duration for the command. Zero means no timeout.
	Timeout time.Duration `json:"timeout,omitempty"`
}

// ExecResult contains the result of a command execution.
type ExecResult struct {
	// ExitCode is the command's exit status.
	ExitCode int `json:"exit_code"`
	// Stdout is the captured standard output.
	Stdout string `json:"stdout"`
	// Stderr is the captured standard error.
	Stderr string `json:"stderr"`
}

// HealthStatus contains the runner service health information.
type HealthStatus struct {
	// OK indicates whether the runner service is healthy.
	OK bool `json:"ok"`
	// Version is the runner service version string.
	Version string `json:"version,omitempty"`
}

// Runner defines the sandbox lifecycle interface. Worker sandbox lifecycle
// code depends only on this interface and imports no Daytona SDK packages.
type Runner interface {
	// CreateSandbox provisions a new Daytona sandbox and returns its metadata.
	CreateSandbox(ctx context.Context, req *CreateSandboxRequest) (*Sandbox, error)

	// Exec executes a command inside an existing sandbox and returns the result.
	Exec(ctx context.Context, sandboxID string, req *ExecRequest) (*ExecResult, error)

	// StreamLogs opens a streaming reader for sandbox logs. The caller must
	// close the returned ReadCloser when done.
	StreamLogs(ctx context.Context, sandboxID string) (io.ReadCloser, error)

	// DestroySandbox tears down an existing sandbox by ID.
	DestroySandbox(ctx context.Context, sandboxID string) error

	// Health checks whether the runner service is reachable and healthy.
	Health(ctx context.Context) (*HealthStatus, error)
}
