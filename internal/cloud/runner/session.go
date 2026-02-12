// Package runner defines the sandbox lifecycle interface and types for
// communicating with a Daytona sandbox service.
//
// session.go defines the SessionExec interface — a contract for long-running
// command execution via Daytona sessions. Sessions allow launching commands
// asynchronously, polling their status, streaming logs via WebSocket, and
// surviving worker restarts (the session persists in the sandbox).
//
// This is used instead of the blocking Runner.Exec for hal auto/run commands
// that can take hours. The Daytona SDK's ExecuteCommand has a hardcoded 60s
// HTTP client timeout, making it unsuitable for long-running commands.
package runner

import "context"

// SessionCommandStatus represents the state of a session command.
type SessionCommandStatus struct {
	// CommandID is the unique identifier of the command within the session.
	CommandID string
	// ExitCode is the command's exit status. Nil if still running.
	ExitCode *int
}

// SessionExec defines long-running command execution via Daytona sessions.
// Unlike Runner.Exec (which blocks on a single HTTP call with a 60s timeout),
// session-based execution:
//
//  1. Creates a named session in the sandbox
//  2. Launches the command asynchronously (returns immediately)
//  3. Polls command status independently (no HTTP timeout concern)
//  4. Streams logs via WebSocket in real-time
//  5. Supports reconnection — sessions survive worker restarts
//
// SDKClient implements both Runner and SessionExec. Test mocks can implement
// SessionExec independently.
type SessionExec interface {
	// CreateSession creates a named session in the sandbox.
	// The sessionID should be deterministic (e.g., derived from attempt ID)
	// so we can reconnect after a worker restart.
	CreateSession(ctx context.Context, sandboxID, sessionID string) error

	// ExecAsync launches a command in a session and returns immediately.
	// The returned CommandID can be used to poll status and stream logs.
	ExecAsync(ctx context.Context, sandboxID, sessionID string, req *ExecRequest) (*SessionCommandStatus, error)

	// GetCommandStatus polls the status of a command in a session.
	// Returns the command's exit code when completed, or nil exit code
	// if still running.
	GetCommandStatus(ctx context.Context, sandboxID, sessionID, commandID string) (*SessionCommandStatus, error)

	// StreamLogs opens a real-time log stream for a session command.
	// stdout and stderr channels receive log chunks as they arrive.
	// Both channels are closed when the stream ends or ctx is cancelled.
	// The caller should provide buffered channels to avoid blocking.
	StreamCommandLogs(ctx context.Context, sandboxID, sessionID, commandID string, stdout, stderr chan<- string) error

	// GetCommandLogs retrieves the full accumulated logs for a session command.
	// Unlike StreamCommandLogs, this is a one-shot fetch (useful for final log
	// capture after command completion).
	GetCommandLogs(ctx context.Context, sandboxID, sessionID, commandID string) (string, error)

	// DeleteSession removes a session and all its resources.
	DeleteSession(ctx context.Context, sandboxID, sessionID string) error
}
