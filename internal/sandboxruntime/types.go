package sandboxruntime

import (
	"context"
	"io"
)

const DriverSSHMachine = "ssh_machine"

// Driver is the complete sandbox runtime boundary used by orchestration code.
type Driver interface {
	ID() string
	LifecycleDriver
	ExecDriver
	FileTransport
}

// LifecycleDriver manages sandbox target lifecycle operations.
type LifecycleDriver interface {
	Create(context.Context, CreateRequest) (*Target, error)
	Start(context.Context, LifecycleRequest) (*Target, error)
	Stop(context.Context, LifecycleRequest) (*Target, error)
	Delete(context.Context, LifecycleRequest) error
	Inspect(context.Context, InspectRequest) (*Target, error)
}

// ExecDriver runs commands inside a sandbox target with streaming I/O.
type ExecDriver interface {
	Exec(context.Context, ExecRequest) (*ExecResult, error)
}

// FileTransport copies files between the host and sandbox target.
type FileTransport interface {
	CopyIn(context.Context, CopyRequest) error
	CopyOut(context.Context, CopyRequest) error
}

// Target describes a resolved runtime target without exposing legacy provider
// types or command-layer durable records.
type Target struct {
	ID         string
	Name       string
	Provider   string
	Status     string
	Runtime    RuntimeState
	Connection ConnectionInfo
}

// RuntimeState captures runtime-driver metadata for a target.
type RuntimeState struct {
	Driver         string
	RuntimeID      string
	Image          string
	WorkerID       string
	IsolationLevel string
}

// ConnectionInfo captures command-agnostic connection metadata for a target.
type ConnectionInfo struct {
	Address           string
	PublicIP          string
	TailscaleIP       string
	TailscaleHostname string
	TailscaleLockdown bool
	WorkspaceID       string
}

// CreateRequest describes a target provisioning request.
type CreateRequest struct {
	Name   string
	Env    map[string]string
	Stdout io.Writer
	Stderr io.Writer
}

// LifecycleRequest describes an operation on an existing target.
type LifecycleRequest struct {
	Target Target
	Stdout io.Writer
	Stderr io.Writer
}

// InspectRequest describes a target inspection request.
type InspectRequest struct {
	Target Target
}

// ExecRequest describes a command that should run inside a target.
type ExecRequest struct {
	Target  Target
	Args    []string
	Stdout  io.Writer
	Stderr  io.Writer
	Stdin   io.Reader
	Env     map[string]string
	WorkDir string
}

// ExecResult describes a completed command execution.
type ExecResult struct {
	ExitCode int
}

// CopyRequest describes one file transfer direction for a target.
type CopyRequest struct {
	Target          Target
	SourcePath      string
	DestinationPath string
}
