package microvm

import (
	"context"
	"io"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	OperationCreate  = "create"
	OperationStart   = "start"
	OperationInspect = "inspect"
	OperationStop    = "stop"
	OperationDelete  = "delete"
	OperationExec    = "exec"
	OperationCopyIn  = "copy_in"
	OperationCopyOut = "copy_out"
)

// Backend is the injectable microVM backend boundary. It owns backend-specific
// target creation and returns fakeable per-target controllers for other
// operations.
type Backend interface {
	Create(context.Context, BackendCreateRequest) (*sandboxruntime.Target, error)
	Controller(context.Context, ControllerRequest) (Controller, error)
}

// Controller is the per-target microVM operation boundary used after the driver
// has validated capability/config inputs and sanitized target metadata.
type Controller interface {
	Start(context.Context, ControllerLifecycleRequest) (*sandboxruntime.Target, error)
	Stop(context.Context, ControllerLifecycleRequest) (*sandboxruntime.Target, error)
	Delete(context.Context, ControllerLifecycleRequest) error
	Inspect(context.Context, ControllerInspectRequest) (*sandboxruntime.Target, error)
	Exec(context.Context, ControllerExecRequest) (*sandboxruntime.ExecResult, error)
	CopyIn(context.Context, ControllerCopyRequest) error
	CopyOut(context.Context, ControllerCopyRequest) error
}

// BackendCreateRequest carries copied, backend-neutral create inputs.
type BackendCreateRequest struct {
	Operation string
	Config    Config
	Name      string
	Env       map[string]string
	Stdout    io.Writer
	Stderr    io.Writer
}

// ControllerRequest asks a backend for the controller responsible for one
// sanitized target operation.
type ControllerRequest struct {
	Operation string
	Config    Config
	Target    sandboxruntime.Target
}

// ControllerLifecycleRequest carries sanitized lifecycle inputs.
type ControllerLifecycleRequest struct {
	Operation string
	Config    Config
	Target    sandboxruntime.Target
	Stdout    io.Writer
	Stderr    io.Writer
}

// ControllerInspectRequest carries sanitized inspect inputs.
type ControllerInspectRequest struct {
	Operation string
	Config    Config
	Target    sandboxruntime.Target
}

// ControllerExecRequest carries sanitized exec inputs while preserving the
// sandboxruntime.Driver streaming I/O contract.
type ControllerExecRequest struct {
	Operation string
	Config    Config
	Target    sandboxruntime.Target
	Args      []string
	Stdout    io.Writer
	Stderr    io.Writer
	Stdin     io.Reader
	Env       map[string]string
	WorkDir   string
}

// ControllerCopyRequest carries sanitized file transfer inputs.
type ControllerCopyRequest struct {
	Operation       string
	Config          Config
	Target          sandboxruntime.Target
	SourcePath      string
	DestinationPath string
}
