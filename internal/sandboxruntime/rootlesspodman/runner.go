package rootlesspodman

import (
	"context"
	"io"
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

// CommandRequest is the command boundary passed to fakeable Podman runners.
// Args is the complete argv, including the executable.
type CommandRequest struct {
	Operation string
	Args      []string
	Env       map[string]string
	WorkDir   string
	Stdin     io.Reader
	Stdout    io.Writer
	Stderr    io.Writer
}

type CommandResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

type LifecycleCommandRunner interface {
	RunLifecycleCommand(context.Context, CommandRequest) (CommandResult, error)
}

type ExecCommandRunner interface {
	RunExecCommand(context.Context, CommandRequest) (CommandResult, error)
}

type CopyCommandRunner interface {
	RunCopyCommand(context.Context, CommandRequest) (CommandResult, error)
}
