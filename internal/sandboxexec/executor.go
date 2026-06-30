package sandboxexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// CommandRequest describes a command that should run inside a sandbox.
type CommandRequest struct {
	Purpose     string
	ProjectDir  string
	SandboxName string
	Command     []string
	WorkDir     string
	Env         map[string]string
	Security    sandbox.SecurityEvaluationRequest
	Stdout      io.Writer
	Stderr      io.Writer
}

// TargetRequest carries command context into injected target resolution.
type TargetRequest struct {
	Purpose     string
	ProjectDir  string
	SandboxName string
	Stdout      io.Writer
	Stderr      io.Writer
}

// PrepareContext carries resolved sandbox dependencies into preparation hooks.
type PrepareContext struct {
	Purpose    string
	ProjectDir string
	Target     sandboxruntime.Target
	Connection sandboxruntime.ConnectionInfo
}

// RunContext carries resolved sandbox dependencies into the command runner.
type RunContext struct {
	Target     sandboxruntime.Target
	Connection sandboxruntime.ConnectionInfo
	Driver     sandboxruntime.Driver
}

// Dependencies contains the side-effect boundaries used by Run.
type Dependencies struct {
	ResolveTarget    func(context.Context, TargetRequest) (*sandbox.SandboxState, error)
	StartTarget      func(context.Context, *sandbox.SandboxState, io.Writer, io.Writer) (*sandbox.SandboxState, error)
	ResolveDriver    func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error)
	PrepareWorkspace func(context.Context, PrepareContext, *CommandRequest) error
	PrepareAuth      func(context.Context, PrepareContext, *CommandRequest) error
	PrepareCommand   func(context.Context, PrepareContext, *CommandRequest) error
	RunCommand       func(context.Context, RunContext, CommandRequest) error
	HandleEvent      func(context.Context, Event) error
	OnTargetReady    func(context.Context, *sandbox.SandboxState) error
	OnDriverReady    func(context.Context, sandboxruntime.Target, sandboxruntime.Driver) error
}

// Result describes the resolved sandbox and command after successful execution.
type Result struct {
	Target  sandboxruntime.Target
	Command CommandRequest
}

// Phase identifies the executor phase that produced an error.
type Phase string

const (
	PhaseResolveTarget    Phase = "resolve_target"
	PhaseProvisionTarget  Phase = "provision"
	PhaseStartTarget      Phase = "start"
	PhaseResolveDriver    Phase = "resolve_driver"
	PhasePrepareWorkspace Phase = "prepare_workspace"
	PhasePrepareAuth      Phase = "prepare_auth"
	PhasePrepareCommand   Phase = "prepare_command"
	PhaseRun              Phase = "run"
)

// PhaseError wraps errors from injected phases while preserving the target and
// provider resolved at the time of failure.
type PhaseError struct {
	Phase    Phase
	Target   *sandbox.SandboxState
	Provider sandbox.Provider
	Err      error
}

func (e *PhaseError) Error() string {
	if e == nil || e.Err == nil {
		return ""
	}
	return e.Err.Error()
}

func (e *PhaseError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// AsPhaseError extracts a sandbox execution phase error from err.
func AsPhaseError(err error) (*PhaseError, bool) {
	var phaseErr *PhaseError
	if errors.As(err, &phaseErr) {
		return phaseErr, true
	}
	return nil, false
}

// EventType identifies command lifecycle events emitted by Run.
type EventType string

const (
	EventCommandStarted   EventType = "command_started"
	EventCommandOutput    EventType = "command_output"
	EventCommandCompleted EventType = "command_completed"
	EventCommandFailed    EventType = "command_failed"
)

const (
	StreamStdout = "stdout"
	StreamStderr = "stderr"
)

// Event is a generic sandbox command lifecycle event. It intentionally avoids
// command-specific durable schemas.
type Event struct {
	Type        EventType
	Phase       Phase
	Purpose     string
	SandboxName string
	Provider    string
	Target      *sandbox.SandboxState
	Command     []string
	WorkDir     string
	Stream      string
	Line        string
	Err         error
}

// Run resolves a sandbox target, starts it when needed, invokes preparation
// hooks, and runs the command through injected dependencies.
func Run(ctx context.Context, req CommandRequest, deps Dependencies) (*Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req = cloneCommandRequest(req)
	if req.Stdout == nil {
		req.Stdout = io.Discard
	}
	if req.Stderr == nil {
		req.Stderr = req.Stdout
	}

	if deps.ResolveTarget == nil {
		return nil, phaseError(PhaseResolveTarget, nil, nil, fmt.Errorf("sandbox target resolver is required"))
	}
	if deps.ResolveDriver == nil {
		return nil, phaseError(PhaseResolveDriver, nil, nil, fmt.Errorf("sandbox runtime driver resolver is required"))
	}
	if deps.RunCommand == nil {
		return nil, phaseError(PhaseRun, nil, nil, fmt.Errorf("sandbox command runner is required"))
	}

	target, err := deps.ResolveTarget(ctx, TargetRequest{
		Purpose:     req.Purpose,
		ProjectDir:  req.ProjectDir,
		SandboxName: req.SandboxName,
		Stdout:      req.Stdout,
		Stderr:      req.Stderr,
	})
	if err != nil {
		return nil, phaseError(PhaseResolveTarget, nil, nil, err)
	}
	if target == nil {
		return nil, phaseError(PhaseResolveTarget, nil, nil, fmt.Errorf("sandbox target is required"))
	}

	if strings.TrimSpace(target.Status) != sandbox.StatusRunning {
		if deps.StartTarget == nil {
			return nil, phaseError(PhaseStartTarget, target, nil, fmt.Errorf("sandbox target starter is required"))
		}
		started, err := deps.StartTarget(ctx, target, req.Stdout, req.Stderr)
		if err != nil {
			return nil, phaseError(PhaseStartTarget, target, nil, err)
		}
		if started == nil {
			return nil, phaseError(PhaseStartTarget, target, nil, fmt.Errorf("started sandbox target is required"))
		}
		target = started
	}
	applySandboxSecurityMetadata(target, req)
	if deps.OnTargetReady != nil {
		if err := deps.OnTargetReady(ctx, target); err != nil {
			return nil, err
		}
	}

	runtimeTarget := runtimeTargetFromSandboxState(target)
	driver, err := deps.ResolveDriver(ctx, runtimeTarget)
	if err != nil {
		return nil, phaseError(PhaseResolveDriver, target, nil, err)
	}
	if driver == nil {
		return nil, phaseError(PhaseResolveDriver, target, nil, fmt.Errorf("sandbox runtime driver is required"))
	}
	if deps.OnDriverReady != nil {
		if err := deps.OnDriverReady(ctx, runtimeTarget, driver); err != nil {
			return nil, err
		}
	}

	prep := PrepareContext{
		Purpose:    req.Purpose,
		ProjectDir: req.ProjectDir,
		Target:     runtimeTarget,
	}
	prep.Connection = prep.Target.Connection
	if deps.PrepareWorkspace != nil {
		if err := deps.PrepareWorkspace(ctx, prep, &req); err != nil {
			return nil, phaseError(PhasePrepareWorkspace, target, nil, err)
		}
	}
	if deps.PrepareAuth != nil {
		if err := deps.PrepareAuth(ctx, prep, &req); err != nil {
			return nil, phaseError(PhasePrepareAuth, target, nil, err)
		}
	}
	if deps.PrepareCommand != nil {
		if err := deps.PrepareCommand(ctx, prep, &req); err != nil {
			return nil, phaseError(PhasePrepareCommand, target, nil, err)
		}
	}

	baseEvent := Event{
		Purpose:     req.Purpose,
		SandboxName: target.Name,
		Provider:    target.Provider,
		Target:      target,
		Command:     append([]string(nil), req.Command...),
		WorkDir:     req.WorkDir,
	}
	if err := emit(ctx, deps.HandleEvent, withEvent(baseEvent, EventCommandStarted, PhaseRun, nil)); err != nil {
		return nil, err
	}

	stdout := newOutputWriter(req.Stdout, StreamStdout, ctx, deps.HandleEvent, baseEvent)
	stderr := newOutputWriter(req.Stderr, StreamStderr, ctx, deps.HandleEvent, baseEvent)
	runReq := cloneCommandRequest(req)
	runReq.Stdout = stdout
	runReq.Stderr = stderr
	runErr := deps.RunCommand(ctx, RunContext{
		Target:     runtimeTarget,
		Connection: runtimeTarget.Connection,
		Driver:     driver,
	}, runReq)
	flushErr := errors.Join(stdout.Flush(), stderr.Flush())
	if runErr != nil {
		if flushErr != nil {
			runErr = errors.Join(runErr, flushErr)
		}
		_ = emit(ctx, deps.HandleEvent, withEvent(baseEvent, EventCommandFailed, PhaseRun, runErr))
		return nil, phaseError(PhaseRun, target, nil, runErr)
	}
	if flushErr != nil {
		_ = emit(ctx, deps.HandleEvent, withEvent(baseEvent, EventCommandFailed, PhaseRun, flushErr))
		return nil, phaseError(PhaseRun, target, nil, flushErr)
	}
	if err := emit(ctx, deps.HandleEvent, withEvent(baseEvent, EventCommandCompleted, PhaseRun, nil)); err != nil {
		return nil, err
	}

	return &Result{
		Target:  runtimeTarget,
		Command: cloneCommandRequest(req),
	}, nil
}

func phaseError(phase Phase, target *sandbox.SandboxState, provider sandbox.Provider, err error) *PhaseError {
	var existing *PhaseError
	if errors.As(err, &existing) {
		if existing.Target == nil {
			existing.Target = target
		}
		if existing.Provider == nil {
			existing.Provider = provider
		}
		return existing
	}
	return &PhaseError{
		Phase:    phase,
		Target:   target,
		Provider: provider,
		Err:      err,
	}
}

func withEvent(base Event, eventType EventType, phase Phase, err error) Event {
	event := base
	event.Type = eventType
	event.Phase = phase
	event.Err = err
	event.Command = append([]string(nil), base.Command...)
	return event
}

func emit(ctx context.Context, handler func(context.Context, Event) error, event Event) error {
	if handler == nil {
		return nil
	}
	return handler(ctx, event)
}

func cloneCommandRequest(req CommandRequest) CommandRequest {
	req.Command = append([]string(nil), req.Command...)
	if req.Env != nil {
		env := make(map[string]string, len(req.Env))
		for key, value := range req.Env {
			env[key] = value
		}
		req.Env = env
	}
	req.Security.RequestedSecretModes = append([]string(nil), req.Security.RequestedSecretModes...)
	req.Security.ActiveSecretModes = append([]string(nil), req.Security.ActiveSecretModes...)
	return req
}

func applySandboxSecurityMetadata(target *sandbox.SandboxState, req CommandRequest) {
	if target == nil {
		return
	}
	if target.Security != nil && emptySecurityEvaluationRequest(req.Security) && len(req.Env) == 0 {
		return
	}
	securityReq := req.Security
	if strings.TrimSpace(securityReq.RuntimeDriver) == "" {
		securityReq.RuntimeDriver = sandboxRuntimeDriver(target)
	}
	if len(req.Env) > 0 {
		securityReq.ActiveSecretModes = append(securityReq.ActiveSecretModes, sandbox.SandboxSecretModeEnv)
	}
	target.Security = sandbox.EvaluateSandboxSecurity(securityReq)
}

func emptySecurityEvaluationRequest(req sandbox.SecurityEvaluationRequest) bool {
	return strings.TrimSpace(req.RuntimeDriver) == "" &&
		strings.TrimSpace(req.RequestedNetworkPolicy) == "" &&
		len(req.RequestedSecretModes) == 0 &&
		len(req.ActiveSecretModes) == 0 &&
		!req.CompatibilityAuthSync
}

func sandboxRuntimeDriver(target *sandbox.SandboxState) string {
	if target == nil || target.Runtime == nil {
		return sandbox.SandboxRuntimeDriverSSHMachine
	}
	if driver := strings.TrimSpace(target.Runtime.Driver); driver != "" {
		return driver
	}
	return sandbox.SandboxRuntimeDriverSSHMachine
}

func runtimeTargetFromSandboxState(target *sandbox.SandboxState) sandboxruntime.Target {
	if target == nil {
		return sandboxruntime.Target{}
	}
	runtimeTarget := sandboxruntime.Target{
		ID:       target.ID,
		Name:     target.Name,
		Provider: target.Provider,
		Status:   target.Status,
		Runtime: sandboxruntime.RuntimeState{
			Driver: sandboxRuntimeDriver(target),
		},
	}
	if target.Runtime != nil {
		runtimeTarget.Runtime = sandboxruntime.RuntimeState{
			Driver:         sandboxRuntimeDriver(target),
			RuntimeID:      target.Runtime.RuntimeID,
			Image:          target.Runtime.Image,
			WorkerID:       target.Runtime.WorkerID,
			IsolationLevel: target.Runtime.IsolationLevel,
		}
	}
	if info := sandbox.ConnectInfoFromState(target); info != nil {
		runtimeTarget.Connection = sandboxruntime.ConnectionInfo{
			Address:           info.IP,
			PublicIP:          info.PublicIP,
			TailscaleIP:       info.TailscaleIP,
			TailscaleHostname: info.TailscaleHostname,
			TailscaleLockdown: info.TailscaleLockdown,
			WorkspaceID:       info.WorkspaceID,
		}
	}
	return runtimeTarget
}

type outputWriter struct {
	mu      sync.Mutex
	dst     io.Writer
	stream  string
	ctx     context.Context
	handler func(context.Context, Event) error
	base    Event
	pending string
}

func newOutputWriter(dst io.Writer, stream string, ctx context.Context, handler func(context.Context, Event) error, base Event) *outputWriter {
	if dst == nil {
		dst = io.Discard
	}
	return &outputWriter{
		dst:     dst,
		stream:  stream,
		ctx:     ctx,
		handler: handler,
		base:    base,
	}
}

func (w *outputWriter) Write(p []byte) (int, error) {
	if w == nil {
		return len(p), nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	w.pending += string(p)
	if err := w.flushCompleteLinesLocked(); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *outputWriter) Flush() error {
	if w == nil {
		return nil
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	if err := w.flushCompleteLinesLocked(); err != nil {
		return err
	}
	rawLine := w.pending
	w.pending = ""
	if rawLine == "" {
		return nil
	}
	if err := w.writeOutputLocked(rawLine); err != nil {
		return err
	}
	line := strings.TrimSpace(rawLine)
	if line == "" {
		return nil
	}
	return w.emitOutputLocked(line)
}

func (w *outputWriter) flushCompleteLinesLocked() error {
	for {
		idx := strings.IndexByte(w.pending, '\n')
		if idx < 0 {
			return nil
		}
		rawLine := w.pending[:idx+1]
		w.pending = w.pending[idx+1:]
		if err := w.writeOutputLocked(rawLine); err != nil {
			return err
		}
		line := strings.TrimSpace(rawLine)
		if line == "" {
			continue
		}
		if err := w.emitOutputLocked(line); err != nil {
			return err
		}
	}
}

func (w *outputWriter) writeOutputLocked(rawLine string) error {
	if rawLine == "" || w.dst == nil {
		return nil
	}
	_, err := w.dst.Write([]byte(rawLine))
	return err
}

func (w *outputWriter) emitOutputLocked(line string) error {
	if w.handler == nil {
		return nil
	}
	event := withEvent(w.base, EventCommandOutput, PhaseRun, nil)
	event.Stream = w.stream
	event.Line = line
	return w.handler(w.ctx, event)
}
