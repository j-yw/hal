package sandboxexec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
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
	Stdin       io.Reader
	Security    sandbox.SecurityEvaluationRequest
	Stdout      io.Writer
	Stderr      io.Writer
	SetupStdout io.Writer
	SetupStderr io.Writer
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
	Driver     sandboxruntime.Driver
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
	ResolveDriver    func(context.Context, sandboxruntime.Target) (sandboxruntime.Driver, error)
	PrepareWorkspace func(context.Context, PrepareContext, *CommandRequest) error
	PrepareAuth      func(context.Context, PrepareContext, *CommandRequest) error
	PrepareCommand   func(context.Context, PrepareContext, *CommandRequest) error
	// RunCommand overrides the default runtime driver Exec path for command-specific compatibility behavior.
	RunCommand    func(context.Context, RunContext, CommandRequest) error
	HandleEvent   func(context.Context, Event) error
	OnTargetReady func(context.Context, *sandbox.SandboxState) error
	OnDriverReady func(context.Context, sandboxruntime.Target, sandboxruntime.Driver) error
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

// PhaseError wraps errors from injected phases while preserving runtime
// boundary context resolved at the time of failure.
type PhaseError struct {
	Phase         Phase
	Target        *sandbox.SandboxState
	RuntimeDriver string
	Err           error
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
	if req.SetupStdout == nil {
		req.SetupStdout = req.Stdout
	}
	if req.SetupStderr == nil {
		req.SetupStderr = req.Stderr
	}

	if deps.ResolveTarget == nil {
		return nil, phaseError(PhaseResolveTarget, nil, "", fmt.Errorf("sandbox target resolver is required"))
	}
	if deps.ResolveDriver == nil {
		return nil, phaseError(PhaseResolveDriver, nil, "", fmt.Errorf("sandbox runtime driver resolver is required"))
	}
	target, err := deps.ResolveTarget(ctx, TargetRequest{
		Purpose:     req.Purpose,
		ProjectDir:  req.ProjectDir,
		SandboxName: req.SandboxName,
		Stdout:      req.Stdout,
		Stderr:      req.Stderr,
	})
	if err != nil {
		return nil, phaseError(PhaseResolveTarget, target, "", err)
	}
	if target == nil {
		return nil, phaseError(PhaseResolveTarget, nil, "", fmt.Errorf("sandbox target is required"))
	}

	targetRunning := strings.TrimSpace(target.Status) == sandbox.StatusRunning
	if targetRunning {
		applySandboxSecurityMetadata(target, req)
		if deps.OnTargetReady != nil {
			if err := deps.OnTargetReady(ctx, target); err != nil {
				return nil, err
			}
		}
	}

	runtimeTarget := runtimeTargetFromSandboxState(target)
	trustedTemplateLock := runtimeTemplateLockFromTarget(runtimeTarget)
	driver, err := deps.ResolveDriver(ctx, runtimeTarget)
	if err != nil {
		return nil, phaseError(PhaseResolveDriver, target, "", err)
	}
	if driver == nil {
		return nil, phaseError(PhaseResolveDriver, target, "", fmt.Errorf("sandbox runtime driver is required"))
	}

	createdInRun := false
	if !targetRunning && workerTargetNeedsCreate(target, runtimeTarget) {
		created, err := driver.Create(ctx, sandboxruntime.CreateRequest{
			Name:   runtimeTarget.Name,
			Stdout: req.SetupStdout,
			Stderr: req.SetupStderr,
		})
		if err != nil {
			if created != nil {
				runtimeTarget = mergeRuntimeTarget(runtimeTarget, *created)
				var correlationErr error
				runtimeTarget, correlationErr = correlateRuntimeTargetTemplateLock(runtimeTarget, trustedTemplateLock)
				target = applyRuntimeTargetToSandboxState(target, runtimeTarget, trustedTemplateLock)
				err = errors.Join(err, correlationErr)
			}
			return nil, phaseError(PhaseProvisionTarget, target, runtimeDriverID(driver), err)
		}
		if created == nil {
			return nil, phaseError(PhaseProvisionTarget, target, runtimeDriverID(driver), fmt.Errorf("created sandbox target is required"))
		}
		runtimeTarget = mergeRuntimeTarget(runtimeTarget, *created)
		runtimeTarget, err = correlateRuntimeTargetTemplateLock(runtimeTarget, trustedTemplateLock)
		target = applyRuntimeTargetToSandboxState(target, runtimeTarget, trustedTemplateLock)
		if err != nil {
			if cleanupErr := driver.Delete(ctx, sandboxruntime.LifecycleRequest{
				Target: runtimeTarget,
				Stdout: req.SetupStdout,
				Stderr: req.SetupStderr,
			}); cleanupErr != nil {
				err = errors.Join(err, fmt.Errorf("delete newly created sandbox target after provision failure: %w", cleanupErr))
			}
			return nil, phaseError(PhaseProvisionTarget, target, runtimeDriverID(driver), err)
		}
		targetRunning = strings.TrimSpace(runtimeTarget.Status) == sandbox.StatusRunning
		createdInRun = true
	}

	if !targetRunning {
		started, startErr := driver.Start(ctx, sandboxruntime.LifecycleRequest{
			Target: runtimeTarget,
			Stdout: req.SetupStdout,
			Stderr: req.SetupStderr,
		})
		if startErr == nil && started == nil {
			startErr = fmt.Errorf("started sandbox target is required")
		}
		if startErr != nil {
			if started != nil {
				runtimeTarget = mergeRuntimeTarget(runtimeTarget, *started)
				var correlationErr error
				runtimeTarget, correlationErr = correlateRuntimeTargetTemplateLock(runtimeTarget, trustedTemplateLock)
				target = applyRuntimeTargetToSandboxState(target, runtimeTarget, trustedTemplateLock)
				startErr = errors.Join(startErr, correlationErr)
			}
			if createdInRun {
				if cleanupErr := driver.Delete(ctx, sandboxruntime.LifecycleRequest{
					Target: runtimeTarget,
					Stdout: req.SetupStdout,
					Stderr: req.SetupStderr,
				}); cleanupErr != nil {
					startErr = errors.Join(startErr, fmt.Errorf("delete newly created sandbox target after start failure: %w", cleanupErr))
				}
			}
			return nil, phaseError(PhaseStartTarget, target, runtimeDriverID(driver), startErr)
		}
		runtimeTarget, err = correlateRuntimeTargetTemplateLock(*started, trustedTemplateLock)
		target = applyRuntimeTargetToSandboxState(target, runtimeTarget, trustedTemplateLock)
		if err != nil {
			if createdInRun {
				if cleanupErr := driver.Delete(ctx, sandboxruntime.LifecycleRequest{
					Target: runtimeTarget,
					Stdout: req.SetupStdout,
					Stderr: req.SetupStderr,
				}); cleanupErr != nil {
					err = errors.Join(err, fmt.Errorf("delete newly created sandbox target after start failure: %w", cleanupErr))
				}
			}
			return nil, phaseError(PhaseStartTarget, target, runtimeDriverID(driver), err)
		}
		applySandboxSecurityMetadata(target, req)
		if deps.OnTargetReady != nil {
			if err := deps.OnTargetReady(ctx, target); err != nil {
				return nil, err
			}
		}
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
		Driver:     driver,
	}
	prep.Connection = prep.Target.Connection
	if deps.PrepareWorkspace != nil {
		if err := deps.PrepareWorkspace(ctx, prep, &req); err != nil {
			return nil, phaseError(PhasePrepareWorkspace, target, runtimeDriverID(driver), err)
		}
	}
	if deps.PrepareAuth != nil {
		if err := deps.PrepareAuth(ctx, prep, &req); err != nil {
			return nil, phaseError(PhasePrepareAuth, target, runtimeDriverID(driver), err)
		}
	}
	if deps.PrepareCommand != nil {
		if err := deps.PrepareCommand(ctx, prep, &req); err != nil {
			return nil, phaseError(PhasePrepareCommand, target, runtimeDriverID(driver), err)
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
	runCommand := deps.RunCommand
	if runCommand == nil {
		runCommand = runRuntimeCommand
	}
	runErr := runCommand(ctx, RunContext{
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
		return nil, phaseError(PhaseRun, target, runtimeDriverID(driver), runErr)
	}
	if flushErr != nil {
		_ = emit(ctx, deps.HandleEvent, withEvent(baseEvent, EventCommandFailed, PhaseRun, flushErr))
		return nil, phaseError(PhaseRun, target, runtimeDriverID(driver), flushErr)
	}
	if err := emit(ctx, deps.HandleEvent, withEvent(baseEvent, EventCommandCompleted, PhaseRun, nil)); err != nil {
		return nil, err
	}

	return &Result{
		Target:  runtimeTarget,
		Command: cloneCommandRequest(req),
	}, nil
}

func workerTargetNeedsCreate(state *sandbox.SandboxState, target sandboxruntime.Target) bool {
	if strings.TrimSpace(target.Runtime.RuntimeID) != "" {
		return false
	}
	return state != nil && state.Host != nil && strings.TrimSpace(state.Host.Kind) == sandbox.SandboxHostKindWorker
}

func mergeRuntimeTarget(selected, resolved sandboxruntime.Target) sandboxruntime.Target {
	if strings.TrimSpace(resolved.ID) == "" {
		resolved.ID = selected.ID
	}
	if strings.TrimSpace(resolved.Name) == "" {
		resolved.Name = selected.Name
	}
	if strings.TrimSpace(resolved.Provider) == "" {
		resolved.Provider = selected.Provider
	}
	if strings.TrimSpace(resolved.Status) == "" {
		resolved.Status = selected.Status
	}
	if strings.TrimSpace(resolved.Runtime.Driver) == "" {
		resolved.Runtime.Driver = selected.Runtime.Driver
	}
	if strings.TrimSpace(resolved.Runtime.RuntimeID) == "" {
		resolved.Runtime.RuntimeID = selected.Runtime.RuntimeID
	}
	if strings.TrimSpace(resolved.Runtime.Image) == "" {
		resolved.Runtime.Image = selected.Runtime.Image
	}
	if strings.TrimSpace(resolved.Runtime.WorkerID) == "" {
		resolved.Runtime.WorkerID = selected.Runtime.WorkerID
	}
	if strings.TrimSpace(resolved.Runtime.IsolationLevel) == "" {
		resolved.Runtime.IsolationLevel = selected.Runtime.IsolationLevel
	}
	if resolved.Runtime.Metadata == nil {
		resolved.Runtime.Metadata = selected.Runtime.Metadata
	}
	if strings.TrimSpace(resolved.Connection.Address) == "" {
		resolved.Connection.Address = selected.Connection.Address
	}
	if strings.TrimSpace(resolved.Connection.PublicIP) == "" {
		resolved.Connection.PublicIP = selected.Connection.PublicIP
	}
	if strings.TrimSpace(resolved.Connection.TailscaleIP) == "" {
		resolved.Connection.TailscaleIP = selected.Connection.TailscaleIP
	}
	if strings.TrimSpace(resolved.Connection.TailscaleHostname) == "" {
		resolved.Connection.TailscaleHostname = selected.Connection.TailscaleHostname
	}
	if strings.TrimSpace(resolved.Connection.WorkspaceID) == "" {
		resolved.Connection.WorkspaceID = selected.Connection.WorkspaceID
	}
	if !resolved.Connection.TailscaleLockdown {
		resolved.Connection.TailscaleLockdown = selected.Connection.TailscaleLockdown
	}
	return resolved
}

func runRuntimeCommand(ctx context.Context, run RunContext, req CommandRequest) error {
	if run.Driver == nil {
		return fmt.Errorf("sandbox runtime driver is required")
	}
	_, err := run.Driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target:  run.Target,
		Args:    append([]string(nil), req.Command...),
		Stdout:  req.Stdout,
		Stderr:  req.Stderr,
		Stdin:   req.Stdin,
		Env:     cloneStringMap(req.Env),
		WorkDir: req.WorkDir,
	})
	return err
}

func phaseError(phase Phase, target *sandbox.SandboxState, runtimeDriver string, err error) *PhaseError {
	var existing *PhaseError
	if errors.As(err, &existing) {
		if existing.Target == nil {
			existing.Target = target
		}
		if strings.TrimSpace(existing.RuntimeDriver) == "" {
			driver := phaseRuntimeDriver(target, runtimeDriver)
			if driver == "" && existing.Target != nil {
				driver = phaseRuntimeDriver(existing.Target, "")
			}
			existing.RuntimeDriver = driver
		}
		return existing
	}
	return &PhaseError{
		Phase:         phase,
		Target:        target,
		RuntimeDriver: phaseRuntimeDriver(target, runtimeDriver),
		Err:           err,
	}
}

func phaseRuntimeDriver(target *sandbox.SandboxState, runtimeDriver string) string {
	if driver := strings.TrimSpace(runtimeDriver); driver != "" {
		return driver
	}
	if target == nil {
		return ""
	}
	return strings.TrimSpace(sandboxRuntimeDriver(target))
}

func runtimeDriverID(driver sandboxruntime.Driver) string {
	if driver == nil {
		return ""
	}
	return strings.TrimSpace(driver.ID())
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
	req.Env = cloneStringMap(req.Env)
	req.Security.RequestedSecretModes = append([]string(nil), req.Security.RequestedSecretModes...)
	req.Security.ActiveSecretModes = append([]string(nil), req.Security.ActiveSecretModes...)
	return req
}

func cloneStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

func applySandboxSecurityMetadata(target *sandbox.SandboxState, req CommandRequest) {
	if target == nil {
		return
	}
	if security := workerBackedHostSecurity(target); security != nil {
		target.Security = cloneSandboxSecurity(security)
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

func workerBackedHostSecurity(target *sandbox.SandboxState) *sandbox.SandboxSecurity {
	if target == nil || target.Host == nil || target.Runtime == nil {
		return nil
	}
	if strings.TrimSpace(target.Host.Kind) != sandbox.SandboxHostKindWorker {
		return nil
	}
	if strings.TrimSpace(target.Runtime.Driver) != sandbox.SandboxRuntimeDriverRootlessPodman {
		return nil
	}
	return target.Host.Security
}

func cloneSandboxSecurity(security *sandbox.SandboxSecurity) *sandbox.SandboxSecurity {
	if security == nil {
		return nil
	}
	capabilityReadiness := sandbox.CloneSandboxSecurityCapabilityReadinessOutputPtr(security.CapabilityReadiness)
	clone := &sandbox.SandboxSecurity{
		CapabilityReadiness:            capabilityReadiness,
		CapabilityReadinessDiagnostics: sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummaryPtr(capabilityReadiness),
	}
	if security.Network != nil {
		network := *security.Network
		network.PolicyResult = sandbox.CloneSandboxNetworkPolicyResultPtr(security.Network.PolicyResult)
		clone.Network = &network
	}
	if security.Secrets != nil {
		secrets := *security.Secrets
		secrets.RequestedModes = append([]string(nil), security.Secrets.RequestedModes...)
		secrets.ActiveModes = append([]string(nil), security.Secrets.ActiveModes...)
		clone.Secrets = &secrets
	}
	return clone
}

func emptySecurityEvaluationRequest(req sandbox.SecurityEvaluationRequest) bool {
	return strings.TrimSpace(req.RuntimeDriver) == "" &&
		strings.TrimSpace(req.RequestedNetworkPolicy) == "" &&
		req.RequestedNetworkPolicyIntent == nil &&
		req.NetworkPolicyCapability == nil &&
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
			Metadata: &sandboxruntime.RuntimeMetadata{
				TemplateLock: runtimeTemplateLockFromSandbox(target.Runtime.TemplateLock),
			},
		}
		if runtimeTarget.Runtime.Metadata.TemplateLock == nil {
			runtimeTarget.Runtime.Metadata = nil
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

func applyRuntimeTargetToSandboxState(
	state *sandbox.SandboxState,
	target sandboxruntime.Target,
	trustedTemplateLock *sandboxruntime.RuntimeTemplateLockMetadata,
) *sandbox.SandboxState {
	if state == nil {
		state = &sandbox.SandboxState{}
	}
	if strings.TrimSpace(target.ID) != "" {
		state.ID = target.ID
	}
	if strings.TrimSpace(target.Name) != "" {
		state.Name = target.Name
	}
	if strings.TrimSpace(target.Provider) != "" {
		state.Provider = target.Provider
	}
	if strings.TrimSpace(target.Status) != "" {
		state.Status = target.Status
	}
	if strings.TrimSpace(target.Connection.WorkspaceID) != "" {
		state.WorkspaceID = target.Connection.WorkspaceID
	}
	if strings.TrimSpace(target.Connection.PublicIP) != "" {
		state.IP = target.Connection.PublicIP
	} else if strings.TrimSpace(target.Connection.Address) != "" {
		state.IP = target.Connection.Address
	}
	if strings.TrimSpace(target.Connection.TailscaleIP) != "" {
		state.TailscaleIP = target.Connection.TailscaleIP
	}
	if strings.TrimSpace(target.Connection.TailscaleHostname) != "" {
		state.TailscaleHostname = target.Connection.TailscaleHostname
	}
	state.TailscaleLockdown = target.Connection.TailscaleLockdown
	if hasRuntimeState(target.Runtime) {
		state.Runtime = &sandbox.SandboxRuntimeState{
			Driver:         target.Runtime.Driver,
			RuntimeID:      target.Runtime.RuntimeID,
			Image:          target.Runtime.Image,
			WorkerID:       target.Runtime.WorkerID,
			IsolationLevel: target.Runtime.IsolationLevel,
			TemplateLock: sandboxTemplateLockFromRuntime(&sandboxruntime.RuntimeMetadata{
				TemplateLock: trustedTemplateLock,
			}),
		}
	}
	return state
}

func runtimeTemplateLockFromTarget(target sandboxruntime.Target) *sandboxruntime.RuntimeTemplateLockMetadata {
	if target.Runtime.Metadata == nil {
		return nil
	}
	return sandboxruntime.SanitizeRuntimeTemplateLockMetadata(target.Runtime.Metadata.TemplateLock)
}

func correlateRuntimeTargetTemplateLock(
	target sandboxruntime.Target,
	trusted *sandboxruntime.RuntimeTemplateLockMetadata,
) (sandboxruntime.Target, error) {
	trusted = sandboxruntime.SanitizeRuntimeTemplateLockMetadata(trusted)
	reported := runtimeTemplateLockFromTarget(target)
	reportedPresent := target.Runtime.Metadata != nil && target.Runtime.Metadata.TemplateLock != nil
	mismatch := reportedPresent && !reflect.DeepEqual(reported, trusted)

	metadata := sandboxruntime.SanitizeRuntimeMetadata(target.Runtime.Metadata)
	if metadata == nil && trusted != nil {
		metadata = &sandboxruntime.RuntimeMetadata{}
	}
	if metadata != nil {
		metadata.SetTemplateLock(trusted)
		metadata = sandboxruntime.SanitizeRuntimeMetadata(metadata)
	}
	target.Runtime.Metadata = metadata

	if mismatch {
		return target, errors.New("runtime-reported template lock does not match command-selected template")
	}
	return target, nil
}

func runtimeTemplateLockFromSandbox(lock *sandbox.SandboxTemplateLockMetadata) *sandboxruntime.RuntimeTemplateLockMetadata {
	lock = sandbox.SanitizeSandboxTemplateLockMetadata(lock)
	if lock == nil {
		return nil
	}
	return sandboxruntime.SanitizeRuntimeTemplateLockMetadata(&sandboxruntime.RuntimeTemplateLockMetadata{
		Document:          runtimeTemplateLockEntryFromSandbox(lock.Document),
		TemplateReference: runtimeTemplateLockEntryFromSandbox(lock.TemplateReference),
		RuntimeImage:      runtimeTemplateLockEntryFromSandbox(lock.RuntimeImage),
		SourceArtifact:    runtimeTemplateLockEntryFromSandbox(lock.SourceArtifact),
		TrustPolicy:       runtimeTemplateTrustPolicyFromSandbox(lock.TrustPolicy),
	})
}

func runtimeTemplateLockEntryFromSandbox(entry *sandbox.SandboxTemplateLockEntryMetadata) *sandboxruntime.RuntimeTemplateLockEntryMetadata {
	if entry == nil {
		return nil
	}
	return &sandboxruntime.RuntimeTemplateLockEntryMetadata{
		SourceKind:      entry.SourceKind,
		ReferenceKind:   entry.ReferenceKind,
		Status:          entry.Status,
		DigestAlgorithm: entry.DigestAlgorithm,
		DigestValue:     entry.DigestValue,
		SizeBytes:       entry.SizeBytes,
		LockedAt:        entry.LockedAt,
		WarningCodes:    append([]string(nil), entry.WarningCodes...),
		ReasonCode:      entry.ReasonCode,
	}
}

func runtimeTemplateTrustPolicyFromSandbox(policy *sandbox.SandboxTemplateTrustPolicyMetadata) *sandboxruntime.RuntimeTemplateTrustPolicyMetadata {
	if policy == nil {
		return nil
	}
	return &sandboxruntime.RuntimeTemplateTrustPolicyMetadata{
		Mode:            policy.Mode,
		Decision:        policy.Decision,
		SourceKind:      policy.SourceKind,
		ReferenceKind:   policy.ReferenceKind,
		Status:          policy.Status,
		DigestAlgorithm: policy.DigestAlgorithm,
		DigestValue:     policy.DigestValue,
		WarningCodes:    append([]string(nil), policy.WarningCodes...),
		ErrorCodes:      append([]string(nil), policy.ErrorCodes...),
		ReasonCodes:     append([]string(nil), policy.ReasonCodes...),
	}
}

func sandboxTemplateLockFromRuntime(metadata *sandboxruntime.RuntimeMetadata) *sandbox.SandboxTemplateLockMetadata {
	metadata = sandboxruntime.SanitizeRuntimeMetadata(metadata)
	if metadata == nil || metadata.TemplateLock == nil {
		return nil
	}
	lock := metadata.TemplateLock
	return sandbox.SanitizeSandboxTemplateLockMetadata(&sandbox.SandboxTemplateLockMetadata{
		Document:          sandboxTemplateLockEntryFromRuntime(lock.Document),
		TemplateReference: sandboxTemplateLockEntryFromRuntime(lock.TemplateReference),
		RuntimeImage:      sandboxTemplateLockEntryFromRuntime(lock.RuntimeImage),
		SourceArtifact:    sandboxTemplateLockEntryFromRuntime(lock.SourceArtifact),
		TrustPolicy:       sandboxTemplateTrustPolicyFromRuntime(lock.TrustPolicy),
	})
}

func sandboxTemplateLockEntryFromRuntime(entry *sandboxruntime.RuntimeTemplateLockEntryMetadata) *sandbox.SandboxTemplateLockEntryMetadata {
	if entry == nil {
		return nil
	}
	return &sandbox.SandboxTemplateLockEntryMetadata{
		SourceKind:      entry.SourceKind,
		ReferenceKind:   entry.ReferenceKind,
		Status:          entry.Status,
		DigestAlgorithm: entry.DigestAlgorithm,
		DigestValue:     entry.DigestValue,
		SizeBytes:       entry.SizeBytes,
		LockedAt:        entry.LockedAt,
		WarningCodes:    append([]string(nil), entry.WarningCodes...),
		ReasonCode:      entry.ReasonCode,
	}
}

func sandboxTemplateTrustPolicyFromRuntime(policy *sandboxruntime.RuntimeTemplateTrustPolicyMetadata) *sandbox.SandboxTemplateTrustPolicyMetadata {
	if policy == nil {
		return nil
	}
	return &sandbox.SandboxTemplateTrustPolicyMetadata{
		Mode:            policy.Mode,
		Decision:        policy.Decision,
		SourceKind:      policy.SourceKind,
		ReferenceKind:   policy.ReferenceKind,
		Status:          policy.Status,
		DigestAlgorithm: policy.DigestAlgorithm,
		DigestValue:     policy.DigestValue,
		WarningCodes:    append([]string(nil), policy.WarningCodes...),
		ErrorCodes:      append([]string(nil), policy.ErrorCodes...),
		ReasonCodes:     append([]string(nil), policy.ReasonCodes...),
	}
}

func hasRuntimeState(runtime sandboxruntime.RuntimeState) bool {
	return strings.TrimSpace(runtime.Driver) != "" ||
		strings.TrimSpace(runtime.RuntimeID) != "" ||
		strings.TrimSpace(runtime.Image) != "" ||
		strings.TrimSpace(runtime.WorkerID) != "" ||
		strings.TrimSpace(runtime.IsolationLevel) != ""
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
