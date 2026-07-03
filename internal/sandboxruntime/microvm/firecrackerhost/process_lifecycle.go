package firecrackerhost

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

const (
	processHandleSource = "firecrackerhost"
	processHandlePrefix = "fc-handle"

	processOperationStart  = "start"
	processOperationWait   = "wait"
	processOperationSignal = "signal"
	processOperationKill   = "kill"

	maxProcessErrorDetailBytes = 512
)

var (
	// ErrHostProcessRequired is returned when a process runner reports success
	// without returning an injected host process handle.
	ErrHostProcessRequired = errors.New("firecracker host process is required")

	processAbsolutePathPattern     = regexp.MustCompile(`(?i)(?:[A-Za-z]:)?/(?:[^\s:'",]+/?)+`)
	processURLPattern              = regexp.MustCompile(`(?i)\bhttps?://[^\s'"]+`)
	processPIDPattern              = regexp.MustCompile(`(?i)\b(?:pid|process[_ -]?id|process)\s*[:=#-]?\s*\d+\b`)
	processSecretAssignmentPattern = regexp.MustCompile(`(?i)\b(?:[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API[_-]?KEY|APIKEY|CREDENTIAL|AUTHORIZATION|BEARER)[A-Z0-9_]*|token|secret|password|api[_-]?key|credential|authorization|bearer)=\S+`)
	processSecretNamePattern       = regexp.MustCompile(`\b[A-Z][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|CREDENTIAL|AUTHORIZATION|BEARER)[A-Z0-9_]*\b`)
	processSecretValuePattern      = regexp.MustCompile(`(?i)\b(?:gh[pousr]_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]+|[A-Za-z0-9_-]*(?:token|secret|password|credential)[A-Za-z0-9_-]*)\b`)
)

// ProcessSignal is a fake-safe process signal label understood by host process
// implementations. It intentionally avoids exposing platform signal values.
type ProcessSignal string

const (
	// ProcessSignalTerminate asks the process to stop gracefully.
	ProcessSignalTerminate ProcessSignal = "terminate"
)

// HostProcess is the fakeable host process lifecycle boundary. Implementations
// may retain raw process metadata internally, but no raw metadata crosses the
// public Firecracker handle surface.
type HostProcess interface {
	Wait(context.Context) error
	Signal(context.Context, ProcessSignal) error
	Kill(context.Context) error
}

// HostProcessRunner starts a host process from the raw Firecracker runner
// request. Tests can inject fakes; the real runner is added by a later phase.
type HostProcessRunner interface {
	StartHostProcess(context.Context, firecracker.ProcessRunnerStartRequest) (HostProcess, error)
}

// ProcessLifecycleError wraps a host process lifecycle failure with sanitized
// public detail while preserving the original cause for errors.Is/errors.As.
type ProcessLifecycleError struct {
	Operation string
	Detail    string
	Err       error
}

func (err *ProcessLifecycleError) Error() string {
	if err == nil {
		return ""
	}
	operation := safeProcessOperation(err.Operation)
	message := "firecracker host process " + operation + " failed"
	if detail := strings.TrimSpace(err.Detail); detail != "" {
		return message + ": " + detail
	}
	return message
}

func (err *ProcessLifecycleError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

// ProcessLifecycleManager implements Firecracker process start and live process
// cleanup using an injected HostProcessRunner and opaque in-memory handles.
type ProcessLifecycleManager struct {
	runner HostProcessRunner

	mu        sync.Mutex
	nextID    uint64
	processes map[string]*trackedProcess
}

type trackedProcess struct {
	process  HostProcess
	finished bool
}

// NewProcessLifecycleManager constructs a fake-safe lifecycle manager. Without
// a runner, StartProcess returns ErrDependencyNotConfigured.
func NewProcessLifecycleManager(runner HostProcessRunner) *ProcessLifecycleManager {
	return &ProcessLifecycleManager{
		runner:    runner,
		processes: map[string]*trackedProcess{},
	}
}

var _ ProcessRunner = (*ProcessLifecycleManager)(nil)
var _ LiveProcessCleanup = (*ProcessLifecycleManager)(nil)

// StartProcess starts a host process through the injected runner and returns a
// stable opaque handle. Raw runner process metadata is kept only in memory.
func (manager *ProcessLifecycleManager) StartProcess(ctx context.Context, req firecracker.ProcessRunnerStartRequest) (firecracker.ProcessHandleMetadata, error) {
	if manager == nil || manager.runner == nil {
		return firecracker.ProcessHandleMetadata{}, dependencyNotConfigured("hostProcessRunner")
	}
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return firecracker.ProcessHandleMetadata{}, err
	}

	process, err := manager.runner.StartHostProcess(ctx, cloneProcessRunnerStartRequest(req))
	if err != nil {
		return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, err)
	}
	if process == nil {
		return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, ErrHostProcessRequired)
	}

	handle := manager.storeProcess(process)
	return handle, nil
}

// CleanupLiveProcess force-stops a tracked live process and waits for it to
// finish. Unknown or already-finished handles are idempotent no-ops.
func (manager *ProcessLifecycleManager) CleanupLiveProcess(ctx context.Context, req firecracker.LiveProcessRequest) error {
	return manager.killAndWait(ctx, req.Handle, false)
}

// StopLiveProcess gracefully stops a tracked live process and waits for it to
// finish. Unknown or already-finished handles are idempotent no-ops.
func (manager *ProcessLifecycleManager) StopLiveProcess(ctx context.Context, req firecracker.LiveProcessRequest) error {
	process, id, ok := manager.lookupActiveProcess(req.Handle)
	if !ok {
		return nil
	}
	ctx = nonNilContext(ctx)
	if err := process.Signal(ctx, ProcessSignalTerminate); err != nil {
		return newProcessLifecycleError(processOperationSignal, err)
	}
	if err := process.Wait(ctx); err != nil {
		return newProcessLifecycleError(processOperationWait, err)
	}
	manager.markProcessFinished(id)
	return nil
}

// DeleteLiveProcess force-stops a tracked live process, waits for it to finish,
// and forgets the opaque handle. Unknown or already-finished handles are
// idempotent no-ops.
func (manager *ProcessLifecycleManager) DeleteLiveProcess(ctx context.Context, req firecracker.LiveProcessRequest) error {
	return manager.killAndWait(ctx, req.Handle, true)
}

func (manager *ProcessLifecycleManager) killAndWait(ctx context.Context, handle firecracker.ProcessHandleMetadata, forget bool) error {
	process, id, ok := manager.lookupActiveProcess(handle)
	if !ok {
		if forget {
			manager.forgetProcess(handle)
		}
		return nil
	}
	ctx = nonNilContext(ctx)
	if err := process.Kill(ctx); err != nil {
		return newProcessLifecycleError(processOperationKill, err)
	}
	if err := process.Wait(ctx); err != nil {
		return newProcessLifecycleError(processOperationWait, err)
	}
	if forget {
		manager.forgetProcessID(id)
		return nil
	}
	manager.markProcessFinished(id)
	return nil
}

func (manager *ProcessLifecycleManager) storeProcess(process HostProcess) firecracker.ProcessHandleMetadata {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.processes == nil {
		manager.processes = map[string]*trackedProcess{}
	}
	manager.nextID++
	id := fmt.Sprintf("%s-%012d", processHandlePrefix, manager.nextID)
	manager.processes[id] = &trackedProcess{process: process}
	return firecracker.ProcessHandleMetadata{
		ID:     id,
		Source: processHandleSource,
	}
}

func (manager *ProcessLifecycleManager) lookupActiveProcess(handle firecracker.ProcessHandleMetadata) (HostProcess, string, bool) {
	if manager == nil {
		return nil, "", false
	}
	id := normalizeProcessHandleID(handle)
	if id == "" {
		return nil, "", false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	tracked, ok := manager.processes[id]
	if !ok || tracked == nil || tracked.finished || tracked.process == nil {
		return nil, id, false
	}
	return tracked.process, id, true
}

func (manager *ProcessLifecycleManager) markProcessFinished(id string) {
	if manager == nil || strings.TrimSpace(id) == "" {
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if tracked := manager.processes[id]; tracked != nil {
		tracked.finished = true
	}
}

func (manager *ProcessLifecycleManager) forgetProcess(handle firecracker.ProcessHandleMetadata) {
	manager.forgetProcessID(normalizeProcessHandleID(handle))
}

func (manager *ProcessLifecycleManager) forgetProcessID(id string) {
	if manager == nil || strings.TrimSpace(id) == "" {
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	delete(manager.processes, id)
}

func normalizeProcessHandleID(handle firecracker.ProcessHandleMetadata) string {
	if strings.TrimSpace(handle.Source) != processHandleSource {
		return ""
	}
	id := strings.TrimSpace(handle.ID)
	if id == "" || !strings.HasPrefix(id, processHandlePrefix+"-") || processSecretValuePattern.MatchString(id) {
		return ""
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return ""
		}
	}
	return id
}

func cloneProcessRunnerStartRequest(req firecracker.ProcessRunnerStartRequest) firecracker.ProcessRunnerStartRequest {
	return firecracker.ProcessRunnerStartRequest{
		Executable:  req.Executable,
		Args:        append([]string(nil), req.Args...),
		Environment: append([]string(nil), req.Environment...),
	}
}

func newProcessLifecycleError(operation string, cause error) *ProcessLifecycleError {
	if cause == nil {
		cause = errors.New("process lifecycle failed")
	}
	return &ProcessLifecycleError{
		Operation: safeProcessOperation(operation),
		Detail:    sanitizeProcessLifecycleErrorDetail(cause),
		Err:       cause,
	}
}

func safeProcessOperation(operation string) string {
	switch strings.TrimSpace(operation) {
	case processOperationStart:
		return processOperationStart
	case processOperationWait:
		return processOperationWait
	case processOperationSignal:
		return processOperationSignal
	case processOperationKill:
		return processOperationKill
	default:
		return "lifecycle"
	}
}

func sanitizeProcessLifecycleErrorDetail(cause error) string {
	if cause == nil {
		return ""
	}
	detail := strings.TrimSpace(cause.Error())
	if detail == "" {
		return ""
	}
	detail = processURLPattern.ReplaceAllString(detail, "[redacted-url]")
	detail = processSecretAssignmentPattern.ReplaceAllString(detail, "[redacted-secret]")
	detail = processSecretNamePattern.ReplaceAllString(detail, "[redacted-env]")
	detail = processPIDPattern.ReplaceAllString(detail, "pid=[redacted-pid]")
	detail = processAbsolutePathPattern.ReplaceAllString(detail, "[redacted-path]")
	detail = processSecretValuePattern.ReplaceAllString(detail, "[redacted-secret]")
	detail = strings.Join(strings.Fields(detail), " ")
	if len(detail) > maxProcessErrorDetailBytes {
		detail = detail[:maxProcessErrorDetailBytes] + "..."
	}
	return detail
}
