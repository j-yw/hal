package firecrackerhost

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

const (
	processHandleSource = "firecrackerhost"
	processHandlePrefix = "fc-handle"

	processOperationStart   = "start"
	processOperationWait    = "wait"
	processOperationSignal  = "signal"
	processOperationKill    = "kill"
	processOperationCleanup = "cleanup"

	maxProcessErrorDetailBytes     = 512
	maxCleanupStateDirNameBytes    = 64
	defaultProcessTerminationGrace = 5 * time.Second
	defaultProcessCleanupTimeout   = 30 * time.Second
)

var (
	// ErrHostProcessRequired is returned when a process runner reports success
	// without returning an injected host process handle.
	ErrHostProcessRequired = errors.New("firecracker host process is required")
	// ErrUnsafeCleanupPath is returned when cleanup receives a path plan that
	// cannot be proven to refer only to Firecracker-owned state.
	ErrUnsafeCleanupPath = errors.New("firecracker cleanup path is unsafe")

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

type hostProcessIdentity interface {
	HostPID() int
	Done() <-chan struct{}
}

// HostProcessRunner starts a host process from the raw Firecracker runner
// request. Tests can inject fakes; the real runner is added by a later phase.
type HostProcessRunner interface {
	StartHostProcess(context.Context, firecracker.ProcessRunnerStartRequest) (HostProcess, error)
}

// CleanupFilesystem is the fakeable filesystem boundary used by state cleanup.
type CleanupFilesystem interface {
	Lstat(string) (os.FileInfo, error)
	RemoveAll(string) error
}

// ProcessLifecycleOption configures ProcessLifecycleManager dependencies.
type ProcessLifecycleOption func(*ProcessLifecycleManager)

// WithProcessLifecycleCleanupFilesystem injects the filesystem used for
// Firecracker-owned state directory cleanup.
func WithProcessLifecycleCleanupFilesystem(filesystem CleanupFilesystem) ProcessLifecycleOption {
	return func(manager *ProcessLifecycleManager) {
		if filesystem != nil {
			manager.cleanupFS = filesystem
		}
	}
}

func WithProcessLifecycleTerminationGrace(value time.Duration) ProcessLifecycleOption {
	return func(manager *ProcessLifecycleManager) {
		if value > 0 {
			manager.terminationGrace = value
		}
	}
}

func WithProcessLifecycleCleanupTimeout(value time.Duration) ProcessLifecycleOption {
	return func(manager *ProcessLifecycleManager) {
		if value > 0 {
			manager.cleanupTimeout = value
		}
	}
}

func withProcessLifecycleProductionVsock() ProcessLifecycleOption {
	return func(manager *ProcessLifecycleManager) {
		manager.productionVsock = true
	}
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
	runner           HostProcessRunner
	cleanupFS        CleanupFilesystem
	terminationGrace time.Duration
	cleanupTimeout   time.Duration
	productionVsock  bool

	mu        sync.Mutex
	nextID    uint64
	processes map[string]*trackedProcess
}

type trackedProcess struct {
	process      HostProcess
	finished     bool
	stateRemoved bool
	paths        firecracker.PathPlan
	hasPaths     bool
}

// NewProcessLifecycleManager constructs a fake-safe lifecycle manager. Without
// a runner, StartProcess returns ErrDependencyNotConfigured.
func NewProcessLifecycleManager(runner HostProcessRunner, options ...ProcessLifecycleOption) *ProcessLifecycleManager {
	manager := &ProcessLifecycleManager{
		runner:           runner,
		cleanupFS:        osCleanupFilesystem{},
		processes:        map[string]*trackedProcess{},
		terminationGrace: defaultProcessTerminationGrace,
		cleanupTimeout:   defaultProcessCleanupTimeout,
	}
	for _, option := range options {
		if option != nil {
			option(manager)
		}
	}
	if manager.cleanupFS == nil {
		manager.cleanupFS = osCleanupFilesystem{}
	}
	return manager
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

	paths, hasPaths := trustedStartPathPlan(req)
	if hasPaths {
		if manager.productionVsock {
			if err := validatePrivateFirecrackerStateDir(paths.StateDir); err != nil {
				return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, ErrUnsafeCleanupPath)
			}
		}
		if err := manager.removeStaleAPISocketBeforeStart(paths); err != nil {
			return firecracker.ProcessHandleMetadata{}, err
		}
		if err := manager.removeOwnedStaleVsockBeforeStart(paths); err != nil {
			return firecracker.ProcessHandleMetadata{}, err
		}
	}

	process, err := manager.runner.StartHostProcess(ctx, cloneProcessRunnerStartRequest(req))
	if err != nil {
		return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, err)
	}
	if process == nil {
		return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, ErrHostProcessRequired)
	}

	handle := manager.storeProcess(process, paths, hasPaths)
	return handle, nil
}

// CleanupLiveProcess force-stops a tracked live process and waits for it to
// finish. Unknown or already-finished handles are idempotent no-ops.
func (manager *ProcessLifecycleManager) CleanupLiveProcess(ctx context.Context, req firecracker.LiveProcessRequest) error {
	plan, removeState, err := manager.trackedCleanupPathPlan(req.Handle, req.Paths)
	if err != nil {
		return newProcessLifecycleError(processOperationCleanup, err)
	}
	if err := manager.killAndWait(ctx, req.Handle, false); err != nil {
		return err
	}
	if !removeState {
		return nil
	}
	if err := manager.removeValidatedStateDir(plan); err != nil {
		return err
	}
	manager.markStateRemoved(req.Handle)
	return nil
}

// StopLiveProcess gracefully stops a tracked live process and waits for it to
// finish. Unknown or already-finished handles are idempotent no-ops.
func (manager *ProcessLifecycleManager) StopLiveProcess(ctx context.Context, req firecracker.LiveProcessRequest) error {
	process, id, ok := manager.lookupActiveProcess(req.Handle)
	if !ok {
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), manager.cleanupTimeout)
	defer cancel()
	var failures []error
	reaped := false
	if err := process.Signal(cleanupCtx, ProcessSignalTerminate); err != nil {
		failures = append(failures, newProcessLifecycleError(processOperationSignal, err))
	} else {
		graceCtx, graceCancel := context.WithTimeout(cleanupCtx, manager.terminationGrace)
		waitErr := process.Wait(graceCtx)
		graceCancel()
		if waitErr == nil {
			manager.markProcessFinished(id)
			return nil
		}
		if !errors.Is(waitErr, context.DeadlineExceeded) {
			failures = append(failures, newProcessLifecycleError(processOperationWait, waitErr))
		}
	}
	if err := process.Kill(cleanupCtx); err != nil {
		failures = append(failures, newProcessLifecycleError(processOperationKill, err))
	} else if err := process.Wait(cleanupCtx); err != nil {
		failures = append(failures, newProcessLifecycleError(processOperationWait, err))
	} else {
		reaped = true
	}
	if !reaped {
		reaped = hostProcessExitObserved(process)
	}
	if reaped {
		manager.markProcessFinished(id)
	}
	return errors.Join(failures...)
}

func hostProcessExitObserved(process HostProcess) bool {
	identity, ok := process.(hostProcessIdentity)
	if !ok || identity.Done() == nil {
		return false
	}
	select {
	case <-identity.Done():
		return true
	default:
		return false
	}
}

// DeleteLiveProcess force-stops a tracked live process, waits for it to finish,
// and forgets the opaque handle. Unknown or already-finished handles are
// idempotent no-ops.
func (manager *ProcessLifecycleManager) DeleteLiveProcess(ctx context.Context, req firecracker.LiveProcessRequest) error {
	plan, removeState, err := manager.trackedCleanupPathPlan(req.Handle, req.Paths)
	if err != nil {
		return newProcessLifecycleError(processOperationCleanup, err)
	}
	if err := manager.killAndWait(ctx, req.Handle, false); err != nil {
		return err
	}
	if removeState {
		if err := manager.removeValidatedStateDir(plan); err != nil {
			return err
		}
		manager.markStateRemoved(req.Handle)
	}
	manager.forgetProcess(req.Handle)
	return nil
}

func (manager *ProcessLifecycleManager) killAndWait(ctx context.Context, handle firecracker.ProcessHandleMetadata, forget bool) error {
	process, id, ok := manager.lookupActiveProcess(handle)
	if !ok {
		if forget {
			manager.forgetProcess(handle)
		}
		return nil
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), manager.cleanupTimeout)
	defer cancel()
	if err := process.Kill(cleanupCtx); err != nil {
		return newProcessLifecycleError(processOperationKill, err)
	}
	if err := process.Wait(cleanupCtx); err != nil {
		return newProcessLifecycleError(processOperationWait, err)
	}
	if forget {
		manager.forgetProcessID(id)
		return nil
	}
	manager.markProcessFinished(id)
	return nil
}

func (manager *ProcessLifecycleManager) storeProcess(process HostProcess, paths firecracker.PathPlan, hasPaths bool) firecracker.ProcessHandleMetadata {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if manager.processes == nil {
		manager.processes = map[string]*trackedProcess{}
	}
	manager.nextID++
	id := fmt.Sprintf("%s-%012d", processHandlePrefix, manager.nextID)
	manager.processes[id] = &trackedProcess{
		process:  process,
		paths:    paths,
		hasPaths: hasPaths,
	}
	return firecracker.ProcessHandleMetadata{
		ID:     id,
		Source: processHandleSource,
	}
}

func (manager *ProcessLifecycleManager) trackedCleanupPathPlan(handle firecracker.ProcessHandleMetadata, paths firecracker.PathPlan) (firecracker.PathPlan, bool, error) {
	if cleanupPathPlanEmpty(paths) {
		return firecracker.PathPlan{}, false, nil
	}

	tracked, ok := manager.lookupProcessSnapshot(handle)
	if !ok {
		return firecracker.PathPlan{}, false, nil
	}

	plan, removeState, err := validatedCleanupPathPlan(paths)
	if err != nil {
		return firecracker.PathPlan{}, false, err
	}
	if !removeState || tracked.stateRemoved {
		return firecracker.PathPlan{}, false, nil
	}
	if !tracked.hasPaths || !cleanupPathPlansEqual(plan, tracked.paths) {
		return firecracker.PathPlan{}, false, fmt.Errorf("state directory does not match tracked live process: %w", ErrUnsafeCleanupPath)
	}
	return plan, true, nil
}

type trackedProcessSnapshot struct {
	paths        firecracker.PathPlan
	hasPaths     bool
	stateRemoved bool
}

func (manager *ProcessLifecycleManager) lookupProcessSnapshot(handle firecracker.ProcessHandleMetadata) (trackedProcessSnapshot, bool) {
	if manager == nil {
		return trackedProcessSnapshot{}, false
	}
	id := normalizeProcessHandleID(handle)
	if id == "" {
		return trackedProcessSnapshot{}, false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	tracked, ok := manager.processes[id]
	if !ok || tracked == nil {
		return trackedProcessSnapshot{}, false
	}
	return trackedProcessSnapshot{
		paths:        tracked.paths,
		hasPaths:     tracked.hasPaths,
		stateRemoved: tracked.stateRemoved,
	}, true
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

type liveProcessIdentity struct {
	pid    int
	done   <-chan struct{}
	handle firecracker.ProcessHandleMetadata
	paths  firecracker.PathPlan
}

func (manager *ProcessLifecycleManager) resolveLiveProcessIdentity(handle firecracker.ProcessHandleMetadata) (liveProcessIdentity, error) {
	process, id, ok := manager.lookupActiveProcess(handle)
	if !ok {
		return liveProcessIdentity{}, errors.New("Firecracker process identity is unavailable")
	}
	identity, ok := process.(hostProcessIdentity)
	if !ok || identity.HostPID() <= 0 || identity.Done() == nil {
		return liveProcessIdentity{}, errors.New("Firecracker process identity is unavailable")
	}
	snapshot, ok := manager.lookupProcessSnapshot(handle)
	if !ok {
		return liveProcessIdentity{}, errors.New("Firecracker process identity is unavailable")
	}
	select {
	case <-identity.Done():
		manager.markProcessFinished(id)
		return liveProcessIdentity{}, errors.New("Firecracker process is not active")
	default:
	}
	return liveProcessIdentity{
		pid: identity.HostPID(), done: identity.Done(),
		handle: firecracker.ProcessHandleMetadata{ID: id, Source: processHandleSource},
		paths:  snapshot.paths,
	}, nil
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

func (manager *ProcessLifecycleManager) markStateRemoved(handle firecracker.ProcessHandleMetadata) {
	if manager == nil {
		return
	}
	id := normalizeProcessHandleID(handle)
	if id == "" {
		return
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if tracked := manager.processes[id]; tracked != nil {
		tracked.stateRemoved = true
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

func (manager *ProcessLifecycleManager) removeValidatedStateDir(plan firecracker.PathPlan) error {
	filesystem := manager.cleanupFilesystem()
	info, err := filesystem.Lstat(plan.StateDir)
	switch {
	case err == nil:
		if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("state directory is invalid: %w", ErrUnsafeCleanupPath))
		}
	case os.IsNotExist(err):
		return nil
	default:
		return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("state directory inspection failed: %w", err))
	}
	if err := filesystem.RemoveAll(plan.StateDir); err != nil {
		return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("state directory removal failed: %w", err))
	}
	return nil
}

func (manager *ProcessLifecycleManager) removeStaleAPISocketBeforeStart(plan firecracker.PathPlan) error {
	filesystem := manager.cleanupFilesystem()
	info, err := filesystem.Lstat(plan.APISocketPath)
	switch {
	case err == nil:
		if info == nil || info.Mode()&os.ModeSymlink != 0 {
			return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("API socket path is invalid: %w", ErrUnsafeCleanupPath))
		}
		if info.Mode()&os.ModeSocket == 0 {
			return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("API socket path already exists and is not a socket: %w", ErrUnsafeCleanupPath))
		}
	case os.IsNotExist(err):
		return nil
	default:
		return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("API socket path inspection failed: %w", err))
	}
	if err := filesystem.RemoveAll(plan.APISocketPath); err != nil {
		return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("stale API socket removal failed: %w", err))
	}
	return nil
}

func (manager *ProcessLifecycleManager) removeOwnedStaleVsockBeforeStart(plan firecracker.PathPlan) error {
	filesystem := manager.cleanupFilesystem()
	info, err := filesystem.Lstat(plan.VsockSocketPath)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("vsock socket inspection failed: %w", err))
	case info == nil || info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0:
		return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("vsock socket path is invalid: %w", ErrUnsafeCleanupPath))
	}
	if err := validateVsockSocketOwnership(plan.VsockSocketPath, info); err != nil {
		return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("vsock socket ownership is invalid: %w", ErrUnsafeCleanupPath))
	}
	if !manager.hasTerminalProcessForPaths(plan) {
		return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("vsock socket has no terminal owner: %w", ErrUnsafeCleanupPath))
	}
	if err := filesystem.RemoveAll(plan.VsockSocketPath); err != nil {
		return newProcessLifecycleError(processOperationCleanup, fmt.Errorf("stale vsock socket removal failed: %w", err))
	}
	return nil
}

func (manager *ProcessLifecycleManager) hasTerminalProcessForPaths(plan firecracker.PathPlan) bool {
	if manager == nil {
		return false
	}
	manager.mu.Lock()
	defer manager.mu.Unlock()
	for _, tracked := range manager.processes {
		if tracked == nil || !tracked.hasPaths || !cleanupPathPlansEqual(tracked.paths, plan) {
			continue
		}
		if !tracked.finished {
			if identity, ok := tracked.process.(hostProcessIdentity); ok && identity.Done() != nil {
				select {
				case <-identity.Done():
					tracked.finished = true
				default:
				}
			}
		}
		if tracked.finished {
			return true
		}
	}
	return false
}

func (manager *ProcessLifecycleManager) cleanupFilesystem() CleanupFilesystem {
	if manager == nil || manager.cleanupFS == nil {
		return osCleanupFilesystem{}
	}
	return manager.cleanupFS
}

func validatedCleanupPathPlan(paths firecracker.PathPlan) (firecracker.PathPlan, bool, error) {
	if cleanupPathPlanEmpty(paths) {
		return firecracker.PathPlan{}, false, nil
	}

	stateDir, err := cleanCleanupStateDir(paths.StateDir)
	if err != nil {
		return firecracker.PathPlan{}, false, err
	}
	apiSocketPath, err := cleanCleanupSupportPath(paths.APISocketPath, stateDir, "API socket", firecracker.DefaultAPISocketPath)
	if err != nil {
		return firecracker.PathPlan{}, false, err
	}
	configPath, err := cleanCleanupSupportPath(paths.ConfigPath, stateDir, "config", firecracker.DefaultConfigPath)
	if err != nil {
		return firecracker.PathPlan{}, false, err
	}
	logPath, err := cleanCleanupSupportPath(paths.LogPath, stateDir, "log", firecracker.DefaultLogPath)
	if err != nil {
		return firecracker.PathPlan{}, false, err
	}
	metricsPath, err := cleanCleanupSupportPath(paths.MetricsPath, stateDir, "metrics", firecracker.DefaultMetricsPath)
	if err != nil {
		return firecracker.PathPlan{}, false, err
	}
	rawVsockSocketPath := paths.VsockSocketPath
	if strings.TrimSpace(rawVsockSocketPath) == "" {
		rawVsockSocketPath = filepath.Join(stateDir, "guest.vsock")
	}
	vsockSocketPath, err := cleanCleanupSupportPath(rawVsockSocketPath, stateDir, "vsock socket", "guest.vsock")
	if err != nil {
		return firecracker.PathPlan{}, false, err
	}

	return firecracker.PathPlan{
		StateDir:        stateDir,
		APISocketPath:   apiSocketPath,
		ConfigPath:      configPath,
		LogPath:         logPath,
		MetricsPath:     metricsPath,
		VsockSocketPath: vsockSocketPath,
	}, true, nil
}

func trustedStartPathPlan(req firecracker.ProcessRunnerStartRequest) (firecracker.PathPlan, bool) {
	apiSocketPath, ok := startRequestFlagValue(req.Args, "--api-sock")
	if !ok {
		return firecracker.PathPlan{}, false
	}
	configPath, ok := startRequestFlagValue(req.Args, "--config-file")
	if !ok {
		return firecracker.PathPlan{}, false
	}
	logPath, ok := startRequestFlagValue(req.Args, "--log-path")
	if !ok {
		return firecracker.PathPlan{}, false
	}
	metricsPath, ok := startRequestFlagValue(req.Args, "--metrics-path")
	if !ok {
		return firecracker.PathPlan{}, false
	}
	stateDir := filepath.Dir(configPath)
	vsockSocketPath := filepath.Join(stateDir, "guest.vsock")
	plan, removeState, err := validatedCleanupPathPlan(firecracker.PathPlan{
		StateDir:        stateDir,
		APISocketPath:   apiSocketPath,
		ConfigPath:      configPath,
		LogPath:         logPath,
		MetricsPath:     metricsPath,
		VsockSocketPath: vsockSocketPath,
	})
	if err != nil || !removeState {
		return firecracker.PathPlan{}, false
	}
	return plan, true
}

func startRequestFlagValue(args []string, flag string) (string, bool) {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == flag {
			return args[i+1], true
		}
	}
	return "", false
}

func cleanupPathPlansEqual(a, b firecracker.PathPlan) bool {
	return filepath.Clean(a.StateDir) == filepath.Clean(b.StateDir) &&
		filepath.Clean(a.APISocketPath) == filepath.Clean(b.APISocketPath) &&
		filepath.Clean(a.ConfigPath) == filepath.Clean(b.ConfigPath) &&
		filepath.Clean(a.LogPath) == filepath.Clean(b.LogPath) &&
		filepath.Clean(a.MetricsPath) == filepath.Clean(b.MetricsPath) &&
		filepath.Clean(a.VsockSocketPath) == filepath.Clean(b.VsockSocketPath)
}

func cleanupPathPlanEmpty(paths firecracker.PathPlan) bool {
	return strings.TrimSpace(paths.StateDir) == "" &&
		strings.TrimSpace(paths.APISocketPath) == "" &&
		strings.TrimSpace(paths.ConfigPath) == "" &&
		strings.TrimSpace(paths.LogPath) == "" &&
		strings.TrimSpace(paths.MetricsPath) == "" &&
		strings.TrimSpace(paths.VsockSocketPath) == ""
}

func cleanCleanupStateDir(path string) (string, error) {
	cleaned, err := cleanAbsoluteCleanupPath(path, "state directory")
	if err != nil {
		return "", err
	}
	if cleanupFilesystemRoot(cleaned) || !validCleanupStateDirName(filepath.Base(cleaned)) {
		return "", fmt.Errorf("state directory is invalid: %w", ErrUnsafeCleanupPath)
	}
	return cleaned, nil
}

func cleanCleanupSupportPath(path, stateDir, role, expectedName string) (string, error) {
	cleaned, err := cleanAbsoluteCleanupPath(path, role+" path")
	if err != nil {
		return "", err
	}
	if filepath.Base(cleaned) != expectedName {
		return "", fmt.Errorf("%s path is invalid: %w", role, ErrUnsafeCleanupPath)
	}
	if filepath.Dir(cleaned) != stateDir {
		return "", fmt.Errorf("%s path must be directly inside the state directory: %w", role, ErrUnsafeCleanupPath)
	}
	rel, err := filepath.Rel(stateDir, cleaned)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("%s path must be inside the state directory: %w", role, ErrUnsafeCleanupPath)
	}
	return cleaned, nil
}

func cleanAbsoluteCleanupPath(path, role string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("%s is required: %w", strings.TrimSpace(role), ErrUnsafeCleanupPath)
	}
	if hasCleanupPathControl(path) {
		return "", fmt.Errorf("%s is invalid: %w", strings.TrimSpace(role), ErrUnsafeCleanupPath)
	}
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("%s must be absolute: %w", strings.TrimSpace(role), ErrUnsafeCleanupPath)
	}
	return cleaned, nil
}

func hasCleanupPathControl(path string) bool {
	for _, r := range path {
		if r == 0 || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func cleanupFilesystemRoot(path string) bool {
	volumeName := filepath.VolumeName(path)
	withoutVolume := strings.TrimPrefix(path, volumeName)
	return withoutVolume == string(filepath.Separator)
}

func validCleanupStateDirName(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" || value == "." || value == ".." || len(value) > maxCleanupStateDirNameBytes {
		return false
	}
	if !strings.HasPrefix(value, "fc-") || processSecretValuePattern.MatchString(value) {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
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
	case processOperationCleanup:
		return processOperationCleanup
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

type osCleanupFilesystem struct{}

func (osCleanupFilesystem) Lstat(path string) (os.FileInfo, error) {
	return os.Lstat(path)
}

func (osCleanupFilesystem) RemoveAll(path string) error {
	return os.RemoveAll(path)
}
