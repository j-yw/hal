package firecrackerhost

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

var (
	errStrictJailerLifecycleInvalid  = errors.New("strict Jailer lifecycle request is invalid")
	errStrictJailerLifecycleInactive = errors.New("strict Jailer process is not active")
)

// strictJailerLifecycleStartRequest keeps the validated command plan and the
// host cleanup authority in one private call. The duplicated hostPaths member
// is intentional: equality with the plan is checked before any live boundary,
// preventing a caller from pairing a command generation with another jail.
type strictJailerLifecycleStartRequest struct {
	launchPlan strictJailerLaunchPlan
	hostPaths  firecracker.PathPlan
}

// strictJailerLifecycleProcess binds one opaque process generation to the host
// paths recorded by ProcessLifecycleManager. It has no public JSON shape.
type strictJailerLifecycleProcess struct {
	handle     firecracker.ProcessHandleMetadata
	hostPaths  firecracker.PathPlan
	runtimeUID uint32
}

type strictJailerLifecycleInspection struct {
	active bool
}

// strictJailerLifecycle is default-off and package-private. It cannot be
// constructed with the legacy direct or asset-FD namespace runner. It owns the
// retained process only; its outer coordinator must retain and clean the
// stager's complete jail-root lease after terminal process proof. PathPlan
// cleanup is not complete jail-root or staged-asset cleanup.
type strictJailerLifecycle struct {
	manager *ProcessLifecycleManager
	runner  *strictJailerNamespaceRunner
}

func newStrictJailerLifecycle(
	runner *strictJailerNamespaceRunner,
	options ...ProcessLifecycleOption,
) (*strictJailerLifecycle, error) {
	if !runner.configured() {
		return nil, errStrictJailerLifecycleInvalid
	}
	return &strictJailerLifecycle{manager: NewProcessLifecycleManager(runner, options...), runner: runner}, nil
}

func (lifecycle *strictJailerLifecycle) start(
	ctx context.Context,
	request strictJailerLifecycleStartRequest,
) (strictJailerLifecycleProcess, error) {
	if lifecycle == nil || lifecycle.manager == nil {
		return strictJailerLifecycleProcess{}, errStrictJailerLifecycleInvalid
	}
	processRequest, hostPaths, runtimeUID, err := validateStrictJailerLifecycleStartRequest(request)
	if err != nil {
		return strictJailerLifecycleProcess{}, errStrictJailerLifecycleInvalid
	}
	handle, err := lifecycle.manager.startStrictJailerProcess(ctx, processRequest, hostPaths, runtimeUID)
	if err != nil {
		return strictJailerLifecycleProcess{}, err
	}
	return strictJailerLifecycleProcess{handle: handle, hostPaths: hostPaths, runtimeUID: runtimeUID}, nil
}

func (lifecycle *strictJailerLifecycle) inspect(
	process strictJailerLifecycleProcess,
) (strictJailerLifecycleInspection, error) {
	if !lifecycle.validProcess(process) {
		return strictJailerLifecycleInspection{}, errStrictJailerLifecycleInvalid
	}
	identity, err := lifecycle.manager.resolveLiveProcessIdentity(process.handle)
	if err != nil || !cleanupPathPlansEqual(identity.paths, process.hostPaths) {
		return strictJailerLifecycleInspection{}, errStrictJailerLifecycleInactive
	}
	return strictJailerLifecycleInspection{active: true}, nil
}

func (lifecycle *strictJailerLifecycle) stop(
	ctx context.Context,
	process strictJailerLifecycleProcess,
) error {
	if !lifecycle.validProcess(process) {
		return errStrictJailerLifecycleInvalid
	}
	return lifecycle.manager.StopLiveProcess(nonNilContext(ctx), firecracker.LiveProcessRequest{
		Handle: process.handle,
		Paths:  process.hostPaths,
	})
}

// terminated requires positive terminal proof for this exact private process
// authority. An inactive or unknown lookup is not proof and fails closed.
func (lifecycle *strictJailerLifecycle) terminated(process strictJailerLifecycleProcess) bool {
	if !lifecycle.validProcess(process) {
		return false
	}
	return lifecycle.manager.LiveProcessTerminated(firecracker.LiveProcessRequest{
		Handle: process.handle,
		Paths:  process.hostPaths,
	})
}

// forgetTerminated retires only the exact structured process authority after
// rechecking positive terminal proof. The outer coordinator calls it only
// after the corresponding retained jail root has reached terminal release.
func (lifecycle *strictJailerLifecycle) forgetTerminated(process strictJailerLifecycleProcess) error {
	if lifecycle == nil || lifecycle.manager == nil {
		return errStrictJailerLifecycleInvalid
	}
	err := lifecycle.manager.forgetTerminatedStrictJailerProcess(process.handle, process.hostPaths, process.runtimeUID)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errStrictJailerLifecycleInactive):
		return errStrictJailerLifecycleInactive
	default:
		return errStrictJailerLifecycleInvalid
	}
}

// retryUncertainStartCleanup lets the future outer coordinator retain its jail
// root lease while retrying an exact partial process. The lease must not be
// released until this returns nil.
func (lifecycle *strictJailerLifecycle) retryUncertainStartCleanup(ctx context.Context) error {
	if lifecycle == nil || lifecycle.runner == nil {
		return errStrictJailerLifecycleInvalid
	}
	return lifecycle.runner.retryRetainedProcessCleanup(nonNilContext(ctx))
}

// strictJailerLifecycleStartCleanupUncertain separates a contained start
// failure (no process remains) from a failure where descriptor/process cleanup
// is not proven. An outer coordinator may release its jail-root lease only for
// the former case.
func strictJailerLifecycleStartCleanupUncertain(err error) bool {
	return errors.Is(err, errStrictJailerNamespaceCleanupIncomplete)
}

func (lifecycle *strictJailerLifecycle) validProcess(process strictJailerLifecycleProcess) bool {
	if lifecycle == nil || lifecycle.manager == nil {
		return false
	}
	hostPaths, hasPaths, err := validatedCleanupPathPlan(process.hostPaths)
	if err != nil || !hasPaths || !cleanupPathPlansEqual(hostPaths, process.hostPaths) {
		return false
	}
	return lifecycle.manager.validateTrackedStrictJailerProcess(process.handle, hostPaths, process.runtimeUID) == nil
}

// startStrictJailerProcess is deliberately separate from StartProcess. It uses
// only the already-correlated host path authority and never parses the
// jail-visible Firecracker arguments for cleanup or polling paths.
func (manager *ProcessLifecycleManager) startStrictJailerProcess(
	ctx context.Context,
	request firecracker.ProcessRunnerStartRequest,
	hostPaths firecracker.PathPlan,
	runtimeUID uint32,
) (firecracker.ProcessHandleMetadata, error) {
	if manager == nil || manager.runner == nil {
		return firecracker.ProcessHandleMetadata{}, dependencyNotConfigured("hostProcessRunner")
	}
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return firecracker.ProcessHandleMetadata{}, err
	}
	paths, hasPaths, err := validatedCleanupPathPlan(hostPaths)
	if err != nil || !hasPaths || !cleanupPathPlansEqual(paths, hostPaths) || runtimeUID == 0 {
		return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, ErrUnsafeCleanupPath)
	}

	var stateIdentity privateStateDirIdentity
	var hasStateIdentity bool
	if manager.productionVsock {
		identity, identityErr := statStrictJailerPrivateStateDir(paths.StateDir, runtimeUID)
		if identityErr != nil {
			return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, ErrUnsafeCleanupPath)
		}
		stateIdentity = identity
		hasStateIdentity = true
	}
	if err := manager.removeStrictJailerStaleAPISocketBeforeStart(paths, stateIdentity, hasStateIdentity, runtimeUID); err != nil {
		return firecracker.ProcessHandleMetadata{}, err
	}
	if err := manager.removeStrictJailerStaleVsockBeforeStart(paths, stateIdentity, hasStateIdentity, runtimeUID); err != nil {
		return firecracker.ProcessHandleMetadata{}, err
	}

	process, err := manager.runner.StartHostProcess(ctx, cloneProcessRunnerStartRequest(request))
	if err != nil {
		return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, err)
	}
	if interfaceValueIsNil(process) {
		return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, ErrHostProcessRequired)
	}
	return manager.storeStrictJailerProcess(process, paths, stateIdentity, hasStateIdentity, runtimeUID), nil
}

func validateStrictJailerLifecycleStartRequest(
	request strictJailerLifecycleStartRequest,
) (firecracker.ProcessRunnerStartRequest, firecracker.PathPlan, uint32, error) {
	authority, err := request.launchPlan.validatedAuthority()
	if err != nil {
		return firecracker.ProcessRunnerStartRequest{}, firecracker.PathPlan{}, 0, errStrictJailerLifecycleInvalid
	}
	planHostPaths, hasPlanHostPaths, err := validatedCleanupPathPlan(authority.hostPaths)
	if err != nil || !hasPlanHostPaths {
		return firecracker.ProcessRunnerStartRequest{}, firecracker.PathPlan{}, 0, errStrictJailerLifecycleInvalid
	}
	authoritativeHostPaths, hasAuthoritativeHostPaths, err := validatedCleanupPathPlan(request.hostPaths)
	if err != nil || !hasAuthoritativeHostPaths || !cleanupPathPlansEqual(planHostPaths, authoritativeHostPaths) {
		return firecracker.ProcessRunnerStartRequest{}, firecracker.PathPlan{}, 0, errStrictJailerLifecycleInvalid
	}
	return authority.process, authoritativeHostPaths, authority.runtimeUID, nil
}

func strictJailerCallerMayCleanup(callerUID, expectedRuntimeUID uint32) bool {
	return expectedRuntimeUID != 0 && (callerUID == 0 || callerUID == expectedRuntimeUID)
}

func (manager *ProcessLifecycleManager) removeStrictJailerStaleAPISocketBeforeStart(
	plan firecracker.PathPlan,
	stateIdentity privateStateDirIdentity,
	hasStateIdentity bool,
	runtimeUID uint32,
) error {
	if manager == nil {
		return newProcessLifecycleError(processOperationCleanup, ErrUnsafeCleanupPath)
	}
	if !manager.productionVsock {
		return nil
	}
	info, err := os.Lstat(plan.APISocketPath)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return newProcessLifecycleError(processOperationCleanup, errors.New("API socket inspection failed"))
	case info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0:
		return newProcessLifecycleError(processOperationCleanup, ErrUnsafeCleanupPath)
	}
	if !hasStateIdentity || validateStrictJailerSocketOwnership(plan.APISocketPath, runtimeUID) != nil ||
		!manager.hasTerminalProcessForPaths(plan, stateIdentity, true) {
		return newProcessLifecycleError(processOperationCleanup, ErrUnsafeCleanupPath)
	}
	if err := removeStrictJailerPinnedStateEntry(plan.StateDir, filepath.Base(plan.APISocketPath), stateIdentity, runtimeUID); err != nil {
		return newProcessLifecycleError(processOperationCleanup, err)
	}
	return nil
}

func (manager *ProcessLifecycleManager) removeStrictJailerStaleVsockBeforeStart(
	plan firecracker.PathPlan,
	stateIdentity privateStateDirIdentity,
	hasStateIdentity bool,
	runtimeUID uint32,
) error {
	if manager == nil {
		return newProcessLifecycleError(processOperationCleanup, ErrUnsafeCleanupPath)
	}
	if !manager.productionVsock {
		return nil
	}
	info, err := os.Lstat(plan.VsockSocketPath)
	switch {
	case os.IsNotExist(err):
		return nil
	case err != nil:
		return newProcessLifecycleError(processOperationCleanup, errors.New("vsock socket inspection failed"))
	case info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0:
		return newProcessLifecycleError(processOperationCleanup, ErrUnsafeCleanupPath)
	}
	if !hasStateIdentity || validateStrictJailerSocketOwnership(plan.VsockSocketPath, runtimeUID) != nil ||
		!manager.hasTerminalProcessForPaths(plan, stateIdentity, true) {
		return newProcessLifecycleError(processOperationCleanup, ErrUnsafeCleanupPath)
	}
	if err := removeStrictJailerPinnedStateEntry(plan.StateDir, filepath.Base(plan.VsockSocketPath), stateIdentity, runtimeUID); err != nil {
		return newProcessLifecycleError(processOperationCleanup, err)
	}
	return nil
}

func (manager *ProcessLifecycleManager) storeStrictJailerProcess(
	process HostProcess,
	paths firecracker.PathPlan,
	stateIdentity privateStateDirIdentity,
	hasStateIdentity bool,
	runtimeUID uint32,
) firecracker.ProcessHandleMetadata {
	return manager.storeProcessRecord(process, paths, true, stateIdentity, hasStateIdentity, runtimeUID, true)
}

func (manager *ProcessLifecycleManager) validateTrackedStrictJailerProcess(
	handle firecracker.ProcessHandleMetadata,
	paths firecracker.PathPlan,
	runtimeUID uint32,
) error {
	if runtimeUID == 0 {
		return ErrUnsafeCleanupPath
	}
	if err := manager.validateTrackedProcessPathPlan(handle, paths); err != nil {
		return err
	}
	snapshot, ok := manager.lookupProcessSnapshot(handle)
	if !ok || !snapshot.hasStrictUID || snapshot.strictRuntimeUID != runtimeUID {
		return ErrUnsafeCleanupPath
	}
	return nil
}

// forgetTerminatedStrictJailerProcess atomically validates and retires one
// strict process record. Unknown handles, path/UID drift, and generations
// without positive terminal proof fail closed and leave the record intact.
func (manager *ProcessLifecycleManager) forgetTerminatedStrictJailerProcess(
	handle firecracker.ProcessHandleMetadata,
	paths firecracker.PathPlan,
	runtimeUID uint32,
) error {
	if manager == nil || runtimeUID == 0 {
		return ErrUnsafeCleanupPath
	}
	validatedPaths, hasPaths, err := validatedCleanupPathPlan(paths)
	id := normalizeProcessHandleID(handle)
	if err != nil || !hasPaths || !cleanupPathPlansEqual(validatedPaths, paths) ||
		id == "" || handle.ID != id || handle.Source != processHandleSource {
		return ErrUnsafeCleanupPath
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	tracked, ok := manager.processes[id]
	if !ok || tracked == nil || !tracked.hasPaths || !cleanupPathPlansEqual(tracked.paths, validatedPaths) ||
		!tracked.hasStrictUID || tracked.strictRuntimeUID != runtimeUID {
		return ErrUnsafeCleanupPath
	}
	if !tracked.finished {
		if !hostProcessExitObserved(tracked.process) {
			return errStrictJailerLifecycleInactive
		}
		tracked.finished = true
	}
	delete(manager.processes, id)
	return nil
}
