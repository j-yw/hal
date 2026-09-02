package firecrackerhost

import (
	"context"
	"errors"
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
	handle    firecracker.ProcessHandleMetadata
	hostPaths firecracker.PathPlan
}

type strictJailerLifecycleInspection struct {
	active bool
}

// strictJailerLifecycle is default-off and package-private. It cannot be
// constructed with the legacy direct or asset-FD namespace runner. It owns the
// retained process only; a future outer coordinator must retain and clean the
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
	processRequest, hostPaths, err := validateStrictJailerLifecycleStartRequest(request)
	if err != nil {
		return strictJailerLifecycleProcess{}, errStrictJailerLifecycleInvalid
	}
	handle, err := lifecycle.manager.startStrictJailerProcess(ctx, processRequest, hostPaths)
	if err != nil {
		return strictJailerLifecycleProcess{}, err
	}
	return strictJailerLifecycleProcess{handle: handle, hostPaths: hostPaths}, nil
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
	return lifecycle.manager.validateTrackedProcessPathPlan(process.handle, hostPaths) == nil
}

// startStrictJailerProcess is deliberately separate from StartProcess. It uses
// only the already-correlated host path authority and never parses the
// jail-visible Firecracker arguments for cleanup or polling paths.
func (manager *ProcessLifecycleManager) startStrictJailerProcess(
	ctx context.Context,
	request firecracker.ProcessRunnerStartRequest,
	hostPaths firecracker.PathPlan,
) (firecracker.ProcessHandleMetadata, error) {
	if manager == nil || manager.runner == nil {
		return firecracker.ProcessHandleMetadata{}, dependencyNotConfigured("hostProcessRunner")
	}
	ctx = nonNilContext(ctx)
	if err := ctx.Err(); err != nil {
		return firecracker.ProcessHandleMetadata{}, err
	}
	paths, hasPaths, err := validatedCleanupPathPlan(hostPaths)
	if err != nil || !hasPaths || !cleanupPathPlansEqual(paths, hostPaths) {
		return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, ErrUnsafeCleanupPath)
	}

	var stateIdentity privateStateDirIdentity
	var hasStateIdentity bool
	if manager.productionVsock {
		identity, identityErr := statPrivateFirecrackerStateDir(paths.StateDir)
		if identityErr != nil {
			return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, ErrUnsafeCleanupPath)
		}
		stateIdentity = identity
		hasStateIdentity = true
	}
	if err := manager.removeStaleAPISocketBeforeStart(paths, stateIdentity, hasStateIdentity); err != nil {
		return firecracker.ProcessHandleMetadata{}, err
	}
	if err := manager.removeOwnedStaleVsockBeforeStart(paths, stateIdentity, hasStateIdentity); err != nil {
		return firecracker.ProcessHandleMetadata{}, err
	}

	process, err := manager.runner.StartHostProcess(ctx, cloneProcessRunnerStartRequest(request))
	if err != nil {
		return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, err)
	}
	if interfaceValueIsNil(process) {
		return firecracker.ProcessHandleMetadata{}, newProcessLifecycleError(processOperationStart, ErrHostProcessRequired)
	}
	return manager.storeProcess(process, paths, true, stateIdentity, hasStateIdentity), nil
}

func validateStrictJailerLifecycleStartRequest(
	request strictJailerLifecycleStartRequest,
) (firecracker.ProcessRunnerStartRequest, firecracker.PathPlan, error) {
	processRequest := request.launchPlan.processRequest()
	command, err := parseStrictJailerCommand(processRequest)
	if err != nil {
		return firecracker.ProcessRunnerStartRequest{}, firecracker.PathPlan{}, errStrictJailerLifecycleInvalid
	}
	planHostPaths, hasPlanHostPaths, err := validatedCleanupPathPlan(request.launchPlan.hostPathPlan())
	if err != nil || !hasPlanHostPaths {
		return firecracker.ProcessRunnerStartRequest{}, firecracker.PathPlan{}, errStrictJailerLifecycleInvalid
	}
	authoritativeHostPaths, hasAuthoritativeHostPaths, err := validatedCleanupPathPlan(request.hostPaths)
	if err != nil || !hasAuthoritativeHostPaths || !cleanupPathPlansEqual(planHostPaths, authoritativeHostPaths) {
		return firecracker.ProcessRunnerStartRequest{}, firecracker.PathPlan{}, errStrictJailerLifecycleInvalid
	}
	planJailPaths, hasPlanJailPaths, err := validatedCleanupPathPlan(request.launchPlan.jailPathPlan())
	if err != nil || !hasPlanJailPaths || !cleanupPathPlansEqual(planJailPaths, command.jailPaths) {
		return firecracker.ProcessRunnerStartRequest{}, firecracker.PathPlan{}, errStrictJailerLifecycleInvalid
	}
	jailRoot := filepath.Join(command.chrootBaseDir, filepath.Base(command.firecrackerPath), command.runtimeID, "root")
	expectedHostPaths, err := strictJailerHostPaths(jailRoot, planJailPaths)
	if err != nil || !cleanupPathPlansEqual(expectedHostPaths, authoritativeHostPaths) {
		return firecracker.ProcessRunnerStartRequest{}, firecracker.PathPlan{}, errStrictJailerLifecycleInvalid
	}
	return processRequest, authoritativeHostPaths, nil
}
