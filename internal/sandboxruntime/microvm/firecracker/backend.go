package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

const (
	targetRuntimeIDPrefix = "fc-"

	liveBootContractOperation   = "firecracker_live_boot"
	liveBootAcceptanceOperation = "firecracker_boot_acceptance"
	liveProcessManagerOperation = "firecracker_live_process_manager"
	liveGuestReadinessOperation = "firecracker_guest_readiness"

	targetCapabilityCreation              = "target_creation"
	targetCapabilityDeterministicIdentity = "deterministic_identity"
	targetCapabilityPathRoleMetadata      = "path_role_metadata"
	targetCapabilityProcessBoundary       = "process_boundary"
)

var (
	errBootAcceptanceProcessNotAccepted   = errors.New("host process was not accepted")
	errBootAcceptanceAPISocketUnavailable = errors.New("host-side API socket was not accepted")
	errGuestReadinessNotReady             = errors.New("guest readiness waiter did not report ready")
	errLiveProcessTerminalNotVerified     = errors.New("live process terminal state was not verified")
)

// BackendOptions configures the Firecracker backend. BaseStateDir is used only
// to derive target-specific path plans. ProcessAdapter prepares process
// descriptors. LiveStart permits StartProcess only when ProcessAdapter,
// BootAcceptanceWaiter, and LiveProcessManager are all explicitly injected.
// GuestReadinessWaiter is optional and remains inert until an explicit live
// start path chooses to call it. GuestTransport is optional and only used for
// guest operations after the controller is live-start enabled and target guest
// readiness is ready. NetworkEnforcement carries sanitized metadata only and
// never starts listeners, mutates firewall/runtime state, or enables live
// enforcement. Raw paths are not exposed on returned targets.
type BackendOptions struct {
	BaseStateDir         string
	ProcessAdapter       ProcessAdapter
	BootAcceptanceWaiter BootAcceptanceWaiter
	LiveProcessManager   LiveProcessManager
	GuestReadinessWaiter GuestReadinessWaiter
	GuestTransport       GuestTransport
	NetworkEnforcement   *sandboxruntime.RuntimeNetworkEnforcementMetadata
	LiveStart            bool
	ProductionVsock      bool
	ProductionBridge     ProductionVsockBridge
}

// BootAcceptanceWaiter is the injected host-side readiness boundary for an
// explicitly live-started Firecracker process.
type BootAcceptanceWaiter interface {
	WaitForBootAcceptance(context.Context, BootAcceptanceRequest) (BootAcceptanceResult, error)
}

// BootAcceptanceRequest carries the sanitized process handle and API socket
// path reference used to wait for host-side Firecracker acceptance.
type BootAcceptanceRequest struct {
	Handle    ProcessHandleMetadata
	APISocket OperationPathReference
}

// BootAcceptanceResult reports host-side process and API socket acceptance. It
// does not imply guest boot readiness or guest command availability.
type BootAcceptanceResult struct {
	ProcessAccepted    bool
	APISocketAvailable bool
}

// LiveProcessManager is the injected cleanup boundary for explicitly
// live-started Firecracker host processes. Requests contain only sanitized
// handle metadata and configured Firecracker state paths.
type LiveProcessManager interface {
	CleanupLiveProcess(context.Context, LiveProcessRequest) error
	StopLiveProcess(context.Context, LiveProcessRequest) error
	DeleteLiveProcess(context.Context, LiveProcessRequest) error
}

// LiveProcessTerminalVerifier is the optional positive terminal-state proof
// used before replacing a tracked production-vsock process. A missing verifier
// or a false result fails closed and retains the process ownership proof.
type LiveProcessTerminalVerifier interface {
	LiveProcessTerminated(LiveProcessRequest) bool
}

// LiveProcessRequest identifies the live-started Firecracker process and
// Firecracker-owned state paths that may be used by cleanup implementations.
type LiveProcessRequest struct {
	Handle ProcessHandleMetadata
	Paths  PathPlan
}

// Backend implements the microVM backend boundary for Firecracker target
// creation metadata and fake-safe start planning.
type Backend struct {
	baseStateDir         string
	processAdapter       ProcessAdapter
	bootAcceptanceWaiter BootAcceptanceWaiter
	liveProcessManager   LiveProcessManager
	guestReadinessWaiter GuestReadinessWaiter
	guestTransport       GuestTransport
	networkEnforcement   *sandboxruntime.RuntimeNetworkEnforcementMetadata
	liveStart            bool
	productionVsock      bool
	productionBridge     ProductionVsockBridge
	liveSessions         *liveSessionRegistry
}

// NewBackend constructs an explicitly injected Firecracker backend.
func NewBackend(options BackendOptions) *Backend {
	backend := &Backend{
		baseStateDir:         strings.TrimSpace(options.BaseStateDir),
		processAdapter:       options.ProcessAdapter,
		bootAcceptanceWaiter: options.BootAcceptanceWaiter,
		liveProcessManager:   options.LiveProcessManager,
		guestReadinessWaiter: options.GuestReadinessWaiter,
		guestTransport:       options.GuestTransport,
		networkEnforcement:   sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(options.NetworkEnforcement),
		liveStart:            options.LiveStart,
		productionVsock:      options.ProductionVsock,
		productionBridge:     options.ProductionBridge,
	}
	if options.ProductionVsock {
		backend.liveSessions = newLiveSessionRegistry()
	}
	return backend
}

func (b *Backend) Create(_ context.Context, req microvm.BackendCreateRequest) (*sandboxruntime.Target, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, microvm.NewTargetNameRequiredError(microvm.OperationCreate)
	}

	config, err := BackendConfigFromMicroVMConfig(req.Config)
	if err != nil {
		return nil, err
	}

	runtimeID := firecrackerRuntimeID(name)
	baseStateDir := ""
	if b != nil {
		baseStateDir = b.baseStateDir
	}
	paths, err := backendPathPlan(runtimeID, baseStateDir, config.Paths)
	if err != nil {
		return nil, err
	}
	config.RuntimeID = runtimeID
	config.Paths = paths

	return &sandboxruntime.Target{
		ID:       runtimeID,
		Name:     firecrackerTargetDisplayName(name, runtimeID),
		Provider: BackendID,
		Status:   sandbox.StatusStopped,
		Runtime: sandboxruntime.RuntimeState{
			Driver:    sandboxruntime.DriverMicroVM,
			RuntimeID: runtimeID,
			Metadata: &sandboxruntime.RuntimeMetadata{
				Backend:            BackendID,
				CapabilityLabels:   firecrackerTargetCapabilityLabels(),
				PathRoles:          firecrackerTargetPathRoles(config.Paths),
				ProcessLaunch:      processBoundaryAvailableRuntimeMetadata(),
				NetworkEnforcement: b.runtimeNetworkEnforcementMetadata(),
			},
		},
	}, nil
}

func (b *Backend) runtimeNetworkEnforcementMetadata() *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	if b == nil {
		return nil
	}
	return sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(b.networkEnforcement)
}

func (b *Backend) Controller(_ context.Context, req microvm.ControllerRequest) (microvm.Controller, error) {
	if strings.TrimSpace(req.Target.ID) == "" &&
		strings.TrimSpace(req.Target.Name) == "" &&
		strings.TrimSpace(req.Target.Runtime.RuntimeID) == "" {
		return nil, microvm.NewTargetRequiredError(req.Operation)
	}
	baseStateDir := ""
	var adapter ProcessAdapter
	var waiter BootAcceptanceWaiter
	var manager LiveProcessManager
	var guestWaiter GuestReadinessWaiter
	var guestTransport GuestTransport
	var networkEnforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata
	var productionVsock bool
	var productionBridge ProductionVsockBridge
	var liveSessions *liveSessionRegistry
	if b != nil {
		baseStateDir = b.baseStateDir
		adapter = b.processAdapter
		waiter = b.bootAcceptanceWaiter
		manager = b.liveProcessManager
		guestWaiter = b.guestReadinessWaiter
		guestTransport = b.guestTransport
		networkEnforcement = b.runtimeNetworkEnforcementMetadata()
		productionVsock = b.productionVsock
		productionBridge = b.productionBridge
		liveSessions = b.liveSessions
	}
	return firecrackerController{
		baseStateDir:         baseStateDir,
		processAdapter:       adapter,
		bootAcceptanceWaiter: waiter,
		liveProcessManager:   manager,
		guestReadinessWaiter: guestWaiter,
		guestTransport:       guestTransport,
		networkEnforcement:   networkEnforcement,
		liveStart:            b != nil && b.liveStart,
		productionVsock:      productionVsock,
		productionBridge:     productionBridge,
		liveSessions:         liveSessions,
	}, nil
}

type firecrackerController struct {
	baseStateDir         string
	processAdapter       ProcessAdapter
	bootAcceptanceWaiter BootAcceptanceWaiter
	liveProcessManager   LiveProcessManager
	guestReadinessWaiter GuestReadinessWaiter
	guestTransport       GuestTransport
	networkEnforcement   *sandboxruntime.RuntimeNetworkEnforcementMetadata
	liveStart            bool
	productionVsock      bool
	productionBridge     ProductionVsockBridge
	liveSessions         *liveSessionRegistry
}

func (c firecrackerController) Start(ctx context.Context, req microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	if err := c.validateLiveBootContract(); err != nil {
		return nil, err
	}
	config, err := c.startBackendConfig(req.Config, req.Target)
	if err != nil {
		return nil, err
	}
	releaseLifecycle, err := c.reserveLiveLifecycle(config.RuntimeID)
	if err != nil {
		return nil, err
	}
	defer releaseLifecycle()
	if c.liveStart {
		if err := c.rejectActiveProductionVsockSession(config.RuntimeID); err != nil {
			return nil, err
		}
	}
	adapter := c.processAdapter
	if adapter == nil {
		adapter = startPlanningProcessAdapter{}
	}
	operation, err := planFirecrackerStartOperation(ctx, adapter, config)
	if err != nil {
		return nil, err
	}
	processLaunch := processBoundaryAvailableRuntimeMetadata()
	var guestReadiness *sandboxruntime.RuntimeGuestReadinessMetadata
	if c.liveStart {
		inheritedFiles, err := renderLiveBootFilesForStart(config)
		if err != nil {
			return nil, err
		}
		liveStart, err := c.startLiveProcessWithInheritedFiles(ctx, operation.ProcessDescriptor, config, inheritedFiles)
		if err != nil {
			return nil, err
		}
		processLaunch = liveStart.processLaunch
		guestReadiness = liveStart.guestReadiness
	}
	return firecrackerStartTarget(req.Target, operation.ProcessDescriptor, processLaunch, guestReadiness, c.networkEnforcement), nil
}

func (c firecrackerController) validateLiveBootContract() error {
	if !c.liveStart {
		return nil
	}
	switch {
	case c.productionVsock && (c.guestReadinessWaiter != nil || c.guestTransport != nil):
		return newLiveBootContractError("productionVsock", "production vsock does not accept caller guest readiness or transport")
	case c.processAdapter == nil:
		return newLiveBootContractError("processAdapter", "live boot requires an injected process adapter")
	case c.bootAcceptanceWaiter == nil:
		return newLiveBootContractError("bootAcceptanceWaiter", "live boot requires an injected host-side acceptance waiter")
	case c.liveProcessManager == nil:
		return newLiveBootContractError("liveProcessManager", "live boot requires an injected live process manager")
	case c.productionVsock && c.productionBridge == nil:
		return newLiveBootContractError("productionVsockBridge", "production vsock requires a host-owned bridge")
	default:
		return nil
	}
}

type firecrackerLiveStartResult struct {
	processLaunch  *sandboxruntime.RuntimeProcessLaunchMetadata
	guestReadiness *sandboxruntime.RuntimeGuestReadinessMetadata
}

func (c firecrackerController) startLiveProcess(ctx context.Context, descriptor ProcessCommandDescriptor, config BackendConfig) (firecrackerLiveStartResult, error) {
	return c.startLiveProcessWithInheritedFiles(ctx, descriptor, config, nil)
}

func (c firecrackerController) startLiveProcessWithInheritedFiles(
	ctx context.Context,
	descriptor ProcessCommandDescriptor,
	config BackendConfig,
	inheritedFiles []*os.File,
) (firecrackerLiveStartResult, error) {
	if len(inheritedFiles) > 0 && config.VerifiedL7Assets != nil {
		defer config.VerifiedL7Assets.Close()
	}
	if err := c.rejectActiveProductionVsockSession(config.RuntimeID); err != nil {
		return firecrackerLiveStartResult{}, err
	}
	if c.liveSessions != nil {
		if active, ok := c.liveSessions.ProofForRuntime(config.RuntimeID); ok && c.productionBridge != nil {
			request := ProductionVsockSessionRequest{
				Handle:    ProcessHandleMetadata{ID: active.ProcessGeneration, Source: active.ProcessSource},
				RuntimeID: active.RuntimeID,
			}
			c.productionBridge.InvalidateSession(request, active.BridgeGeneration)
		}
		c.liveSessions.InvalidateRuntime(config.RuntimeID)
	}
	handle, err := startProcessWithInheritedFiles(ctx, c.processAdapter, descriptor, inheritedFiles)
	if err != nil {
		return firecrackerLiveStartResult{}, err
	}
	processProof, terminalVerifiable := liveProcessProofFromHandle(config.RuntimeID, handle)
	if c.liveSessions != nil {
		c.liveSessions.TrackProcess(processProof)
		if !terminalVerifiable {
			return firecrackerLiveStartResult{}, c.cleanupLiveProcessAfterStartFailure(
				ctx,
				handle,
				processProof,
				false,
				config.Paths,
				newProcessBoundaryError("processHandle", "live process handle is unavailable"),
			)
		}
	}
	launch, err := c.waitForBootAcceptance(ctx, handle, config.Paths)
	if err != nil {
		return firecrackerLiveStartResult{}, c.cleanupLiveProcessAfterStartFailure(ctx, handle, processProof, true, config.Paths, err)
	}
	guestReadiness, bridgeGeneration, err := c.waitForGuestReadiness(ctx, handle, config.RuntimeID, config.Paths)
	if err != nil {
		return firecrackerLiveStartResult{}, c.cleanupLiveProcessAfterStartFailure(ctx, handle, processProof, true, config.Paths, err)
	}
	if c.liveSessions != nil && guestReadiness != nil {
		c.liveSessions.Activate(liveSessionProof{
			RuntimeID: config.RuntimeID, ProcessGeneration: handle.ID, ProcessSource: handle.Source, BridgeGeneration: bridgeGeneration,
		})
	}
	return firecrackerLiveStartResult{
		processLaunch:  launch,
		guestReadiness: guestReadiness,
	}, nil
}

func (c firecrackerController) rejectActiveProductionVsockSession(runtimeID string) error {
	if c.liveSessions == nil || c.productionBridge == nil {
		return nil
	}
	if process, ok := c.liveSessions.ProcessForRuntime(runtimeID); ok {
		verifier, verifierOK := c.liveProcessManager.(LiveProcessTerminalVerifier)
		request := LiveProcessRequest{
			Handle: ProcessHandleMetadata{
				ID:     process.ProcessGeneration,
				Source: process.ProcessSource,
			},
		}
		if !verifierOK || !verifier.LiveProcessTerminated(request) {
			return newProcessBoundaryError("runtime", "live process is already active")
		}
		c.invalidateLiveProcessProof(process)
	}
	active, ok := c.liveSessions.ProofForRuntime(runtimeID)
	if !ok {
		return nil
	}
	request := ProductionVsockSessionRequest{
		Handle:    ProcessHandleMetadata{ID: active.ProcessGeneration, Source: active.ProcessSource},
		RuntimeID: active.RuntimeID,
	}
	if c.productionBridge.SessionActive(request, active.BridgeGeneration) {
		return newProcessBoundaryError("runtime", "live process is already active")
	}
	return nil
}

func (c firecrackerController) waitForBootAcceptance(ctx context.Context, handle ProcessHandleMetadata, paths PathPlan) (*sandboxruntime.RuntimeProcessLaunchMetadata, error) {
	result, err := c.bootAcceptanceWaiter.WaitForBootAcceptance(processContext(ctx), BootAcceptanceRequest{
		Handle: sanitizeProcessHandleMetadata(handle),
		APISocket: OperationPathReference{
			Role: OperationPathRoleAPISocket,
			Path: paths.APISocketPath,
		},
	})
	if err != nil {
		return nil, newLiveBootAcceptanceFailure("bootAcceptanceWaiter", liveBootAcceptanceFailureMessage(err), err)
	}
	if !result.ProcessAccepted {
		return nil, newLiveBootAcceptanceFailure("processAccepted", "host process was not accepted", errBootAcceptanceProcessNotAccepted)
	}
	if !result.APISocketAvailable {
		return nil, newLiveBootAcceptanceFailure("apiSocket", "host-side API socket was not accepted", errBootAcceptanceAPISocketUnavailable)
	}
	return NewProcessLaunchMetadata(ProcessLaunchStateAccepted, handle).RuntimeMetadata(), nil
}

func (c firecrackerController) waitForGuestReadiness(ctx context.Context, handle ProcessHandleMetadata, runtimeID string, paths PathPlan) (*sandboxruntime.RuntimeGuestReadinessMetadata, string, error) {
	if c.productionVsock {
		result, generation, err := c.productionBridge.ActivateSession(processContext(ctx), ProductionVsockSessionRequest{
			Handle: sanitizeProcessHandleMetadata(handle), RuntimeID: runtimeID, SocketPath: paths.VsockSocketPath,
		})
		if err != nil {
			return nil, "", newLiveGuestReadinessFailure("productionVsockBridge", liveGuestReadinessFailureMessage(err), err)
		}
		result = SanitizeGuestReadinessResult(result)
		if result.State != sandboxruntime.RuntimeGuestReadinessStateReady || safeFirecrackerMetadataToken(generation) == "" {
			return nil, "", newLiveGuestReadinessFailure("guestReadinessState", "guest readiness was not reported ready", errGuestReadinessNotReady)
		}
		return result.RuntimeMetadata(), generation, nil
	}
	if c.guestReadinessWaiter == nil {
		return nil, "", nil
	}
	result, err := c.guestReadinessWaiter.WaitForGuestReadiness(processContext(ctx), NewGuestReadinessRequest(handle, runtimeID))
	if err != nil {
		return nil, "", newLiveGuestReadinessFailure("guestReadinessWaiter", liveGuestReadinessFailureMessage(err), err)
	}
	result = SanitizeGuestReadinessResult(result)
	if result.State != sandboxruntime.RuntimeGuestReadinessStateReady {
		return nil, "", newLiveGuestReadinessFailure("guestReadinessState", "guest readiness was not reported ready", errGuestReadinessNotReady)
	}
	return result.RuntimeMetadata(), "", nil
}

func (c firecrackerController) cleanupLiveProcessAfterStartFailure(
	ctx context.Context,
	handle ProcessHandleMetadata,
	processProof liveProcessProof,
	terminalVerifiable bool,
	paths PathPlan,
	startErr error,
) error {
	request := LiveProcessRequest{
		Handle: sanitizeProcessHandleMetadata(handle),
		Paths:  paths,
	}
	cleanupErr := c.cleanupLiveProcess(liveStartCleanupContext(ctx), request)
	if cleanupErr == nil {
		if c.liveSessions != nil {
			if !terminalVerifiable {
				return errors.Join(
					startErr,
					newLiveProcessManagerFailure(
						"liveProcessManager",
						"live process cleanup terminal state was not verified",
						errLiveProcessTerminalNotVerified,
					),
				)
			}
			verifier, verifierOK := c.liveProcessManager.(LiveProcessTerminalVerifier)
			if !verifierOK || !verifier.LiveProcessTerminated(request) {
				return errors.Join(
					startErr,
					newLiveProcessManagerFailure(
						"liveProcessManager",
						"live process cleanup terminal state was not verified",
						errLiveProcessTerminalNotVerified,
					),
				)
			}
			c.liveSessions.InvalidateProcess(processProof)
		}
		return startErr
	}
	return errors.Join(startErr, cleanupErr)
}

func liveStartCleanupContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return context.WithoutCancel(ctx)
}

func (c firecrackerController) cleanupLiveProcess(ctx context.Context, req LiveProcessRequest) error {
	if c.liveProcessManager == nil {
		return newLiveBootContractError("liveProcessManager", "live boot requires an injected live process manager")
	}
	if err := c.liveProcessManager.CleanupLiveProcess(processContext(ctx), req); err != nil {
		return newLiveProcessManagerFailure("liveProcessManager", "live process cleanup failed", err)
	}
	return nil
}

func (c firecrackerController) Stop(ctx context.Context, req microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	paths, err := firecrackerLifecyclePathPlan(req.Target, c.baseStateDir)
	if err != nil {
		return nil, err
	}
	releaseLifecycle, err := c.reserveLiveLifecycle(firecrackerStartRuntimeID(req.Target))
	if err != nil {
		return nil, err
	}
	defer releaseLifecycle()
	plan, err := RenderStopOperationPlan(paths)
	if err != nil {
		return nil, err
	}
	liveReq, live, err := c.liveProcessRequestForLifecycle(req.Target, paths)
	if err != nil {
		return nil, err
	}
	if live {
		if err := c.stopLiveProcess(ctx, liveReq); err != nil {
			return nil, err
		}
		c.invalidateLiveProcess(req.Target)
	}
	return firecrackerLifecycleTarget(req.Target, plan.Summary(), sandbox.StatusStopped, c.networkEnforcement), nil
}

func (c firecrackerController) stopLiveProcess(ctx context.Context, req LiveProcessRequest) error {
	if c.liveProcessManager == nil {
		return newLiveBootContractError("liveProcessManager", "live boot requires an injected live process manager")
	}
	if err := c.liveProcessManager.StopLiveProcess(processContext(ctx), req); err != nil {
		return newLiveProcessManagerFailure("liveProcessManager", "live process stop failed", err)
	}
	return nil
}

func (c firecrackerController) Delete(ctx context.Context, req microvm.ControllerLifecycleRequest) error {
	paths, err := firecrackerLifecyclePathPlan(req.Target, c.baseStateDir)
	if err != nil {
		return err
	}
	releaseLifecycle, err := c.reserveLiveLifecycle(firecrackerStartRuntimeID(req.Target))
	if err != nil {
		return err
	}
	defer releaseLifecycle()
	if _, err := RenderDeleteOperationPlan(paths); err != nil {
		return err
	}
	liveReq, live, err := c.liveProcessRequestForLifecycle(req.Target, paths)
	if err != nil {
		return err
	}
	if live {
		if err := c.deleteLiveProcess(ctx, liveReq); err != nil {
			return err
		}
		c.invalidateLiveProcess(req.Target)
	}
	return nil
}

func (c firecrackerController) deleteLiveProcess(ctx context.Context, req LiveProcessRequest) error {
	if c.liveProcessManager == nil {
		return newLiveBootContractError("liveProcessManager", "live boot requires an injected live process manager")
	}
	if err := c.liveProcessManager.DeleteLiveProcess(processContext(ctx), req); err != nil {
		return newLiveProcessManagerFailure("liveProcessManager", "live process delete failed", err)
	}
	return nil
}

func (c firecrackerController) liveProcessRequestForLifecycle(target sandboxruntime.Target, paths PathPlan) (LiveProcessRequest, bool, error) {
	request, accepted := liveProcessRequestFromTarget(target, paths)
	if c.liveSessions == nil {
		return request, accepted, nil
	}
	active, activeExists := c.liveSessions.ProcessForRuntime(firecrackerStartRuntimeID(target))
	if !activeExists {
		return request, accepted, nil
	}
	if active.unverified ||
		!accepted ||
		request.Handle.ID != active.ProcessGeneration ||
		request.Handle.Source != active.ProcessSource {
		return LiveProcessRequest{}, false, newProcessBoundaryError(
			"processHandle",
			"live process handle is stale or unavailable",
		)
	}
	return request, true, nil
}

func (c firecrackerController) reserveLiveLifecycle(runtimeID string) (func(), error) {
	if !c.liveStart || c.liveSessions == nil {
		return func() {}, nil
	}
	if !c.liveSessions.ReserveLifecycle(runtimeID) {
		return nil, newProcessBoundaryError("runtime", "live lifecycle operation is already in progress")
	}
	return func() {
		c.liveSessions.ReleaseLifecycle(runtimeID)
	}, nil
}

func (c firecrackerController) Inspect(_ context.Context, req microvm.ControllerInspectRequest) (*sandboxruntime.Target, error) {
	plan, err := planFirecrackerInspectOperation(req.Target, c.baseStateDir)
	if err != nil {
		return nil, err
	}
	return firecrackerLifecycleTarget(req.Target, plan.Summary(), "", c.networkEnforcement), nil
}

func (c firecrackerController) Exec(ctx context.Context, req microvm.ControllerExecRequest) (*sandboxruntime.ExecResult, error) {
	if !c.canDelegateGuestTransport(req.Target) {
		return nil, unsupportedFirecrackerOperation(req.Operation)
	}
	transport := c.activeGuestTransport()
	result, err := transport.Exec(processContext(ctx), GuestExecRequest{
		Target:  req.Target,
		Args:    req.Args,
		Env:     req.Env,
		WorkDir: req.WorkDir,
		Stdin:   req.Stdin,
		Stdout:  req.Stdout,
		Stderr:  req.Stderr,
	})
	if err != nil {
		if shouldInvalidateGuestTransportSession(err) {
			c.invalidateGuestSession(req.Target)
		}
		return nil, newGuestTransportExecFailure(req.Operation, err)
	}
	return result, nil
}

func shouldInvalidateGuestTransportSession(err error) bool {
	return err != nil &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded)
}

func (c firecrackerController) CopyIn(ctx context.Context, req microvm.ControllerCopyRequest) error {
	if !c.canDelegateGuestTransport(req.Target) {
		return unsupportedFirecrackerOperation(req.Operation)
	}
	err := c.activeGuestTransport().CopyIn(processContext(ctx), GuestCopyRequest{
		Target:          req.Target,
		SourcePath:      req.SourcePath,
		DestinationPath: req.DestinationPath,
	})
	if err != nil {
		if shouldInvalidateGuestTransportSession(err) {
			c.invalidateGuestSession(req.Target)
		}
		return newGuestTransportCopyInFailure(req.Operation, err)
	}
	return nil
}

func (c firecrackerController) CopyOut(ctx context.Context, req microvm.ControllerCopyRequest) error {
	if !c.canDelegateGuestTransport(req.Target) {
		return unsupportedFirecrackerOperation(req.Operation)
	}
	err := c.activeGuestTransport().CopyOut(processContext(ctx), GuestCopyRequest{
		Target:          req.Target,
		SourcePath:      req.SourcePath,
		DestinationPath: req.DestinationPath,
	})
	if err != nil {
		if shouldInvalidateGuestTransportSession(err) {
			c.invalidateGuestSession(req.Target)
		}
		return newGuestTransportCopyOutFailure(req.Operation, err)
	}
	return nil
}

func (c firecrackerController) canDelegateGuestTransport(target sandboxruntime.Target) bool {
	if !c.liveStart || c.activeGuestTransport() == nil || target.Runtime.Metadata == nil {
		return false
	}
	readiness := sandboxruntime.SanitizeRuntimeGuestReadinessMetadata(target.Runtime.Metadata.GuestReadiness)
	if !c.productionVsock {
		return readiness != nil && readiness.State == sandboxruntime.RuntimeGuestReadinessStateReady
	}
	process := sanitizeRuntimeProcessLaunchMetadata(target.Runtime.Metadata.ProcessLaunch)
	if c.liveSessions == nil || readiness == nil || readiness.State != sandboxruntime.RuntimeGuestReadinessStateReady || process == nil {
		return false
	}
	proof, ok := c.liveSessions.Proof(firecrackerStartRuntimeID(target), process.ProcessID)
	if !ok {
		return false
	}
	req := ProductionVsockSessionRequest{Handle: ProcessHandleMetadata{ID: process.ProcessID, Source: proof.ProcessSource}, RuntimeID: proof.RuntimeID}
	if c.productionBridge.SessionActive(req, proof.BridgeGeneration) {
		return true
	}
	c.liveSessions.Invalidate(proof)
	return false
}

func (c firecrackerController) activeGuestTransport() GuestTransport {
	if c.productionVsock {
		return c.productionBridge
	}
	return c.guestTransport
}

func (c firecrackerController) invalidateGuestSession(target sandboxruntime.Target) {
	if !c.productionVsock || c.productionBridge == nil || c.liveSessions == nil || target.Runtime.Metadata == nil {
		return
	}
	process := sanitizeRuntimeProcessLaunchMetadata(target.Runtime.Metadata.ProcessLaunch)
	if process == nil {
		return
	}
	proof, ok := c.liveSessions.Proof(firecrackerStartRuntimeID(target), process.ProcessID)
	if !ok {
		return
	}
	c.productionBridge.InvalidateSession(ProductionVsockSessionRequest{
		Handle:    ProcessHandleMetadata{ID: process.ProcessID, Source: proof.ProcessSource},
		RuntimeID: proof.RuntimeID,
	}, proof.BridgeGeneration)
	c.liveSessions.Invalidate(proof)
}

func (c firecrackerController) invalidateLiveProcess(target sandboxruntime.Target) {
	if c.liveSessions == nil || target.Runtime.Metadata == nil {
		return
	}
	process := sanitizeRuntimeProcessLaunchMetadata(target.Runtime.Metadata.ProcessLaunch)
	if process == nil {
		return
	}
	proof, ok := c.liveSessions.Process(firecrackerStartRuntimeID(target), process.ProcessID)
	if !ok {
		return
	}
	c.invalidateLiveProcessProof(proof)
}

func (c firecrackerController) invalidateLiveProcessProof(proof liveProcessProof) {
	if c.liveSessions == nil {
		return
	}
	if session, ok := c.liveSessions.Proof(proof.RuntimeID, proof.ProcessGeneration); ok {
		if c.productionBridge != nil {
			c.productionBridge.InvalidateSession(ProductionVsockSessionRequest{
				Handle: ProcessHandleMetadata{
					ID:     proof.ProcessGeneration,
					Source: proof.ProcessSource,
				},
				RuntimeID: proof.RuntimeID,
			}, session.BridgeGeneration)
		}
		c.liveSessions.Invalidate(session)
	}
	c.liveSessions.InvalidateProcess(proof)
}

type firecrackerStartOperation struct {
	Plan              StartOperationPlan
	ProcessDescriptor ProcessCommandDescriptor
}

type startPlanningProcessAdapter struct{}

func (startPlanningProcessAdapter) PrepareStartCommand(_ context.Context, req ProcessStartCommandRequest) (ProcessCommandDescriptor, error) {
	return ProcessCommandDescriptorFromStartPlan(req.Plan)
}

func (startPlanningProcessAdapter) StartProcess(context.Context, ProcessStartRequest) (ProcessHandleMetadata, error) {
	return ProcessHandleMetadata{}, newProcessBoundaryError("processAdapter", "process start is not available during start planning")
}

func (c firecrackerController) startBackendConfig(input microvm.Config, target sandboxruntime.Target) (BackendConfig, error) {
	config, err := BackendConfigFromMicroVMConfig(input)
	if err != nil {
		return BackendConfig{}, err
	}
	runtimeID := firecrackerStartRuntimeID(target)
	paths, err := backendPathPlan(runtimeID, c.baseStateDir, config.Paths)
	if err != nil {
		return BackendConfig{}, err
	}
	config.RuntimeID = runtimeID
	config.Paths = paths
	config.ProductionVsock = c.productionVsock
	return config, nil
}

func planFirecrackerStartOperation(ctx context.Context, adapter ProcessAdapter, config BackendConfig) (firecrackerStartOperation, error) {
	plan, err := RenderStartOperationPlan(config)
	if err != nil {
		return firecrackerStartOperation{}, err
	}
	descriptor, err := PrepareStartCommand(ctx, adapter, plan)
	if err != nil {
		return firecrackerStartOperation{}, err
	}
	return firecrackerStartOperation{
		Plan:              plan,
		ProcessDescriptor: descriptor,
	}, nil
}

func planFirecrackerStopOperation(target sandboxruntime.Target, baseStateDir string) (StopOperationPlan, error) {
	paths, err := firecrackerLifecyclePathPlan(target, baseStateDir)
	if err != nil {
		return StopOperationPlan{}, err
	}
	return RenderStopOperationPlan(paths)
}

func planFirecrackerInspectOperation(target sandboxruntime.Target, baseStateDir string) (InspectOperationPlan, error) {
	paths, err := firecrackerLifecyclePathPlan(target, baseStateDir)
	if err != nil {
		return InspectOperationPlan{}, err
	}
	return RenderInspectOperationPlan(paths)
}

func planFirecrackerDeleteOperation(target sandboxruntime.Target, baseStateDir string) (DeleteOperationPlan, error) {
	paths, err := firecrackerLifecyclePathPlan(target, baseStateDir)
	if err != nil {
		return DeleteOperationPlan{}, err
	}
	return RenderDeleteOperationPlan(paths)
}

func firecrackerLifecyclePathPlan(target sandboxruntime.Target, baseStateDir string) (PathPlan, error) {
	return PlanPaths(PathPlanRequest{
		RuntimeID:    firecrackerStartRuntimeID(target),
		BaseStateDir: baseStateDir,
	})
}

func backendPathPlan(runtimeID, baseStateDir string, fallback PathPlan) (PathPlan, error) {
	if strings.TrimSpace(baseStateDir) != "" {
		return PlanPaths(PathPlanRequest{
			RuntimeID:    runtimeID,
			BaseStateDir: baseStateDir,
		})
	}
	return fallback, nil
}

func firecrackerStartRuntimeID(target sandboxruntime.Target) string {
	for _, candidate := range []string{
		target.Runtime.RuntimeID,
		target.ID,
	} {
		if value := strings.TrimSpace(candidate); value != "" {
			return value
		}
	}
	if name := strings.TrimSpace(target.Name); name != "" {
		return firecrackerRuntimeID(name)
	}
	return ""
}

func firecrackerStartTarget(target sandboxruntime.Target, descriptor ProcessCommandDescriptor, processLaunch *sandboxruntime.RuntimeProcessLaunchMetadata, guestReadiness *sandboxruntime.RuntimeGuestReadinessMetadata, networkEnforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata) *sandboxruntime.Target {
	started := cloneFirecrackerTarget(target)
	ensureFirecrackerPlanningTarget(&started, target, networkEnforcement)
	started.Runtime.Metadata.OperationPlan = firecrackerRuntimeOperationPlanMetadata(descriptor)
	if processLaunch != nil {
		started.Runtime.Metadata.ProcessLaunch = cloneRuntimeProcessLaunchMetadata(processLaunch)
	}
	if guestReadiness != nil {
		started.Runtime.Metadata.GuestReadiness = sandboxruntime.SanitizeRuntimeGuestReadinessMetadata(guestReadiness)
	}
	return &started
}

func firecrackerLifecycleTarget(target sandboxruntime.Target, summary OperationPlanSummary, status string, networkEnforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata) *sandboxruntime.Target {
	planned := cloneFirecrackerTarget(target)
	ensureFirecrackerPlanningTarget(&planned, target, networkEnforcement)
	if strings.TrimSpace(status) != "" {
		planned.Status = status
	}
	planned.Runtime.Metadata.OperationPlan = firecrackerRuntimeOperationPlanSummaryMetadata(summary)
	return &planned
}

func liveProcessRequestFromTarget(target sandboxruntime.Target, paths PathPlan) (LiveProcessRequest, bool) {
	if target.Runtime.Metadata == nil {
		return LiveProcessRequest{}, false
	}
	processLaunch := sanitizeRuntimeProcessLaunchMetadata(target.Runtime.Metadata.ProcessLaunch)
	if processLaunch == nil || processLaunch.State != string(ProcessLaunchStateAccepted) {
		return LiveProcessRequest{}, false
	}
	return LiveProcessRequest{
		Handle: sanitizeProcessHandleMetadata(ProcessHandleMetadata{
			ID:     processLaunch.ProcessID,
			Source: processLaunch.ProcessIDSource,
		}),
		Paths: paths,
	}, true
}

func ensureFirecrackerPlanningTarget(target *sandboxruntime.Target, source sandboxruntime.Target, fallbackNetworkEnforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata) {
	var processLaunch *sandboxruntime.RuntimeProcessLaunchMetadata
	var networkEnforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata
	if target.Runtime.Metadata != nil {
		processLaunch = sanitizeRuntimeProcessLaunchMetadata(target.Runtime.Metadata.ProcessLaunch)
		networkEnforcement = sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(target.Runtime.Metadata.NetworkEnforcement)
	}
	if networkEnforcement == nil {
		networkEnforcement = sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(fallbackNetworkEnforcement)
	}
	if strings.TrimSpace(target.Provider) == "" {
		target.Provider = BackendID
	}
	if strings.TrimSpace(target.Status) == "" {
		target.Status = sandbox.StatusUnknown
	}
	if strings.TrimSpace(target.Runtime.Driver) == "" {
		target.Runtime.Driver = sandboxruntime.DriverMicroVM
	}
	if strings.TrimSpace(target.Runtime.RuntimeID) == "" {
		target.Runtime.RuntimeID = firecrackerStartRuntimeID(source)
	}
	if strings.TrimSpace(target.ID) == "" {
		target.ID = target.Runtime.RuntimeID
	}
	if target.Runtime.Metadata == nil {
		target.Runtime.Metadata = &sandboxruntime.RuntimeMetadata{}
	}
	target.Runtime.Metadata.Backend = BackendID
	target.Runtime.Metadata.CapabilityLabels = firecrackerTargetCapabilityLabels()
	target.Runtime.Metadata.PathRoles = firecrackerTargetPathRoleLabels()
	if processLaunch == nil {
		processLaunch = processBoundaryAvailableRuntimeMetadata()
	}
	target.Runtime.Metadata.ProcessLaunch = processLaunch
	target.Runtime.Metadata.GuestReadiness = nil
	target.Runtime.Metadata.NetworkEnforcement = networkEnforcement
}

func firecrackerRuntimeOperationPlanMetadata(descriptor ProcessCommandDescriptor) *sandboxruntime.RuntimeOperationPlan {
	summary := descriptor.Summary()
	metadata := firecrackerRuntimeOperationPlanSummaryMetadata(summary)
	metadata.ProcessDescriptor = &sandboxruntime.RuntimeProcessDescriptor{
		Action:         string(summary.Action),
		ExecutableRole: string(summary.ExecutableRole),
		Argv:           runtimeOperationArguments(summary.Argv),
		Environment:    runtimeOperationEnvironment(summary.Environment),
		PathRoles:      runtimeOperationPathRoles(summary.PathRoles),
		Payloads:       runtimeOperationPayloads(summary.Payloads),
	}
	return metadata
}

func firecrackerRuntimeOperationPlanSummaryMetadata(summary OperationPlanSummary) *sandboxruntime.RuntimeOperationPlan {
	return &sandboxruntime.RuntimeOperationPlan{
		Action:      string(summary.Action),
		Environment: runtimeOperationEnvironment(summary.Environment),
		PathRoles:   runtimeOperationPathRoles(summary.PathRoles),
		Payloads:    runtimeOperationPayloads(summary.Payloads),
	}
}

func runtimeOperationArguments(arguments []OperationArgumentSummary) []sandboxruntime.RuntimeOperationArgument {
	if len(arguments) == 0 {
		return []sandboxruntime.RuntimeOperationArgument{}
	}
	out := make([]sandboxruntime.RuntimeOperationArgument, 0, len(arguments))
	for _, argument := range arguments {
		out = append(out, sandboxruntime.RuntimeOperationArgument{
			Value:    argument.Value,
			PathRole: string(argument.PathRole),
		})
	}
	return out
}

func runtimeOperationEnvironment(environment []OperationEnvironmentMetadata) []sandboxruntime.RuntimeOperationEnvironment {
	if len(environment) == 0 {
		return []sandboxruntime.RuntimeOperationEnvironment{}
	}
	out := make([]sandboxruntime.RuntimeOperationEnvironment, 0, len(environment))
	for _, entry := range environment {
		out = append(out, sandboxruntime.RuntimeOperationEnvironment{
			Name:   entry.Name,
			Source: entry.Source,
		})
	}
	return out
}

func runtimeOperationPathRoles(pathRoles []OperationPathRole) []string {
	if len(pathRoles) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(pathRoles))
	for _, role := range pathRoles {
		out = append(out, string(role))
	}
	return out
}

func runtimeOperationPayloads(payloads []OperationPayloadReference) []sandboxruntime.RuntimeOperationPayload {
	if len(payloads) == 0 {
		return []sandboxruntime.RuntimeOperationPayload{}
	}
	out := make([]sandboxruntime.RuntimeOperationPayload, 0, len(payloads))
	for _, payload := range payloads {
		out = append(out, sandboxruntime.RuntimeOperationPayload{
			Role:    string(payload.Role),
			APIPath: payload.APIPath,
			Assets:  runtimeOperationPayloadAssets(payload.Assets),
		})
	}
	return out
}

func runtimeOperationPayloadAssets(assets []OperationPayloadAssetMetadata) []sandboxruntime.RuntimeOperationPayloadAsset {
	if len(assets) == 0 {
		return nil
	}
	out := make([]sandboxruntime.RuntimeOperationPayloadAsset, 0, len(assets))
	for _, asset := range assets {
		out = append(out, sandboxruntime.RuntimeOperationPayloadAsset{
			AssetRole: asset.AssetRole,
			ID:        asset.ID,
			Labels:    cloneStringSlice(asset.Labels),
			Digest:    runtimeOperationPayloadDigest(asset.Digest),
		})
	}
	return out
}

func runtimeOperationPayloadDigest(digest *OperationPayloadDigestMetadata) *sandboxruntime.RuntimeOperationPayloadDigest {
	if digest == nil {
		return nil
	}
	return &sandboxruntime.RuntimeOperationPayloadDigest{
		Algorithm: digest.Algorithm,
		Value:     digest.Value,
	}
}

func cloneFirecrackerTarget(target sandboxruntime.Target) sandboxruntime.Target {
	target.Runtime.Metadata = cloneFirecrackerRuntimeMetadata(target.Runtime.Metadata)
	return target
}

func cloneFirecrackerRuntimeMetadata(metadata *sandboxruntime.RuntimeMetadata) *sandboxruntime.RuntimeMetadata {
	if metadata == nil {
		return nil
	}
	copied := *metadata
	copied.CapabilityLabels = cloneStringSlice(metadata.CapabilityLabels)
	copied.PathRoles = cloneStringSlice(metadata.PathRoles)
	copied.OperationPlan = cloneFirecrackerRuntimeOperationPlan(metadata.OperationPlan)
	copied.ProcessLaunch = cloneRuntimeProcessLaunchMetadata(metadata.ProcessLaunch)
	copied.GuestReadiness = sandboxruntime.SanitizeRuntimeGuestReadinessMetadata(metadata.GuestReadiness)
	copied.NetworkEnforcement = sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(metadata.NetworkEnforcement)
	return &copied
}

func cloneFirecrackerRuntimeOperationPlan(plan *sandboxruntime.RuntimeOperationPlan) *sandboxruntime.RuntimeOperationPlan {
	if plan == nil {
		return nil
	}
	copied := *plan
	copied.Environment = append([]sandboxruntime.RuntimeOperationEnvironment(nil), plan.Environment...)
	copied.PathRoles = cloneStringSlice(plan.PathRoles)
	copied.Payloads = cloneFirecrackerRuntimeOperationPayloads(plan.Payloads)
	copied.ProcessDescriptor = cloneFirecrackerRuntimeProcessDescriptor(plan.ProcessDescriptor)
	return &copied
}

func cloneFirecrackerRuntimeProcessDescriptor(descriptor *sandboxruntime.RuntimeProcessDescriptor) *sandboxruntime.RuntimeProcessDescriptor {
	if descriptor == nil {
		return nil
	}
	copied := *descriptor
	copied.Argv = append([]sandboxruntime.RuntimeOperationArgument(nil), descriptor.Argv...)
	copied.Environment = append([]sandboxruntime.RuntimeOperationEnvironment(nil), descriptor.Environment...)
	copied.PathRoles = cloneStringSlice(descriptor.PathRoles)
	copied.Payloads = cloneFirecrackerRuntimeOperationPayloads(descriptor.Payloads)
	return &copied
}

func cloneFirecrackerRuntimeOperationPayloads(payloads []sandboxruntime.RuntimeOperationPayload) []sandboxruntime.RuntimeOperationPayload {
	if payloads == nil {
		return nil
	}
	out := make([]sandboxruntime.RuntimeOperationPayload, len(payloads))
	for i, payload := range payloads {
		out[i] = payload
		out[i].Assets = cloneFirecrackerRuntimeOperationPayloadAssets(payload.Assets)
	}
	return out
}

func cloneFirecrackerRuntimeOperationPayloadAssets(assets []sandboxruntime.RuntimeOperationPayloadAsset) []sandboxruntime.RuntimeOperationPayloadAsset {
	if assets == nil {
		return nil
	}
	out := make([]sandboxruntime.RuntimeOperationPayloadAsset, len(assets))
	for i, asset := range assets {
		out[i] = asset
		out[i].Labels = cloneStringSlice(asset.Labels)
		if asset.Digest != nil {
			digest := *asset.Digest
			out[i].Digest = &digest
		}
	}
	return out
}

func sanitizeRuntimeProcessLaunchMetadata(metadata *sandboxruntime.RuntimeProcessLaunchMetadata) *sandboxruntime.RuntimeProcessLaunchMetadata {
	if metadata == nil {
		return nil
	}
	return SanitizeProcessLaunchMetadata(ProcessLaunchMetadata{
		State:           ProcessLaunchState(metadata.State),
		ProcessID:       metadata.ProcessID,
		ProcessIDSource: metadata.ProcessIDSource,
	}).RuntimeMetadata()
}

func unsupportedFirecrackerOperation(operation string) error {
	if strings.TrimSpace(operation) == "" {
		operation = "firecracker_backend"
	}
	return microvm.NewUnavailableCapabilityError(operation, errors.New("firecracker backend operation is not supported in this phase"))
}

func newGuestTransportExecFailure(operation string, cause error) *microvm.OperationError {
	if strings.TrimSpace(operation) == "" {
		operation = microvm.OperationExec
	}
	if cause == nil {
		cause = errors.New("guest transport exec failed")
	}
	err := microvm.NewBackendOperationFailedError(operation, sanitizedGuestTransportCause{cause: cause})
	err.Field = "guestTransport"
	err.Message = "guest transport exec failed"
	return err
}

func newGuestTransportCopyInFailure(operation string, cause error) *microvm.OperationError {
	if strings.TrimSpace(operation) == "" {
		operation = microvm.OperationCopyIn
	}
	if cause == nil {
		cause = errors.New("guest transport copy in failed")
	}
	var publicationError GuestCopyPublicationError
	if errors.As(cause, &publicationError) && publicationError.CopyPublicationDurabilityUncertain() {
		err := microvm.NewOperationError(microvm.ErrorCodeDurabilityUncertain, operation, microvm.ErrDurabilityUncertain)
		err.Field = "guestTransport"
		err.Message = "guest copy publication durability is uncertain"
		return err
	}
	err := microvm.NewBackendOperationFailedError(operation, sanitizedGuestTransportCause{cause: cause})
	err.Field = "guestTransport"
	err.Message = "guest transport copy in failed"
	return err
}

func newGuestTransportCopyOutFailure(operation string, cause error) *microvm.OperationError {
	if strings.TrimSpace(operation) == "" {
		operation = microvm.OperationCopyOut
	}
	if cause == nil {
		cause = errors.New("guest transport copy out failed")
	}
	err := microvm.NewBackendOperationFailedError(operation, sanitizedGuestTransportCause{cause: cause})
	err.Field = "guestTransport"
	err.Message = "guest transport copy out failed"
	return err
}

type sanitizedGuestTransportCause struct {
	cause error
}

func (err sanitizedGuestTransportCause) Error() string {
	return "guest transport failed"
}

func (err sanitizedGuestTransportCause) Is(target error) bool {
	return target != nil && errors.Is(err.cause, target)
}

func newLiveBootContractError(field, message string) *microvm.OperationError {
	err := microvm.NewInvalidConfigError(liveBootContractOperation, microvm.ErrInvalidConfig)
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}

func newLiveBootAcceptanceFailure(field, message string, cause error) *microvm.OperationError {
	return newLiveDependencyFailure(liveBootAcceptanceOperation, field, message, cause)
}

func newLiveGuestReadinessFailure(field, message string, cause error) *microvm.OperationError {
	return newLiveDependencyFailure(liveGuestReadinessOperation, field, message, cause)
}

func newLiveProcessManagerFailure(field, message string, cause error) *microvm.OperationError {
	return newLiveDependencyFailure(liveProcessManagerOperation, field, message, cause)
}

func newLiveDependencyFailure(operation, field, message string, cause error) *microvm.OperationError {
	if cause == nil {
		cause = errors.New(message)
	}
	err := microvm.NewBackendOperationFailedError(operation, sanitizedLiveDependencyCause{
		detail: sanitizedLiveDependencyDetail(operation, cause),
		cause:  cause,
	})
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}

func liveBootAcceptanceFailureMessage(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "host-side boot acceptance timed out"
	}
	return "host-side boot acceptance failed"
}

func liveGuestReadinessFailureMessage(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "guest readiness timed out"
	}
	return "guest readiness failed"
}

func sanitizedLiveDependencyDetail(operation string, cause error) string {
	if cause == nil {
		return ""
	}
	return sanitizeFirecrackerFailureDetail(operation, cause)
}

func sanitizeFirecrackerFailureDetail(operation string, cause error) string {
	if cause == nil {
		return ""
	}
	sanitized := microvm.NewBackendOperationFailedError(operation, cause)
	return sanitizeProcessBoundaryAdapterDetail(sanitized.Error())
}

type sanitizedLiveDependencyCause struct {
	detail string
	cause  error
}

func (err sanitizedLiveDependencyCause) Error() string {
	if detail := strings.TrimSpace(err.detail); detail != "" {
		return detail
	}
	return "live Firecracker dependency failed"
}

func (err sanitizedLiveDependencyCause) Is(target error) bool {
	return target != nil && errors.Is(err.cause, target)
}

func firecrackerRuntimeID(name string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(name)))
	encoded := hex.EncodeToString(sum[:])
	return targetRuntimeIDPrefix + encoded[:24]
}

func firecrackerTargetDisplayName(name, runtimeID string) string {
	if safe := safeFirecrackerMetadataToken(name); safe != "" {
		return safe
	}
	return runtimeID
}

func safeFirecrackerMetadataToken(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxPathPlanRuntimeIDBytes || unsafeFirecrackerMetadataValue(value) {
		return ""
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return ""
		}
	}
	return value
}

func unsafeFirecrackerMetadataValue(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"/",
		"\\",
		"token",
		"secret",
		"password",
		"credential",
		"authorization",
		"bearer",
		"api_key",
		"apikey",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func firecrackerTargetCapabilityLabels() []string {
	return []string{
		targetCapabilityCreation,
		targetCapabilityDeterministicIdentity,
		targetCapabilityPathRoleMetadata,
		targetCapabilityProcessBoundary,
	}
}

func firecrackerTargetPathRoles(paths PathPlan) []string {
	if paths == (PathPlan{}) {
		return []string{}
	}
	return firecrackerTargetPathRoleLabels()
}

func firecrackerTargetPathRoleLabels() []string {
	return []string{
		string(OperationPathRoleStateDir),
		string(OperationPathRoleAPISocket),
		string(OperationPathRoleConfig),
		string(OperationPathRoleLog),
		string(OperationPathRoleMetrics),
	}
}
