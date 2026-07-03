package firecracker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

	targetCapabilityCreation              = "target_creation"
	targetCapabilityDeterministicIdentity = "deterministic_identity"
	targetCapabilityPathRoleMetadata      = "path_role_metadata"
	targetCapabilityProcessBoundary       = "process_boundary"
)

var (
	errBootAcceptanceProcessNotAccepted   = errors.New("host process was not accepted")
	errBootAcceptanceAPISocketUnavailable = errors.New("host-side API socket was not accepted")
)

// BackendOptions configures the Firecracker backend. BaseStateDir is used only
// to derive target-specific path plans. ProcessAdapter prepares process
// descriptors. LiveStart permits StartProcess only when ProcessAdapter,
// BootAcceptanceWaiter, and LiveProcessManager are all explicitly injected. Raw
// paths are not exposed on returned targets.
type BackendOptions struct {
	BaseStateDir         string
	ProcessAdapter       ProcessAdapter
	BootAcceptanceWaiter BootAcceptanceWaiter
	LiveProcessManager   LiveProcessManager
	LiveStart            bool
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
	liveStart            bool
}

// NewBackend constructs an explicitly injected Firecracker backend.
func NewBackend(options BackendOptions) *Backend {
	return &Backend{
		baseStateDir:         strings.TrimSpace(options.BaseStateDir),
		processAdapter:       options.ProcessAdapter,
		bootAcceptanceWaiter: options.BootAcceptanceWaiter,
		liveProcessManager:   options.LiveProcessManager,
		liveStart:            options.LiveStart,
	}
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
				Backend:          BackendID,
				CapabilityLabels: firecrackerTargetCapabilityLabels(),
				PathRoles:        firecrackerTargetPathRoles(config.Paths),
				ProcessLaunch:    processBoundaryAvailableRuntimeMetadata(),
			},
		},
	}, nil
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
	if b != nil {
		baseStateDir = b.baseStateDir
		adapter = b.processAdapter
		waiter = b.bootAcceptanceWaiter
		manager = b.liveProcessManager
	}
	return firecrackerController{
		baseStateDir:         baseStateDir,
		processAdapter:       adapter,
		bootAcceptanceWaiter: waiter,
		liveProcessManager:   manager,
		liveStart:            b != nil && b.liveStart,
	}, nil
}

type firecrackerController struct {
	baseStateDir         string
	processAdapter       ProcessAdapter
	bootAcceptanceWaiter BootAcceptanceWaiter
	liveProcessManager   LiveProcessManager
	liveStart            bool
}

func (c firecrackerController) Start(ctx context.Context, req microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	if err := c.validateLiveBootContract(); err != nil {
		return nil, err
	}
	config, err := c.startBackendConfig(req.Config, req.Target)
	if err != nil {
		return nil, err
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
	if c.liveStart {
		if err := renderLiveBootFiles(config); err != nil {
			return nil, err
		}
		liveLaunch, err := c.startLiveProcess(ctx, operation.ProcessDescriptor, config.Paths)
		if err != nil {
			return nil, err
		}
		processLaunch = liveLaunch
	}
	return firecrackerStartTarget(req.Target, operation.ProcessDescriptor, processLaunch), nil
}

func (c firecrackerController) validateLiveBootContract() error {
	if !c.liveStart {
		return nil
	}
	switch {
	case c.processAdapter == nil:
		return newLiveBootContractError("processAdapter", "live boot requires an injected process adapter")
	case c.bootAcceptanceWaiter == nil:
		return newLiveBootContractError("bootAcceptanceWaiter", "live boot requires an injected host-side acceptance waiter")
	case c.liveProcessManager == nil:
		return newLiveBootContractError("liveProcessManager", "live boot requires an injected live process manager")
	default:
		return nil
	}
}

func (c firecrackerController) startLiveProcess(ctx context.Context, descriptor ProcessCommandDescriptor, paths PathPlan) (*sandboxruntime.RuntimeProcessLaunchMetadata, error) {
	handle, err := StartProcess(ctx, c.processAdapter, descriptor)
	if err != nil {
		return nil, err
	}
	launch, err := c.waitForBootAcceptance(ctx, handle, paths)
	if err != nil {
		return nil, c.cleanupLiveProcessAfterBootAcceptanceFailure(ctx, handle, paths, err)
	}
	return launch, nil
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

func (c firecrackerController) cleanupLiveProcessAfterBootAcceptanceFailure(ctx context.Context, handle ProcessHandleMetadata, paths PathPlan, acceptanceErr error) error {
	cleanupErr := c.cleanupLiveProcess(ctx, LiveProcessRequest{
		Handle: sanitizeProcessHandleMetadata(handle),
		Paths:  paths,
	})
	if cleanupErr == nil {
		return acceptanceErr
	}
	return errors.Join(acceptanceErr, cleanupErr)
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
	plan, err := RenderStopOperationPlan(paths)
	if err != nil {
		return nil, err
	}
	if liveReq, ok := liveProcessRequestFromTarget(req.Target, paths); ok {
		if err := c.stopLiveProcess(ctx, liveReq); err != nil {
			return nil, err
		}
	}
	return firecrackerLifecycleTarget(req.Target, plan.Summary(), sandbox.StatusStopped), nil
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
	if _, err := RenderDeleteOperationPlan(paths); err != nil {
		return err
	}
	if liveReq, ok := liveProcessRequestFromTarget(req.Target, paths); ok {
		return c.deleteLiveProcess(ctx, liveReq)
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

func (c firecrackerController) Inspect(_ context.Context, req microvm.ControllerInspectRequest) (*sandboxruntime.Target, error) {
	plan, err := planFirecrackerInspectOperation(req.Target, c.baseStateDir)
	if err != nil {
		return nil, err
	}
	return firecrackerLifecycleTarget(req.Target, plan.Summary(), ""), nil
}

func (firecrackerController) Exec(_ context.Context, req microvm.ControllerExecRequest) (*sandboxruntime.ExecResult, error) {
	return nil, unsupportedFirecrackerOperation(req.Operation)
}

func (firecrackerController) CopyIn(_ context.Context, req microvm.ControllerCopyRequest) error {
	return unsupportedFirecrackerOperation(req.Operation)
}

func (firecrackerController) CopyOut(_ context.Context, req microvm.ControllerCopyRequest) error {
	return unsupportedFirecrackerOperation(req.Operation)
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

func firecrackerStartTarget(target sandboxruntime.Target, descriptor ProcessCommandDescriptor, processLaunch *sandboxruntime.RuntimeProcessLaunchMetadata) *sandboxruntime.Target {
	started := cloneFirecrackerTarget(target)
	ensureFirecrackerPlanningTarget(&started, target)
	started.Runtime.Metadata.OperationPlan = firecrackerRuntimeOperationPlanMetadata(descriptor)
	if processLaunch != nil {
		started.Runtime.Metadata.ProcessLaunch = cloneRuntimeProcessLaunchMetadata(processLaunch)
	}
	return &started
}

func firecrackerLifecycleTarget(target sandboxruntime.Target, summary OperationPlanSummary, status string) *sandboxruntime.Target {
	planned := cloneFirecrackerTarget(target)
	ensureFirecrackerPlanningTarget(&planned, target)
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

func ensureFirecrackerPlanningTarget(target *sandboxruntime.Target, source sandboxruntime.Target) {
	var processLaunch *sandboxruntime.RuntimeProcessLaunchMetadata
	if target.Runtime.Metadata != nil {
		processLaunch = sanitizeRuntimeProcessLaunchMetadata(target.Runtime.Metadata.ProcessLaunch)
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
		})
	}
	return out
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
	return &copied
}

func cloneFirecrackerRuntimeOperationPlan(plan *sandboxruntime.RuntimeOperationPlan) *sandboxruntime.RuntimeOperationPlan {
	if plan == nil {
		return nil
	}
	copied := *plan
	copied.Environment = append([]sandboxruntime.RuntimeOperationEnvironment(nil), plan.Environment...)
	copied.PathRoles = cloneStringSlice(plan.PathRoles)
	copied.Payloads = append([]sandboxruntime.RuntimeOperationPayload(nil), plan.Payloads...)
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
	copied.Payloads = append([]sandboxruntime.RuntimeOperationPayload(nil), descriptor.Payloads...)
	return &copied
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

func newLiveBootContractError(field, message string) *microvm.OperationError {
	err := microvm.NewInvalidConfigError(liveBootContractOperation, microvm.ErrInvalidConfig)
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}

func newLiveBootAcceptanceFailure(field, message string, cause error) *microvm.OperationError {
	return newLiveDependencyFailure(liveBootAcceptanceOperation, field, message, cause)
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
