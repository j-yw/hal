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

	targetCapabilityCreation              = "target_creation"
	targetCapabilityDeterministicIdentity = "deterministic_identity"
	targetCapabilityPathRoleMetadata      = "path_role_metadata"
	targetCapabilityProcessBoundary       = "process_boundary"
)

// BackendOptions configures the metadata-only Firecracker backend. BaseStateDir
// is used only to derive target-specific path plans; ProcessAdapter prepares
// process descriptors without starting processes. Raw paths are not exposed on
// returned targets.
type BackendOptions struct {
	BaseStateDir   string
	ProcessAdapter ProcessAdapter
}

// Backend implements the microVM backend boundary for Firecracker target
// creation metadata and fake-safe start planning.
type Backend struct {
	baseStateDir   string
	processAdapter ProcessAdapter
}

// NewBackend constructs an explicitly injected Firecracker backend.
func NewBackend(options BackendOptions) *Backend {
	return &Backend{
		baseStateDir:   strings.TrimSpace(options.BaseStateDir),
		processAdapter: options.ProcessAdapter,
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
	paths, err := PlanPaths(PathPlanRequest{
		RuntimeID:    runtimeID,
		BaseStateDir: baseStateDir,
	})
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
	if b != nil {
		baseStateDir = b.baseStateDir
		adapter = b.processAdapter
	}
	if adapter == nil {
		adapter = startPlanningProcessAdapter{}
	}
	return firecrackerController{
		baseStateDir:   baseStateDir,
		processAdapter: adapter,
	}, nil
}

type firecrackerController struct {
	baseStateDir   string
	processAdapter ProcessAdapter
}

func (c firecrackerController) Start(ctx context.Context, req microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	config, err := c.startBackendConfig(req.Config, req.Target)
	if err != nil {
		return nil, err
	}
	operation, err := planFirecrackerStartOperation(ctx, c.processAdapter, config)
	if err != nil {
		return nil, err
	}
	return firecrackerStartTarget(req.Target, operation.ProcessDescriptor), nil
}

func (c firecrackerController) Stop(_ context.Context, req microvm.ControllerLifecycleRequest) (*sandboxruntime.Target, error) {
	plan, err := planFirecrackerStopOperation(req.Target, c.baseStateDir)
	if err != nil {
		return nil, err
	}
	return firecrackerLifecycleTarget(req.Target, plan.Summary(), sandbox.StatusStopped), nil
}

func (c firecrackerController) Delete(_ context.Context, req microvm.ControllerLifecycleRequest) error {
	_, err := planFirecrackerDeleteOperation(req.Target, c.baseStateDir)
	return err
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
	paths, err := PlanPaths(PathPlanRequest{
		RuntimeID:    runtimeID,
		BaseStateDir: c.baseStateDir,
	})
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

func firecrackerStartTarget(target sandboxruntime.Target, descriptor ProcessCommandDescriptor) *sandboxruntime.Target {
	started := cloneFirecrackerTarget(target)
	ensureFirecrackerPlanningTarget(&started, target)
	started.Runtime.Metadata.OperationPlan = firecrackerRuntimeOperationPlanMetadata(descriptor)
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

func ensureFirecrackerPlanningTarget(target *sandboxruntime.Target, source sandboxruntime.Target) {
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

func unsupportedFirecrackerOperation(operation string) error {
	if strings.TrimSpace(operation) == "" {
		operation = "firecracker_backend"
	}
	return microvm.NewUnavailableCapabilityError(operation, errors.New("firecracker backend operation is not supported in this phase"))
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
