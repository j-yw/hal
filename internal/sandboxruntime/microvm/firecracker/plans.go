package firecracker

import (
	"errors"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

const (
	// OperationPlanningOperation is the sanitized operation label used for
	// Firecracker lifecycle operation planning errors.
	OperationPlanningOperation = "firecracker_operation_plan"

	firecrackerMachineConfigAPIPath = "/machine-config"
	firecrackerBootSourceAPIPath    = "/boot-source"
	firecrackerRootDriveAPIPath     = "/drives/rootfs"
)

const (
	OperationActionStart   OperationAction = microvm.OperationStart
	OperationActionStop    OperationAction = microvm.OperationStop
	OperationActionInspect OperationAction = microvm.OperationInspect
	OperationActionDelete  OperationAction = microvm.OperationDelete
)

const (
	OperationPathRoleExecutable OperationPathRole = "executable"
	OperationPathRoleStateDir   OperationPathRole = "state_dir"
	OperationPathRoleAPISocket  OperationPathRole = "api_socket"
	OperationPathRoleConfig     OperationPathRole = "config"
	OperationPathRoleLog        OperationPathRole = "log"
	OperationPathRoleMetrics    OperationPathRole = "metrics"
)

const (
	OperationPayloadRoleMachineConfig OperationPayloadRole = "machine_config"
	OperationPayloadRoleBootSource    OperationPayloadRole = "boot_source"
	OperationPayloadRoleRootDrive     OperationPayloadRole = "root_drive"
)

// OperationAction identifies the planned Firecracker lifecycle action without
// invoking backend behavior.
type OperationAction string

// OperationPathRole is the safe public label for a process-boundary path.
type OperationPathRole string

// OperationPayloadRole is the safe public label for a rendered payload.
type OperationPayloadRole string

// OperationPathReference carries a process-boundary host path with a safe role.
// JSON intentionally exposes only Role so public plan encodings do not leak raw
// host paths.
type OperationPathReference struct {
	Role OperationPathRole `json:"role"`
	Path string            `json:"-"`
}

// OperationEnvironmentMetadata describes an environment entry without exposing
// secret or host-specific values. Start plans use an explicit empty slice when
// no environment entries are required.
type OperationEnvironmentMetadata struct {
	Name   string `json:"name,omitempty"`
	Source string `json:"source,omitempty"`
}

// OperationPayloadReference identifies a rendered Firecracker payload by safe
// role, API path, and optional immutable asset metadata without copying
// path-bearing payload bodies.
type OperationPayloadReference struct {
	Role    OperationPayloadRole            `json:"role"`
	APIPath string                          `json:"apiPath"`
	Assets  []OperationPayloadAssetMetadata `json:"assets,omitempty"`
}

// OperationPayloadAssetMetadata carries safe immutable launch asset metadata.
// Host paths are intentionally omitted from public process and runtime output.
type OperationPayloadAssetMetadata struct {
	AssetRole string                          `json:"assetRole,omitempty"`
	ID        string                          `json:"id,omitempty"`
	Labels    []string                        `json:"labels,omitempty"`
	Digest    *OperationPayloadDigestMetadata `json:"digest,omitempty"`
}

// OperationPayloadDigestMetadata carries digest lock metadata copied from a
// validated immutable launch descriptor.
type OperationPayloadDigestMetadata struct {
	Algorithm string `json:"algorithm,omitempty"`
	Value     string `json:"value,omitempty"`
}

// OperationArgumentSummary is the public, reviewable argv shape. Literal flags
// appear as values; host path argv positions appear only by safe path role.
type OperationArgumentSummary struct {
	Value    string            `json:"value,omitempty"`
	PathRole OperationPathRole `json:"pathRole,omitempty"`
}

// OperationPlanSummary is the sanitized public description of an operation
// plan. It omits raw process-boundary host paths and payload bodies.
type OperationPlanSummary struct {
	Action         OperationAction                `json:"action"`
	ExecutableRole OperationPathRole              `json:"executableRole,omitempty"`
	Argv           []OperationArgumentSummary     `json:"argv"`
	Environment    []OperationEnvironmentMetadata `json:"environment"`
	PathRoles      []OperationPathRole            `json:"pathRoles"`
	Payloads       []OperationPayloadReference    `json:"payloads"`
}

// StartOperationPlan describes the Firecracker process launch contract without
// starting the process.
type StartOperationPlan struct {
	Action      OperationAction                `json:"action"`
	Executable  OperationPathReference         `json:"executable"`
	Argv        []string                       `json:"-"`
	EnablePCI   bool                           `json:"enablePCI,omitempty"`
	Environment []OperationEnvironmentMetadata `json:"environment"`
	APISocket   OperationPathReference         `json:"apiSocket"`
	Config      OperationPathReference         `json:"config"`
	Log         OperationPathReference         `json:"log"`
	Metrics     OperationPathReference         `json:"metrics"`
	Payloads    []OperationPayloadReference    `json:"payloads"`
}

// StopOperationPlan describes the intended Firecracker stop action without
// calling the Firecracker API socket.
type StopOperationPlan struct {
	Action    OperationAction        `json:"action"`
	APISocket OperationPathReference `json:"apiSocket"`
}

// InspectOperationPlan describes the intended Firecracker inspect action
// without calling the Firecracker API socket.
type InspectOperationPlan struct {
	Action    OperationAction        `json:"action"`
	APISocket OperationPathReference `json:"apiSocket"`
}

// DeleteOperationPlan describes the intended Firecracker cleanup action without
// removing process-boundary files or directories.
type DeleteOperationPlan struct {
	Action    OperationAction        `json:"action"`
	StateDir  OperationPathReference `json:"stateDir"`
	APISocket OperationPathReference `json:"apiSocket"`
	Config    OperationPathReference `json:"config"`
	Log       OperationPathReference `json:"log"`
	Metrics   OperationPathReference `json:"metrics"`
}

// RenderStartOperationPlan derives a fake-testable Firecracker start plan. It
// validates payload renderability but stores only payload references.
func RenderStartOperationPlan(config BackendConfig) (StartOperationPlan, error) {
	return renderStartOperationPlanWithL8Authority(config, productionL8AuthorityOperations())
}

func renderStartOperationPlanWithL8Authority(
	config BackendConfig,
	authority l8AuthorityOperations,
) (StartOperationPlan, error) {
	if config.LaunchDescriptor != nil {
		if _, err := firecrackerLaunchDescriptorAssets(config.LaunchDescriptor, OperationPlanningOperation); err != nil {
			return StartOperationPlan{}, err
		}
	}
	executable, err := operationPathReference(OperationPathRoleExecutable, config.ExecutablePath, "executablePath")
	if err != nil {
		return StartOperationPlan{}, err
	}
	apiSocket, err := operationPathReference(OperationPathRoleAPISocket, config.Paths.APISocketPath, "apiSocketPath")
	if err != nil {
		return StartOperationPlan{}, err
	}
	configPath, err := operationPathReference(OperationPathRoleConfig, config.Paths.ConfigPath, "configPath")
	if err != nil {
		return StartOperationPlan{}, err
	}
	logPath, err := operationPathReference(OperationPathRoleLog, config.Paths.LogPath, "logPath")
	if err != nil {
		return StartOperationPlan{}, err
	}
	metricsPath, err := operationPathReference(OperationPathRoleMetrics, config.Paths.MetricsPath, "metricsPath")
	if err != nil {
		return StartOperationPlan{}, err
	}
	payloads, err := validateOperationPayloadReferencesWithL8Authority(config, authority)
	if err != nil {
		return StartOperationPlan{}, err
	}

	enablePCI := config.ProductionVsock
	argv, err := processStartArgvWithPCI(executable, []OperationPathReference{
		apiSocket,
		configPath,
		logPath,
		metricsPath,
	}, enablePCI)
	if err != nil {
		return StartOperationPlan{}, err
	}

	return StartOperationPlan{
		Action:      OperationActionStart,
		Executable:  executable,
		Argv:        argv,
		EnablePCI:   enablePCI,
		Environment: []OperationEnvironmentMetadata{},
		APISocket:   apiSocket,
		Config:      configPath,
		Log:         logPath,
		Metrics:     metricsPath,
		Payloads:    payloads,
	}, nil
}

// RenderStopOperationPlan derives a fake-testable Firecracker stop plan.
func RenderStopOperationPlan(paths PathPlan) (StopOperationPlan, error) {
	apiSocket, err := operationPathReference(OperationPathRoleAPISocket, paths.APISocketPath, "apiSocketPath")
	if err != nil {
		return StopOperationPlan{}, err
	}
	return StopOperationPlan{
		Action:    OperationActionStop,
		APISocket: apiSocket,
	}, nil
}

// RenderInspectOperationPlan derives a fake-testable Firecracker inspect plan.
func RenderInspectOperationPlan(paths PathPlan) (InspectOperationPlan, error) {
	apiSocket, err := operationPathReference(OperationPathRoleAPISocket, paths.APISocketPath, "apiSocketPath")
	if err != nil {
		return InspectOperationPlan{}, err
	}
	return InspectOperationPlan{
		Action:    OperationActionInspect,
		APISocket: apiSocket,
	}, nil
}

// RenderDeleteOperationPlan derives a fake-testable Firecracker cleanup plan.
func RenderDeleteOperationPlan(paths PathPlan) (DeleteOperationPlan, error) {
	stateDir, err := operationPathReference(OperationPathRoleStateDir, paths.StateDir, "stateDir")
	if err != nil {
		return DeleteOperationPlan{}, err
	}
	apiSocket, err := operationPathReference(OperationPathRoleAPISocket, paths.APISocketPath, "apiSocketPath")
	if err != nil {
		return DeleteOperationPlan{}, err
	}
	configPath, err := operationPathReference(OperationPathRoleConfig, paths.ConfigPath, "configPath")
	if err != nil {
		return DeleteOperationPlan{}, err
	}
	logPath, err := operationPathReference(OperationPathRoleLog, paths.LogPath, "logPath")
	if err != nil {
		return DeleteOperationPlan{}, err
	}
	metricsPath, err := operationPathReference(OperationPathRoleMetrics, paths.MetricsPath, "metricsPath")
	if err != nil {
		return DeleteOperationPlan{}, err
	}

	return DeleteOperationPlan{
		Action:    OperationActionDelete,
		StateDir:  stateDir,
		APISocket: apiSocket,
		Config:    configPath,
		Log:       logPath,
		Metrics:   metricsPath,
	}, nil
}

func (plan StartOperationPlan) Summary() OperationPlanSummary {
	argv := []OperationArgumentSummary{
		{PathRole: plan.Executable.Role},
	}
	if plan.EnablePCI {
		argv = append(argv, OperationArgumentSummary{Value: "--enable-pci"})
	}
	argv = append(argv,
		OperationArgumentSummary{Value: "--api-sock"},
		OperationArgumentSummary{PathRole: plan.APISocket.Role},
		OperationArgumentSummary{Value: "--config-file"},
		OperationArgumentSummary{PathRole: plan.Config.Role},
		OperationArgumentSummary{Value: "--log-path"},
		OperationArgumentSummary{PathRole: plan.Log.Role},
		OperationArgumentSummary{Value: "--metrics-path"},
		OperationArgumentSummary{PathRole: plan.Metrics.Role},
	)
	return OperationPlanSummary{
		Action:         plan.Action,
		ExecutableRole: plan.Executable.Role,
		Argv:           argv,
		Environment:    cloneOperationEnvironment(plan.Environment),
		PathRoles: []OperationPathRole{
			plan.APISocket.Role,
			plan.Config.Role,
			plan.Log.Role,
			plan.Metrics.Role,
		},
		Payloads: cloneOperationPayloadReferences(plan.Payloads),
	}
}

func (plan StopOperationPlan) Summary() OperationPlanSummary {
	return lifecycleOperationSummary(plan.Action, []OperationPathRole{plan.APISocket.Role})
}

func (plan InspectOperationPlan) Summary() OperationPlanSummary {
	return lifecycleOperationSummary(plan.Action, []OperationPathRole{plan.APISocket.Role})
}

func (plan DeleteOperationPlan) Summary() OperationPlanSummary {
	return lifecycleOperationSummary(plan.Action, []OperationPathRole{
		plan.StateDir.Role,
		plan.APISocket.Role,
		plan.Config.Role,
		plan.Log.Role,
		plan.Metrics.Role,
	})
}

func lifecycleOperationSummary(action OperationAction, pathRoles []OperationPathRole) OperationPlanSummary {
	return OperationPlanSummary{
		Action:      action,
		Argv:        []OperationArgumentSummary{},
		Environment: []OperationEnvironmentMetadata{},
		PathRoles:   cloneOperationPathRoles(pathRoles),
		Payloads:    []OperationPayloadReference{},
	}
}

func operationPathReference(role OperationPathRole, path string, field string) (OperationPathReference, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return OperationPathReference{}, newOperationPlanError(field, "path role is required")
	}
	if hasUnsafePathControl(path) {
		return OperationPathReference{}, newOperationPlanError(field, "path role is invalid")
	}
	return OperationPathReference{
		Role: role,
		Path: path,
	}, nil
}

func validateOperationPayloadReferences(config BackendConfig) ([]OperationPayloadReference, error) {
	return validateOperationPayloadReferencesWithL8Authority(config, productionL8AuthorityOperations())
}

func validateOperationPayloadReferencesWithL8Authority(
	config BackendConfig,
	authority l8AuthorityOperations,
) ([]OperationPayloadReference, error) {
	if _, err := RenderMachineConfigPayload(config); err != nil {
		return nil, operationPlanPayloadError(err)
	}
	if _, err := renderBootSourcePayloadWithL8Authority(config, authority); err != nil {
		return nil, operationPlanPayloadError(err)
	}
	if _, err := RenderRootDrivePayload(config); err != nil {
		return nil, operationPlanPayloadError(err)
	}
	payloads, err := operationPayloadReferencesForConfig(config)
	if err != nil {
		return nil, operationPlanPayloadError(err)
	}
	return payloads, nil
}

func operationPlanPayloadError(err error) error {
	field := "payloads"
	message := "payload rendering failed"

	var operationErr *microvm.OperationError
	if errors.As(err, &operationErr) {
		if strings.TrimSpace(operationErr.Field) != "" {
			field = operationErr.Field
		}
		if strings.TrimSpace(operationErr.Message) != "" {
			message = operationErr.Message
		}
	}
	return newOperationPlanError(field, message)
}

func operationPayloadReferences() []OperationPayloadReference {
	return []OperationPayloadReference{
		{Role: OperationPayloadRoleMachineConfig, APIPath: firecrackerMachineConfigAPIPath},
		{Role: OperationPayloadRoleBootSource, APIPath: firecrackerBootSourceAPIPath},
		{Role: OperationPayloadRoleRootDrive, APIPath: firecrackerRootDriveAPIPath},
	}
}

func operationPayloadReferencesForConfig(config BackendConfig) ([]OperationPayloadReference, error) {
	payloads := operationPayloadReferences()
	if config.LaunchDescriptor == nil {
		return payloads, nil
	}
	launchAssets, err := firecrackerLaunchDescriptorAssets(config.LaunchDescriptor, PayloadRenderingOperation)
	if err != nil {
		return nil, err
	}
	payloads[1].Assets = []OperationPayloadAssetMetadata{
		operationPayloadAssetMetadata(launchAssets.Kernel),
	}
	if launchAssets.HasInitrd {
		payloads[1].Assets = append(payloads[1].Assets, operationPayloadAssetMetadata(launchAssets.Initrd))
	}
	payloads[2].Assets = []OperationPayloadAssetMetadata{
		operationPayloadAssetMetadata(launchAssets.Rootfs),
	}
	return payloads, nil
}

func operationPayloadAssetMetadata(asset assets.LaunchAsset) OperationPayloadAssetMetadata {
	metadata := OperationPayloadAssetMetadata{
		AssetRole: string(asset.Role),
		ID:        string(asset.ID),
		Labels:    launchAssetLabels(asset.Labels),
		Digest: &OperationPayloadDigestMetadata{
			Algorithm: string(asset.Lock.Digest.Algorithm),
			Value:     asset.Lock.Digest.Value,
		},
	}
	if metadata.Labels == nil {
		metadata.Labels = []string{}
	}
	return metadata
}

func launchAssetLabels(labels []assets.SafeLabel) []string {
	if labels == nil {
		return nil
	}
	out := make([]string, len(labels))
	for i, label := range labels {
		out[i] = string(label)
	}
	return out
}

func cloneOperationEnvironment(in []OperationEnvironmentMetadata) []OperationEnvironmentMetadata {
	if len(in) == 0 {
		return []OperationEnvironmentMetadata{}
	}
	out := make([]OperationEnvironmentMetadata, len(in))
	copy(out, in)
	return out
}

func cloneOperationPathRoles(in []OperationPathRole) []OperationPathRole {
	if len(in) == 0 {
		return []OperationPathRole{}
	}
	out := make([]OperationPathRole, len(in))
	copy(out, in)
	return out
}

func cloneOperationPayloadReferences(in []OperationPayloadReference) []OperationPayloadReference {
	if len(in) == 0 {
		return []OperationPayloadReference{}
	}
	out := make([]OperationPayloadReference, len(in))
	for i, payload := range in {
		out[i] = payload
		out[i].Assets = cloneOperationPayloadAssetMetadata(payload.Assets)
	}
	return out
}

func cloneOperationPayloadAssetMetadata(in []OperationPayloadAssetMetadata) []OperationPayloadAssetMetadata {
	if len(in) == 0 {
		return nil
	}
	out := make([]OperationPayloadAssetMetadata, len(in))
	for i, asset := range in {
		out[i] = asset
		out[i].Labels = cloneStringSlice(asset.Labels)
		if asset.Digest != nil {
			digest := *asset.Digest
			out[i].Digest = &digest
		}
	}
	return out
}

func newOperationPlanError(field, message string) *microvm.OperationError {
	err := microvm.NewInvalidConfigError(OperationPlanningOperation, microvm.ErrInvalidConfig)
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}
