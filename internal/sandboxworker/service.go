package sandboxworker

import (
	"context"
	"fmt"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

var defaultSupportedOperations = []string{
	OperationStatus,
	OperationCapabilities,
	OperationCreate,
	OperationStart,
	OperationStop,
	OperationDelete,
	OperationInspect,
	OperationExec,
	OperationCopyIn,
	OperationCopyOut,
}

var defaultRuntimeDriverOperations = []string{
	OperationCreate,
	OperationStart,
	OperationStop,
	OperationDelete,
	OperationInspect,
	OperationExec,
	OperationCopyIn,
	OperationCopyOut,
}

var microVMRuntimeDriverOperations = []string{
	OperationCreate,
	OperationStart,
	OperationStop,
	OperationDelete,
	OperationInspect,
}

// Service reports local worker state and capabilities without depending on
// command-layer records or concrete runtime adapters.
type Service struct {
	workerID          string
	hostKind          string
	socketPath        string
	registry          *DriverRegistry
	health            WorkerHealth
	capacity          WorkerCapacity
	security          SecurityPolicy
	metadata          *sandboxruntime.RuntimeMetadata
	supportedOps      []string
	driverDescriptors map[string]RuntimeDriver
	jobs              *jobManager
}

// ServiceOptions configures a local worker service.
type ServiceOptions struct {
	WorkerID string
	HostKind string

	SocketPath string
	Registry   *DriverRegistry

	Health   WorkerHealth
	Capacity WorkerCapacity
	Security SecurityPolicy

	NetworkEnforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata
	Metadata           *sandboxruntime.RuntimeMetadata

	SupportedOperations []string
	RuntimeDrivers      map[string]RuntimeDriver

	JobContext  context.Context
	JobStateDir string
}

// NewService returns a worker service with validated status and capability
// metadata.
func NewService(options ServiceOptions) (*Service, error) {
	workerID := strings.TrimSpace(options.WorkerID)
	if workerID == "" {
		return nil, fmt.Errorf("worker service workerId is required")
	}

	hostKind := strings.TrimSpace(options.HostKind)
	if hostKind == "" {
		hostKind = HostKindLocal
	}
	if !validHostKind(hostKind) {
		return nil, fmt.Errorf("worker service hostKind %q is unsupported", hostKind)
	}

	registry := options.Registry
	if registry == nil {
		registry = &DriverRegistry{}
	}

	health := options.Health
	if strings.TrimSpace(health.Status) == "" {
		health.Status = HealthStatusHealthy
		if strings.TrimSpace(health.Message) == "" {
			health.Message = "ready"
		}
	}

	capacity := options.Capacity
	if capacity.MaxConcurrentSandboxes == 0 && capacity.ActiveSandboxes == 0 {
		capacity.MaxConcurrentSandboxes = 1
	}

	security := options.Security
	if zeroSecurityPolicy(security) {
		security = DefaultWorkerSecurityPolicy()
	}
	security = projectWorkerSecurityPolicy(security, options.NetworkEnforcement)

	descriptors := cloneRuntimeDriverMap(options.RuntimeDrivers)
	supportedOps := cloneStringSlice(options.SupportedOperations)
	if len(supportedOps) == 0 {
		supportedOps = defaultSupportedOperationsForDrivers(registry.DriverIDs(), descriptors)
	}
	var jobs *jobManager
	if strings.TrimSpace(options.JobStateDir) != "" {
		var err error
		jobs, err = newJobManager(jobManagerOptions{
			Context:  options.JobContext,
			WorkerID: workerID,
			StateDir: options.JobStateDir,
		})
		if err != nil {
			return nil, fmt.Errorf("worker job state is unavailable")
		}
		supportedOps = appendMissingStrings(supportedOps,
			OperationJobStart,
			OperationJobStatus,
			OperationJobLogs,
			OperationJobCancel,
		)
	}
	service := &Service{
		workerID:          workerID,
		hostKind:          hostKind,
		socketPath:        strings.TrimSpace(options.SocketPath),
		registry:          registry,
		health:            health,
		capacity:          capacity,
		security:          cloneSecurityPolicy(security),
		metadata:          sandboxruntime.SanitizeRuntimeMetadata(options.Metadata),
		supportedOps:      supportedOps,
		driverDescriptors: descriptors,
		jobs:              jobs,
	}

	if err := service.Status().Validate(); err != nil {
		return nil, fmt.Errorf("worker service status: %w", err)
	}
	if err := service.Capabilities().Validate(); err != nil {
		return nil, fmt.Errorf("worker service capabilities: %w", err)
	}
	return service, nil
}

// Status returns current worker readiness generated from service state and the
// registered runtime drivers.
func (service *Service) Status() Status {
	return Status{
		ProtocolVersion:         ProtocolVersion,
		WorkerID:                service.workerID,
		HostKind:                service.hostKind,
		SocketPath:              service.socketPath,
		SupportedRuntimeDrivers: service.registry.DriverIDs(),
		Health:                  service.health,
		Capacity:                service.capacity,
		Security:                cloneSecurityPolicy(service.security),
		Metadata:                sandboxruntime.SanitizeRuntimeMetadata(service.metadata),
	}
}

// Capabilities returns supported protocol operations, runtime drivers, and
// honest worker security metadata generated from service state.
func (service *Service) Capabilities() Capabilities {
	driverIDs := service.registry.DriverIDs()
	drivers := make([]RuntimeDriver, 0, len(driverIDs))
	for _, driverID := range driverIDs {
		drivers = append(drivers, service.runtimeDriverCapability(driverID))
	}
	return Capabilities{
		ProtocolVersion:     ProtocolVersion,
		WorkerID:            service.workerID,
		SupportedOperations: cloneStringSlice(service.supportedOps),
		RuntimeDrivers:      drivers,
		Security:            cloneSecurityPolicy(service.security),
		Metadata:            sandboxruntime.SanitizeRuntimeMetadata(service.metadata),
	}
}

// StatusResponse returns a successful status protocol response.
func (service *Service) StatusResponse(requestID string) Response {
	status := service.Status()
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(requestID),
		Operation:       OperationStatus,
		OK:              true,
		Status:          &status,
	}
}

// CapabilitiesResponse returns a successful capabilities protocol response.
func (service *Service) CapabilitiesResponse(requestID string) Response {
	capabilities := service.Capabilities()
	return Response{
		ProtocolVersion: ProtocolVersion,
		RequestID:       strings.TrimSpace(requestID),
		Operation:       OperationCapabilities,
		OK:              true,
		Capabilities:    &capabilities,
	}
}

// DefaultWorkerSecurityPolicy reports the worker foundation's requested
// posture separately from the controls the local worker actually enforces.
func DefaultWorkerSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		Requested: SecurityControls{
			NetworkPolicy:      NetworkPolicyDenyByDefault,
			NetworkEnforcement: NetworkEnforcementRuntime,
			CredentialModes: []string{
				CredentialModeSSHAgent,
			},
			IsolationLevel: IsolationLevelContainer,
		},
		Enforced: SecurityControls{
			NetworkPolicy:      NetworkPolicyBestEffort,
			NetworkEnforcement: NetworkEnforcementNone,
			CredentialModes: []string{
				CredentialModeEnv,
				CredentialModeLegacyAuthSync,
			},
			IsolationLevel: IsolationLevelHost,
		},
	}
}

func (service *Service) runtimeDriverCapability(driverID string) RuntimeDriver {
	driver := runtimeDriverCapabilityFromDescriptors(driverID, service.driverDescriptors)
	if service != nil && service.jobs != nil && stringSliceContains(driver.Operations, OperationExec) {
		driver.Operations = appendMissingStrings(driver.Operations, OperationJobStart)
	}
	return driver
}

func runtimeDriverCapabilityFromDescriptors(driverID string, descriptors map[string]RuntimeDriver) RuntimeDriver {
	if descriptor, ok := descriptors[driverID]; ok {
		descriptor.ID = strings.TrimSpace(defaultString(descriptor.ID, driverID))
		descriptor.Operations = cloneStringSlice(descriptor.Operations)
		descriptor.NetworkEnforcement = sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(descriptor.NetworkEnforcement)
		descriptor.Metadata = sandboxruntime.SanitizeRuntimeMetadata(descriptor.Metadata)
		descriptor.Security = projectRuntimeDriverSecurityPolicyForDriver(descriptor.ID, descriptor.Security, descriptor.NetworkEnforcement)
		return descriptor
	}

	return defaultRuntimeDriverCapability(driverID)
}

func defaultSupportedOperationsForDrivers(driverIDs []string, descriptors map[string]RuntimeDriver) []string {
	supported := map[string]bool{
		OperationStatus:       true,
		OperationCapabilities: true,
	}
	for _, driverID := range driverIDs {
		driver := runtimeDriverCapabilityFromDescriptors(driverID, descriptors)
		for _, operation := range driver.Operations {
			supported[operation] = true
		}
	}
	operations := make([]string, 0, len(defaultSupportedOperations))
	for _, operation := range defaultSupportedOperations {
		if supported[operation] {
			operations = append(operations, operation)
		}
	}
	return operations
}

func (service *Service) supportsRequestOperation(operation, driverID string) bool {
	operation = strings.TrimSpace(operation)
	if operation == OperationStatus || operation == OperationCapabilities {
		return true
	}
	if operation == OperationJobStatus || operation == OperationJobLogs || operation == OperationJobCancel {
		return service != nil && service.jobs != nil && stringSliceContains(service.supportedOps, operation)
	}
	if operation == OperationJobStart && (service == nil || service.jobs == nil) {
		return false
	}
	if !validOperation(operation) {
		return false
	}
	driverID = strings.TrimSpace(driverID)
	if driverID == "" || service == nil || service.registry == nil {
		return stringSliceContains(service.supportedOps, operation)
	}
	if !stringSliceContains(service.registry.DriverIDs(), driverID) {
		return true
	}
	driver := service.runtimeDriverCapability(driverID)
	return stringSliceContains(driver.Operations, operation)
}

func appendMissingStrings(values []string, additions ...string) []string {
	result := cloneStringSlice(values)
	for _, addition := range additions {
		if !stringSliceContains(result, addition) {
			result = append(result, addition)
		}
	}
	return result
}

func defaultRuntimeDriverCapability(driverID string) RuntimeDriver {
	if driverID == RuntimeDriverRootlessPodman {
		return rootlessPodmanRuntimeDriverCapability()
	}
	if driverID == RuntimeDriverMicroVM {
		return microVMRuntimeDriverCapability()
	}

	isolationLevel := defaultRuntimeDriverIsolation(driverID)
	return RuntimeDriver{
		ID:             driverID,
		HostKind:       HostKindLocal,
		IsolationLevel: isolationLevel,
		Operations:     cloneStringSlice(defaultRuntimeDriverOperations),
		Security:       defaultRuntimeDriverSecurityPolicy(isolationLevel),
	}
}

func rootlessPodmanRuntimeDriverCapability() RuntimeDriver {
	return RuntimeDriver{
		ID:             RuntimeDriverRootlessPodman,
		HostKind:       HostKindLocal,
		IsolationLevel: IsolationLevelContainer,
		Operations:     cloneStringSlice(defaultRuntimeDriverOperations),
		Security:       rootlessPodmanRuntimeDriverSecurityPolicy(),
	}
}

func microVMRuntimeDriverCapability() RuntimeDriver {
	return RuntimeDriver{
		ID:             RuntimeDriverMicroVM,
		HostKind:       HostKindLocal,
		IsolationLevel: IsolationLevelVM,
		Operations:     cloneStringSlice(microVMRuntimeDriverOperations),
		Security:       microVMRuntimeDriverSecurityPolicy(),
	}
}

func defaultRuntimeDriverIsolation(driverID string) string {
	switch driverID {
	case RuntimeDriverRootlessPodman:
		return IsolationLevelContainer
	case RuntimeDriverMicroVM:
		return IsolationLevelVM
	default:
		return IsolationLevelHost
	}
}

func rootlessPodmanRuntimeDriverSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		Requested: SecurityControls{
			NetworkPolicy:      NetworkPolicyDenyByDefault,
			NetworkEnforcement: NetworkEnforcementRuntime,
			CredentialModes: []string{
				CredentialModeSSHAgent,
			},
			IsolationLevel:      IsolationLevelContainer,
			CredentialProxyMode: false,
		},
		Enforced: SecurityControls{
			NetworkPolicy:      NetworkPolicyBestEffort,
			NetworkEnforcement: NetworkEnforcementNone,
			CredentialModes: []string{
				CredentialModeEnv,
				CredentialModeLegacyAuthSync,
			},
			IsolationLevel:      IsolationLevelContainer,
			CredentialProxyMode: false,
		},
	}
}

func defaultRuntimeDriverSecurityPolicy(isolationLevel string) SecurityPolicy {
	return SecurityPolicy{
		Requested: SecurityControls{
			NetworkPolicy:      NetworkPolicyDenyByDefault,
			NetworkEnforcement: NetworkEnforcementRuntime,
			CredentialModes: []string{
				CredentialModeSSHAgent,
			},
			IsolationLevel: isolationLevel,
		},
		Enforced: SecurityControls{
			NetworkPolicy:      NetworkPolicyBestEffort,
			NetworkEnforcement: NetworkEnforcementNone,
			CredentialModes: []string{
				CredentialModeEnv,
				CredentialModeLegacyAuthSync,
			},
			IsolationLevel: isolationLevel,
		},
	}
}

func microVMRuntimeDriverSecurityPolicy() SecurityPolicy {
	return SecurityPolicy{
		Requested: SecurityControls{
			NetworkPolicy:       NetworkPolicyBestEffort,
			NetworkEnforcement:  NetworkEnforcementNone,
			IsolationLevel:      IsolationLevelVM,
			CredentialProxyMode: false,
		},
		Enforced: SecurityControls{
			NetworkPolicy:       NetworkPolicyBestEffort,
			NetworkEnforcement:  NetworkEnforcementNone,
			IsolationLevel:      IsolationLevelVM,
			CredentialProxyMode: false,
		},
	}
}

func cloneRuntimeDriverMap(drivers map[string]RuntimeDriver) map[string]RuntimeDriver {
	if len(drivers) == 0 {
		return nil
	}
	clone := make(map[string]RuntimeDriver, len(drivers))
	for id, driver := range drivers {
		driver.Operations = cloneStringSlice(driver.Operations)
		driver.Security = cloneSecurityPolicy(driver.Security)
		driver.NetworkEnforcement = sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(driver.NetworkEnforcement)
		driver.Metadata = sandboxruntime.SanitizeRuntimeMetadata(driver.Metadata)
		clone[strings.TrimSpace(id)] = driver
	}
	return clone
}

func cloneSecurityPolicy(policy SecurityPolicy) SecurityPolicy {
	return SecurityPolicy{
		Requested:          cloneSecurityControls(policy.Requested),
		Enforced:           cloneSecurityControls(policy.Enforced),
		NetworkEnforcement: sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(policy.NetworkEnforcement),
	}
}

func cloneSecurityControls(controls SecurityControls) SecurityControls {
	controls.CredentialModes = cloneStringSlice(controls.CredentialModes)
	controls.NetworkEnforcementCapability = sandboxruntime.SanitizeRuntimeNetworkEnforcementCapability(controls.NetworkEnforcementCapability)
	return controls
}

func projectRuntimeDriverSecurityPolicy(policy SecurityPolicy, enforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata) SecurityPolicy {
	return projectNetworkEnforcementSecurityPolicy(policy, enforcement, false)
}

func projectRuntimeDriverSecurityPolicyForDriver(driverID string, policy SecurityPolicy, enforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata) SecurityPolicy {
	projected := projectRuntimeDriverSecurityPolicy(policy, enforcement)
	if strings.TrimSpace(driverID) == RuntimeDriverMicroVM {
		return projected
	}
	clearRuntimeDriverEnforcedNetworkControls(&projected.Enforced)
	return projected
}

func projectWorkerSecurityPolicy(policy SecurityPolicy, enforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata) SecurityPolicy {
	if enforcement == nil {
		enforcement = policy.NetworkEnforcement
	}
	return projectNetworkEnforcementSecurityPolicy(policy, enforcement, true)
}

func projectNetworkEnforcementSecurityPolicy(policy SecurityPolicy, enforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata, includeProof bool) SecurityPolicy {
	projected := cloneSecurityPolicy(policy)
	enforcement = sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(enforcement)
	if includeProof {
		projected.NetworkEnforcement = enforcement
	} else {
		projected.NetworkEnforcement = nil
	}
	if enforcement != nil && enforcement.Plan != nil && enforcement.Plan.DefaultPosture == NetworkPolicyDenyByDefault {
		projected.Requested.NetworkPolicy = NetworkPolicyDenyByDefault
	}
	if enforcement != nil && enforcement.Plan != nil &&
		projected.Requested.NetworkPolicy == "" &&
		enforcement.Plan.PolicyPreset == NetworkPolicyDenyByDefault {
		projected.Requested.NetworkPolicy = NetworkPolicyDenyByDefault
	}

	if enforcement != nil || runtimeDriverSecurityHasNetworkEnforcementClaim(projected.Enforced) {
		clearRuntimeDriverEnforcedNetworkControls(&projected.Enforced)
	}
	if !runtimeDriverNetworkEnforcementActiveSuccess(enforcement) {
		return projected
	}

	capability := sandboxruntime.SanitizeRuntimeNetworkEnforcementCapability(enforcement.Result.Capability)
	mode := runtimeDriverNetworkEnforcementMode(enforcement.Result.EnforcementMode)
	if capability == nil || !runtimeDriverNetworkEnforcementModeCanEnforce(mode) {
		return projected
	}

	switch mode {
	case NetworkEnforcementProxy:
		proxyCapability := runtimeDriverNetworkEnforcementProxyCapability(capability)
		if proxyCapability == nil {
			return projected
		}
		projected.Enforced.NetworkEnforcementCapability = proxyCapability
		projected.Enforced.NetworkEnforcement = NetworkEnforcementProxy
	case NetworkEnforcementProxyFirewall:
		if !runtimeDriverNetworkEnforcementStrictDualProof(enforcement, capability) {
			return projected
		}
		projected.Enforced.NetworkEnforcementCapability = capability
		projected.Enforced.NetworkEnforcement = NetworkEnforcementProxyFirewall
		projected.Enforced.NetworkPolicy = NetworkPolicyDenyByDefault
	default:
		return projected
	}
	return projected
}

func runtimeDriverSecurityHasNetworkEnforcementClaim(controls SecurityControls) bool {
	if controls.NetworkPolicy == NetworkPolicyDenyByDefault || controls.NetworkEnforcementCapability != nil {
		return true
	}
	switch controls.NetworkEnforcement {
	case NetworkEnforcementBestEffort,
		NetworkEnforcementRuntime,
		NetworkEnforcementProxy,
		NetworkEnforcementFirewall,
		NetworkEnforcementProxyFirewall:
		return true
	default:
		return false
	}
}

func clearRuntimeDriverEnforcedNetworkControls(controls *SecurityControls) {
	if controls == nil {
		return
	}
	controls.NetworkPolicy = NetworkPolicyBestEffort
	controls.NetworkEnforcement = NetworkEnforcementNone
	controls.NetworkEnforcementCapability = nil
}

func runtimeDriverNetworkEnforcementActiveSuccess(enforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata) bool {
	enforcement = sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(enforcement)
	if enforcement == nil ||
		enforcement.Result == nil ||
		enforcement.Result.Outcome != "success" ||
		len(enforcement.Result.WarningCodes) > 0 {
		return false
	}
	mode := runtimeDriverNetworkEnforcementMode(enforcement.Result.EnforcementMode)
	if !runtimeDriverNetworkEnforcementModeCanEnforce(mode) {
		return false
	}
	if sandboxruntime.SanitizeRuntimeNetworkEnforcementCapability(enforcement.Result.Capability) == nil {
		return false
	}
	return runtimeDriverNetworkEnforcementOrchestrationActive(enforcement.Orchestration, mode)
}

func runtimeDriverNetworkEnforcementOrchestrationActive(orchestration *sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata, mode string) bool {
	if orchestration == nil ||
		orchestration.Status != "active" ||
		orchestration.ReasonCode != "active" ||
		len(orchestration.WarningCodes) > 0 {
		return false
	}
	proxyActive := runtimeDriverNetworkEnforcementLifecycleActive(orchestration.Proxy)
	ruleActive := false
	if mode != NetworkEnforcementProxy {
		for i := range orchestration.Rules {
			rule := &orchestration.Rules[i]
			if !runtimeDriverNetworkEnforcementLifecycleActive(rule) {
				return false
			}
			if runtimeDriverNetworkEnforcementLifecycleHasMechanism(rule, NetworkEnforcementFirewall) ||
				runtimeDriverNetworkEnforcementLifecycleHasMechanism(rule, NetworkEnforcementRuntime) {
				ruleActive = true
			}
		}
	}
	switch mode {
	case NetworkEnforcementProxyFirewall:
		return proxyActive && ruleActive
	case NetworkEnforcementProxy:
		return proxyActive
	case NetworkEnforcementFirewall, NetworkEnforcementRuntime:
		return ruleActive
	default:
		return false
	}
}

func runtimeDriverNetworkEnforcementStrictDualProof(enforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata, capability *sandboxruntime.RuntimeNetworkEnforcementCapability) bool {
	if enforcement == nil ||
		enforcement.Result == nil ||
		runtimeDriverNetworkEnforcementMode(enforcement.Result.EnforcementMode) != NetworkEnforcementProxyFirewall ||
		len(enforcement.Result.WarningCodes) > 0 {
		return false
	}
	if capability == nil ||
		!capability.SupportsDefaultDenyPosture ||
		!networkEnforcementCapabilitySupportsMode(capability, NetworkEnforcementProxyFirewall) {
		return false
	}
	return runtimeDriverNetworkEnforcementOrchestrationActive(enforcement.Orchestration, NetworkEnforcementProxyFirewall)
}

func runtimeDriverNetworkEnforcementProxyCapability(capability *sandboxruntime.RuntimeNetworkEnforcementCapability) *sandboxruntime.RuntimeNetworkEnforcementCapability {
	if !networkEnforcementCapabilitySupportsMode(capability, NetworkEnforcementProxy) {
		return nil
	}
	proxyCapability := *capability
	proxyCapability.Modes = []string{NetworkEnforcementProxy}
	proxyCapability.SupportsDefaultDenyPosture = false
	return sandboxruntime.SanitizeRuntimeNetworkEnforcementCapability(&proxyCapability)
}

func runtimeDriverNetworkEnforcementLifecycleActive(lifecycle *sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata) bool {
	return lifecycle != nil &&
		lifecycle.Status == "active" &&
		lifecycle.ReasonCode == "active" &&
		len(lifecycle.WarningCodes) == 0
}

func runtimeDriverNetworkEnforcementLifecycleHasMechanism(lifecycle *sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata, mechanism string) bool {
	if lifecycle == nil {
		return false
	}
	for _, candidate := range lifecycle.Mechanisms {
		if candidate == mechanism {
			return true
		}
	}
	return false
}

func runtimeDriverNetworkEnforcementMode(mode string) string {
	switch mode {
	case NetworkEnforcementBestEffort,
		NetworkEnforcementProxy,
		NetworkEnforcementFirewall,
		NetworkEnforcementRuntime,
		NetworkEnforcementProxyFirewall:
		return mode
	default:
		return ""
	}
}

func runtimeDriverNetworkEnforcementModeCanEnforce(mode string) bool {
	switch mode {
	case NetworkEnforcementProxy,
		NetworkEnforcementFirewall,
		NetworkEnforcementRuntime,
		NetworkEnforcementProxyFirewall:
		return true
	default:
		return false
	}
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	clone := append([]string(nil), values...)
	return clone
}

func stringSliceContains(values []string, want string) bool {
	want = strings.TrimSpace(want)
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}

func zeroSecurityPolicy(policy SecurityPolicy) bool {
	return zeroSecurityControls(policy.Requested) &&
		zeroSecurityControls(policy.Enforced) &&
		policy.NetworkEnforcement == nil
}

func zeroSecurityControls(controls SecurityControls) bool {
	return controls.NetworkPolicy == "" &&
		controls.NetworkEnforcement == "" &&
		controls.NetworkEnforcementCapability == nil &&
		len(controls.CredentialModes) == 0 &&
		controls.IsolationLevel == "" &&
		!controls.CredentialProxyMode
}

func defaultString(value, fallback string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback
	}
	return value
}
