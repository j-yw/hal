package sandboxworker

import (
	"fmt"
	"strings"
)

var defaultSupportedOperations = []string{
	OperationStatus,
	OperationCapabilities,
}

var defaultRuntimeDriverOperations = []string{
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
	supportedOps      []string
	driverDescriptors map[string]RuntimeDriver
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

	SupportedOperations []string
	RuntimeDrivers      map[string]RuntimeDriver
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

	supportedOps := cloneStringSlice(options.SupportedOperations)
	if len(supportedOps) == 0 {
		supportedOps = cloneStringSlice(defaultSupportedOperations)
	}

	descriptors := cloneRuntimeDriverMap(options.RuntimeDrivers)
	service := &Service{
		workerID:          workerID,
		hostKind:          hostKind,
		socketPath:        strings.TrimSpace(options.SocketPath),
		registry:          registry,
		health:            health,
		capacity:          capacity,
		security:          cloneSecurityPolicy(security),
		supportedOps:      supportedOps,
		driverDescriptors: descriptors,
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
	if descriptor, ok := service.driverDescriptors[driverID]; ok {
		descriptor.ID = strings.TrimSpace(defaultString(descriptor.ID, driverID))
		descriptor.Operations = cloneStringSlice(descriptor.Operations)
		descriptor.Security = cloneSecurityPolicy(descriptor.Security)
		return descriptor
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

func defaultRuntimeDriverIsolation(driverID string) string {
	switch driverID {
	case RuntimeDriverRootlessPodman:
		return IsolationLevelContainer
	default:
		return IsolationLevelHost
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

func cloneRuntimeDriverMap(drivers map[string]RuntimeDriver) map[string]RuntimeDriver {
	if len(drivers) == 0 {
		return nil
	}
	clone := make(map[string]RuntimeDriver, len(drivers))
	for id, driver := range drivers {
		driver.Operations = cloneStringSlice(driver.Operations)
		driver.Security = cloneSecurityPolicy(driver.Security)
		clone[strings.TrimSpace(id)] = driver
	}
	return clone
}

func cloneSecurityPolicy(policy SecurityPolicy) SecurityPolicy {
	return SecurityPolicy{
		Requested: cloneSecurityControls(policy.Requested),
		Enforced:  cloneSecurityControls(policy.Enforced),
	}
}

func cloneSecurityControls(controls SecurityControls) SecurityControls {
	controls.CredentialModes = cloneStringSlice(controls.CredentialModes)
	return controls
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	clone := append([]string(nil), values...)
	return clone
}

func zeroSecurityPolicy(policy SecurityPolicy) bool {
	return zeroSecurityControls(policy.Requested) && zeroSecurityControls(policy.Enforced)
}

func zeroSecurityControls(controls SecurityControls) bool {
	return controls.NetworkPolicy == "" &&
		controls.NetworkEnforcement == "" &&
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
