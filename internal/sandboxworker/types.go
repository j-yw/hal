package sandboxworker

import (
	"fmt"
	"strings"
)

const (
	ProtocolVersion = "sandboxworker-v1"

	OperationStatus       = "status"
	OperationCapabilities = "capabilities"
	OperationCreate       = "create"
	OperationStart        = "start"
	OperationStop         = "stop"
	OperationDelete       = "delete"
	OperationInspect      = "inspect"
	OperationExec         = "exec"
	OperationCopyIn       = "copy_in"
	OperationCopyOut      = "copy_out"

	HostKindLocal  = "local"
	HostKindWorker = "worker"

	HealthStatusHealthy   = "healthy"
	HealthStatusDegraded  = "degraded"
	HealthStatusUnhealthy = "unhealthy"
	HealthStatusUnknown   = "unknown"

	RuntimeDriverSSHMachine     = "ssh_machine"
	RuntimeDriverRootlessPodman = "rootless_podman"

	IsolationLevelHost      = "host"
	IsolationLevelContainer = "container"

	NetworkPolicyDenyByDefault = "deny_by_default"
	NetworkPolicyBestEffort    = "best_effort"

	NetworkEnforcementNone    = "none"
	NetworkEnforcementRuntime = "runtime"

	CredentialModeEnv            = "env"
	CredentialModeFileTmpfs      = "file_tmpfs"
	CredentialModeSSHAgent       = "ssh_agent"
	CredentialModeLegacyAuthSync = "legacy_auth_sync"
)

const (
	unsupportedIsolationLevelMicroVM      = "microvm"
	unsupportedNetworkEnforcementFirewall = "firewall"
	unsupportedNetworkEnforcementProxy    = "proxy"
	unsupportedCredentialModeProxy        = "credential_proxy"
)

// Request is the versioned protocol envelope accepted by a local sandbox
// worker. Operation-specific payloads stay command-agnostic and use worker
// package types rather than command-layer durable records.
type Request struct {
	ProtocolVersion string            `json:"protocolVersion,omitempty"`
	RequestID       string            `json:"requestId,omitempty"`
	Operation       string            `json:"operation"`
	DriverID        string            `json:"driverId,omitempty"`
	Target          *Target           `json:"target,omitempty"`
	Create          *CreateRequest    `json:"create,omitempty"`
	Lifecycle       *LifecycleRequest `json:"lifecycle,omitempty"`
	Inspect         *InspectRequest   `json:"inspect,omitempty"`
}

// Response is the versioned protocol envelope returned by a local sandbox
// worker.
type Response struct {
	ProtocolVersion string        `json:"protocolVersion,omitempty"`
	RequestID       string        `json:"requestId,omitempty"`
	Operation       string        `json:"operation"`
	OK              bool          `json:"ok"`
	Status          *Status       `json:"status,omitempty"`
	Capabilities    *Capabilities `json:"capabilities,omitempty"`
	Target          *Target       `json:"target,omitempty"`
	Error           *Error        `json:"error,omitempty"`
}

// Error is a structured protocol error safe for local protocol responses.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Status describes observable worker readiness without embedding command state.
type Status struct {
	ProtocolVersion         string         `json:"protocolVersion,omitempty"`
	WorkerID                string         `json:"workerId"`
	HostKind                string         `json:"hostKind"`
	SocketPath              string         `json:"socketPath,omitempty"`
	SupportedRuntimeDrivers []string       `json:"supportedRuntimeDrivers,omitempty"`
	Health                  WorkerHealth   `json:"health"`
	Capacity                WorkerCapacity `json:"capacity"`
	Security                SecurityPolicy `json:"security"`
}

// WorkerHealth reports worker health using a small stable vocabulary.
type WorkerHealth struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// WorkerCapacity reports local worker capacity without reserving resources.
type WorkerCapacity struct {
	MaxConcurrentSandboxes int `json:"maxConcurrentSandboxes"`
	ActiveSandboxes        int `json:"activeSandboxes"`
}

// Capabilities describes supported protocol operations, runtime drivers, and
// honest security posture.
type Capabilities struct {
	ProtocolVersion     string          `json:"protocolVersion,omitempty"`
	WorkerID            string          `json:"workerId"`
	SupportedOperations []string        `json:"supportedOperations,omitempty"`
	RuntimeDrivers      []RuntimeDriver `json:"runtimeDrivers,omitempty"`
	Security            SecurityPolicy  `json:"security"`
}

// RuntimeDriver is the worker protocol's command-agnostic runtime driver
// descriptor.
type RuntimeDriver struct {
	ID             string         `json:"id"`
	HostKind       string         `json:"hostKind"`
	IsolationLevel string         `json:"isolationLevel"`
	Operations     []string       `json:"operations,omitempty"`
	Security       SecurityPolicy `json:"security"`
}

// SecurityPolicy separates requested controls from controls the worker
// actually enforces.
type SecurityPolicy struct {
	Requested SecurityControls `json:"requested"`
	Enforced  SecurityControls `json:"enforced"`
}

// SecurityControls captures network, credential, and isolation controls.
type SecurityControls struct {
	NetworkPolicy       string   `json:"networkPolicy,omitempty"`
	NetworkEnforcement  string   `json:"networkEnforcement,omitempty"`
	CredentialModes     []string `json:"credentialModes,omitempty"`
	IsolationLevel      string   `json:"isolationLevel,omitempty"`
	CredentialProxyMode bool     `json:"credentialProxyMode,omitempty"`
}

// Target is the worker protocol target shape used by lifecycle and inspect
// operations.
type Target struct {
	ID      string            `json:"id,omitempty"`
	Name    string            `json:"name"`
	Status  string            `json:"status,omitempty"`
	Runtime RuntimeTarget     `json:"runtime"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// RuntimeTarget captures runtime identity without importing durable sandbox
// records or concrete adapters.
type RuntimeTarget struct {
	Driver         string `json:"driver"`
	RuntimeID      string `json:"runtimeId,omitempty"`
	Image          string `json:"image,omitempty"`
	WorkerID       string `json:"workerId,omitempty"`
	IsolationLevel string `json:"isolationLevel,omitempty"`
}

// CreateRequest describes a worker-backed target creation request.
type CreateRequest struct {
	Name     string            `json:"name"`
	Env      map[string]string `json:"env,omitempty"`
	Security SecurityPolicy    `json:"security,omitempty"`
}

// LifecycleRequest describes a worker-backed lifecycle request for an existing
// target.
type LifecycleRequest struct {
	Target Target `json:"target"`
}

// InspectRequest describes a worker-backed inspect request for an existing
// target.
type InspectRequest struct {
	Target Target `json:"target"`
}

// WithDefaults returns req with protocol defaults applied.
func (req Request) WithDefaults() Request {
	req.ProtocolVersion = defaultProtocolVersion(req.ProtocolVersion)
	return req
}

// Validate checks the worker request envelope.
func (req Request) Validate() error {
	req = req.WithDefaults()
	if err := validateProtocolVersion(req.ProtocolVersion); err != nil {
		return err
	}
	if !validOperation(req.Operation) {
		return fmt.Errorf("worker request operation %q is unsupported", req.Operation)
	}
	switch req.Operation {
	case OperationCreate:
		if strings.TrimSpace(req.DriverID) == "" {
			return fmt.Errorf("worker request driverId is required for %s", req.Operation)
		}
		if req.Create == nil {
			return fmt.Errorf("worker request create payload is required for %s", req.Operation)
		}
		return req.Create.Validate()
	case OperationStart, OperationStop, OperationDelete:
		if strings.TrimSpace(req.DriverID) == "" {
			return fmt.Errorf("worker request driverId is required for %s", req.Operation)
		}
		if req.Lifecycle == nil {
			return fmt.Errorf("worker request lifecycle payload is required for %s", req.Operation)
		}
		return req.Lifecycle.Validate()
	case OperationInspect:
		if strings.TrimSpace(req.DriverID) == "" {
			return fmt.Errorf("worker request driverId is required for %s", req.Operation)
		}
		if req.Inspect == nil {
			return fmt.Errorf("worker request inspect payload is required for %s", req.Operation)
		}
		return req.Inspect.Validate()
	default:
		return nil
	}
}

// WithDefaults returns resp with protocol defaults applied.
func (resp Response) WithDefaults() Response {
	resp.ProtocolVersion = defaultProtocolVersion(resp.ProtocolVersion)
	return resp
}

// Validate checks the worker response envelope and populated payloads.
func (resp Response) Validate() error {
	resp = resp.WithDefaults()
	if err := validateProtocolVersion(resp.ProtocolVersion); err != nil {
		return err
	}
	if !validOperation(resp.Operation) {
		return fmt.Errorf("worker response operation %q is unsupported", resp.Operation)
	}
	if resp.OK && resp.Error != nil {
		return fmt.Errorf("worker response cannot include error when ok is true")
	}
	if !resp.OK && resp.Error == nil {
		return fmt.Errorf("worker response error is required when ok is false")
	}
	if resp.Status != nil {
		if err := resp.Status.Validate(); err != nil {
			return fmt.Errorf("worker response status: %w", err)
		}
	}
	if resp.Capabilities != nil {
		if err := resp.Capabilities.Validate(); err != nil {
			return fmt.Errorf("worker response capabilities: %w", err)
		}
	}
	if resp.Target != nil {
		if err := resp.Target.Validate(); err != nil {
			return fmt.Errorf("worker response target: %w", err)
		}
	}
	return nil
}

// WithDefaults returns status with protocol defaults applied.
func (status Status) WithDefaults() Status {
	status.ProtocolVersion = defaultProtocolVersion(status.ProtocolVersion)
	return status
}

// Validate checks required worker status fields.
func (status Status) Validate() error {
	status = status.WithDefaults()
	if err := validateProtocolVersion(status.ProtocolVersion); err != nil {
		return err
	}
	if strings.TrimSpace(status.WorkerID) == "" {
		return fmt.Errorf("worker status workerId is required")
	}
	if !validHostKind(status.HostKind) {
		return fmt.Errorf("worker status hostKind %q is unsupported", status.HostKind)
	}
	if !validHealthStatus(status.Health.Status) {
		return fmt.Errorf("worker status health status %q is unsupported", status.Health.Status)
	}
	if status.Capacity.MaxConcurrentSandboxes < 0 {
		return fmt.Errorf("worker status maxConcurrentSandboxes must be non-negative")
	}
	if status.Capacity.ActiveSandboxes < 0 {
		return fmt.Errorf("worker status activeSandboxes must be non-negative")
	}
	if status.Capacity.MaxConcurrentSandboxes > 0 && status.Capacity.ActiveSandboxes > status.Capacity.MaxConcurrentSandboxes {
		return fmt.Errorf("worker status activeSandboxes must not exceed maxConcurrentSandboxes")
	}
	if err := status.Security.Validate(); err != nil {
		return fmt.Errorf("worker status security: %w", err)
	}
	for _, driverID := range status.SupportedRuntimeDrivers {
		if strings.TrimSpace(driverID) == "" {
			return fmt.Errorf("worker status supportedRuntimeDrivers must not include empty driver IDs")
		}
	}
	return nil
}

// WithDefaults returns capabilities with protocol defaults applied.
func (capabilities Capabilities) WithDefaults() Capabilities {
	capabilities.ProtocolVersion = defaultProtocolVersion(capabilities.ProtocolVersion)
	return capabilities
}

// Validate checks worker capabilities.
func (capabilities Capabilities) Validate() error {
	capabilities = capabilities.WithDefaults()
	if err := validateProtocolVersion(capabilities.ProtocolVersion); err != nil {
		return err
	}
	if strings.TrimSpace(capabilities.WorkerID) == "" {
		return fmt.Errorf("worker capabilities workerId is required")
	}
	for _, operation := range capabilities.SupportedOperations {
		if !validOperation(operation) {
			return fmt.Errorf("worker capabilities supported operation %q is unsupported", operation)
		}
	}
	if err := capabilities.Security.Validate(); err != nil {
		return fmt.Errorf("worker capabilities security: %w", err)
	}
	seenDrivers := map[string]bool{}
	for _, driver := range capabilities.RuntimeDrivers {
		if err := driver.Validate(); err != nil {
			return fmt.Errorf("worker capabilities runtime driver %q: %w", driver.ID, err)
		}
		if seenDrivers[driver.ID] {
			return fmt.Errorf("worker capabilities runtime driver %q is duplicated", driver.ID)
		}
		seenDrivers[driver.ID] = true
	}
	return nil
}

// Validate checks worker runtime driver capability metadata.
func (driver RuntimeDriver) Validate() error {
	if strings.TrimSpace(driver.ID) == "" {
		return fmt.Errorf("runtime driver id is required")
	}
	if !validHostKind(driver.HostKind) {
		return fmt.Errorf("runtime driver hostKind %q is unsupported", driver.HostKind)
	}
	if !validEnforcedIsolationLevel(driver.IsolationLevel) {
		return fmt.Errorf("runtime driver isolationLevel %q is unsupported or overstated", driver.IsolationLevel)
	}
	for _, operation := range driver.Operations {
		if !validOperation(operation) {
			return fmt.Errorf("runtime driver operation %q is unsupported", operation)
		}
	}
	if err := driver.Security.Validate(); err != nil {
		return fmt.Errorf("runtime driver security: %w", err)
	}
	return nil
}

// Validate checks security metadata and rejects unsupported enforcement claims.
func (policy SecurityPolicy) Validate() error {
	if err := validateRequestedSecurityControls(policy.Requested); err != nil {
		return fmt.Errorf("requested controls: %w", err)
	}
	if err := validateEnforcedSecurityControls(policy.Enforced); err != nil {
		return fmt.Errorf("enforced controls: %w", err)
	}
	return nil
}

// Validate checks creation payload fields.
func (req CreateRequest) Validate() error {
	if strings.TrimSpace(req.Name) == "" {
		return fmt.Errorf("create request name is required")
	}
	if err := req.Security.Validate(); err != nil {
		return fmt.Errorf("create request security: %w", err)
	}
	return nil
}

// Validate checks lifecycle payload fields.
func (req LifecycleRequest) Validate() error {
	return req.Target.Validate()
}

// Validate checks inspect payload fields.
func (req InspectRequest) Validate() error {
	return req.Target.Validate()
}

// Validate checks target fields.
func (target Target) Validate() error {
	if strings.TrimSpace(target.Name) == "" && strings.TrimSpace(target.ID) == "" {
		return fmt.Errorf("target name or id is required")
	}
	if strings.TrimSpace(target.Runtime.Driver) == "" {
		return fmt.Errorf("target runtime driver is required")
	}
	if target.Runtime.IsolationLevel != "" && !validEnforcedIsolationLevel(target.Runtime.IsolationLevel) {
		return fmt.Errorf("target runtime isolationLevel %q is unsupported or overstated", target.Runtime.IsolationLevel)
	}
	return nil
}

func defaultProtocolVersion(version string) string {
	if strings.TrimSpace(version) == "" {
		return ProtocolVersion
	}
	return strings.TrimSpace(version)
}

func validateProtocolVersion(version string) error {
	if version != ProtocolVersion {
		return fmt.Errorf("worker protocol version %q is unsupported", version)
	}
	return nil
}

func validateRequestedSecurityControls(controls SecurityControls) error {
	if controls.NetworkPolicy != "" && !validRequestedNetworkPolicy(controls.NetworkPolicy) {
		return fmt.Errorf("networkPolicy %q is unsupported", controls.NetworkPolicy)
	}
	if controls.NetworkEnforcement != "" && !validRequestedNetworkEnforcement(controls.NetworkEnforcement) {
		return fmt.Errorf("networkEnforcement %q is unsupported", controls.NetworkEnforcement)
	}
	if controls.IsolationLevel != "" && !validRequestedIsolationLevel(controls.IsolationLevel) {
		return fmt.Errorf("isolationLevel %q is unsupported", controls.IsolationLevel)
	}
	if controls.CredentialProxyMode {
		return fmt.Errorf("credentialProxyMode is unsupported")
	}
	return validateCredentialModes(controls.CredentialModes, false)
}

func validateEnforcedSecurityControls(controls SecurityControls) error {
	if controls.NetworkPolicy != "" && controls.NetworkPolicy != NetworkPolicyBestEffort {
		return fmt.Errorf("networkPolicy %q overstates worker enforcement", controls.NetworkPolicy)
	}
	switch controls.NetworkEnforcement {
	case "", NetworkEnforcementNone, NetworkEnforcementRuntime:
	default:
		return fmt.Errorf("networkEnforcement %q overstates worker enforcement", controls.NetworkEnforcement)
	}
	if controls.CredentialProxyMode {
		return fmt.Errorf("credentialProxyMode overstates worker credential support")
	}
	if controls.IsolationLevel != "" && !validEnforcedIsolationLevel(controls.IsolationLevel) {
		return fmt.Errorf("isolationLevel %q overstates worker isolation", controls.IsolationLevel)
	}
	return validateCredentialModes(controls.CredentialModes, true)
}

func validateCredentialModes(modes []string, enforced bool) error {
	for _, mode := range modes {
		mode = strings.TrimSpace(mode)
		if mode == "" {
			return fmt.Errorf("credentialModes must not include empty modes")
		}
		if !validCredentialMode(mode) {
			return fmt.Errorf("credentialModes %q is unsupported", mode)
		}
	}
	return nil
}

func validRequestedNetworkPolicy(policy string) bool {
	switch policy {
	case NetworkPolicyDenyByDefault, NetworkPolicyBestEffort:
		return true
	default:
		return false
	}
}

func validRequestedNetworkEnforcement(mode string) bool {
	switch mode {
	case NetworkEnforcementNone, NetworkEnforcementRuntime:
		return true
	default:
		return false
	}
}

func validRequestedIsolationLevel(level string) bool {
	switch level {
	case IsolationLevelHost, IsolationLevelContainer:
		return true
	default:
		return false
	}
}

func validEnforcedIsolationLevel(level string) bool {
	switch level {
	case IsolationLevelHost, IsolationLevelContainer:
		return true
	default:
		return false
	}
}

func validCredentialMode(mode string) bool {
	switch mode {
	case CredentialModeEnv,
		CredentialModeFileTmpfs,
		CredentialModeSSHAgent,
		CredentialModeLegacyAuthSync:
		return true
	default:
		return false
	}
}

func validOperation(operation string) bool {
	switch operation {
	case OperationStatus,
		OperationCapabilities,
		OperationCreate,
		OperationStart,
		OperationStop,
		OperationDelete,
		OperationInspect,
		OperationExec,
		OperationCopyIn,
		OperationCopyOut:
		return true
	default:
		return false
	}
}

func validHostKind(kind string) bool {
	switch kind {
	case HostKindLocal, HostKindWorker:
		return true
	default:
		return false
	}
}

func validHealthStatus(status string) bool {
	switch status {
	case HealthStatusHealthy, HealthStatusDegraded, HealthStatusUnhealthy, HealthStatusUnknown:
		return true
	default:
		return false
	}
}
