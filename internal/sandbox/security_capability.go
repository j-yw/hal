package sandbox

// SandboxSecurityCapabilityReadinessState is a durable, redaction-safe
// readiness label for security capability metadata.
type SandboxSecurityCapabilityReadinessState string

const (
	SandboxSecurityCapabilityReadinessMetadataOnly SandboxSecurityCapabilityReadinessState = "metadata_only"
	SandboxSecurityCapabilityReadinessUnsupported  SandboxSecurityCapabilityReadinessState = "unsupported"
	SandboxSecurityCapabilityReadinessBlocked      SandboxSecurityCapabilityReadinessState = "blocked"
	SandboxSecurityCapabilityReadinessReady        SandboxSecurityCapabilityReadinessState = "ready"
)

// SandboxSecurityCapabilityFamily groups security capabilities by contract
// area using enum-like metadata only.
type SandboxSecurityCapabilityFamily string

const (
	SandboxSecurityCapabilityFamilyNetworkPolicy   SandboxSecurityCapabilityFamily = "network_policy"
	SandboxSecurityCapabilityFamilyNetworkProxy    SandboxSecurityCapabilityFamily = "network_proxy"
	SandboxSecurityCapabilityFamilyCredentialProxy SandboxSecurityCapabilityFamily = "credential_proxy"
	SandboxSecurityCapabilityFamilySecretDelivery  SandboxSecurityCapabilityFamily = "secret_delivery"
	SandboxSecurityCapabilityFamilyIsolation       SandboxSecurityCapabilityFamily = "isolation"
	SandboxSecurityCapabilityFamilyWorkspace       SandboxSecurityCapabilityFamily = "workspace"
	SandboxSecurityCapabilityFamilyTemplate        SandboxSecurityCapabilityFamily = "template"
)

// SandboxSecurityCapabilityName identifies a requested or ready capability
// without carrying endpoints, paths, or credential material.
type SandboxSecurityCapabilityName string

const (
	SandboxSecurityCapabilityNetworkDenyByDefault       SandboxSecurityCapabilityName = "network_deny_by_default"
	SandboxSecurityCapabilityNetworkProxyEnforcement    SandboxSecurityCapabilityName = "network_proxy_enforcement"
	SandboxSecurityCapabilityNetworkFirewallEnforcement SandboxSecurityCapabilityName = "network_firewall_enforcement"
	SandboxSecurityCapabilityNetworkRuntimeEnforcement  SandboxSecurityCapabilityName = "network_runtime_enforcement"
	SandboxSecurityCapabilityCredentialProxy            SandboxSecurityCapabilityName = "credential_proxy"
	SandboxSecurityCapabilitySecretEnv                  SandboxSecurityCapabilityName = "secret_env"
	SandboxSecurityCapabilitySecretFileTmpfs            SandboxSecurityCapabilityName = "secret_file_tmpfs"
	SandboxSecurityCapabilitySecretSSHAgent             SandboxSecurityCapabilityName = "secret_ssh_agent"
	SandboxSecurityCapabilitySecretHTTPProxy            SandboxSecurityCapabilityName = "secret_http_proxy"
	SandboxSecurityCapabilityIsolationMicroVM           SandboxSecurityCapabilityName = "isolation_microvm"
	SandboxSecurityCapabilityIsolatedWorkspace          SandboxSecurityCapabilityName = "isolated_workspace"
	SandboxSecurityCapabilityDirectHostWorktree         SandboxSecurityCapabilityName = "direct_host_worktree"
	SandboxSecurityCapabilityTemplateLockDigest         SandboxSecurityCapabilityName = "template_lock_digest"
)

// SandboxSecurityCapabilitySource identifies where capability metadata came
// from without importing command, factory, worker, runtime, or provider code.
type SandboxSecurityCapabilitySource string

const (
	SandboxSecurityCapabilitySourceRequested SandboxSecurityCapabilitySource = "requested"
	SandboxSecurityCapabilitySourceMetadata  SandboxSecurityCapabilitySource = "metadata"
	SandboxSecurityCapabilitySourceRuntime   SandboxSecurityCapabilitySource = "runtime"
	SandboxSecurityCapabilitySourceWorker    SandboxSecurityCapabilitySource = "worker"
)

// SandboxSecurityCapabilityReasonCode is a safe explanation label for a
// readiness result.
type SandboxSecurityCapabilityReasonCode string

const (
	SandboxSecurityCapabilityReasonMetadataOnly                  SandboxSecurityCapabilityReasonCode = "metadata_only"
	SandboxSecurityCapabilityReasonCapabilityMissing             SandboxSecurityCapabilityReasonCode = "capability_missing"
	SandboxSecurityCapabilityReasonModeUnsupported               SandboxSecurityCapabilityReasonCode = "mode_unsupported"
	SandboxSecurityCapabilityReasonCapabilityBlocked             SandboxSecurityCapabilityReasonCode = "capability_blocked"
	SandboxSecurityCapabilityReasonCapabilityConfirmed           SandboxSecurityCapabilityReasonCode = "capability_confirmed"
	SandboxSecurityCapabilityReasonMetadataEnforcementUnproven   SandboxSecurityCapabilityReasonCode = "metadata_enforcement_unproven"
	SandboxSecurityCapabilityReasonMetadataDeliveryUnproven      SandboxSecurityCapabilityReasonCode = "metadata_delivery_unproven"
	SandboxSecurityCapabilityReasonReadinessMissing              SandboxSecurityCapabilityReasonCode = "readiness_missing"
	SandboxSecurityCapabilityReasonMicroVMReadinessMissing       SandboxSecurityCapabilityReasonCode = "microvm_readiness_missing"
	SandboxSecurityCapabilityReasonMicroVMSupportMissing         SandboxSecurityCapabilityReasonCode = "microvm_support_missing"
	SandboxSecurityCapabilityReasonWorkspaceIsolationMissing     SandboxSecurityCapabilityReasonCode = "workspace_isolation_missing"
	SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree   SandboxSecurityCapabilityReasonCode = "workspace_direct_host_worktree"
	SandboxSecurityCapabilityReasonNetworkEnforcementMissing     SandboxSecurityCapabilityReasonCode = "network_enforcement_missing"
	SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly SandboxSecurityCapabilityReasonCode = "network_enforcement_planned_only"
	SandboxSecurityCapabilityReasonNetworkEnforcementBestEffort  SandboxSecurityCapabilityReasonCode = "network_enforcement_best_effort"
	SandboxSecurityCapabilityReasonNetworkEnforcementPartial     SandboxSecurityCapabilityReasonCode = "network_enforcement_partial"
	SandboxSecurityCapabilityReasonNetworkEnforcementUnsupported SandboxSecurityCapabilityReasonCode = "network_enforcement_unsupported"
	SandboxSecurityCapabilityReasonNetworkEnforcementFailed      SandboxSecurityCapabilityReasonCode = "network_enforcement_failed"
	SandboxSecurityCapabilityReasonCredentialActivationMissing   SandboxSecurityCapabilityReasonCode = "credential_activation_missing"
	SandboxSecurityCapabilityReasonTemplateLockDigestMissing     SandboxSecurityCapabilityReasonCode = "template_lock_digest_missing"
	SandboxSecurityCapabilityReasonMicroVMReadinessConfirmed     SandboxSecurityCapabilityReasonCode = "microvm_readiness_confirmed"
	SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed   SandboxSecurityCapabilityReasonCode = "workspace_isolation_confirmed"
	SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed   SandboxSecurityCapabilityReasonCode = "network_enforcement_confirmed"
	SandboxSecurityCapabilityReasonCredentialActivationConfirmed SandboxSecurityCapabilityReasonCode = "credential_activation_confirmed"
	SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed   SandboxSecurityCapabilityReasonCode = "template_lock_digest_confirmed"
	SandboxSecurityCapabilityReasonUnknown                       SandboxSecurityCapabilityReasonCode = "unknown"
)

// SandboxSecurityCapabilityWarningCode is a safe warning label for readiness
// results.
type SandboxSecurityCapabilityWarningCode string

const (
	SandboxSecurityCapabilityWarningMetadataNotCapability SandboxSecurityCapabilityWarningCode = "metadata_not_capability"
	SandboxSecurityCapabilityWarningUnsupportedMode       SandboxSecurityCapabilityWarningCode = "unsupported_mode"
	SandboxSecurityCapabilityWarningBlockedByPolicy       SandboxSecurityCapabilityWarningCode = "blocked_by_policy"
)

// SandboxSecurityCapabilityMetadata describes a requested or ready capability
// using only safe identifiers and enum-like metadata.
type SandboxSecurityCapabilityMetadata struct {
	ID           string                                  `json:"id,omitempty"`
	Family       SandboxSecurityCapabilityFamily         `json:"family"`
	Capability   SandboxSecurityCapabilityName           `json:"capability"`
	Mode         string                                  `json:"mode,omitempty"`
	Source       SandboxSecurityCapabilitySource         `json:"source,omitempty"`
	Status       SandboxSecurityCapabilityReadinessState `json:"status,omitempty"`
	ReasonCode   SandboxSecurityCapabilityReasonCode     `json:"reasonCode,omitempty"`
	WarningCodes []SandboxSecurityCapabilityWarningCode  `json:"warningCodes,omitempty"`
}

// SandboxSecurityCapabilityWorkerPostureMetadata captures safe local/worker
// posture labels without treating them as proof of live security capability.
type SandboxSecurityCapabilityWorkerPostureMetadata struct {
	WorkerKind          string   `json:"workerKind,omitempty"`
	RuntimeDriver       string   `json:"runtimeDriver,omitempty"`
	IsolationLevel      string   `json:"isolationLevel,omitempty"`
	NetworkPolicy       string   `json:"networkPolicy,omitempty"`
	NetworkEnforcement  string   `json:"networkEnforcement,omitempty"`
	CredentialModes     []string `json:"credentialModes,omitempty"`
	CredentialProxyMode bool     `json:"credentialProxyMode,omitempty"`
}

// SandboxSecurityCapabilityReadinessRequest separates requested capabilities
// from explicit capability metadata and existing metadata-only records.
type SandboxSecurityCapabilityReadinessRequest struct {
	Requested                 []SandboxSecurityCapabilityMetadata              `json:"requested,omitempty"`
	Ready                     []SandboxSecurityCapabilityMetadata              `json:"ready,omitempty"`
	WorkerPostures            []SandboxSecurityCapabilityWorkerPostureMetadata `json:"workerPostures,omitempty"`
	NetworkProxySession       *SandboxNetworkProxySessionMetadata              `json:"networkProxySession,omitempty"`
	NetworkPolicyDecisionLogs []SandboxNetworkPolicyDecisionLogRecord          `json:"networkPolicyDecisionLogs,omitempty"`
	CredentialProxyPlan       *SandboxCredentialProxyPlanMetadata              `json:"credentialPlanMetadata,omitempty"`
	CredentialProxySession    *SandboxCredentialProxySessionMetadata           `json:"credentialSessionMetadata,omitempty"`
	CredentialProxyBindings   []SandboxCredentialProxyBindingMetadata          `json:"credentialBindingMetadata,omitempty"`
}

// SandboxSecurityCapabilityReadinessInput is the request-shaped input contract
// accepted by readiness evaluation. It is an alias so callers can use either
// request or input terminology without changing the JSON contract.
type SandboxSecurityCapabilityReadinessInput = SandboxSecurityCapabilityReadinessRequest

// SandboxSecurityCapabilityReadinessResult records one readiness decision for
// requested, ready, or metadata-only capability posture.
type SandboxSecurityCapabilityReadinessResult struct {
	State        SandboxSecurityCapabilityReadinessState `json:"state"`
	Metadata     *SandboxSecurityCapabilityMetadata      `json:"metadata,omitempty"`
	Requested    *SandboxSecurityCapabilityMetadata      `json:"requested,omitempty"`
	Ready        *SandboxSecurityCapabilityMetadata      `json:"ready,omitempty"`
	ReasonCode   SandboxSecurityCapabilityReasonCode     `json:"reasonCode,omitempty"`
	WarningCodes []SandboxSecurityCapabilityWarningCode  `json:"warningCodes,omitempty"`
}

// SandboxSecurityCapabilityReadinessOutput is the result-shaped output contract
// for readiness evaluation. It carries only per-capability readiness decisions.
type SandboxSecurityCapabilityReadinessOutput struct {
	Results []SandboxSecurityCapabilityReadinessResult `json:"results,omitempty"`
}
