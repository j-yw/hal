package sandbox

// SandboxCredentialProxySource identifies where credential proxy metadata was
// produced without importing command, factory, or worker packages.
type SandboxCredentialProxySource string

const (
	SandboxCredentialProxySourceRun     SandboxCredentialProxySource = "run"
	SandboxCredentialProxySourceAuto    SandboxCredentialProxySource = "auto"
	SandboxCredentialProxySourceFactory SandboxCredentialProxySource = "factory"
	SandboxCredentialProxySourceWorker  SandboxCredentialProxySource = "worker"
)

// SandboxCredentialProxyMode is a metadata-only credential proxy plan mode. It
// describes intended coordination between safe secret broker and network proxy
// references without carrying delivery behavior.
type SandboxCredentialProxyMode string

const (
	SandboxCredentialProxyModeMetadataOnly             SandboxCredentialProxyMode = "metadata_only"
	SandboxCredentialProxyModeSecretBrokerReference    SandboxCredentialProxyMode = "secret_broker_reference"
	SandboxCredentialProxyModeNetworkProxyReference    SandboxCredentialProxyMode = "network_proxy_reference"
	SandboxCredentialProxyModeBrokeredNetworkReference SandboxCredentialProxyMode = "brokered_network_reference"
)

// SandboxCredentialProxyStatus is a durable state label for credential proxy
// plans, sessions, and bindings. It does not imply runtime behavior exists.
type SandboxCredentialProxyStatus string

const (
	SandboxCredentialProxyStatusPlanned   SandboxCredentialProxyStatus = "planned"
	SandboxCredentialProxyStatusReady     SandboxCredentialProxyStatus = "ready"
	SandboxCredentialProxyStatusActive    SandboxCredentialProxyStatus = "active"
	SandboxCredentialProxyStatusCompleted SandboxCredentialProxyStatus = "completed"
	SandboxCredentialProxyStatusSkipped   SandboxCredentialProxyStatus = "skipped"
	SandboxCredentialProxyStatusFailed    SandboxCredentialProxyStatus = "failed"
	SandboxCredentialProxyStatusDisabled  SandboxCredentialProxyStatus = "disabled"
)

// SandboxCredentialProxyBindingOutcome records the durable result of one
// credential proxy binding without exposing secret values or delivery output.
type SandboxCredentialProxyBindingOutcome string

const (
	SandboxCredentialProxyBindingOutcomePlanned   SandboxCredentialProxyBindingOutcome = "planned"
	SandboxCredentialProxyBindingOutcomeBound     SandboxCredentialProxyBindingOutcome = "bound"
	SandboxCredentialProxyBindingOutcomeOmitted   SandboxCredentialProxyBindingOutcome = "omitted"
	SandboxCredentialProxyBindingOutcomeSkipped   SandboxCredentialProxyBindingOutcome = "skipped"
	SandboxCredentialProxyBindingOutcomeFailed    SandboxCredentialProxyBindingOutcome = "failed"
	SandboxCredentialProxyBindingOutcomeAuditOnly SandboxCredentialProxyBindingOutcome = "audit_only"
)

// SandboxCredentialProxyWarningCode is a redaction-safe warning label for
// credential proxy session metadata.
type SandboxCredentialProxyWarningCode string

const (
	SandboxCredentialProxyWarningMissingSecretBrokerSession SandboxCredentialProxyWarningCode = "missing_secret_broker_session"
	SandboxCredentialProxyWarningMissingNetworkProxySession SandboxCredentialProxyWarningCode = "missing_network_proxy_session"
	SandboxCredentialProxyWarningPolicySnapshotUnavailable  SandboxCredentialProxyWarningCode = "policy_snapshot_unavailable"
	SandboxCredentialProxyWarningUnsupportedDeliveryMode    SandboxCredentialProxyWarningCode = "unsupported_delivery_mode"
	SandboxCredentialProxyWarningBindingOmitted             SandboxCredentialProxyWarningCode = "binding_omitted"
)

// SandboxCredentialProxyReasonCode is a redaction-safe reason label shared by
// session and binding metadata.
type SandboxCredentialProxyReasonCode string

const (
	SandboxCredentialProxyReasonRequested                  SandboxCredentialProxyReasonCode = "requested"
	SandboxCredentialProxyReasonSecretBrokerUnavailable    SandboxCredentialProxyReasonCode = "secret_broker_unavailable"
	SandboxCredentialProxyReasonNetworkProxyUnavailable    SandboxCredentialProxyReasonCode = "network_proxy_unavailable"
	SandboxCredentialProxyReasonPolicySnapshotUnavailable  SandboxCredentialProxyReasonCode = "policy_snapshot_unavailable"
	SandboxCredentialProxyReasonDeliveryModeUnsupported    SandboxCredentialProxyReasonCode = "delivery_mode_unsupported"
	SandboxCredentialProxyReasonDestinationCategorySkipped SandboxCredentialProxyReasonCode = "destination_category_skipped"
	SandboxCredentialProxyReasonDisabled                   SandboxCredentialProxyReasonCode = "disabled"
	SandboxCredentialProxyReasonUnknown                    SandboxCredentialProxyReasonCode = "unknown"
)

// SandboxCredentialProxyDeliveryMode is a durable delivery mode identifier for
// credential proxy bindings. It mirrors sandbox secret mode identifiers as
// metadata only and never carries credential material.
type SandboxCredentialProxyDeliveryMode string

const (
	SandboxCredentialProxyDeliveryModeEnv            SandboxCredentialProxyDeliveryMode = SandboxSecretModeEnv
	SandboxCredentialProxyDeliveryModeFileTmpfs      SandboxCredentialProxyDeliveryMode = SandboxSecretModeFileTmpfs
	SandboxCredentialProxyDeliveryModeSSHAgent       SandboxCredentialProxyDeliveryMode = SandboxSecretModeSSHAgent
	SandboxCredentialProxyDeliveryModeHTTPProxy      SandboxCredentialProxyDeliveryMode = SandboxSecretModeHTTPProxy
	SandboxCredentialProxyDeliveryModeLegacyAuthSync SandboxCredentialProxyDeliveryMode = SandboxSecretModeLegacyAuthSync
)

// SandboxCredentialProxyRequestCategory is a safe request class for binding
// metadata. It intentionally excludes raw methods, URLs, hosts, headers, bodies,
// environment values, socket paths, and local paths.
type SandboxCredentialProxyRequestCategory string

const (
	SandboxCredentialProxyRequestSecretDelivery SandboxCredentialProxyRequestCategory = "secret_delivery"
	SandboxCredentialProxyRequestNetworkAuth    SandboxCredentialProxyRequestCategory = "network_auth"
	SandboxCredentialProxyRequestSourceControl  SandboxCredentialProxyRequestCategory = "source_control"
	SandboxCredentialProxyRequestArtifactSync   SandboxCredentialProxyRequestCategory = "artifact_sync"
	SandboxCredentialProxyRequestUnknown        SandboxCredentialProxyRequestCategory = "unknown"
)

// SandboxCredentialProxyPlanMetadata captures a durable credential proxy plan
// using safe identifiers and enum-like metadata only. It must not contain raw
// hosts, URLs, ports, headers, environment values, socket paths, local paths,
// tokens, credential values, secret values, or raw network destinations.
type SandboxCredentialProxyPlanMetadata struct {
	ID                    string                                `json:"id"`
	Source                SandboxCredentialProxySource          `json:"source"`
	SecretBrokerSessionID string                                `json:"secretBrokerSessionId,omitempty"`
	NetworkProxySessionID string                                `json:"networkProxySessionId,omitempty"`
	PolicySnapshot        *SandboxNetworkPolicySnapshotIdentity `json:"policySnapshot,omitempty"`
	BindingCount          int                                   `json:"bindingCount,omitempty"`
	Mode                  SandboxCredentialProxyMode            `json:"mode,omitempty"`
	Status                SandboxCredentialProxyStatus          `json:"status,omitempty"`
}

// SandboxCredentialProxySessionMetadata captures durable session metadata for
// future credential proxy plumbing without representing listeners, runtime
// mutation paths, or credential material channels.
type SandboxCredentialProxySessionMetadata struct {
	ID                    string                                `json:"id"`
	PlanID                string                                `json:"planId"`
	Source                SandboxCredentialProxySource          `json:"source"`
	SecretBrokerSessionID string                                `json:"secretBrokerSessionId,omitempty"`
	NetworkProxySessionID string                                `json:"networkProxySessionId,omitempty"`
	PolicySnapshot        *SandboxNetworkPolicySnapshotIdentity `json:"policySnapshot,omitempty"`
	Status                SandboxCredentialProxyStatus          `json:"status,omitempty"`
	WarningCode           SandboxCredentialProxyWarningCode     `json:"warningCode,omitempty"`
	ReasonCode            SandboxCredentialProxyReasonCode      `json:"reasonCode,omitempty"`
}

// SandboxCredentialProxyBindingMetadata identifies one safe binding between a
// credential proxy plan or session and a safe secret reference. It carries only
// IDs, enum-like delivery metadata, safe request categories, and safe network
// destination categories.
type SandboxCredentialProxyBindingMetadata struct {
	ID                  string                                  `json:"id"`
	PlanID              string                                  `json:"planId,omitempty"`
	SessionID           string                                  `json:"sessionId,omitempty"`
	SecretID            string                                  `json:"secretId"`
	DeliveryMode        SandboxCredentialProxyDeliveryMode      `json:"deliveryMode"`
	RequestCategory     SandboxCredentialProxyRequestCategory   `json:"requestCategory,omitempty"`
	DestinationCategory SandboxNetworkPolicyDestinationCategory `json:"destinationCategory,omitempty"`
	Outcome             SandboxCredentialProxyBindingOutcome    `json:"outcome,omitempty"`
	Status              SandboxCredentialProxyStatus            `json:"status,omitempty"`
	ReasonCode          SandboxCredentialProxyReasonCode        `json:"reasonCode,omitempty"`
}
