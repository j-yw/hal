// Package credentialdelivery defines durable metadata contracts for credential
// delivery planning and activation. The package is data-only: it carries safe
// identifiers and enum-like state, not secret material or live adapter details.
package credentialdelivery

import (
	"strconv"

	"github.com/jywlabs/hal/internal/sandbox"
)

// Mode is a stable metadata identifier for a supported delivery mode.
type Mode string

const (
	ModeHTTPProxy      Mode = "http_proxy"
	ModeSSHAgent       Mode = "ssh_agent"
	ModeFileTmpfs      Mode = "file_tmpfs"
	ModeEnv            Mode = "env"
	ModeLegacyAuthSync Mode = "legacy_auth_sync"
)

// SupportedModes returns the exact credential delivery metadata modes Hal
// recognizes for planning.
func SupportedModes() []Mode {
	return []Mode{
		ModeHTTPProxy,
		ModeSSHAgent,
		ModeFileTmpfs,
		ModeEnv,
		ModeLegacyAuthSync,
	}
}

// DestinationCategory is a safe destination class for binding metadata. It
// intentionally excludes raw hosts, IPs, ports, URLs, paths, and socket names.
type DestinationCategory string

const (
	DestinationPublicInternet  DestinationCategory = "public_internet"
	DestinationPrivateNetwork  DestinationCategory = "private_network"
	DestinationMetadataService DestinationCategory = "metadata_service"
	DestinationLoopback        DestinationCategory = "loopback"
	DestinationUnixSocket      DestinationCategory = "unix_socket"
	DestinationUnknown         DestinationCategory = "unknown"
)

// SupportedDestinationCategories returns the exact credential delivery
// destination classes Hal recognizes for persisted binding metadata.
func SupportedDestinationCategories() []DestinationCategory {
	return []DestinationCategory{
		DestinationPublicInternet,
		DestinationPrivateNetwork,
		DestinationMetadataService,
		DestinationLoopback,
		DestinationUnixSocket,
		DestinationUnknown,
	}
}

// Source identifies where delivery metadata was produced.
type Source string

const (
	SourceRun     Source = "run"
	SourceAuto    Source = "auto"
	SourceFactory Source = "factory"
	SourceWorker  Source = "worker"
	SourceRuntime Source = "runtime"
)

// Status is a redaction-safe lifecycle state shared by requests, bindings,
// plans, activations, and status summaries.
type Status string

const (
	StatusRequested Status = "requested"
	StatusPlanned   Status = "planned"
	StatusReady     Status = "ready"
	StatusActive    Status = "active"
	StatusCompleted Status = "completed"
	StatusSkipped   Status = "skipped"
	StatusFailed    Status = "failed"
	StatusDisabled  Status = "disabled"
)

// ReasonCode is a stable explanation label for delivery metadata.
type ReasonCode string

const (
	ReasonRequested              ReasonCode = "requested"
	ReasonUnsupportedMode        ReasonCode = "unsupported_mode"
	ReasonMissingSecretReference ReasonCode = "missing_secret_reference"
	ReasonMissingServiceBinding  ReasonCode = "missing_service_binding"
	ReasonActivationUnavailable  ReasonCode = "activation_unavailable"
	ReasonCompatibilityMode      ReasonCode = "compatibility_mode"
	ReasonDisabled               ReasonCode = "disabled"
	ReasonUnknown                ReasonCode = "unknown"
)

// WarningCode is a redaction-safe warning label for delivery metadata.
type WarningCode string

const (
	WarningUnsupportedMode         WarningCode = "unsupported_mode"
	WarningBindingOmitted          WarningCode = "binding_omitted"
	WarningActivationSkipped       WarningCode = "activation_skipped"
	WarningAdapterUnavailable      WarningCode = "adapter_unavailable"
	WarningLegacyAuthCompatibility WarningCode = "legacy_auth_compatibility"
)

// ErrorCode is a redaction-safe error label for delivery metadata.
type ErrorCode string

const (
	ErrorMissingRequiredField   ErrorCode = "missing_required_field"
	ErrorMissingSecretReference ErrorCode = "missing_secret_reference"
	ErrorUnsupportedMode        ErrorCode = "unsupported_mode"
	ErrorUnsupportedCategory    ErrorCode = "unsupported_category"
	ErrorUnsafeReference        ErrorCode = "unsafe_reference"
	ErrorUnsafeMetadata         ErrorCode = "unsafe_metadata"
	ErrorDuplicateBinding       ErrorCode = "duplicate_binding"
	ErrorResolverFailed         ErrorCode = "resolver_failed"
	ErrorActivationFailed       ErrorCode = "activation_failed"
)

// Request captures requested delivery intent and any already-active delivery
// metadata using safe identifiers only.
type Request struct {
	ID             string    `json:"id"`
	Source         Source    `json:"source,omitempty"`
	RequestedModes []Mode    `json:"requestedModes,omitempty"`
	ActiveModes    []Mode    `json:"activeModes,omitempty"`
	Bindings       []Binding `json:"bindings,omitempty"`
	Status         Status    `json:"status,omitempty"`
}

// Binding identifies one safe secret reference and the delivery mode requested
// for it. ServiceID, labels, policy snapshot IDs, plan IDs, and proxy session
// IDs are durable metadata only; they are not raw transport endpoints.
type Binding struct {
	ID                    string              `json:"id"`
	RequestID             string              `json:"requestId,omitempty"`
	PlanID                string              `json:"planId,omitempty"`
	PolicySnapshotID      string              `json:"policySnapshotId,omitempty"`
	SecretRef             string              `json:"secretRef"`
	NetworkProxySessionID string              `json:"networkProxySessionId,omitempty"`
	ServiceID             string              `json:"serviceId,omitempty"`
	ServiceLabels         []string            `json:"serviceLabels,omitempty"`
	DomainLabels          []string            `json:"domainLabels,omitempty"`
	DestinationCategory   DestinationCategory `json:"destinationCategory,omitempty"`
	DeliveryMode          Mode                `json:"deliveryMode"`
	Status                Status              `json:"status,omitempty"`
	ReasonCode            ReasonCode          `json:"reasonCode,omitempty"`
}

// SecretReference is the safe broker ID passed to a metadata resolver. It must
// not contain raw secret values, provider details, endpoints, or local paths.
type SecretReference struct {
	BindingID string `json:"bindingId,omitempty"`
	SecretRef string `json:"secretRef"`
}

// BrokerSecretMetadata is the resolver output allowed into delivery planning.
// It intentionally excludes secret names, values, provider payloads, endpoints,
// paths, and delivery handles.
type BrokerSecretMetadata struct {
	ID       string `json:"id"`
	Source   string `json:"source,omitempty"`
	Required bool   `json:"required"`
	Present  bool   `json:"present"`
}

// ResolvedBindingSecretMetadata records that a binding's safe secret reference
// matched broker metadata. It is planning metadata only and carries no value.
type ResolvedBindingSecretMetadata struct {
	BindingID    string               `json:"bindingId"`
	SecretRef    string               `json:"secretRef"`
	DeliveryMode Mode                 `json:"deliveryMode,omitempty"`
	BrokerSecret BrokerSecretMetadata `json:"brokerSecret"`
}

// SecretResolutionResult is the fail-closed output of resolving binding secret
// references before any delivery plan can be activated.
type SecretResolutionResult struct {
	Valid    bool                            `json:"valid"`
	Bindings []ResolvedBindingSecretMetadata `json:"bindings,omitempty"`
	Warnings []Warning                       `json:"warnings,omitempty"`
	Errors   []SanitizedError                `json:"errors,omitempty"`
}

// Plan is a durable delivery plan summary produced before activation.
type Plan struct {
	ID                    string           `json:"id"`
	RequestID             string           `json:"requestId,omitempty"`
	NetworkProxySessionID string           `json:"networkProxySessionId,omitempty"`
	HTTPProxyProof        *HTTPProxyProof  `json:"httpProxyProof,omitempty"`
	RequestedModes        []Mode           `json:"requestedModes,omitempty"`
	ActiveModes           []Mode           `json:"activeModes,omitempty"`
	BindingCount          int              `json:"bindingCount,omitempty"`
	Status                Status           `json:"status,omitempty"`
	Warnings              []Warning        `json:"warnings,omitempty"`
	Errors                []SanitizedError `json:"errors,omitempty"`
}

// HTTPProxyProof records the safe broker and network-enforcement proof IDs
// that allow an http_proxy binding to become active after adapter activation.
type HTTPProxyProof struct {
	BindingID                string                                          `json:"bindingId,omitempty"`
	SecretID                 string                                          `json:"secretId,omitempty"`
	SecretBrokerSessionID    string                                          `json:"secretBrokerSessionId,omitempty"`
	CredentialProxyPlanID    string                                          `json:"credentialProxyPlanId,omitempty"`
	CredentialProxySessionID string                                          `json:"credentialProxySessionId,omitempty"`
	CredentialProxyBindingID string                                          `json:"credentialProxyBindingId,omitempty"`
	NetworkEnforcement       *sandbox.SandboxNetworkEnforcementProofMetadata `json:"networkEnforcement,omitempty"`
}

// ActivationRequest is the redaction-safe adapter input for an activation
// attempt. It contains a sanitized plan and binding metadata only, never secret
// values or live delivery handles.
type ActivationRequest struct {
	ActivationID string    `json:"activationId,omitempty"`
	Plan         Plan      `json:"plan"`
	Bindings     []Binding `json:"bindings,omitempty"`
}

// ActivationResult records the redaction-safe outcome of an activation attempt.
type ActivationResult struct {
	ID             string                     `json:"id"`
	PlanID         string                     `json:"planId"`
	RequestedModes []Mode                     `json:"requestedModes,omitempty"`
	ActiveModes    []Mode                     `json:"activeModes,omitempty"`
	Bindings       []BindingActivationResult  `json:"bindings,omitempty"`
	ProofRefs      []ActivationProofReference `json:"proofRefs,omitempty"`
	Status         Status                     `json:"status,omitempty"`
	ReasonCode     ReasonCode                 `json:"reasonCode,omitempty"`
	Warnings       []Warning                  `json:"warnings,omitempty"`
}

// BindingActivationResult records the activation state for one planned binding.
type BindingActivationResult struct {
	BindingID    string     `json:"bindingId"`
	DeliveryMode Mode       `json:"deliveryMode"`
	Status       Status     `json:"status,omitempty"`
	ReasonCode   ReasonCode `json:"reasonCode,omitempty"`
	ProofRef     string     `json:"proofRef,omitempty"`
}

// ActivationProofReference records a safe proof identifier associated with a
// binding and delivery mode. It is not a raw adapter handle or transport path.
type ActivationProofReference struct {
	ProofID      string `json:"proofId"`
	BindingID    string `json:"bindingId,omitempty"`
	DeliveryMode Mode   `json:"deliveryMode"`
}

// StatusMetadata is a compact delivery lifecycle summary for durable surfaces.
type StatusMetadata struct {
	ID             string     `json:"id"`
	RequestID      string     `json:"requestId,omitempty"`
	PlanID         string     `json:"planId,omitempty"`
	ActivationID   string     `json:"activationId,omitempty"`
	RequestedModes []Mode     `json:"requestedModes,omitempty"`
	ActiveModes    []Mode     `json:"activeModes,omitempty"`
	Status         Status     `json:"status,omitempty"`
	ReasonCode     ReasonCode `json:"reasonCode,omitempty"`
	WarningCount   int        `json:"warningCount,omitempty"`
	ErrorCount     int        `json:"errorCount,omitempty"`
}

// Warning contains safe metadata about a non-fatal delivery planning or
// activation condition.
type Warning struct {
	Code       WarningCode `json:"code"`
	ReasonCode ReasonCode  `json:"reasonCode,omitempty"`
	BindingID  string      `json:"bindingId,omitempty"`
	Mode       Mode        `json:"mode,omitempty"`
}

// SanitizedError identifies a delivery error by safe code and location only.
type SanitizedError struct {
	Code       ErrorCode  `json:"code"`
	Field      string     `json:"field,omitempty"`
	BindingID  string     `json:"bindingId,omitempty"`
	Mode       Mode       `json:"mode,omitempty"`
	Index      *int       `json:"index,omitempty"`
	ReasonCode ReasonCode `json:"reasonCode,omitempty"`
}

func (e SanitizedError) Error() string {
	code := string(e.Code)
	if code == "" {
		code = "credential_delivery_error"
	}
	location := "metadata"
	if e.Field != "" {
		location = e.Field
	}
	if e.Index != nil {
		location += "[" + strconv.Itoa(*e.Index) + "]"
	}
	return "credential delivery " + code + " at " + location
}

// ValidationResult is the deterministic output of pure credential delivery
// metadata validation. Errors must identify safe fields and indexes only.
type ValidationResult struct {
	Valid  bool             `json:"valid"`
	Errors []SanitizedError `json:"errors,omitempty"`
}
