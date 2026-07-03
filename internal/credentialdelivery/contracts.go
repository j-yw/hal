// Package credentialdelivery defines durable metadata contracts for credential
// delivery planning and activation. The package is data-only: it carries safe
// identifiers and enum-like state, not secret material or live adapter details.
package credentialdelivery

import "strconv"

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
	ErrorMissingRequiredField ErrorCode = "missing_required_field"
	ErrorUnsupportedMode      ErrorCode = "unsupported_mode"
	ErrorUnsafeReference      ErrorCode = "unsafe_reference"
	ErrorDuplicateBinding     ErrorCode = "duplicate_binding"
	ErrorActivationFailed     ErrorCode = "activation_failed"
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
// for it. ServiceID is an opaque safe service identifier, not a transport
// endpoint.
type Binding struct {
	ID           string     `json:"id"`
	RequestID    string     `json:"requestId,omitempty"`
	PlanID       string     `json:"planId,omitempty"`
	SecretRef    string     `json:"secretRef"`
	ServiceID    string     `json:"serviceId,omitempty"`
	DeliveryMode Mode       `json:"deliveryMode"`
	Status       Status     `json:"status,omitempty"`
	ReasonCode   ReasonCode `json:"reasonCode,omitempty"`
}

// Plan is a durable delivery plan summary produced before activation.
type Plan struct {
	ID             string           `json:"id"`
	RequestID      string           `json:"requestId,omitempty"`
	RequestedModes []Mode           `json:"requestedModes,omitempty"`
	ActiveModes    []Mode           `json:"activeModes,omitempty"`
	BindingCount   int              `json:"bindingCount,omitempty"`
	Status         Status           `json:"status,omitempty"`
	Warnings       []Warning        `json:"warnings,omitempty"`
	Errors         []SanitizedError `json:"errors,omitempty"`
}

// ActivationResult records the redaction-safe outcome of an activation attempt.
type ActivationResult struct {
	ID             string                    `json:"id"`
	PlanID         string                    `json:"planId"`
	RequestedModes []Mode                    `json:"requestedModes,omitempty"`
	ActiveModes    []Mode                    `json:"activeModes,omitempty"`
	Bindings       []BindingActivationResult `json:"bindings,omitempty"`
	Status         Status                    `json:"status,omitempty"`
	Warnings       []Warning                 `json:"warnings,omitempty"`
	Errors         []SanitizedError          `json:"errors,omitempty"`
}

// BindingActivationResult records the activation state for one planned binding.
type BindingActivationResult struct {
	BindingID    string     `json:"bindingId"`
	DeliveryMode Mode       `json:"deliveryMode"`
	Status       Status     `json:"status,omitempty"`
	ReasonCode   ReasonCode `json:"reasonCode,omitempty"`
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
