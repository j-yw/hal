package microvm

import (
	"encoding/json"
	"regexp"
	"strings"
)

const (
	LiveE2EComponentFirecracker        LiveE2EReadinessComponent = "firecracker"
	LiveE2EComponentKVM                LiveE2EReadinessComponent = "kvm"
	LiveE2EComponentNetworkProxy       LiveE2EReadinessComponent = "network_proxy"
	LiveE2EComponentFirewall           LiveE2EReadinessComponent = "firewall"
	LiveE2EComponentCredentialDelivery LiveE2EReadinessComponent = "credential_delivery"
	LiveE2EComponentTemplateTrust      LiveE2EReadinessComponent = "template_trust"
)

const (
	LiveE2EReadinessUnknown     LiveE2EReadinessStatus = "unknown"
	LiveE2EReadinessReady       LiveE2EReadinessStatus = "ready"
	LiveE2EReadinessMissing     LiveE2EReadinessStatus = "missing"
	LiveE2EReadinessUnavailable LiveE2EReadinessStatus = "unavailable"
	LiveE2EReadinessBlocked     LiveE2EReadinessStatus = "blocked"
	LiveE2EReadinessSkipped     LiveE2EReadinessStatus = "skipped"
)

const (
	LiveE2EReasonReady                              LiveE2EReasonCode = "ready"
	LiveE2EReasonNotRequested                       LiveE2EReasonCode = "not_requested"
	LiveE2EReasonBuildTagMissing                    LiveE2EReasonCode = "build_tag_missing"
	LiveE2EReasonLiveMarkerMissing                  LiveE2EReasonCode = "live_marker_missing"
	LiveE2EReasonFirecrackerMarkerMissing           LiveE2EReasonCode = "firecracker_marker_missing"
	LiveE2EReasonFirecrackerBinaryMissing           LiveE2EReasonCode = "firecracker_binary_missing"
	LiveE2EReasonFirecrackerKernelMissing           LiveE2EReasonCode = "firecracker_kernel_missing"
	LiveE2EReasonFirecrackerRootfsMissing           LiveE2EReasonCode = "firecracker_rootfs_missing"
	LiveE2EReasonFirecrackerUnavailable             LiveE2EReasonCode = "firecracker_unavailable"
	LiveE2EReasonKVMCapabilityMissing               LiveE2EReasonCode = "kvm_capability_missing"
	LiveE2EReasonKVMDeviceMissing                   LiveE2EReasonCode = "kvm_device_missing"
	LiveE2EReasonKVMUnreadable                      LiveE2EReasonCode = "kvm_unreadable"
	LiveE2EReasonNetworkProxyMarkerMissing          LiveE2EReasonCode = "network_proxy_marker_missing"
	LiveE2EReasonNetworkProxyUnavailable            LiveE2EReasonCode = "network_proxy_unavailable"
	LiveE2EReasonFirewallMarkerMissing              LiveE2EReasonCode = "firewall_marker_missing"
	LiveE2EReasonFirewallUnavailable                LiveE2EReasonCode = "firewall_unavailable"
	LiveE2EReasonCredentialDeliveryMarkerMissing    LiveE2EReasonCode = "credential_delivery_marker_missing"
	LiveE2EReasonCredentialDeliveryEnvMarkerMissing LiveE2EReasonCode = "credential_delivery_env_marker_missing"
	LiveE2EReasonCredentialDeliveryUnavailable      LiveE2EReasonCode = "credential_delivery_unavailable"
	LiveE2EReasonTemplateTrustMarkerMissing         LiveE2EReasonCode = "template_trust_marker_missing"
	LiveE2EReasonTemplateTrustUnavailable           LiveE2EReasonCode = "template_trust_unavailable"
)

const (
	liveE2EMaxIDBytes      = 128
	liveE2EMaxMessageBytes = 256
)

var (
	liveE2EEnvironmentAssignmentPattern = regexp.MustCompile(`\b([A-Z][A-Z0-9_]{2,})\s*=\s*[^\s,;]+`)
	liveE2ELocalSocketPattern           = regexp.MustCompile(`(?i)\b[a-z0-9_.-]+\.sock\b`)
	liveE2EHostAssignmentPattern        = regexp.MustCompile(`(?i)\b(host|hostname)\s*[=:]\s*[a-z0-9][a-z0-9._-]*\b`)
	liveE2EPortAssignmentPattern        = regexp.MustCompile(`(?i)\b(port)\s*[=:]\s*\d+\b`)
	liveE2EProviderHandlePattern        = regexp.MustCompile(`(?i)\b(provider|provider_handle|handle)\s*[=:]\s*[^\s,;]+`)
)

// LiveE2EReadinessComponent identifies one safe prerequisite category in the
// opt-in microVM live E2E harness.
type LiveE2EReadinessComponent string

// LiveE2EReadinessStatus is the stable public readiness state for live E2E
// prerequisites.
type LiveE2EReadinessStatus string

// LiveE2EReasonCode is a sanitized reason label for live E2E readiness
// metadata.
type LiveE2EReasonCode string

// LiveE2EMetadata is the redaction-safe metadata contract for the microVM live
// E2E harness. It carries only safe IDs, enum-like statuses, reason codes, and
// sanitized messages; it must not carry host paths, sockets, URLs, ports,
// credential values, provider handles, raw hostnames, or raw environment values.
type LiveE2EMetadata struct {
	ID                 string                    `json:"id,omitempty"`
	Status             LiveE2EReadinessStatus    `json:"status,omitempty"`
	ReasonCode         LiveE2EReasonCode         `json:"reasonCode,omitempty"`
	Message            string                    `json:"message,omitempty"`
	Firecracker        *LiveE2EReadinessMetadata `json:"firecracker,omitempty"`
	KVM                *LiveE2EReadinessMetadata `json:"kvm,omitempty"`
	NetworkProxy       *LiveE2EReadinessMetadata `json:"networkProxy,omitempty"`
	Firewall           *LiveE2EReadinessMetadata `json:"firewall,omitempty"`
	CredentialDelivery *LiveE2EReadinessMetadata `json:"credentialDelivery,omitempty"`
	TemplateTrust      *LiveE2EReadinessMetadata `json:"templateTrust,omitempty"`
}

// LiveE2EReadinessMetadata describes one live E2E prerequisite without
// exposing the local value that proved or failed readiness.
type LiveE2EReadinessMetadata struct {
	Component  LiveE2EReadinessComponent `json:"component,omitempty"`
	ID         string                    `json:"id,omitempty"`
	Status     LiveE2EReadinessStatus    `json:"status,omitempty"`
	ReasonCode LiveE2EReasonCode         `json:"reasonCode,omitempty"`
	Message    string                    `json:"message,omitempty"`
}

// NewLiveE2EReadinessMetadata builds a sanitized readiness record and returns
// nil when no safe readiness information remains.
func NewLiveE2EReadinessMetadata(component LiveE2EReadinessComponent, id string, status LiveE2EReadinessStatus, reason LiveE2EReasonCode, message string) *LiveE2EReadinessMetadata {
	metadata := sanitizeLiveE2EReadinessMetadata(LiveE2EReadinessMetadata{
		Component:  component,
		ID:         id,
		Status:     status,
		ReasonCode: reason,
		Message:    message,
	}, "")
	if liveE2EReadinessMetadataEmpty(metadata) {
		return nil
	}
	return &metadata
}

// SanitizeLiveE2EMetadata returns a copy that is safe for durable JSON records
// and test output.
func SanitizeLiveE2EMetadata(metadata LiveE2EMetadata) LiveE2EMetadata {
	return LiveE2EMetadata{
		ID:                 sanitizeLiveE2EID(metadata.ID),
		Status:             sanitizeLiveE2EReadinessStatus(metadata.Status),
		ReasonCode:         sanitizeLiveE2EReasonCode(metadata.ReasonCode),
		Message:            sanitizeLiveE2EMessage(metadata.Message),
		Firecracker:        sanitizeLiveE2EReadinessMetadataPtr(metadata.Firecracker, LiveE2EComponentFirecracker),
		KVM:                sanitizeLiveE2EReadinessMetadataPtr(metadata.KVM, LiveE2EComponentKVM),
		NetworkProxy:       sanitizeLiveE2EReadinessMetadataPtr(metadata.NetworkProxy, LiveE2EComponentNetworkProxy),
		Firewall:           sanitizeLiveE2EReadinessMetadataPtr(metadata.Firewall, LiveE2EComponentFirewall),
		CredentialDelivery: sanitizeLiveE2EReadinessMetadataPtr(metadata.CredentialDelivery, LiveE2EComponentCredentialDelivery),
		TemplateTrust:      sanitizeLiveE2EReadinessMetadataPtr(metadata.TemplateTrust, LiveE2EComponentTemplateTrust),
	}
}

// SanitizeLiveE2EReadinessMetadata returns a safe readiness metadata copy.
func SanitizeLiveE2EReadinessMetadata(metadata LiveE2EReadinessMetadata) LiveE2EReadinessMetadata {
	return sanitizeLiveE2EReadinessMetadata(metadata, "")
}

func (metadata LiveE2EMetadata) MarshalJSON() ([]byte, error) {
	type liveE2EMetadataJSON LiveE2EMetadata
	sanitized := SanitizeLiveE2EMetadata(metadata)
	return json.Marshal(liveE2EMetadataJSON(sanitized))
}

func (metadata LiveE2EReadinessMetadata) MarshalJSON() ([]byte, error) {
	type liveE2EReadinessMetadataJSON LiveE2EReadinessMetadata
	sanitized := SanitizeLiveE2EReadinessMetadata(metadata)
	return json.Marshal(liveE2EReadinessMetadataJSON(sanitized))
}

func sanitizeLiveE2EReadinessMetadataPtr(metadata *LiveE2EReadinessMetadata, component LiveE2EReadinessComponent) *LiveE2EReadinessMetadata {
	if metadata == nil {
		return nil
	}
	sanitized := sanitizeLiveE2EReadinessMetadata(*metadata, component)
	if liveE2EReadinessMetadataEmpty(sanitized) {
		return nil
	}
	return &sanitized
}

func sanitizeLiveE2EReadinessMetadata(metadata LiveE2EReadinessMetadata, component LiveE2EReadinessComponent) LiveE2EReadinessMetadata {
	sanitized := LiveE2EReadinessMetadata{
		Component:  sanitizeLiveE2EReadinessComponent(metadata.Component),
		ID:         sanitizeLiveE2EID(metadata.ID),
		Status:     sanitizeLiveE2EReadinessStatus(metadata.Status),
		ReasonCode: sanitizeLiveE2EReasonCode(metadata.ReasonCode),
		Message:    sanitizeLiveE2EMessage(metadata.Message),
	}
	if component != "" && !liveE2EReadinessMetadataEmpty(sanitized) {
		sanitized.Component = component
	}
	return sanitized
}

func liveE2EReadinessMetadataEmpty(metadata LiveE2EReadinessMetadata) bool {
	return metadata.ID == "" &&
		metadata.Status == "" &&
		metadata.ReasonCode == "" &&
		metadata.Message == ""
}

func sanitizeLiveE2EReadinessComponent(value LiveE2EReadinessComponent) LiveE2EReadinessComponent {
	switch LiveE2EReadinessComponent(normalizeLiveE2EEnum(string(value))) {
	case LiveE2EComponentFirecracker,
		LiveE2EComponentKVM,
		LiveE2EComponentNetworkProxy,
		LiveE2EComponentFirewall,
		LiveE2EComponentCredentialDelivery,
		LiveE2EComponentTemplateTrust:
		return LiveE2EReadinessComponent(normalizeLiveE2EEnum(string(value)))
	default:
		return ""
	}
}

func sanitizeLiveE2EReadinessStatus(value LiveE2EReadinessStatus) LiveE2EReadinessStatus {
	switch LiveE2EReadinessStatus(normalizeLiveE2EEnum(string(value))) {
	case LiveE2EReadinessUnknown,
		LiveE2EReadinessReady,
		LiveE2EReadinessMissing,
		LiveE2EReadinessUnavailable,
		LiveE2EReadinessBlocked,
		LiveE2EReadinessSkipped:
		return LiveE2EReadinessStatus(normalizeLiveE2EEnum(string(value)))
	default:
		return ""
	}
}

func sanitizeLiveE2EReasonCode(value LiveE2EReasonCode) LiveE2EReasonCode {
	switch LiveE2EReasonCode(normalizeLiveE2EEnum(string(value))) {
	case LiveE2EReasonReady,
		LiveE2EReasonNotRequested,
		LiveE2EReasonBuildTagMissing,
		LiveE2EReasonLiveMarkerMissing,
		LiveE2EReasonFirecrackerMarkerMissing,
		LiveE2EReasonFirecrackerBinaryMissing,
		LiveE2EReasonFirecrackerKernelMissing,
		LiveE2EReasonFirecrackerRootfsMissing,
		LiveE2EReasonFirecrackerUnavailable,
		LiveE2EReasonKVMCapabilityMissing,
		LiveE2EReasonKVMDeviceMissing,
		LiveE2EReasonKVMUnreadable,
		LiveE2EReasonNetworkProxyMarkerMissing,
		LiveE2EReasonNetworkProxyUnavailable,
		LiveE2EReasonFirewallMarkerMissing,
		LiveE2EReasonFirewallUnavailable,
		LiveE2EReasonCredentialDeliveryMarkerMissing,
		LiveE2EReasonCredentialDeliveryEnvMarkerMissing,
		LiveE2EReasonCredentialDeliveryUnavailable,
		LiveE2EReasonTemplateTrustMarkerMissing,
		LiveE2EReasonTemplateTrustUnavailable:
		return LiveE2EReasonCode(normalizeLiveE2EEnum(string(value)))
	default:
		return ""
	}
}

func sanitizeLiveE2EID(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || len(trimmed) > liveE2EMaxIDBytes || liveE2EIDUnsafeFreeform(trimmed) {
		return ""
	}
	var builder strings.Builder
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r + ('a' - 'A'))
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			builder.WriteRune(r)
		default:
			return ""
		}
	}
	out := builder.String()
	if out == "" || liveE2EAllDigits(out) {
		return ""
	}
	return out
}

func liveE2EIDUnsafeFreeform(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"authorization",
		"bearer",
		"cookie",
		"set-cookie",
		"token",
		"password",
		"passwd",
		"api_key",
		"api-key",
		"apikey",
		"access_key",
		"access-key",
		"private_key",
		"private-key",
		"secret",
		"provider_handle",
		"provider-handle",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.ContainsAny(value, "/\\?#\"'`{}[]()<>|;&=$:@") ||
		hostEndpointPattern.MatchString(value) ||
		ipEndpointPattern.MatchString(value) ||
		liveE2EContainsControl(value)
}

func sanitizeLiveE2EMessage(value string) string {
	message := sanitizeOperationDetail(value)
	if message == "" {
		return ""
	}
	message = liveE2EEnvironmentAssignmentPattern.ReplaceAllString(message, "$1=[redacted]")
	message = liveE2ELocalSocketPattern.ReplaceAllString(message, "[redacted-socket]")
	message = liveE2EHostAssignmentPattern.ReplaceAllString(message, "$1=[redacted-host]")
	message = liveE2EPortAssignmentPattern.ReplaceAllString(message, "$1=[redacted]")
	message = liveE2EProviderHandlePattern.ReplaceAllString(message, "$1=[redacted-provider]")
	message = strings.Join(strings.Fields(message), " ")
	if liveE2EMessageUnsafeResidual(message) {
		return ""
	}
	if len(message) > liveE2EMaxMessageBytes {
		message = strings.TrimSpace(message[:liveE2EMaxMessageBytes]) + "..."
	}
	return message
}

func liveE2EMessageUnsafeResidual(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"://",
		"ghp_",
		"sk-",
		"bearer ",
		"authorization",
		"proxy-authorization",
		"set-cookie",
		"provider_handle=",
		"provider-handle=",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.ContainsAny(value, "\\`{}<>|;&") ||
		hostEndpointPattern.MatchString(value) ||
		ipEndpointPattern.MatchString(value) ||
		liveE2ELocalSocketPattern.MatchString(value) ||
		liveE2EContainsControl(value)
}

func normalizeLiveE2EEnum(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func liveE2EContainsControl(value string) bool {
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

func liveE2EAllDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}
