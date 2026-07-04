package microvm

import "encoding/json"

const (
	LiveE2EPrerequisiteFirecrackerBinary   LiveE2EPrerequisiteName = "firecracker_binary"
	LiveE2EPrerequisiteFirecrackerKernel   LiveE2EPrerequisiteName = "firecracker_kernel"
	LiveE2EPrerequisiteFirecrackerRootfs   LiveE2EPrerequisiteName = "firecracker_rootfs"
	LiveE2EPrerequisiteKVMCapability       LiveE2EPrerequisiteName = "kvm_capability"
	LiveE2EPrerequisiteNetworkProxyMarker  LiveE2EPrerequisiteName = "network_proxy_marker"
	LiveE2EPrerequisiteFirewallMarker      LiveE2EPrerequisiteName = "firewall_marker"
	LiveE2EPrerequisiteCredentialMarker    LiveE2EPrerequisiteName = "credential_delivery_marker"
	LiveE2EPrerequisiteTemplateTrustMarker LiveE2EPrerequisiteName = "template_trust_marker"
)

// LiveE2EPrerequisiteName identifies a required live E2E setup item without
// carrying the local value, path, endpoint, socket, or provider handle used to
// satisfy it.
type LiveE2EPrerequisiteName string

// LiveE2EPrerequisiteDiagnostic is a redaction-safe skip diagnostic for one
// missing live E2E setup item.
type LiveE2EPrerequisiteDiagnostic struct {
	Prerequisite LiveE2EPrerequisiteName   `json:"prerequisite,omitempty"`
	Component    LiveE2EReadinessComponent `json:"component,omitempty"`
	Status       LiveE2EReadinessStatus    `json:"status,omitempty"`
	ReasonCode   LiveE2EReasonCode         `json:"reasonCode,omitempty"`
	Message      string                    `json:"message,omitempty"`
}

// BuildMissingLiveE2EPrerequisiteDiagnostic maps a missing setup item to a
// stable, redaction-safe diagnostic. Unknown prerequisite names return an empty
// diagnostic.
func BuildMissingLiveE2EPrerequisiteDiagnostic(prerequisite LiveE2EPrerequisiteName) LiveE2EPrerequisiteDiagnostic {
	spec, ok := liveE2EPrerequisiteSpecFor(prerequisite)
	if !ok {
		return LiveE2EPrerequisiteDiagnostic{}
	}
	return SanitizeLiveE2EPrerequisiteDiagnostic(LiveE2EPrerequisiteDiagnostic{
		Prerequisite: spec.prerequisite,
		Component:    spec.component,
		Status:       LiveE2EReadinessMissing,
		ReasonCode:   spec.reasonCode,
		Message:      spec.message,
	})
}

// BuildMissingLiveE2EPrerequisiteDiagnostics maps missing setup items to
// redaction-safe diagnostics while dropping unknown prerequisite names.
func BuildMissingLiveE2EPrerequisiteDiagnostics(prerequisites []LiveE2EPrerequisiteName) []LiveE2EPrerequisiteDiagnostic {
	if prerequisites == nil {
		return nil
	}
	diagnostics := make([]LiveE2EPrerequisiteDiagnostic, 0, len(prerequisites))
	for _, prerequisite := range prerequisites {
		diagnostic := BuildMissingLiveE2EPrerequisiteDiagnostic(prerequisite)
		if !liveE2EPrerequisiteDiagnosticEmpty(diagnostic) {
			diagnostics = append(diagnostics, diagnostic)
		}
	}
	return diagnostics
}

// SanitizeLiveE2EPrerequisiteDiagnostic returns a copy suitable for JSON,
// logs, and test skip output.
func SanitizeLiveE2EPrerequisiteDiagnostic(diagnostic LiveE2EPrerequisiteDiagnostic) LiveE2EPrerequisiteDiagnostic {
	return LiveE2EPrerequisiteDiagnostic{
		Prerequisite: sanitizeLiveE2EPrerequisiteName(diagnostic.Prerequisite),
		Component:    sanitizeLiveE2EReadinessComponent(diagnostic.Component),
		Status:       sanitizeLiveE2EReadinessStatus(diagnostic.Status),
		ReasonCode:   sanitizeLiveE2EReasonCode(diagnostic.ReasonCode),
		Message:      sanitizeLiveE2EMessage(diagnostic.Message),
	}
}

// ReadinessMetadata converts the diagnostic to the shared readiness metadata
// shape used by the live E2E metadata contract.
func (diagnostic LiveE2EPrerequisiteDiagnostic) ReadinessMetadata() *LiveE2EReadinessMetadata {
	sanitized := SanitizeLiveE2EPrerequisiteDiagnostic(diagnostic)
	if liveE2EPrerequisiteDiagnosticEmpty(sanitized) {
		return nil
	}
	return NewLiveE2EReadinessMetadata(
		sanitized.Component,
		string(sanitized.Prerequisite),
		sanitized.Status,
		sanitized.ReasonCode,
		sanitized.Message,
	)
}

func (diagnostic LiveE2EPrerequisiteDiagnostic) MarshalJSON() ([]byte, error) {
	type liveE2EPrerequisiteDiagnosticJSON LiveE2EPrerequisiteDiagnostic
	sanitized := SanitizeLiveE2EPrerequisiteDiagnostic(diagnostic)
	return json.Marshal(liveE2EPrerequisiteDiagnosticJSON(sanitized))
}

type liveE2EPrerequisiteSpec struct {
	prerequisite LiveE2EPrerequisiteName
	component    LiveE2EReadinessComponent
	reasonCode   LiveE2EReasonCode
	message      string
}

func liveE2EPrerequisiteSpecFor(prerequisite LiveE2EPrerequisiteName) (liveE2EPrerequisiteSpec, bool) {
	switch sanitizeLiveE2EPrerequisiteName(prerequisite) {
	case LiveE2EPrerequisiteFirecrackerBinary:
		return liveE2EPrerequisiteSpec{
			prerequisite: LiveE2EPrerequisiteFirecrackerBinary,
			component:    LiveE2EComponentFirecracker,
			reasonCode:   LiveE2EReasonFirecrackerBinaryMissing,
			message:      "Install or enable the Firecracker binary before running the live E2E harness.",
		}, true
	case LiveE2EPrerequisiteFirecrackerKernel:
		return liveE2EPrerequisiteSpec{
			prerequisite: LiveE2EPrerequisiteFirecrackerKernel,
			component:    LiveE2EComponentFirecracker,
			reasonCode:   LiveE2EReasonFirecrackerKernelMissing,
			message:      "Provide the microVM kernel marker before running the live E2E harness.",
		}, true
	case LiveE2EPrerequisiteFirecrackerRootfs:
		return liveE2EPrerequisiteSpec{
			prerequisite: LiveE2EPrerequisiteFirecrackerRootfs,
			component:    LiveE2EComponentFirecracker,
			reasonCode:   LiveE2EReasonFirecrackerRootfsMissing,
			message:      "Provide the microVM rootfs marker before running the live E2E harness.",
		}, true
	case LiveE2EPrerequisiteKVMCapability:
		return liveE2EPrerequisiteSpec{
			prerequisite: LiveE2EPrerequisiteKVMCapability,
			component:    LiveE2EComponentKVM,
			reasonCode:   LiveE2EReasonKVMCapabilityMissing,
			message:      "Enable host KVM capability before running the live E2E harness.",
		}, true
	case LiveE2EPrerequisiteNetworkProxyMarker:
		return liveE2EPrerequisiteSpec{
			prerequisite: LiveE2EPrerequisiteNetworkProxyMarker,
			component:    LiveE2EComponentNetworkProxy,
			reasonCode:   LiveE2EReasonNetworkProxyMarkerMissing,
			message:      "Set the network proxy live marker before claiming proxy enforcement readiness.",
		}, true
	case LiveE2EPrerequisiteFirewallMarker:
		return liveE2EPrerequisiteSpec{
			prerequisite: LiveE2EPrerequisiteFirewallMarker,
			component:    LiveE2EComponentFirewall,
			reasonCode:   LiveE2EReasonFirewallMarkerMissing,
			message:      "Set the firewall live marker before claiming firewall enforcement readiness.",
		}, true
	case LiveE2EPrerequisiteCredentialMarker:
		return liveE2EPrerequisiteSpec{
			prerequisite: LiveE2EPrerequisiteCredentialMarker,
			component:    LiveE2EComponentCredentialDelivery,
			reasonCode:   LiveE2EReasonCredentialDeliveryMarkerMissing,
			message:      "Set the credential delivery live marker before running credential delivery checks.",
		}, true
	case LiveE2EPrerequisiteTemplateTrustMarker:
		return liveE2EPrerequisiteSpec{
			prerequisite: LiveE2EPrerequisiteTemplateTrustMarker,
			component:    LiveE2EComponentTemplateTrust,
			reasonCode:   LiveE2EReasonTemplateTrustMarkerMissing,
			message:      "Set the template trust marker before running template trust checks.",
		}, true
	default:
		return liveE2EPrerequisiteSpec{}, false
	}
}

func sanitizeLiveE2EPrerequisiteName(value LiveE2EPrerequisiteName) LiveE2EPrerequisiteName {
	switch LiveE2EPrerequisiteName(normalizeLiveE2EEnum(string(value))) {
	case LiveE2EPrerequisiteFirecrackerBinary,
		LiveE2EPrerequisiteFirecrackerKernel,
		LiveE2EPrerequisiteFirecrackerRootfs,
		LiveE2EPrerequisiteKVMCapability,
		LiveE2EPrerequisiteNetworkProxyMarker,
		LiveE2EPrerequisiteFirewallMarker,
		LiveE2EPrerequisiteCredentialMarker,
		LiveE2EPrerequisiteTemplateTrustMarker:
		return LiveE2EPrerequisiteName(normalizeLiveE2EEnum(string(value)))
	default:
		return ""
	}
}

func liveE2EPrerequisiteDiagnosticEmpty(diagnostic LiveE2EPrerequisiteDiagnostic) bool {
	return diagnostic.Prerequisite == "" &&
		diagnostic.Component == "" &&
		diagnostic.Status == "" &&
		diagnostic.ReasonCode == "" &&
		diagnostic.Message == ""
}
