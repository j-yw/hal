package microvm

import (
	"encoding/json"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// LiveE2ENetworkEnforcementReadinessInput carries explicit marker facts and
// sanitized runtime network-enforcement metadata. It never carries listener
// endpoints, firewall rules, process handles, sockets, credentials, or raw
// network destinations.
type LiveE2ENetworkEnforcementReadinessInput struct {
	LiveMarker         bool
	ProxyMarker        bool
	FirewallMarker     bool
	NetworkEnforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata
}

// LiveE2ENetworkEnforcementReadinessResult is the redaction-safe network
// readiness decision used by the microVM live E2E harness before live work.
type LiveE2ENetworkEnforcementReadinessResult struct {
	Status             LiveE2EReadinessStatus                            `json:"status,omitempty"`
	ReasonCode         LiveE2EReasonCode                                 `json:"reasonCode,omitempty"`
	NetworkProxy       *LiveE2EReadinessMetadata                         `json:"networkProxy,omitempty"`
	Firewall           *LiveE2EReadinessMetadata                         `json:"firewall,omitempty"`
	NetworkEnforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata `json:"networkEnforcement,omitempty"`
	Diagnostics        []LiveE2EPrerequisiteDiagnostic                   `json:"diagnostics,omitempty"`
}

// ProjectLiveE2ENetworkEnforcementReadiness sanitizes network-enforcement
// metadata and refuses to treat proxy/firewall enforcement as ready unless both
// explicit live markers and active proxy/firewall lifecycle metadata are
// present.
func ProjectLiveE2ENetworkEnforcementReadiness(input LiveE2ENetworkEnforcementReadinessInput) LiveE2ENetworkEnforcementReadinessResult {
	if diagnostics := liveE2ENetworkEnforcementMarkerDiagnostics(input); len(diagnostics) > 0 {
		return liveE2ENetworkEnforcementReadinessSkipped(diagnostics)
	}

	metadata := sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(input.NetworkEnforcement)
	proxyStatus, proxyReason := liveE2ENetworkProxyReadiness(metadata)
	firewallStatus, firewallReason := liveE2EFirewallReadiness(metadata)
	status := LiveE2EReadinessReady
	reason := LiveE2EReasonReady
	if proxyStatus != LiveE2EReadinessReady {
		status = LiveE2EReadinessUnavailable
		reason = proxyReason
	} else if firewallStatus != LiveE2EReadinessReady {
		status = LiveE2EReadinessUnavailable
		reason = firewallReason
	}

	return SanitizeLiveE2ENetworkEnforcementReadinessResult(LiveE2ENetworkEnforcementReadinessResult{
		Status:             status,
		ReasonCode:         reason,
		NetworkProxy:       NewLiveE2EReadinessMetadata(LiveE2EComponentNetworkProxy, "network-proxy", proxyStatus, proxyReason, "Network proxy readiness metadata projected for the live E2E harness."),
		Firewall:           NewLiveE2EReadinessMetadata(LiveE2EComponentFirewall, "firewall", firewallStatus, firewallReason, "Firewall readiness metadata projected for the live E2E harness."),
		NetworkEnforcement: metadata,
	})
}

// SanitizeLiveE2ENetworkEnforcementReadinessResult returns a JSON-safe copy of
// the network enforcement readiness projection.
func SanitizeLiveE2ENetworkEnforcementReadinessResult(result LiveE2ENetworkEnforcementReadinessResult) LiveE2ENetworkEnforcementReadinessResult {
	status := sanitizeLiveE2EReadinessStatus(result.Status)
	reason := sanitizeLiveE2EReasonCode(result.ReasonCode)
	diagnostics := sanitizeLiveE2EPrerequisiteDiagnostics(result.Diagnostics)
	networkProxy := sanitizeLiveE2EReadinessMetadataPtr(result.NetworkProxy, LiveE2EComponentNetworkProxy)
	firewall := sanitizeLiveE2EReadinessMetadataPtr(result.Firewall, LiveE2EComponentFirewall)
	metadata := sandboxruntime.SanitizeRuntimeNetworkEnforcementMetadata(result.NetworkEnforcement)
	if len(diagnostics) > 0 {
		status = LiveE2EReadinessSkipped
		if reason == "" {
			reason = diagnostics[0].ReasonCode
		}
		networkProxy = nil
		firewall = nil
		metadata = nil
	}
	if status == "" {
		status = LiveE2EReadinessUnavailable
	}
	if reason == "" {
		if status == LiveE2EReadinessReady {
			reason = LiveE2EReasonReady
		} else {
			reason = liveE2ENetworkEnforcementUnavailableReason(networkProxy, firewall)
		}
	}
	return LiveE2ENetworkEnforcementReadinessResult{
		Status:             status,
		ReasonCode:         reason,
		NetworkProxy:       networkProxy,
		Firewall:           firewall,
		NetworkEnforcement: metadata,
		Diagnostics:        diagnostics,
	}
}

// CanRunLiveAction reports whether the network readiness projection permits
// live E2E work.
func (result LiveE2ENetworkEnforcementReadinessResult) CanRunLiveAction() bool {
	sanitized := SanitizeLiveE2ENetworkEnforcementReadinessResult(result)
	return sanitized.Status == LiveE2EReadinessReady &&
		sanitized.ReasonCode == LiveE2EReasonReady &&
		liveE2EReadinessReady(sanitized.NetworkProxy) &&
		liveE2EReadinessReady(sanitized.Firewall) &&
		sanitized.NetworkEnforcement != nil &&
		len(sanitized.Diagnostics) == 0
}

// ShouldSkipLiveAction reports whether the projection should become a safe
// test skip before live E2E work.
func (result LiveE2ENetworkEnforcementReadinessResult) ShouldSkipLiveAction() bool {
	sanitized := SanitizeLiveE2ENetworkEnforcementReadinessResult(result)
	return sanitized.Status == LiveE2EReadinessSkipped && len(sanitized.Diagnostics) > 0
}

// ShouldFailLiveAction reports whether explicit readiness metadata is present
// but inconsistent with a live proxy/firewall enforcement claim.
func (result LiveE2ENetworkEnforcementReadinessResult) ShouldFailLiveAction() bool {
	return !result.ShouldSkipLiveAction() && !result.CanRunLiveAction()
}

// LiveE2ENetworkEnforcementReadinessSkipMessage formats a redaction-safe skip
// message using only prerequisite names and reason codes.
func LiveE2ENetworkEnforcementReadinessSkipMessage(result LiveE2ENetworkEnforcementReadinessResult) string {
	sanitized := SanitizeLiveE2ENetworkEnforcementReadinessResult(result)
	if sanitized.CanRunLiveAction() {
		return "microVM live E2E network enforcement readiness satisfied"
	}
	segments := []string{"microVM live E2E network enforcement skipped"}
	if sanitized.ReasonCode != "" {
		segments = append(segments, "reason "+string(sanitized.ReasonCode))
	}
	if diagnostics := liveE2EFirecrackerDiagnosticSummary(sanitized.Diagnostics); diagnostics != "" {
		segments = append(segments, "diagnostics "+diagnostics)
	}
	return strings.Join(segments, "; ")
}

// LiveE2ENetworkEnforcementReadinessFailureMessage formats sanitized
// diagnostics for inconsistent explicit network readiness claims.
func LiveE2ENetworkEnforcementReadinessFailureMessage(result LiveE2ENetworkEnforcementReadinessResult) string {
	sanitized := SanitizeLiveE2ENetworkEnforcementReadinessResult(result)
	if sanitized.CanRunLiveAction() {
		return "microVM live E2E network enforcement readiness satisfied"
	}
	if sanitized.ShouldSkipLiveAction() {
		return LiveE2ENetworkEnforcementReadinessSkipMessage(sanitized)
	}
	segments := []string{"microVM live E2E network enforcement readiness failed"}
	if sanitized.ReasonCode != "" {
		segments = append(segments, "reason "+string(sanitized.ReasonCode))
	}
	segments = append(segments, liveE2ENetworkEnforcementReadinessSegment("networkProxy", sanitized.NetworkProxy))
	segments = append(segments, liveE2ENetworkEnforcementReadinessSegment("firewall", sanitized.Firewall))
	return strings.Join(compactLiveE2ESegments(segments), "; ")
}

func (result LiveE2ENetworkEnforcementReadinessResult) MarshalJSON() ([]byte, error) {
	type liveE2ENetworkEnforcementReadinessResultJSON LiveE2ENetworkEnforcementReadinessResult
	sanitized := SanitizeLiveE2ENetworkEnforcementReadinessResult(result)
	return json.Marshal(liveE2ENetworkEnforcementReadinessResultJSON(sanitized))
}

func liveE2ENetworkEnforcementMarkerDiagnostics(input LiveE2ENetworkEnforcementReadinessInput) []LiveE2EPrerequisiteDiagnostic {
	if !input.LiveMarker {
		return BuildMissingLiveE2EPrerequisiteDiagnostics([]LiveE2EPrerequisiteName{
			LiveE2EPrerequisiteNetworkProxyMarker,
			LiveE2EPrerequisiteFirewallMarker,
		})
	}
	var diagnostics []LiveE2EPrerequisiteDiagnostic
	if !input.ProxyMarker {
		diagnostics = append(diagnostics, BuildMissingLiveE2EPrerequisiteDiagnostic(LiveE2EPrerequisiteNetworkProxyMarker))
	}
	if !input.FirewallMarker {
		diagnostics = append(diagnostics, BuildMissingLiveE2EPrerequisiteDiagnostic(LiveE2EPrerequisiteFirewallMarker))
	}
	return sanitizeLiveE2EPrerequisiteDiagnostics(diagnostics)
}

func liveE2ENetworkProxyReadiness(metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) (LiveE2EReadinessStatus, LiveE2EReasonCode) {
	if liveE2ENetworkProxyResultReady(metadata) &&
		liveE2ENetworkEnforcementLifecycleActive(metadata) &&
		liveE2ENetworkProxyLifecycleActive(metadata) {
		return LiveE2EReadinessReady, LiveE2EReasonReady
	}
	return LiveE2EReadinessUnavailable, LiveE2EReasonNetworkProxyUnavailable
}

func liveE2EFirewallReadiness(metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) (LiveE2EReadinessStatus, LiveE2EReasonCode) {
	if liveE2ENetworkEnforcementResultReady(metadata) &&
		liveE2ENetworkEnforcementLifecycleActive(metadata) &&
		liveE2EFirewallLifecycleActive(metadata) {
		return LiveE2EReadinessReady, LiveE2EReasonReady
	}
	return LiveE2EReadinessUnavailable, LiveE2EReasonFirewallUnavailable
}

func liveE2ENetworkProxyResultReady(metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) bool {
	if metadata == nil || metadata.Result == nil {
		return false
	}
	result := metadata.Result
	if result.Outcome != "success" && result.Outcome != "best_effort" {
		return false
	}
	if !liveE2EStringListContains(result.Mechanisms, "proxy") {
		return false
	}
	switch result.EnforcementMode {
	case "proxy", "proxy_firewall", "best_effort":
		return true
	default:
		return false
	}
}

func liveE2ENetworkEnforcementResultReady(metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) bool {
	if metadata == nil || metadata.Result == nil || metadata.Result.Capability == nil {
		return false
	}
	result := metadata.Result
	return result.Outcome == "success" &&
		result.EnforcementMode == "proxy_firewall" &&
		result.Capability.Supported &&
		result.Capability.SupportsDefaultDenyPosture &&
		liveE2EStringListContains(result.Mechanisms, "proxy") &&
		liveE2EStringListContains(result.Mechanisms, "firewall")
}

func liveE2ENetworkEnforcementLifecycleActive(metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) bool {
	return metadata != nil &&
		metadata.Orchestration != nil &&
		metadata.Orchestration.Status == "active"
}

func liveE2ENetworkProxyLifecycleActive(metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) bool {
	if metadata == nil || metadata.Orchestration == nil || metadata.Orchestration.Proxy == nil {
		return false
	}
	proxy := metadata.Orchestration.Proxy
	return proxy.Status == "active" && liveE2EStringListContains(proxy.Mechanisms, "proxy")
}

func liveE2EFirewallLifecycleActive(metadata *sandboxruntime.RuntimeNetworkEnforcementMetadata) bool {
	if metadata == nil || metadata.Orchestration == nil {
		return false
	}
	for _, rule := range metadata.Orchestration.Rules {
		if rule.Status == "active" && liveE2EStringListContains(rule.Mechanisms, "firewall") {
			return true
		}
	}
	return false
}

func liveE2ENetworkEnforcementReadinessSkipped(diagnostics []LiveE2EPrerequisiteDiagnostic) LiveE2ENetworkEnforcementReadinessResult {
	diagnostics = sanitizeLiveE2EPrerequisiteDiagnostics(diagnostics)
	reason := LiveE2EReasonNetworkProxyUnavailable
	if len(diagnostics) > 0 {
		reason = diagnostics[0].ReasonCode
	}
	return SanitizeLiveE2ENetworkEnforcementReadinessResult(LiveE2ENetworkEnforcementReadinessResult{
		Status:      LiveE2EReadinessSkipped,
		ReasonCode:  reason,
		Diagnostics: diagnostics,
	})
}

func liveE2ENetworkEnforcementUnavailableReason(networkProxy, firewall *LiveE2EReadinessMetadata) LiveE2EReasonCode {
	if networkProxy == nil || networkProxy.Status != LiveE2EReadinessReady {
		return LiveE2EReasonNetworkProxyUnavailable
	}
	if firewall == nil || firewall.Status != LiveE2EReadinessReady {
		return LiveE2EReasonFirewallUnavailable
	}
	return LiveE2EReasonNetworkProxyUnavailable
}

func liveE2EReadinessReady(metadata *LiveE2EReadinessMetadata) bool {
	return metadata != nil &&
		metadata.Status == LiveE2EReadinessReady &&
		metadata.ReasonCode == LiveE2EReasonReady
}

func liveE2ENetworkEnforcementReadinessSegment(name string, metadata *LiveE2EReadinessMetadata) string {
	if metadata == nil {
		return name + " unavailable"
	}
	parts := []string{name}
	if metadata.Status != "" {
		parts = append(parts, "status "+string(metadata.Status))
	}
	if metadata.ReasonCode != "" {
		parts = append(parts, "reason "+string(metadata.ReasonCode))
	}
	return strings.Join(parts, " ")
}

func compactLiveE2ESegments(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func liveE2EStringListContains(values []string, want string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == want {
			return true
		}
	}
	return false
}
