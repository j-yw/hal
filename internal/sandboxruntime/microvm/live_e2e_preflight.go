package microvm

import (
	"encoding/json"
	"strings"
)

// LiveE2EFirecrackerPreflightInput carries only explicit marker facts and
// injectable host probes. It does not read process environment or start live
// runtime components.
type LiveE2EFirecrackerPreflightInput struct {
	FirecrackerLiveMarker   bool
	FirecrackerBinaryMarker string
	KernelMarker            string
	RootfsMarker            string
	Probe                   CapabilityProbe
	CapabilityDetector      CapabilityDetector
}

// LiveE2EFirecrackerPreflightResult is the redaction-safe decision the live
// E2E harness must inspect before any Firecracker-backed action is attempted.
type LiveE2EFirecrackerPreflightResult struct {
	Status      LiveE2EReadinessStatus          `json:"status,omitempty"`
	ReasonCode  LiveE2EReasonCode               `json:"reasonCode,omitempty"`
	Diagnostics []LiveE2EPrerequisiteDiagnostic `json:"diagnostics,omitempty"`
}

// PreflightLiveE2EFirecrackerRuntime validates the opt-in Firecracker launch
// requirements using marker presence, asset readability, and host capability
// metadata only. It does not start Firecracker, sandboxd, guest transports,
// network listeners, or firewall mutation.
func PreflightLiveE2EFirecrackerRuntime(input LiveE2EFirecrackerPreflightInput) LiveE2EFirecrackerPreflightResult {
	if !input.FirecrackerLiveMarker {
		return liveE2EFirecrackerPreflightSkipped([]LiveE2EPrerequisiteDiagnostic{
			BuildMissingLiveE2EPrerequisiteDiagnostic(LiveE2EPrerequisiteFirecrackerLiveMarker),
		})
	}

	markerDiagnostics := liveE2EFirecrackerMarkerDiagnostics(input)
	if len(markerDiagnostics) > 0 {
		return liveE2EFirecrackerPreflightSkipped(markerDiagnostics)
	}

	probe := input.Probe
	if probe == nil {
		probe = hostCapabilityProbe{}
	}

	assetDiagnostics := liveE2EFirecrackerAssetDiagnostics(probe, input)
	if len(assetDiagnostics) > 0 {
		return liveE2EFirecrackerPreflightSkipped(assetDiagnostics)
	}

	detector := input.CapabilityDetector
	if detector == nil {
		detector = HostCapabilityDetector{Probe: probe}
	}
	report := detector.DetectMicroVMCapability(CapabilityDetectionRequest{
		Config: Config{HypervisorPath: strings.TrimSpace(input.FirecrackerBinaryMarker)},
	})
	if diagnostic := liveE2EFirecrackerCapabilityDiagnostic(report); diagnostic != nil {
		return liveE2EFirecrackerPreflightSkipped([]LiveE2EPrerequisiteDiagnostic{*diagnostic})
	}

	return SanitizeLiveE2EFirecrackerPreflightResult(LiveE2EFirecrackerPreflightResult{
		Status:     LiveE2EReadinessReady,
		ReasonCode: LiveE2EReasonReady,
	})
}

// CanRunLiveAction reports whether the preflight result permits live runtime
// work.
func (result LiveE2EFirecrackerPreflightResult) CanRunLiveAction() bool {
	sanitized := SanitizeLiveE2EFirecrackerPreflightResult(result)
	return sanitized.Status == LiveE2EReadinessReady &&
		sanitized.ReasonCode == LiveE2EReasonReady &&
		len(sanitized.Diagnostics) == 0
}

// ShouldSkipLiveAction reports whether the preflight result should be turned
// into a safe skip before live runtime work.
func (result LiveE2EFirecrackerPreflightResult) ShouldSkipLiveAction() bool {
	return !result.CanRunLiveAction()
}

// LiveE2EFirecrackerPreflightSkipMessage formats a redaction-safe skip message
// using prerequisite names and reason codes only.
func LiveE2EFirecrackerPreflightSkipMessage(result LiveE2EFirecrackerPreflightResult) string {
	sanitized := SanitizeLiveE2EFirecrackerPreflightResult(result)
	if sanitized.CanRunLiveAction() {
		return "microVM live E2E Firecracker preflight satisfied"
	}
	segments := []string{"microVM live E2E Firecracker preflight skipped"}
	if sanitized.ReasonCode != "" {
		segments = append(segments, "reason "+string(sanitized.ReasonCode))
	}
	if diagnostics := liveE2EFirecrackerDiagnosticSummary(sanitized.Diagnostics); diagnostics != "" {
		segments = append(segments, "diagnostics "+diagnostics)
	}
	return strings.Join(segments, "; ")
}

// SanitizeLiveE2EFirecrackerPreflightResult returns a durable, redaction-safe
// copy of a preflight decision.
func SanitizeLiveE2EFirecrackerPreflightResult(result LiveE2EFirecrackerPreflightResult) LiveE2EFirecrackerPreflightResult {
	status := sanitizeLiveE2EReadinessStatus(result.Status)
	reason := sanitizeLiveE2EReasonCode(result.ReasonCode)
	diagnostics := sanitizeLiveE2EPrerequisiteDiagnostics(result.Diagnostics)
	if len(diagnostics) > 0 {
		status = LiveE2EReadinessSkipped
		if reason == "" {
			reason = diagnostics[0].ReasonCode
		}
	}
	if status == LiveE2EReadinessReady && reason == "" {
		reason = LiveE2EReasonReady
	}
	if status == "" && reason != "" {
		status = LiveE2EReadinessSkipped
	}
	return LiveE2EFirecrackerPreflightResult{
		Status:      status,
		ReasonCode:  reason,
		Diagnostics: diagnostics,
	}
}

func (result LiveE2EFirecrackerPreflightResult) MarshalJSON() ([]byte, error) {
	type liveE2EFirecrackerPreflightResultJSON LiveE2EFirecrackerPreflightResult
	sanitized := SanitizeLiveE2EFirecrackerPreflightResult(result)
	return json.Marshal(liveE2EFirecrackerPreflightResultJSON(sanitized))
}

func liveE2EFirecrackerMarkerDiagnostics(input LiveE2EFirecrackerPreflightInput) []LiveE2EPrerequisiteDiagnostic {
	var diagnostics []LiveE2EPrerequisiteDiagnostic
	for _, req := range []struct {
		value        string
		prerequisite LiveE2EPrerequisiteName
	}{
		{value: input.FirecrackerBinaryMarker, prerequisite: LiveE2EPrerequisiteFirecrackerBinary},
		{value: input.KernelMarker, prerequisite: LiveE2EPrerequisiteFirecrackerKernel},
		{value: input.RootfsMarker, prerequisite: LiveE2EPrerequisiteFirecrackerRootfs},
	} {
		if strings.TrimSpace(req.value) == "" {
			diagnostics = append(diagnostics, BuildMissingLiveE2EPrerequisiteDiagnostic(req.prerequisite))
		}
	}
	return sanitizeLiveE2EPrerequisiteDiagnostics(diagnostics)
}

func liveE2EFirecrackerAssetDiagnostics(probe CapabilityProbe, input LiveE2EFirecrackerPreflightInput) []LiveE2EPrerequisiteDiagnostic {
	var diagnostics []LiveE2EPrerequisiteDiagnostic
	if _, err := probe.LookPath(strings.TrimSpace(input.FirecrackerBinaryMarker)); err != nil {
		diagnostics = append(diagnostics, liveE2EUnavailablePrerequisiteDiagnostic(
			LiveE2EPrerequisiteFirecrackerBinary,
			LiveE2EComponentFirecracker,
			LiveE2EReasonFirecrackerUnavailable,
			"Firecracker binary prerequisite is unavailable for the live E2E harness.",
		))
	}
	if diagnostic := liveE2EReadableAssetDiagnostic(probe, strings.TrimSpace(input.KernelMarker), LiveE2EPrerequisiteFirecrackerKernel); diagnostic != nil {
		diagnostics = append(diagnostics, *diagnostic)
	}
	if diagnostic := liveE2EReadableAssetDiagnostic(probe, strings.TrimSpace(input.RootfsMarker), LiveE2EPrerequisiteFirecrackerRootfs); diagnostic != nil {
		diagnostics = append(diagnostics, *diagnostic)
	}
	return sanitizeLiveE2EPrerequisiteDiagnostics(diagnostics)
}

func liveE2EReadableAssetDiagnostic(probe CapabilityProbe, marker string, prerequisite LiveE2EPrerequisiteName) *LiveE2EPrerequisiteDiagnostic {
	if err := probe.Stat(marker); err != nil {
		if capabilityIsNotExist(err) {
			diagnostic := BuildMissingLiveE2EPrerequisiteDiagnostic(prerequisite)
			return &diagnostic
		}
		diagnostic := liveE2EFirecrackerAssetUnavailableDiagnostic(prerequisite)
		return &diagnostic
	}
	if err := probe.OpenReadOnly(marker); err != nil {
		diagnostic := liveE2EFirecrackerAssetUnavailableDiagnostic(prerequisite)
		return &diagnostic
	}
	return nil
}

func liveE2EFirecrackerAssetUnavailableDiagnostic(prerequisite LiveE2EPrerequisiteName) LiveE2EPrerequisiteDiagnostic {
	return liveE2EUnavailablePrerequisiteDiagnostic(
		prerequisite,
		LiveE2EComponentFirecracker,
		LiveE2EReasonFirecrackerUnavailable,
		"Firecracker launch asset prerequisite is unavailable for the live E2E harness.",
	)
}

func liveE2EFirecrackerCapabilityDiagnostic(report CapabilityReport) *LiveE2EPrerequisiteDiagnostic {
	if report.Availability == CapabilityAvailabilityAvailable {
		return nil
	}
	switch report.ReasonCode {
	case CapabilityReasonHypervisorExecutableMissing:
		diagnostic := liveE2EUnavailablePrerequisiteDiagnostic(
			LiveE2EPrerequisiteFirecrackerBinary,
			LiveE2EComponentFirecracker,
			LiveE2EReasonFirecrackerUnavailable,
			"Firecracker binary prerequisite is unavailable for the live E2E harness.",
		)
		return &diagnostic
	case CapabilityReasonKVMDeviceMissing:
		diagnostic := liveE2EUnavailablePrerequisiteDiagnostic(
			LiveE2EPrerequisiteKVMCapability,
			LiveE2EComponentKVM,
			LiveE2EReasonKVMDeviceMissing,
			"Host KVM device prerequisite is unavailable for the live E2E harness.",
		)
		return &diagnostic
	case CapabilityReasonKVMDeviceUnreadable:
		diagnostic := liveE2EUnavailablePrerequisiteDiagnostic(
			LiveE2EPrerequisiteKVMCapability,
			LiveE2EComponentKVM,
			LiveE2EReasonKVMUnreadable,
			"Host KVM device prerequisite is unreadable for the live E2E harness.",
		)
		return &diagnostic
	default:
		diagnostic := liveE2EUnavailablePrerequisiteDiagnostic(
			LiveE2EPrerequisiteKVMCapability,
			LiveE2EComponentKVM,
			LiveE2EReasonKVMCapabilityMissing,
			"Host microVM capability prerequisite is unavailable for the live E2E harness.",
		)
		return &diagnostic
	}
}

func liveE2EUnavailablePrerequisiteDiagnostic(prerequisite LiveE2EPrerequisiteName, component LiveE2EReadinessComponent, reason LiveE2EReasonCode, message string) LiveE2EPrerequisiteDiagnostic {
	return SanitizeLiveE2EPrerequisiteDiagnostic(LiveE2EPrerequisiteDiagnostic{
		Prerequisite: prerequisite,
		Component:    component,
		Status:       LiveE2EReadinessUnavailable,
		ReasonCode:   reason,
		Message:      message,
	})
}

func liveE2EFirecrackerPreflightSkipped(diagnostics []LiveE2EPrerequisiteDiagnostic) LiveE2EFirecrackerPreflightResult {
	diagnostics = sanitizeLiveE2EPrerequisiteDiagnostics(diagnostics)
	reason := LiveE2EReasonCode("")
	if len(diagnostics) > 0 {
		reason = diagnostics[0].ReasonCode
	}
	return SanitizeLiveE2EFirecrackerPreflightResult(LiveE2EFirecrackerPreflightResult{
		Status:      LiveE2EReadinessSkipped,
		ReasonCode:  reason,
		Diagnostics: diagnostics,
	})
}

func sanitizeLiveE2EPrerequisiteDiagnostics(values []LiveE2EPrerequisiteDiagnostic) []LiveE2EPrerequisiteDiagnostic {
	if len(values) == 0 {
		return nil
	}
	out := make([]LiveE2EPrerequisiteDiagnostic, 0, len(values))
	for _, value := range values {
		sanitized := SanitizeLiveE2EPrerequisiteDiagnostic(value)
		if !liveE2EPrerequisiteDiagnosticEmpty(sanitized) {
			out = append(out, sanitized)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func liveE2EFirecrackerDiagnosticSummary(diagnostics []LiveE2EPrerequisiteDiagnostic) string {
	diagnostics = sanitizeLiveE2EPrerequisiteDiagnostics(diagnostics)
	if len(diagnostics) == 0 {
		return ""
	}
	parts := make([]string, 0, len(diagnostics))
	for _, diagnostic := range diagnostics {
		if diagnostic.Prerequisite == "" || diagnostic.ReasonCode == "" {
			continue
		}
		parts = append(parts, string(diagnostic.Prerequisite)+":"+string(diagnostic.ReasonCode))
	}
	return strings.Join(parts, " ")
}
