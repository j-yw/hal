package microvm

import (
	"encoding/json"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

// LiveE2ECredentialDeliveryMetadata is the compact credential activation
// summary the live E2E harness may publish. It carries only safe identifiers,
// delivery mode labels, activation status, and reason metadata.
type LiveE2ECredentialDeliveryMetadata struct {
	ID             string   `json:"id,omitempty"`
	RequestID      string   `json:"requestId,omitempty"`
	PlanID         string   `json:"planId,omitempty"`
	ActivationID   string   `json:"activationId,omitempty"`
	RequestedModes []string `json:"requestedModes,omitempty"`
	ActiveModes    []string `json:"activeModes,omitempty"`
	Status         string   `json:"status,omitempty"`
	ReasonCode     string   `json:"reasonCode,omitempty"`
}

// LiveE2ECredentialDeliveryProjectionInput carries explicit marker facts and
// already-compact activation metadata. It never carries credential values or
// environment values.
type LiveE2ECredentialDeliveryProjectionInput struct {
	LiveMarker         bool
	EnvDeliveryMarker  bool
	CredentialDelivery LiveE2ECredentialDeliveryMetadata
}

// LiveE2ECredentialDeliveryProjectionResult is the redaction-safe credential
// delivery decision used by the microVM live E2E harness before live work.
type LiveE2ECredentialDeliveryProjectionResult struct {
	Status             LiveE2EReadinessStatus             `json:"status,omitempty"`
	ReasonCode         LiveE2EReasonCode                  `json:"reasonCode,omitempty"`
	Readiness          *LiveE2EReadinessMetadata          `json:"readiness,omitempty"`
	CredentialDelivery *LiveE2ECredentialDeliveryMetadata `json:"credentialDelivery,omitempty"`
	Diagnostics        []LiveE2EPrerequisiteDiagnostic    `json:"diagnostics,omitempty"`
}

// ProjectLiveE2ECredentialDeliveryMetadata sanitizes credential activation
// metadata and enforces the credential-delivery live markers needed before the
// harness can treat the projection as ready.
func ProjectLiveE2ECredentialDeliveryMetadata(input LiveE2ECredentialDeliveryProjectionInput) LiveE2ECredentialDeliveryProjectionResult {
	if !input.LiveMarker {
		return liveE2ECredentialDeliveryProjectionSkipped([]LiveE2EPrerequisiteDiagnostic{
			BuildMissingLiveE2EPrerequisiteDiagnostic(LiveE2EPrerequisiteCredentialMarker),
		})
	}
	if liveE2ECredentialDeliveryUsesEnvMode(input.CredentialDelivery) && !input.EnvDeliveryMarker {
		return liveE2ECredentialDeliveryProjectionSkipped([]LiveE2EPrerequisiteDiagnostic{
			BuildMissingLiveE2EPrerequisiteDiagnostic(LiveE2EPrerequisiteCredentialEnvMarker),
		})
	}

	metadata := SanitizeLiveE2ECredentialDeliveryMetadata(input.CredentialDelivery)
	if metadata.ID == "" {
		return liveE2ECredentialDeliveryProjectionUnavailable()
	}
	status, reason := liveE2ECredentialDeliveryReadiness(metadata)
	return SanitizeLiveE2ECredentialDeliveryProjectionResult(LiveE2ECredentialDeliveryProjectionResult{
		Status:             status,
		ReasonCode:         reason,
		Readiness:          NewLiveE2EReadinessMetadata(LiveE2EComponentCredentialDelivery, metadata.ID, status, reason, "Credential delivery activation metadata projected for the live E2E harness."),
		CredentialDelivery: &metadata,
	})
}

// SanitizeLiveE2ECredentialDeliveryMetadata returns a durable-safe credential
// delivery metadata copy.
func SanitizeLiveE2ECredentialDeliveryMetadata(metadata LiveE2ECredentialDeliveryMetadata) LiveE2ECredentialDeliveryMetadata {
	runtimeMetadata := sandboxruntime.SanitizeRuntimeCredentialDeliveryMetadata(&sandboxruntime.RuntimeCredentialDeliveryMetadata{
		ID:             metadata.ID,
		RequestID:      metadata.RequestID,
		PlanID:         metadata.PlanID,
		ActivationID:   metadata.ActivationID,
		RequestedModes: metadata.RequestedModes,
		ActiveModes:    metadata.ActiveModes,
		Status:         metadata.Status,
		ReasonCode:     metadata.ReasonCode,
	})
	if runtimeMetadata == nil {
		return LiveE2ECredentialDeliveryMetadata{}
	}
	return LiveE2ECredentialDeliveryMetadata{
		ID:             runtimeMetadata.ID,
		RequestID:      runtimeMetadata.RequestID,
		PlanID:         runtimeMetadata.PlanID,
		ActivationID:   runtimeMetadata.ActivationID,
		RequestedModes: append([]string(nil), runtimeMetadata.RequestedModes...),
		ActiveModes:    append([]string(nil), runtimeMetadata.ActiveModes...),
		Status:         runtimeMetadata.Status,
		ReasonCode:     runtimeMetadata.ReasonCode,
	}
}

// SanitizeLiveE2ECredentialDeliveryProjectionResult returns a JSON-safe copy
// of the credential delivery readiness projection.
func SanitizeLiveE2ECredentialDeliveryProjectionResult(result LiveE2ECredentialDeliveryProjectionResult) LiveE2ECredentialDeliveryProjectionResult {
	status := sanitizeLiveE2EReadinessStatus(result.Status)
	reason := sanitizeLiveE2EReasonCode(result.ReasonCode)
	diagnostics := sanitizeLiveE2EPrerequisiteDiagnostics(result.Diagnostics)
	readiness := sanitizeLiveE2EReadinessMetadataPtr(result.Readiness, LiveE2EComponentCredentialDelivery)
	var credentialDelivery *LiveE2ECredentialDeliveryMetadata
	if result.CredentialDelivery != nil {
		sanitized := SanitizeLiveE2ECredentialDeliveryMetadata(*result.CredentialDelivery)
		if sanitized.ID != "" {
			credentialDelivery = &sanitized
		}
	}
	if len(diagnostics) > 0 {
		status = LiveE2EReadinessSkipped
		if reason == "" {
			reason = diagnostics[0].ReasonCode
		}
		readiness = diagnostics[0].ReadinessMetadata()
		credentialDelivery = nil
	}
	if credentialDelivery == nil && status == LiveE2EReadinessReady {
		status = LiveE2EReadinessUnavailable
		reason = LiveE2EReasonCredentialDeliveryUnavailable
	}
	if status == "" && credentialDelivery == nil {
		status = LiveE2EReadinessUnavailable
	}
	if reason == "" {
		if status == LiveE2EReadinessReady {
			reason = LiveE2EReasonReady
		} else if status != "" {
			reason = LiveE2EReasonCredentialDeliveryUnavailable
		}
	}
	if readiness == nil && status != "" {
		readiness = NewLiveE2EReadinessMetadata(LiveE2EComponentCredentialDelivery, "credential-delivery", status, reason, "Credential delivery activation metadata projected for the live E2E harness.")
	}
	return LiveE2ECredentialDeliveryProjectionResult{
		Status:             status,
		ReasonCode:         reason,
		Readiness:          readiness,
		CredentialDelivery: credentialDelivery,
		Diagnostics:        diagnostics,
	}
}

// CanRunLiveAction reports whether the projection permits live E2E work.
func (result LiveE2ECredentialDeliveryProjectionResult) CanRunLiveAction() bool {
	sanitized := SanitizeLiveE2ECredentialDeliveryProjectionResult(result)
	return sanitized.Status == LiveE2EReadinessReady &&
		sanitized.ReasonCode == LiveE2EReasonReady &&
		sanitized.CredentialDelivery != nil &&
		len(sanitized.Diagnostics) == 0
}

// ShouldSkipLiveAction reports whether the projection should become a safe
// test skip before live E2E work.
func (result LiveE2ECredentialDeliveryProjectionResult) ShouldSkipLiveAction() bool {
	return !result.CanRunLiveAction()
}

// LiveE2ECredentialDeliveryProjectionSkipMessage formats a redaction-safe skip
// message using only safe status labels, prerequisite names, and reason codes.
func LiveE2ECredentialDeliveryProjectionSkipMessage(result LiveE2ECredentialDeliveryProjectionResult) string {
	sanitized := SanitizeLiveE2ECredentialDeliveryProjectionResult(result)
	if sanitized.CanRunLiveAction() {
		return "microVM live E2E credential delivery metadata ready"
	}
	segments := []string{"microVM live E2E credential delivery skipped"}
	if sanitized.ReasonCode != "" {
		segments = append(segments, "reason "+string(sanitized.ReasonCode))
	}
	if sanitized.Status != "" {
		segments = append(segments, "status "+string(sanitized.Status))
	}
	if diagnostics := liveE2EFirecrackerDiagnosticSummary(sanitized.Diagnostics); diagnostics != "" {
		segments = append(segments, "diagnostics "+diagnostics)
	}
	return strings.Join(segments, "; ")
}

func (metadata LiveE2ECredentialDeliveryMetadata) MarshalJSON() ([]byte, error) {
	type liveE2ECredentialDeliveryMetadataJSON LiveE2ECredentialDeliveryMetadata
	sanitized := SanitizeLiveE2ECredentialDeliveryMetadata(metadata)
	return json.Marshal(liveE2ECredentialDeliveryMetadataJSON(sanitized))
}

func (result LiveE2ECredentialDeliveryProjectionResult) MarshalJSON() ([]byte, error) {
	type liveE2ECredentialDeliveryProjectionResultJSON LiveE2ECredentialDeliveryProjectionResult
	sanitized := SanitizeLiveE2ECredentialDeliveryProjectionResult(result)
	return json.Marshal(liveE2ECredentialDeliveryProjectionResultJSON(sanitized))
}

func liveE2ECredentialDeliveryProjectionSkipped(diagnostics []LiveE2EPrerequisiteDiagnostic) LiveE2ECredentialDeliveryProjectionResult {
	diagnostics = sanitizeLiveE2EPrerequisiteDiagnostics(diagnostics)
	reason := LiveE2EReasonCredentialDeliveryUnavailable
	if len(diagnostics) > 0 {
		reason = diagnostics[0].ReasonCode
	}
	return SanitizeLiveE2ECredentialDeliveryProjectionResult(LiveE2ECredentialDeliveryProjectionResult{
		Status:      LiveE2EReadinessSkipped,
		ReasonCode:  reason,
		Diagnostics: diagnostics,
	})
}

func liveE2ECredentialDeliveryProjectionUnavailable() LiveE2ECredentialDeliveryProjectionResult {
	return SanitizeLiveE2ECredentialDeliveryProjectionResult(LiveE2ECredentialDeliveryProjectionResult{
		Status:     LiveE2EReadinessUnavailable,
		ReasonCode: LiveE2EReasonCredentialDeliveryUnavailable,
		Readiness: NewLiveE2EReadinessMetadata(
			LiveE2EComponentCredentialDelivery,
			"credential-delivery",
			LiveE2EReadinessUnavailable,
			LiveE2EReasonCredentialDeliveryUnavailable,
			"Credential delivery activation metadata is unavailable for the live E2E harness.",
		),
	})
}

func liveE2ECredentialDeliveryReadiness(metadata LiveE2ECredentialDeliveryMetadata) (LiveE2EReadinessStatus, LiveE2EReasonCode) {
	switch normalizeLiveE2EEnum(metadata.Status) {
	case "active":
		return LiveE2EReadinessReady, LiveE2EReasonReady
	case "requested", "planned", "ready", "completed", "skipped", "failed", "disabled":
		return LiveE2EReadinessUnavailable, LiveE2EReasonCredentialDeliveryUnavailable
	default:
		return LiveE2EReadinessUnavailable, LiveE2EReasonCredentialDeliveryUnavailable
	}
}

func liveE2ECredentialDeliveryUsesEnvMode(metadata LiveE2ECredentialDeliveryMetadata) bool {
	for _, mode := range append(append([]string(nil), metadata.RequestedModes...), metadata.ActiveModes...) {
		if normalizeLiveE2EEnum(mode) == "env" {
			return true
		}
	}
	return false
}
