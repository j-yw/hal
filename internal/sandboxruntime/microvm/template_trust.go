package microvm

import (
	"encoding/json"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	liveE2ETemplateTrustStatusTrusted     = "trusted"
	liveE2ETemplateTrustStatusRejected    = "rejected"
	liveE2ETemplateTrustStatusAdvisory    = "advisory"
	liveE2ETemplateTrustStatusUnavailable = "unavailable"

	liveE2ETemplateTrustProvenanceDocument          = "document"
	liveE2ETemplateTrustProvenanceTemplateReference = "template_reference"
	liveE2ETemplateTrustProvenanceRuntimeImage      = "runtime_image"
	liveE2ETemplateTrustProvenanceSourceArtifact    = "source_artifact"
)

// LiveE2ETemplateTrustMetadata is the compact template acquisition trust
// summary the live E2E harness may publish. It carries only safe template IDs,
// provenance labels, trust policy IDs, trust status values, and reason codes.
type LiveE2ETemplateTrustMetadata struct {
	TemplateID       string   `json:"templateId,omitempty"`
	ProvenanceLabels []string `json:"provenanceLabels,omitempty"`
	TrustPolicyID    string   `json:"trustPolicyId,omitempty"`
	Status           string   `json:"status,omitempty"`
	ReasonCodes      []string `json:"reasonCodes,omitempty"`
}

// LiveE2ETemplateTrustProjectionInput carries explicit marker facts plus
// already-sanitized or sanitizable template-lock metadata. It must never carry
// raw registry references, local cache paths, provider handles, credentials, or
// source locations.
type LiveE2ETemplateTrustProjectionInput struct {
	LiveMarker    bool
	TemplateID    string
	TrustPolicyID string
	TemplateLock  *sandboxruntime.RuntimeTemplateLockMetadata
	TemplateTrust LiveE2ETemplateTrustMetadata
}

// LiveE2ETemplateTrustProjectionResult is the redaction-safe template trust
// decision used by the microVM live E2E harness before live work.
type LiveE2ETemplateTrustProjectionResult struct {
	Status        LiveE2EReadinessStatus          `json:"status,omitempty"`
	ReasonCode    LiveE2EReasonCode               `json:"reasonCode,omitempty"`
	Readiness     *LiveE2EReadinessMetadata       `json:"readiness,omitempty"`
	TemplateTrust *LiveE2ETemplateTrustMetadata   `json:"templateTrust,omitempty"`
	Diagnostics   []LiveE2EPrerequisiteDiagnostic `json:"diagnostics,omitempty"`
}

// ProjectLiveE2ETemplateTrustMetadata sanitizes template provenance/trust
// metadata and enforces the template-trust live marker needed before the
// harness can treat the projection as ready.
func ProjectLiveE2ETemplateTrustMetadata(input LiveE2ETemplateTrustProjectionInput) LiveE2ETemplateTrustProjectionResult {
	if !input.LiveMarker {
		return liveE2ETemplateTrustProjectionSkipped([]LiveE2EPrerequisiteDiagnostic{
			BuildMissingLiveE2EPrerequisiteDiagnostic(LiveE2EPrerequisiteTemplateTrustMarker),
		})
	}

	metadata := liveE2ETemplateTrustMetadataFromInput(input)
	if liveE2ETemplateTrustRequiredMetadataMissing(metadata) {
		return liveE2ETemplateTrustProjectionSkipped([]LiveE2EPrerequisiteDiagnostic{
			BuildMissingLiveE2EPrerequisiteDiagnostic(LiveE2EPrerequisiteTemplateTrustMetadata),
		})
	}
	status, reason := liveE2ETemplateTrustReadiness(metadata)
	return SanitizeLiveE2ETemplateTrustProjectionResult(LiveE2ETemplateTrustProjectionResult{
		Status:        status,
		ReasonCode:    reason,
		Readiness:     NewLiveE2EReadinessMetadata(LiveE2EComponentTemplateTrust, metadata.TemplateID, status, reason, "Template trust metadata projected for the live E2E harness."),
		TemplateTrust: &metadata,
	})
}

// SanitizeLiveE2ETemplateTrustMetadata returns a durable-safe template trust
// metadata copy.
func SanitizeLiveE2ETemplateTrustMetadata(metadata LiveE2ETemplateTrustMetadata) LiveE2ETemplateTrustMetadata {
	return LiveE2ETemplateTrustMetadata{
		TemplateID:       sanitizeLiveE2EID(metadata.TemplateID),
		ProvenanceLabels: sanitizeLiveE2ETemplateTrustProvenanceLabels(metadata.ProvenanceLabels),
		TrustPolicyID:    sanitizeLiveE2EID(metadata.TrustPolicyID),
		Status:           sanitizeLiveE2ETemplateTrustStatus(metadata.Status),
		ReasonCodes:      sanitizeLiveE2ETemplateTrustReasonCodes(metadata.ReasonCodes),
	}
}

// SanitizeLiveE2ETemplateTrustProjectionResult returns a JSON-safe copy of the
// template trust readiness projection.
func SanitizeLiveE2ETemplateTrustProjectionResult(result LiveE2ETemplateTrustProjectionResult) LiveE2ETemplateTrustProjectionResult {
	status := sanitizeLiveE2EReadinessStatus(result.Status)
	reason := sanitizeLiveE2EReasonCode(result.ReasonCode)
	diagnostics := sanitizeLiveE2EPrerequisiteDiagnostics(result.Diagnostics)
	readiness := sanitizeLiveE2EReadinessMetadataPtr(result.Readiness, LiveE2EComponentTemplateTrust)
	var templateTrust *LiveE2ETemplateTrustMetadata
	if result.TemplateTrust != nil {
		sanitized := SanitizeLiveE2ETemplateTrustMetadata(*result.TemplateTrust)
		if !liveE2ETemplateTrustMetadataEmpty(sanitized) {
			templateTrust = &sanitized
		}
	}
	if len(diagnostics) > 0 {
		status = LiveE2EReadinessSkipped
		if reason == "" {
			reason = diagnostics[0].ReasonCode
		}
		readiness = diagnostics[0].ReadinessMetadata()
		templateTrust = nil
	}
	if status == LiveE2EReadinessReady && !liveE2ETemplateTrustMetadataTrusted(templateTrust) {
		status = LiveE2EReadinessUnavailable
		reason = LiveE2EReasonTemplateTrustUnavailable
	}
	if status == "" {
		if templateTrust == nil {
			status = LiveE2EReadinessUnavailable
		} else {
			status, reason = liveE2ETemplateTrustReadiness(*templateTrust)
		}
	}
	if reason == "" {
		if status == LiveE2EReadinessReady {
			reason = LiveE2EReasonReady
		} else if status != "" {
			reason = LiveE2EReasonTemplateTrustUnavailable
		}
	}
	if readiness == nil && status != "" {
		readinessID := "template-trust"
		if templateTrust != nil && templateTrust.TemplateID != "" {
			readinessID = templateTrust.TemplateID
		}
		readiness = NewLiveE2EReadinessMetadata(LiveE2EComponentTemplateTrust, readinessID, status, reason, "Template trust metadata projected for the live E2E harness.")
	}
	return LiveE2ETemplateTrustProjectionResult{
		Status:        status,
		ReasonCode:    reason,
		Readiness:     readiness,
		TemplateTrust: templateTrust,
		Diagnostics:   diagnostics,
	}
}

// CanRunLiveAction reports whether the projection permits live E2E work.
func (result LiveE2ETemplateTrustProjectionResult) CanRunLiveAction() bool {
	sanitized := SanitizeLiveE2ETemplateTrustProjectionResult(result)
	return sanitized.Status == LiveE2EReadinessReady &&
		sanitized.ReasonCode == LiveE2EReasonReady &&
		liveE2ETemplateTrustMetadataTrusted(sanitized.TemplateTrust) &&
		len(sanitized.Diagnostics) == 0
}

// ShouldSkipLiveAction reports whether the projection should become a safe
// test skip before live E2E work.
func (result LiveE2ETemplateTrustProjectionResult) ShouldSkipLiveAction() bool {
	return !result.CanRunLiveAction()
}

// LiveE2ETemplateTrustProjectionSkipMessage formats a redaction-safe skip
// message using only safe status labels, prerequisite names, and reason codes.
func LiveE2ETemplateTrustProjectionSkipMessage(result LiveE2ETemplateTrustProjectionResult) string {
	sanitized := SanitizeLiveE2ETemplateTrustProjectionResult(result)
	if sanitized.CanRunLiveAction() {
		return "microVM live E2E template trust metadata ready"
	}
	segments := []string{"microVM live E2E template trust skipped"}
	if sanitized.ReasonCode != "" {
		segments = append(segments, "reason "+string(sanitized.ReasonCode))
	}
	if sanitized.Status != "" {
		segments = append(segments, "status "+string(sanitized.Status))
	}
	if sanitized.TemplateTrust != nil && sanitized.TemplateTrust.Status != "" {
		segments = append(segments, "trustStatus "+sanitized.TemplateTrust.Status)
	}
	if diagnostics := liveE2EFirecrackerDiagnosticSummary(sanitized.Diagnostics); diagnostics != "" {
		segments = append(segments, "diagnostics "+diagnostics)
	}
	return strings.Join(segments, "; ")
}

func (metadata LiveE2ETemplateTrustMetadata) MarshalJSON() ([]byte, error) {
	type liveE2ETemplateTrustMetadataJSON LiveE2ETemplateTrustMetadata
	sanitized := SanitizeLiveE2ETemplateTrustMetadata(metadata)
	return json.Marshal(liveE2ETemplateTrustMetadataJSON(sanitized))
}

func (result LiveE2ETemplateTrustProjectionResult) MarshalJSON() ([]byte, error) {
	type liveE2ETemplateTrustProjectionResultJSON LiveE2ETemplateTrustProjectionResult
	sanitized := SanitizeLiveE2ETemplateTrustProjectionResult(result)
	return json.Marshal(liveE2ETemplateTrustProjectionResultJSON(sanitized))
}

func liveE2ETemplateTrustMetadataFromInput(input LiveE2ETemplateTrustProjectionInput) LiveE2ETemplateTrustMetadata {
	templateID := firstLiveE2ETemplateTrustSafeID(input.TemplateID, input.TemplateTrust.TemplateID)
	trustPolicyID := firstLiveE2ETemplateTrustSafeID(input.TrustPolicyID, input.TemplateTrust.TrustPolicyID)
	lock := sandboxruntime.SanitizeRuntimeTemplateLockMetadata(input.TemplateLock)
	if lock == nil || lock.TrustPolicy == nil {
		metadata := input.TemplateTrust
		if metadata.TemplateID == "" {
			metadata.TemplateID = templateID
		}
		if metadata.TrustPolicyID == "" {
			metadata.TrustPolicyID = trustPolicyID
		}
		return SanitizeLiveE2ETemplateTrustMetadata(metadata)
	}
	return SanitizeLiveE2ETemplateTrustMetadata(LiveE2ETemplateTrustMetadata{
		TemplateID:       templateID,
		ProvenanceLabels: liveE2ETemplateTrustProvenanceLabels(lock),
		TrustPolicyID:    trustPolicyID,
		Status:           lock.TrustPolicy.Decision,
		ReasonCodes:      liveE2ETemplateTrustReasonCodes(lock),
	})
}

func firstLiveE2ETemplateTrustSafeID(values ...string) string {
	for _, value := range values {
		if sanitized := sanitizeLiveE2EID(value); sanitized != "" {
			return sanitized
		}
	}
	return ""
}

func liveE2ETemplateTrustReadiness(metadata LiveE2ETemplateTrustMetadata) (LiveE2EReadinessStatus, LiveE2EReasonCode) {
	if metadata.TemplateID != "" &&
		metadata.TrustPolicyID != "" &&
		metadata.Status == liveE2ETemplateTrustStatusTrusted &&
		len(metadata.ProvenanceLabels) > 0 {
		return LiveE2EReadinessReady, LiveE2EReasonReady
	}
	return LiveE2EReadinessUnavailable, LiveE2EReasonTemplateTrustUnavailable
}

func liveE2ETemplateTrustProjectionSkipped(diagnostics []LiveE2EPrerequisiteDiagnostic) LiveE2ETemplateTrustProjectionResult {
	diagnostics = sanitizeLiveE2EPrerequisiteDiagnostics(diagnostics)
	reason := LiveE2EReasonTemplateTrustUnavailable
	if len(diagnostics) > 0 {
		reason = diagnostics[0].ReasonCode
	}
	return SanitizeLiveE2ETemplateTrustProjectionResult(LiveE2ETemplateTrustProjectionResult{
		Status:      LiveE2EReadinessSkipped,
		ReasonCode:  reason,
		Diagnostics: diagnostics,
	})
}

func liveE2ETemplateTrustMetadataTrusted(metadata *LiveE2ETemplateTrustMetadata) bool {
	if metadata == nil {
		return false
	}
	return metadata.TemplateID != "" &&
		metadata.TrustPolicyID != "" &&
		metadata.Status == liveE2ETemplateTrustStatusTrusted &&
		len(metadata.ProvenanceLabels) > 0
}

func liveE2ETemplateTrustMetadataEmpty(metadata LiveE2ETemplateTrustMetadata) bool {
	return metadata.TemplateID == "" &&
		len(metadata.ProvenanceLabels) == 0 &&
		metadata.TrustPolicyID == "" &&
		metadata.Status == "" &&
		len(metadata.ReasonCodes) == 0
}

func liveE2ETemplateTrustRequiredMetadataMissing(metadata LiveE2ETemplateTrustMetadata) bool {
	return metadata.TemplateID == "" ||
		len(metadata.ProvenanceLabels) == 0 ||
		metadata.TrustPolicyID == "" ||
		metadata.Status == ""
}

func liveE2ETemplateTrustProvenanceLabels(lock *sandboxruntime.RuntimeTemplateLockMetadata) []string {
	if lock == nil {
		return nil
	}
	labels := make([]string, 0, 4)
	labels = appendLiveE2ETemplateTrustProvenanceLabel(labels, liveE2ETemplateTrustProvenanceDocument, lock.Document)
	labels = appendLiveE2ETemplateTrustProvenanceLabel(labels, liveE2ETemplateTrustProvenanceTemplateReference, lock.TemplateReference)
	labels = appendLiveE2ETemplateTrustProvenanceLabel(labels, liveE2ETemplateTrustProvenanceRuntimeImage, lock.RuntimeImage)
	labels = appendLiveE2ETemplateTrustProvenanceLabel(labels, liveE2ETemplateTrustProvenanceSourceArtifact, lock.SourceArtifact)
	return sanitizeLiveE2ETemplateTrustProvenanceLabels(labels)
}

func appendLiveE2ETemplateTrustProvenanceLabel(labels []string, label string, entry *sandboxruntime.RuntimeTemplateLockEntryMetadata) []string {
	if entry == nil || entry.Status == "" {
		return labels
	}
	return append(labels, label)
}

func liveE2ETemplateTrustReasonCodes(lock *sandboxruntime.RuntimeTemplateLockMetadata) []string {
	if lock == nil {
		return nil
	}
	var codes []string
	if lock.TrustPolicy != nil {
		codes = append(codes, lock.TrustPolicy.ReasonCodes...)
		codes = append(codes, lock.TrustPolicy.ErrorCodes...)
		codes = append(codes, lock.TrustPolicy.WarningCodes...)
	}
	for _, entry := range []*sandboxruntime.RuntimeTemplateLockEntryMetadata{
		lock.Document,
		lock.TemplateReference,
		lock.RuntimeImage,
		lock.SourceArtifact,
	} {
		if entry == nil {
			continue
		}
		codes = append(codes, entry.ReasonCode)
		codes = append(codes, entry.WarningCodes...)
	}
	return sanitizeLiveE2ETemplateTrustReasonCodes(codes)
}

func sanitizeLiveE2ETemplateTrustStatus(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case liveE2ETemplateTrustStatusTrusted:
		return liveE2ETemplateTrustStatusTrusted
	case liveE2ETemplateTrustStatusRejected:
		return liveE2ETemplateTrustStatusRejected
	case liveE2ETemplateTrustStatusAdvisory:
		return liveE2ETemplateTrustStatusAdvisory
	case liveE2ETemplateTrustStatusUnavailable:
		return liveE2ETemplateTrustStatusUnavailable
	default:
		return ""
	}
}

func sanitizeLiveE2ETemplateTrustProvenanceLabels(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		label := sanitizeLiveE2ETemplateTrustProvenanceLabel(value)
		if label == "" || seen[label] {
			continue
		}
		out = append(out, label)
		seen[label] = true
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeLiveE2ETemplateTrustProvenanceLabel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case liveE2ETemplateTrustProvenanceDocument:
		return liveE2ETemplateTrustProvenanceDocument
	case liveE2ETemplateTrustProvenanceTemplateReference:
		return liveE2ETemplateTrustProvenanceTemplateReference
	case liveE2ETemplateTrustProvenanceRuntimeImage:
		return liveE2ETemplateTrustProvenanceRuntimeImage
	case liveE2ETemplateTrustProvenanceSourceArtifact:
		return liveE2ETemplateTrustProvenanceSourceArtifact
	default:
		return ""
	}
}

func sanitizeLiveE2ETemplateTrustReasonCodes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		code := sanitizeLiveE2ETemplateTrustReasonCode(value)
		if code == "" || seen[code] {
			continue
		}
		out = append(out, code)
		seen[code] = true
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sanitizeLiveE2ETemplateTrustReasonCode(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	switch normalized {
	case "document_digest",
		"template_reference_digest",
		"runtime_image_digest",
		"source_artifact_digest",
		"immutable_digest",
		"mutable_reference",
		"unresolved_mutable_reference",
		"missing_digest_pin",
		"unresolved_lock_entry",
		"lock_provenance_mismatch",
		"resolver_unavailable",
		"unsupported_source":
		return normalized
	default:
		return ""
	}
}
