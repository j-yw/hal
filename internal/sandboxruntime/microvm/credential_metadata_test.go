package microvm

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestLiveE2ECredentialDeliveryMetadataContractFieldsAndJSONNames(t *testing.T) {
	metadataType := reflect.TypeOf(LiveE2ECredentialDeliveryMetadata{})
	assertConfigField(t, metadataType, "ID", reflect.TypeOf(""), `json:"id,omitempty"`)
	assertConfigField(t, metadataType, "RequestID", reflect.TypeOf(""), `json:"requestId,omitempty"`)
	assertConfigField(t, metadataType, "PlanID", reflect.TypeOf(""), `json:"planId,omitempty"`)
	assertConfigField(t, metadataType, "ActivationID", reflect.TypeOf(""), `json:"activationId,omitempty"`)
	assertConfigField(t, metadataType, "RequestedModes", reflect.TypeOf([]string{}), `json:"requestedModes,omitempty"`)
	assertConfigField(t, metadataType, "ActiveModes", reflect.TypeOf([]string{}), `json:"activeModes,omitempty"`)
	assertConfigField(t, metadataType, "Status", reflect.TypeOf(""), `json:"status,omitempty"`)
	assertConfigField(t, metadataType, "ReasonCode", reflect.TypeOf(""), `json:"reasonCode,omitempty"`)

	resultType := reflect.TypeOf(LiveE2ECredentialDeliveryProjectionResult{})
	assertConfigField(t, resultType, "Status", reflect.TypeOf(LiveE2EReadinessStatus("")), `json:"status,omitempty"`)
	assertConfigField(t, resultType, "ReasonCode", reflect.TypeOf(LiveE2EReasonCode("")), `json:"reasonCode,omitempty"`)
	assertConfigField(t, resultType, "Readiness", reflect.TypeOf((*LiveE2EReadinessMetadata)(nil)), `json:"readiness,omitempty"`)
	assertConfigField(t, resultType, "CredentialDelivery", reflect.TypeOf((*LiveE2ECredentialDeliveryMetadata)(nil)), `json:"credentialDelivery,omitempty"`)
	assertConfigField(t, resultType, "Diagnostics", reflect.TypeOf([]LiveE2EPrerequisiteDiagnostic{}), `json:"diagnostics,omitempty"`)
}

func TestLiveE2ECredentialDeliveryProjectionRequiresLiveAndEnvMarkers(t *testing.T) {
	envActivation := liveE2ECredentialDeliveryFixture("env", "active")

	missingLive := ProjectLiveE2ECredentialDeliveryMetadata(LiveE2ECredentialDeliveryProjectionInput{
		LiveMarker:         false,
		EnvDeliveryMarker:  true,
		CredentialDelivery: envActivation,
	})
	assertCredentialDeliveryProjectionSkip(t, missingLive, LiveE2EPrerequisiteCredentialMarker, LiveE2EReasonCredentialDeliveryMarkerMissing)
	assertCredentialDeliveryProjectionNoUnsafeFragments(t, "missing live marker", missingLive, liveE2ECredentialDeliveryUnsafeFragments()...)

	missingEnv := ProjectLiveE2ECredentialDeliveryMetadata(LiveE2ECredentialDeliveryProjectionInput{
		LiveMarker:         true,
		EnvDeliveryMarker:  false,
		CredentialDelivery: envActivation,
	})
	assertCredentialDeliveryProjectionSkip(t, missingEnv, LiveE2EPrerequisiteCredentialEnvMarker, LiveE2EReasonCredentialDeliveryEnvMarkerMissing)
	assertCredentialDeliveryProjectionNoUnsafeFragments(t, "missing env marker", missingEnv, liveE2ECredentialDeliveryUnsafeFragments()...)

	httpProxy := ProjectLiveE2ECredentialDeliveryMetadata(LiveE2ECredentialDeliveryProjectionInput{
		LiveMarker:         true,
		EnvDeliveryMarker:  false,
		CredentialDelivery: liveE2ECredentialDeliveryFixture("http_proxy", "active"),
	})
	if !httpProxy.CanRunLiveAction() {
		t.Fatalf("http_proxy credential delivery projection skipped without env marker: %#v", httpProxy)
	}
	if httpProxy.CredentialDelivery == nil || len(httpProxy.CredentialDelivery.ActiveModes) != 1 || httpProxy.CredentialDelivery.ActiveModes[0] != "http_proxy" {
		t.Fatalf("http_proxy credential delivery metadata = %#v, want active http_proxy mode", httpProxy.CredentialDelivery)
	}
	assertCredentialDeliveryProjectionNoUnsafeFragments(t, "http proxy ready", httpProxy, liveE2ECredentialDeliveryUnsafeFragments()...)
}

func TestLiveE2ECredentialDeliveryProjectionRedactsActivationMetadataAndTimelineStyleRecords(t *testing.T) {
	metadata := liveE2ECredentialDeliveryFixture("env", "ACTIVE")
	metadata.RequestedModes = append(metadata.RequestedModes, "ghp_us007_secret")
	metadata.ActiveModes = append(metadata.ActiveModes, "US007_ENV_VALUE")
	metadata.ReasonCode = "REQUESTED"

	result := ProjectLiveE2ECredentialDeliveryMetadata(LiveE2ECredentialDeliveryProjectionInput{
		LiveMarker:         true,
		EnvDeliveryMarker:  true,
		CredentialDelivery: metadata,
	})
	if !result.CanRunLiveAction() {
		t.Fatalf("credential delivery projection = %#v, want ready", result)
	}
	if result.CredentialDelivery == nil {
		t.Fatal("credentialDelivery = nil")
	}
	if result.CredentialDelivery.Status != "active" || result.CredentialDelivery.ReasonCode != "requested" {
		t.Fatalf("credential delivery status = %#v, want sanitized active/requested", result.CredentialDelivery)
	}
	if !reflect.DeepEqual(result.CredentialDelivery.RequestedModes, []string{"env"}) ||
		!reflect.DeepEqual(result.CredentialDelivery.ActiveModes, []string{"env"}) {
		t.Fatalf("credential delivery modes = requested %#v active %#v, want env only", result.CredentialDelivery.RequestedModes, result.CredentialDelivery.ActiveModes)
	}

	timelineStyleRecord := struct {
		EventType string         `json:"eventType"`
		Metadata  map[string]any `json:"metadata"`
		Message   string         `json:"message"`
	}{
		EventType: "credential_delivery_projection",
		Metadata: map[string]any{
			"credentialDelivery": result.CredentialDelivery,
			"readiness":          result.Readiness,
			"diagnostics":        result.Diagnostics,
		},
		Message: LiveE2ECredentialDeliveryProjectionSkipMessage(result),
	}
	assertCredentialDeliveryProjectionNoUnsafeFragments(t, "timeline-style record", timelineStyleRecord, liveE2ECredentialDeliveryUnsafeFragments()...)
}

func TestLiveE2ECredentialDeliveryProjectionFailsClosedForUnsafeOrUnavailableActivation(t *testing.T) {
	unsafeMetadata := liveE2ECredentialDeliveryFixture("env", "active")
	unsafeMetadata.ID = "https://credentials.example.test/delivery?token=ghp_us007_secret"
	unsafeMetadata.ActivationID = "/tmp/us007-credential.sock"
	result := ProjectLiveE2ECredentialDeliveryMetadata(LiveE2ECredentialDeliveryProjectionInput{
		LiveMarker:         true,
		EnvDeliveryMarker:  true,
		CredentialDelivery: unsafeMetadata,
	})
	if !result.ShouldSkipLiveAction() {
		t.Fatalf("unsafe credential delivery metadata allowed live action: %#v", result)
	}
	if result.ReasonCode != LiveE2EReasonCredentialDeliveryUnavailable {
		t.Fatalf("unsafe metadata reason = %q, want %q", result.ReasonCode, LiveE2EReasonCredentialDeliveryUnavailable)
	}
	assertCredentialDeliveryProjectionNoUnsafeFragments(t, "unsafe metadata", result, liveE2ECredentialDeliveryUnsafeFragments()...)

	nonActive := ProjectLiveE2ECredentialDeliveryMetadata(LiveE2ECredentialDeliveryProjectionInput{
		LiveMarker:         true,
		EnvDeliveryMarker:  true,
		CredentialDelivery: liveE2ECredentialDeliveryFixture("env", "failed"),
	})
	if !nonActive.ShouldSkipLiveAction() {
		t.Fatalf("failed credential delivery metadata allowed live action: %#v", nonActive)
	}
	if nonActive.CredentialDelivery == nil || nonActive.CredentialDelivery.Status != "failed" {
		t.Fatalf("failed credential delivery metadata = %#v, want compact failed status preserved", nonActive.CredentialDelivery)
	}
	assertCredentialDeliveryProjectionNoUnsafeFragments(t, "failed metadata", nonActive, liveE2ECredentialDeliveryUnsafeFragments()...)
}

func liveE2ECredentialDeliveryFixture(mode, status string) LiveE2ECredentialDeliveryMetadata {
	return LiveE2ECredentialDeliveryMetadata{
		ID:             "credential-delivery-us007",
		RequestID:      "credential-request-us007",
		PlanID:         "credential-plan-us007",
		ActivationID:   "credential-activation-us007",
		RequestedModes: []string{mode},
		ActiveModes:    []string{mode},
		Status:         status,
		ReasonCode:     "requested",
	}
}

func assertCredentialDeliveryProjectionSkip(t *testing.T, result LiveE2ECredentialDeliveryProjectionResult, prerequisite LiveE2EPrerequisiteName, reason LiveE2EReasonCode) {
	t.Helper()
	if !result.ShouldSkipLiveAction() {
		t.Fatalf("ShouldSkipLiveAction() = false, want true for %#v", result)
	}
	if result.Status != LiveE2EReadinessSkipped {
		t.Fatalf("status = %q, want %q", result.Status, LiveE2EReadinessSkipped)
	}
	diagnostic := requireLiveE2EPreflightDiagnostic(t, result.Diagnostics, prerequisite)
	if diagnostic.ReasonCode != reason {
		t.Fatalf("%s reason = %q, want %q", prerequisite, diagnostic.ReasonCode, reason)
	}
	if result.CredentialDelivery != nil {
		t.Fatalf("credentialDelivery = %#v, want omitted for missing marker diagnostic", result.CredentialDelivery)
	}
}

func assertCredentialDeliveryProjectionNoUnsafeFragments(t *testing.T, label string, value any, forbidden ...string) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error: %v", label, err)
	}
	publicText := string(encoded)
	if result, ok := value.(LiveE2ECredentialDeliveryProjectionResult); ok {
		publicText += " " + LiveE2ECredentialDeliveryProjectionSkipMessage(result)
	}
	for _, unsafe := range forbidden {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("%s leaked unsafe credential fragment %q in %s", label, unsafe, publicText)
		}
	}
}

func liveE2ECredentialDeliveryUnsafeFragments() []string {
	return []string{
		"ghp_us007_secret",
		"US007_ENV_VALUE",
		"Authorization",
		"Bearer",
		"token=",
		"secret=",
		"https://",
		"credentials.example.test",
		"/tmp/",
		".sock",
		"env=raw",
	}
}
