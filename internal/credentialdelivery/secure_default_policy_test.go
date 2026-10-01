package credentialdelivery

import (
	"testing"
)

func TestSecureDefaultPolicySanitizesUnsafeServiceDomainAndSecretMetadata(t *testing.T) {
	rawURL := "https://api.github.example.invalid/credential?token=ghp_raw_secret_value"
	rawPath := "/tmp/credential-delivery/token"
	rawServiceID := "api.github.example.invalid"
	rawHeader := "Authorization: Bearer ghp_raw_secret_value"
	rawTokenID := "github_pat_raw_secret_value"
	rawSecretValue := "GITHUB_TOKEN=ghp_raw_secret_value"

	sanitized := SanitizeBindingMetadata(Binding{
		ID:                    "binding-safe",
		RequestID:             rawURL,
		PlanID:                rawPath,
		PolicySnapshotID:      "policy-snapshot-01",
		SecretRef:             "env:GITHUB_TOKEN",
		NetworkProxySessionID: rawPath,
		ServiceID:             rawServiceID,
		ServiceLabels:         []string{"source-control", rawHeader, rawTokenID},
		DomainLabels:          []string{"github", "api.github.com", rawPath},
		DestinationCategory:   DestinationCategory(rawURL),
		DeliveryMode:          ModeEnv,
		Status:                Status("TOKEN=raw-secret"),
		ReasonCode:            ReasonCode("secretValue=raw-secret"),
	})

	if sanitized.ID == "" {
		t.Fatal("sanitized binding was dropped, want safe required metadata preserved")
	}
	if sanitized.RequestID != "" ||
		sanitized.PlanID != "" ||
		sanitized.NetworkProxySessionID != "" ||
		sanitized.ServiceID != "" ||
		sanitized.DestinationCategory != "" ||
		sanitized.Status != "" ||
		sanitized.ReasonCode != "" {
		t.Fatalf("sanitized binding = %#v, want unsafe optional metadata cleared", sanitized)
	}
	if len(sanitized.ServiceLabels) != 1 || sanitized.ServiceLabels[0] != "source-control" {
		t.Fatalf("service labels = %#v, want only safe labels", sanitized.ServiceLabels)
	}
	if len(sanitized.DomainLabels) != 1 || sanitized.DomainLabels[0] != "github" {
		t.Fatalf("domain labels = %#v, want only safe labels", sanitized.DomainLabels)
	}
	if unsafe := SanitizeBindingMetadata(Binding{
		ID:           "binding-raw-secret",
		SecretRef:    rawSecretValue,
		DeliveryMode: ModeEnv,
	}); unsafe.ID != "" {
		t.Fatalf("unsafe secret binding = %#v, want dropped", unsafe)
	}
	assertCredentialDeliverySanitizeNoUnsafeLeak(t, sanitized,
		rawURL,
		rawPath,
		rawServiceID,
		rawHeader,
		rawTokenID,
		rawSecretValue,
		"ghp_raw_secret_value",
	)
}

func TestSecureDefaultStatusProjectionOmitsCompatibilityActiveModes(t *testing.T) {
	got := StatusMetadataFromActivation(Plan{
		ID:             "delivery-plan-compatibility",
		RequestID:      "delivery-request-compatibility",
		RequestedModes: []Mode{ModeEnv, ModeLegacyAuthSync},
		Status:         StatusPlanned,
	}, ActivationResult{
		ID:             "activation-compatibility",
		PlanID:         "delivery-plan-compatibility",
		RequestedModes: []Mode{ModeEnv, ModeLegacyAuthSync},
		ActiveModes:    []Mode{ModeEnv, ModeLegacyAuthSync},
		Status:         StatusActive,
		Warnings: []Warning{
			{
				Code:       WarningCompatibilityMode,
				ReasonCode: ReasonCompatibilityMode,
				Mode:       ModeEnv,
			},
			{
				Code:       WarningLegacyAuthCompatibility,
				ReasonCode: ReasonCompatibilityMode,
				Mode:       ModeLegacyAuthSync,
			},
		},
	})

	if got.Status != StatusSkipped {
		t.Fatalf("status metadata status = %q, want skipped for compatibility-only active modes", got.Status)
	}
	assertPlanModes(t, got.RequestedModes, []Mode{ModeEnv, ModeLegacyAuthSync})
	assertPlanModes(t, got.ActiveModes, nil)
	if got.ReasonCode != ReasonCompatibilityMode {
		t.Fatalf("status metadata reason = %q, want %q", got.ReasonCode, ReasonCompatibilityMode)
	}
}
