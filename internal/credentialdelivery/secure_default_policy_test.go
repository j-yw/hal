package credentialdelivery

import "testing"

func TestBuildDeliveryPlanDefaultsSafeServiceDomainBindingsToProofBearingModes(t *testing.T) {
	envBinding := secureDefaultPolicyBindingFixture("binding-env", ModeEnv)
	legacyBinding := secureDefaultPolicyBindingFixture("binding-legacy", ModeLegacyAuthSync)

	got := BuildDeliveryPlan(PlanConstructionRequest{
		PlanID:         "delivery-plan-secure-default",
		RequestID:      "delivery-request-secure-default",
		Bindings:       []Binding{envBinding, legacyBinding},
		PolicySnapshot: planPolicySnapshotFixture(),
		ResolvedBindings: []ResolvedBindingSecretMetadata{
			resolvedPlanBindingFixture(envBinding),
			resolvedPlanBindingFixture(legacyBinding),
		},
	})

	assertPlanValid(t, got)
	assertPlanModes(t, got.RequestedModes, []Mode{
		ModeHTTPProxy,
		ModeSSHAgent,
		ModeFileTmpfs,
		ModeEnv,
		ModeLegacyAuthSync,
	})
	assertPlanModes(t, got.ActiveModes, nil)
	assertPlanWarning(t, got, WarningActivationSkipped, ReasonMissingServiceBinding, ModeHTTPProxy)
	assertPlanWarning(t, got, WarningAdapterUnavailable, ReasonActivationUnavailable, ModeSSHAgent)
	assertPlanWarning(t, got, WarningAdapterUnavailable, ReasonActivationUnavailable, ModeFileTmpfs)
	assertPlanWarning(t, got, WarningCompatibilityMode, ReasonCompatibilityMode, ModeEnv)
	assertPlanWarning(t, got, WarningLegacyAuthCompatibility, ReasonCompatibilityMode, ModeLegacyAuthSync)
	if got.BindingCount != 2 {
		t.Fatalf("binding count = %d, want 2 safe broker bindings", got.BindingCount)
	}
	assertPlanNoUnsafeLeak(t, got)
}

func TestBuildDeliveryPlanClassifiesCompatibilityModesAsRequestedOnly(t *testing.T) {
	tests := []struct {
		name        string
		mode        Mode
		wantWarning WarningCode
	}{
		{
			name:        "env",
			mode:        ModeEnv,
			wantWarning: WarningCompatibilityMode,
		},
		{
			name:        "legacy auth sync",
			mode:        ModeLegacyAuthSync,
			wantWarning: WarningLegacyAuthCompatibility,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			binding := secureDefaultPolicyBindingFixture("binding-"+string(tt.mode), tt.mode)
			request := planConstructionRequestFixture(binding)
			request.RequestedModes = []Mode{tt.mode}
			configureHTTPProxyProof(&request)

			got := BuildDeliveryPlan(request)

			assertPlanValid(t, got)
			assertPlanModes(t, got.RequestedModes, []Mode{tt.mode})
			assertPlanModes(t, got.ActiveModes, nil)
			assertPlanWarning(t, got, tt.wantWarning, ReasonCompatibilityMode, tt.mode)
			assertPlanNoUnsafeLeak(t, got)
		})
	}
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

func secureDefaultPolicyBindingFixture(id string, mode Mode) Binding {
	binding := planBindingFixture(mode)
	binding.ID = id
	binding.SecretRef = "env:" + credentialDeliveryPolicySecretName(id)
	return binding
}

func credentialDeliveryPolicySecretName(id string) string {
	switch id {
	case "binding-env":
		return "GITHUB_TOKEN"
	case "binding-legacy":
		return "LEGACY_TOKEN"
	default:
		return "SERVICE_TOKEN"
	}
}
