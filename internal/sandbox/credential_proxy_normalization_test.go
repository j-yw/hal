package sandbox

import "testing"

func TestCredentialProxyNormalizationTrimsIDFieldsBeforeValidation(t *testing.T) {
	plan := NormalizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		ID:                    " CredentialPlan-01 ",
		Source:                SandboxCredentialProxySource(" RUN "),
		SecretBrokerSessionID: " BrokerSession-01 ",
		NetworkProxySessionID: " NetworkProxySession-01 ",
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        " PolicySnapshot-01 ",
			Version:   " V1 ",
			Preset:    SandboxNetworkPolicyPreset(" ALLOW_LISTED "),
			RuleSetID: " Rules-01 ",
		},
		Mode:   SandboxCredentialProxyMode(" BROKERED_NETWORK_REFERENCE "),
		Status: SandboxCredentialProxyStatus(" PLANNED "),
	})
	if plan.ID != "CredentialPlan-01" {
		t.Fatalf("plan ID = %q, want trimmed safe casing", plan.ID)
	}
	if plan.SecretBrokerSessionID != "BrokerSession-01" {
		t.Fatalf("secret broker session ID = %q, want trimmed safe casing", plan.SecretBrokerSessionID)
	}
	if plan.NetworkProxySessionID != "NetworkProxySession-01" {
		t.Fatalf("network proxy session ID = %q, want trimmed safe casing", plan.NetworkProxySessionID)
	}
	if plan.PolicySnapshot == nil {
		t.Fatalf("policy snapshot = nil, want normalized copy")
	}
	if plan.PolicySnapshot.ID != "PolicySnapshot-01" || plan.PolicySnapshot.Version != "V1" || plan.PolicySnapshot.RuleSetID != "Rules-01" {
		t.Fatalf("policy snapshot IDs = %#v, want trimmed safe casing", plan.PolicySnapshot)
	}
	assertCredentialProxyValidationValid(t, ValidateSandboxCredentialProxyPlanMetadata(plan))

	session := NormalizeSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
		ID:                    " CredentialSession-01 ",
		PlanID:                " CredentialPlan-01 ",
		Source:                SandboxCredentialProxySource(" FACTORY "),
		SecretBrokerSessionID: " BrokerSession-01 ",
		NetworkProxySessionID: " NetworkProxySession-01 ",
		PolicySnapshot:        &SandboxNetworkPolicySnapshotIdentity{ID: " PolicySnapshot-01 "},
		Status:                SandboxCredentialProxyStatus(" ACTIVE "),
		WarningCode:           SandboxCredentialProxyWarningCode(" BINDING_OMITTED "),
		ReasonCode:            SandboxCredentialProxyReasonCode(" REQUESTED "),
	})
	if session.ID != "CredentialSession-01" || session.PlanID != "CredentialPlan-01" {
		t.Fatalf("session IDs = %#v, want trimmed safe casing", session)
	}
	assertCredentialProxyValidationValid(t, ValidateSandboxCredentialProxySessionMetadata(session))

	binding := NormalizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
		ID:              " CredentialBinding-01 ",
		PlanID:          " CredentialPlan-01 ",
		SessionID:       " CredentialSession-01 ",
		SecretID:        " Secret-01 ",
		DeliveryMode:    SandboxCredentialProxyDeliveryMode(" ENV "),
		RequestCategory: SandboxCredentialProxyRequestCategory(" SECRET_DELIVERY "),
		Outcome:         SandboxCredentialProxyBindingOutcome(" BOUND "),
		Status:          SandboxCredentialProxyStatus(" COMPLETED "),
		ReasonCode:      SandboxCredentialProxyReasonCode(" REQUESTED "),
	})
	if binding.ID != "CredentialBinding-01" || binding.PlanID != "CredentialPlan-01" || binding.SessionID != "CredentialSession-01" || binding.SecretID != "Secret-01" {
		t.Fatalf("binding IDs = %#v, want trimmed safe casing", binding)
	}
	assertCredentialProxyValidationValid(t, ValidateSandboxCredentialProxyBindingMetadata(binding))
}

func TestCredentialProxyNormalizationLowercasesEnumLikeMetadata(t *testing.T) {
	plan := NormalizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		ID:     "credential-plan-01",
		Source: SandboxCredentialProxySource("AUTO"),
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:     "policy-snapshot-01",
			Preset: SandboxNetworkPolicyPreset("DENY_BY_DEFAULT"),
		},
		Mode:   SandboxCredentialProxyMode("SECRET_BROKER_REFERENCE"),
		Status: SandboxCredentialProxyStatus("READY"),
	})
	if plan.Source != SandboxCredentialProxySourceAuto {
		t.Fatalf("plan source = %q, want %q", plan.Source, SandboxCredentialProxySourceAuto)
	}
	if plan.Mode != SandboxCredentialProxyModeSecretBrokerReference {
		t.Fatalf("plan mode = %q, want %q", plan.Mode, SandboxCredentialProxyModeSecretBrokerReference)
	}
	if plan.Status != SandboxCredentialProxyStatusReady {
		t.Fatalf("plan status = %q, want %q", plan.Status, SandboxCredentialProxyStatusReady)
	}
	if plan.PolicySnapshot.Preset != SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("policy preset = %q, want %q", plan.PolicySnapshot.Preset, SandboxNetworkPolicyPresetDenyByDefault)
	}

	session := NormalizeSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
		ID:          "credential-session-01",
		PlanID:      "credential-plan-01",
		Source:      SandboxCredentialProxySource("WORKER"),
		Status:      SandboxCredentialProxyStatus("FAILED"),
		WarningCode: SandboxCredentialProxyWarningCode("UNSUPPORTED_DELIVERY_MODE"),
		ReasonCode:  SandboxCredentialProxyReasonCode("DELIVERY_MODE_UNSUPPORTED"),
	})
	if session.Source != SandboxCredentialProxySourceWorker {
		t.Fatalf("session source = %q, want %q", session.Source, SandboxCredentialProxySourceWorker)
	}
	if session.WarningCode != SandboxCredentialProxyWarningUnsupportedDeliveryMode {
		t.Fatalf("warning code = %q, want %q", session.WarningCode, SandboxCredentialProxyWarningUnsupportedDeliveryMode)
	}
	if session.ReasonCode != SandboxCredentialProxyReasonDeliveryModeUnsupported {
		t.Fatalf("reason code = %q, want %q", session.ReasonCode, SandboxCredentialProxyReasonDeliveryModeUnsupported)
	}

	binding := NormalizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
		ID:                  "credential-binding-01",
		PlanID:              "credential-plan-01",
		SecretID:            "secret-01",
		DeliveryMode:        SandboxCredentialProxyDeliveryMode("FILE_TMPFS"),
		RequestCategory:     SandboxCredentialProxyRequestCategory("ARTIFACT_SYNC"),
		DestinationCategory: SandboxNetworkPolicyDestinationCategory("METADATA_SERVICE"),
		Outcome:             SandboxCredentialProxyBindingOutcome("AUDIT_ONLY"),
		Status:              SandboxCredentialProxyStatus("SKIPPED"),
		ReasonCode:          SandboxCredentialProxyReasonCode("DESTINATION_CATEGORY_SKIPPED"),
	})
	if binding.DeliveryMode != SandboxCredentialProxyDeliveryModeFileTmpfs {
		t.Fatalf("delivery mode = %q, want %q", binding.DeliveryMode, SandboxCredentialProxyDeliveryModeFileTmpfs)
	}
	if binding.RequestCategory != SandboxCredentialProxyRequestArtifactSync {
		t.Fatalf("request category = %q, want %q", binding.RequestCategory, SandboxCredentialProxyRequestArtifactSync)
	}
	if binding.DestinationCategory != SandboxNetworkPolicyDestinationMetadataService {
		t.Fatalf("destination category = %q, want %q", binding.DestinationCategory, SandboxNetworkPolicyDestinationMetadataService)
	}
	if binding.Outcome != SandboxCredentialProxyBindingOutcomeAuditOnly {
		t.Fatalf("outcome = %q, want %q", binding.Outcome, SandboxCredentialProxyBindingOutcomeAuditOnly)
	}
}

func TestCredentialProxyNormalizationPreservesNilReferencesAndEmptySlices(t *testing.T) {
	plan := NormalizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		ID:     "credential-plan-01",
		Source: SandboxCredentialProxySourceRun,
	})
	if plan.PolicySnapshot != nil {
		t.Fatalf("policy snapshot = %#v, want nil", plan.PolicySnapshot)
	}

	var nilPlans []SandboxCredentialProxyPlanMetadata
	if got := NormalizeSandboxCredentialProxyPlanMetadataRecords(nilPlans); got != nil {
		t.Fatalf("nil plan records normalized to %#v, want nil", got)
	}
	emptyPlans := NormalizeSandboxCredentialProxyPlanMetadataRecords([]SandboxCredentialProxyPlanMetadata{})
	if emptyPlans == nil || len(emptyPlans) != 0 {
		t.Fatalf("empty plan records = %#v, want explicit empty slice", emptyPlans)
	}

	var nilSessions []SandboxCredentialProxySessionMetadata
	if got := NormalizeSandboxCredentialProxySessionMetadataRecords(nilSessions); got != nil {
		t.Fatalf("nil session records normalized to %#v, want nil", got)
	}
	emptySessions := NormalizeSandboxCredentialProxySessionMetadataRecords([]SandboxCredentialProxySessionMetadata{})
	if emptySessions == nil || len(emptySessions) != 0 {
		t.Fatalf("empty session records = %#v, want explicit empty slice", emptySessions)
	}

	var nilBindings []SandboxCredentialProxyBindingMetadata
	if got := NormalizeSandboxCredentialProxyBindingMetadataRecords(nilBindings); got != nil {
		t.Fatalf("nil binding records normalized to %#v, want nil", got)
	}
	emptyBindings := NormalizeSandboxCredentialProxyBindingMetadataRecords([]SandboxCredentialProxyBindingMetadata{})
	if emptyBindings == nil || len(emptyBindings) != 0 {
		t.Fatalf("empty binding records = %#v, want explicit empty slice", emptyBindings)
	}
}

func TestCredentialProxyNormalizationDoesNotConvertUnsafeValuesIntoAcceptedValues(t *testing.T) {
	plan := NormalizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
		ID:     " https://user:pass@example.invalid/path?token=value ",
		Source: SandboxCredentialProxySource("RUN"),
	})
	assertCredentialProxyValidationError(t, ValidateSandboxCredentialProxyPlanMetadata(plan), SandboxCredentialProxyValidationUnsafeID, "id")

	session := NormalizeSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
		ID:     "credential-session-01",
		PlanID: "api.example.invalid",
		Source: SandboxCredentialProxySource("AUTO"),
	})
	assertCredentialProxyValidationError(t, ValidateSandboxCredentialProxySessionMetadata(session), SandboxCredentialProxyValidationUnsafeReference, "planId")

	binding := NormalizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
		ID:           "credential-binding-01",
		PlanID:       "credential-plan-01",
		SecretID:     "secret-01",
		DeliveryMode: SandboxCredentialProxyDeliveryMode(" HTTPS://EXAMPLE.INVALID "),
	})
	assertCredentialProxyValidationError(t, ValidateSandboxCredentialProxyBindingMetadata(binding), SandboxCredentialProxyValidationUnsafeMetadata, "deliveryMode")
}
