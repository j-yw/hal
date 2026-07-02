package sandbox

import "testing"

func TestEvaluateSecurityCapabilityReadinessTreatsNetworkProxyMetadataAsMetadataOnly(t *testing.T) {
	enforced := true
	output := EvaluateSandboxSecurityCapabilityReadiness(SandboxSecurityCapabilityReadinessInput{
		NetworkProxySession: &SandboxNetworkProxySessionMetadata{
			ID:     "network-proxy-session-01",
			Source: SandboxNetworkPolicyDecisionSourceRun,
			PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
				ID:     "policy-snapshot-01",
				Preset: SandboxNetworkPolicyPresetDenyByDefault,
			},
			EnforcementMode: SandboxNetworkEnforcementModeProxy,
		},
		NetworkPolicyDecisionLogs: []SandboxNetworkPolicyDecisionLogRecord{{
			ID:             "decision-log-01",
			Source:         SandboxNetworkPolicyDecisionSourceRun,
			ProxySessionID: "network-proxy-session-01",
			Request: &SandboxNetworkPolicyRequestSummary{
				ID:                  "request-01",
				DestinationCategory: SandboxNetworkPolicyDestinationMetadataService,
			},
			Outcome:         SandboxNetworkPolicyDecisionOutcomeDenied,
			ReasonCode:      SandboxNetworkPolicyDecisionReasonDefaultDeny,
			PolicyPreset:    SandboxNetworkPolicyPresetDenyByDefault,
			EnforcementMode: SandboxNetworkEnforcementModeProxy,
			Enforced:        &enforced,
		}},
	})

	if len(output.Results) != 2 {
		t.Fatalf("result count = %d, want 2: %#v", len(output.Results), output.Results)
	}
	assertSecurityCapabilityMetadataOnlyResult(t, output.Results[0],
		SandboxSecurityCapabilityFamilyNetworkProxy,
		SandboxSecurityCapabilityNetworkProxyEnforcement,
		SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
	)
	assertSecurityCapabilityMetadataOnlyResult(t, output.Results[1],
		SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityNetworkDenyByDefault,
		SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
	)
}

func TestEvaluateSecurityCapabilityReadinessTreatsCredentialProxyMetadataAsMetadataOnly(t *testing.T) {
	output := EvaluateSandboxSecurityCapabilityReadiness(SandboxSecurityCapabilityReadinessInput{
		CredentialProxyPlan: &SandboxCredentialProxyPlanMetadata{
			ID:                    "credential-proxy-plan-01",
			Source:                SandboxCredentialProxySourceRun,
			SecretBrokerSessionID: "secret-broker-session-01",
			NetworkProxySessionID: "network-proxy-session-01",
			BindingCount:          1,
			Mode:                  SandboxCredentialProxyModeBrokeredNetworkReference,
			Status:                SandboxCredentialProxyStatusReady,
		},
		CredentialProxySession: &SandboxCredentialProxySessionMetadata{
			ID:                    "credential-proxy-session-01",
			PlanID:                "credential-proxy-plan-01",
			Source:                SandboxCredentialProxySourceRun,
			SecretBrokerSessionID: "secret-broker-session-01",
			NetworkProxySessionID: "network-proxy-session-01",
			Status:                SandboxCredentialProxyStatusActive,
			ReasonCode:            SandboxCredentialProxyReasonRequested,
		},
		CredentialProxyBindings: []SandboxCredentialProxyBindingMetadata{{
			ID:                  "credential-proxy-binding-01",
			PlanID:              "credential-proxy-plan-01",
			SessionID:           "credential-proxy-session-01",
			SecretID:            "env:GITHUB_TOKEN",
			DeliveryMode:        SandboxCredentialProxyDeliveryModeHTTPProxy,
			RequestCategory:     SandboxCredentialProxyRequestSourceControl,
			DestinationCategory: SandboxNetworkPolicyDestinationPublicInternet,
			Outcome:             SandboxCredentialProxyBindingOutcomeBound,
			Status:              SandboxCredentialProxyStatusReady,
			ReasonCode:          SandboxCredentialProxyReasonRequested,
		}},
	})

	if len(output.Results) != 3 {
		t.Fatalf("result count = %d, want 3: %#v", len(output.Results), output.Results)
	}
	for _, result := range output.Results {
		assertSecurityCapabilityMetadataOnlyResult(t, result,
			SandboxSecurityCapabilityFamilyCredentialProxy,
			SandboxSecurityCapabilityCredentialProxy,
			SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		)
	}
}

func assertSecurityCapabilityMetadataOnlyResult(t *testing.T, result SandboxSecurityCapabilityReadinessResult, family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName, reason SandboxSecurityCapabilityReasonCode) {
	t.Helper()

	if result.State != SandboxSecurityCapabilityReadinessMetadataOnly {
		t.Fatalf("state = %q, want metadata_only", result.State)
	}
	if result.Requested != nil {
		t.Fatalf("requested = %#v, want nil for metadata-only result", result.Requested)
	}
	if result.Ready != nil {
		t.Fatalf("ready = %#v, want nil without explicit live capability metadata", result.Ready)
	}
	if result.ReasonCode != reason {
		t.Fatalf("reasonCode = %q, want %q", result.ReasonCode, reason)
	}
	assertSecurityCapabilityMetadataNotCapabilityWarning(t, result.WarningCodes)

	if result.Metadata == nil {
		t.Fatal("metadata = nil, want metadata-only capability context")
	}
	if result.Metadata.Family != family {
		t.Fatalf("metadata family = %q, want %q", result.Metadata.Family, family)
	}
	if result.Metadata.Capability != capability {
		t.Fatalf("metadata capability = %q, want %q", result.Metadata.Capability, capability)
	}
	if result.Metadata.Source != SandboxSecurityCapabilitySourceMetadata {
		t.Fatalf("metadata source = %q, want metadata", result.Metadata.Source)
	}
	if result.Metadata.Status != SandboxSecurityCapabilityReadinessMetadataOnly {
		t.Fatalf("metadata status = %q, want metadata_only", result.Metadata.Status)
	}
	if result.Metadata.ReasonCode != reason {
		t.Fatalf("metadata reasonCode = %q, want %q", result.Metadata.ReasonCode, reason)
	}
	assertSecurityCapabilityMetadataNotCapabilityWarning(t, result.Metadata.WarningCodes)
	if result.Metadata.ID != "" || result.Metadata.Mode != "" {
		t.Fatalf("metadata copied source identifiers or modes: %#v", result.Metadata)
	}
}

func assertSecurityCapabilityMetadataNotCapabilityWarning(t *testing.T, warnings []SandboxSecurityCapabilityWarningCode) {
	t.Helper()

	if len(warnings) != 1 || warnings[0] != SandboxSecurityCapabilityWarningMetadataNotCapability {
		t.Fatalf("warningCodes = %#v, want metadata_not_capability", warnings)
	}
}
