package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

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

func TestEvaluateSecurityCapabilityReadinessMarksRequestedStrictNetworkEnforcementUnsupportedWithoutSupport(t *testing.T) {
	rawRuntimeID := "runtime://podman-host.example.invalid/var/run/provider.sock"
	output := EvaluateSandboxSecurityCapabilityReadiness(SandboxSecurityCapabilityReadinessInput{
		Requested: []SandboxSecurityCapabilityMetadata{{
			ID:         rawRuntimeID,
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeFirewall,
			Source:     SandboxSecurityCapabilitySourceRequested,
		}},
		Ready: []SandboxSecurityCapabilityMetadata{{
			ID:         "metadata-only-network-01",
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeFirewall,
			Source:     SandboxSecurityCapabilitySourceMetadata,
			Status:     SandboxSecurityCapabilityReadinessReady,
		}},
	})

	if len(output.Results) != 1 {
		t.Fatalf("result count = %d, want 1: %#v", len(output.Results), output.Results)
	}
	assertSecurityCapabilityUnsupportedResult(t, output.Results[0],
		SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityNetworkDenyByDefault,
		SandboxNetworkEnforcementModeFirewall,
		SandboxSecurityCapabilityReasonCapabilityMissing,
	)
	assertSecurityCapabilityOutputExcludes(t, output, rawRuntimeID, "podman-host.example.invalid", "provider.sock")
}

func TestEvaluateSecurityCapabilityReadinessMarksRequestedCredentialProxyUnsupportedWithoutSupport(t *testing.T) {
	rawProviderID := "provider://host.example.invalid/credential-proxy/socket"
	output := EvaluateSandboxSecurityCapabilityReadiness(SandboxSecurityCapabilityReadinessInput{
		Requested: []SandboxSecurityCapabilityMetadata{{
			ID:         rawProviderID,
			Family:     SandboxSecurityCapabilityFamilyCredentialProxy,
			Capability: SandboxSecurityCapabilityCredentialProxy,
			Mode:       SandboxSecretModeHTTPProxy,
			Source:     SandboxSecurityCapabilitySourceRequested,
		}},
		CredentialProxyPlan: &SandboxCredentialProxyPlanMetadata{
			ID:                    "credential-proxy-plan-01",
			Source:                SandboxCredentialProxySourceRun,
			SecretBrokerSessionID: "secret-broker-session-01",
			NetworkProxySessionID: "network-proxy-session-01",
			BindingCount:          1,
			Mode:                  SandboxCredentialProxyModeBrokeredNetworkReference,
			Status:                SandboxCredentialProxyStatusReady,
		},
	})

	if len(output.Results) != 2 {
		t.Fatalf("result count = %d, want 2: %#v", len(output.Results), output.Results)
	}
	assertSecurityCapabilityUnsupportedResult(t, output.Results[0],
		SandboxSecurityCapabilityFamilyCredentialProxy,
		SandboxSecurityCapabilityCredentialProxy,
		SandboxSecretModeHTTPProxy,
		SandboxSecurityCapabilityReasonCapabilityMissing,
	)
	assertSecurityCapabilityMetadataOnlyResult(t, output.Results[1],
		SandboxSecurityCapabilityFamilyCredentialProxy,
		SandboxSecurityCapabilityCredentialProxy,
		SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
	)
	assertSecurityCapabilityOutputExcludes(t, output, rawProviderID, "host.example.invalid", "credential-proxy/socket")
}

func TestEvaluateSecurityCapabilityReadinessMarksExplicitBlockedCapability(t *testing.T) {
	rawRequestID := "config:///Users/v/project/.hal/config.yaml?secretName=GITHUB_TOKEN"
	rawBlockerID := "runtime://podman-host.example.invalid/var/run/provider.sock?token=raw-token"
	rawWarning := SandboxSecurityCapabilityWarningCode("token=raw-token")

	output := EvaluateSandboxSecurityCapabilityReadiness(SandboxSecurityCapabilityReadinessInput{
		Requested: []SandboxSecurityCapabilityMetadata{{
			ID:         rawRequestID,
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeFirewall,
			Source:     SandboxSecurityCapabilitySourceRequested,
		}},
		Ready: []SandboxSecurityCapabilityMetadata{{
			ID:         rawBlockerID,
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeFirewall,
			Source:     SandboxSecurityCapabilitySourceRuntime,
			Status:     SandboxSecurityCapabilityReadinessBlocked,
			ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{
				SandboxSecurityCapabilityWarningBlockedByPolicy,
				rawWarning,
			},
		}},
	})

	if len(output.Results) != 1 {
		t.Fatalf("result count = %d, want 1: %#v", len(output.Results), output.Results)
	}
	assertSecurityCapabilityBlockedResult(t, output.Results[0],
		SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityNetworkDenyByDefault,
		SandboxNetworkEnforcementModeFirewall,
		SandboxSecurityCapabilitySourceRuntime,
		[]SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningBlockedByPolicy},
	)
	assertSecurityCapabilityOutputExcludes(t, output,
		rawRequestID,
		rawBlockerID,
		"/Users/v/project",
		"podman-host.example.invalid",
		"provider.sock",
		"GITHUB_TOKEN",
		"raw-token",
	)
}

func TestEvaluateSecurityCapabilityReadinessRequiresExplicitSafeBlockerMetadata(t *testing.T) {
	tests := []struct {
		name              string
		requestedMode     string
		ready             []SandboxSecurityCapabilityMetadata
		wantResultCount   int
		wantUnsupported   bool
		forbiddenInOutput []string
	}{
		{
			name:          "metadata source blocked is not explicit support",
			requestedMode: SandboxNetworkEnforcementModeFirewall,
			ready: []SandboxSecurityCapabilityMetadata{{
				ID:         "metadata-blocker-01",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
				Mode:       SandboxNetworkEnforcementModeFirewall,
				Source:     SandboxSecurityCapabilitySourceMetadata,
				Status:     SandboxSecurityCapabilityReadinessBlocked,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
			}},
			wantResultCount: 1,
			wantUnsupported: true,
		},
		{
			name:          "blocked reason without blocked status is not a blocker",
			requestedMode: SandboxNetworkEnforcementModeFirewall,
			ready: []SandboxSecurityCapabilityMetadata{{
				ID:         "ready-network-01",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
				Mode:       SandboxNetworkEnforcementModeFirewall,
				Source:     SandboxSecurityCapabilitySourceRuntime,
				Status:     SandboxSecurityCapabilityReadinessReady,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
			}},
			wantResultCount: 0,
		},
		{
			name:          "raw blocker mode is not safe blocker metadata",
			requestedMode: "",
			ready: []SandboxSecurityCapabilityMetadata{{
				ID:         "unsafe-blocker-01",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
				Mode:       "/tmp/provider.sock",
				Source:     SandboxSecurityCapabilitySourceRuntime,
				Status:     SandboxSecurityCapabilityReadinessBlocked,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
				WarningCodes: []SandboxSecurityCapabilityWarningCode{
					SandboxSecurityCapabilityWarningCode("secretName=GITHUB_TOKEN"),
				},
			}},
			wantResultCount:   1,
			wantUnsupported:   true,
			forbiddenInOutput: []string{"/tmp/provider.sock", "GITHUB_TOKEN"},
		},
		{
			name:          "raw blocker reason is not safe blocker metadata",
			requestedMode: SandboxNetworkEnforcementModeFirewall,
			ready: []SandboxSecurityCapabilityMetadata{{
				ID:         "unsafe-reason-blocker-01",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
				Mode:       SandboxNetworkEnforcementModeFirewall,
				Source:     SandboxSecurityCapabilitySourceRuntime,
				Status:     SandboxSecurityCapabilityReadinessBlocked,
				ReasonCode: SandboxSecurityCapabilityReasonCode("config=/Users/v/project/.hal/config.yaml"),
			}},
			wantResultCount:   1,
			wantUnsupported:   true,
			forbiddenInOutput: []string{"/Users/v/project", "config.yaml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output := EvaluateSandboxSecurityCapabilityReadiness(SandboxSecurityCapabilityReadinessInput{
				Requested: []SandboxSecurityCapabilityMetadata{{
					Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
					Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
					Mode:       tt.requestedMode,
					Source:     SandboxSecurityCapabilitySourceRequested,
				}},
				Ready: tt.ready,
			})

			if len(output.Results) != tt.wantResultCount {
				t.Fatalf("result count = %d, want %d: %#v", len(output.Results), tt.wantResultCount, output.Results)
			}
			for _, result := range output.Results {
				if result.State == SandboxSecurityCapabilityReadinessBlocked {
					t.Fatalf("state = blocked from non-explicit blocker metadata: %#v", result)
				}
			}
			if tt.wantUnsupported {
				assertSecurityCapabilityUnsupportedResult(t, output.Results[0],
					SandboxSecurityCapabilityFamilyNetworkPolicy,
					SandboxSecurityCapabilityNetworkDenyByDefault,
					sandboxSecurityCapabilitySafeMode(SandboxSecurityCapabilityFamilyNetworkPolicy, SandboxSecurityCapabilityNetworkDenyByDefault, tt.requestedMode),
					SandboxSecurityCapabilityReasonCapabilityMissing,
				)
			}
			assertSecurityCapabilityOutputExcludes(t, output, tt.forbiddenInOutput...)
		})
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

func assertSecurityCapabilityBlockedResult(t *testing.T, result SandboxSecurityCapabilityReadinessResult, family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName, mode string, blockerSource SandboxSecurityCapabilitySource, warnings []SandboxSecurityCapabilityWarningCode) {
	t.Helper()

	if result.State != SandboxSecurityCapabilityReadinessBlocked {
		t.Fatalf("state = %q, want blocked", result.State)
	}
	if result.Metadata != nil {
		t.Fatalf("metadata = %#v, want nil for blocked request", result.Metadata)
	}
	if result.ReasonCode != SandboxSecurityCapabilityReasonCapabilityBlocked {
		t.Fatalf("reasonCode = %q, want capability_blocked", result.ReasonCode)
	}
	assertSecurityCapabilityWarningsEqual(t, result.WarningCodes, warnings)

	if result.Requested == nil {
		t.Fatal("requested = nil, want sanitized requested capability context")
	}
	assertSecurityCapabilityBlockedContext(t, *result.Requested,
		family,
		capability,
		mode,
		SandboxSecurityCapabilitySourceRequested,
		warnings,
	)

	if result.Ready == nil {
		t.Fatal("ready = nil, want sanitized blocker capability context")
	}
	assertSecurityCapabilityBlockedContext(t, *result.Ready,
		family,
		capability,
		mode,
		blockerSource,
		warnings,
	)
}

func assertSecurityCapabilityBlockedContext(t *testing.T, metadata SandboxSecurityCapabilityMetadata, family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName, mode string, source SandboxSecurityCapabilitySource, warnings []SandboxSecurityCapabilityWarningCode) {
	t.Helper()

	if metadata.Family != family {
		t.Fatalf("family = %q, want %q", metadata.Family, family)
	}
	if metadata.Capability != capability {
		t.Fatalf("capability = %q, want %q", metadata.Capability, capability)
	}
	if metadata.Mode != mode {
		t.Fatalf("mode = %q, want %q", metadata.Mode, mode)
	}
	if metadata.Source != source {
		t.Fatalf("source = %q, want %q", metadata.Source, source)
	}
	if metadata.Status != SandboxSecurityCapabilityReadinessBlocked {
		t.Fatalf("status = %q, want blocked", metadata.Status)
	}
	if metadata.ReasonCode != SandboxSecurityCapabilityReasonCapabilityBlocked {
		t.Fatalf("reasonCode = %q, want capability_blocked", metadata.ReasonCode)
	}
	assertSecurityCapabilityWarningsEqual(t, metadata.WarningCodes, warnings)
	if metadata.ID != "" {
		t.Fatalf("metadata copied source identifier: %#v", metadata)
	}
}

func assertSecurityCapabilityUnsupportedResult(t *testing.T, result SandboxSecurityCapabilityReadinessResult, family SandboxSecurityCapabilityFamily, capability SandboxSecurityCapabilityName, mode string, reason SandboxSecurityCapabilityReasonCode) {
	t.Helper()

	if result.State != SandboxSecurityCapabilityReadinessUnsupported {
		t.Fatalf("state = %q, want unsupported", result.State)
	}
	if result.Metadata != nil {
		t.Fatalf("metadata = %#v, want nil for unsupported request", result.Metadata)
	}
	if result.Ready != nil {
		t.Fatalf("ready = %#v, want nil without explicit live capability support", result.Ready)
	}
	if result.ReasonCode != reason {
		t.Fatalf("reasonCode = %q, want %q", result.ReasonCode, reason)
	}
	if len(result.WarningCodes) != 0 {
		t.Fatalf("warningCodes = %#v, want none for missing capability", result.WarningCodes)
	}
	if result.Requested == nil {
		t.Fatal("requested = nil, want sanitized requested capability context")
	}
	if result.Requested.Family != family {
		t.Fatalf("requested family = %q, want %q", result.Requested.Family, family)
	}
	if result.Requested.Capability != capability {
		t.Fatalf("requested capability = %q, want %q", result.Requested.Capability, capability)
	}
	if result.Requested.Mode != mode {
		t.Fatalf("requested mode = %q, want %q", result.Requested.Mode, mode)
	}
	if result.Requested.Source != SandboxSecurityCapabilitySourceRequested {
		t.Fatalf("requested source = %q, want requested", result.Requested.Source)
	}
	if result.Requested.Status != SandboxSecurityCapabilityReadinessUnsupported {
		t.Fatalf("requested status = %q, want unsupported", result.Requested.Status)
	}
	if result.Requested.ReasonCode != reason {
		t.Fatalf("requested reasonCode = %q, want %q", result.Requested.ReasonCode, reason)
	}
	if len(result.Requested.WarningCodes) != 0 {
		t.Fatalf("requested warningCodes = %#v, want none for missing capability", result.Requested.WarningCodes)
	}
	if result.Requested.ID != "" {
		t.Fatalf("requested copied source identifier: %#v", result.Requested)
	}
}

func assertSecurityCapabilityWarningsEqual(t *testing.T, got, want []SandboxSecurityCapabilityWarningCode) {
	t.Helper()

	if len(got) != len(want) {
		t.Fatalf("warningCodes = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("warningCodes = %#v, want %#v", got, want)
		}
	}
}

func assertSecurityCapabilityMetadataNotCapabilityWarning(t *testing.T, warnings []SandboxSecurityCapabilityWarningCode) {
	t.Helper()

	if len(warnings) != 1 || warnings[0] != SandboxSecurityCapabilityWarningMetadataNotCapability {
		t.Fatalf("warningCodes = %#v, want metadata_not_capability", warnings)
	}
}

func assertSecurityCapabilityOutputExcludes(t *testing.T, output SandboxSecurityCapabilityReadinessOutput, forbidden ...string) {
	t.Helper()

	data, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("json.Marshal(output) error = %v", err)
	}
	payload := string(data)
	for _, value := range forbidden {
		if strings.Contains(payload, value) {
			t.Fatalf("readiness output leaked raw value %q in %s", value, payload)
		}
	}
}
