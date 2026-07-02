package sandbox

import (
	"reflect"
	"testing"
)

func TestProjectSandboxSecurityCapabilityReadinessInputNilAndEmpty(t *testing.T) {
	tests := []struct {
		name     string
		security *SandboxSecurity
	}{
		{name: "nil security", security: nil},
		{name: "empty security", security: &SandboxSecurity{}},
		{name: "empty nested security", security: &SandboxSecurity{
			Network: &SandboxNetworkSecurity{},
			Secrets: &SandboxSecretSecurity{},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProjectSandboxSecurityCapabilityReadinessInput(tt.security)
			if !reflect.DeepEqual(got, SandboxSecurityCapabilityReadinessInput{}) {
				t.Fatalf("projected input = %#v, want empty readiness input", got)
			}
			validation := ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(got)
			if !validation.Valid {
				t.Fatalf("projected input validation errors = %#v, want valid", validation.Errors)
			}
			output := EvaluateSandboxSecurityCapabilityReadiness(got)
			if len(output.Results) != 0 {
				t.Fatalf("readiness output results = %#v, want none", output.Results)
			}
		})
	}
}

func TestProjectSandboxSecurityCapabilityReadinessInputCompatibilityOnly(t *testing.T) {
	security := EvaluateSSHMachineCompatibilitySecurity(SecurityEvaluationRequest{
		RuntimeDriver:          SandboxRuntimeDriverSSHMachine,
		RequestedNetworkPolicy: SandboxNetworkPolicyDenyByDefault,
		RequestedSecretModes:   []string{SandboxSecretModeHTTPProxy},
		CompatibilityAuthSync:  true,
	})

	got := ProjectSandboxSecurityCapabilityReadinessInput(security)
	assertProjectedSecurityCapabilityMetadata(t, got.Requested, []SandboxSecurityCapabilityMetadata{
		{
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
		{
			Family:     SandboxSecurityCapabilityFamilySecretDelivery,
			Capability: SandboxSecurityCapabilitySecretHTTPProxy,
			Mode:       SandboxSecretModeHTTPProxy,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
	})
	if len(got.Ready) != 0 {
		t.Fatalf("projected ready metadata = %#v, want none for compatibility-only summaries", got.Ready)
	}
	validation := ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(got)
	if !validation.Valid {
		t.Fatalf("projected input validation errors = %#v, want valid", validation.Errors)
	}

	output := EvaluateSandboxSecurityCapabilityReadiness(got)
	if len(output.Results) != len(got.Requested) {
		t.Fatalf("readiness output result count = %d, want %d: %#v", len(output.Results), len(got.Requested), output.Results)
	}
	assertSecurityCapabilityUnsupportedResult(t, output.Results[0],
		SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityNetworkDenyByDefault,
		"",
		SandboxSecurityCapabilityReasonCapabilityMissing,
	)
	assertSecurityCapabilityUnsupportedResult(t, output.Results[1],
		SandboxSecurityCapabilityFamilySecretDelivery,
		SandboxSecurityCapabilitySecretHTTPProxy,
		SandboxSecretModeHTTPProxy,
		SandboxSecurityCapabilityReasonCapabilityMissing,
	)
}

func TestProjectSandboxSecurityCapabilityReadinessInputExplicitSafeMetadata(t *testing.T) {
	security := &SandboxSecurity{
		Network: &SandboxNetworkSecurity{
			PolicyRequested: SandboxNetworkPolicyDenyByDefault,
			PolicyEnforced:  SandboxNetworkPolicyDenyByDefault,
			EnforcementMode: SandboxNetworkEnforcementModeFirewall,
		},
		Secrets: &SandboxSecretSecurity{
			RequestedModes: []string{
				" " + SandboxSecretModeFileTmpfs + " ",
				SandboxSecretModeHTTPProxy,
				"token=raw-secret",
			},
			ActiveModes: []string{
				SandboxSecretModeFileTmpfs,
				SandboxSecretModeEnv,
				SandboxSecretModeFileTmpfs,
				SandboxSecretModeLegacyAuthSync,
			},
		},
	}

	got := ProjectSandboxSecurityCapabilityReadinessInput(security)
	assertProjectedSecurityCapabilityMetadata(t, got.Requested, []SandboxSecurityCapabilityMetadata{
		{
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
		{
			Family:     SandboxSecurityCapabilityFamilySecretDelivery,
			Capability: SandboxSecurityCapabilitySecretFileTmpfs,
			Mode:       SandboxSecretModeFileTmpfs,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
		{
			Family:     SandboxSecurityCapabilityFamilySecretDelivery,
			Capability: SandboxSecurityCapabilitySecretHTTPProxy,
			Mode:       SandboxSecretModeHTTPProxy,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
	})
	assertProjectedSecurityCapabilityMetadata(t, got.Ready, []SandboxSecurityCapabilityMetadata{
		{
			Family:       SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability:   SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:         SandboxNetworkEnforcementModeFirewall,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
		{
			Family:       SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability:   SandboxSecurityCapabilityNetworkFirewallEnforcement,
			Mode:         SandboxNetworkEnforcementModeFirewall,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
		{
			Family:       SandboxSecurityCapabilityFamilySecretDelivery,
			Capability:   SandboxSecurityCapabilitySecretFileTmpfs,
			Mode:         SandboxSecretModeFileTmpfs,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
		{
			Family:       SandboxSecurityCapabilityFamilySecretDelivery,
			Capability:   SandboxSecurityCapabilitySecretEnv,
			Mode:         SandboxSecretModeEnv,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
	})
	validation := ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(got)
	if !validation.Valid {
		t.Fatalf("projected input validation errors = %#v, want valid", validation.Errors)
	}
	assertSecurityCapabilityJSONExcludes(t, got, "token=raw-secret", string(SandboxSecretModeLegacyAuthSync))

	output := EvaluateSandboxSecurityCapabilityReadiness(got)
	if len(output.Results) != len(got.Requested) {
		t.Fatalf("readiness output result count = %d, want %d: %#v", len(output.Results), len(got.Requested), output.Results)
	}
	for i, result := range output.Results {
		if result.State == SandboxSecurityCapabilityReadinessReady {
			t.Fatalf("projected metadata-only summary produced ready result[%d]: %#v", i, result)
		}
	}
}

func assertProjectedSecurityCapabilityMetadata(t *testing.T, got, want []SandboxSecurityCapabilityMetadata) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projected metadata = %#v, want %#v", got, want)
	}
}
