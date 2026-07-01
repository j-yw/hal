package sandbox

import "testing"

func TestNetworkPolicyPresets(t *testing.T) {
	presets := []SandboxNetworkPolicyPreset{
		SandboxNetworkPolicyPresetLegacyDefault,
		SandboxNetworkPolicyPresetDefault,
		SandboxNetworkPolicyPresetAllowListed,
		SandboxNetworkPolicyPresetDenyByDefault,
		SandboxNetworkPolicyPresetDisabled,
		SandboxNetworkPolicyPresetNoPolicy,
	}
	for _, preset := range presets {
		if preset == "" {
			t.Fatalf("network policy preset must not be empty")
		}
	}

	wantValues := []struct {
		preset SandboxNetworkPolicyPreset
		want   string
	}{
		{preset: SandboxNetworkPolicyPresetLegacyDefault, want: "legacy_default"},
		{preset: SandboxNetworkPolicyPresetDefault, want: "legacy_default"},
		{preset: SandboxNetworkPolicyPresetAllowListed, want: "allow_listed"},
		{preset: SandboxNetworkPolicyPresetDenyByDefault, want: SandboxNetworkPolicyDenyByDefault},
		{preset: SandboxNetworkPolicyPresetDisabled, want: "disabled"},
		{preset: SandboxNetworkPolicyPresetNoPolicy, want: "no_policy"},
	}
	for _, tt := range wantValues {
		if string(tt.preset) != tt.want {
			t.Fatalf("preset %q = %q, want %q", tt.preset, string(tt.preset), tt.want)
		}
	}
}

func TestNetworkPolicyConstants(t *testing.T) {
	requested := SandboxNetworkPolicyIntent{
		Preset: SandboxNetworkPolicyPresetAllowListed,
		Rules: []SandboxNetworkPolicyRule{
			{
				Kind:     SandboxNetworkPolicyRuleKindDomain,
				Value:    "example.com",
				Decision: SandboxNetworkPolicyDecisionAllow,
			},
		},
	}
	effective := SandboxNetworkPolicyIntent{
		Preset: SandboxNetworkPolicyPresetLegacyDefault,
	}
	capability := SandboxNetworkPolicyEnforcementCapability{
		Supported:                  false,
		Modes:                      []string{SandboxNetworkEnforcementModeNone},
		SupportsDomainRules:        false,
		SupportsEndpointRules:      false,
		SupportsPrivateRangeRules:  false,
		SupportsMetadataEndpoint:   false,
		SupportsLoopbackRules:      false,
		SupportsLinkLocalRules:     false,
		SupportsDefaultDenyPosture: false,
	}

	result := SandboxNetworkPolicyResult{
		Requested:       requested,
		Effective:       effective,
		EnforcementMode: SandboxNetworkEnforcementModeNone,
		Capability:      capability,
		Warnings: []SandboxNetworkPolicyWarning{
			{
				Code:   SandboxNetworkPolicyWarningUnsupportedEnforcement,
				Policy: string(SandboxNetworkPolicyPresetAllowListed),
			},
		},
	}

	if result.Requested.Preset != SandboxNetworkPolicyPresetAllowListed {
		t.Fatalf("requested preset = %q, want %q", result.Requested.Preset, SandboxNetworkPolicyPresetAllowListed)
	}
	if result.Effective.Preset != SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("effective preset = %q, want %q", result.Effective.Preset, SandboxNetworkPolicyPresetLegacyDefault)
	}
	if result.Capability.Supported {
		t.Fatalf("capability supported = true, want false for compatibility metadata")
	}
	if result.EnforcementMode != SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforcement mode = %q, want %q", result.EnforcementMode, SandboxNetworkEnforcementModeNone)
	}
	if result.Warnings[0].Code != SandboxNetworkPolicyWarningUnsupportedEnforcement {
		t.Fatalf("warning code = %q, want %q", result.Warnings[0].Code, SandboxNetworkPolicyWarningUnsupportedEnforcement)
	}
}
