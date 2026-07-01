package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

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

func TestNetworkPolicyRuleValidation(t *testing.T) {
	valid := ValidateSandboxNetworkPolicyIntent(SandboxNetworkPolicyIntent{
		Preset: SandboxNetworkPolicyPresetAllowListed,
		Rules: []SandboxNetworkPolicyRule{
			{
				Kind:     SandboxNetworkPolicyRuleKindDomain,
				Value:    "api.example.com",
				Decision: SandboxNetworkPolicyDecisionAllow,
			},
			{
				Kind:     SandboxNetworkPolicyRuleKindEndpoint,
				Value:    "api.example.com:443",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
		},
	})
	if !valid.Valid {
		t.Fatalf("valid policy returned errors: %#v", valid.Errors)
	}
	if !hasNetworkPolicyDataDecision(valid, SandboxNetworkPolicyDataDecisionDomainRule) {
		t.Fatalf("validation decisions missing domain rule: %#v", valid.Decisions)
	}
	if !hasNetworkPolicyDataDecision(valid, SandboxNetworkPolicyDataDecisionEndpointRule) {
		t.Fatalf("validation decisions missing endpoint rule: %#v", valid.Decisions)
	}

	tests := []struct {
		name string
		rule SandboxNetworkPolicyRule
		code SandboxNetworkPolicyValidationCode
	}{
		{
			name: "empty domain",
			rule: SandboxNetworkPolicyRule{
				Kind:     SandboxNetworkPolicyRuleKindDomain,
				Value:    " ",
				Decision: SandboxNetworkPolicyDecisionAllow,
			},
			code: SandboxNetworkPolicyValidationInvalidRuleValue,
		},
		{
			name: "unsupported domain wildcard",
			rule: SandboxNetworkPolicyRule{
				Kind:     SandboxNetworkPolicyRuleKindDomain,
				Value:    "*.example.com",
				Decision: SandboxNetworkPolicyDecisionAllow,
			},
			code: SandboxNetworkPolicyValidationUnsupportedWildcard,
		},
		{
			name: "malformed domain",
			rule: SandboxNetworkPolicyRule{
				Kind:     SandboxNetworkPolicyRuleKindDomain,
				Value:    "bad_host_name",
				Decision: SandboxNetworkPolicyDecisionAllow,
			},
			code: SandboxNetworkPolicyValidationMalformedDomain,
		},
		{
			name: "credential-bearing domain url",
			rule: SandboxNetworkPolicyRule{
				Kind:     SandboxNetworkPolicyRuleKindDomain,
				Value:    "https://user:super-secret-token@example.com/path?api_key=secret-query",
				Decision: SandboxNetworkPolicyDecisionAllow,
			},
			code: SandboxNetworkPolicyValidationCredentialBearingURL,
		},
		{
			name: "endpoint missing port",
			rule: SandboxNetworkPolicyRule{
				Kind:     SandboxNetworkPolicyRuleKindEndpoint,
				Value:    "api.example.com",
				Decision: SandboxNetworkPolicyDecisionAllow,
			},
			code: SandboxNetworkPolicyValidationMalformedEndpoint,
		},
		{
			name: "endpoint invalid port",
			rule: SandboxNetworkPolicyRule{
				Kind:     SandboxNetworkPolicyRuleKindEndpoint,
				Value:    "api.example.com:not-a-port",
				Decision: SandboxNetworkPolicyDecisionAllow,
			},
			code: SandboxNetworkPolicyValidationMalformedEndpoint,
		},
		{
			name: "credential-bearing endpoint url",
			rule: SandboxNetworkPolicyRule{
				Kind:     SandboxNetworkPolicyRuleKindEndpoint,
				Value:    "https://user:super-secret-token@example.com:443/path?api_key=secret-query",
				Decision: SandboxNetworkPolicyDecisionAllow,
			},
			code: SandboxNetworkPolicyValidationCredentialBearingURL,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateSandboxNetworkPolicyIntent(SandboxNetworkPolicyIntent{
				Preset: SandboxNetworkPolicyPresetAllowListed,
				Rules:  []SandboxNetworkPolicyRule{tt.rule},
			})
			if got.Valid {
				t.Fatalf("ValidateSandboxNetworkPolicyIntent() valid = true, want false")
			}
			if !hasNetworkPolicyValidationCode(got, tt.code) {
				t.Fatalf("validation errors = %#v, want code %q", got.Errors, tt.code)
			}
			assertNetworkPolicyValidationNoUnsafeLeak(t, got)
		})
	}
}

func TestNetworkPolicyPrivateRangeValidation(t *testing.T) {
	valid := ValidateSandboxNetworkPolicyIntent(SandboxNetworkPolicyIntent{
		Preset: SandboxNetworkPolicyPresetDenyByDefault,
		Rules: []SandboxNetworkPolicyRule{
			{
				Kind:     SandboxNetworkPolicyRuleKindPrivateRange,
				Value:    "10.0.0.0/8",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
			{
				Kind:     SandboxNetworkPolicyRuleKindPrivateRange,
				Value:    "172.16.0.0/12",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
			{
				Kind:     SandboxNetworkPolicyRuleKindPrivateRange,
				Value:    "192.168.1.0/24",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
		},
	})
	if !valid.Valid {
		t.Fatalf("private range policy returned errors: %#v", valid.Errors)
	}
	if !hasNetworkPolicyDataDecision(valid, SandboxNetworkPolicyDataDecisionDefaultDenyPosture) {
		t.Fatalf("validation decisions missing default-deny posture: %#v", valid.Decisions)
	}
	if !hasNetworkPolicyDataDecision(valid, SandboxNetworkPolicyDataDecisionPrivateRangeRule) {
		t.Fatalf("validation decisions missing private range rule: %#v", valid.Decisions)
	}
	payload, err := json.Marshal(valid)
	if err != nil {
		t.Fatalf("marshal validation result: %v", err)
	}
	for _, forbidden := range []string{"enforcementMode", "capability", "enforced"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("validation result %s must not imply enforcement metadata %q", payload, forbidden)
		}
	}

	invalid := ValidateSandboxNetworkPolicyIntent(SandboxNetworkPolicyIntent{
		Preset: SandboxNetworkPolicyPresetDenyByDefault,
		Rules: []SandboxNetworkPolicyRule{
			{
				Kind:     SandboxNetworkPolicyRuleKindPrivateRange,
				Value:    "8.8.8.0/24",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
			{
				Kind:     SandboxNetworkPolicyRuleKindPrivateRange,
				Value:    "127.0.0.0/8",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
		},
	})
	if invalid.Valid {
		t.Fatalf("public or loopback ranges validated as private: %#v", invalid)
	}
	if !hasNetworkPolicyValidationCode(invalid, SandboxNetworkPolicyValidationNonPrivateRange) {
		t.Fatalf("validation errors = %#v, want non-private range code", invalid.Errors)
	}
}

func TestNetworkPolicyMetadataEndpointValidation(t *testing.T) {
	valid := ValidateSandboxNetworkPolicyIntent(SandboxNetworkPolicyIntent{
		Preset: SandboxNetworkPolicyPresetAllowListed,
		Rules: []SandboxNetworkPolicyRule{
			{
				Kind:     SandboxNetworkPolicyRuleKindMetadataEndpoint,
				Value:    "169.254.169.254",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
			{
				Kind:     SandboxNetworkPolicyRuleKindLoopback,
				Value:    "127.0.0.1",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
			{
				Kind:     SandboxNetworkPolicyRuleKindLinkLocal,
				Value:    "169.254.10.20",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
		},
	})
	if !valid.Valid {
		t.Fatalf("metadata/loopback/link-local policy returned errors: %#v", valid.Errors)
	}
	for _, decision := range []SandboxNetworkPolicyDataDecision{
		SandboxNetworkPolicyDataDecisionMetadataEndpointRule,
		SandboxNetworkPolicyDataDecisionLoopbackRule,
		SandboxNetworkPolicyDataDecisionLinkLocalRule,
	} {
		if !hasNetworkPolicyDataDecision(valid, decision) {
			t.Fatalf("validation decisions missing %q: %#v", decision, valid.Decisions)
		}
	}

	tests := []struct {
		name string
		rule SandboxNetworkPolicyRule
		code SandboxNetworkPolicyValidationCode
	}{
		{
			name: "metadata endpoint rejects arbitrary public address",
			rule: SandboxNetworkPolicyRule{
				Kind:     SandboxNetworkPolicyRuleKindMetadataEndpoint,
				Value:    "203.0.113.10",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
			code: SandboxNetworkPolicyValidationNonMetadataEndpoint,
		},
		{
			name: "loopback rejects private address",
			rule: SandboxNetworkPolicyRule{
				Kind:     SandboxNetworkPolicyRuleKindLoopback,
				Value:    "10.0.0.1",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
			code: SandboxNetworkPolicyValidationNonLoopback,
		},
		{
			name: "link-local rejects public address",
			rule: SandboxNetworkPolicyRule{
				Kind:     SandboxNetworkPolicyRuleKindLinkLocal,
				Value:    "203.0.113.10",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
			code: SandboxNetworkPolicyValidationNonLinkLocal,
		},
		{
			name: "metadata endpoint rejects credential-bearing url",
			rule: SandboxNetworkPolicyRule{
				Kind:     SandboxNetworkPolicyRuleKindMetadataEndpoint,
				Value:    "http://user:super-secret-token@169.254.169.254/latest/meta-data?api_key=secret-query",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
			code: SandboxNetworkPolicyValidationCredentialBearingURL,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateSandboxNetworkPolicyIntent(SandboxNetworkPolicyIntent{
				Preset: SandboxNetworkPolicyPresetAllowListed,
				Rules:  []SandboxNetworkPolicyRule{tt.rule},
			})
			if got.Valid {
				t.Fatalf("ValidateSandboxNetworkPolicyIntent() valid = true, want false")
			}
			if !hasNetworkPolicyValidationCode(got, tt.code) {
				t.Fatalf("validation errors = %#v, want code %q", got.Errors, tt.code)
			}
			assertNetworkPolicyValidationNoUnsafeLeak(t, got)
		})
	}
}

func hasNetworkPolicyDataDecision(result SandboxNetworkPolicyValidationResult, code SandboxNetworkPolicyDataDecision) bool {
	for _, decision := range result.Decisions {
		if decision.Code == code {
			return true
		}
	}
	return false
}

func hasNetworkPolicyValidationCode(result SandboxNetworkPolicyValidationResult, code SandboxNetworkPolicyValidationCode) bool {
	for _, err := range result.Errors {
		if err.Code == code {
			return true
		}
	}
	return false
}

func assertNetworkPolicyValidationNoUnsafeLeak(t *testing.T, result SandboxNetworkPolicyValidationResult) {
	t.Helper()

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal validation result: %v", err)
	}
	for _, unsafe := range []string{"super-secret-token", "secret-query", "api_key", "user:", "://", "?"} {
		if strings.Contains(string(payload), unsafe) {
			t.Fatalf("validation result leaked unsafe input %q: %s", unsafe, payload)
		}
	}
}
