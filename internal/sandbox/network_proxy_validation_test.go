package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNetworkProxySessionValidationAndNormalization(t *testing.T) {
	got := ValidateAndNormalizeSandboxNetworkProxySessionMetadata(SandboxNetworkProxySessionMetadata{
		ID:     " proxy-session-01 ",
		Source: SandboxNetworkPolicyDecisionSource(" RUN "),
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-01 ",
			Version:   " v1 ",
			Preset:    SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: " rules-01 ",
		},
		EnforcementMode: " PROXY_FIREWALL ",
	})
	if !got.Valid {
		t.Fatalf("ValidateAndNormalizeSandboxNetworkProxySessionMetadata() valid = false, errors: %#v", got.Errors)
	}
	if got.Normalized == nil {
		t.Fatal("normalized proxy session = nil")
	}
	normalized := *got.Normalized
	if normalized.ID != "proxy-session-01" {
		t.Fatalf("normalized id = %q, want proxy-session-01", normalized.ID)
	}
	if normalized.Source != SandboxNetworkPolicyDecisionSourceRun {
		t.Fatalf("normalized source = %q, want %q", normalized.Source, SandboxNetworkPolicyDecisionSourceRun)
	}
	if normalized.EnforcementMode != SandboxNetworkEnforcementModeProxyFirewall {
		t.Fatalf("normalized enforcement mode = %q, want %q", normalized.EnforcementMode, SandboxNetworkEnforcementModeProxyFirewall)
	}
	if normalized.PolicySnapshot == nil {
		t.Fatal("normalized policy snapshot = nil")
	}
	if normalized.PolicySnapshot.ID != "policy-snapshot-01" {
		t.Fatalf("normalized policy snapshot id = %q, want policy-snapshot-01", normalized.PolicySnapshot.ID)
	}
	if normalized.PolicySnapshot.Version != "v1" {
		t.Fatalf("normalized policy snapshot version = %q, want v1", normalized.PolicySnapshot.Version)
	}
	if normalized.PolicySnapshot.Preset != SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("normalized policy snapshot preset = %q, want %q", normalized.PolicySnapshot.Preset, SandboxNetworkPolicyPresetDenyByDefault)
	}
	if normalized.PolicySnapshot.RuleSetID != "rules-01" {
		t.Fatalf("normalized policy snapshot rule set id = %q, want rules-01", normalized.PolicySnapshot.RuleSetID)
	}
}

func TestNetworkProxySessionValidationRejectsMalformedMetadata(t *testing.T) {
	secretLikeValue := "https://user:proxy-secret@example.invalid/path?token=proxy-secret"
	tests := []struct {
		name  string
		input SandboxNetworkProxySessionMetadata
		code  SandboxNetworkProxyValidationCode
		field string
	}{
		{
			name: "missing session id",
			input: SandboxNetworkProxySessionMetadata{
				ID:     " \t ",
				Source: SandboxNetworkPolicyDecisionSourceRun,
			},
			code:  SandboxNetworkProxyValidationMissingRequiredField,
			field: "id",
		},
		{
			name: "missing source",
			input: SandboxNetworkProxySessionMetadata{
				ID:     "proxy-session-01",
				Source: SandboxNetworkPolicyDecisionSource(" \t "),
			},
			code:  SandboxNetworkProxyValidationMissingRequiredField,
			field: "source",
		},
		{
			name: "invalid source",
			input: SandboxNetworkProxySessionMetadata{
				ID:     "proxy-session-01",
				Source: SandboxNetworkPolicyDecisionSource(secretLikeValue),
			},
			code:  SandboxNetworkProxyValidationInvalidSource,
			field: "source",
		},
		{
			name: "missing policy snapshot id",
			input: SandboxNetworkProxySessionMetadata{
				ID:     "proxy-session-01",
				Source: SandboxNetworkPolicyDecisionSourceAuto,
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
					ID: " \t ",
				},
			},
			code:  SandboxNetworkProxyValidationMissingRequiredField,
			field: "policySnapshot.id",
		},
		{
			name: "invalid policy snapshot preset",
			input: SandboxNetworkProxySessionMetadata{
				ID:     "proxy-session-01",
				Source: SandboxNetworkPolicyDecisionSourceFactory,
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
					ID:     "policy-snapshot-01",
					Preset: SandboxNetworkPolicyPreset(secretLikeValue),
				},
			},
			code:  SandboxNetworkProxyValidationInvalidPolicyPreset,
			field: "policySnapshot.preset",
		},
		{
			name: "invalid enforcement mode",
			input: SandboxNetworkProxySessionMetadata{
				ID:              "proxy-session-01",
				Source:          SandboxNetworkPolicyDecisionSourceWorker,
				EnforcementMode: secretLikeValue,
			},
			code:  SandboxNetworkProxyValidationInvalidEnforcement,
			field: "enforcementMode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateAndNormalizeSandboxNetworkProxySessionMetadata(tt.input)
			if got.Valid {
				t.Fatalf("ValidateAndNormalizeSandboxNetworkProxySessionMetadata() valid = true, want false")
			}
			if got.Normalized != nil {
				t.Fatalf("normalized metadata = %#v, want nil on invalid input", got.Normalized)
			}
			if !hasNetworkProxyValidationError(got, tt.code, tt.field) {
				t.Fatalf("validation errors = %#v, want code %q field %q", got.Errors, tt.code, tt.field)
			}
			assertNetworkProxyValidationNoUnsafeLeak(t, got)
		})
	}
}

func TestNetworkProxySessionValidationDoesNotInferEnforcement(t *testing.T) {
	got := ValidateAndNormalizeSandboxNetworkProxySessionMetadata(SandboxNetworkProxySessionMetadata{
		ID:     "proxy-session-02",
		Source: SandboxNetworkPolicyDecisionSourceAuto,
	})
	if !got.Valid {
		t.Fatalf("ValidateAndNormalizeSandboxNetworkProxySessionMetadata() valid = false, errors: %#v", got.Errors)
	}
	if got.Normalized == nil {
		t.Fatal("normalized proxy session = nil")
	}
	if got.Normalized.EnforcementMode != "" {
		t.Fatalf("normalized enforcement mode = %q, want empty when absent", got.Normalized.EnforcementMode)
	}

	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	for _, forbidden := range []string{"enforcementMode", "capability", "enforced"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("validation result %s must not infer enforcement metadata %q", payload, forbidden)
		}
	}
}

func hasNetworkProxyValidationError(result SandboxNetworkProxyValidationResult, code SandboxNetworkProxyValidationCode, field string) bool {
	for _, err := range result.Errors {
		if err.Code == code && err.Field == field {
			return true
		}
	}
	return false
}

func assertNetworkProxyValidationNoUnsafeLeak(t *testing.T, result SandboxNetworkProxyValidationResult) {
	t.Helper()

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	for _, unsafe := range []string{
		"proxy-secret",
		"user:",
		"token=",
		"example.invalid",
		"://",
		"?",
	} {
		if strings.Contains(string(payload), unsafe) {
			t.Fatalf("validation result leaked unsafe input %q: %s", unsafe, payload)
		}
	}
}
