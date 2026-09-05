package sandbox

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestEffectiveNetworkPolicy(t *testing.T) {
	requested := SandboxNetworkPolicyIntent{
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
				Decision: SandboxNetworkPolicyDecisionAllow,
			},
			{
				Kind:     SandboxNetworkPolicyRuleKindMetadataEndpoint,
				Value:    "169.254.169.254",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
		},
	}
	capability := SandboxNetworkPolicyEnforcementCapability{
		Supported:                  true,
		Modes:                      []string{SandboxNetworkEnforcementModeNone, SandboxNetworkEnforcementModeRuntime},
		SupportsDomainRules:        true,
		SupportsEndpointRules:      true,
		SupportsMetadataEndpoint:   true,
		SupportsDefaultDenyPosture: true,
	}

	got := EvaluateSandboxNetworkPolicy(requested, capability)
	if !reflect.DeepEqual(got.Requested, requested) {
		t.Fatalf("requested policy = %#v, want %#v", got.Requested, requested)
	}
	if !reflect.DeepEqual(got.Effective, requested) {
		t.Fatalf("effective policy = %#v, want requested policy", got.Effective)
	}
	if got.EnforcementMode != SandboxNetworkEnforcementModeRuntime {
		t.Fatalf("enforcement mode = %q, want %q", got.EnforcementMode, SandboxNetworkEnforcementModeRuntime)
	}
	if !reflect.DeepEqual(got.Capability, capability) {
		t.Fatalf("capability = %#v, want %#v", got.Capability, capability)
	}
	if len(got.Warnings) != 0 {
		t.Fatalf("warnings = %#v, want none", got.Warnings)
	}

	got.Requested.Rules[0].Value = "changed.example.com"
	if requested.Rules[0].Value != "api.example.com" {
		t.Fatalf("evaluator result aliased requested rules")
	}
}

func TestEffectiveNetworkPolicyWarnings(t *testing.T) {
	t.Run("unsupported enforcement downgrades with sanitized warning metadata", func(t *testing.T) {
		requested := SandboxNetworkPolicyIntent{
			Preset: SandboxNetworkPolicyPresetAllowListed,
			Rules: []SandboxNetworkPolicyRule{
				{
					Kind:     SandboxNetworkPolicyRuleKindDomain,
					Value:    "https://user:super-secret-token@example.com/path?api_key=secret-query",
					Decision: SandboxNetworkPolicyDecisionAllow,
				},
			},
		}
		got := EvaluateSandboxNetworkPolicy(requested, SandboxNetworkPolicyEnforcementCapability{
			Supported: false,
			Modes:     []string{SandboxNetworkEnforcementModeNone},
		})

		if got.Effective.Preset != SandboxNetworkPolicyPresetLegacyDefault {
			t.Fatalf("effective preset = %q, want %q", got.Effective.Preset, SandboxNetworkPolicyPresetLegacyDefault)
		}
		if len(got.Effective.Rules) != 0 {
			t.Fatalf("effective rules = %#v, want none after unsupported downgrade", got.Effective.Rules)
		}
		if got.EnforcementMode != SandboxNetworkEnforcementModeNone {
			t.Fatalf("enforcement mode = %q, want %q", got.EnforcementMode, SandboxNetworkEnforcementModeNone)
		}
		assertNetworkPolicyWarning(t, got.Warnings, SandboxNetworkPolicyWarningUnsupportedEnforcement, SandboxNetworkPolicyWarningReasonEnforcementUnsupported, string(SandboxNetworkPolicyPresetAllowListed))
		assertNetworkPolicyWarningsSafe(t, got.Warnings)
	})

	t.Run("unsupported rule kinds are omitted without leaking raw values", func(t *testing.T) {
		requested := SandboxNetworkPolicyIntent{
			Preset: SandboxNetworkPolicyPresetAllowListed,
			Rules: []SandboxNetworkPolicyRule{
				{
					Kind:     SandboxNetworkPolicyRuleKindDomain,
					Value:    "api.example.com",
					Decision: SandboxNetworkPolicyDecisionAllow,
				},
				{
					Kind:     SandboxNetworkPolicyRuleKindEndpoint,
					Value:    "https://user:super-secret-token@example.com:443/path?api_key=secret-query",
					Decision: SandboxNetworkPolicyDecisionAllow,
				},
			},
		}
		got := EvaluateSandboxNetworkPolicy(requested, SandboxNetworkPolicyEnforcementCapability{
			Supported:                  true,
			Modes:                      []string{SandboxNetworkEnforcementModeRuntime},
			SupportsDomainRules:        true,
			SupportsEndpointRules:      false,
			SupportsDefaultDenyPosture: true,
		})

		if got.Effective.Preset != SandboxNetworkPolicyPresetAllowListed {
			t.Fatalf("effective preset = %q, want %q", got.Effective.Preset, SandboxNetworkPolicyPresetAllowListed)
		}
		if len(got.Effective.Rules) != 1 || got.Effective.Rules[0].Kind != SandboxNetworkPolicyRuleKindDomain {
			t.Fatalf("effective rules = %#v, want only supported domain rule", got.Effective.Rules)
		}
		assertNetworkPolicyWarning(t, got.Warnings, SandboxNetworkPolicyWarningUnsupportedEnforcement, SandboxNetworkPolicyWarningReasonRuleKindUnsupported, "rule:endpoint")
		assertNetworkPolicyWarningsSafe(t, got.Warnings)
	})
}

func TestCloneSandboxNetworkPolicyResultOmitsRuleValues(t *testing.T) {
	requested := SandboxNetworkPolicyIntent{
		Preset: SandboxNetworkPolicyPresetAllowListed,
		Rules: []SandboxNetworkPolicyRule{
			{
				Kind:     SandboxNetworkPolicyRuleKindDomain,
				Value:    "api.example.com",
				Decision: SandboxNetworkPolicyDecisionAllow,
			},
			{
				Kind:     SandboxNetworkPolicyRuleKindMetadataEndpoint,
				Value:    "169.254.169.254",
				Decision: SandboxNetworkPolicyDecisionDeny,
			},
		},
	}
	result := EvaluateSandboxNetworkPolicy(requested, SandboxNetworkPolicyEnforcementCapability{
		Supported:                  true,
		Modes:                      []string{SandboxNetworkEnforcementModeRuntime},
		SupportsDomainRules:        true,
		SupportsMetadataEndpoint:   true,
		SupportsDefaultDenyPosture: true,
	})

	cloned := CloneSandboxNetworkPolicyResult(result)
	if len(cloned.Requested.Rules) != len(requested.Rules) {
		t.Fatalf("requested rule count = %d, want %d", len(cloned.Requested.Rules), len(requested.Rules))
	}
	if len(cloned.Effective.Rules) != len(requested.Rules) {
		t.Fatalf("effective rule count = %d, want %d", len(cloned.Effective.Rules), len(requested.Rules))
	}
	for _, rule := range append(cloned.Requested.Rules, cloned.Effective.Rules...) {
		if rule.Value != "" {
			t.Fatalf("durable policy rule value = %q, want omitted", rule.Value)
		}
	}
	if result.Requested.Rules[0].Value != "api.example.com" || result.Effective.Rules[1].Value != "169.254.169.254" {
		t.Fatalf("clone mutated source result: %#v", result)
	}

	payload, err := json.Marshal(cloned)
	if err != nil {
		t.Fatalf("marshal cloned result: %v", err)
	}
	for _, forbidden := range []string{"api.example.com", "169.254.169.254", "secret", "token", "://"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("durable policy result leaked %q: %s", forbidden, payload)
		}
	}
}

func TestEffectiveNetworkPolicyNoRealNetworking(t *testing.T) {
	const filename = "network_policy_evaluator.go"

	src, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read %s: %v", filename, err)
	}
	parsed, err := parser.ParseFile(token.NewFileSet(), filename, src, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse %s: %v", filename, err)
	}

	forbiddenImports := map[string]bool{
		"net":                    true,
		"net/http":               true,
		"net/url":                true,
		"os/exec":                true,
		"github.com/spf13/cobra": true,
	}
	for _, imp := range parsed.Imports {
		path := strings.Trim(imp.Path.Value, `"`)
		if forbiddenImports[path] ||
			strings.Contains(path, "/cmd") ||
			strings.Contains(path, "sandboxruntime") ||
			strings.Contains(path, "sandboxworker") ||
			strings.Contains(path, "provider") ||
			strings.Contains(path, "docker") ||
			strings.Contains(path, "podman") {
			t.Fatalf("%s imports %q, evaluator must remain data-only", filename, path)
		}
	}

	for _, forbidden := range []string{
		"Dial(",
		"Listen(",
		"Lookup",
		"http.",
		"iptables",
		"firewall-cmd",
		"docker",
		"podman",
		"NewClientDriver",
	} {
		if strings.Contains(string(src), forbidden) {
			t.Fatalf("%s contains forbidden networking/runtime operation marker %q", filename, forbidden)
		}
	}
}

func assertNetworkPolicyWarning(t *testing.T, warnings []SandboxNetworkPolicyWarning, code SandboxNetworkPolicyWarningCode, reason SandboxNetworkPolicyWarningReason, policy string) {
	t.Helper()

	for _, warning := range warnings {
		if warning.Code == code && warning.Reason == reason && warning.Policy == policy && warning.Message != "" {
			return
		}
	}
	t.Fatalf("warnings = %#v, want code %q reason %q policy %q with a message", warnings, code, reason, policy)
}

func assertNetworkPolicyWarningsSafe(t *testing.T, warnings []SandboxNetworkPolicyWarning) {
	t.Helper()

	payload, err := json.Marshal(warnings)
	if err != nil {
		t.Fatalf("marshal warnings: %v", err)
	}
	for _, unsafe := range []string{"super-secret-token", "secret-query", "api_key", "user:", "://", "example.com:443"} {
		if strings.Contains(string(payload), unsafe) {
			t.Fatalf("warning metadata leaked unsafe input %q: %s", unsafe, payload)
		}
	}
}
