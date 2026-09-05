package sandbox

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSandboxSecurityCompatibility(t *testing.T) {
	got := EvaluateSSHMachineCompatibilitySecurity(SecurityEvaluationRequest{
		RuntimeDriver:          SandboxRuntimeDriverSSHMachine,
		RequestedNetworkPolicy: SandboxNetworkPolicyDenyByDefault,
	})
	if got == nil || got.Network == nil {
		t.Fatalf("security network = %#v, want populated metadata", got)
	}
	if got.Network.PolicyRequested != SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policyRequested = %q, want %q", got.Network.PolicyRequested, SandboxNetworkPolicyDenyByDefault)
	}
	if got.Network.PolicyEnforced != SandboxNetworkPolicyBestEffort {
		t.Fatalf("policyEnforced = %q, want %q", got.Network.PolicyEnforced, SandboxNetworkPolicyBestEffort)
	}
	if got.Network.EnforcementMode != SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforcementMode = %q, want %q", got.Network.EnforcementMode, SandboxNetworkEnforcementModeNone)
	}
	result := got.Network.PolicyResult
	if result == nil {
		t.Fatal("policyResult = nil, want effective policy metadata")
	}
	if result.Requested.Preset != SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("policyResult.requested.preset = %q, want %q", result.Requested.Preset, SandboxNetworkPolicyPresetDenyByDefault)
	}
	if result.Effective.Preset != SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("policyResult.effective.preset = %q, want %q", result.Effective.Preset, SandboxNetworkPolicyPresetLegacyDefault)
	}
	if result.EnforcementMode != SandboxNetworkEnforcementModeNone {
		t.Fatalf("policyResult.enforcementMode = %q, want %q", result.EnforcementMode, SandboxNetworkEnforcementModeNone)
	}
	if result.Capability.Supported {
		t.Fatalf("policyResult.capability.supported = true, compatibility path must not imply enforcement")
	}
	assertSandboxNetworkPolicyWarningsSafe(t, result.Warnings)
}

func TestEffectiveNetworkPolicyCompatibility(t *testing.T) {
	rootless := EvaluateSandboxSecurity(SecurityEvaluationRequest{
		RuntimeDriver:          SandboxRuntimeDriverRootlessPodman,
		RequestedNetworkPolicy: SandboxNetworkPolicyDenyByDefault,
	})
	if rootless == nil || rootless.Network == nil || rootless.Network.PolicyResult == nil {
		t.Fatalf("rootless security = %#v, want network policy metadata", rootless)
	}
	if rootless.Network.PolicyEnforced == SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("rootless policyEnforced = %q, want compatibility downgrade without explicit capability", rootless.Network.PolicyEnforced)
	}
	if rootless.Network.EnforcementMode != SandboxNetworkEnforcementModeNone {
		t.Fatalf("rootless enforcementMode = %q, want %q without explicit capability", rootless.Network.EnforcementMode, SandboxNetworkEnforcementModeNone)
	}
	if rootless.Network.PolicyResult.Effective.Preset != SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("rootless effective preset = %q, want %q", rootless.Network.PolicyResult.Effective.Preset, SandboxNetworkPolicyPresetLegacyDefault)
	}

	explicit := EvaluateSandboxSecurity(SecurityEvaluationRequest{
		RuntimeDriver:          SandboxRuntimeDriverRootlessPodman,
		RequestedNetworkPolicy: SandboxNetworkPolicyDenyByDefault,
		NetworkPolicyCapability: &SandboxNetworkPolicyEnforcementCapability{
			Supported:                  true,
			Modes:                      []string{SandboxNetworkEnforcementModeFirewall},
			SupportsDefaultDenyPosture: true,
		},
	})
	if explicit == nil || explicit.Network == nil || explicit.Network.PolicyResult == nil {
		t.Fatalf("explicit rootless security = %#v, want network policy metadata", explicit)
	}
	if explicit.Network.PolicyEnforced != SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("explicit rootless policyEnforced = %q, want %q", explicit.Network.PolicyEnforced, SandboxNetworkPolicyDenyByDefault)
	}
	if explicit.Network.EnforcementMode != SandboxNetworkEnforcementModeFirewall {
		t.Fatalf("explicit rootless enforcementMode = %q, want %q", explicit.Network.EnforcementMode, SandboxNetworkEnforcementModeFirewall)
	}
	if explicit.Network.PolicyResult.Effective.Preset != SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("explicit rootless effective preset = %q, want %q", explicit.Network.PolicyResult.Effective.Preset, SandboxNetworkPolicyPresetDenyByDefault)
	}
}

func TestEvaluateSSHMachineCompatibilitySecurityUsesRequestedNetworkPolicyIntent(t *testing.T) {
	requested := SandboxNetworkPolicyIntent{
		Preset: SandboxNetworkPolicyPresetDisabled,
	}
	got := EvaluateSSHMachineCompatibilitySecurity(SecurityEvaluationRequest{
		RuntimeDriver:                SandboxRuntimeDriverSSHMachine,
		RequestedNetworkPolicyIntent: &requested,
	})
	if got == nil || got.Network == nil || got.Network.PolicyResult == nil {
		t.Fatalf("security network = %#v, want populated policy result", got)
	}
	if got.Network.PolicyRequested != SandboxNetworkPolicyBestEffort {
		t.Fatalf("policyRequested = %q, want %q derived from disabled intent", got.Network.PolicyRequested, SandboxNetworkPolicyBestEffort)
	}
	if got.Network.PolicyEnforced != SandboxNetworkPolicyBestEffort {
		t.Fatalf("policyEnforced = %q, want %q", got.Network.PolicyEnforced, SandboxNetworkPolicyBestEffort)
	}
	if got.Network.EnforcementMode != SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforcementMode = %q, want %q", got.Network.EnforcementMode, SandboxNetworkEnforcementModeNone)
	}
	if got.Network.PolicyResult.Requested.Preset != SandboxNetworkPolicyPresetDisabled {
		t.Fatalf("policyResult.requested.preset = %q, want %q", got.Network.PolicyResult.Requested.Preset, SandboxNetworkPolicyPresetDisabled)
	}
	if got.Network.PolicyResult.Effective.Preset != SandboxNetworkPolicyPresetDisabled {
		t.Fatalf("policyResult.effective.preset = %q, want %q", got.Network.PolicyResult.Effective.Preset, SandboxNetworkPolicyPresetDisabled)
	}
}

func TestEvaluateSSHMachineCompatibilitySecurityDowngradesUnsupportedStrictIntent(t *testing.T) {
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
	got := EvaluateSSHMachineCompatibilitySecurity(SecurityEvaluationRequest{
		RuntimeDriver:                SandboxRuntimeDriverSSHMachine,
		RequestedNetworkPolicyIntent: &requested,
		NetworkPolicyCapability: &SandboxNetworkPolicyEnforcementCapability{
			Supported: true,
			Modes:     []string{SandboxNetworkEnforcementModeBestEffort},
		},
	})
	if got == nil || got.Network == nil || got.Network.PolicyResult == nil {
		t.Fatalf("security network = %#v, want populated policy result", got)
	}
	if got.Network.PolicyRequested != SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policyRequested = %q, want %q for strict intent", got.Network.PolicyRequested, SandboxNetworkPolicyDenyByDefault)
	}
	if got.Network.PolicyEnforced == SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policyEnforced = %q, unsupported strict intent must not claim deny-by-default enforcement", got.Network.PolicyEnforced)
	}
	if got.Network.EnforcementMode != SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforcementMode = %q, want %q after downgrade", got.Network.EnforcementMode, SandboxNetworkEnforcementModeNone)
	}
	if got.Network.PolicyResult.Effective.Preset != SandboxNetworkPolicyPresetLegacyDefault {
		t.Fatalf("effective preset = %q, want %q", got.Network.PolicyResult.Effective.Preset, SandboxNetworkPolicyPresetLegacyDefault)
	}
	assertNetworkPolicyWarning(t, got.Network.PolicyResult.Warnings, SandboxNetworkPolicyWarningUnsupportedEnforcement, SandboxNetworkPolicyWarningReasonModeUnavailable, string(SandboxNetworkPolicyPresetAllowListed))
	assertSandboxNetworkPolicyWarningsSafe(t, got.Network.PolicyResult.Warnings)
}

func TestEvaluateSSHMachineCompatibilitySecurityDefaultsNetworkHonestly(t *testing.T) {
	got := EvaluateSSHMachineCompatibilitySecurity(SecurityEvaluationRequest{
		RuntimeDriver:         SandboxRuntimeDriverSSHMachine,
		CompatibilityAuthSync: true,
	})
	if got == nil || got.Network == nil {
		t.Fatalf("security network = %#v, want populated metadata", got)
	}
	if got.Network.PolicyRequested != SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policyRequested = %q, want %q", got.Network.PolicyRequested, SandboxNetworkPolicyDenyByDefault)
	}
	if got.Network.PolicyEnforced == SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policyEnforced = %q, compatibility path must not claim deny-by-default enforcement", got.Network.PolicyEnforced)
	}
	if got.Network.PolicyEnforced != SandboxNetworkPolicyBestEffort {
		t.Fatalf("policyEnforced = %q, want %q", got.Network.PolicyEnforced, SandboxNetworkPolicyBestEffort)
	}
	if got.Network.EnforcementMode != SandboxNetworkEnforcementModeNone {
		t.Fatalf("enforcementMode = %q, want %q", got.Network.EnforcementMode, SandboxNetworkEnforcementModeNone)
	}
	if got.Secrets == nil || !reflect.DeepEqual(got.Secrets.ActiveModes, []string{SandboxSecretModeLegacyAuthSync}) {
		t.Fatalf("active secret modes = %#v, want legacy auth sync only", got.Secrets)
	}
}

func TestEvaluateSSHMachineCompatibilitySecuritySeparatesRequestedAndActiveSecretModes(t *testing.T) {
	got := EvaluateSSHMachineCompatibilitySecurity(SecurityEvaluationRequest{
		RuntimeDriver:          SandboxRuntimeDriverSSHMachine,
		RequestedNetworkPolicy: SandboxNetworkPolicyDenyByDefault,
		RequestedSecretModes: []string{
			SandboxSecretModeHTTPProxy,
			SandboxSecretModeHTTPProxy,
			"sk-test-secret-value",
			"",
		},
		ActiveSecretModes: []string{
			SandboxSecretModeEnv,
			"ghp_fake_secret_value",
			SandboxSecretModeEnv,
		},
		CompatibilityAuthSync: true,
	})
	if got.Network.PolicyRequested != SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policyRequested = %q, want deny_by_default", got.Network.PolicyRequested)
	}
	if got.Network.PolicyEnforced == SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("policyEnforced overclaimed compatibility enforcement: %#v", got.Network)
	}
	wantRequested := []string{SandboxSecretModeHTTPProxy}
	if !reflect.DeepEqual(got.Secrets.RequestedModes, wantRequested) {
		t.Fatalf("requested modes = %#v, want %#v", got.Secrets.RequestedModes, wantRequested)
	}
	wantActive := []string{SandboxSecretModeEnv, SandboxSecretModeLegacyAuthSync}
	if !reflect.DeepEqual(got.Secrets.ActiveModes, wantActive) {
		t.Fatalf("active modes = %#v, want %#v", got.Secrets.ActiveModes, wantActive)
	}
	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal security metadata: %v", err)
	}
	for _, unsafe := range []string{"sk-test-secret-value", "ghp_fake_secret_value"} {
		if strings.Contains(string(payload), unsafe) {
			t.Fatalf("security metadata leaked raw secret %q: %s", unsafe, payload)
		}
	}
}

func TestEvaluateSSHMachineCompatibilitySecurityIsDeterministic(t *testing.T) {
	req := SecurityEvaluationRequest{
		RuntimeDriver:          SandboxRuntimeDriverSSHMachine,
		RequestedNetworkPolicy: SandboxNetworkPolicyBestEffort,
		RequestedSecretModes:   []string{SandboxSecretModeHTTPProxy, SandboxSecretModeSSHAgent},
		ActiveSecretModes:      []string{SandboxSecretModeEnv},
		CompatibilityAuthSync:  true,
	}
	first := EvaluateSSHMachineCompatibilitySecurity(req)
	second := EvaluateSSHMachineCompatibilitySecurity(req)
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("security evaluation not deterministic:\nfirst:  %#v\nsecond: %#v", first, second)
	}
}

func assertSandboxNetworkPolicyWarningsSafe(t *testing.T, warnings []SandboxNetworkPolicyWarning) {
	t.Helper()
	payload, err := json.Marshal(warnings)
	if err != nil {
		t.Fatalf("marshal warnings: %v", err)
	}
	for _, unsafe := range []string{"secret", "token", "://", "169.254.169.254", "api.example.com"} {
		if strings.Contains(string(payload), unsafe) {
			t.Fatalf("warnings leaked unsafe content %q in %s", unsafe, payload)
		}
	}
}
