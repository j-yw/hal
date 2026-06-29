package sandbox

import (
	"reflect"
	"testing"
)

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
