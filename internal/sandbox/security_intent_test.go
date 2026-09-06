package sandbox

import (
	"reflect"
	"testing"
)

func TestMapSandboxSecurityIntentDefaultsToLegacyCompatibilityRequest(t *testing.T) {
	got := MapSandboxSecurityIntent(SandboxSecurityIntent{
		CompatibilityAuthSync: true,
	})

	if got.RuntimeDriver != SandboxRuntimeDriverSSHMachine {
		t.Fatalf("RuntimeDriver = %q, want %q", got.RuntimeDriver, SandboxRuntimeDriverSSHMachine)
	}
	if got.RequestedNetworkPolicy != SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("RequestedNetworkPolicy = %q, want %q", got.RequestedNetworkPolicy, SandboxNetworkPolicyDenyByDefault)
	}
	if got.RequestedNetworkPolicyIntent != nil {
		t.Fatalf("RequestedNetworkPolicyIntent = %#v, want nil for absent config", got.RequestedNetworkPolicyIntent)
	}
	if got.NetworkPolicyCapability != nil {
		t.Fatalf("NetworkPolicyCapability = %#v, want nil for absent config", got.NetworkPolicyCapability)
	}
	if !reflect.DeepEqual(got.RequestedSecretModes, []string{SandboxSecretModeHTTPProxy}) {
		t.Fatalf("RequestedSecretModes = %#v, want legacy http_proxy", got.RequestedSecretModes)
	}
	if len(got.ActiveSecretModes) != 0 {
		t.Fatalf("ActiveSecretModes = %#v, want no configured active modes", got.ActiveSecretModes)
	}
	if !got.CompatibilityAuthSync {
		t.Fatalf("CompatibilityAuthSync = false, want caller-provided compatibility sync preserved")
	}
}

func TestMapSandboxSecurityIntentPreservesExplicitPolicyAndSecretModes(t *testing.T) {
	policy := SandboxNetworkPolicyIntent{
		Preset: SandboxNetworkPolicyPresetAllowListed,
		Rules: []SandboxNetworkPolicyRule{
			{Kind: SandboxNetworkPolicyRuleKindDomain, Value: "api.example.com", Decision: SandboxNetworkPolicyDecisionAllow},
		},
	}
	capability := SandboxNetworkPolicyEnforcementCapability{
		Supported:                  true,
		Modes:                      []string{SandboxNetworkEnforcementModeRuntime},
		SupportsDomainRules:        true,
		SupportsDefaultDenyPosture: true,
	}
	secrets := &SandboxSecretDeliveryIntent{
		RequestedModes: []string{SandboxSecretModeEnv, SandboxSecretModeSSHAgent},
		ActiveModes:    []string{SandboxSecretModeEnv},
	}

	got := MapSandboxSecurityIntent(SandboxSecurityIntent{
		RuntimeDriver:           SandboxRuntimeDriverRootlessPodman,
		NetworkPolicy:           &policy,
		NetworkPolicyCapability: &capability,
		Secrets:                 secrets,
	})

	if got.RuntimeDriver != SandboxRuntimeDriverRootlessPodman {
		t.Fatalf("RuntimeDriver = %q, want %q", got.RuntimeDriver, SandboxRuntimeDriverRootlessPodman)
	}
	if got.RequestedNetworkPolicy != SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("RequestedNetworkPolicy = %q, want restrictive compatibility label", got.RequestedNetworkPolicy)
	}
	if got.RequestedNetworkPolicyIntent == nil {
		t.Fatal("RequestedNetworkPolicyIntent = nil, want explicit policy intent")
	}
	if !reflect.DeepEqual(*got.RequestedNetworkPolicyIntent, policy) {
		t.Fatalf("RequestedNetworkPolicyIntent = %#v, want %#v", *got.RequestedNetworkPolicyIntent, policy)
	}
	if got.NetworkPolicyCapability == nil {
		t.Fatal("NetworkPolicyCapability = nil, want explicit capability metadata")
	}
	if !reflect.DeepEqual(*got.NetworkPolicyCapability, capability) {
		t.Fatalf("NetworkPolicyCapability = %#v, want %#v", *got.NetworkPolicyCapability, capability)
	}
	if !reflect.DeepEqual(got.RequestedSecretModes, secrets.RequestedModes) {
		t.Fatalf("RequestedSecretModes = %#v, want %#v", got.RequestedSecretModes, secrets.RequestedModes)
	}
	if !reflect.DeepEqual(got.ActiveSecretModes, secrets.ActiveModes) {
		t.Fatalf("ActiveSecretModes = %#v, want %#v", got.ActiveSecretModes, secrets.ActiveModes)
	}

	got.RequestedNetworkPolicyIntent.Rules[0].Value = "mutated.example.com"
	got.NetworkPolicyCapability.Modes[0] = SandboxNetworkEnforcementModeFirewall
	got.RequestedSecretModes[0] = SandboxSecretModeFileTmpfs
	got.ActiveSecretModes[0] = SandboxSecretModeFileTmpfs
	if policy.Rules[0].Value != "api.example.com" {
		t.Fatalf("mapper aliased network policy rules: %#v", policy.Rules)
	}
	if capability.Modes[0] != SandboxNetworkEnforcementModeRuntime {
		t.Fatalf("mapper aliased capability modes: %#v", capability.Modes)
	}
	if secrets.RequestedModes[0] != SandboxSecretModeEnv {
		t.Fatalf("mapper aliased requested secret modes: %#v", secrets.RequestedModes)
	}
	if secrets.ActiveModes[0] != SandboxSecretModeEnv {
		t.Fatalf("mapper aliased active secret modes: %#v", secrets.ActiveModes)
	}
}

func TestMapSandboxSecurityIntentDistinguishesAbsentAndExplicitEmptySecrets(t *testing.T) {
	absent := MapSandboxSecurityIntent(SandboxSecurityIntent{})
	if !reflect.DeepEqual(absent.RequestedSecretModes, []string{SandboxSecretModeHTTPProxy}) {
		t.Fatalf("absent RequestedSecretModes = %#v, want legacy http_proxy", absent.RequestedSecretModes)
	}

	explicitEmpty := MapSandboxSecurityIntent(SandboxSecurityIntent{
		Secrets: &SandboxSecretDeliveryIntent{},
	})
	if len(explicitEmpty.RequestedSecretModes) != 0 {
		t.Fatalf("explicit empty RequestedSecretModes = %#v, want none", explicitEmpty.RequestedSecretModes)
	}
	if len(explicitEmpty.ActiveSecretModes) != 0 {
		t.Fatalf("explicit empty ActiveSecretModes = %#v, want none", explicitEmpty.ActiveSecretModes)
	}
	if explicitEmpty.RequestedNetworkPolicy != SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("explicit empty RequestedNetworkPolicy = %q, want absent network policy default", explicitEmpty.RequestedNetworkPolicy)
	}
}
