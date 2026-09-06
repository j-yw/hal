package sandbox

import "strings"

// SandboxSecretDeliveryIntent carries sandbox-native secret delivery metadata.
// A nil *SandboxSecretDeliveryIntent means legacy defaults should apply; a
// non-nil value with empty slices means no configured secret modes were set.
type SandboxSecretDeliveryIntent struct {
	RequestedModes []string
	ActiveModes    []string
}

// SandboxSecurityIntent captures optional sandbox security config in the pure
// sandbox package before it is mapped into evaluator input.
type SandboxSecurityIntent struct {
	RuntimeDriver           string
	NetworkPolicy           *SandboxNetworkPolicyIntent
	NetworkPolicyCapability *SandboxNetworkPolicyEnforcementCapability
	Secrets                 *SandboxSecretDeliveryIntent
	CompatibilityAuthSync   bool
}

// MapSandboxSecurityIntent adapts sandbox-native optional policy and secret
// metadata into the evaluator request used by runtime compatibility metadata.
func MapSandboxSecurityIntent(intent SandboxSecurityIntent) SecurityEvaluationRequest {
	req := SecurityEvaluationRequest{
		RuntimeDriver:          defaultSandboxSecurityIntentRuntimeDriver(intent.RuntimeDriver),
		RequestedNetworkPolicy: SandboxNetworkPolicyDenyByDefault,
		RequestedSecretModes:   []string{SandboxSecretModeHTTPProxy},
		CompatibilityAuthSync:  intent.CompatibilityAuthSync,
	}

	if intent.NetworkPolicy != nil {
		networkPolicy := CloneSandboxNetworkPolicyIntent(*intent.NetworkPolicy)
		req.RequestedNetworkPolicy = compatibilityNetworkPolicyLabelForIntent(networkPolicy)
		req.RequestedNetworkPolicyIntent = &networkPolicy
	}
	if intent.NetworkPolicyCapability != nil {
		capability := CloneSandboxNetworkPolicyEnforcementCapability(*intent.NetworkPolicyCapability)
		req.NetworkPolicyCapability = &capability
	}
	if intent.Secrets != nil {
		req.RequestedSecretModes = cloneStringSlice(intent.Secrets.RequestedModes)
		req.ActiveSecretModes = cloneStringSlice(intent.Secrets.ActiveModes)
	}

	return req
}

func defaultSandboxSecurityIntentRuntimeDriver(runtimeDriver string) string {
	if driver := strings.TrimSpace(runtimeDriver); driver != "" {
		return driver
	}
	return SandboxRuntimeDriverSSHMachine
}

func compatibilityNetworkPolicyLabelForIntent(intent SandboxNetworkPolicyIntent) string {
	switch intent.Preset {
	case SandboxNetworkPolicyPresetDisabled,
		SandboxNetworkPolicyPresetNoPolicy,
		SandboxNetworkPolicyPresetLegacyDefault:
		return SandboxNetworkPolicyBestEffort
	default:
		return SandboxNetworkPolicyDenyByDefault
	}
}

func cloneStringSlice(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return append([]string(nil), in...)
}
