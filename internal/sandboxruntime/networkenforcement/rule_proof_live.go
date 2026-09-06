//go:build network_enforcement_live

package networkenforcement

// RuleProofLiveBuildTagEnabled reports whether this build can construct live
// rule proof adapters from injected live runners.
func RuleProofLiveBuildTagEnabled() bool {
	return true
}

// NewLiveFirewallRuleProofAdapter constructs the live-tag firewall rule proof
// seam. Live mutation still requires explicit gate metadata and an injected
// runner.
func NewLiveFirewallRuleProofAdapter(input RuleProofLiveAdapterInput) RuleLifecycleAdapter {
	input.Gate.BuildTagEnabled = true
	return NewGatedFirewallRuleProofAdapter(input)
}

// NewLiveRuntimeRuleProofAdapter constructs the live-tag runtime rule proof
// seam. Live mutation still requires explicit gate metadata and an injected
// runner.
func NewLiveRuntimeRuleProofAdapter(input RuleProofLiveAdapterInput) RuleLifecycleAdapter {
	input.Gate.BuildTagEnabled = true
	return NewGatedRuntimeRuleProofAdapter(input)
}
