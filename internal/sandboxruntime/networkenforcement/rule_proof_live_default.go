//go:build !network_enforcement_live

package networkenforcement

// RuleProofLiveBuildTagEnabled reports whether this build can construct live
// rule proof adapters. Default builds always return false.
func RuleProofLiveBuildTagEnabled() bool {
	return false
}

// NewLiveFirewallRuleProofAdapter is the default-build firewall live seam. It
// always returns a disabled adapter even when caller-supplied gate metadata is
// otherwise complete.
func NewLiveFirewallRuleProofAdapter(input RuleProofLiveAdapterInput) RuleLifecycleAdapter {
	input.Gate.BuildTagEnabled = false
	return NewGatedFirewallRuleProofAdapter(input)
}

// NewLiveRuntimeRuleProofAdapter is the default-build runtime live seam. It
// always returns a disabled adapter even when caller-supplied gate metadata is
// otherwise complete.
func NewLiveRuntimeRuleProofAdapter(input RuleProofLiveAdapterInput) RuleLifecycleAdapter {
	input.Gate.BuildTagEnabled = false
	return NewGatedRuntimeRuleProofAdapter(input)
}
