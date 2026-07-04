//go:build !network_enforcement_live

package microvm

import (
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestLiveNetworkEnforcementPlanningDefaultBuildIgnoresEnvGatesAndDoesNotInvokeAdapters(t *testing.T) {
	listener := &recordingMicroVMLiveProxyListener{}
	rules := &recordingMicroVMLiveRuleProof{mechanism: networkenforcement.EnforcementMechanismFirewall}
	driver := NewDriver(DriverOptions{
		CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
		NetworkEnforcement: NewLiveNetworkEnforcementPlanning(NetworkEnforcementLiveOptions{
			Request:       microVMNetworkEnforcementTestPlanRequest(),
			ProxyListener: listener,
			RuleRunner:    rules,
			RuleGate: networkenforcement.RuleProofLiveGateInput{
				NetworkEnabled:  true,
				FirewallEnabled: true,
			},
		}),
	})

	if len(listener.calls) != 0 || len(rules.calls) != 0 {
		t.Fatalf("default build live calls = proxy:%#v rules:%#v, want none without network_enforcement_live build tag", listener.calls, rules.calls)
	}
	metadata := driver.Metadata().NetworkEnforcement
	assertMicroVMNetworkEnforcementNotStrictReady(t, metadata)
	if metadata == nil || metadata.Result == nil ||
		metadata.Result.Outcome != string(networkenforcement.ResultOutcomeUnsupported) ||
		metadata.Result.EnforcementMode != string(networkenforcement.ResultModeNone) {
		t.Fatalf("NetworkEnforcement = %#v, want unsupported metadata in default build", metadata)
	}
}
