//go:build network_enforcement_live

package microvm

import (
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement"
)

func TestLiveNetworkEnforcementPlanningLiveBuildRequiresEnvGatesBeforeInvokingAdapters(t *testing.T) {
	for _, tt := range []struct {
		name      string
		gate      networkenforcement.RuleProofLiveGateInput
		wantCalls bool
	}{
		{
			name: "missing network env",
			gate: networkenforcement.RuleProofLiveGateInput{FirewallEnabled: true},
		},
		{
			name: "missing firewall env",
			gate: networkenforcement.RuleProofLiveGateInput{NetworkEnabled: true},
		},
		{
			name:      "all env gates",
			gate:      networkenforcement.RuleProofLiveGateInput{NetworkEnabled: true, FirewallEnabled: true},
			wantCalls: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			listener := &recordingMicroVMLiveProxyListener{}
			rules := &recordingMicroVMLiveRuleProof{mechanism: networkenforcement.EnforcementMechanismFirewall}
			driver := NewDriver(DriverOptions{
				CapabilityDetector: fixedCapabilityDetector(availableCapabilityReport()),
				NetworkEnforcement: NewLiveNetworkEnforcementPlanning(NetworkEnforcementLiveOptions{
					Request:       microVMNetworkEnforcementTestPlanRequest(),
					ProxyListener: listener,
					RuleRunner:    rules,
					RuleGate:      tt.gate,
				}),
			})

			metadata := driver.Metadata().NetworkEnforcement
			if tt.wantCalls {
				assertMicroVMLiveProxyListenerCalls(t, listener.calls, []string{"prepare_proxy", "start_proxy", "active_proxy"})
				assertMicroVMLiveRuleProofCalls(t, rules.calls, []string{"plan_rules", "apply_rules", "active_rules"})
				if metadata == nil || metadata.Result == nil || metadata.Result.EnforcementMode != string(networkenforcement.ResultModeProxyFirewall) {
					t.Fatalf("NetworkEnforcement = %#v, want proxy_firewall through live build and env gates", metadata)
				}
				return
			}
			if len(listener.calls) != 0 || len(rules.calls) != 0 {
				t.Fatalf("live calls = proxy:%#v rules:%#v, want none with incomplete env gate", listener.calls, rules.calls)
			}
			assertMicroVMNetworkEnforcementNotStrictReady(t, metadata)
		})
	}
}
