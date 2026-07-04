package sandboxruntime

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestUS002RuntimeNetworkEnforcementProofProjectionRequiresActiveDualEvidence(t *testing.T) {
	tests := []struct {
		name      string
		configure func(*RuntimeNetworkEnforcementMetadata)
		wantReady bool
		wantProxy bool
		wantRule  bool
		wantWarn  bool
	}{
		{
			name:      "active proxy firewall proof",
			wantReady: true,
			wantProxy: true,
			wantRule:  true,
		},
		{
			name: "proxy only proof",
			configure: func(metadata *RuntimeNetworkEnforcementMetadata) {
				metadata.Orchestration.Rules = nil
				metadata.Result.EnforcementMode = "proxy"
				metadata.Result.Mechanisms = []string{"proxy"}
			},
			wantProxy: true,
		},
		{
			name: "firewall rule only proof",
			configure: func(metadata *RuntimeNetworkEnforcementMetadata) {
				metadata.Orchestration.Proxy = nil
				metadata.Result.EnforcementMode = "firewall"
				metadata.Result.Mechanisms = []string{"firewall"}
			},
			wantRule: true,
		},
		{
			name: "best effort proof",
			configure: func(metadata *RuntimeNetworkEnforcementMetadata) {
				metadata.Result.Outcome = "best_effort"
				metadata.Result.EnforcementMode = "best_effort"
			},
			wantProxy: true,
			wantRule:  true,
		},
		{
			name: "failed proof",
			configure: func(metadata *RuntimeNetworkEnforcementMetadata) {
				metadata.Orchestration.Status = "failed"
				metadata.Result.Outcome = "failure"
				metadata.Result.ReasonCode = "adapter_failed"
			},
			wantProxy: true,
			wantRule:  true,
		},
		{
			name: "unsupported proof",
			configure: func(metadata *RuntimeNetworkEnforcementMetadata) {
				metadata.Result.Outcome = "unsupported"
				metadata.Result.ReasonCode = "adapter_unsupported"
				metadata.Result.Capability.Supported = false
			},
			wantProxy: true,
			wantRule:  true,
		},
		{
			name: "warning bearing proof",
			configure: func(metadata *RuntimeNetworkEnforcementMetadata) {
				metadata.Result.WarningCodes = []string{"partial_enforcement"}
				metadata.Orchestration.Proxy.WarningCodes = []string{"partial_lifecycle"}
			},
			wantProxy: true,
			wantRule:  true,
			wantWarn:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := us002RuntimeNetworkEnforcementProofFixture()
			if tt.configure != nil {
				tt.configure(metadata)
			}
			proof := ProjectRuntimeNetworkEnforcementProofMetadata(metadata)

			if got := RuntimeNetworkEnforcementProofHasActiveProxy(proof); got != tt.wantProxy {
				t.Fatalf("RuntimeNetworkEnforcementProofHasActiveProxy() = %t, want %t: %#v", got, tt.wantProxy, proof)
			}
			if got := RuntimeNetworkEnforcementProofHasActiveFirewallOrRuntimeRule(proof); got != tt.wantRule {
				t.Fatalf("RuntimeNetworkEnforcementProofHasActiveFirewallOrRuntimeRule() = %t, want %t: %#v", got, tt.wantRule, proof)
			}
			if got := RuntimeNetworkEnforcementProofHasWarnings(proof); got != tt.wantWarn {
				t.Fatalf("RuntimeNetworkEnforcementProofHasWarnings() = %t, want %t: %#v", got, tt.wantWarn, proof)
			}
			if got := RuntimeNetworkEnforcementProofProvesActiveProxyFirewall(proof); got != tt.wantReady {
				t.Fatalf("RuntimeNetworkEnforcementProofProvesActiveProxyFirewall() = %t, want %t: %#v", got, tt.wantReady, proof)
			}

			encoded, err := json.Marshal(proof)
			if err != nil {
				t.Fatalf("Marshal(proof) error = %v", err)
			}
			for _, unsafe := range []string{
				"127.0.0.1",
				"/tmp",
				".sock",
				"iptables",
				"provider",
				"firecracker",
				"Authorization",
				"Bearer",
				"token",
				"secret",
			} {
				if strings.Contains(string(encoded), unsafe) {
					t.Fatalf("runtime proof leaked unsafe fragment %q in %s", unsafe, encoded)
				}
			}
		})
	}
}

func us002RuntimeNetworkEnforcementProofFixture() *RuntimeNetworkEnforcementMetadata {
	return &RuntimeNetworkEnforcementMetadata{
		Plan: &RuntimeNetworkEnforcementPlanMetadata{
			ID:               "network-plan-us002",
			Source:           "microvm",
			Operation:        "prepare_network",
			PolicySnapshotID: "policy-snapshot-us002",
			PolicyPreset:     "deny_by_default",
			DefaultPosture:   "deny_by_default",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"default_deny", "iptables -A OUTPUT -d 127.0.0.1 --dport 443", "/tmp/firewall.sock"},
		},
		Orchestration: &RuntimeNetworkEnforcementOrchestrationMetadata{
			PlanID:           "network-plan-us002",
			AdapterID:        "network-adapter-us002",
			Status:           "active",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"start_proxy", "apply_rules"},
			PolicySnapshotID: "policy-snapshot-us002",
			PolicyPreset:     "deny_by_default",
			Proxy: &RuntimeNetworkEnforcementLifecycleMetadata{
				ID:               "network-proxy-us002",
				PlanID:           "network-plan-us002",
				AdapterID:        "network-adapter-us002",
				Status:           "active",
				Mechanisms:       []string{"proxy"},
				Operations:       []string{"active_proxy", "listen 127.0.0.1:8080", "/tmp/proxy.sock"},
				PolicySnapshotID: "policy-snapshot-us002",
				PolicyPreset:     "deny_by_default",
				CapabilityLabels: []string{"proxy_active", "provider=firecracker"},
				ReasonCode:       "active",
			},
			Rules: []RuntimeNetworkEnforcementLifecycleMetadata{{
				ID:               "network-rules-us002",
				PlanID:           "network-plan-us002",
				AdapterID:        "network-adapter-us002",
				Status:           "active",
				Mechanisms:       []string{"firewall"},
				Operations:       []string{"apply_rules", "iptables -A OUTPUT -d 127.0.0.1 --dport 443 token=secret"},
				PolicySnapshotID: "policy-snapshot-us002",
				PolicyPreset:     "deny_by_default",
				CapabilityLabels: []string{"default_deny", "provider=firecracker"},
				ReasonCode:       "active",
			}},
			CapabilityLabels: []string{"proxy_active", "rules_active", "provider=firecracker"},
			ReasonCode:       "active",
		},
		Result: &RuntimeNetworkEnforcementResultMetadata{
			PlanID:           "network-plan-us002",
			AdapterID:        "network-adapter-us002",
			Outcome:          "success",
			EnforcementMode:  "proxy_firewall",
			Mechanisms:       []string{"proxy", "firewall"},
			Operations:       []string{"proxy_route", "firewall_apply", "Authorization: Bearer secret"},
			PolicySnapshotID: "policy-snapshot-us002",
			PolicyPreset:     "deny_by_default",
			Capability: &RuntimeNetworkEnforcementCapability{
				Supported:                  true,
				Modes:                      []string{"proxy_firewall"},
				SupportsDomainRules:        true,
				SupportsEndpointRules:      true,
				SupportsPrivateRangeRules:  true,
				SupportsMetadataEndpoint:   true,
				SupportsDefaultDenyPosture: true,
			},
			ReasonCode: "applied",
		},
	}
}
