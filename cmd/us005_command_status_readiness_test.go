package cmd

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestUS005CommandNetworkSecurityDowngradesProxyFirewallWithoutRuntimeProof(t *testing.T) {
	security := us005StrictSandboxSecurity()

	sanitized := sanitizeCommandSandboxSecurity(security)
	if sanitized == nil || sanitized.Network == nil {
		t.Fatalf("sanitizeCommandSandboxSecurity() = %#v, want sanitized network metadata", sanitized)
	}
	us005RequireBestEffortNetworkSecurity(t, "command sanitizer", sanitized.Network, sandbox.SandboxNetworkEnforcementModeNone)

	summary := newSandboxRuntimeSecuritySummary(security)
	us005RequireBestEffortRuntimeSummary(t, "runtime summary", summary, sandbox.SandboxNetworkEnforcementModeNone)

	metadata := factorySandboxSecurityMetadata(security)
	if metadata == nil || metadata.Network == nil {
		t.Fatalf("factorySandboxSecurityMetadata() = %#v, want sanitized network metadata", metadata)
	}
	us005RequireBestEffortFactoryNetwork(t, "factory metadata", metadata.Network, sandbox.SandboxNetworkEnforcementModeNone)
}

func TestUS005SandboxRuntimeStatusJSONRequiresActiveDualNetworkProof(t *testing.T) {
	tests := []struct {
		name               string
		security           sandboxworker.SecurityPolicy
		enforcement        *sandboxruntime.RuntimeNetworkEnforcementMetadata
		wantNetworkPolicy  string
		wantEnforcement    string
		wantNetworkReady   bool
		wantStrictBlocking bool
	}{
		{
			name:               "missing proof with strong labels",
			security:           us005StrictWorkerSecurityPolicy(),
			enforcement:        nil,
			wantNetworkPolicy:  sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement:    sandbox.SandboxNetworkEnforcementModeNone,
			wantNetworkReady:   false,
			wantStrictBlocking: true,
		},
		{
			name:               "proxy only proof stays partial",
			security:           us005ProxyOnlyWorkerSecurityPolicy(),
			enforcement:        us005ProxyOnlyNetworkMetadata("us005-proxy-only"),
			wantNetworkPolicy:  sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement:    sandbox.SandboxNetworkEnforcementModeProxy,
			wantNetworkReady:   false,
			wantStrictBlocking: true,
		},
		{
			name:               "missing rule proof",
			security:           us005StrictWorkerSecurityPolicy(),
			enforcement:        us005ProxyFirewallNetworkMetadataWithoutRuleProof("us005-missing-rule"),
			wantNetworkPolicy:  sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement:    sandbox.SandboxNetworkEnforcementModeNone,
			wantNetworkReady:   false,
			wantStrictBlocking: true,
		},
		{
			name:               "failed rule proof",
			security:           us005StrictWorkerSecurityPolicy(),
			enforcement:        us005ProxyFirewallNetworkMetadataWithRuleStatus("us005-failed-rule", "failed", "adapter_failed"),
			wantNetworkPolicy:  sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement:    sandbox.SandboxNetworkEnforcementModeNone,
			wantNetworkReady:   false,
			wantStrictBlocking: true,
		},
		{
			name:               "unsupported rule proof",
			security:           us005StrictWorkerSecurityPolicy(),
			enforcement:        us005UnsupportedProxyFirewallNetworkMetadata("us005-unsupported-rule"),
			wantNetworkPolicy:  sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement:    sandbox.SandboxNetworkEnforcementModeNone,
			wantNetworkReady:   false,
			wantStrictBlocking: true,
		},
		{
			name:               "warning-bearing rule proof",
			security:           us005StrictWorkerSecurityPolicy(),
			enforcement:        us005ProxyFirewallNetworkMetadataWithRuleWarning("us005-warning-rule"),
			wantNetworkPolicy:  sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement:    sandbox.SandboxNetworkEnforcementModeNone,
			wantNetworkReady:   false,
			wantStrictBlocking: true,
		},
		{
			name:               "active dual proxy firewall proof",
			security:           us005StrictWorkerSecurityPolicy(),
			enforcement:        us005ProxyFirewallNetworkMetadata("us005-active-dual"),
			wantNetworkPolicy:  sandbox.SandboxNetworkPolicyDenyByDefault,
			wantEnforcement:    sandbox.SandboxNetworkEnforcementModeProxyFirewall,
			wantNetworkReady:   true,
			wantStrictBlocking: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hostID := "worker-" + strings.ReplaceAll(tt.name, " ", "-")
			resp := us005SandboxRuntimeStatusJSON(t, hostID, tt.security, tt.enforcement)
			us005RequireRuntimeStatusNetwork(t, tt.name, resp, tt.wantNetworkPolicy, tt.wantEnforcement)
			us005RequireNetworkReadiness(t, tt.name, resp.Security, tt.wantNetworkReady)
			us005RequireStrictReadiness(t, tt.name, resp.Security, tt.wantStrictBlocking)
			us005AssertRuntimeStatusJSONRedacted(t, tt.name, resp)
		})
	}
}

func TestUS005FactoryStrictReadinessBlocksDowngradedProxyFirewallMetadata(t *testing.T) {
	security := applyCommandSandboxSecurityReadinessGate(
		us005StrictSandboxSecurity(),
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		nil,
	)
	if security == nil || security.SecurityReadinessGate == nil {
		t.Fatalf("strict readiness security = %#v, want blocked gate", security)
	}
	if security.SecurityReadinessGate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
		t.Fatalf("strict readiness gate = %#v, want blocked without proof", security.SecurityReadinessGate)
	}
	us005RequireBestEffortNetworkSecurity(t, "strict readiness security", security.Network, sandbox.SandboxNetworkEnforcementModeNone)

	metadata := factorySandboxSecurityMetadata(security)
	if metadata == nil || metadata.Network == nil || metadata.SecurityReadinessGate == nil {
		t.Fatalf("factory security metadata = %#v, want downgraded network plus readiness gate", metadata)
	}
	us005RequireBestEffortFactoryNetwork(t, "factory strict readiness", metadata.Network, sandbox.SandboxNetworkEnforcementModeNone)
	if metadata.SecurityReadinessGate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
		t.Fatalf("factory readiness gate = %#v, want blocked without proof", metadata.SecurityReadinessGate)
	}

	payload := mustMarshalSandboxSecurityMetadata(t, factory.SandboxMetadata{Security: metadata})
	for _, forbidden := range []string{
		`"policyEnforced":"deny_by_default"`,
		`"networkEnforcement":"proxy_firewall"`,
		`"enforcementMode":"proxy_firewall"`,
		"api.internal.example.com",
		"/tmp/",
		"Authorization",
		"secret",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("factory readiness payload leaked or overclaimed %q:\n%s", forbidden, payload)
		}
	}
}

func TestUS005CommandStatusReadinessFilesAvoidLiveEnforcementImplementation(t *testing.T) {
	files := []string{
		"sandbox_security_projection.go",
		"sandbox_runtime_contracts.go",
		"factory_sandbox_readiness.go",
		"factory_sandbox_executor.go",
		"sandbox_host_mapping.go",
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			path := filepath.Join(".", file)
			src, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile(%s) error: %v", path, err)
			}
			parsed, err := parser.ParseFile(token.NewFileSet(), path, src, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("ParseFile(%s) error: %v", path, err)
			}
			for _, imported := range parsed.Imports {
				path := strings.Trim(imported.Path.Value, `"`)
				for _, forbidden := range []string{
					"github.com/jywlabs/hal/internal/sandboxruntime/networkenforcement",
					"net",
					"net/http",
					"os/exec",
					"syscall",
				} {
					if path == forbidden {
						t.Fatalf("%s imports %s; command status/readiness must consume sanitized metadata only", file, forbidden)
					}
				}
			}
			for _, marker := range []string{
				"RuleProofAdapter",
				"NewRuleProof",
				"PolicyProxyLifecycle",
				"iptables",
				"nftables",
				"pfctl",
			} {
				if strings.Contains(string(src), marker) {
					t.Fatalf("%s contains live enforcement marker %q; command status/readiness must not own enforcement behavior", file, marker)
				}
			}
		})
	}
}

func us005SandboxRuntimeStatusJSON(t *testing.T, hostID string, security sandboxworker.SecurityPolicy, enforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata) SandboxRuntimeStatusResponse {
	t.Helper()
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                hostID,
		Name:              hostID,
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/private/" + hostID + ".sock",
		SupportedRuntimes: []string{sandboxworker.RuntimeDriverMicroVM},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	refreshedAt := time.Date(2026, 7, 4, 15, 5, 0, 0, time.UTC)
	fakeClient := &fakeSandboxHostWorkerClient{
		status: us012WorkerStatus(hostID),
		capabilities: &sandboxworker.Capabilities{
			WorkerID: hostID,
			RuntimeDrivers: []sandboxworker.RuntimeDriver{{
				ID:                 sandboxworker.RuntimeDriverMicroVM,
				HostKind:           sandboxworker.HostKindLocal,
				IsolationLevel:     sandboxworker.IsolationLevelVM,
				Operations:         []string{sandboxworker.OperationStart, sandboxworker.OperationStatus},
				Security:           security,
				NetworkEnforcement: enforcement,
			}},
		},
	}
	deps := defaultSandboxRuntimeDeps()
	deps.now = func() time.Time { return refreshedAt }
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		return fakeClient, nil
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(deps)
	cmd.SetArgs([]string{"status", hostID, sandboxworker.RuntimeDriverMicroVM, "--live", "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}
	return decodeOneSandboxRuntimeStatusJSON(t, stdout.Bytes())
}

func us005StrictSandboxSecurity() *sandbox.SandboxSecurity {
	return &sandbox.SandboxSecurity{
		Network: &sandbox.SandboxNetworkSecurity{
			PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
			PolicyEnforced:  sandbox.SandboxNetworkPolicyDenyByDefault,
			EnforcementMode: sandbox.SandboxNetworkEnforcementModeProxyFirewall,
			PolicyResult:    us005StrictNetworkPolicyResult(),
		},
	}
}

func us005StrictNetworkPolicyResult() *sandbox.SandboxNetworkPolicyResult {
	result := sandbox.EvaluateSandboxNetworkPolicy(
		sandbox.SandboxNetworkPolicyIntent{Preset: sandbox.SandboxNetworkPolicyPresetDenyByDefault},
		sandbox.SandboxNetworkPolicyEnforcementCapability{
			Supported:                  true,
			Modes:                      []string{sandbox.SandboxNetworkEnforcementModeProxyFirewall},
			SupportsDomainRules:        true,
			SupportsEndpointRules:      true,
			SupportsPrivateRangeRules:  true,
			SupportsMetadataEndpoint:   true,
			SupportsLoopbackRules:      true,
			SupportsLinkLocalRules:     true,
			SupportsDefaultDenyPosture: true,
		},
	)
	return sandbox.CloneSandboxNetworkPolicyResultPtr(&result)
}

func us005StrictWorkerSecurityPolicy() sandboxworker.SecurityPolicy {
	return sandboxworker.SecurityPolicy{
		Requested: sandboxworker.SecurityControls{
			NetworkPolicy:      sandboxworker.NetworkPolicyDenyByDefault,
			NetworkEnforcement: sandboxworker.NetworkEnforcementRuntime,
			IsolationLevel:     sandboxworker.IsolationLevelVM,
		},
		Enforced: sandboxworker.SecurityControls{
			NetworkPolicy:      sandboxworker.NetworkPolicyDenyByDefault,
			NetworkEnforcement: sandboxworker.NetworkEnforcementProxyFirewall,
			NetworkEnforcementCapability: &sandboxruntime.RuntimeNetworkEnforcementCapability{
				Supported:                  true,
				Modes:                      []string{sandboxworker.NetworkEnforcementProxyFirewall},
				SupportsDomainRules:        true,
				SupportsEndpointRules:      true,
				SupportsPrivateRangeRules:  true,
				SupportsMetadataEndpoint:   true,
				SupportsLoopbackRules:      true,
				SupportsLinkLocalRules:     true,
				SupportsDefaultDenyPosture: true,
			},
			IsolationLevel: sandboxworker.IsolationLevelVM,
		},
	}
}

func us005ProxyOnlyWorkerSecurityPolicy() sandboxworker.SecurityPolicy {
	policy := us005StrictWorkerSecurityPolicy()
	policy.Enforced.NetworkPolicy = sandboxworker.NetworkPolicyBestEffort
	policy.Enforced.NetworkEnforcement = sandboxworker.NetworkEnforcementProxy
	policy.Enforced.NetworkEnforcementCapability = &sandboxruntime.RuntimeNetworkEnforcementCapability{
		Supported:                 true,
		Modes:                     []string{sandboxworker.NetworkEnforcementProxy},
		SupportsDomainRules:       true,
		SupportsEndpointRules:     true,
		SupportsPrivateRangeRules: true,
		SupportsMetadataEndpoint:  true,
		SupportsLoopbackRules:     true,
		SupportsLinkLocalRules:    true,
	}
	return policy
}

func us005ProxyFirewallRuntimeCapability() *sandboxruntime.RuntimeNetworkEnforcementCapability {
	return &sandboxruntime.RuntimeNetworkEnforcementCapability{
		Supported:                  true,
		Modes:                      []string{sandboxworker.NetworkEnforcementProxyFirewall},
		SupportsDomainRules:        true,
		SupportsEndpointRules:      true,
		SupportsPrivateRangeRules:  true,
		SupportsMetadataEndpoint:   true,
		SupportsLoopbackRules:      true,
		SupportsLinkLocalRules:     true,
		SupportsDefaultDenyPosture: true,
	}
}

func us005ProxyOnlyRuntimeCapability() *sandboxruntime.RuntimeNetworkEnforcementCapability {
	capability := us005ProxyFirewallRuntimeCapability()
	capability.Modes = []string{sandboxworker.NetworkEnforcementProxy}
	capability.SupportsDefaultDenyPosture = false
	return capability
}

func us005ProxyFirewallNetworkMetadata(planID string) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	return us005ProxyFirewallNetworkMetadataWithRuleStatus(planID, "active", "active")
}

func us005ProxyFirewallNetworkMetadataWithoutRuleProof(planID string) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	metadata := us005ProxyFirewallNetworkMetadata(planID)
	metadata.Orchestration.Rules = nil
	return metadata
}

func us005ProxyFirewallNetworkMetadataWithRuleStatus(planID, status, reason string) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	metadata := us005BaseNetworkMetadata(planID, sandboxworker.NetworkEnforcementProxyFirewall, us005ProxyFirewallRuntimeCapability())
	metadata.Orchestration.Rules = []sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{{
		ID:               planID + "-firewall-rule",
		PlanID:           planID,
		AdapterID:        "runtime-firewall-rule-proof",
		Status:           status,
		Mechanisms:       []string{sandboxworker.NetworkEnforcementFirewall},
		Operations:       []string{"rule_proof"},
		PolicySnapshotID: planID + "-snapshot",
		PolicyPreset:     sandboxworker.NetworkPolicyDenyByDefault,
		ReasonCode:       reason,
	}}
	if status == "failed" {
		metadata.Result.Outcome = "failure"
		metadata.Result.ReasonCode = "adapter_failed"
	}
	return metadata
}

func us005ProxyFirewallNetworkMetadataWithRuleWarning(planID string) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	metadata := us005ProxyFirewallNetworkMetadata(planID)
	metadata.Orchestration.Rules[0].WarningCodes = []string{"partial_lifecycle"}
	metadata.Result.WarningCodes = []string{"partial_enforcement"}
	return metadata
}

func us005UnsupportedProxyFirewallNetworkMetadata(planID string) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	metadata := us005ProxyFirewallNetworkMetadata(planID)
	metadata.Result.Outcome = "unsupported"
	metadata.Result.ReasonCode = "adapter_unsupported"
	metadata.Result.Capability = &sandboxruntime.RuntimeNetworkEnforcementCapability{
		Supported: false,
		Modes:     []string{sandboxworker.NetworkEnforcementProxyFirewall},
	}
	return metadata
}

func us005ProxyOnlyNetworkMetadata(planID string) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	return us005BaseNetworkMetadata(planID, sandboxworker.NetworkEnforcementProxy, us005ProxyOnlyRuntimeCapability())
}

func us005BaseNetworkMetadata(planID, mode string, capability *sandboxruntime.RuntimeNetworkEnforcementCapability) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	return &sandboxruntime.RuntimeNetworkEnforcementMetadata{
		Plan: &sandboxruntime.RuntimeNetworkEnforcementPlanMetadata{
			ID:               planID,
			Source:           "worker",
			Operation:        "prepare_network",
			PolicySnapshotID: planID + "-snapshot",
			PolicyPreset:     sandboxworker.NetworkPolicyDenyByDefault,
			DefaultPosture:   sandboxworker.NetworkPolicyDenyByDefault,
			Mechanisms:       []string{sandboxworker.NetworkEnforcementProxy, mode},
			Operations:       []string{"default_deny", "proxy_route"},
		},
		Orchestration: &sandboxruntime.RuntimeNetworkEnforcementOrchestrationMetadata{
			PlanID:           planID,
			AdapterID:        "runtime-network-proof",
			Status:           "active",
			Mechanisms:       []string{sandboxworker.NetworkEnforcementProxy, mode},
			Operations:       []string{"active_proxy"},
			PolicySnapshotID: planID + "-snapshot",
			PolicyPreset:     sandboxworker.NetworkPolicyDenyByDefault,
			Proxy: &sandboxruntime.RuntimeNetworkEnforcementLifecycleMetadata{
				ID:               planID + "-proxy",
				PlanID:           planID,
				AdapterID:        "policy-proxy-proof",
				Status:           "active",
				Mechanisms:       []string{sandboxworker.NetworkEnforcementProxy},
				Operations:       []string{"active_proxy"},
				PolicySnapshotID: planID + "-snapshot",
				PolicyPreset:     sandboxworker.NetworkPolicyDenyByDefault,
				ReasonCode:       "active",
			},
			ReasonCode: "active",
		},
		Result: &sandboxruntime.RuntimeNetworkEnforcementResultMetadata{
			PlanID:           planID,
			AdapterID:        "runtime-network-proof",
			Outcome:          "success",
			EnforcementMode:  mode,
			Mechanisms:       us005NetworkEnforcementResultMechanisms(mode),
			Operations:       []string{"apply"},
			PolicySnapshotID: planID + "-snapshot",
			PolicyPreset:     sandboxworker.NetworkPolicyDenyByDefault,
			Capability:       capability,
			ReasonCode:       "applied",
		},
	}
}

func us005NetworkEnforcementResultMechanisms(mode string) []string {
	if mode == sandboxworker.NetworkEnforcementProxyFirewall {
		return []string{sandboxworker.NetworkEnforcementProxy, sandboxworker.NetworkEnforcementFirewall}
	}
	return []string{mode}
}

func us005RequireRuntimeStatusNetwork(t *testing.T, label string, resp SandboxRuntimeStatusResponse, wantPolicy, wantEnforcement string) {
	t.Helper()
	if resp.Security.Enforced.NetworkPolicy == nil || *resp.Security.Enforced.NetworkPolicy != wantPolicy {
		t.Fatalf("%s enforced networkPolicy = %q, want %q; enforced=%#v policyResult=%#v readiness=%#v", label, sandboxRuntimeStringPtrValue(resp.Security.Enforced.NetworkPolicy, ""), wantPolicy, resp.Security.Enforced, resp.Security.NetworkPolicyResult, resp.Security.CapabilityReadiness)
	}
	if resp.Security.Enforced.NetworkEnforcement == nil || *resp.Security.Enforced.NetworkEnforcement != wantEnforcement {
		t.Fatalf("%s enforced networkEnforcement = %q, want %q; security=%#v", label, sandboxRuntimeStringPtrValue(resp.Security.Enforced.NetworkEnforcement, ""), wantEnforcement, resp.Security)
	}
	if wantPolicy == sandbox.SandboxNetworkPolicyBestEffort {
		if sandboxRuntimeStringPtrEquals(resp.Security.Enforced.NetworkPolicy, sandbox.SandboxNetworkPolicyDenyByDefault) ||
			sandboxRuntimeStringPtrEquals(resp.Security.Enforced.NetworkEnforcement, sandbox.SandboxNetworkEnforcementModeProxyFirewall) {
			t.Fatalf("%s overclaimed strict network security: %#v", label, resp.Security.Enforced)
		}
		if resp.Security.NetworkPolicyResult != nil {
			if resp.Security.NetworkPolicyResult.Effective.Preset != sandbox.SandboxNetworkPolicyPresetLegacyDefault ||
				resp.Security.NetworkPolicyResult.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
				t.Fatalf("%s networkPolicyResult = %#v, want best-effort downgrade", label, resp.Security.NetworkPolicyResult)
			}
		}
	}
}

func us005RequireBestEffortRuntimeSummary(t *testing.T, label string, summary SandboxRuntimeSecuritySummary, wantEnforcement string) {
	t.Helper()
	if summary.Enforced.NetworkPolicy == nil || *summary.Enforced.NetworkPolicy != sandbox.SandboxNetworkPolicyBestEffort {
		t.Fatalf("%s enforced networkPolicy = %#v, want best_effort", label, summary.Enforced.NetworkPolicy)
	}
	if summary.Enforced.NetworkEnforcement == nil || *summary.Enforced.NetworkEnforcement != wantEnforcement {
		t.Fatalf("%s networkEnforcement = %#v, want %q", label, summary.Enforced.NetworkEnforcement, wantEnforcement)
	}
	if summary.NetworkPolicyResult != nil &&
		summary.NetworkPolicyResult.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone {
		t.Fatalf("%s networkPolicyResult = %#v, want non-enforcing result", label, summary.NetworkPolicyResult)
	}
}

func us005RequireBestEffortNetworkSecurity(t *testing.T, label string, network *sandbox.SandboxNetworkSecurity, wantEnforcement string) {
	t.Helper()
	if network == nil {
		t.Fatalf("%s network security = nil", label)
	}
	if network.PolicyRequested != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("%s policyRequested = %q, want deny_by_default", label, network.PolicyRequested)
	}
	if network.PolicyEnforced != sandbox.SandboxNetworkPolicyBestEffort {
		t.Fatalf("%s policyEnforced = %q, want best_effort", label, network.PolicyEnforced)
	}
	if network.EnforcementMode != wantEnforcement {
		t.Fatalf("%s enforcementMode = %q, want %q", label, network.EnforcementMode, wantEnforcement)
	}
	if network.PolicyResult != nil &&
		(network.PolicyResult.Effective.Preset != sandbox.SandboxNetworkPolicyPresetLegacyDefault ||
			network.PolicyResult.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone) {
		t.Fatalf("%s policyResult = %#v, want best-effort downgrade", label, network.PolicyResult)
	}
}

func us005RequireBestEffortFactoryNetwork(t *testing.T, label string, network *factory.SandboxNetworkSecurityMetadata, wantEnforcement string) {
	t.Helper()
	if network == nil {
		t.Fatalf("%s factory network security = nil", label)
	}
	if network.PolicyRequested != sandbox.SandboxNetworkPolicyDenyByDefault {
		t.Fatalf("%s policyRequested = %q, want deny_by_default", label, network.PolicyRequested)
	}
	if network.PolicyEnforced != sandbox.SandboxNetworkPolicyBestEffort {
		t.Fatalf("%s policyEnforced = %q, want best_effort", label, network.PolicyEnforced)
	}
	if network.EnforcementMode != wantEnforcement {
		t.Fatalf("%s enforcementMode = %q, want %q", label, network.EnforcementMode, wantEnforcement)
	}
	if network.PolicyResult != nil &&
		(network.PolicyResult.Effective.Preset != sandbox.SandboxNetworkPolicyPresetLegacyDefault ||
			network.PolicyResult.EnforcementMode != sandbox.SandboxNetworkEnforcementModeNone) {
		t.Fatalf("%s policyResult = %#v, want best-effort downgrade", label, network.PolicyResult)
	}
}

func us005RequireStrictReadiness(t *testing.T, label string, security SandboxRuntimeSecuritySummary, wantBlocking bool) {
	t.Helper()
	if security.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("%s capabilityReadinessDiagnostics = nil", label)
	}
	if security.CapabilityReadinessDiagnostics.WouldBlockStrictGate != wantBlocking {
		t.Fatalf("%s WouldBlockStrictGate = %v, want %v (%#v)", label, security.CapabilityReadinessDiagnostics.WouldBlockStrictGate, wantBlocking, security.CapabilityReadinessDiagnostics)
	}
	if security.SecurityReadinessGate == nil || security.SecurityReadinessGate.Counts == nil {
		t.Fatalf("%s securityReadinessGate = %#v, want readiness gate counts", label, security.SecurityReadinessGate)
	}
	if wantBlocking {
		if security.SecurityReadinessGate.Counts.StrictBlocking == 0 {
			t.Fatalf("%s securityReadinessGate = %#v, want strict-blocking counts", label, security.SecurityReadinessGate)
		}
		return
	}
	if security.SecurityReadinessGate.Counts.StrictBlocking != 0 ||
		security.SecurityReadinessGate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed {
		t.Fatalf("%s securityReadinessGate = %#v, want proof-complete allowed readiness", label, security.SecurityReadinessGate)
	}
}

func us005RequireNetworkReadiness(t *testing.T, label string, security SandboxRuntimeSecuritySummary, wantReady bool) {
	t.Helper()
	if security.CapabilityReadiness == nil {
		t.Fatalf("%s capabilityReadiness = nil", label)
	}
	var gotReady bool
	for _, result := range security.CapabilityReadiness.Results {
		if result.State != sandbox.SandboxSecurityCapabilityReadinessReady || result.Ready == nil {
			continue
		}
		if result.Ready.Family == sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy &&
			result.Ready.Capability == sandbox.SandboxSecurityCapabilityNetworkDenyByDefault &&
			result.Ready.ReasonCode == sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed {
			gotReady = true
		}
	}
	if gotReady != wantReady {
		t.Fatalf("%s network readiness ready = %v, want %v; readiness=%#v", label, gotReady, wantReady, security.CapabilityReadiness)
	}
}

func us005AssertRuntimeStatusJSONRedacted(t *testing.T, label string, resp SandboxRuntimeStatusResponse) {
	t.Helper()
	payload := mustMarshalSandboxSecurityMetadata(t, resp)
	for _, forbidden := range []string{
		"/tmp/private",
		".sock",
		"://",
		"api.internal.example.com",
		"Authorization",
		"Bearer",
		"OPENAI_API_KEY",
		"GITHUB_TOKEN",
		"token=",
		"secret",
		"iptables",
		"nftables",
		"pfctl",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("%s runtime status JSON leaked forbidden fragment %q:\n%s", label, forbidden, payload)
		}
	}
}
