package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestUS013SandboxRuntimeInspectionReportsOnlyProvenNetworkEnforcement(t *testing.T) {
	tests := []struct {
		name              string
		security          sandboxworker.SecurityPolicy
		enforcement       *sandboxruntime.RuntimeNetworkEnforcementMetadata
		wantPolicy        string
		wantEnforcement   string
		wantNetworkReady  bool
		wantProof         bool
		wantProofOutcome  string
		wantProofMode     string
		wantProofSupport  bool
		wantProxyStatus   string
		wantRuleStatus    string
		wantDualProofLive bool
	}{
		{
			name:            "compatibility metadata without runtime proof",
			security:        us005StrictWorkerSecurityPolicy(),
			wantPolicy:      sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement: sandbox.SandboxNetworkEnforcementModeNone,
		},
		{
			name:             "proxy only proof remains partial",
			security:         us005ProxyOnlyWorkerSecurityPolicy(),
			enforcement:      us005ProxyOnlyNetworkMetadata("us013-proxy-only"),
			wantPolicy:       sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement:  sandbox.SandboxNetworkEnforcementModeProxy,
			wantProof:        true,
			wantProofOutcome: "success",
			wantProofMode:    sandbox.SandboxNetworkEnforcementModeProxy,
			wantProofSupport: true,
			wantProxyStatus:  "active",
		},
		{
			name:             "best effort proxy firewall metadata is downgraded",
			security:         us005StrictWorkerSecurityPolicy(),
			enforcement:      us005BestEffortProxyFirewallNetworkMetadata("us013-best-effort"),
			wantPolicy:       sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement:  sandbox.SandboxNetworkEnforcementModeNone,
			wantProof:        true,
			wantProofOutcome: "best_effort",
			wantProofMode:    sandbox.SandboxNetworkEnforcementModeBestEffort,
			wantProxyStatus:  "active",
			wantRuleStatus:   "active",
		},
		{
			name:             "planned proxy firewall metadata is downgraded",
			security:         us005StrictWorkerSecurityPolicy(),
			enforcement:      us005ProxyFirewallNetworkMetadataWithLifecycleStatus("us013-planned", "planned", "prepared"),
			wantPolicy:       sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement:  sandbox.SandboxNetworkEnforcementModeNone,
			wantProof:        true,
			wantProofOutcome: "best_effort",
			wantProofMode:    sandbox.SandboxNetworkEnforcementModeNone,
		},
		{
			name:             "fake only proxy firewall metadata is downgraded",
			security:         us005StrictWorkerSecurityPolicy(),
			enforcement:      us012StatusProxyFirewallMetadataWithOrchestrationStatus("us013-fake-only", "skipped", "skipped"),
			wantPolicy:       sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement:  sandbox.SandboxNetworkEnforcementModeNone,
			wantProof:        true,
			wantProofOutcome: "best_effort",
			wantProofMode:    sandbox.SandboxNetworkEnforcementModeNone,
		},
		{
			name:             "historical proxy firewall metadata is downgraded",
			security:         us005StrictWorkerSecurityPolicy(),
			enforcement:      us012StatusProxyFirewallMetadataWithOrchestrationStatus("us013-historical", "stopped", "stopped"),
			wantPolicy:       sandbox.SandboxNetworkPolicyBestEffort,
			wantEnforcement:  sandbox.SandboxNetworkEnforcementModeNone,
			wantProof:        true,
			wantProofOutcome: "best_effort",
			wantProofMode:    sandbox.SandboxNetworkEnforcementModeNone,
		},
		{
			name:              "active dual proof remains proxy firewall",
			security:          us005StrictWorkerSecurityPolicy(),
			enforcement:       us005ProxyFirewallNetworkMetadata("us013-active-dual"),
			wantPolicy:        sandbox.SandboxNetworkPolicyDenyByDefault,
			wantEnforcement:   sandbox.SandboxNetworkEnforcementModeProxyFirewall,
			wantNetworkReady:  true,
			wantProof:         true,
			wantProofOutcome:  "success",
			wantProofMode:     sandbox.SandboxNetworkEnforcementModeProxyFirewall,
			wantProofSupport:  true,
			wantProxyStatus:   "active",
			wantRuleStatus:    "active",
			wantDualProofLive: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			resp, jsonOutput, humanOutput := us013RuntimeInspectionOutputs(t, tt.name, tt.security, tt.enforcement)

			if resp.Source.Mode != SandboxRuntimeSourceLiveRefreshed || !resp.Source.RequestedLive {
				t.Fatalf("source = %#v, want live-refreshed runtime inspection", resp.Source)
			}
			us005RequireRuntimeStatusNetwork(t, tt.name, resp, tt.wantPolicy, tt.wantEnforcement)
			us005RequireNetworkReadiness(t, tt.name, resp.Security, tt.wantNetworkReady)
			us013RequireRuntimeProofSummary(t, tt.name, resp.Security.NetworkEnforcementProof, us013RuntimeProofExpectation{
				present:       tt.wantProof,
				outcome:       tt.wantProofOutcome,
				mode:          tt.wantProofMode,
				supported:     tt.wantProofSupport,
				proxyStatus:   tt.wantProxyStatus,
				ruleStatus:    tt.wantRuleStatus,
				activeDual:    tt.wantDualProofLive,
				activeProxyOK: tt.wantEnforcement == sandbox.SandboxNetworkEnforcementModeProxy || tt.wantDualProofLive,
			})
			us013AssertRuntimeInspectionConservative(t, tt.name, jsonOutput, humanOutput, tt.wantEnforcement)
			us013AssertRuntimeInspectionRedacted(t, tt.name+" JSON", jsonOutput)
			us013AssertRuntimeInspectionRedacted(t, tt.name+" human", humanOutput)
		})
	}
}

type us013RuntimeProofExpectation struct {
	present       bool
	outcome       string
	mode          string
	supported     bool
	proxyStatus   string
	ruleStatus    string
	activeDual    bool
	activeProxyOK bool
}

func us013RuntimeInspectionOutputs(t *testing.T, name string, security sandboxworker.SecurityPolicy, enforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata) (SandboxRuntimeStatusResponse, string, string) {
	t.Helper()
	setSandboxHostRegistryHome(t)

	hostID := "us013-runtime-" + us013Slug(name)
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                hostID,
		Name:              hostID + "-builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/private/" + hostID + ".sock",
		SupportedRuntimes: []string{sandboxworker.RuntimeDriverMicroVM},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	refreshedAt := time.Date(2026, 7, 4, 21, 13, 0, 0, time.UTC)
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

	jsonCmd, jsonStdout, jsonStderr := newTestSandboxRuntimeCommand(deps)
	jsonCmd.SetArgs([]string{"status", hostID, sandboxworker.RuntimeDriverMicroVM, "--live", "--json"})
	if err := jsonCmd.Execute(); err != nil {
		t.Fatalf("JSON Execute() error = %v; stderr=%q", err, jsonStderr.String())
	}
	resp := decodeOneSandboxRuntimeStatusJSON(t, jsonStdout.Bytes())

	humanCmd, humanStdout, humanStderr := newTestSandboxRuntimeCommand(deps)
	humanCmd.SetArgs([]string{"status", hostID, sandboxworker.RuntimeDriverMicroVM, "--live"})
	if err := humanCmd.Execute(); err != nil {
		t.Fatalf("human Execute() error = %v; stderr=%q", err, humanStderr.String())
	}

	return resp, jsonStdout.String(), humanStdout.String()
}

func us013RequireRuntimeProofSummary(t *testing.T, label string, proof *sandbox.SandboxNetworkEnforcementProofMetadata, want us013RuntimeProofExpectation) {
	t.Helper()
	if !want.present {
		if proof != nil {
			t.Fatalf("%s networkEnforcementProof = %#v, want omitted compatibility proof summary", label, proof)
		}
		return
	}
	if proof == nil {
		t.Fatalf("%s networkEnforcementProof = nil, want sanitized proof summary", label)
	}
	if proof.ResultOutcome != want.outcome ||
		proof.ResultEnforcementMode != want.mode ||
		proof.ResultSupported != want.supported {
		t.Fatalf("%s networkEnforcementProof result = %#v, want outcome=%q mode=%q supported=%t", label, proof, want.outcome, want.mode, want.supported)
	}
	if proof.ProxyLifecycleStatus != want.proxyStatus {
		t.Fatalf("%s proxy lifecycle status = %q, want %q; proof=%#v", label, proof.ProxyLifecycleStatus, want.proxyStatus, proof)
	}
	if proof.FirewallLifecycleStatus != want.ruleStatus {
		t.Fatalf("%s firewall lifecycle status = %q, want %q; proof=%#v", label, proof.FirewallLifecycleStatus, want.ruleStatus, proof)
	}
	if got := sandbox.SandboxNetworkEnforcementProofProvesActiveProxyFirewall(*proof); got != want.activeDual {
		t.Fatalf("%s active proxy-firewall proof = %t, want %t; proof=%#v", label, got, want.activeDual, proof)
	}
	if got := sandbox.SandboxNetworkEnforcementProofProvesActiveHTTPProxy(*proof); got != want.activeProxyOK {
		t.Fatalf("%s active proxy proof = %t, want %t; proof=%#v", label, got, want.activeProxyOK, proof)
	}
}

func us013AssertRuntimeInspectionConservative(t *testing.T, label, jsonOutput, humanOutput, wantEnforcement string) {
	t.Helper()
	for _, output := range []struct {
		name string
		text string
	}{
		{name: "JSON", text: jsonOutput},
		{name: "human", text: humanOutput},
	} {
		if wantEnforcement != sandbox.SandboxNetworkEnforcementModeProxyFirewall {
			for _, forbidden := range []string{
				`"networkEnforcement":"proxy_firewall"`,
				`"resultEnforcementMode":"proxy_firewall"`,
				"via proxy_firewall",
				"enforced network deny_by_default via proxy_firewall",
				"network proof result success via proxy_firewall",
			} {
				if strings.Contains(output.text, forbidden) {
					t.Fatalf("%s %s output rendered unproven proxy-firewall enforcement via %q:\n%s", label, output.name, forbidden, output.text)
				}
			}
		}
		if wantEnforcement != sandbox.SandboxNetworkEnforcementModeProxy &&
			wantEnforcement != sandbox.SandboxNetworkEnforcementModeProxyFirewall &&
			strings.Contains(output.text, "via proxy") {
			t.Fatalf("%s %s output rendered proxy enforcement without active proxy proof:\n%s", label, output.name, output.text)
		}
	}
}

func us013AssertRuntimeInspectionRedacted(t *testing.T, label, output string) {
	t.Helper()
	for _, forbidden := range []string{
		"/tmp/private",
		".sock",
		"status.internal.example.com",
		"api.internal.example.com",
		"203.0.113.42",
		"10.0.0.5",
		"127.0.0.1",
		"169.254.169.254",
		"Authorization",
		"Bearer",
		"OPENAI_API_KEY",
		"GITHUB_TOKEN",
		"token",
		"secret",
		"iptables",
		"nft ",
		"pfctl",
		"connect ",
		"listen ",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("%s leaked forbidden runtime inspection fragment %q:\n%s", label, forbidden, output)
		}
	}
}

func us013Slug(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	replacer := strings.NewReplacer(" ", "-", "_", "-", "/", "-", ".", "-", ":", "-")
	value = replacer.Replace(value)
	value = strings.Trim(value, "-")
	if value == "" {
		return "case"
	}
	return value
}
