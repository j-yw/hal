package cmd

import (
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestUS012SecureDefaultStatusSurfaceDoesNotOverclaimNetworkEnforcement(t *testing.T) {
	tests := []struct {
		name            string
		security        sandboxworker.SecurityPolicy
		enforcement     *sandboxruntime.RuntimeNetworkEnforcementMetadata
		wantEnforcement string
	}{
		{
			name:            "compatibility metadata without live proof",
			security:        us005StrictWorkerSecurityPolicy(),
			enforcement:     nil,
			wantEnforcement: sandbox.SandboxNetworkEnforcementModeNone,
		},
		{
			name:            "active proxy-only partial proof",
			security:        us005ProxyOnlyWorkerSecurityPolicy(),
			enforcement:     us005ProxyOnlyNetworkMetadata("us012-status-proxy-only"),
			wantEnforcement: sandbox.SandboxNetworkEnforcementModeProxy,
		},
		{
			name:            "planned proxy plus firewall metadata",
			security:        us005StrictWorkerSecurityPolicy(),
			enforcement:     us012StatusProxyFirewallMetadataWithOrchestrationStatus("us012-status-planned", "planned", "prepared"),
			wantEnforcement: sandbox.SandboxNetworkEnforcementModeNone,
		},
		{
			name:            "fake-only proxy plus firewall metadata",
			security:        us005StrictWorkerSecurityPolicy(),
			enforcement:     us012StatusProxyFirewallMetadataWithOrchestrationStatus("us012-status-fake-only", "skipped", "skipped"),
			wantEnforcement: sandbox.SandboxNetworkEnforcementModeNone,
		},
		{
			name:            "historical proxy plus firewall metadata",
			security:        us005StrictWorkerSecurityPolicy(),
			enforcement:     us012StatusProxyFirewallMetadataWithOrchestrationStatus("us012-status-historical", "stopped", "stopped"),
			wantEnforcement: sandbox.SandboxNetworkEnforcementModeNone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, jsonOutput, humanOutput := us012StatusSurfaceOutputs(t, tt.name, tt.security, tt.enforcement)

			if resp.Source.Mode != SandboxRuntimeSourceLiveRefreshed || !resp.Source.RequestedLive {
				t.Fatalf("source = %#v, want live-refreshed status inspection", resp.Source)
			}
			us005RequireRuntimeStatusNetwork(t, tt.name, resp, sandbox.SandboxNetworkPolicyBestEffort, tt.wantEnforcement)
			us005RequireNetworkReadiness(t, tt.name, resp.Security, false)
			us012RequireCompatibilityStatusGateBlocksStrictAcceptance(t, tt.name, resp.Security)
			us012AssertStatusSurfaceHonest(t, tt.name, humanOutput, tt.wantEnforcement)
			us012AssertStatusSurfaceRedacted(t, tt.name+" JSON", jsonOutput)
			us012AssertStatusSurfaceRedacted(t, tt.name+" human", humanOutput)
		})
	}
}

func us012StatusSurfaceOutputs(t *testing.T, name string, security sandboxworker.SecurityPolicy, enforcement *sandboxruntime.RuntimeNetworkEnforcementMetadata) (SandboxRuntimeStatusResponse, string, string) {
	t.Helper()
	setSandboxHostRegistryHome(t)

	slug := us009RunSurfaceSlug(name)
	hostID := "us012-status-" + slug
	if err := sandbox.SaveHost(&sandbox.SandboxHost{
		ID:                hostID,
		Name:              hostID + "-builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/private/" + hostID + ".sock",
		SupportedRuntimes: []string{sandboxworker.RuntimeDriverMicroVM},
	}); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	refreshedAt := time.Date(2026, 7, 4, 20, 12, 0, 0, time.UTC)
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

func us012StatusProxyFirewallMetadataWithOrchestrationStatus(planID, status, reason string) *sandboxruntime.RuntimeNetworkEnforcementMetadata {
	metadata := us005ProxyFirewallNetworkMetadata(planID)
	metadata.Plan.Operations = append(metadata.Plan.Operations,
		"connect https://status.internal.example.com:443",
		"/tmp/us012-status-proxy-firewall.sock",
		"GITHUB_TOKEN",
	)
	metadata.Orchestration.Status = status
	metadata.Orchestration.ReasonCode = reason
	metadata.Orchestration.Operations = append(metadata.Orchestration.Operations,
		"fake_only_probe",
		"iptables -A OUTPUT -d 203.0.113.42 -j DROP",
		"Authorization: Bearer secret",
	)
	metadata.Result.Operations = append(metadata.Result.Operations,
		"nft add rule inet filter output",
		"token=secret",
	)
	return metadata
}

func us012RequireCompatibilityStatusGateBlocksStrictAcceptance(t *testing.T, label string, security SandboxRuntimeSecuritySummary) {
	t.Helper()
	if security.SecurityReadinessGate == nil || security.SecurityReadinessGate.Counts == nil {
		t.Fatalf("%s securityReadinessGate = %#v, want compatibility diagnostic gate", label, security.SecurityReadinessGate)
	}
	if security.SecurityReadinessGate.PolicyMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility {
		t.Fatalf("%s securityReadinessGate = %#v, want compatibility policy mode for status inspection", label, security.SecurityReadinessGate)
	}
	if security.SecurityReadinessGate.Outcome == sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed ||
		security.SecurityReadinessGate.Counts.StrictBlocking == 0 {
		t.Fatalf("%s securityReadinessGate = %#v, want non-accepted strict secure-default diagnostics", label, security.SecurityReadinessGate)
	}
	if security.CapabilityReadinessDiagnostics == nil || !security.CapabilityReadinessDiagnostics.WouldBlockStrictGate {
		t.Fatalf("%s diagnostics = %#v, want strict-blocking diagnostics", label, security.CapabilityReadinessDiagnostics)
	}
}

func us012AssertStatusSurfaceHonest(t *testing.T, label, output, wantEnforcement string) {
	t.Helper()
	if !strings.Contains(output, "Secure default readiness: compatibility advisory") {
		t.Fatalf("%s human output = %q, want compatibility advisory readiness", label, output)
	}
	if strings.Contains(output, "Secure default readiness: strict allowed") ||
		strings.Contains(output, "proof-complete") ||
		strings.Contains(output, "enforced network deny_by_default") ||
		strings.Contains(output, "via proxy_firewall") {
		t.Fatalf("%s human output overclaimed secure-default enforcement:\n%s", label, output)
	}
	if wantEnforcement == sandbox.SandboxNetworkEnforcementModeProxy {
		if !strings.Contains(output, "enforced network best_effort via proxy") {
			t.Fatalf("%s human output = %q, want preserved proxy-only partial enforcement label", label, output)
		}
		return
	}
	if strings.Contains(output, "via proxy") {
		t.Fatalf("%s human output preserved proxy label without active proxy proof:\n%s", label, output)
	}
}

func us012AssertStatusSurfaceRedacted(t *testing.T, label, output string) {
	t.Helper()
	for _, forbidden := range []string{
		"/tmp/private",
		".sock",
		"status.internal.example.com",
		"203.0.113.42",
		"Authorization",
		"Bearer",
		"GITHUB_TOKEN",
		"token=secret",
		"secret",
		"iptables",
		"nft ",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("%s leaked forbidden status fragment %q:\n%s", label, forbidden, output)
		}
	}
}
