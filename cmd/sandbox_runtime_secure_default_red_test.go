package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestUS009SandboxRuntimeListJSONSurfacesStrictAndCompatibilitySecureDefaultDecisions(t *testing.T) {
	setSandboxHostRegistryHome(t)

	blockedReadiness := us009IncompleteSecureDefaultReadiness()
	blockedDiagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*blockedReadiness)

	tests := []struct {
		name        string
		hostID      string
		policyMode  sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode
		wantOutcome sandbox.SandboxSecurityCapabilityReadinessGateOutcome
	}{
		{
			name:        "strict blocked decision",
			hostID:      "us009-strict-blocked",
			policyMode:  sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			wantOutcome: sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
		},
		{
			name:        "compatibility advisory decision",
			hostID:      "us009-compat-advisory",
			policyMode:  sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility,
			wantOutcome: sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAdvisory,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			expected := sandbox.EvaluateSandboxSecurityCapabilityReadinessGate(tt.policyMode, blockedDiagnostics)
			if expected.Outcome != tt.wantOutcome {
				t.Fatalf("fixture decision = %#v, want outcome %q", expected, tt.wantOutcome)
			}
			if err := sandbox.SaveHost(us009RuntimeHostWithSecurity(tt.hostID, blockedReadiness, expected)); err != nil {
				t.Fatalf("SaveHost() error = %v", err)
			}

			cmd, stdout, stderr := newTestSandboxRuntimeCommand(us009RuntimeDepsNoWorker(t))
			cmd.SetArgs([]string{"list", tt.hostID, "--json"})
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
			}

			raw := us009DecodeJSONMap(t, stdout.Bytes())
			security := us009RequireObject(t, raw, "security")
			diagnostics := us009RequireObject(t, security, "capabilityReadinessDiagnostics")
			us009RequireBoolField(t, "capabilityReadinessDiagnostics", diagnostics, "advisoryOnly", true)
			us009RequireBoolField(t, "capabilityReadinessDiagnostics", diagnostics, "wouldBlockStrictGate", true)

			gate := us009RequireObject(t, security, "securityReadinessGate")
			us009AssertGateDecision(t, "runtime list securityReadinessGate", gate, expected)
			us009AssertNoForbiddenRuntimeSecureDefaultFragments(t, "runtime list JSON", stdout.String())
		})
	}
}

func TestUS009SandboxRuntimeStatusJSONSurfacesProofCompleteAllowedSecureDefaultDecision(t *testing.T) {
	setSandboxHostRegistryHome(t)

	readiness := us009ProofCompleteSecureDefaultReadiness()
	diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*readiness)
	expected := sandbox.EvaluateSandboxSecurityCapabilityReadinessGate(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict, diagnostics)
	if expected.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed {
		t.Fatalf("proof-complete fixture decision = %#v, want allowed", expected)
	}
	if err := sandbox.SaveHost(us009RuntimeHostWithSecurity("us009-proof-complete", readiness, expected)); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	cmd, stdout, stderr := newTestSandboxRuntimeCommand(us009RuntimeDepsNoWorker(t))
	cmd.SetArgs([]string{"status", "us009-proof-complete", sandbox.SandboxRuntimeDriverRootlessPodman, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
	}

	raw := us009DecodeJSONMap(t, stdout.Bytes())
	security := us009RequireObject(t, raw, "security")
	diagnosticsMap := us009RequireObject(t, security, "capabilityReadinessDiagnostics")
	us009RequireBoolField(t, "capabilityReadinessDiagnostics", diagnosticsMap, "wouldBlockStrictGate", false)

	gate := us009RequireObject(t, security, "securityReadinessGate")
	us009AssertGateDecision(t, "runtime status securityReadinessGate", gate, expected)
	us009AssertIntField(t, "runtime status securityReadinessGate counts", us009RequireObject(t, gate, "counts"), "ready", 5)
	us009AssertNoForbiddenRuntimeSecureDefaultFragments(t, "runtime status JSON", stdout.String())
}

func TestUS009SandboxRuntimeHumanOutputExplainsStrictVersusAdvisorySecureDefaultBehavior(t *testing.T) {
	setSandboxHostRegistryHome(t)

	blockedReadiness := us009IncompleteSecureDefaultReadiness()
	blockedDiagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*blockedReadiness)
	advisory := sandbox.EvaluateSandboxSecurityCapabilityReadinessGate(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility, blockedDiagnostics)
	if err := sandbox.SaveHost(us009RuntimeHostWithSecurity("us009-human-advisory", blockedReadiness, advisory)); err != nil {
		t.Fatalf("SaveHost(advisory) error = %v", err)
	}

	advisoryCmd, advisoryStdout, advisoryStderr := newTestSandboxRuntimeCommand(us009RuntimeDepsNoWorker(t))
	advisoryCmd.SetArgs([]string{"list", "us009-human-advisory"})
	if err := advisoryCmd.Execute(); err != nil {
		t.Fatalf("advisory Execute() error = %v; stderr=%q", err, advisoryStderr.String())
	}
	advisoryOutput := advisoryStdout.String()
	for _, want := range []string{
		"Secure default readiness: compatibility advisory",
		"strict secure-default would block",
		"reason codes",
		string(sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly),
	} {
		if !strings.Contains(advisoryOutput, want) {
			t.Fatalf("advisory human output = %q, want %q", advisoryOutput, want)
		}
	}
	us009AssertNoForbiddenRuntimeSecureDefaultFragments(t, "advisory human output", advisoryOutput)

	readiness := us009ProofCompleteSecureDefaultReadiness()
	allowedDiagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*readiness)
	allowed := sandbox.EvaluateSandboxSecurityCapabilityReadinessGate(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict, allowedDiagnostics)
	if err := sandbox.SaveHost(us009RuntimeHostWithSecurity("us009-human-allowed", readiness, allowed)); err != nil {
		t.Fatalf("SaveHost(allowed) error = %v", err)
	}

	allowedCmd, allowedStdout, allowedStderr := newTestSandboxRuntimeCommand(us009RuntimeDepsNoWorker(t))
	allowedCmd.SetArgs([]string{"status", "us009-human-allowed", sandbox.SandboxRuntimeDriverRootlessPodman})
	if err := allowedCmd.Execute(); err != nil {
		t.Fatalf("allowed Execute() error = %v; stderr=%q", err, allowedStderr.String())
	}
	allowedOutput := allowedStdout.String()
	for _, want := range []string{
		"Secure default readiness: strict allowed",
		"proof-complete",
		"ready=5",
		string(sandbox.SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed),
	} {
		if !strings.Contains(allowedOutput, want) {
			t.Fatalf("allowed human output = %q, want %q", allowedOutput, want)
		}
	}
	us009AssertNoForbiddenRuntimeSecureDefaultFragments(t, "allowed human output", allowedOutput)
}

func TestUS009SandboxRuntimeSecureDefaultOutputRedactsUnsafeFragments(t *testing.T) {
	setSandboxHostRegistryHome(t)

	readiness := us009UnsafeReadinessWithSafeFallback()
	diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*readiness)
	expected := sandbox.EvaluateSandboxSecurityCapabilityReadinessGate(sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility, diagnostics)
	host := us009RuntimeHostWithSecurity("us009-redaction", readiness, expected)
	host.Endpoint = "ssh://alice:ghp_us009_token@runtime.internal.invalid:22/private?token=raw-token"
	if err := sandbox.SaveHost(host); err != nil {
		t.Fatalf("SaveHost() error = %v", err)
	}

	var combined bytes.Buffer
	var listJSON string
	for _, args := range [][]string{
		{"list", "us009-redaction", "--json"},
		{"status", "us009-redaction", sandbox.SandboxRuntimeDriverRootlessPodman, "--json"},
		{"list", "us009-redaction"},
		{"status", "us009-redaction", sandbox.SandboxRuntimeDriverRootlessPodman},
	} {
		cmd, stdout, stderr := newTestSandboxRuntimeCommand(us009RuntimeDepsNoWorker(t))
		cmd.SetArgs(args)
		if err := cmd.Execute(); err != nil {
			t.Fatalf("Execute(%v) error = %v; stderr=%q", args, err, stderr.String())
		}
		if args[0] == "list" && len(args) == 3 && args[2] == "--json" {
			listJSON = stdout.String()
		}
		combined.WriteString(stdout.String())
		combined.WriteByte('\n')
	}

	output := combined.String()
	us009AssertNoForbiddenRuntimeSecureDefaultFragments(t, "combined runtime output", output)

	listRaw := us009DecodeJSONMap(t, []byte(listJSON))
	security := us009RequireObject(t, listRaw, "security")
	gate := us009RequireObject(t, security, "securityReadinessGate")
	us009AssertGateDecision(t, "redacted runtime list gate", gate, expected)
}

func us009RuntimeDepsNoWorker(t *testing.T) sandboxRuntimeDeps {
	t.Helper()
	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("US-009 runtime status tests must stay cached/fake-only and must not contact worker daemons")
		return nil, nil
	}
	return deps
}

func us009RuntimeHostWithSecurity(hostID string, readiness *sandbox.SandboxSecurityCapabilityReadinessOutput, gate sandbox.SandboxSecurityCapabilityReadinessGateDecision) *sandbox.SandboxHost {
	diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*readiness)
	return &sandbox.SandboxHost{
		ID:                hostID,
		Name:              hostID + "-builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/us009-runtime.sock",
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
		Capacity:          &sandbox.HostCapacity{MaxConcurrentSandboxes: 2},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: sandbox.SandboxNetworkPolicyDenyByDefault,
				PolicyEnforced:  sandbox.SandboxNetworkPolicyBestEffort,
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeNone,
			},
			Secrets: &sandbox.SandboxSecretSecurity{
				RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
				ActiveModes:    []string{sandbox.SandboxSecretModeLegacyAuthSync},
			},
			CapabilityReadiness:            readiness,
			CapabilityReadinessDiagnostics: &diagnostics,
			SecurityReadinessGate:          &gate,
		},
	}
}

func us009IncompleteSecureDefaultReadiness() *sandbox.SandboxSecurityCapabilityReadinessOutput {
	return &sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{
			us009MetadataOnlyCapability(
				sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
				sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
				sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly,
			),
			us009MetadataOnlyCapability(
				sandbox.SandboxSecurityCapabilityFamilySecretDelivery,
				sandbox.SandboxSecurityCapabilitySecretHTTPProxy,
				sandbox.SandboxSecurityCapabilityReasonCredentialActivationMissing,
			),
			us009BlockedCapability(
				sandbox.SandboxSecurityCapabilityFamilyWorkspace,
				sandbox.SandboxSecurityCapabilityDirectHostWorktree,
				sandbox.SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree,
			),
		},
	}
}

func us009ProofCompleteSecureDefaultReadiness() *sandbox.SandboxSecurityCapabilityReadinessOutput {
	return &sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{
			us009ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyIsolation, sandbox.SandboxSecurityCapabilityIsolationMicroVM, sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessConfirmed),
			us009ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyWorkspace, sandbox.SandboxSecurityCapabilityIsolatedWorkspace, sandbox.SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed),
			us009ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy, sandbox.SandboxSecurityCapabilityNetworkDenyByDefault, sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed),
			us009ReadyCapability(sandbox.SandboxSecurityCapabilityFamilySecretDelivery, sandbox.SandboxSecurityCapabilitySecretHTTPProxy, sandbox.SandboxSecurityCapabilityReasonCredentialActivationConfirmed),
			us009ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyTemplate, sandbox.SandboxSecurityCapabilityTemplateLockDigest, sandbox.SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed),
		},
	}
}

func us009UnsafeReadinessWithSafeFallback() *sandbox.SandboxSecurityCapabilityReadinessOutput {
	readiness := us009IncompleteSecureDefaultReadiness()
	readiness.Results = append(readiness.Results, sandbox.SandboxSecurityCapabilityReadinessResult{
		State:      sandbox.SandboxSecurityCapabilityReadinessMetadataOnly,
		ReasonCode: sandbox.SandboxSecurityCapabilityReasonTemplateLockDigestMissing,
		Metadata: &sandbox.SandboxSecurityCapabilityMetadata{
			ID:         "raw-template-ref:main?token=raw-template-token",
			Family:     sandbox.SandboxSecurityCapabilityFamilyTemplate,
			Capability: sandbox.SandboxSecurityCapabilityTemplateLockDigest,
			Mode:       "/Users/alice/private/us009-worktree/template.yaml",
			Source:     sandbox.SandboxSecurityCapabilitySourceMetadata,
			Status:     sandbox.SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode: sandbox.SandboxSecurityCapabilityReasonCode("Authorization: Bearer raw-header-token"),
			WarningCodes: []sandbox.SandboxSecurityCapabilityWarningCode{
				sandbox.SandboxSecurityCapabilityWarningCode("credential_value=raw-credential-value"),
				sandbox.SandboxSecurityCapabilityWarningCode("iptables -A OUTPUT -d proxy.internal.local:8080 -j DROP"),
				sandbox.SandboxSecurityCapabilityWarningCode("nft add rule inet filter output drop"),
			},
		},
	})
	return readiness
}

func us009ReadyCapability(family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName, reason sandbox.SandboxSecurityCapabilityReasonCode) sandbox.SandboxSecurityCapabilityReadinessResult {
	return sandbox.SandboxSecurityCapabilityReadinessResult{
		State:      sandbox.SandboxSecurityCapabilityReadinessReady,
		ReasonCode: reason,
		Requested: &sandbox.SandboxSecurityCapabilityMetadata{
			Family:     family,
			Capability: capability,
			Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
		},
		Ready: &sandbox.SandboxSecurityCapabilityMetadata{
			Family:     family,
			Capability: capability,
			Source:     sandbox.SandboxSecurityCapabilitySourceRuntime,
			Status:     sandbox.SandboxSecurityCapabilityReadinessReady,
			ReasonCode: reason,
		},
	}
}

func us009MetadataOnlyCapability(family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName, reason sandbox.SandboxSecurityCapabilityReasonCode) sandbox.SandboxSecurityCapabilityReadinessResult {
	return sandbox.SandboxSecurityCapabilityReadinessResult{
		State:      sandbox.SandboxSecurityCapabilityReadinessMetadataOnly,
		ReasonCode: reason,
		Metadata: &sandbox.SandboxSecurityCapabilityMetadata{
			Family:     family,
			Capability: capability,
			Source:     sandbox.SandboxSecurityCapabilitySourceMetadata,
			Status:     sandbox.SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode: reason,
		},
	}
}

func us009BlockedCapability(family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName, reason sandbox.SandboxSecurityCapabilityReasonCode) sandbox.SandboxSecurityCapabilityReadinessResult {
	return sandbox.SandboxSecurityCapabilityReadinessResult{
		State:      sandbox.SandboxSecurityCapabilityReadinessBlocked,
		ReasonCode: reason,
		Requested: &sandbox.SandboxSecurityCapabilityMetadata{
			Family:     family,
			Capability: capability,
			Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
			Status:     sandbox.SandboxSecurityCapabilityReadinessBlocked,
			ReasonCode: reason,
		},
	}
}

func us009DecodeJSONMap(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal() error = %v; payload=%s", err, data)
	}
	return raw
}

func us009RequireObject(t *testing.T, values map[string]any, field string) map[string]any {
	t.Helper()
	object, ok := values[field].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want object; keys=%v", field, values[field], us009MapKeys(values))
	}
	return object
}

func us009AssertGateDecision(t *testing.T, label string, gate map[string]any, expected sandbox.SandboxSecurityCapabilityReadinessGateDecision) {
	t.Helper()
	us009RequireStringField(t, label, gate, "code", string(expected.Code))
	us009RequireStringField(t, label, gate, "outcome", string(expected.Outcome))
	us009RequireStringField(t, label, gate, "policyMode", string(expected.PolicyMode))
	us009RequireStringField(t, label, gate, "reason", string(expected.Reason))
	if expected.Counts == nil {
		if _, ok := gate["counts"]; ok {
			t.Fatalf("%s counts = %#v, want omitted", label, gate["counts"])
		}
		return
	}
	counts := us009RequireObject(t, gate, "counts")
	us009AssertIntField(t, label, counts, "total", expected.Counts.Total)
	us009AssertIntField(t, label, counts, "ready", expected.Counts.Ready)
	us009AssertIntField(t, label, counts, "advisory", expected.Counts.Advisory)
	us009AssertIntField(t, label, counts, "blocked", expected.Counts.Blocked)
	us009AssertIntField(t, label, counts, "metadataOnly", expected.Counts.MetadataOnly)
	us009AssertIntField(t, label, counts, "unsupported", expected.Counts.Unsupported)
	us009AssertIntField(t, label, counts, "strictBlocking", expected.Counts.StrictBlocking)
	reasonCodeCounts := us009RequireObject(t, counts, "reasonCodeCounts")
	for reason, want := range expected.Counts.ReasonCodeCounts {
		us009AssertIntField(t, label, reasonCodeCounts, string(reason), want)
	}
}

func us009RequireStringField(t *testing.T, label string, values map[string]any, field, want string) {
	t.Helper()
	if got, ok := values[field].(string); !ok || got != want {
		t.Fatalf("%s %s = %#v, want %q", label, field, values[field], want)
	}
}

func us009RequireBoolField(t *testing.T, label string, values map[string]any, field string, want bool) {
	t.Helper()
	if got, ok := values[field].(bool); !ok || got != want {
		t.Fatalf("%s %s = %#v, want %t", label, field, values[field], want)
	}
}

func us009AssertIntField(t *testing.T, label string, values map[string]any, field string, want int) {
	t.Helper()
	if got := us009IntValue(values[field]); got != want {
		t.Fatalf("%s %s = %#v, want %d", label, field, values[field], want)
	}
}

func us009IntValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	default:
		return 0
	}
}

func us009MapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return sortedUniqueStrings(keys)
}

func us009AssertNoForbiddenRuntimeSecureDefaultFragments(t *testing.T, label, output string) {
	t.Helper()
	for _, forbidden := range us009ForbiddenRuntimeSecureDefaultFragments() {
		if strings.Contains(output, forbidden) {
			t.Fatalf("%s leaked forbidden fragment %q:\n%s", label, forbidden, output)
		}
	}
}

func us009ForbiddenRuntimeSecureDefaultFragments() []string {
	return []string{
		"unix:///tmp/us009-runtime.sock",
		"/tmp/us009-runtime.sock",
		"us009-runtime.sock",
		"runtime.internal.invalid",
		"ghp_us009_token",
		"token=raw-token",
		"Authorization:",
		"Bearer raw-header-token",
		"credential_value=raw-credential-value",
		"raw-template-ref:main",
		"raw-template-token",
		"/Users/alice/private/us009-worktree",
		"iptables -A OUTPUT",
		"nft add rule",
		"proxy.internal.local:8080",
		"/var/run/hal-firewall.sock",
		"/var/run/hal-proxy.sock",
	}
}
