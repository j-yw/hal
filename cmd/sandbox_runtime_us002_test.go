package cmd

import (
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestUS002SandboxRuntimeListJSONDecodesCachedUnsupportedLiveAndSecureDefaultState(t *testing.T) {
	tests := []struct {
		name  string
		host  *sandbox.SandboxHost
		args  []string
		check func(*testing.T, SandboxRuntimeListResponse)
	}{
		{
			name: "cached default source",
			host: &sandbox.SandboxHost{
				ID:                "us002-list-cached",
				Name:              "cached-worker",
				Kind:              sandbox.SandboxHostKindWorker,
				Endpoint:          "unix:///tmp/us002-list-cached.sock",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
			},
			args: []string{"list", "us002-list-cached", "--json"},
			check: func(t *testing.T, resp SandboxRuntimeListResponse) {
				t.Helper()
				us002AssertRuntimeListContract(t, resp)
				if resp.Source.Mode != SandboxRuntimeSourceCached || resp.Source.RequestedLive || resp.Source.CacheUpdated || resp.Source.RefreshedAt != nil {
					t.Fatalf("source = %#v, want cached default source", resp.Source)
				}
				if len(resp.Runtimes) != 1 || resp.Runtimes[0].ID != sandbox.SandboxRuntimeDriverRootlessPodman {
					t.Fatalf("runtimes = %#v, want cached rootless runtime", resp.Runtimes)
				}
			},
		},
		{
			name: "unsupported live keeps explicit request state",
			host: &sandbox.SandboxHost{
				ID:                "us002-list-unsupported",
				Name:              "ssh-worker",
				Kind:              sandbox.SandboxHostKindSSH,
				Endpoint:          "ssh://alice:ghp_us002_token@runtime.internal.invalid:22/private?token=us002",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverSSHMachine},
			},
			args: []string{"list", "us002-list-unsupported", "--live", "--json"},
			check: func(t *testing.T, resp SandboxRuntimeListResponse) {
				t.Helper()
				us002AssertRuntimeListContract(t, resp)
				if resp.Source.Mode != SandboxRuntimeSourceUnsupportedLive || !resp.Source.RequestedLive || resp.Source.CacheUpdated || resp.Source.RefreshedAt != nil {
					t.Fatalf("source = %#v, want unsupported-live explicit request state", resp.Source)
				}
				if len(resp.Diagnostics) != 1 || resp.Diagnostics[0].Code != SandboxRuntimeStatusErrorLiveUnsupported {
					t.Fatalf("diagnostics = %#v, want live_unsupported diagnostic", resp.Diagnostics)
				}
				if resp.Host.Endpoint.Summary != "ssh endpoint" {
					t.Fatalf("endpoint summary = %q, want safe ssh endpoint", resp.Host.Endpoint.Summary)
				}
			},
		},
		{
			name: "secure default metadata",
			host: us002RuntimeHostWithSecurity(
				"us002-list-secure-default",
				us002BlockedSecureDefaultReadiness(),
				sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			),
			args: []string{"list", "us002-list-secure-default", "--json"},
			check: func(t *testing.T, resp SandboxRuntimeListResponse) {
				t.Helper()
				us002AssertRuntimeListContract(t, resp)
				us002AssertBlockedSecureDefaultSummary(t, "runtime list", resp.Security)
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			setSandboxHostRegistryHome(t)
			if err := sandbox.SaveHost(tt.host); err != nil {
				t.Fatalf("SaveHost() error = %v", err)
			}

			cmd, stdout, stderr := newTestSandboxRuntimeCommand(us002RuntimeDepsNoWorker(t))
			cmd.SetArgs(tt.args)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
			}

			output := stdout.String()
			resp := decodeOneSandboxRuntimeListJSON(t, stdout.Bytes())
			tt.check(t, resp)
			us002AssertNoForbiddenRuntimeOutput(t, output)
			if strings.Contains(output, "Sandbox runtimes for") {
				t.Fatalf("runtime list JSON included human output: %s", output)
			}
		})
	}
}

func TestUS002SandboxRuntimeStatusJSONDecodesSuccessMissingRuntimeAndSecureDefaultState(t *testing.T) {
	tests := []struct {
		name    string
		host    *sandbox.SandboxHost
		args    []string
		wantErr bool
		check   func(*testing.T, SandboxRuntimeStatusResponse)
	}{
		{
			name: "cached success",
			host: &sandbox.SandboxHost{
				ID:                "us002-status-success",
				Name:              "status-worker",
				Kind:              sandbox.SandboxHostKindWorker,
				Endpoint:          "unix:///tmp/us002-status-success.sock",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
			},
			args: []string{"status", "us002-status-success", sandbox.SandboxRuntimeDriverRootlessPodman, "--json"},
			check: func(t *testing.T, resp SandboxRuntimeStatusResponse) {
				t.Helper()
				us002AssertRuntimeStatusContract(t, resp)
				if resp.Source.Mode != SandboxRuntimeSourceCached || resp.Source.RequestedLive || resp.Source.CacheUpdated || resp.Source.RefreshedAt != nil {
					t.Fatalf("source = %#v, want cached default source", resp.Source)
				}
				if resp.Runtime.ID != sandbox.SandboxRuntimeDriverRootlessPodman {
					t.Fatalf("runtime = %#v, want requested rootless runtime", resp.Runtime)
				}
				if resp.Readiness.Status != SandboxRuntimeReadinessUnknown {
					t.Fatalf("readiness = %#v, want cached unknown readiness", resp.Readiness)
				}
			},
		},
		{
			name: "cached missing runtime keeps host secure default metadata",
			host: us002RuntimeHostWithSecurity(
				"us002-status-missing",
				us002BlockedSecureDefaultReadiness(),
				sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			),
			args:    []string{"status", "us002-status-missing", sandbox.SandboxRuntimeDriverMicroVM, "--json"},
			wantErr: true,
			check: func(t *testing.T, resp SandboxRuntimeStatusResponse) {
				t.Helper()
				us002AssertRuntimeStatusContract(t, resp)
				if resp.Source.Mode != SandboxRuntimeSourceCached || resp.Source.RequestedLive {
					t.Fatalf("source = %#v, want cached default source", resp.Source)
				}
				if len(resp.Errors) != 1 || resp.Errors[0].Code != SandboxRuntimeStatusErrorRuntimeNotFound {
					t.Fatalf("errors = %#v, want runtime_not_found", resp.Errors)
				}
				if resp.Readiness.Status != SandboxRuntimeReadinessUnavailable {
					t.Fatalf("readiness = %#v, want unavailable missing runtime", resp.Readiness)
				}
				us002AssertBlockedSecureDefaultSummary(t, "missing runtime status", resp.Security)
			},
		},
		{
			name: "secure default proof complete",
			host: us002RuntimeHostWithSecurity(
				"us002-status-secure-default",
				us002ProofCompleteSecureDefaultReadiness(),
				sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			),
			args: []string{"status", "us002-status-secure-default", sandbox.SandboxRuntimeDriverRootlessPodman, "--json"},
			check: func(t *testing.T, resp SandboxRuntimeStatusResponse) {
				t.Helper()
				us002AssertRuntimeStatusContract(t, resp)
				if resp.Security.CapabilityReadinessDiagnostics == nil || resp.Security.SecurityReadinessGate == nil {
					t.Fatalf("security = %#v, want diagnostics and gate", resp.Security)
				}
				if resp.Security.SecurityReadinessGate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed ||
					resp.Security.SecurityReadinessGate.PolicyMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict {
					t.Fatalf("securityReadinessGate = %#v, want strict allowed", resp.Security.SecurityReadinessGate)
				}
				if resp.Security.CapabilityReadinessDiagnostics.WouldBlockStrictGate {
					t.Fatalf("capabilityReadinessDiagnostics = %#v, want proof-complete non-blocking diagnostics", resp.Security.CapabilityReadinessDiagnostics)
				}
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			setSandboxHostRegistryHome(t)
			if err := sandbox.SaveHost(tt.host); err != nil {
				t.Fatalf("SaveHost() error = %v", err)
			}

			cmd, stdout, stderr := newTestSandboxRuntimeCommand(us002RuntimeDepsNoWorker(t))
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if tt.wantErr {
				if err == nil {
					t.Fatal("Execute() error = nil, want error")
				}
			} else if err != nil {
				t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
			}

			output := stdout.String()
			resp := decodeOneSandboxRuntimeStatusJSON(t, stdout.Bytes())
			tt.check(t, resp)
			us002AssertNoForbiddenRuntimeOutput(t, output+"\n"+stderr.String())
			if strings.Contains(output, "Sandbox runtime ") {
				t.Fatalf("runtime status JSON included human output: %s", output)
			}
		})
	}
}

func TestUS002SandboxRuntimeHumanOutputReportsModesReadinessAndSafeRemediation(t *testing.T) {
	setSandboxHostRegistryHome(t)
	if err := sandbox.SaveHost(us002RuntimeHostWithSecurity(
		"us002-human-blocked",
		us002BlockedSecureDefaultReadiness(),
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
	)); err != nil {
		t.Fatalf("SaveHost(blocked) error = %v", err)
	}
	if err := sandbox.SaveHost(us002RuntimeHostWithSecurity(
		"us002-human-allowed",
		us002ProofCompleteSecureDefaultReadiness(),
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
	)); err != nil {
		t.Fatalf("SaveHost(allowed) error = %v", err)
	}
	unsupported := us002RuntimeHostWithSecurity(
		"us002-human-unsupported",
		us002BlockedSecureDefaultReadiness(),
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility,
	)
	unsupported.Kind = sandbox.SandboxHostKindSSH
	unsupported.Endpoint = "ssh://alice:ghp_us002_token@runtime.internal.invalid:22/private?token=us002"
	if err := sandbox.SaveHost(unsupported); err != nil {
		t.Fatalf("SaveHost(unsupported) error = %v", err)
	}

	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "cached list strict blocked",
			args: []string{"list", "us002-human-blocked"},
			want: []string{
				"Sandbox runtimes for us002-human-blocked-builder (cached)",
				"cached durable runtime metadata",
				"Secure default readiness: strict blocked",
				"strict secure-default would block",
				"remediation=provide missing secure-default proof or configuration before strict mode",
			},
		},
		{
			name: "cached status strict allowed",
			args: []string{"status", "us002-human-allowed", sandbox.SandboxRuntimeDriverRootlessPodman},
			want: []string{
				"Sandbox runtime rootless_podman on us002-human-allowed-builder (cached)",
				"unknown (cached metadata confirms runtime registration; live readiness unknown)",
				"Secure default readiness: strict allowed",
				"proof-complete",
			},
		},
		{
			name: "unsupported live status compatibility advisory",
			args: []string{"status", "us002-human-unsupported", sandbox.SandboxRuntimeDriverRootlessPodman, "--live"},
			want: []string{
				"Sandbox runtime rootless_podman on us002-human-unsupported-builder (unsupported-live)",
				"live runtime inspection is unsupported for host kind ssh; using cached durable metadata",
				"Secure default readiness: compatibility advisory",
				"remediation=provide missing secure-default proof or configuration before strict mode",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cmd, stdout, stderr := newTestSandboxRuntimeCommand(us002RuntimeDepsNoWorker(t))
			cmd.SetArgs(tt.args)
			if err := cmd.Execute(); err != nil {
				t.Fatalf("Execute() error = %v; stderr=%q", err, stderr.String())
			}
			output := stdout.String()
			for _, want := range tt.want {
				if !strings.Contains(output, want) {
					t.Fatalf("stdout = %q, want %q", output, want)
				}
			}
			us002AssertNoForbiddenRuntimeOutput(t, output)
		})
	}
}

func us002RuntimeDepsNoWorker(t *testing.T) sandboxRuntimeDeps {
	t.Helper()
	deps := defaultSandboxRuntimeDeps()
	deps.newWorkerClient = func(string) (sandboxHostWorkerClient, error) {
		t.Fatal("US-002 runtime output tests must stay cached/fake-only and must not contact worker daemons")
		return nil, nil
	}
	return deps
}

func us002RuntimeHostWithSecurity(hostID string, readiness *sandbox.SandboxSecurityCapabilityReadinessOutput, mode sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode) *sandbox.SandboxHost {
	diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(*readiness)
	gate := sandbox.EvaluateSandboxSecurityCapabilityReadinessGate(mode, diagnostics)
	return &sandbox.SandboxHost{
		ID:                hostID,
		Name:              hostID + "-builder",
		Kind:              sandbox.SandboxHostKindWorker,
		Endpoint:          "unix:///tmp/us002-runtime.sock",
		SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
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

func us002BlockedSecureDefaultReadiness() *sandbox.SandboxSecurityCapabilityReadinessOutput {
	return &sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{
			us002MetadataOnlyCapability(
				sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
				sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
				sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly,
			),
			us002MetadataOnlyCapability(
				sandbox.SandboxSecurityCapabilityFamilySecretDelivery,
				sandbox.SandboxSecurityCapabilitySecretHTTPProxy,
				sandbox.SandboxSecurityCapabilityReasonCredentialActivationMissing,
			),
			us002BlockedCapability(
				sandbox.SandboxSecurityCapabilityFamilyWorkspace,
				sandbox.SandboxSecurityCapabilityDirectHostWorktree,
				sandbox.SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree,
			),
		},
	}
}

func us002ProofCompleteSecureDefaultReadiness() *sandbox.SandboxSecurityCapabilityReadinessOutput {
	return &sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{
			us002ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyIsolation, sandbox.SandboxSecurityCapabilityIsolationMicroVM, sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessConfirmed),
			us002ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyWorkspace, sandbox.SandboxSecurityCapabilityIsolatedWorkspace, sandbox.SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed),
			us002ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy, sandbox.SandboxSecurityCapabilityNetworkDenyByDefault, sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed),
			us002ReadyCapability(sandbox.SandboxSecurityCapabilityFamilySecretDelivery, sandbox.SandboxSecurityCapabilitySecretHTTPProxy, sandbox.SandboxSecurityCapabilityReasonCredentialActivationConfirmed),
			us002ReadyCapability(sandbox.SandboxSecurityCapabilityFamilyTemplate, sandbox.SandboxSecurityCapabilityTemplateLockDigest, sandbox.SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed),
		},
	}
}

func us002ReadyCapability(family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName, reason sandbox.SandboxSecurityCapabilityReasonCode) sandbox.SandboxSecurityCapabilityReadinessResult {
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

func us002MetadataOnlyCapability(family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName, reason sandbox.SandboxSecurityCapabilityReasonCode) sandbox.SandboxSecurityCapabilityReadinessResult {
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

func us002BlockedCapability(family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName, reason sandbox.SandboxSecurityCapabilityReasonCode) sandbox.SandboxSecurityCapabilityReadinessResult {
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

func us002AssertRuntimeListContract(t *testing.T, resp SandboxRuntimeListResponse) {
	t.Helper()
	if resp.ContractType != SandboxRuntimeListContractType || resp.ContractVersion != SandboxRuntimeListContractVersion {
		t.Fatalf("contract identity = %q/%q, want runtime list contract", resp.ContractType, resp.ContractVersion)
	}
	if strings.TrimSpace(resp.Source.Mode) == "" {
		t.Fatalf("source.mode is empty: %#v", resp.Source)
	}
}

func us002AssertRuntimeStatusContract(t *testing.T, resp SandboxRuntimeStatusResponse) {
	t.Helper()
	if resp.ContractType != SandboxRuntimeStatusContractType || resp.ContractVersion != SandboxRuntimeStatusContractVersion {
		t.Fatalf("contract identity = %q/%q, want runtime status contract", resp.ContractType, resp.ContractVersion)
	}
	if strings.TrimSpace(resp.Source.Mode) == "" {
		t.Fatalf("source.mode is empty: %#v", resp.Source)
	}
}

func us002AssertBlockedSecureDefaultSummary(t *testing.T, label string, security SandboxRuntimeSecuritySummary) {
	t.Helper()
	if security.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("%s capabilityReadinessDiagnostics = nil, want blocked diagnostics", label)
	}
	if !security.CapabilityReadinessDiagnostics.WouldBlockStrictGate {
		t.Fatalf("%s capabilityReadinessDiagnostics = %#v, want strict-blocking diagnostics", label, security.CapabilityReadinessDiagnostics)
	}
	if security.SecurityReadinessGate == nil {
		t.Fatalf("%s securityReadinessGate = nil, want strict blocked decision", label)
	}
	if security.SecurityReadinessGate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked ||
		security.SecurityReadinessGate.PolicyMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict {
		t.Fatalf("%s securityReadinessGate = %#v, want strict blocked decision", label, security.SecurityReadinessGate)
	}
	if security.SecurityReadinessGate.Counts == nil || security.SecurityReadinessGate.Counts.StrictBlocking == 0 {
		t.Fatalf("%s securityReadinessGate counts = %#v, want strict blocking counts", label, security.SecurityReadinessGate.Counts)
	}
}

func us002AssertNoForbiddenRuntimeOutput(t *testing.T, output string) {
	t.Helper()
	for _, forbidden := range []string{
		"unix:///tmp/us002-runtime.sock",
		"/tmp/us002-runtime.sock",
		"us002-runtime.sock",
		"us002-list-cached.sock",
		"us002-status-success.sock",
		"runtime.internal.invalid",
		"ghp_us002_token",
		"token=us002",
		"/private?token",
	} {
		if strings.Contains(output, forbidden) {
			t.Fatalf("runtime output leaked forbidden fragment %q:\n%s", forbidden, output)
		}
	}
}
