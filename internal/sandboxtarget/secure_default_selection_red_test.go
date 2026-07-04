package sandboxtarget

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/securedefaultfixtures"
)

func TestSelectStrictSecureDefaultRejectsMicroVMTargetWithoutCachedReadiness(t *testing.T) {
	target := strictSecureDefaultMicroVMSandbox("microvm-missing-readiness")
	host := strictSecureDefaultMicroVMHost()

	result := Select(Request{
		SandboxName:    target.Name,
		HostID:         host.ID,
		RuntimeDriver:  sandbox.SandboxRuntimeDriverMicroVM,
		IsolationLevel: sandbox.SandboxIsolationLevelVM,
		Fallback:       FallbackPolicy{Disabled: true},
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{host}, nil
		},
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loaded sandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
	})

	requireStrictSecureDefaultSelectionBlocked(t, result,
		strictSecureDefaultSafeReasons(
			string(sandbox.SandboxSecurityCapabilityReadinessGateReasonReadinessMissing),
			string(sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessMissing),
			string(sandbox.SandboxSecurityCapabilityReasonReadinessMissing),
		),
		strictSecureDefaultForbiddenFragments()...,
	)
}

func TestSelectStrictSecureDefaultRejectsCompatibilityTargetsInsteadOfSelectingThem(t *testing.T) {
	tests := []struct {
		name   string
		target *sandbox.SandboxState
		reason []string
	}{
		{
			name:   "ssh-machine compatibility",
			target: strictSecureDefaultCompatibilitySandbox("strict-ssh-compat", sandbox.SandboxRuntimeDriverSSHMachine, sandbox.SandboxIsolationLevelHost, nil, strictSecureDefaultMicroVMUnsupportedSecurity()),
			reason: strictSecureDefaultSafeReasons(
				string(sandbox.SandboxSecurityCapabilityReadinessGateReasonCapabilityUnsupported),
				string(sandbox.SandboxSecurityCapabilityReasonMicroVMSupportMissing),
			),
		},
		{
			name:   "rootless compatibility",
			target: strictSecureDefaultCompatibilitySandbox("strict-rootless-compat", sandbox.SandboxRuntimeDriverRootlessPodman, sandbox.SandboxIsolationLevelContainer, nil, strictSecureDefaultMicroVMUnsupportedSecurity()),
			reason: strictSecureDefaultSafeReasons(
				string(sandbox.SandboxSecurityCapabilityReadinessGateReasonCapabilityUnsupported),
				string(sandbox.SandboxSecurityCapabilityReasonMicroVMSupportMissing),
			),
		},
		{
			name: "direct-host workspace",
			target: strictSecureDefaultCompatibilitySandbox("strict-direct-workspace", sandbox.SandboxRuntimeDriverMicroVM, sandbox.SandboxIsolationLevelVM, &sandbox.SandboxWorkspace{
				Mode:        sandbox.SandboxWorkspaceModeDirect,
				InputSource: sandbox.SandboxWorkspaceInputSourceCopy,
				Repo:        "https://alice:ghp_strict_secret@example.test/org/private-repo.git",
				Branch:      "feature/direct-host",
				SyncRef:     "/Users/alice/private/worktree",
			}, strictSecureDefaultDirectWorkspaceBlockedSecurity()),
			reason: strictSecureDefaultSafeReasons(
				string(sandbox.SandboxSecurityCapabilityReadinessGateReasonCapabilityBlocked),
				string(sandbox.SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree),
			),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Select(Request{
				SandboxName: tt.target.Name,
				Fallback:    FallbackPolicy{Disabled: true},
			}, CachedState{
				LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
					if name != tt.target.Name {
						t.Fatalf("loaded sandbox name = %q, want %q", name, tt.target.Name)
					}
					return tt.target, nil
				},
			})

			requireStrictSecureDefaultSelectionBlocked(t, result, tt.reason, strictSecureDefaultForbiddenFragments()...)
		})
	}
}

func TestSelectStrictSecureDefaultDefaultSelectionAllowsProofCompleteRunningTarget(t *testing.T) {
	target := strictSecureDefaultProofCompleteSandbox("strict-ready-default")
	stopped := strictSecureDefaultProofCompleteSandbox("strict-stopped")
	stopped.Status = sandbox.StatusStopped

	result := Select(Request{
		SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		Fallback: FallbackPolicy{
			AllowDefaultRunningSandbox: true,
		},
	}, CachedState{
		LoadSandbox: func(string) (*sandbox.SandboxState, error) {
			t.Fatal("LoadSandbox should not run for strict cached default selection")
			return nil, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			return []*sandbox.SandboxState{stopped, target}, nil
		},
	})

	if result.Failed() || result.NeedsProvisioning() || result.Sandbox != target {
		var failureMessage string
		if result.Failure != nil {
			failureMessage = result.Failure.Error()
		}
		t.Fatalf("result = %#v failure = %q gate = %#v, want proof-complete running target selected without provisioning", result, failureMessage, result.SecurityReadinessGate)
	}
	if result.Source.Kind != SourceDefaultRunningSandbox {
		t.Fatalf("source = %#v, want default running sandbox", result.Source)
	}
	if result.SecurityReadinessGate == nil ||
		result.SecurityReadinessGate.PolicyMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict ||
		result.SecurityReadinessGate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed ||
		result.SecurityReadinessGate.Code != sandbox.SandboxSecurityCapabilityReadinessGateCodeAllowed {
		t.Fatalf("security readiness gate = %#v, want strict allowed decision", result.SecurityReadinessGate)
	}
}

func TestUS003SelectStrictSecureDefaultRejectsMissingOrWeakTargetSelectionProof(t *testing.T) {
	tests := []struct {
		name        string
		fixture     securedefaultfixtures.EvidenceSet
		wantReasons []string
	}{
		{
			name:    "missing strict target-selection proof",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(securedefaultfixtures.OmitProof(securedefaultfixtures.ProofStrictTargetSelection)),
			wantReasons: strictSecureDefaultSafeReasons(
				string(sandbox.SandboxSecurityCapabilityReadinessGateReasonPolicyOff),
				string(sandbox.SandboxSecurityCapabilityReadinessGateReasonReadinessMissing),
			),
		},
		{
			name:    "advisory-only target-selection metadata",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(securedefaultfixtures.DowngradeProof(securedefaultfixtures.ProofStrictTargetSelection, securedefaultfixtures.DowngradeAdvisory)),
			wantReasons: strictSecureDefaultSafeReasons(
				string(sandbox.SandboxSecurityCapabilityReadinessGateReasonPolicyAdvisory),
			),
		},
		{
			name:    "warning-bearing target-selection metadata",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(securedefaultfixtures.DowngradeProof(securedefaultfixtures.ProofStrictTargetSelection, securedefaultfixtures.DowngradeWarningBearing)),
			wantReasons: strictSecureDefaultSafeReasons(
				string(sandbox.SandboxSecurityCapabilityReasonWarningBearing),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := strictSecureDefaultFixtureSandbox("us003-"+strings.ReplaceAll(tt.name, " ", "-"), tt.fixture)

			result := Select(Request{
				SandboxName:               target.Name,
				SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
				Fallback:                  FallbackPolicy{Disabled: true},
			}, CachedState{
				LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
					if name != target.Name {
						t.Fatalf("loaded sandbox name = %q, want %q", name, target.Name)
					}
					return target, nil
				},
			})

			requireStrictSecureDefaultSelectionBlocked(t, result, tt.wantReasons, strictSecureDefaultForbiddenFragments()...)
		})
	}
}

func TestUS004SelectStrictSecureDefaultRejectsMissingOrWeakMicroVMReadinessProof(t *testing.T) {
	tests := []struct {
		name        string
		fixture     securedefaultfixtures.EvidenceSet
		wantReasons []string
	}{
		{
			name:    "missing microVM readiness evidence",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(securedefaultfixtures.OmitProof(securedefaultfixtures.ProofMicroVMReadiness)),
			wantReasons: strictSecureDefaultSafeReasons(
				string(sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessMissing),
			),
		},
		{
			name:    "planned microVM metadata",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(securedefaultfixtures.DowngradeProof(securedefaultfixtures.ProofMicroVMReadiness, securedefaultfixtures.DowngradePlanned)),
			wantReasons: strictSecureDefaultSafeReasons(
				string(sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessMissing),
			),
		},
		{
			name:    "compatibility microVM metadata",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(securedefaultfixtures.DowngradeProof(securedefaultfixtures.ProofMicroVMReadiness, securedefaultfixtures.DowngradeCompatibility)),
			wantReasons: strictSecureDefaultSafeReasons(
				string(sandbox.SandboxSecurityCapabilityReasonMicroVMSupportMissing),
			),
		},
		{
			name:    "fake-only microVM metadata",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(securedefaultfixtures.DowngradeProof(securedefaultfixtures.ProofMicroVMReadiness, securedefaultfixtures.DowngradeFakeOnly)),
			wantReasons: strictSecureDefaultSafeReasons(
				string(sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessMissing),
			),
		},
		{
			name:    "historical microVM metadata",
			fixture: securedefaultfixtures.CompleteAcceptedEvidenceSet(securedefaultfixtures.DowngradeProof(securedefaultfixtures.ProofMicroVMReadiness, securedefaultfixtures.DowngradeHistorical)),
			wantReasons: strictSecureDefaultSafeReasons(
				string(sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessMissing),
			),
		},
	}

	accepted := securedefaultfixtures.CompleteAcceptedEvidenceSet().Gate
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := strictSecureDefaultFixtureSandbox("us004-"+strings.ReplaceAll(tt.name, " ", "-"), tt.fixture)
			target.Security.SecurityReadinessGate = &accepted

			result := Select(Request{
				SandboxName:               target.Name,
				SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
				Fallback:                  FallbackPolicy{Disabled: true},
			}, CachedState{
				LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
					if name != target.Name {
						t.Fatalf("loaded sandbox name = %q, want %q", name, target.Name)
					}
					return target, nil
				},
			})

			requireStrictSecureDefaultSelectionBlocked(t, result, tt.wantReasons, strictSecureDefaultForbiddenFragments()...)
			requireStrictSecureDefaultSelectionBlockedBeforeAcceptedDecision(t, result, tt.wantReasons)
		})
	}
}

func TestSelectStrictSecureDefaultRejectsWarningBearingReadyEvidence(t *testing.T) {
	target := strictSecureDefaultCompatibilitySandbox(
		"strict-warning-ready",
		sandbox.SandboxRuntimeDriverRootlessPodman,
		sandbox.SandboxIsolationLevelContainer,
		nil,
		strictSecureDefaultWarningBearingReadySecurity(),
	)

	result := Select(Request{
		SandboxName: target.Name,
		Fallback:    FallbackPolicy{Disabled: true},
	}, CachedState{
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loaded sandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
	})

	requireStrictSecureDefaultSelectionBlocked(t, result,
		strictSecureDefaultSafeReasons(
			string(sandbox.SandboxSecurityCapabilityReasonWarningBearing),
		),
		strictSecureDefaultForbiddenFragments()...,
	)
}

func TestSelectStrictSecureDefaultRejectsUnsupportedRuntimeWithoutProvisioning(t *testing.T) {
	result := Select(Request{
		HostID:                    "compat-host",
		RuntimeDriver:             sandbox.SandboxRuntimeDriverMicroVM,
		SecurityReadinessGateMode: sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
		Project: ProjectContext{
			Branch:     "feature/strict-runtime",
			Repository: "https://alice:ghp_strict_secret@example.test/org/private-repo.git",
		},
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{{
				ID:                "compat-host",
				Name:              "compat host",
				Kind:              sandbox.SandboxHostKindWorker,
				Endpoint:          "ssh://deploy:secret@example.test/tmp/private/compat.sock?token=secret",
				SupportedRuntimes: []string{sandbox.SandboxRuntimeDriverRootlessPodman},
				Health:            &sandbox.HostHealth{Status: "healthy", Message: "token=secret"},
			}}, nil
		},
		ListSandboxes: func() ([]*sandbox.SandboxState, error) {
			t.Fatal("ListSandboxes should not run after unsupported strict runtime rejection")
			return nil, nil
		},
	})

	if result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want unsupported runtime rejection instead of provisioning", result)
	}
	if !result.Failed() {
		t.Fatalf("result = %#v, want unsupported runtime failure", result)
	}
	if result.Failure.Reason != FailureReasonRuntimeUnsupported {
		t.Fatalf("failure reason = %q, want %q", result.Failure.Reason, FailureReasonRuntimeUnsupported)
	}
	requireFailureOmitsFragments(t, result.Failure, strictSecureDefaultForbiddenFragments()...)
}

func TestSelectStrictSecureDefaultDoesNotPlanCompatibilityProvisioningForMissingMicroVMTarget(t *testing.T) {
	result := Select(Request{
		SandboxName:    "missing-microvm",
		RuntimeDriver:  sandbox.SandboxRuntimeDriverMicroVM,
		IsolationLevel: sandbox.SandboxIsolationLevelVM,
		Project: ProjectContext{
			Branch:     "feature/strict-microvm",
			Repository: "https://alice:ghp_strict_secret@example.test/org/private-repo.git",
		},
	}, CachedState{
		ListHosts: func() ([]*sandbox.SandboxHost, error) {
			return []*sandbox.SandboxHost{strictSecureDefaultMicroVMHost()}, nil
		},
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != "missing-microvm" {
				t.Fatalf("loaded sandbox name = %q, want missing-microvm", name)
			}
			return nil, fs.ErrNotExist
		},
	})

	if result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want strict secure-default failure instead of compatibility provisioning", result)
	}
	if !result.Failed() {
		t.Fatalf("result = %#v, want strict secure-default failure for missing microVM target", result)
	}
	if result.Failure.Reason != FailureReasonSandboxNotFound {
		t.Fatalf("failure reason = %q, want %q", result.Failure.Reason, FailureReasonSandboxNotFound)
	}
	requireFailureOmitsFragments(t, result.Failure, strictSecureDefaultForbiddenFragments()...)
}

func TestSelectCompatibilitySecureDefaultReadinessRemainsAdvisoryAndTruthful(t *testing.T) {
	target := strictSecureDefaultCompatibilitySandbox(
		"compat-rootless-advisory",
		sandbox.SandboxRuntimeDriverRootlessPodman,
		sandbox.SandboxIsolationLevelContainer,
		nil,
		strictSecureDefaultMicroVMUnsupportedSecurity(),
	)

	result := Select(Request{SandboxName: target.Name}, CachedState{
		LoadSandbox: func(name string) (*sandbox.SandboxState, error) {
			if name != target.Name {
				t.Fatalf("loaded sandbox name = %q, want %q", name, target.Name)
			}
			return target, nil
		},
	})

	if result.Failed() || result.Sandbox != target {
		t.Fatalf("result = %#v, want compatibility target selected with advisory readiness", result)
	}
	if result.Sandbox.Host == nil || result.Sandbox.Host.Security == nil ||
		result.Sandbox.Host.Security.CapabilityReadinessDiagnostics == nil {
		t.Fatalf("selected host security = %#v, want readiness diagnostics preserved", result.Sandbox.Host)
	}
	diagnostics := result.Sandbox.Host.Security.CapabilityReadinessDiagnostics
	if !diagnostics.AdvisoryOnly || !diagnostics.WouldBlockStrictGate {
		t.Fatalf("diagnostics = %#v, want advisory metadata that truthfully reports strict blocking", diagnostics)
	}
	decision := sandbox.EvaluateSandboxSecurityCapabilityReadinessGate(
		sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility,
		*diagnostics,
	)
	if decision.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAdvisory ||
		decision.Code != sandbox.SandboxSecurityCapabilityReadinessGateCodeAdvisory ||
		decision.Reason != sandbox.SandboxSecurityCapabilityReadinessGateReasonPolicyCompatibility {
		t.Fatalf("compatibility decision = %#v, want advisory non-blocking strict-readiness truth", decision)
	}
}

func requireStrictSecureDefaultSelectionBlocked(t *testing.T, result Result, wantReasons []string, forbidden ...string) {
	t.Helper()
	if result.NeedsProvisioning() {
		t.Fatalf("result = %#v, want strict secure-default rejection instead of provisioning fallback", result)
	}
	if !result.Failed() {
		t.Fatalf("result = %#v, want strict secure-default target-selection failure", result)
	}
	if result.Failure.Reason != FailureReasonIsolationUnavailable {
		t.Fatalf("failure reason = %q, want %q", result.Failure.Reason, FailureReasonIsolationUnavailable)
	}
	message := result.Failure.Error()
	if !strings.Contains(message, string(sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked)) {
		t.Fatalf("failure message = %q, want safe blocked code %q", message, sandbox.SandboxSecurityCapabilityReadinessGateCodeBlocked)
	}
	if !strictSecureDefaultMessageHasAnyReason(message, wantReasons) {
		t.Fatalf("failure message = %q, want one of safe reason codes %#v", message, wantReasons)
	}
	requireFailureOmitsFragments(t, result.Failure, forbidden...)
}

func strictSecureDefaultSafeReasons(reasons ...string) []string {
	return append([]string(nil), reasons...)
}

func strictSecureDefaultMessageHasAnyReason(message string, reasons []string) bool {
	for _, reason := range reasons {
		if strings.TrimSpace(reason) != "" && strings.Contains(message, reason) {
			return true
		}
	}
	return false
}

func requireFailureOmitsFragments(t *testing.T, failure *Failure, forbidden ...string) {
	t.Helper()
	if failure == nil {
		t.Fatal("failure = nil")
	}
	payload := strings.Join([]string{
		string(failure.Reason),
		failure.Error(),
		failure.SandboxName,
		failure.HostID,
		failure.RuntimeDriver,
		failure.IsolationLevel,
	}, "\n")
	for _, fragment := range forbidden {
		if strings.TrimSpace(fragment) == "" {
			continue
		}
		if strings.Contains(payload, fragment) {
			t.Fatalf("target-selection failure leaked %q: %s", fragment, payload)
		}
	}
}

func requireStrictSecureDefaultSelectionBlockedBeforeAcceptedDecision(t *testing.T, result Result, wantReasons []string) {
	t.Helper()
	if result.SecurityReadinessGate == nil {
		t.Fatal("security readiness gate = nil, want strict blocked decision")
	}
	if result.SecurityReadinessGate.Outcome == sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed ||
		result.SecurityReadinessGate.Code == sandbox.SandboxSecurityCapabilityReadinessGateCodeAllowed ||
		result.SecurityReadinessGate.Reason == sandbox.SandboxSecurityCapabilityReadinessGateReasonReadinessReady {
		t.Fatalf("security readiness gate = %#v, want MicroVM rejection before accepted decision", result.SecurityReadinessGate)
	}
	if result.SecurityReadinessGate.PolicyMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict ||
		result.SecurityReadinessGate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
		t.Fatalf("security readiness gate = %#v, want strict blocked decision", result.SecurityReadinessGate)
	}
	if result.SecurityReadinessGate.Counts == nil || result.SecurityReadinessGate.Counts.StrictBlocking == 0 {
		t.Fatalf("security readiness gate counts = %#v, want strict blocking count", result.SecurityReadinessGate.Counts)
	}
	message := targetSelectionReadinessGateFailureMessage(*result.SecurityReadinessGate)
	if !strictSecureDefaultMessageHasAnyReason(message, wantReasons) {
		t.Fatalf("security readiness gate message = %q, want one of safe reason codes %#v", message, wantReasons)
	}
}

func strictSecureDefaultMicroVMHost() *sandbox.SandboxHost {
	return &sandbox.SandboxHost{
		ID:       "microvm-host",
		Name:     "microvm host",
		Kind:     sandbox.SandboxHostKindLocal,
		Endpoint: "ssh://deploy:secret@example.test/tmp/private/microvm.sock?token=secret",
		SupportedRuntimes: []string{
			sandbox.SandboxRuntimeDriverMicroVM,
		},
		Health: &sandbox.HostHealth{Status: "healthy", Message: "token=secret"},
	}
}

func strictSecureDefaultMicroVMSandbox(name string) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		Name:     name,
		Provider: "local",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:       "microvm-host",
			Name:     "microvm host",
			Kind:     sandbox.SandboxHostKindLocal,
			Endpoint: "ssh://deploy:secret@example.test/tmp/private/microvm.sock?token=secret",
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverMicroVM,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "microvm-runtime-secret",
			Image:          "ghcr.io/private/raw-microvm-image:latest",
		},
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			Repo:        "https://alice:ghp_strict_secret@example.test/org/private-repo.git",
			Branch:      "feature/strict-microvm",
			SyncRef:     "/Users/alice/private/worktree",
		},
	}
}

func strictSecureDefaultProofCompleteSandbox(name string) *sandbox.SandboxState {
	target := strictSecureDefaultMicroVMSandbox(name)
	target.Status = sandbox.StatusRunning
	target.Security = strictSecureDefaultProofCompleteSecurity()
	target.Host.Security = nil
	return target
}

func strictSecureDefaultProofCompleteSecurity() *sandbox.SandboxSecurity {
	security := strictSecureDefaultSecurityFromReadiness(sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{
			strictSecureDefaultReadyResult(
				sandbox.SandboxSecurityCapabilityFamilyIsolation,
				sandbox.SandboxSecurityCapabilityIsolationMicroVM,
				"",
				sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessConfirmed,
			),
			strictSecureDefaultReadyResult(
				sandbox.SandboxSecurityCapabilityFamilyWorkspace,
				sandbox.SandboxSecurityCapabilityIsolatedWorkspace,
				"",
				sandbox.SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed,
			),
			strictSecureDefaultReadyResult(
				sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
				sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
				sandbox.SandboxNetworkEnforcementModeProxyFirewall,
				sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed,
			),
			strictSecureDefaultReadyResult(
				sandbox.SandboxSecurityCapabilityFamilySecretDelivery,
				sandbox.SandboxSecurityCapabilitySecretHTTPProxy,
				sandbox.SandboxSecretModeHTTPProxy,
				sandbox.SandboxSecurityCapabilityReasonCredentialActivationConfirmed,
			),
			strictSecureDefaultReadyResult(
				sandbox.SandboxSecurityCapabilityFamilyTemplate,
				sandbox.SandboxSecurityCapabilitySelectedTemplateTrust,
				"",
				sandbox.SandboxSecurityCapabilityReasonSelectedTemplateTrustConfirmed,
			),
		},
	})
	gate := sandbox.EvaluateSandboxSecureDefaultReadiness(*security.CapabilityReadiness)
	security.SecurityReadinessGate = &gate
	return security
}

func strictSecureDefaultFixtureSandbox(name string, fixture securedefaultfixtures.EvidenceSet) *sandbox.SandboxState {
	target := strictSecureDefaultMicroVMSandbox(name)
	security := fixture.Security()
	security.Network = nil
	security.Secrets = nil
	target.Security = security
	target.Host.Security = nil
	return target
}

func strictSecureDefaultWarningBearingReadySecurity() *sandbox.SandboxSecurity {
	result := strictSecureDefaultReadyResult(
		sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy,
		sandbox.SandboxSecurityCapabilityNetworkDenyByDefault,
		sandbox.SandboxNetworkEnforcementModeProxyFirewall,
		sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed,
	)
	result.WarningCodes = []sandbox.SandboxSecurityCapabilityWarningCode{
		sandbox.SandboxSecurityCapabilityWarningUnsupportedMode,
	}
	result.Ready.WarningCodes = []sandbox.SandboxSecurityCapabilityWarningCode{
		sandbox.SandboxSecurityCapabilityWarningBlockedByPolicy,
	}
	return strictSecureDefaultSecurityFromReadiness(sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{result},
	})
}

func strictSecureDefaultReadyResult(family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName, mode string, reason sandbox.SandboxSecurityCapabilityReasonCode) sandbox.SandboxSecurityCapabilityReadinessResult {
	return sandbox.SandboxSecurityCapabilityReadinessResult{
		State:      sandbox.SandboxSecurityCapabilityReadinessReady,
		ReasonCode: reason,
		Requested: &sandbox.SandboxSecurityCapabilityMetadata{
			Family:     family,
			Capability: capability,
			Mode:       mode,
			Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
		},
		Ready: &sandbox.SandboxSecurityCapabilityMetadata{
			Family:     family,
			Capability: capability,
			Mode:       mode,
			Source:     sandbox.SandboxSecurityCapabilitySourceRuntime,
			Status:     sandbox.SandboxSecurityCapabilityReadinessReady,
			ReasonCode: reason,
		},
	}
}

func strictSecureDefaultCompatibilitySandbox(name, runtimeDriver, isolationLevel string, workspace *sandbox.SandboxWorkspace, security *sandbox.SandboxSecurity) *sandbox.SandboxState {
	return &sandbox.SandboxState{
		Name:     name,
		Provider: "compat",
		Status:   sandbox.StatusRunning,
		Host: &sandbox.SandboxHost{
			ID:       "compat-host",
			Name:     "compat host",
			Kind:     sandbox.SandboxHostKindSSH,
			Endpoint: "ssh://deploy:secret@example.test/tmp/private/compat.sock?token=secret",
			Security: security,
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         runtimeDriver,
			IsolationLevel: isolationLevel,
			RuntimeID:      "compat-runtime-secret",
			Image:          "ghcr.io/private/raw-compat-image:latest",
		},
		Workspace: workspace,
		Security:  security,
	}
}

func strictSecureDefaultMicroVMUnsupportedSecurity() *sandbox.SandboxSecurity {
	return strictSecureDefaultSecurityFromReadiness(sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{
			{
				State: sandbox.SandboxSecurityCapabilityReadinessUnsupported,
				Requested: &sandbox.SandboxSecurityCapabilityMetadata{
					ID:         "requested-microvm-isolation",
					Family:     sandbox.SandboxSecurityCapabilityFamilyIsolation,
					Capability: sandbox.SandboxSecurityCapabilityIsolationMicroVM,
					Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
				},
				ReasonCode: sandbox.SandboxSecurityCapabilityReasonMicroVMSupportMissing,
			},
		},
	})
}

func strictSecureDefaultDirectWorkspaceBlockedSecurity() *sandbox.SandboxSecurity {
	return strictSecureDefaultSecurityFromReadiness(sandbox.SandboxSecurityCapabilityReadinessOutput{
		Results: []sandbox.SandboxSecurityCapabilityReadinessResult{
			{
				State: sandbox.SandboxSecurityCapabilityReadinessBlocked,
				Requested: &sandbox.SandboxSecurityCapabilityMetadata{
					ID:         "requested-isolated-workspace",
					Family:     sandbox.SandboxSecurityCapabilityFamilyWorkspace,
					Capability: sandbox.SandboxSecurityCapabilityIsolatedWorkspace,
					Source:     sandbox.SandboxSecurityCapabilitySourceRequested,
				},
				Ready: &sandbox.SandboxSecurityCapabilityMetadata{
					ID:         "direct-host-worktree",
					Family:     sandbox.SandboxSecurityCapabilityFamilyWorkspace,
					Capability: sandbox.SandboxSecurityCapabilityDirectHostWorktree,
					Source:     sandbox.SandboxSecurityCapabilitySourceMetadata,
					Status:     sandbox.SandboxSecurityCapabilityReadinessBlocked,
					ReasonCode: sandbox.SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree,
				},
				ReasonCode: sandbox.SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree,
			},
		},
	})
}

func strictSecureDefaultSecurityFromReadiness(readiness sandbox.SandboxSecurityCapabilityReadinessOutput) *sandbox.SandboxSecurity {
	sanitized := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(readiness)
	diagnostics := sandbox.DeriveSandboxSecurityCapabilityReadinessDiagnosticSummary(sanitized)
	return &sandbox.SandboxSecurity{
		CapabilityReadiness:            &sanitized,
		CapabilityReadinessDiagnostics: &diagnostics,
	}
}

func strictSecureDefaultForbiddenFragments() []string {
	return []string{
		"ssh://",
		"deploy:secret",
		"example.test",
		"token=secret",
		"ghp_strict_secret",
		"/tmp/private",
		"/Users/alice",
		"ghcr.io/private",
		"raw-microvm-image",
		"raw-compat-image",
		"microvm-runtime-secret",
		"compat-runtime-secret",
	}
}
