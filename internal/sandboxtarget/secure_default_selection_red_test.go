package sandboxtarget

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
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
