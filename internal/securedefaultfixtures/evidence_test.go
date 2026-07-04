package securedefaultfixtures

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestCompleteAcceptedEvidenceSetBuildsStrictAllowedReadiness(t *testing.T) {
	fixture := CompleteAcceptedEvidenceSet()

	if fixture.GateMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict || !fixture.StrictTargetSelection {
		t.Fatalf("target selection mode = %q strict=%t, want strict target selection", fixture.GateMode, fixture.StrictTargetSelection)
	}
	if fixture.Gate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed {
		t.Fatalf("gate outcome = %q, want allowed: %#v", fixture.Gate.Outcome, fixture.Gate)
	}
	if fixture.Gate.Counts == nil || fixture.Gate.Counts.Ready < 6 || fixture.Gate.Counts.StrictBlocking != 0 {
		t.Fatalf("gate counts = %#v, want proof-complete ready counts without strict blockers", fixture.Gate.Counts)
	}

	requireReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyIsolation, sandbox.SandboxSecurityCapabilityIsolationMicroVM, sandbox.SandboxSecurityCapabilityReasonMicroVMReadinessConfirmed)
	requireReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyWorkspace, sandbox.SandboxSecurityCapabilityIsolatedWorkspace, sandbox.SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed)
	requireReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy, sandbox.SandboxSecurityCapabilityNetworkDenyByDefault, sandbox.SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed)
	requireReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilySecretDelivery, sandbox.SandboxSecurityCapabilitySecretHTTPProxy, sandbox.SandboxSecurityCapabilityReasonCredentialActivationConfirmed)
	requireReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyTemplate, sandbox.SandboxSecurityCapabilityTemplateLockDigest, sandbox.SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed)
	requireReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyTemplate, sandbox.SandboxSecurityCapabilitySelectedTemplateTrust, sandbox.SandboxSecurityCapabilityReasonSelectedTemplateTrustConfirmed)

	if sanitized := sandbox.SanitizeSandboxSecurityCapabilityReadinessInput(fixture.Input); !reflect.DeepEqual(sanitized, fixture.Input) {
		t.Fatalf("fixture input is not sanitized:\ngot:  %#v\nwant: %#v", fixture.Input, sanitized)
	}
	if sanitized := sandbox.SanitizeSandboxSecurityCapabilityReadinessOutput(fixture.Readiness); !reflect.DeepEqual(sanitized, fixture.Readiness) {
		t.Fatalf("fixture output is not sanitized:\ngot:  %#v\nwant: %#v", fixture.Readiness, sanitized)
	}
	if validation := sandbox.ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(fixture.Input); !validation.Valid {
		t.Fatalf("fixture input validation errors = %#v", validation.Errors)
	}
}

func TestEvidenceSetCanOmitEachProofIndependently(t *testing.T) {
	tests := []struct {
		proof Proof
		check func(*testing.T, EvidenceSet)
	}{
		{
			proof: ProofStrictTargetSelection,
			check: func(t *testing.T, fixture EvidenceSet) {
				t.Helper()
				if fixture.GateMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeOff || fixture.StrictTargetSelection {
					t.Fatalf("target selection omitted mode = %q strict=%t, want off/non-strict", fixture.GateMode, fixture.StrictTargetSelection)
				}
			},
		},
		{
			proof: ProofMicroVMReadiness,
			check: func(t *testing.T, fixture EvidenceSet) {
				t.Helper()
				requireNoReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyIsolation, sandbox.SandboxSecurityCapabilityIsolationMicroVM)
			},
		},
		{
			proof: ProofWorkspaceIsolation,
			check: func(t *testing.T, fixture EvidenceSet) {
				t.Helper()
				requireNoReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyWorkspace, sandbox.SandboxSecurityCapabilityIsolatedWorkspace)
			},
		},
		{
			proof: ProofProxyFirewallEnforcement,
			check: func(t *testing.T, fixture EvidenceSet) {
				t.Helper()
				requireNoReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy, sandbox.SandboxSecurityCapabilityNetworkDenyByDefault)
			},
		},
		{
			proof: ProofCredentialDelivery,
			check: func(t *testing.T, fixture EvidenceSet) {
				t.Helper()
				requireNoReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilySecretDelivery, sandbox.SandboxSecurityCapabilitySecretHTTPProxy)
			},
		},
		{
			proof: ProofTemplateTrust,
			check: func(t *testing.T, fixture EvidenceSet) {
				t.Helper()
				requireNoReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyTemplate, sandbox.SandboxSecurityCapabilityTemplateLockDigest)
				requireNoReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyTemplate, sandbox.SandboxSecurityCapabilitySelectedTemplateTrust)
			},
		},
	}

	for _, tt := range tests {
		t.Run(string(tt.proof), func(t *testing.T) {
			fixture := CompleteAcceptedEvidenceSet(OmitProof(tt.proof))
			if got := fixture.ProofStates[tt.proof]; got != ProofStateOmitted {
				t.Fatalf("proof state = %q, want omitted", got)
			}
			if tt.proof != ProofStrictTargetSelection && fixture.Gate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
				t.Fatalf("gate outcome after omitting %s = %q, want blocked: %#v", tt.proof, fixture.Gate.Outcome, fixture.Gate)
			}
			tt.check(t, fixture)
			assertFixtureDataSafe(t, fixture)
		})
	}
}

func TestEvidenceSetCanDowngradeEachProofIndependently(t *testing.T) {
	tests := []struct {
		proof     Proof
		downgrade Downgrade
	}{
		{proof: ProofStrictTargetSelection, downgrade: DowngradeCompatibility},
		{proof: ProofMicroVMReadiness, downgrade: DowngradeUnsupported},
		{proof: ProofWorkspaceIsolation, downgrade: DowngradeBlocked},
		{proof: ProofProxyFirewallEnforcement, downgrade: DowngradeProxyOnly},
		{proof: ProofCredentialDelivery, downgrade: DowngradeMetadataOnly},
		{proof: ProofTemplateTrust, downgrade: DowngradeAdvisory},
	}

	for _, tt := range tests {
		t.Run(string(tt.proof), func(t *testing.T) {
			fixture := CompleteAcceptedEvidenceSet(DowngradeProof(tt.proof, tt.downgrade))
			if got := fixture.ProofStates[tt.proof]; got != ProofStateDowngraded {
				t.Fatalf("proof state = %q, want downgraded", got)
			}
			if tt.proof == ProofStrictTargetSelection {
				if fixture.GateMode != sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility || fixture.StrictTargetSelection {
					t.Fatalf("target selection downgrade mode = %q strict=%t, want compatibility/non-strict", fixture.GateMode, fixture.StrictTargetSelection)
				}
			} else if fixture.Gate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
				t.Fatalf("gate outcome after downgrading %s = %q, want blocked: %#v", tt.proof, fixture.Gate.Outcome, fixture.Gate)
			}
			assertFixtureDataSafe(t, fixture)
		})
	}
}

func TestTargetSelectionProofDowngradeVariantsStayWeak(t *testing.T) {
	tests := []struct {
		name       string
		downgrade  Downgrade
		wantMode   sandbox.SandboxSecurityCapabilityReadinessGatePolicyMode
		wantGate   sandbox.SandboxSecurityCapabilityReadinessGateOutcome
		wantReason sandbox.SandboxSecurityCapabilityReadinessGateReasonCode
	}{
		{
			name:       "compatibility",
			downgrade:  DowngradeCompatibility,
			wantMode:   sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeCompatibility,
			wantGate:   sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
			wantReason: sandbox.SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
		},
		{
			name:       "advisory",
			downgrade:  DowngradeAdvisory,
			wantMode:   sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeAdvisory,
			wantGate:   sandbox.SandboxSecurityCapabilityReadinessGateOutcomeAllowed,
			wantReason: sandbox.SandboxSecurityCapabilityReadinessGateReasonReadinessReady,
		},
		{
			name:       "warning bearing",
			downgrade:  DowngradeWarningBearing,
			wantMode:   sandbox.SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
			wantGate:   sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
			wantReason: sandbox.SandboxSecurityCapabilityReadinessGateReasonCode(sandbox.SandboxSecurityCapabilityReasonWarningBearing),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := CompleteAcceptedEvidenceSet(DowngradeProof(ProofStrictTargetSelection, tt.downgrade))
			if fixture.StrictTargetSelection {
				t.Fatalf("StrictTargetSelection = true, want false for %s target-selection proof", tt.downgrade)
			}
			if fixture.GateMode != tt.wantMode {
				t.Fatalf("GateMode = %q, want %q", fixture.GateMode, tt.wantMode)
			}
			if fixture.Gate.Outcome != tt.wantGate || fixture.Gate.Reason != tt.wantReason {
				t.Fatalf("Gate = %#v, want outcome=%s reason=%s", fixture.Gate, tt.wantGate, tt.wantReason)
			}
			assertFixtureDataSafe(t, fixture)
		})
	}
}

func TestNetworkProofDowngradeVariantsStayIncomplete(t *testing.T) {
	for _, downgrade := range []Downgrade{
		DowngradeProxyOnly,
		DowngradeFirewallOnly,
		DowngradeBestEffort,
		DowngradeUnsupported,
		DowngradeFailed,
		DowngradeWarningBearing,
	} {
		t.Run(string(downgrade), func(t *testing.T) {
			fixture := CompleteAcceptedEvidenceSet(DowngradeProof(ProofProxyFirewallEnforcement, downgrade))
			if fixture.Gate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
				t.Fatalf("gate outcome for network downgrade %s = %q, want blocked: %#v", downgrade, fixture.Gate.Outcome, fixture.Gate)
			}
			requireNoReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyNetworkPolicy, sandbox.SandboxSecurityCapabilityNetworkDenyByDefault)
			assertFixtureDataSafe(t, fixture)
		})
	}
}

func TestMicroVMProofDowngradeVariantsStayIncomplete(t *testing.T) {
	for _, downgrade := range []Downgrade{
		DowngradePlanned,
		DowngradeCompatibility,
		DowngradeFakeOnly,
		DowngradeHistorical,
		DowngradeUnsupported,
		DowngradeWarningBearing,
	} {
		t.Run(string(downgrade), func(t *testing.T) {
			fixture := CompleteAcceptedEvidenceSet(DowngradeProof(ProofMicroVMReadiness, downgrade))
			if fixture.Gate.Outcome != sandbox.SandboxSecurityCapabilityReadinessGateOutcomeBlocked {
				t.Fatalf("gate outcome for microVM downgrade %s = %q, want blocked: %#v", downgrade, fixture.Gate.Outcome, fixture.Gate)
			}
			requireNoReadyResult(t, fixture.Readiness, sandbox.SandboxSecurityCapabilityFamilyIsolation, sandbox.SandboxSecurityCapabilityIsolationMicroVM)
			assertFixtureDataSafe(t, fixture)
		})
	}
}

func TestFixtureDataContainsOnlySanitizedEvidenceMetadata(t *testing.T) {
	fixtures := []EvidenceSet{
		CompleteAcceptedEvidenceSet(),
		CompleteAcceptedEvidenceSet(OmitProof(ProofMicroVMReadiness)),
		CompleteAcceptedEvidenceSet(DowngradeProof(ProofProxyFirewallEnforcement, DowngradeFirewallOnly)),
		CompleteAcceptedEvidenceSet(DowngradeProof(ProofCredentialDelivery, DowngradeWarningBearing)),
		CompleteAcceptedEvidenceSet(DowngradeProof(ProofTemplateTrust, DowngradeBlocked)),
	}
	for i, fixture := range fixtures {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			assertFixtureDataSafe(t, fixture)
			security := fixture.Security()
			if security.CapabilityReadiness == nil || security.CapabilityReadinessDiagnostics == nil || security.SecurityReadinessGate == nil {
				t.Fatalf("security fixture missing readiness surfaces: %#v", security)
			}
			assertFixtureDataSafe(t, security)
		})
	}
}

func requireReadyResult(t *testing.T, output sandbox.SandboxSecurityCapabilityReadinessOutput, family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName, reason sandbox.SandboxSecurityCapabilityReasonCode) {
	t.Helper()
	for _, result := range output.Results {
		if result.State != sandbox.SandboxSecurityCapabilityReadinessReady || result.Ready == nil {
			continue
		}
		if result.Ready.Family == family && result.Ready.Capability == capability && result.ReasonCode == reason {
			return
		}
	}
	t.Fatalf("readiness output missing ready %s/%s reason %s: %#v", family, capability, reason, output.Results)
}

func requireNoReadyResult(t *testing.T, output sandbox.SandboxSecurityCapabilityReadinessOutput, family sandbox.SandboxSecurityCapabilityFamily, capability sandbox.SandboxSecurityCapabilityName) {
	t.Helper()
	for _, result := range output.Results {
		if result.State == sandbox.SandboxSecurityCapabilityReadinessReady &&
			result.Ready != nil &&
			result.Ready.Family == family &&
			result.Ready.Capability == capability {
			t.Fatalf("readiness output has unexpected ready %s/%s: %#v", family, capability, result)
		}
	}
}

func assertFixtureDataSafe(t *testing.T, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	payload := string(data)
	for _, forbidden := range []string{
		"://",
		"/Users/",
		"/private/",
		".sock",
		"Authorization",
		"Bearer",
		"raw-",
		"ghp_",
		"github_pat_",
		"GITHUB_TOKEN",
		"SERVICE_TOKEN",
		"token=",
		"credential_value",
		"secret_value",
		"iptables",
		"nft ",
		"ghcr.io",
		"registry",
		"template.yaml",
		"provider",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("fixture payload leaked forbidden fragment %q: %s", forbidden, payload)
		}
	}
}
