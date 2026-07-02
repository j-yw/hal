package sandbox

import (
	"reflect"
	"testing"
)

func TestProjectSandboxSecurityCapabilityReadinessInputNilAndEmpty(t *testing.T) {
	tests := []struct {
		name     string
		security *SandboxSecurity
	}{
		{name: "nil security", security: nil},
		{name: "empty security", security: &SandboxSecurity{}},
		{name: "empty nested security", security: &SandboxSecurity{
			Network: &SandboxNetworkSecurity{},
			Secrets: &SandboxSecretSecurity{},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ProjectSandboxSecurityCapabilityReadinessInput(tt.security)
			if !reflect.DeepEqual(got, SandboxSecurityCapabilityReadinessInput{}) {
				t.Fatalf("projected input = %#v, want empty readiness input", got)
			}
			validation := ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(got)
			if !validation.Valid {
				t.Fatalf("projected input validation errors = %#v, want valid", validation.Errors)
			}
			output := EvaluateSandboxSecurityCapabilityReadiness(got)
			if len(output.Results) != 0 {
				t.Fatalf("readiness output results = %#v, want none", output.Results)
			}
		})
	}
}

func TestProjectSandboxSecurityCapabilityReadinessInputCompatibilityOnly(t *testing.T) {
	security := EvaluateSSHMachineCompatibilitySecurity(SecurityEvaluationRequest{
		RuntimeDriver:          SandboxRuntimeDriverSSHMachine,
		RequestedNetworkPolicy: SandboxNetworkPolicyDenyByDefault,
		RequestedSecretModes:   []string{SandboxSecretModeHTTPProxy},
		CompatibilityAuthSync:  true,
	})

	got := ProjectSandboxSecurityCapabilityReadinessInput(security)
	assertProjectedSecurityCapabilityMetadata(t, got.Requested, []SandboxSecurityCapabilityMetadata{
		{
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
		{
			Family:     SandboxSecurityCapabilityFamilySecretDelivery,
			Capability: SandboxSecurityCapabilitySecretHTTPProxy,
			Mode:       SandboxSecretModeHTTPProxy,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
	})
	if len(got.Ready) != 0 {
		t.Fatalf("projected ready metadata = %#v, want none for compatibility-only summaries", got.Ready)
	}
	validation := ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(got)
	if !validation.Valid {
		t.Fatalf("projected input validation errors = %#v, want valid", validation.Errors)
	}

	output := EvaluateSandboxSecurityCapabilityReadiness(got)
	if len(output.Results) != len(got.Requested) {
		t.Fatalf("readiness output result count = %d, want %d: %#v", len(output.Results), len(got.Requested), output.Results)
	}
	assertSecurityCapabilityUnsupportedResult(t, output.Results[0],
		SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityNetworkDenyByDefault,
		"",
		SandboxSecurityCapabilityReasonCapabilityMissing,
	)
	assertSecurityCapabilityUnsupportedResult(t, output.Results[1],
		SandboxSecurityCapabilityFamilySecretDelivery,
		SandboxSecurityCapabilitySecretHTTPProxy,
		SandboxSecretModeHTTPProxy,
		SandboxSecurityCapabilityReasonCapabilityMissing,
	)
}

func TestProjectSandboxSecurityCapabilityReadinessInputExplicitSafeMetadata(t *testing.T) {
	security := &SandboxSecurity{
		Network: &SandboxNetworkSecurity{
			PolicyRequested: SandboxNetworkPolicyDenyByDefault,
			PolicyEnforced:  SandboxNetworkPolicyDenyByDefault,
			EnforcementMode: SandboxNetworkEnforcementModeFirewall,
		},
		Secrets: &SandboxSecretSecurity{
			RequestedModes: []string{
				" " + SandboxSecretModeFileTmpfs + " ",
				SandboxSecretModeHTTPProxy,
				"token=raw-secret",
			},
			ActiveModes: []string{
				SandboxSecretModeFileTmpfs,
				SandboxSecretModeEnv,
				SandboxSecretModeFileTmpfs,
				SandboxSecretModeLegacyAuthSync,
			},
		},
	}

	got := ProjectSandboxSecurityCapabilityReadinessInput(security)
	assertProjectedSecurityCapabilityMetadata(t, got.Requested, []SandboxSecurityCapabilityMetadata{
		{
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
		{
			Family:     SandboxSecurityCapabilityFamilySecretDelivery,
			Capability: SandboxSecurityCapabilitySecretFileTmpfs,
			Mode:       SandboxSecretModeFileTmpfs,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
		{
			Family:     SandboxSecurityCapabilityFamilySecretDelivery,
			Capability: SandboxSecurityCapabilitySecretHTTPProxy,
			Mode:       SandboxSecretModeHTTPProxy,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
	})
	assertProjectedSecurityCapabilityMetadata(t, got.Ready, []SandboxSecurityCapabilityMetadata{
		{
			Family:       SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability:   SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:         SandboxNetworkEnforcementModeFirewall,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
		{
			Family:       SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability:   SandboxSecurityCapabilityNetworkFirewallEnforcement,
			Mode:         SandboxNetworkEnforcementModeFirewall,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
		{
			Family:       SandboxSecurityCapabilityFamilySecretDelivery,
			Capability:   SandboxSecurityCapabilitySecretFileTmpfs,
			Mode:         SandboxSecretModeFileTmpfs,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
		{
			Family:       SandboxSecurityCapabilityFamilySecretDelivery,
			Capability:   SandboxSecurityCapabilitySecretEnv,
			Mode:         SandboxSecretModeEnv,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
	})
	validation := ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(got)
	if !validation.Valid {
		t.Fatalf("projected input validation errors = %#v, want valid", validation.Errors)
	}
	assertSecurityCapabilityJSONExcludes(t, got, "token=raw-secret", string(SandboxSecretModeLegacyAuthSync))

	output := EvaluateSandboxSecurityCapabilityReadiness(got)
	if len(output.Results) != len(got.Requested) {
		t.Fatalf("readiness output result count = %d, want %d: %#v", len(output.Results), len(got.Requested), output.Results)
	}
	for i, result := range output.Results {
		if result.State == SandboxSecurityCapabilityReadinessReady {
			t.Fatalf("projected metadata-only summary produced ready result[%d]: %#v", i, result)
		}
	}
}

func TestProjectSandboxSecurityCapabilityReadinessInputProjectsPolicyResultWithoutRuleValues(t *testing.T) {
	policyResult := EvaluateSandboxNetworkPolicy(
		SandboxNetworkPolicyIntent{
			Preset: SandboxNetworkPolicyPresetAllowListed,
			Rules: []SandboxNetworkPolicyRule{{
				Kind:     SandboxNetworkPolicyRuleKindDomain,
				Value:    "api.github.example.invalid",
				Decision: SandboxNetworkPolicyDecisionAllow,
			}},
		},
		SandboxNetworkPolicyEnforcementCapability{
			Supported:                  true,
			Modes:                      []string{SandboxNetworkEnforcementModeFirewall},
			SupportsDomainRules:        true,
			SupportsDefaultDenyPosture: true,
		},
	)
	security := &SandboxSecurity{
		Network: &SandboxNetworkSecurity{
			PolicyResult: &policyResult,
		},
	}

	got := ProjectSandboxSecurityCapabilityReadinessInput(security)
	assertProjectedSecurityCapabilityMetadata(t, got.Requested, []SandboxSecurityCapabilityMetadata{{
		Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
		Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
		Source:     SandboxSecurityCapabilitySourceRequested,
	}})
	assertProjectedSecurityCapabilityMetadata(t, got.Ready, []SandboxSecurityCapabilityMetadata{
		{
			Family:       SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability:   SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:         SandboxNetworkEnforcementModeFirewall,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
		{
			Family:       SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability:   SandboxSecurityCapabilityNetworkFirewallEnforcement,
			Mode:         SandboxNetworkEnforcementModeFirewall,
			Source:       SandboxSecurityCapabilitySourceMetadata,
			Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
			ReasonCode:   SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
			WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
		},
	})
	validation := ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(got)
	if !validation.Valid {
		t.Fatalf("projected input validation errors = %#v, want valid", validation.Errors)
	}
	assertSecurityCapabilityJSONExcludes(t, got, "api.github.example.invalid")

	output := EvaluateSandboxSecurityCapabilityReadiness(got)
	if len(output.Results) != 1 {
		t.Fatalf("readiness output result count = %d, want 1: %#v", len(output.Results), output.Results)
	}
	assertSecurityCapabilityUnsupportedResult(t, output.Results[0],
		SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityNetworkDenyByDefault,
		"",
		SandboxSecurityCapabilityReasonCapabilityMissing,
	)
}

func TestProjectSandboxPolicyProxyCredentialCapabilityReadinessInputMetadataOnlyNotReady(t *testing.T) {
	enforced := true
	got := ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput(SandboxPolicyProxyCredentialCapabilityReadinessProjection{
		NetworkProxySession: &SandboxNetworkProxySessionMetadata{
			ID:     "network-proxy-session-01",
			Source: SandboxNetworkPolicyDecisionSourceRun,
			PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
				ID:     "policy-snapshot-01",
				Preset: SandboxNetworkPolicyPresetDenyByDefault,
			},
			EnforcementMode: SandboxNetworkEnforcementModeProxy,
		},
		NetworkPolicyDecisionLogs: []SandboxNetworkPolicyDecisionLogRecord{{
			ID:             "decision-log-01",
			Source:         SandboxNetworkPolicyDecisionSourceRun,
			ProxySessionID: "network-proxy-session-01",
			Request: &SandboxNetworkPolicyRequestSummary{
				ID:                  "request-01",
				Operation:           "connect",
				DestinationCategory: SandboxNetworkPolicyDestinationMetadataService,
			},
			Outcome:         SandboxNetworkPolicyDecisionOutcomeDenied,
			ReasonCode:      SandboxNetworkPolicyDecisionReasonDefaultDeny,
			PolicyPreset:    SandboxNetworkPolicyPresetDenyByDefault,
			EnforcementMode: SandboxNetworkEnforcementModeProxy,
			Enforced:        &enforced,
		}},
		CredentialProxyPlan: &SandboxCredentialProxyPlanMetadata{
			ID:                    "credential-proxy-plan-01",
			Source:                SandboxCredentialProxySourceRun,
			SecretBrokerSessionID: "secret-broker-session-01",
			NetworkProxySessionID: "network-proxy-session-01",
			BindingCount:          1,
			Mode:                  SandboxCredentialProxyModeBrokeredNetworkReference,
			Status:                SandboxCredentialProxyStatusReady,
		},
		CredentialProxySession: &SandboxCredentialProxySessionMetadata{
			ID:                    "credential-proxy-session-01",
			PlanID:                "credential-proxy-plan-01",
			Source:                SandboxCredentialProxySourceRun,
			SecretBrokerSessionID: "secret-broker-session-01",
			NetworkProxySessionID: "network-proxy-session-01",
			Status:                SandboxCredentialProxyStatusActive,
			ReasonCode:            SandboxCredentialProxyReasonRequested,
		},
		CredentialProxyBindings: []SandboxCredentialProxyBindingMetadata{{
			ID:                  "credential-proxy-binding-01",
			PlanID:              "credential-proxy-plan-01",
			SessionID:           "credential-proxy-session-01",
			SecretID:            "env:GITHUB_TOKEN",
			DeliveryMode:        SandboxCredentialProxyDeliveryModeHTTPProxy,
			RequestCategory:     SandboxCredentialProxyRequestSourceControl,
			DestinationCategory: SandboxNetworkPolicyDestinationPublicInternet,
			Outcome:             SandboxCredentialProxyBindingOutcomeBound,
			Status:              SandboxCredentialProxyStatusReady,
			ReasonCode:          SandboxCredentialProxyReasonRequested,
		}},
	})

	if got.NetworkProxySession == nil || got.NetworkProxySession.ID != "network-proxy-session-01" {
		t.Fatalf("network proxy session = %#v, want sanitized session metadata", got.NetworkProxySession)
	}
	if len(got.NetworkPolicyDecisionLogs) != 1 {
		t.Fatalf("network policy decision logs = %#v, want one sanitized record", got.NetworkPolicyDecisionLogs)
	}
	if got.CredentialProxyPlan == nil || got.CredentialProxySession == nil || len(got.CredentialProxyBindings) != 1 {
		t.Fatalf("credential proxy metadata = %#v/%#v/%#v, want plan/session/binding", got.CredentialProxyPlan, got.CredentialProxySession, got.CredentialProxyBindings)
	}
	validation := ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(got)
	if !validation.Valid {
		t.Fatalf("projected input validation errors = %#v, want valid", validation.Errors)
	}

	output := EvaluateSandboxSecurityCapabilityReadiness(got)
	if len(output.Results) != 5 {
		t.Fatalf("readiness output result count = %d, want 5: %#v", len(output.Results), output.Results)
	}
	assertSecurityCapabilityMetadataOnlyResult(t, output.Results[0],
		SandboxSecurityCapabilityFamilyNetworkProxy,
		SandboxSecurityCapabilityNetworkProxyEnforcement,
		SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
	)
	assertSecurityCapabilityMetadataOnlyResult(t, output.Results[1],
		SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityNetworkDenyByDefault,
		SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
	)
	for i, result := range output.Results[2:] {
		if result.State == SandboxSecurityCapabilityReadinessReady {
			t.Fatalf("credential proxy metadata-only result[%d] inferred ready: %#v", i+2, result)
		}
		assertSecurityCapabilityMetadataOnlyResult(t, result,
			SandboxSecurityCapabilityFamilyCredentialProxy,
			SandboxSecurityCapabilityCredentialProxy,
			SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
		)
	}
}

func TestProjectSandboxPolicyProxyCredentialCapabilityReadinessInputRequiresExplicitReadyMetadata(t *testing.T) {
	got := ProjectSandboxPolicyProxyCredentialCapabilityReadinessInput(SandboxPolicyProxyCredentialCapabilityReadinessProjection{
		Requested: []SandboxSecurityCapabilityMetadata{{
			Family:     SandboxSecurityCapabilityFamilyCredentialProxy,
			Capability: SandboxSecurityCapabilityCredentialProxy,
			Mode:       string(SandboxCredentialProxyModeBrokeredNetworkReference),
			Source:     SandboxSecurityCapabilitySourceRequested,
		}},
		Ready: []SandboxSecurityCapabilityMetadata{{
			Family:     SandboxSecurityCapabilityFamilyCredentialProxy,
			Capability: SandboxSecurityCapabilityCredentialProxy,
			Mode:       string(SandboxCredentialProxyModeBrokeredNetworkReference),
			Source:     SandboxSecurityCapabilitySourceWorker,
			Status:     SandboxSecurityCapabilityReadinessReady,
			ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
		}},
		CredentialProxyPlan: &SandboxCredentialProxyPlanMetadata{
			ID:                    "credential-proxy-plan-01",
			Source:                SandboxCredentialProxySourceWorker,
			SecretBrokerSessionID: "secret-broker-session-01",
			NetworkProxySessionID: "network-proxy-session-01",
			BindingCount:          1,
			Mode:                  SandboxCredentialProxyModeBrokeredNetworkReference,
			Status:                SandboxCredentialProxyStatusReady,
		},
	})

	output := EvaluateSandboxSecurityCapabilityReadiness(got)
	if len(output.Results) != 2 {
		t.Fatalf("readiness output result count = %d, want 2: %#v", len(output.Results), output.Results)
	}
	assertSecurityCapabilityReadyResult(t, output.Results[0],
		SandboxSecurityCapabilityFamilyCredentialProxy,
		SandboxSecurityCapabilityCredentialProxy,
		string(SandboxCredentialProxyModeBrokeredNetworkReference),
		SandboxSecurityCapabilitySourceWorker,
	)
	assertSecurityCapabilityMetadataOnlyResult(t, output.Results[1],
		SandboxSecurityCapabilityFamilyCredentialProxy,
		SandboxSecurityCapabilityCredentialProxy,
		SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
	)
}

func TestProjectSandboxWorkerRuntimeCapabilityReadinessInputRootlessMetadataOnly(t *testing.T) {
	got := ProjectSandboxWorkerRuntimeCapabilityReadinessInput(SandboxWorkerRuntimeCapabilityReadinessProjection{
		Host: &SandboxHost{
			Kind: SandboxHostKindWorker,
			Security: &SandboxSecurity{
				Network: &SandboxNetworkSecurity{
					PolicyEnforced:  SandboxNetworkPolicyBestEffort,
					EnforcementMode: SandboxNetworkEnforcementModeNone,
				},
				Secrets: &SandboxSecretSecurity{
					ActiveModes: []string{SandboxSecretModeFileTmpfs, SandboxSecretModeFileTmpfs, "token=raw-secret"},
				},
			},
		},
		Runtime: &SandboxRuntimeState{
			Driver:         " " + SandboxRuntimeDriverRootlessPodman + " ",
			IsolationLevel: SandboxIsolationLevelContainer,
			RuntimeID:      "runtime-01",
			Image:          "ghcr.io/jywlabs/hal-worker:latest",
			WorkerID:       "worker-01",
		},
	})

	assertProjectedSecurityCapabilityWorkerPostures(t, got.WorkerPostures, []SandboxSecurityCapabilityWorkerPostureMetadata{{
		WorkerKind:         SandboxHostKindWorker,
		RuntimeDriver:      SandboxRuntimeDriverRootlessPodman,
		IsolationLevel:     SandboxIsolationLevelContainer,
		NetworkPolicy:      SandboxNetworkPolicyBestEffort,
		NetworkEnforcement: SandboxNetworkEnforcementModeNone,
		CredentialModes:    []string{SandboxSecretModeFileTmpfs},
	}})
	if len(got.Ready) != 0 {
		t.Fatalf("projected ready metadata = %#v, want none for rootless posture", got.Ready)
	}
	validation := ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(got)
	if !validation.Valid {
		t.Fatalf("projected input validation errors = %#v, want valid", validation.Errors)
	}
	assertSecurityCapabilityJSONExcludes(t, got, "runtime-01", "ghcr.io", "worker-01", "token=raw-secret")

	output := EvaluateSandboxSecurityCapabilityReadiness(got)
	if len(output.Results) != 2 {
		t.Fatalf("readiness output result count = %d, want 2: %#v", len(output.Results), output.Results)
	}
	assertSecurityCapabilityMetadataOnlyResult(t, output.Results[0],
		SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityNetworkDenyByDefault,
		SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
	)
	assertSecurityCapabilityMetadataOnlyResult(t, output.Results[1],
		SandboxSecurityCapabilityFamilySecretDelivery,
		SandboxSecurityCapabilitySecretFileTmpfs,
		SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
	)
}

func TestProjectSandboxWorkerRuntimeCapabilityReadinessInputCompatibilityUnsupportedWithoutReady(t *testing.T) {
	security := EvaluateSSHMachineCompatibilitySecurity(SecurityEvaluationRequest{
		RuntimeDriver:          SandboxRuntimeDriverSSHMachine,
		RequestedNetworkPolicy: SandboxNetworkPolicyDenyByDefault,
		RequestedSecretModes:   []string{SandboxSecretModeHTTPProxy},
		CompatibilityAuthSync:  true,
	})
	securityInput := ProjectSandboxSecurityCapabilityReadinessInput(security)
	got := ProjectSandboxWorkerRuntimeCapabilityReadinessInput(SandboxWorkerRuntimeCapabilityReadinessProjection{
		Host: &SandboxHost{
			Kind:     SandboxHostKindSSH,
			Security: security,
		},
		Runtime: &SandboxRuntimeState{
			Driver:         SandboxRuntimeDriverSSHMachine,
			IsolationLevel: SandboxIsolationLevelHost,
		},
	})
	got.Requested = securityInput.Requested

	output := EvaluateSandboxSecurityCapabilityReadiness(got)
	if len(output.Results) != len(got.Requested)+1 {
		t.Fatalf("readiness output result count = %d, want %d: %#v", len(output.Results), len(got.Requested)+1, output.Results)
	}
	for i, result := range output.Results[:len(got.Requested)] {
		if result.State == SandboxSecurityCapabilityReadinessReady {
			t.Fatalf("result[%d] inferred ready from compatibility posture: %#v", i, result)
		}
		assertSecurityCapabilityUnsupportedResult(t, result,
			got.Requested[i].Family,
			got.Requested[i].Capability,
			got.Requested[i].Mode,
			SandboxSecurityCapabilityReasonCapabilityMissing,
		)
	}
	assertSecurityCapabilityMetadataOnlyResult(t, output.Results[len(got.Requested)],
		SandboxSecurityCapabilityFamilyNetworkPolicy,
		SandboxSecurityCapabilityNetworkDenyByDefault,
		SandboxSecurityCapabilityReasonMetadataEnforcementUnproven,
	)
}

func TestProjectSandboxWorkerRuntimeCapabilityReadinessInputExplicitReadyMetadata(t *testing.T) {
	requested := SandboxSecurityCapabilityMetadata{
		Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
		Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
		Mode:       SandboxNetworkEnforcementModeFirewall,
		Source:     SandboxSecurityCapabilitySourceRequested,
	}
	for _, source := range []SandboxSecurityCapabilitySource{
		SandboxSecurityCapabilitySourceRuntime,
		SandboxSecurityCapabilitySourceWorker,
	} {
		t.Run(string(source), func(t *testing.T) {
			got := ProjectSandboxWorkerRuntimeCapabilityReadinessInput(SandboxWorkerRuntimeCapabilityReadinessProjection{
				Runtime: &SandboxRuntimeState{
					Driver:         SandboxRuntimeDriverRootlessPodman,
					IsolationLevel: SandboxIsolationLevelContainer,
				},
				Ready: []SandboxSecurityCapabilityMetadata{{
					Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
					Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
					Mode:       SandboxNetworkEnforcementModeFirewall,
					Source:     source,
					Status:     SandboxSecurityCapabilityReadinessReady,
					ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
				}},
			})
			got.Requested = []SandboxSecurityCapabilityMetadata{requested}

			output := EvaluateSandboxSecurityCapabilityReadiness(got)
			if len(output.Results) != 1 {
				t.Fatalf("readiness output result count = %d, want 1: %#v", len(output.Results), output.Results)
			}
			assertSecurityCapabilityReadyResult(t, output.Results[0],
				SandboxSecurityCapabilityFamilyNetworkPolicy,
				SandboxSecurityCapabilityNetworkDenyByDefault,
				SandboxNetworkEnforcementModeFirewall,
				source,
			)
		})
	}
}

func TestProjectSandboxWorkerRuntimeCapabilityReadinessInputCopiesOnlySafeLabels(t *testing.T) {
	got := ProjectSandboxWorkerRuntimeCapabilityReadinessInput(SandboxWorkerRuntimeCapabilityReadinessProjection{
		Host: &SandboxHost{
			ID:       "worker-01",
			Name:     "worker-one",
			Kind:     SandboxHostKindWorker,
			Endpoint: "unix:///tmp/raw-worker.sock",
			Security: &SandboxSecurity{
				Network: &SandboxNetworkSecurity{
					PolicyEnforced:  SandboxNetworkPolicyDenyByDefault,
					EnforcementMode: "http://127.0.0.1:3128",
				},
				Secrets: &SandboxSecretSecurity{
					ActiveModes: []string{SandboxSecretModeFileTmpfs, "/tmp/secret"},
				},
			},
		},
		Runtime: &SandboxRuntimeState{
			Driver:         SandboxRuntimeDriverRootlessPodman,
			IsolationLevel: "/tmp/vm",
			RuntimeID:      "container-01",
			Image:          "ghcr.io/private/runtime:latest?token=secret",
			WorkerID:       "worker@example.internal",
		},
		WorkerRouting: &WorkerRoutingMetadata{
			SelectedWorkerHostID:   "worker-01",
			SelectedWorkerHostName: "worker-one",
			RuntimeDriverID:        "unix:///tmp/podman.sock",
			IsolationLevel:         SandboxIsolationLevelContainer,
			EndpointSummary:        "/tmp/podman.sock",
		},
	})

	assertProjectedSecurityCapabilityWorkerPostures(t, got.WorkerPostures, []SandboxSecurityCapabilityWorkerPostureMetadata{{
		WorkerKind:      SandboxHostKindWorker,
		RuntimeDriver:   SandboxRuntimeDriverRootlessPodman,
		IsolationLevel:  SandboxIsolationLevelContainer,
		NetworkPolicy:   SandboxNetworkPolicyDenyByDefault,
		CredentialModes: []string{SandboxSecretModeFileTmpfs},
	}})
	validation := ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(got)
	if !validation.Valid {
		t.Fatalf("projected input validation errors = %#v, want valid", validation.Errors)
	}
	assertSecurityCapabilityJSONExcludes(t, got,
		"worker-01",
		"worker-one",
		"unix:///tmp/raw-worker.sock",
		"http://127.0.0.1:3128",
		"/tmp/secret",
		"/tmp/vm",
		"container-01",
		"ghcr.io/private",
		"worker@example.internal",
		"unix:///tmp/podman.sock",
		"/tmp/podman.sock",
	)
}

func assertProjectedSecurityCapabilityMetadata(t *testing.T, got, want []SandboxSecurityCapabilityMetadata) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projected metadata = %#v, want %#v", got, want)
	}
}

func assertProjectedSecurityCapabilityWorkerPostures(t *testing.T, got, want []SandboxSecurityCapabilityWorkerPostureMetadata) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("projected worker postures = %#v, want %#v", got, want)
	}
}
