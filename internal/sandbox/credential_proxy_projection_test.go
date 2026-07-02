package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestProjectSandboxCredentialProxyMetadataProjectsSafeNetworkProxyAndSecurityIntent(t *testing.T) {
	networkSession := SandboxNetworkProxySessionMetadata{
		ID:     " network-proxy-session-01 ",
		Source: SandboxNetworkPolicyDecisionSourceRun,
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-01 ",
			Version:   " v1 ",
			Preset:    SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: " rules-01 ",
		},
		EnforcementMode: SandboxNetworkEnforcementModeProxyFirewall,
	}
	intent := &SandboxSecretDeliveryIntent{
		RequestedModes: []string{SandboxSecretModeHTTPProxy, SandboxSecretModeEnv},
		ActiveModes:    []string{SandboxSecretModeHTTPProxy},
	}

	projection := ProjectSandboxCredentialProxyMetadata(SandboxCredentialProxyProjectionRequest{
		PlanID:                "credential-plan-01",
		SessionID:             "credential-session-01",
		BindingIDPrefix:       "credential",
		Source:                SandboxCredentialProxySourceRun,
		SecretBrokerSessionID: " secret-broker-session-01 ",
		SecretIDs:             []string{"env:GITHUB_TOKEN"},
		SecretDeliveryIntent:  intent,
		NetworkProxySession:   &networkSession,
		RequestCategory:       SandboxCredentialProxyRequestNetworkAuth,
		DestinationCategory:   SandboxNetworkPolicyDestinationPublicInternet,
	})

	if projection.Plan == nil {
		t.Fatal("projection.Plan = nil, want plan metadata")
	}
	if projection.Session == nil {
		t.Fatal("projection.Session = nil, want session metadata")
	}
	if projection.Plan.Mode != SandboxCredentialProxyModeBrokeredNetworkReference {
		t.Fatalf("plan mode = %q, want %q", projection.Plan.Mode, SandboxCredentialProxyModeBrokeredNetworkReference)
	}
	if projection.Plan.SecretBrokerSessionID != "secret-broker-session-01" {
		t.Fatalf("plan secret broker session id = %q, want sanitized id", projection.Plan.SecretBrokerSessionID)
	}
	if projection.Plan.NetworkProxySessionID != "network-proxy-session-01" {
		t.Fatalf("plan network proxy session id = %q, want sanitized id", projection.Plan.NetworkProxySessionID)
	}
	if projection.Plan.PolicySnapshot == nil || projection.Session.PolicySnapshot == nil {
		t.Fatalf("policy snapshots = %#v %#v, want copied snapshot metadata", projection.Plan.PolicySnapshot, projection.Session.PolicySnapshot)
	}
	if projection.Plan.PolicySnapshot == networkSession.PolicySnapshot || projection.Session.PolicySnapshot == networkSession.PolicySnapshot {
		t.Fatal("projection policy snapshots alias the input network proxy snapshot")
	}
	if projection.Plan.PolicySnapshot.ID != "policy-snapshot-01" ||
		projection.Plan.PolicySnapshot.Version != "v1" ||
		projection.Plan.PolicySnapshot.Preset != SandboxNetworkPolicyPresetDenyByDefault ||
		projection.Plan.PolicySnapshot.RuleSetID != "rules-01" {
		t.Fatalf("plan policy snapshot = %#v, want sanitized copy", projection.Plan.PolicySnapshot)
	}

	if got, want := len(projection.Bindings), 2; got != want {
		t.Fatalf("len(bindings) = %d, want %d: %#v", got, want, projection.Bindings)
	}
	if projection.Plan.BindingCount != len(projection.Bindings) {
		t.Fatalf("plan binding count = %d, want %d", projection.Plan.BindingCount, len(projection.Bindings))
	}
	httpProxyBinding := requireCredentialProxyProjectionBinding(t, projection.Bindings, SandboxCredentialProxyDeliveryModeHTTPProxy)
	if httpProxyBinding.Outcome != SandboxCredentialProxyBindingOutcomeAuditOnly || httpProxyBinding.Status != SandboxCredentialProxyStatusReady {
		t.Fatalf("http proxy binding = %#v, want active-mode metadata recorded as audit-only ready", httpProxyBinding)
	}
	envBinding := requireCredentialProxyProjectionBinding(t, projection.Bindings, SandboxCredentialProxyDeliveryModeEnv)
	if envBinding.Outcome != SandboxCredentialProxyBindingOutcomePlanned || envBinding.Status != SandboxCredentialProxyStatusPlanned {
		t.Fatalf("env binding = %#v, want requested-only metadata recorded as planned", envBinding)
	}
	for _, binding := range projection.Bindings {
		if binding.Outcome == SandboxCredentialProxyBindingOutcomeBound || binding.Status == SandboxCredentialProxyStatusActive {
			t.Fatalf("binding claims live credential delivery: %#v", binding)
		}
		if binding.SecretID != "env:GITHUB_TOKEN" {
			t.Fatalf("binding secret id = %q, want broker-style safe id", binding.SecretID)
		}
		if binding.RequestCategory != SandboxCredentialProxyRequestNetworkAuth {
			t.Fatalf("binding request category = %q, want network_auth", binding.RequestCategory)
		}
		if binding.DestinationCategory != SandboxNetworkPolicyDestinationPublicInternet {
			t.Fatalf("binding destination category = %q, want public_internet", binding.DestinationCategory)
		}
		assertCredentialProxyProjectionValidationValid(t, ValidateSandboxCredentialProxyBindingMetadata(binding))
	}
	assertCredentialProxyProjectionValidationValid(t, ValidateSandboxCredentialProxyPlanMetadata(*projection.Plan))
	assertCredentialProxyProjectionValidationValid(t, ValidateSandboxCredentialProxySessionMetadata(*projection.Session))

	networkSession.PolicySnapshot.ID = "mutated-policy-snapshot"
	intent.RequestedModes[0] = SandboxSecretModeSSHAgent
	if projection.Plan.PolicySnapshot.ID != "policy-snapshot-01" {
		t.Fatalf("projection plan snapshot changed after input mutation: %#v", projection.Plan.PolicySnapshot)
	}
	if projection.Bindings[0].DeliveryMode != SandboxCredentialProxyDeliveryModeHTTPProxy {
		t.Fatalf("projection binding changed after input mutation: %#v", projection.Bindings[0])
	}

	data, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("json.Marshal(projection) error = %v", err)
	}
	assertCredentialProxyProjectionPayloadExcludes(t, string(data), "enforcementMode", SandboxNetworkEnforcementModeProxyFirewall, "host", "url", "header", "body")
}

func TestProjectSandboxCredentialProxyMetadataOmitsAbsentAndUnsupportedInputs(t *testing.T) {
	absent := ProjectSandboxCredentialProxyMetadata(SandboxCredentialProxyProjectionRequest{})
	if absent.Plan != nil || absent.Session != nil || absent.Bindings != nil {
		t.Fatalf("absent projection = %#v, want zero metadata", absent)
	}

	rawProxyURL := "https://api.example.invalid:443/path?token=value"
	unsafeNetworkOnly := ProjectSandboxCredentialProxyMetadata(SandboxCredentialProxyProjectionRequest{
		PlanID:    "credential-plan-01",
		SessionID: "credential-session-01",
		Source:    SandboxCredentialProxySourceRun,
		NetworkProxySession: &SandboxNetworkProxySessionMetadata{
			ID:              rawProxyURL,
			Source:          SandboxNetworkPolicyDecisionSourceRun,
			EnforcementMode: SandboxNetworkEnforcementModeProxy,
		},
	})
	if unsafeNetworkOnly.Plan != nil || unsafeNetworkOnly.Session != nil || unsafeNetworkOnly.Bindings != nil {
		t.Fatalf("unsafe network-only projection = %#v, want omitted metadata", unsafeNetworkOnly)
	}

	unsupported := ProjectSandboxCredentialProxyMetadata(SandboxCredentialProxyProjectionRequest{
		PlanID:                "credential-plan-02",
		SessionID:             "credential-session-02",
		Source:                SandboxCredentialProxySourceFactory,
		SecretBrokerSessionID: "secret-broker-session-02",
		SecretIDs:             []string{"env:GITHUB_TOKEN"},
		SecretDeliveryIntent: &SandboxSecretDeliveryIntent{
			RequestedModes: []string{"unsupported_mode"},
			ActiveModes:    []string{"http://proxy.example.invalid/token"},
		},
	})
	if unsupported.Plan == nil || unsupported.Session == nil {
		t.Fatalf("unsupported mode projection = %#v, want safe plan/session metadata with omitted bindings", unsupported)
	}
	if len(unsupported.Bindings) != 0 {
		t.Fatalf("unsupported mode bindings = %#v, want omitted bindings", unsupported.Bindings)
	}
	if unsupported.Session.WarningCode != SandboxCredentialProxyWarningUnsupportedDeliveryMode ||
		unsupported.Session.ReasonCode != SandboxCredentialProxyReasonDeliveryModeUnsupported {
		t.Fatalf("unsupported mode session = %#v, want unsupported delivery warning", unsupported.Session)
	}
	data, err := json.Marshal(unsupported)
	if err != nil {
		t.Fatalf("json.Marshal(unsupported) error = %v", err)
	}
	assertCredentialProxyProjectionPayloadExcludes(t, string(data), rawProxyURL, "unsupported_mode", "proxy.example.invalid", "token")
}

func TestProjectSandboxCredentialProxyMetadataPreservesExplicitEmptyBindingSlice(t *testing.T) {
	explicitEmpty := ProjectSandboxCredentialProxyMetadata(SandboxCredentialProxyProjectionRequest{
		PlanID:                "credential-plan-empty",
		SessionID:             "credential-session-empty",
		Source:                SandboxCredentialProxySourceAuto,
		SecretBrokerSessionID: "secret-broker-session-empty",
		SecretIDs:             []string{},
		SecretDeliveryIntent: &SandboxSecretDeliveryIntent{
			RequestedModes: []string{},
			ActiveModes:    []string{},
		},
	})
	if explicitEmpty.Plan == nil || explicitEmpty.Session == nil {
		t.Fatalf("explicit empty projection = %#v, want plan/session metadata", explicitEmpty)
	}
	if explicitEmpty.Bindings == nil {
		t.Fatalf("bindings = nil, want explicit empty slice")
	}
	if len(explicitEmpty.Bindings) != 0 {
		t.Fatalf("bindings = %#v, want empty", explicitEmpty.Bindings)
	}
	if explicitEmpty.Session.WarningCode != SandboxCredentialProxyWarningBindingOmitted {
		t.Fatalf("session warning = %q, want %q", explicitEmpty.Session.WarningCode, SandboxCredentialProxyWarningBindingOmitted)
	}

	implicitEmpty := ProjectSandboxCredentialProxyMetadata(SandboxCredentialProxyProjectionRequest{
		PlanID:                "credential-plan-implicit",
		SessionID:             "credential-session-implicit",
		Source:                SandboxCredentialProxySourceAuto,
		SecretBrokerSessionID: "secret-broker-session-implicit",
	})
	if implicitEmpty.Plan == nil || implicitEmpty.Session == nil {
		t.Fatalf("implicit empty projection = %#v, want plan/session metadata", implicitEmpty)
	}
	if implicitEmpty.Bindings != nil {
		t.Fatalf("bindings = %#v, want nil when binding inputs were absent", implicitEmpty.Bindings)
	}
}

func requireCredentialProxyProjectionBinding(t *testing.T, bindings []SandboxCredentialProxyBindingMetadata, mode SandboxCredentialProxyDeliveryMode) SandboxCredentialProxyBindingMetadata {
	t.Helper()

	for _, binding := range bindings {
		if binding.DeliveryMode == mode {
			return binding
		}
	}
	t.Fatalf("missing binding for mode %q in %#v", mode, bindings)
	return SandboxCredentialProxyBindingMetadata{}
}

func assertCredentialProxyProjectionValidationValid(t *testing.T, result SandboxCredentialProxyValidationResult) {
	t.Helper()

	if !result.Valid || len(result.Errors) != 0 {
		t.Fatalf("credential proxy validation = %#v, want valid", result)
	}
}

func assertCredentialProxyProjectionPayloadExcludes(t *testing.T, payload string, forbiddenValues ...string) {
	t.Helper()

	for _, forbidden := range forbiddenValues {
		if forbidden == "" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("payload leaked forbidden value %q in %s", forbidden, payload)
		}
	}
}
