package factory

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/credentialdelivery"
	"github.com/jywlabs/hal/internal/sandbox"
)

func TestCredentialProxyReferencesSecretBrokerMetadataBySafeIDs(t *testing.T) {
	secretValue := "credentialValue=raw-secret-token-123"
	broker := NewInMemorySecretBroker()
	session, err := broker.CreateSession(SecretBrokerSessionRequest{
		ID: " broker-session-credential-proxy ",
		ResolvedSecrets: []ResolvedRunSecret{{
			Name:     "GITHUB_TOKEN",
			Source:   RunSecretSourceEnv,
			Required: true,
			Value:    secretValue,
		}},
		RequestedDeliveryModes: []string{SecretBrokerDeliveryModeEnv, SecretBrokerDeliveryModeHTTPProxy},
		ActiveDeliveryModes:    []string{SecretBrokerDeliveryModeHTTPProxy},
	})
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}
	if len(session.Secrets) != 1 {
		t.Fatalf("session secrets = %#v, want one secret metadata entry", session.Secrets)
	}

	plan := CredentialProxyPlanMetadataFromSecretBrokerSession(SecretBrokerCredentialProxyPlanRequest{
		ID:      "credential-plan-01",
		Source:  sandbox.SandboxCredentialProxySourceFactory,
		Session: session,
		Status:  sandbox.SandboxCredentialProxyStatusPlanned,
	})
	proxySession := CredentialProxySessionMetadataFromSecretBrokerSession(SecretBrokerCredentialProxySessionRequest{
		ID:      "credential-session-01",
		PlanID:  plan.ID,
		Source:  sandbox.SandboxCredentialProxySourceFactory,
		Session: session,
		Status:  sandbox.SandboxCredentialProxyStatusReady,
	})
	binding := CredentialProxyBindingMetadataFromSecretBrokerSecret(SecretBrokerCredentialProxyBindingRequest{
		ID:              "credential-binding-01",
		SessionID:       proxySession.ID,
		Secret:          session.Secrets[0],
		DeliveryMode:    SecretBrokerDeliveryModeHTTPProxy,
		RequestCategory: sandbox.SandboxCredentialProxyRequestNetworkAuth,
		Outcome:         sandbox.SandboxCredentialProxyBindingOutcomeBound,
		Status:          sandbox.SandboxCredentialProxyStatusReady,
		ReasonCode:      sandbox.SandboxCredentialProxyReasonRequested,
	})

	if plan.SecretBrokerSessionID != session.ID {
		t.Fatalf("plan secret broker session ID = %q, want %q", plan.SecretBrokerSessionID, session.ID)
	}
	if proxySession.SecretBrokerSessionID != session.ID {
		t.Fatalf("session secret broker session ID = %q, want %q", proxySession.SecretBrokerSessionID, session.ID)
	}
	if binding.SecretID != session.Secrets[0].ID {
		t.Fatalf("binding secret ID = %q, want %q", binding.SecretID, session.Secrets[0].ID)
	}
	if binding.SecretID != "env:GITHUB_TOKEN" {
		t.Fatalf("binding secret ID = %q, want broker secret metadata ID", binding.SecretID)
	}
	if binding.DeliveryMode != sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy {
		t.Fatalf("binding delivery mode = %q, want %q", binding.DeliveryMode, sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy)
	}

	assertCredentialProxyFactoryValidationValid(t, sandbox.ValidateSandboxCredentialProxyPlanMetadata(plan))
	assertCredentialProxyFactoryValidationValid(t, sandbox.ValidateSandboxCredentialProxySessionMetadata(proxySession))
	assertCredentialProxyFactoryValidationValid(t, sandbox.ValidateSandboxCredentialProxyBindingMetadata(binding))

	data, err := json.Marshal(struct {
		Plan    sandbox.SandboxCredentialProxyPlanMetadata    `json:"plan"`
		Session sandbox.SandboxCredentialProxySessionMetadata `json:"session"`
		Binding sandbox.SandboxCredentialProxyBindingMetadata `json:"binding"`
	}{
		Plan:    plan,
		Session: proxySession,
		Binding: binding,
	})
	if err != nil {
		t.Fatalf("json.Marshal(credential proxy metadata) error: %v", err)
	}
	payload := string(data)
	assertCredentialProxyFactoryNoRawPayload(t, payload, secretValue, "credentialValue=", "raw-secret-token-123", `"value"`, `"Value"`)
	for _, forbidden := range []string{`"name"`, `"source":"env"`, `"required"`, `"present"`} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("credential proxy metadata copied broker secret fields instead of IDs only: %s", payload)
		}
	}
}

func TestCredentialProxySecretBrokerHelperDropsUnsafeSecretReferences(t *testing.T) {
	secretValue := "credentialValue=raw-secret-token-456"
	binding := CredentialProxyBindingMetadataFromSecretBrokerSecret(SecretBrokerCredentialProxyBindingRequest{
		ID:           "credential-binding-unsafe",
		SessionID:    "credential-session-01",
		Secret:       SecretBrokerSecretMetadata{ID: secretValue, Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv},
		DeliveryMode: SecretBrokerDeliveryModeEnv,
	})
	if binding != (sandbox.SandboxCredentialProxyBindingMetadata{}) {
		t.Fatalf("unsafe secret broker reference sanitized to %#v, want zero binding", binding)
	}
	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatalf("json.Marshal(binding) error: %v", err)
	}
	assertCredentialProxyFactoryNoRawPayload(t, string(data), secretValue, "credentialValue=", "raw-secret-token-456")

	result := sandbox.ValidateSandboxCredentialProxyBindingMetadata(sandbox.SandboxCredentialProxyBindingMetadata{
		ID:           "credential-binding-unsafe",
		SessionID:    "credential-session-01",
		SecretID:     secretValue,
		DeliveryMode: sandbox.SandboxCredentialProxyDeliveryModeEnv,
	})
	if result.Valid {
		t.Fatal("ValidateSandboxCredentialProxyBindingMetadata() valid = true, want false")
	}
	resultData, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	assertCredentialProxyFactoryNoRawPayload(t, string(resultData), secretValue, "credentialValue=", "raw-secret-token-456")
	for _, validationErr := range result.Errors {
		assertCredentialProxyFactoryNoRawPayload(t, validationErr.Error(), secretValue, "credentialValue=", "raw-secret-token-456")
	}
}

func TestProjectCredentialProxyMetadataFromSafeSecretBrokerNetworkAndSecurityIntent(t *testing.T) {
	secretValue := "credentialValue=raw-secret-token-789"
	broker := NewInMemorySecretBroker()
	session, err := broker.CreateSession(SecretBrokerSessionRequest{
		ID: " secret-broker-session-projection ",
		ResolvedSecrets: []ResolvedRunSecret{{
			Name:     "GITHUB_TOKEN",
			Source:   RunSecretSourceEnv,
			Required: true,
			Value:    secretValue,
		}},
	})
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}
	networkSession := sandbox.SandboxNetworkProxySessionMetadata{
		ID:     " network-proxy-session-projection ",
		Source: sandbox.SandboxNetworkPolicyDecisionSourceFactory,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-projection ",
			Version:   " v1 ",
			Preset:    sandbox.SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: " rules-projection ",
		},
		EnforcementMode: sandbox.SandboxNetworkEnforcementModeProxyFirewall,
	}
	intent := &sandbox.SandboxSecretDeliveryIntent{
		RequestedModes: []string{SecretBrokerDeliveryModeHTTPProxy, SecretBrokerDeliveryModeEnv},
		ActiveModes:    []string{SecretBrokerDeliveryModeHTTPProxy},
	}

	projection := ProjectCredentialProxyMetadata(CredentialProxyProjectionRequest{
		PlanID:               "credential-plan-projection",
		SessionID:            "credential-session-projection",
		BindingIDPrefix:      "credential-projection",
		Source:               sandbox.SandboxCredentialProxySourceFactory,
		SecretBrokerSession:  &session,
		SecretDeliveryIntent: intent,
		NetworkProxySession:  &networkSession,
		RequestCategory:      sandbox.SandboxCredentialProxyRequestNetworkAuth,
		DestinationCategory:  sandbox.SandboxNetworkPolicyDestinationPublicInternet,
	})

	if projection.Plan == nil {
		t.Fatal("projection.Plan = nil, want plan metadata")
	}
	if projection.Session == nil {
		t.Fatal("projection.Session = nil, want session metadata")
	}
	if projection.Plan.SecretBrokerSessionID != "secret-broker-session-projection" {
		t.Fatalf("plan secret broker session ID = %q, want sanitized broker ID", projection.Plan.SecretBrokerSessionID)
	}
	if projection.Plan.NetworkProxySessionID != "network-proxy-session-projection" {
		t.Fatalf("plan network proxy session ID = %q, want sanitized proxy ID", projection.Plan.NetworkProxySessionID)
	}
	if projection.Plan.Mode != sandbox.SandboxCredentialProxyModeBrokeredNetworkReference {
		t.Fatalf("plan mode = %q, want brokered network reference", projection.Plan.Mode)
	}
	if got, want := len(projection.Bindings), 2; got != want {
		t.Fatalf("len(bindings) = %d, want %d: %#v", got, want, projection.Bindings)
	}
	httpProxyBinding := requireFactoryCredentialProxyProjectionBinding(t, projection.Bindings, sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy)
	if httpProxyBinding.SecretID != "env:GITHUB_TOKEN" {
		t.Fatalf("http proxy binding secret ID = %q, want broker safe secret ID", httpProxyBinding.SecretID)
	}
	if httpProxyBinding.Outcome != sandbox.SandboxCredentialProxyBindingOutcomeAuditOnly ||
		httpProxyBinding.Status != sandbox.SandboxCredentialProxyStatusReady {
		t.Fatalf("http proxy binding = %#v, want active-mode metadata without live delivery claim", httpProxyBinding)
	}
	envBinding := requireFactoryCredentialProxyProjectionBinding(t, projection.Bindings, sandbox.SandboxCredentialProxyDeliveryModeEnv)
	if envBinding.Outcome != sandbox.SandboxCredentialProxyBindingOutcomePlanned ||
		envBinding.Status != sandbox.SandboxCredentialProxyStatusPlanned {
		t.Fatalf("env binding = %#v, want requested-only metadata", envBinding)
	}
	for _, binding := range projection.Bindings {
		if binding.Outcome == sandbox.SandboxCredentialProxyBindingOutcomeBound || binding.Status == sandbox.SandboxCredentialProxyStatusActive {
			t.Fatalf("binding claims credential delivery: %#v", binding)
		}
		assertCredentialProxyFactoryValidationValid(t, sandbox.ValidateSandboxCredentialProxyBindingMetadata(binding))
	}
	assertCredentialProxyFactoryValidationValid(t, sandbox.ValidateSandboxCredentialProxyPlanMetadata(*projection.Plan))
	assertCredentialProxyFactoryValidationValid(t, sandbox.ValidateSandboxCredentialProxySessionMetadata(*projection.Session))

	intent.RequestedModes[0] = SecretBrokerDeliveryModeSSHAgent
	networkSession.PolicySnapshot.ID = "mutated-policy-snapshot"
	if projection.Bindings[0].DeliveryMode != sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy {
		t.Fatalf("projection binding changed after intent mutation: %#v", projection.Bindings[0])
	}
	if projection.Plan.PolicySnapshot.ID != "policy-snapshot-projection" {
		t.Fatalf("projection policy snapshot changed after network input mutation: %#v", projection.Plan.PolicySnapshot)
	}

	data, err := json.Marshal(projection)
	if err != nil {
		t.Fatalf("json.Marshal(projection) error: %v", err)
	}
	payload := string(data)
	assertCredentialProxyFactoryNoRawPayload(t, payload, secretValue, "credentialValue=", "raw-secret-token-789", `"value"`, `"Value"`)
	for _, forbidden := range []string{`"name"`, `"source":"env"`, `"required"`, `"present"`, "enforcementMode", sandbox.SandboxNetworkEnforcementModeProxyFirewall} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("credential proxy projection copied unsafe or unrelated metadata %q in %s", forbidden, payload)
		}
	}
}

func TestFactoryCredentialProxyMetadataCanSatisfyHTTPProxyActivationProof(t *testing.T) {
	broker := NewInMemorySecretBroker()
	session, err := broker.CreateSession(SecretBrokerSessionRequest{
		ID: "secret-broker-session-http-proxy",
		ResolvedSecrets: []ResolvedRunSecret{{
			Name:     "GITHUB_TOKEN",
			Source:   RunSecretSourceEnv,
			Required: true,
			Value:    "ghp_factory_http_proxy_secret",
		}},
		RequestedDeliveryModes: []string{SecretBrokerDeliveryModeHTTPProxy},
		ActiveDeliveryModes:    []string{SecretBrokerDeliveryModeHTTPProxy},
	})
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}
	binding := credentialdelivery.Binding{
		ID:                    "binding-http-proxy",
		PolicySnapshotID:      "policy-snapshot-01",
		SecretRef:             session.Secrets[0].ID,
		NetworkProxySessionID: "network-proxy-session-01",
		ServiceID:             "service-source-control",
		DestinationCategory:   credentialdelivery.DestinationPublicInternet,
		DeliveryMode:          credentialdelivery.ModeHTTPProxy,
		Status:                credentialdelivery.StatusPlanned,
		ReasonCode:            credentialdelivery.ReasonRequested,
	}
	networkSession := sandbox.SandboxNetworkProxySessionMetadata{
		ID:     "network-proxy-session-01",
		Source: sandbox.SandboxNetworkPolicyDecisionSourceFactory,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:     "policy-snapshot-01",
			Preset: sandbox.SandboxNetworkPolicyPresetDenyByDefault,
		},
		EnforcementMode: sandbox.SandboxNetworkEnforcementModeProxyFirewall,
	}
	credentialPlan := CredentialProxyPlanMetadataFromSecretBrokerSession(SecretBrokerCredentialProxyPlanRequest{
		ID:      "credential-proxy-plan-01",
		Source:  sandbox.SandboxCredentialProxySourceFactory,
		Session: session,
		Status:  sandbox.SandboxCredentialProxyStatusReady,
	})
	credentialPlan.NetworkProxySessionID = networkSession.ID
	credentialPlan.PolicySnapshot = networkSession.PolicySnapshot
	credentialPlan.Mode = sandbox.SandboxCredentialProxyModeBrokeredNetworkReference
	credentialPlan = sandbox.SanitizeSandboxCredentialProxyPlanMetadata(credentialPlan)
	credentialSession := CredentialProxySessionMetadataFromSecretBrokerSession(SecretBrokerCredentialProxySessionRequest{
		ID:      "credential-proxy-session-01",
		PlanID:  credentialPlan.ID,
		Source:  sandbox.SandboxCredentialProxySourceFactory,
		Session: session,
		Status:  sandbox.SandboxCredentialProxyStatusReady,
	})
	credentialSession.NetworkProxySessionID = networkSession.ID
	credentialSession.PolicySnapshot = networkSession.PolicySnapshot
	credentialSession = sandbox.SanitizeSandboxCredentialProxySessionMetadata(credentialSession)
	credentialBinding := CredentialProxyBindingMetadataFromSecretBrokerSecret(SecretBrokerCredentialProxyBindingRequest{
		ID:                  "credential-proxy-binding-01",
		PlanID:              credentialPlan.ID,
		SessionID:           credentialSession.ID,
		Secret:              session.Secrets[0],
		DeliveryMode:        SecretBrokerDeliveryModeHTTPProxy,
		RequestCategory:     sandbox.SandboxCredentialProxyRequestSourceControl,
		DestinationCategory: sandbox.SandboxNetworkPolicyDestinationPublicInternet,
		Outcome:             sandbox.SandboxCredentialProxyBindingOutcomeBound,
		Status:              sandbox.SandboxCredentialProxyStatusReady,
		ReasonCode:          sandbox.SandboxCredentialProxyReasonRequested,
	})
	request := credentialdelivery.PlanConstructionRequest{
		PlanID:              "delivery-plan-01",
		RequestID:           "delivery-request-01",
		RequestedModes:      []credentialdelivery.Mode{credentialdelivery.ModeHTTPProxy},
		Bindings:            []credentialdelivery.Binding{binding},
		ResolvedBindings:    []credentialdelivery.ResolvedBindingSecretMetadata{factoryResolvedHTTPProxyBinding(binding)},
		PolicySnapshot:      networkSession.PolicySnapshot,
		NetworkProxySession: &networkSession,
		NetworkEnforcementProof: &sandbox.SandboxNetworkEnforcementProofMetadata{
			NetworkProxySessionID:    networkSession.ID,
			PolicySnapshotID:         "policy-snapshot-01",
			NetworkEnforcementPlanID: "network-enforcement-plan-01",
			ProxyLifecycleStatus:     "active",
			ProxyLifecycleReasonCode: "active",
			ResultOutcome:            "success",
			ResultEnforcementMode:    sandbox.SandboxNetworkEnforcementModeProxyFirewall,
			ResultSupported:          true,
		},
		CredentialProxyPlan:     &credentialPlan,
		CredentialProxySession:  &credentialSession,
		CredentialProxyBindings: []sandbox.SandboxCredentialProxyBindingMetadata{credentialBinding},
	}

	active := credentialdelivery.BuildDeliveryPlan(request)
	if active.HTTPProxyProof == nil || active.NetworkProxySessionID != networkSession.ID {
		t.Fatalf("active plan = %#v, want http_proxy proof from factory broker metadata", active)
	}
	withoutBroker := request
	withoutBroker.CredentialProxySession = nil
	inactive := credentialdelivery.BuildDeliveryPlan(withoutBroker)
	if inactive.HTTPProxyProof != nil || len(inactive.ActiveModes) != 0 {
		t.Fatalf("inactive plan = %#v, want broker removal to fail closed", inactive)
	}

	data, err := json.Marshal(struct {
		Active   credentialdelivery.Plan `json:"active"`
		Inactive credentialdelivery.Plan `json:"inactive"`
	}{Active: active, Inactive: inactive})
	if err != nil {
		t.Fatalf("json.Marshal(plans) error: %v", err)
	}
	assertCredentialProxyFactoryNoRawPayload(t, string(data), "ghp_factory_http_proxy_secret", "credentialValue", "Authorization", "Bearer")
}

func TestProjectCredentialProxyMetadataPreservesExplicitEmptyBrokerMetadata(t *testing.T) {
	session := SecretBrokerSessionMetadata{
		ID:      "secret-broker-session-empty",
		Secrets: []SecretBrokerSecretMetadata{},
		DeliveryModes: &SecretBrokerDeliveryModeMetadata{
			RequestedModes: []string{},
			ActiveModes:    []string{},
		},
	}
	projection := ProjectCredentialProxyMetadata(CredentialProxyProjectionRequest{
		PlanID:              "credential-plan-empty",
		SessionID:           "credential-session-empty",
		Source:              sandbox.SandboxCredentialProxySourceFactory,
		SecretBrokerSession: &session,
	})
	if projection.Plan == nil || projection.Session == nil {
		t.Fatalf("projection = %#v, want plan/session metadata", projection)
	}
	if projection.Bindings == nil {
		t.Fatal("projection.Bindings = nil, want explicit empty slice")
	}
	if len(projection.Bindings) != 0 {
		t.Fatalf("projection.Bindings = %#v, want empty", projection.Bindings)
	}
}

func factoryResolvedHTTPProxyBinding(binding credentialdelivery.Binding) credentialdelivery.ResolvedBindingSecretMetadata {
	return credentialdelivery.ResolvedBindingSecretMetadata{
		BindingID:    binding.ID,
		SecretRef:    binding.SecretRef,
		DeliveryMode: binding.DeliveryMode,
		BrokerSecret: credentialdelivery.BrokerSecretMetadata{
			ID:       binding.SecretRef,
			Source:   "broker",
			Required: true,
			Present:  true,
		},
	}
}

func TestRunSecretRedactorRedactsSandboxCredentialProxyMetadata(t *testing.T) {
	secretValue := "credential-proxy-collision-value"
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{{
		Name:  "COLLISION_SECRET",
		Value: secretValue,
	}})
	record := RunRecord{
		RunID: "run-redact-sandbox-credential-proxy",
		Sandbox: &SandboxMetadata{
			Name:   "factory-sandbox",
			Status: "running",
			CredentialProxyPlan: &sandbox.SandboxCredentialProxyPlanMetadata{
				ID:                    secretValue,
				Source:                sandbox.SandboxCredentialProxySource(secretValue),
				SecretBrokerSessionID: secretValue,
				NetworkProxySessionID: secretValue,
				PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
					ID:        secretValue,
					Version:   secretValue,
					Preset:    sandbox.SandboxNetworkPolicyPreset(secretValue),
					RuleSetID: secretValue,
				},
				Mode:   sandbox.SandboxCredentialProxyMode(secretValue),
				Status: sandbox.SandboxCredentialProxyStatus(secretValue),
			},
			CredentialProxySession: &sandbox.SandboxCredentialProxySessionMetadata{
				ID:                    secretValue,
				PlanID:                secretValue,
				Source:                sandbox.SandboxCredentialProxySource(secretValue),
				SecretBrokerSessionID: secretValue,
				NetworkProxySessionID: secretValue,
				PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
					ID:        secretValue,
					Version:   secretValue,
					Preset:    sandbox.SandboxNetworkPolicyPreset(secretValue),
					RuleSetID: secretValue,
				},
				Status:      sandbox.SandboxCredentialProxyStatus(secretValue),
				WarningCode: sandbox.SandboxCredentialProxyWarningCode(secretValue),
				ReasonCode:  sandbox.SandboxCredentialProxyReasonCode(secretValue),
			},
			CredentialProxyBindings: []sandbox.SandboxCredentialProxyBindingMetadata{{
				ID:                  secretValue,
				PlanID:              secretValue,
				SessionID:           secretValue,
				SecretID:            secretValue,
				DeliveryMode:        sandbox.SandboxCredentialProxyDeliveryMode(secretValue),
				RequestCategory:     sandbox.SandboxCredentialProxyRequestCategory(secretValue),
				DestinationCategory: sandbox.SandboxNetworkPolicyDestinationCategory(secretValue),
				Outcome:             sandbox.SandboxCredentialProxyBindingOutcome(secretValue),
				Status:              sandbox.SandboxCredentialProxyStatus(secretValue),
				ReasonCode:          sandbox.SandboxCredentialProxyReasonCode(secretValue),
			}},
		},
	}

	redacted := redactor.RedactRunRecord(record)
	data, err := json.Marshal(redacted)
	if err != nil {
		t.Fatalf("json.Marshal(redacted) error: %v", err)
	}
	payload := string(data)
	if strings.Contains(payload, secretValue) {
		t.Fatalf("redacted record leaked credential proxy collision value: %s", payload)
	}
	if !strings.Contains(payload, RunSecretRedactionPlaceholder) {
		t.Fatalf("redacted record missing redaction placeholder: %s", payload)
	}
	if record.Sandbox.CredentialProxyPlan.ID != secretValue {
		t.Fatal("RedactRunRecord mutated original credential proxy metadata")
	}
}

func requireFactoryCredentialProxyProjectionBinding(t *testing.T, bindings []sandbox.SandboxCredentialProxyBindingMetadata, mode sandbox.SandboxCredentialProxyDeliveryMode) sandbox.SandboxCredentialProxyBindingMetadata {
	t.Helper()

	for _, binding := range bindings {
		if binding.DeliveryMode == mode {
			return binding
		}
	}
	t.Fatalf("missing binding for mode %q in %#v", mode, bindings)
	return sandbox.SandboxCredentialProxyBindingMetadata{}
}

func assertCredentialProxyFactoryValidationValid(t *testing.T, result sandbox.SandboxCredentialProxyValidationResult) {
	t.Helper()

	if !result.Valid || len(result.Errors) != 0 {
		t.Fatalf("credential proxy validation = %#v, want valid", result)
	}
}

func assertCredentialProxyFactoryNoRawPayload(t *testing.T, payload string, forbiddenValues ...string) {
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
