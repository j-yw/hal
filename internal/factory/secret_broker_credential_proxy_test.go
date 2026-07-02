package factory

import (
	"encoding/json"
	"strings"
	"testing"

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
