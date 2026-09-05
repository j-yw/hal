package factory

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestResolveRunSecretsRequiredEnvSuccess(t *testing.T) {
	secretValue := "ghp_factory_secret_value_123"
	resolved, metadata, err := ResolveRunSecrets([]RunSecretInput{
		{Name: " GITHUB_TOKEN ", Source: RunSecretSourceEnv, Required: true},
	}, func(name string) (string, bool) {
		if name != "GITHUB_TOKEN" {
			t.Fatalf("lookup name = %q, want GITHUB_TOKEN", name)
		}
		return secretValue, true
	})
	if err != nil {
		t.Fatalf("ResolveRunSecrets() unexpected error: %v", err)
	}

	wantResolved := []ResolvedRunSecret{{
		Name:     "GITHUB_TOKEN",
		Source:   RunSecretSourceEnv,
		Required: true,
		Value:    secretValue,
	}}
	if !reflect.DeepEqual(resolved, wantResolved) {
		t.Fatalf("resolved = %#v, want %#v", resolved, wantResolved)
	}

	wantMetadata := []RunSecretMetadata{{
		Name:     "GITHUB_TOKEN",
		Source:   RunSecretSourceEnv,
		Required: true,
		Present:  true,
	}}
	if !reflect.DeepEqual(metadata, wantMetadata) {
		t.Fatalf("metadata = %#v, want %#v", metadata, wantMetadata)
	}
}

func TestResolveRunSecretsRequiredEnvMissing(t *testing.T) {
	resolved, metadata, err := ResolveRunSecrets([]RunSecretInput{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true},
	}, func(string) (string, bool) {
		return "", false
	})
	if err == nil {
		t.Fatal("ResolveRunSecrets() error = nil, want missing secret error")
	}
	if !errors.Is(err, ErrRequiredRunSecretMissing) {
		t.Fatalf("ResolveRunSecrets() error = %v, want ErrRequiredRunSecretMissing", err)
	}
	if !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Fatalf("error = %q, want env var name", err.Error())
	}
	if strings.Contains(err.Error(), "ghp_factory_secret_value_123") {
		t.Fatalf("error leaked secret value: %q", err.Error())
	}
	if len(resolved) != 0 {
		t.Fatalf("resolved = %#v, want none", resolved)
	}
	wantMetadata := []RunSecretMetadata{{
		Name:     "GITHUB_TOKEN",
		Source:   RunSecretSourceEnv,
		Required: true,
		Present:  false,
	}}
	if !reflect.DeepEqual(metadata, wantMetadata) {
		t.Fatalf("metadata = %#v, want %#v", metadata, wantMetadata)
	}
}

func TestResolveRunSecretsRequiredEnvEmpty(t *testing.T) {
	_, metadata, err := ResolveRunSecrets([]RunSecretInput{
		{Name: "GITHUB_TOKEN", Source: RunSecretSourceEnv, Required: true},
	}, func(string) (string, bool) {
		return " \t ", true
	})
	if err == nil {
		t.Fatal("ResolveRunSecrets() error = nil, want empty secret error")
	}
	if !errors.Is(err, ErrRequiredRunSecretMissing) {
		t.Fatalf("ResolveRunSecrets() error = %v, want ErrRequiredRunSecretMissing", err)
	}
	if len(metadata) != 1 || metadata[0].Present {
		t.Fatalf("metadata = %#v, want present=false", metadata)
	}
}

func TestResolveRunSecretsOptionalEnvMissing(t *testing.T) {
	resolved, metadata, err := ResolveRunSecrets([]RunSecretInput{
		{Name: "OPTIONAL_TOKEN", Source: RunSecretSourceEnv, Required: false},
	}, func(string) (string, bool) {
		return "", false
	})
	if err != nil {
		t.Fatalf("ResolveRunSecrets() unexpected error: %v", err)
	}
	if len(resolved) != 0 {
		t.Fatalf("resolved = %#v, want none", resolved)
	}
	wantMetadata := []RunSecretMetadata{{
		Name:     "OPTIONAL_TOKEN",
		Source:   RunSecretSourceEnv,
		Required: false,
		Present:  false,
	}}
	if !reflect.DeepEqual(metadata, wantMetadata) {
		t.Fatalf("metadata = %#v, want %#v", metadata, wantMetadata)
	}
}

func TestResolveRunSecretsWithProvidersUsesRegisteredProvider(t *testing.T) {
	secretValue := "short_lived_token_value"
	called := false

	resolved, metadata, err := ResolveRunSecretsWithProviders([]RunSecretInput{
		{Name: " OIDC_TOKEN ", Source: "oidc", Required: true},
	}, RunSecretProviders{
		"oidc": RunSecretProviderFunc(func(secret RunSecretInput) (string, bool, error) {
			called = true
			if secret.Name != "OIDC_TOKEN" {
				t.Fatalf("provider secret name = %q, want OIDC_TOKEN", secret.Name)
			}
			if secret.Source != "oidc" {
				t.Fatalf("provider secret source = %q, want oidc", secret.Source)
			}
			return secretValue, true, nil
		}),
	})
	if err != nil {
		t.Fatalf("ResolveRunSecretsWithProviders() unexpected error: %v", err)
	}
	if !called {
		t.Fatal("registered provider was not called")
	}

	wantResolved := []ResolvedRunSecret{{
		Name:     "OIDC_TOKEN",
		Source:   "oidc",
		Required: true,
		Value:    secretValue,
	}}
	if !reflect.DeepEqual(resolved, wantResolved) {
		t.Fatalf("resolved = %#v, want %#v", resolved, wantResolved)
	}

	wantMetadata := []RunSecretMetadata{{
		Name:     "OIDC_TOKEN",
		Source:   "oidc",
		Required: true,
		Present:  true,
	}}
	if !reflect.DeepEqual(metadata, wantMetadata) {
		t.Fatalf("metadata = %#v, want %#v", metadata, wantMetadata)
	}
}

func TestResolveRunSecretsUnsupportedNonEnvSource(t *testing.T) {
	resolved, metadata, err := ResolveRunSecrets([]RunSecretInput{
		{Name: "OIDC_TOKEN", Source: "oidc", Required: true},
	}, func(string) (string, bool) {
		t.Fatal("env lookup should not be called for unsupported non-env source")
		return "", false
	})
	if err == nil {
		t.Fatal("ResolveRunSecrets() error = nil, want unsupported source error")
	}
	if !errors.Is(err, ErrUnsupportedRunSecretSource) {
		t.Fatalf("ResolveRunSecrets() error = %v, want ErrUnsupportedRunSecretSource", err)
	}
	if !strings.Contains(err.Error(), "oidc") || !strings.Contains(err.Error(), "OIDC_TOKEN") {
		t.Fatalf("error = %q, want source and secret name", err.Error())
	}
	if len(resolved) != 0 {
		t.Fatalf("resolved = %#v, want none", resolved)
	}
	if len(metadata) != 0 {
		t.Fatalf("metadata = %#v, want none", metadata)
	}
}

func TestSecretBrokerSessionLifecycle(t *testing.T) {
	secretValue := "ghp_factory_broker_secret_value_123"
	broker := NewInMemorySecretBroker()

	session, err := broker.CreateSession(SecretBrokerSessionRequest{
		ID: " broker-session-1 ",
		ResolvedSecrets: []ResolvedRunSecret{{
			Name:     " GITHUB_TOKEN ",
			Source:   RunSecretSourceEnv,
			Required: true,
			Value:    secretValue,
		}},
	})
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}
	if session.ID != "broker-session-1" {
		t.Fatalf("session ID = %q, want broker-session-1", session.ID)
	}
	if len(session.Secrets) != 1 {
		t.Fatalf("session secrets = %#v, want one entry", session.Secrets)
	}

	secretMetadata := session.Secrets[0]
	if secretMetadata.ID == "" {
		t.Fatal("secret metadata ID should not be empty")
	}
	if secretMetadata.Name != "GITHUB_TOKEN" {
		t.Fatalf("secret metadata name = %q, want GITHUB_TOKEN", secretMetadata.Name)
	}

	loaded, ok := broker.SessionMetadata(session.ID)
	if !ok {
		t.Fatal("SessionMetadata() ok = false, want true")
	}
	if !reflect.DeepEqual(loaded, session) {
		t.Fatalf("SessionMetadata() = %#v, want %#v", loaded, session)
	}

	byID, ok := broker.LookupSecretByID(session.ID, secretMetadata.ID)
	if !ok {
		t.Fatal("LookupSecretByID() ok = false, want true")
	}
	if byID.Value != secretValue {
		t.Fatalf("LookupSecretByID() value = %q, want raw in-memory value", byID.Value)
	}
	byName, ok := broker.LookupSecretByName(session.ID, secretMetadata.Name)
	if !ok {
		t.Fatal("LookupSecretByName() ok = false, want true")
	}
	if !reflect.DeepEqual(byName, byID) {
		t.Fatalf("LookupSecretByName() = %#v, want %#v", byName, byID)
	}

	if !broker.CloseSession(session.ID) {
		t.Fatal("CloseSession() = false, want true")
	}
	if _, ok := broker.SessionMetadata(session.ID); ok {
		t.Fatal("SessionMetadata() ok = true after close, want false")
	}
	if _, ok := broker.LookupSecretByID(session.ID, secretMetadata.ID); ok {
		t.Fatal("LookupSecretByID() ok = true after close, want false")
	}
	if broker.CloseSession(session.ID) {
		t.Fatal("CloseSession() second call = true, want false")
	}
}

func TestSecretBrokerUsesRunSecretMetadata(t *testing.T) {
	secretValue := "npm_factory_broker_secret_value_456"
	input := RunSecretInput{
		Name:     "NPM_TOKEN",
		Source:   RunSecretSourceEnv,
		Required: false,
	}
	resolved := ResolvedRunSecret{
		Name:     input.Name,
		Source:   input.Source,
		Required: input.Required,
		Value:    secretValue,
	}

	broker := NewInMemorySecretBroker()
	session, err := broker.CreateSession(SecretBrokerSessionRequest{
		ID:              "broker-session-metadata",
		RequestedInputs: []RunSecretInput{input},
		ResolvedSecrets: []ResolvedRunSecret{resolved},
	})
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}
	if len(session.Secrets) != 1 {
		t.Fatalf("session secrets = %#v, want one entry", session.Secrets)
	}

	secretMetadata := session.Secrets[0]
	if got, want := secretMetadata.RunSecretMetadata(), resolved.Metadata(); got != want {
		t.Fatalf("RunSecretMetadata() = %#v, want %#v", got, want)
	}
	if got, want := secretMetadata.RunSecretInput(), input; got != want {
		t.Fatalf("RunSecretInput() = %#v, want %#v", got, want)
	}

	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("json.Marshal(session) error: %v", err)
	}
	payload := string(data)
	if strings.Contains(payload, secretValue) {
		t.Fatalf("session metadata JSON leaked secret value: %s", payload)
	}
	if strings.Contains(payload, "value") {
		t.Fatalf("session metadata JSON contains a value field: %s", payload)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("json.Unmarshal(session) error: %v", err)
	}
	requireExactJSONKeys(t, raw, []string{"id", "secrets"})
	secrets, ok := raw["secrets"].([]any)
	if !ok || len(secrets) != 1 {
		t.Fatalf("secrets = %#v, want one secret metadata entry", raw["secrets"])
	}
	firstSecret, ok := secrets[0].(map[string]any)
	if !ok {
		t.Fatalf("secrets[0] should be an object, got %T", secrets[0])
	}
	requireExactJSONKeys(t, firstSecret, []string{"id", "name", "source", "required", "present"})
}
