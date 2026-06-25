package factory

import (
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
