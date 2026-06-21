package factory

import (
	"errors"
	"fmt"
	"strings"
)

// ErrRequiredRunSecretMissing marks failures caused by a required run secret
// that could not be resolved from its configured source.
var ErrRequiredRunSecretMissing = errors.New("required factory run secret is missing")

// ErrUnsupportedRunSecretSource marks failures caused by a run secret source
// that has no configured provider.
var ErrUnsupportedRunSecretSource = errors.New("unsupported factory run secret source")

// RunSecretLookup resolves an environment variable name to its value.
type RunSecretLookup func(name string) (string, bool)

// RunSecretProvider resolves one run-scoped secret from a configured source.
// Providers must return raw values only to in-memory callers; durable state uses
// RunSecretMetadata instead.
type RunSecretProvider interface {
	ResolveRunSecret(secret RunSecretInput) (value string, ok bool, err error)
}

// RunSecretProviderFunc adapts a function to RunSecretProvider.
type RunSecretProviderFunc func(secret RunSecretInput) (value string, ok bool, err error)

// ResolveRunSecret implements RunSecretProvider.
func (f RunSecretProviderFunc) ResolveRunSecret(secret RunSecretInput) (string, bool, error) {
	return f(secret)
}

// RunSecretProviders maps secret source names to their resolver.
type RunSecretProviders map[string]RunSecretProvider

// NewEnvRunSecretProvider builds the v1 env-backed secret provider.
func NewEnvRunSecretProvider(lookup RunSecretLookup) RunSecretProvider {
	return RunSecretProviderFunc(func(secret RunSecretInput) (string, bool, error) {
		if lookup == nil {
			return "", false, fmt.Errorf("factory run secret environment lookup dependency is required")
		}
		value, ok := lookup(secret.Name)
		return value, ok, nil
	})
}

// DefaultRunSecretProviders returns the providers implemented by v1 factory
// runs. Future token sources should be added here only after their resolver is
// implemented.
func DefaultRunSecretProviders(lookup RunSecretLookup) RunSecretProviders {
	return RunSecretProviders{
		RunSecretSourceEnv: NewEnvRunSecretProvider(lookup),
	}
}

// ResolvedRunSecret carries a resolved secret value in memory only. Do not
// persist this type or include it in user-facing JSON.
type ResolvedRunSecret struct {
	Name     string
	Source   string
	Required bool
	Value    string
}

// Metadata returns the redaction-safe durable representation of a resolved
// secret.
func (s ResolvedRunSecret) Metadata() RunSecretMetadata {
	return RunSecretMetadata{
		Name:     s.Name,
		Source:   s.Source,
		Required: s.Required,
		Present:  strings.TrimSpace(s.Value) != "",
	}
}

// RequiredRunSecretMissingError identifies which environment variable must be
// provided without including any secret value.
type RequiredRunSecretMissingError struct {
	Name string
}

func (e RequiredRunSecretMissingError) Error() string {
	name := strings.TrimSpace(e.Name)
	if name == "" {
		return "required factory run secret is missing or empty"
	}
	return fmt.Sprintf("required factory run secret %q is missing or empty; set environment variable %s before running factory execution", name, name)
}

func (e RequiredRunSecretMissingError) Unwrap() error {
	return ErrRequiredRunSecretMissing
}

// UnsupportedRunSecretSourceError identifies a source that does not have a
// configured provider.
type UnsupportedRunSecretSourceError struct {
	Name   string
	Source string
}

func (e UnsupportedRunSecretSourceError) Error() string {
	source := strings.TrimSpace(e.Source)
	name := strings.TrimSpace(e.Name)
	if source == "" {
		return "factory run secret source is unsupported"
	}
	if name == "" {
		return fmt.Sprintf("unsupported factory run secret source %q", source)
	}
	return fmt.Sprintf("unsupported factory run secret source %q for %s", source, name)
}

func (e UnsupportedRunSecretSourceError) Unwrap() error {
	return ErrUnsupportedRunSecretSource
}

// ResolveRunSecrets resolves run-scoped secret inputs and returns both the
// in-memory values and the safe metadata that may be persisted on RunRecord.
func ResolveRunSecrets(inputs []RunSecretInput, lookup RunSecretLookup) ([]ResolvedRunSecret, []RunSecretMetadata, error) {
	if len(inputs) == 0 {
		return nil, nil, nil
	}
	if lookup == nil {
		return nil, nil, fmt.Errorf("factory run secret environment lookup dependency is required")
	}

	return ResolveRunSecretsWithProviders(inputs, DefaultRunSecretProviders(lookup))
}

// ResolveRunSecretsWithProviders resolves run-scoped secret inputs using the
// provider registered for each source. This is the extension point for future
// non-env token sources; the default factory path currently registers only the
// env provider.
func ResolveRunSecretsWithProviders(inputs []RunSecretInput, providers RunSecretProviders) ([]ResolvedRunSecret, []RunSecretMetadata, error) {
	if len(inputs) == 0 {
		return nil, nil, nil
	}

	resolved := make([]ResolvedRunSecret, 0, len(inputs))
	metadata := make([]RunSecretMetadata, 0, len(inputs))
	for _, input := range inputs {
		secret, err := normalizeRunSecretInput(input)
		if err != nil {
			return resolved, metadata, err
		}

		provider, ok := providers[secret.Source]
		if !ok || provider == nil {
			return resolved, metadata, UnsupportedRunSecretSourceError{
				Name:   secret.Name,
				Source: secret.Source,
			}
		}

		value, ok, err := provider.ResolveRunSecret(secret)
		if err != nil {
			return resolved, metadata, fmt.Errorf("resolve factory run secret %s from %s: %w", secret.Name, secret.Source, err)
		}
		present := ok && strings.TrimSpace(value) != ""
		metadata = append(metadata, secret.Metadata(present))
		if !present {
			if secret.Required {
				return resolved, metadata, RequiredRunSecretMissingError{Name: secret.Name}
			}
			continue
		}
		resolved = append(resolved, ResolvedRunSecret{
			Name:     secret.Name,
			Source:   secret.Source,
			Required: secret.Required,
			Value:    value,
		})
	}
	return resolved, metadata, nil
}

func normalizeRunSecretInput(input RunSecretInput) (RunSecretInput, error) {
	secret := RunSecretInput{
		Name:     strings.TrimSpace(input.Name),
		Source:   strings.TrimSpace(input.Source),
		Required: input.Required,
	}
	if secret.Name == "" {
		return RunSecretInput{}, fmt.Errorf("factory run secret name is required")
	}
	if secret.Source == "" {
		return RunSecretInput{}, fmt.Errorf("factory run secret source is required for %s", secret.Name)
	}
	return secret, nil
}
