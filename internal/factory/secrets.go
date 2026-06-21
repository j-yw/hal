package factory

import (
	"errors"
	"fmt"
	"strings"
)

// ErrRequiredRunSecretMissing marks failures caused by a required run secret
// that could not be resolved from its configured source.
var ErrRequiredRunSecretMissing = errors.New("required factory run secret is missing")

// RunSecretLookup resolves an environment variable name to its value.
type RunSecretLookup func(name string) (string, bool)

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

// ResolveRunSecrets resolves run-scoped secret inputs and returns both the
// in-memory values and the safe metadata that may be persisted on RunRecord.
func ResolveRunSecrets(inputs []RunSecretInput, lookup RunSecretLookup) ([]ResolvedRunSecret, []RunSecretMetadata, error) {
	if len(inputs) == 0 {
		return nil, nil, nil
	}
	if lookup == nil {
		return nil, nil, fmt.Errorf("factory run secret environment lookup dependency is required")
	}

	resolved := make([]ResolvedRunSecret, 0, len(inputs))
	metadata := make([]RunSecretMetadata, 0, len(inputs))
	for _, input := range inputs {
		secret, err := normalizeRunSecretInput(input)
		if err != nil {
			return resolved, metadata, err
		}

		switch secret.Source {
		case RunSecretSourceEnv:
			value, ok := lookup(secret.Name)
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
		default:
			return resolved, metadata, fmt.Errorf("unsupported factory run secret source %q for %s", secret.Source, secret.Name)
		}
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
