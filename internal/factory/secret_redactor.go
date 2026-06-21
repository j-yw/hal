package factory

import (
	"sort"
	"strings"
)

// RunSecretRedactionPlaceholder is the stable replacement for configured run
// secret values in user-facing output and persisted factory records.
const RunSecretRedactionPlaceholder = "[REDACTED]"

// RunSecretRedactor redacts resolved run-scoped secret values from strings.
type RunSecretRedactor struct {
	secretValues []string
}

// NewRunSecretRedactor builds a redactor from resolved in-memory run secrets.
func NewRunSecretRedactor(secrets []ResolvedRunSecret) RunSecretRedactor {
	if len(secrets) == 0 {
		return RunSecretRedactor{}
	}

	valueSet := make(map[string]struct{}, len(secrets))
	for _, secret := range secrets {
		addRunSecretRedactionValue(valueSet, secret.Value)
	}

	return RunSecretRedactor{
		secretValues: sortedRunSecretRedactionValues(valueSet),
	}
}

// RedactString replaces every configured secret value with the stable
// placeholder.
func (r RunSecretRedactor) RedactString(value string) string {
	for _, secret := range r.secretValues {
		value = strings.ReplaceAll(value, secret, RunSecretRedactionPlaceholder)
	}
	return value
}

func addRunSecretRedactionValue(values map[string]struct{}, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	values[value] = struct{}{}

	for _, fragment := range strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r'
	}) {
		trimmed := strings.TrimSpace(fragment)
		if trimmed == "" {
			continue
		}
		values[fragment] = struct{}{}
		values[trimmed] = struct{}{}
	}
}

func sortedRunSecretRedactionValues(values map[string]struct{}) []string {
	tokens := make([]string, 0, len(values))
	for value := range values {
		if strings.TrimSpace(value) != "" {
			tokens = append(tokens, value)
		}
	}
	sort.Slice(tokens, func(i, j int) bool {
		if len(tokens[i]) == len(tokens[j]) {
			return tokens[i] < tokens[j]
		}
		return len(tokens[i]) > len(tokens[j])
	})
	return tokens
}
