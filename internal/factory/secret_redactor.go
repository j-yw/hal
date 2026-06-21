package factory

import (
	"reflect"
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

// RedactArtifactReference returns a copy of artifact with run-scoped secret
// values removed from persisted string metadata.
func (r RunSecretRedactor) RedactArtifactReference(artifact ArtifactReference) ArtifactReference {
	if len(r.secretValues) == 0 {
		return artifact
	}
	artifact.ID = r.RedactString(artifact.ID)
	artifact.Name = r.RedactString(artifact.Name)
	artifact.Type = r.RedactString(artifact.Type)
	artifact.SourcePath = r.RedactString(artifact.SourcePath)
	artifact.StoredPath = r.RedactString(artifact.StoredPath)
	artifact.Path = r.RedactString(artifact.Path)
	artifact.URL = r.RedactString(artifact.URL)
	artifact.Summary = r.redactArtifactSummary(artifact.Summary)
	artifact.Warnings = r.redactStringSlice(artifact.Warnings)
	return artifact
}

func (r RunSecretRedactor) redactStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = r.RedactString(value)
	}
	return out
}

func (r RunSecretRedactor) redactArtifactSummary(summary map[string]any) map[string]any {
	if len(summary) == 0 {
		return nil
	}
	out := make(map[string]any, len(summary))
	for key, value := range summary {
		out[r.RedactString(key)] = r.redactArtifactValue(value)
	}
	return out
}

func (r RunSecretRedactor) redactArtifactValue(value any) any {
	switch v := value.(type) {
	case string:
		return r.RedactString(v)
	case map[string]any:
		return r.redactArtifactSummary(v)
	default:
		return r.redactArtifactReflectValue(reflect.ValueOf(value))
	}
}

func (r RunSecretRedactor) redactArtifactReflectValue(value reflect.Value) any {
	if !value.IsValid() {
		return nil
	}

	switch value.Kind() {
	case reflect.Interface, reflect.Pointer:
		if value.IsNil() {
			return nil
		}
		return r.redactArtifactReflectValue(value.Elem())
	case reflect.String:
		return r.RedactString(value.String())
	case reflect.Array, reflect.Slice:
		if value.Kind() == reflect.Slice && value.IsNil() {
			return nil
		}
		out := make([]any, value.Len())
		for i := 0; i < value.Len(); i++ {
			out[i] = r.redactArtifactReflectValue(value.Index(i))
		}
		return out
	case reflect.Map:
		if value.IsNil() {
			return nil
		}
		out := make(map[string]any, value.Len())
		iter := value.MapRange()
		for iter.Next() {
			key := iter.Key()
			if key.Kind() != reflect.String {
				continue
			}
			out[r.RedactString(key.String())] = r.redactArtifactReflectValue(iter.Value())
		}
		return out
	default:
		return value.Interface()
	}
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
