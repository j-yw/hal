package factory

import (
	"encoding/json"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/verify"
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

// RedactRunRecord returns a copy of record with resolved run-scoped secret
// values removed from durable string metadata.
func (r RunSecretRedactor) RedactRunRecord(record RunRecord) RunRecord {
	if len(r.secretValues) == 0 {
		return record
	}
	record.Status = r.RedactString(record.Status)
	record.ExecutorMode = r.RedactString(record.ExecutorMode)
	record.Source = r.redactSourceMetadata(record.Source)
	record.RepoPath = r.RedactString(record.RepoPath)
	record.RepoRemote = r.RedactString(record.RepoRemote)
	record.BranchName = r.RedactString(record.BranchName)
	record.BaseBranch = r.RedactString(record.BaseBranch)
	record.SandboxName = r.RedactString(record.SandboxName)
	record.Sandbox = r.redactSandboxMetadata(record.Sandbox)
	record.CurrentStep = r.RedactString(record.CurrentStep)
	record.Artifacts = r.redactArtifactReferences(record.Artifacts)
	record.Verification = r.redactVerificationRecord(record.Verification)
	record.Failure = r.redactFailureSummary(record.Failure)
	record.Secrets = r.redactSecretMetadata(record.Secrets)
	return record
}

func (r RunSecretRedactor) redactSourceMetadata(source SourceMetadata) SourceMetadata {
	source.Kind = r.RedactString(source.Kind)
	source.Path = r.RedactString(source.Path)
	source.ReportPath = r.RedactString(source.ReportPath)
	source.Title = r.RedactString(source.Title)
	return source
}

func (r RunSecretRedactor) redactSandboxMetadata(sandbox *SandboxMetadata) *SandboxMetadata {
	if sandbox == nil {
		return nil
	}
	safe := *sandbox
	safe.Name = r.RedactString(safe.Name)
	safe.Provider = r.RedactString(safe.Provider)
	safe.Status = r.RedactString(safe.Status)
	safe.Connection = r.redactSandboxConnectionMetadata(safe.Connection)
	safe.SSHCommand = r.RedactString(safe.SSHCommand)
	safe.CleanupCommand = r.RedactString(safe.CleanupCommand)
	safe.Handoff = r.RedactString(safe.Handoff)
	return &safe
}

func (r RunSecretRedactor) redactSandboxConnectionMetadata(connection *SandboxConnectionMetadata) *SandboxConnectionMetadata {
	if connection == nil {
		return nil
	}
	safe := *connection
	safe.Address = r.RedactString(safe.Address)
	safe.PublicIP = r.RedactString(safe.PublicIP)
	safe.TailscaleIP = r.RedactString(safe.TailscaleIP)
	safe.TailscaleHostname = r.RedactString(safe.TailscaleHostname)
	return &safe
}

func (r RunSecretRedactor) redactArtifactReferences(artifacts []ArtifactReference) []ArtifactReference {
	if len(artifacts) == 0 {
		return nil
	}
	safe := make([]ArtifactReference, len(artifacts))
	for i, artifact := range artifacts {
		safe[i] = r.RedactArtifactReference(artifact)
	}
	return safe
}

func (r RunSecretRedactor) redactVerificationRecord(verification *VerificationRecord) *VerificationRecord {
	if verification == nil {
		return nil
	}
	safe := *verification
	if len(verification.Artifacts) > 0 {
		safe.Artifacts = make([]verify.ArtifactReference, len(verification.Artifacts))
		for i, artifact := range verification.Artifacts {
			safe.Artifacts[i] = verify.ArtifactReference{
				CheckID: r.RedactString(artifact.CheckID),
				Kind:    r.RedactString(artifact.Kind),
				Path:    r.RedactString(artifact.Path),
			}
		}
	}
	return &safe
}

func (r RunSecretRedactor) redactFailureSummary(failure *FailureSummary) *FailureSummary {
	if failure == nil {
		return nil
	}
	safe := *failure
	safe.Step = r.RedactString(safe.Step)
	safe.Category = r.RedactString(safe.Category)
	safe.Message = r.RedactString(safe.Message)
	safe.SuggestedCommand = r.RedactString(safe.SuggestedCommand)
	return &safe
}

func (r RunSecretRedactor) redactSecretMetadata(secrets []RunSecretMetadata) []RunSecretMetadata {
	if len(secrets) == 0 {
		return nil
	}
	safe := make([]RunSecretMetadata, len(secrets))
	copy(safe, secrets)
	return safe
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
	addRunSecretRedactionCandidate(values, value)

	for _, fragment := range strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r'
	}) {
		trimmed := strings.TrimSpace(fragment)
		if trimmed == "" {
			continue
		}
		addRunSecretRedactionCandidate(values, fragment)
		addRunSecretRedactionCandidate(values, trimmed)
	}
}

func addRunSecretRedactionCandidate(values map[string]struct{}, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	for _, candidate := range []string{
		value,
		url.PathEscape(value),
		url.QueryEscape(value),
		runSecretUserinfoEscape(value),
	} {
		addRunSecretRedactionLiteral(values, candidate)
	}
}

func addRunSecretRedactionLiteral(values map[string]struct{}, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	values[value] = struct{}{}
	for _, encoded := range runSecretSerializedStringVariants(value) {
		values[encoded] = struct{}{}
	}
}

func runSecretSerializedStringVariants(value string) []string {
	var variants []string
	if encoded, err := json.Marshal(value); err == nil {
		variants = append(variants, trimRunSecretQuotedString(string(encoded)))
	}
	variants = append(variants, trimRunSecretQuotedString(strconv.Quote(value)))
	return variants
}

func trimRunSecretQuotedString(value string) string {
	if len(value) >= 2 {
		return value[1 : len(value)-1]
	}
	return value
}

func runSecretUserinfoEscape(value string) string {
	const userinfoPrefix = "__hal_secret__:"
	return strings.TrimPrefix(url.UserPassword("__hal_secret__", value).String(), userinfoPrefix)
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
