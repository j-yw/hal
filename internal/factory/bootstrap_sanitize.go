package factory

import (
	"encoding/json"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

const (
	bootstrapRedactedValue  = "[REDACTED]"
	bootstrapRedactedEnvKey = "[REDACTED_ENV]"
)

// BootstrapSanitizer redacts secret values and sensitive environment key names
// from records that may be persisted or shown in bootstrap timelines.
type BootstrapSanitizer struct {
	secretValues []string
	envKeys      []string
}

// NewBootstrapSanitizer builds a redactor from environment values attached to
// a bootstrap request. It intentionally keeps storage and policy decisions out
// of the bootstrap package; callers decide which values enter the request.
func NewBootstrapSanitizer(request BootstrapRequest) BootstrapSanitizer {
	valueSet := map[string]struct{}{}
	keySet := map[string]struct{}{}

	addKey := func(key string) {
		key = strings.TrimSpace(key)
		if key == "" || !isSensitiveBootstrapEnvKey(key) {
			return
		}
		keySet[key] = struct{}{}
		if value := request.Env[key]; value != "" {
			addBootstrapRedactionValue(valueSet, value)
		}
	}

	for key, value := range request.Env {
		if !isSensitiveBootstrapEnvKey(key) {
			continue
		}
		keySet[strings.TrimSpace(key)] = struct{}{}
		if value != "" {
			addBootstrapRedactionValue(valueSet, value)
		}
	}
	for _, key := range request.RequiredEnvKeys {
		addKey(key)
	}
	addURLCredentialRedactionTokens(valueSet, request.RepositoryURL)
	for _, value := range request.secretValues {
		addBootstrapRedactionValue(valueSet, value)
	}

	return BootstrapSanitizer{
		secretValues: sortedRedactionTokens(valueSet),
		envKeys:      sortedRedactionTokens(keySet),
	}
}

func addURLCredentialRedactionTokens(valueSet map[string]struct{}, rawURL string) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return
	}

	addSCPStyleURLCredentialRedactionTokens(valueSet, rawURL)

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return
	}

	if parsed.User != nil {
		if userinfo := parsed.User.String(); userinfo != "" {
			addBootstrapRedactionValue(valueSet, userinfo)
		}
		if username := parsed.User.Username(); bootstrapCredentialTokenLooksSensitive(username) {
			addBootstrapRedactionValue(valueSet, username)
		}
		if password, ok := parsed.User.Password(); ok && password != "" {
			addBootstrapRedactionValue(valueSet, password)
		}
	}
	addURLCredentialParameterRedactionTokens(valueSet, parsed.RawQuery)
	addURLCredentialParameterRedactionTokens(valueSet, parsed.Fragment)
}

func addSCPStyleURLCredentialRedactionTokens(valueSet map[string]struct{}, rawURL string) {
	if strings.Contains(rawURL, "://") || !strings.Contains(rawURL, "@") {
		return
	}

	for i := 0; i < len(rawURL); {
		atOffset := strings.Index(rawURL[i:], "@")
		if atOffset < 0 {
			return
		}
		at := i + atOffset
		start := at
		for start > 0 && bootstrapSCPStyleUserinfoChar(rawURL[start-1]) {
			start--
		}
		userinfo := rawURL[start:at]
		hostStart := at + 1
		hostEnd := hostStart
		for hostEnd < len(rawURL) && bootstrapSCPStyleHostChar(rawURL[hostEnd]) {
			hostEnd++
		}
		if userinfo == "" || hostEnd == hostStart || hostEnd >= len(rawURL) || rawURL[hostEnd] != ':' {
			i = at + 1
			continue
		}
		pathStart := hostEnd + 1
		if pathStart >= len(rawURL) || bootstrapSCPStylePathTerminator(rawURL[pathStart]) {
			i = at + 1
			continue
		}
		if !bootstrapSCPStyleUserinfoLooksCredentialed(userinfo, rawURL[hostStart:hostEnd]) {
			i = at + 1
			continue
		}
		addBootstrapRedactionValue(valueSet, userinfo)
		if separator := strings.LastIndex(userinfo, ":"); separator >= 0 && separator+1 < len(userinfo) {
			addBootstrapRedactionValue(valueSet, userinfo[separator+1:])
		}
		i = at + 1
	}
}

func bootstrapSCPStyleUserinfoChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '.' || ch == '_' || ch == '-' || ch == '+' || ch == ':' || ch == '%'
}

func bootstrapSCPStyleHostChar(ch byte) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9') ||
		ch == '.' || ch == '-' || ch == '_' || ch == '[' || ch == ']'
}

func bootstrapSCPStylePathTerminator(ch byte) bool {
	switch ch {
	case ' ', '\t', '\n', '\r', '"', '\'', '<', '>', '`':
		return true
	default:
		return false
	}
}

func bootstrapSCPStyleUserinfoLooksCredentialed(userinfo, host string) bool {
	normalized := strings.ToLower(strings.TrimSpace(userinfo))
	if normalized == "" || normalized == "git" {
		return false
	}
	if strings.Contains(normalized, ":") || bootstrapCredentialTokenLooksSensitive(normalized) {
		return true
	}
	switch strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]") {
	case "github.com", "ssh.github.com", "gitlab.com", "bitbucket.org":
		return true
	default:
		return false
	}
}

func bootstrapCredentialTokenLooksSensitive(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return false
	}
	if isSensitiveBootstrapEnvKey(normalized) {
		return true
	}
	for _, marker := range []string{"ghp_", "github_pat_", "glpat", "oauth", "x-access-token", "x-token-auth"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func addURLCredentialParameterRedactionTokens(valueSet map[string]struct{}, rawParameters string) {
	rawParameters = strings.TrimSpace(rawParameters)
	if rawParameters == "" {
		return
	}
	values, err := url.ParseQuery(rawParameters)
	if err != nil {
		return
	}
	for key, params := range values {
		if !isSensitiveBootstrapEnvKey(key) {
			continue
		}
		for _, value := range params {
			addBootstrapRedactionValue(valueSet, value)
		}
	}
}

func addBootstrapRedactionValue(values map[string]struct{}, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	addBootstrapRedactionCandidate(values, value)

	for _, fragment := range strings.FieldsFunc(value, func(r rune) bool {
		return r == '\n' || r == '\r'
	}) {
		trimmed := strings.TrimSpace(fragment)
		if trimmed == "" {
			continue
		}
		addBootstrapRedactionCandidate(values, fragment)
		addBootstrapRedactionCandidate(values, trimmed)
	}
}

func addBootstrapRedactionCandidate(values map[string]struct{}, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	for _, candidate := range []string{
		value,
		url.PathEscape(value),
		url.QueryEscape(value),
		bootstrapUserinfoEscape(value),
	} {
		addBootstrapRedactionLiteral(values, candidate)
	}
}

func addBootstrapRedactionLiteral(values map[string]struct{}, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	values[value] = struct{}{}
	for _, encoded := range bootstrapSerializedStringVariants(value) {
		values[encoded] = struct{}{}
	}
}

func bootstrapSerializedStringVariants(value string) []string {
	var variants []string
	if encoded, err := json.Marshal(value); err == nil {
		variants = append(variants, trimBootstrapQuotedString(string(encoded)))
	}
	variants = append(variants, trimBootstrapQuotedString(strconv.Quote(value)))
	return variants
}

func trimBootstrapQuotedString(value string) string {
	if len(value) >= 2 {
		return value[1 : len(value)-1]
	}
	return value
}

func bootstrapUserinfoEscape(value string) string {
	const userinfoPrefix = "__hal_bootstrap__:"
	return strings.TrimPrefix(url.UserPassword("__hal_bootstrap__", value).String(), userinfoPrefix)
}

// SanitizeBootstrapCommand returns a copy of command with sensitive args,
// directories, and env entries redacted for records and tests.
func SanitizeBootstrapCommand(request BootstrapRequest, command BootstrapCommand) BootstrapCommand {
	return NewBootstrapSanitizer(request).SanitizeCommand(command)
}

// SanitizeBootstrapCommandResult returns a copy of result with sensitive output
// and metadata redacted for records and tests.
func SanitizeBootstrapCommandResult(request BootstrapRequest, result BootstrapCommandResult) BootstrapCommandResult {
	return NewBootstrapSanitizer(request).SanitizeCommandResult(result)
}

// SanitizeBootstrapTimelineEvent returns a copy of event with sensitive output
// and metadata redacted before timeline persistence.
func SanitizeBootstrapTimelineEvent(request BootstrapRequest, event BootstrapTimelineEvent) BootstrapTimelineEvent {
	return NewBootstrapSanitizer(request).SanitizeTimelineEvent(event)
}

func (s BootstrapSanitizer) SanitizeCommand(command BootstrapCommand) BootstrapCommand {
	command.Name = s.SanitizeString(command.Name)
	command.Dir = s.SanitizeString(command.Dir)
	command.Args = s.sanitizeStrings(command.Args)
	command.Env = s.sanitizeMap(command.Env, true)
	return command
}

func (s BootstrapSanitizer) SanitizeCommandResult(result BootstrapCommandResult) BootstrapCommandResult {
	result.StdoutSummary = s.SanitizeString(result.StdoutSummary)
	result.StderrSummary = s.SanitizeString(result.StderrSummary)
	result.OutputSummary = s.SanitizeString(result.OutputSummary)
	result.Metadata = s.sanitizeMap(result.Metadata, false)
	return result
}

func (s BootstrapSanitizer) SanitizeTimelineEvent(event BootstrapTimelineEvent) BootstrapTimelineEvent {
	event.Step = s.SanitizeString(event.Step)
	event.Status = s.SanitizeString(event.Status)
	event.Message = s.SanitizeString(event.Message)
	event.CommandSummary = s.SanitizeString(event.CommandSummary)
	event.OutputSummary = s.SanitizeString(event.OutputSummary)
	event.Metadata = s.sanitizeMap(event.Metadata, false)
	return event
}

func (s BootstrapSanitizer) SanitizeString(value string) string {
	for _, secret := range s.secretValues {
		value = strings.ReplaceAll(value, secret, bootstrapRedactedValue)
	}
	for _, key := range s.envKeys {
		value = strings.ReplaceAll(value, key, bootstrapRedactedEnvKey)
	}
	return value
}

func (s BootstrapSanitizer) sanitizeStrings(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = s.SanitizeString(value)
	}
	return out
}

func (s BootstrapSanitizer) sanitizeMap(values map[string]string, forceSensitiveValueRedaction bool) map[string]string {
	if values == nil {
		return nil
	}

	out := make(map[string]string, len(values))
	for key, value := range values {
		if isSensitiveBootstrapEnvKey(key) {
			out[bootstrapRedactedEnvKey] = bootstrapRedactedValue
			continue
		}

		sanitizedKey := s.SanitizeString(key)
		sanitizedValue := s.SanitizeString(value)
		if forceSensitiveValueRedaction && sanitizedKey == bootstrapRedactedEnvKey {
			sanitizedValue = bootstrapRedactedValue
		}
		out[sanitizedKey] = sanitizedValue
	}
	return out
}

func sortedRedactionTokens(values map[string]struct{}) []string {
	tokens := make([]string, 0, len(values))
	for value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
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

func isSensitiveBootstrapEnvKey(key string) bool {
	key = strings.ToUpper(strings.TrimSpace(key))
	if key == "" {
		return false
	}

	parts := strings.FieldsFunc(key, func(r rune) bool {
		return r == '_' || r == '-' || r == '.'
	})
	for _, part := range parts {
		switch part {
		case "AUTH", "CREDENTIAL", "CREDENTIALS", "KEY", "PASS", "PASSWD", "PASSWORD", "PRIVATE", "SECRET", "TOKEN":
			return true
		}
	}
	return false
}
