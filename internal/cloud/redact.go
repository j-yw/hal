package cloud

import (
	"regexp"
	"strings"
)

const redactedPlaceholder = "[REDACTED]"

// RedactionRule defines a single masking rule with a name and compiled regex.
type RedactionRule struct {
	Name    string
	Pattern *regexp.Regexp
}

// defaultRules is the ordered set of redaction rules applied by Redact.
// Each rule targets a specific secret pattern with deterministic masking.
var defaultRules = []RedactionRule{
	{
		Name: "bearer_token",
		// Matches: Bearer <token> in headers (base64, hex, JWT-like)
		Pattern: regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9\-._~+/]+=*`),
	},
	{
		Name: "github_pat_fine_grained",
		// Matches: GitHub fine-grained PATs (github_pat_...)
		Pattern: regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`),
	},
	{
		Name: "github_pat_classic",
		// Matches: GitHub classic PATs (ghp_, gho_, ghu_, ghs_, ghr_)
		Pattern: regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{36,}`),
	},
	{
		Name: "device_code",
		// Matches: OAuth device codes (typically 8+ hex/alphanumeric with hyphens)
		// Format: device_code=<value> or "device_code":"<value>"
		Pattern: regexp.MustCompile(`(device_code[=:"]+\s*)[A-Za-z0-9\-]{8,}`),
	},
	{
		Name: "session_cookie",
		// Matches: session cookie assignments (session=, _session=, sid=, session_id=, connect.sid=)
		Pattern: regexp.MustCompile(`((?:_?session(?:_id)?|sid|connect\.sid)\s*=\s*)[A-Za-z0-9\-._~+/%:=]+`),
	},
	{
		Name: "api_key_param",
		// Matches: api_key=<value> or api-key=<value> in query strings, configs, and JSON
		// Requires explicit separator (- or _) between "api" and "key"
		Pattern: regexp.MustCompile(`(?i)((?:api[-_]key)(?:\s*[=:]\s*"?|"\s*:\s*"?))[A-Za-z0-9\-._~+/]+=*`),
	},
	{
		Name: "x_api_key_header",
		// Matches: X-Api-Key: <value> header
		Pattern: regexp.MustCompile(`(?i)(X-Api-Key:\s*)[A-Za-z0-9\-._~+/]+=*`),
	},
	{
		Name: "authorization_basic",
		// Matches: Basic <base64-credentials> in Authorization headers
		Pattern: regexp.MustCompile(`(?i)(Basic\s+)[A-Za-z0-9+/]+=*`),
	},
	{
		Name: "sk_live_key",
		// Matches: Stripe-style secret keys (sk_live_, sk_test_, rk_live_, rk_test_)
		Pattern: regexp.MustCompile(`[sr]k_(?:live|test)_[A-Za-z0-9]{20,}`),
	},
}

// Redact applies all default redaction rules to the input string.
// Each matched secret is replaced with [REDACTED].
// Rules are applied in order; later rules do not re-match prior replacements.
func Redact(input string) string {
	result := input
	for _, rule := range defaultRules {
		result = applyRule(rule, result)
	}
	return result
}

// RedactWith applies the given rules to the input string.
// This allows callers to use custom rule sets for testing or extension.
func RedactWith(input string, rules []RedactionRule) string {
	result := input
	for _, rule := range rules {
		result = applyRule(rule, result)
	}
	return result
}

// DefaultRedactionRules returns a copy of the default rule set.
func DefaultRedactionRules() []RedactionRule {
	rules := make([]RedactionRule, len(defaultRules))
	copy(rules, defaultRules)
	return rules
}

// applyRule replaces matches of the rule's pattern with [REDACTED].
// If the pattern has a capture group, only the part after the group is replaced,
// preserving the prefix (e.g., "Bearer " stays, the token is replaced).
func applyRule(rule RedactionRule, input string) string {
	return rule.Pattern.ReplaceAllStringFunc(input, func(match string) string {
		loc := rule.Pattern.FindStringSubmatchIndex(match)
		// If there's a capture group (prefix to preserve), keep it
		if len(loc) >= 4 && loc[2] >= 0 {
			prefix := match[:loc[3]-loc[0]]
			return prefix + redactedPlaceholder
		}
		return redactedPlaceholder
	})
}

// RedactBytes applies all default redaction rules to the input byte slice.
func RedactBytes(input []byte) []byte {
	return []byte(Redact(string(input)))
}

// ContainsSecret checks if the input appears to contain any known secret patterns.
func ContainsSecret(input string) bool {
	for _, rule := range defaultRules {
		if rule.Pattern.MatchString(input) {
			return true
		}
	}
	return false
}

// RedactMultiline applies redaction to each line of input independently.
// This is useful for log streams where each line may contain different secrets.
func RedactMultiline(input string) string {
	lines := strings.Split(input, "\n")
	for i, line := range lines {
		lines[i] = Redact(line)
	}
	return strings.Join(lines, "\n")
}
