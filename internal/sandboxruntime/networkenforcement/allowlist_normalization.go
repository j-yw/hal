package networkenforcement

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// AllowlistRuleValidationCode identifies redaction-safe normalization failures.
type AllowlistRuleValidationCode string

const (
	AllowlistRuleValidationInvalidCategory     AllowlistRuleValidationCode = "invalid_category"
	AllowlistRuleValidationInvalidValue        AllowlistRuleValidationCode = "invalid_rule_value"
	AllowlistRuleValidationUnsafeValue         AllowlistRuleValidationCode = "unsafe_rule_value"
	AllowlistRuleValidationUnsupportedWildcard AllowlistRuleValidationCode = "unsupported_wildcard"
	AllowlistRuleValidationMalformedDomain     AllowlistRuleValidationCode = "malformed_domain"
	AllowlistRuleValidationMalformedEndpoint   AllowlistRuleValidationCode = "malformed_endpoint"
	AllowlistRuleValidationNonPrivateRange     AllowlistRuleValidationCode = "non_private_range"
	AllowlistRuleValidationNonMetadataEndpoint AllowlistRuleValidationCode = "non_metadata_endpoint"
	AllowlistRuleValidationNonLoopback         AllowlistRuleValidationCode = "non_loopback"
	AllowlistRuleValidationNonLinkLocal        AllowlistRuleValidationCode = "non_link_local"
)

// AllowlistRuleValidationError is safe to persist or return to callers. It
// intentionally omits the rejected raw rule value.
type AllowlistRuleValidationError struct {
	Code         AllowlistRuleValidationCode `json:"code"`
	RuleIndex    int                         `json:"ruleIndex"`
	RuleCategory AllowlistRuleCategory       `json:"ruleCategory,omitempty"`
	Message      string                      `json:"message,omitempty"`
}

func (e AllowlistRuleValidationError) Error() string {
	category := sanitizeAllowlistRuleCategory(e.RuleCategory)
	if category != "" {
		return fmt.Sprintf("allowlist rule %d %s failed validation: %s", e.RuleIndex, category, e.Code)
	}
	return fmt.Sprintf("allowlist rule %d failed validation: %s", e.RuleIndex, e.Code)
}

// AllowlistRuleNormalizationResult contains only redaction-safe normalized
// metadata: rule identifiers, category classes, operation labels, and sanitized
// validation errors.
type AllowlistRuleNormalizationResult struct {
	Valid          bool                           `json:"valid"`
	RuleIDs        []string                       `json:"ruleIds,omitempty"`
	RuleCategories []AllowlistRuleCategory        `json:"ruleCategories,omitempty"`
	Operations     []string                       `json:"operations,omitempty"`
	Errors         []AllowlistRuleValidationError `json:"errors,omitempty"`
}

// NormalizeAllowlistRules validates raw allowlist rule values, then returns
// only safe rule IDs, category classes, and stable operation labels. Raw rule
// values are never copied into the result.
func NormalizeAllowlistRules(rules []AllowlistRule) AllowlistRuleNormalizationResult {
	result := AllowlistRuleNormalizationResult{Valid: true}
	if len(rules) == 0 {
		return result
	}

	categories := make(map[AllowlistRuleCategory]bool)
	for i, rule := range rules {
		category := sanitizeAllowlistRuleCategory(rule.Category)
		if category == "" {
			result.addError(i, rule.Category, AllowlistRuleValidationInvalidCategory, "allowlist rule category is unsupported")
			continue
		}
		if code, message := validateAllowlistRuleValue(category, rule.Value); code != "" {
			result.addError(i, category, code, message)
			continue
		}
		if safeID := sanitizeIdentifier(rule.ID); safeID != "" {
			result.RuleIDs = append(result.RuleIDs, safeID)
		}
		categories[category] = true
	}

	result.RuleCategories = allowlistRuleCategoriesFromSet(categories)
	result.Operations = operationsForAllowlistRuleCategories(result.RuleCategories)
	result.Valid = len(result.Errors) == 0
	return result
}

func (r *AllowlistRuleNormalizationResult) addError(index int, category AllowlistRuleCategory, code AllowlistRuleValidationCode, message string) {
	r.Errors = append(r.Errors, AllowlistRuleValidationError{
		Code:         code,
		RuleIndex:    index,
		RuleCategory: sanitizeAllowlistRuleCategory(category),
		Message:      message,
	})
}

func validateAllowlistRuleValue(category AllowlistRuleCategory, value string) (AllowlistRuleValidationCode, string) {
	value = strings.TrimSpace(value)
	if unsafeAllowlistRuleValue(value) {
		return AllowlistRuleValidationUnsafeValue, "allowlist rule value contains unsafe metadata"
	}
	switch category {
	case AllowlistRuleCategoryDomain:
		return validateAllowlistDomainRuleValue(value)
	case AllowlistRuleCategoryEndpoint:
		return validateAllowlistEndpointRuleValue(value)
	case AllowlistRuleCategoryPrivateRange:
		return validateAllowlistReservedRuleValue(value, AllowlistRuleValidationNonPrivateRange, "allowlist private range rule value is unsupported", isAllowlistPrivateRangeValue)
	case AllowlistRuleCategoryMetadataEndpoint:
		return validateAllowlistReservedRuleValue(value, AllowlistRuleValidationNonMetadataEndpoint, "allowlist metadata endpoint rule value is unsupported", isAllowlistMetadataEndpointValue)
	case AllowlistRuleCategoryLoopback:
		return validateAllowlistReservedRuleValue(value, AllowlistRuleValidationNonLoopback, "allowlist loopback rule value is unsupported", isAllowlistLoopbackValue)
	case AllowlistRuleCategoryLinkLocal:
		return validateAllowlistReservedRuleValue(value, AllowlistRuleValidationNonLinkLocal, "allowlist link-local rule value is unsupported", isAllowlistLinkLocalValue)
	default:
		return AllowlistRuleValidationInvalidCategory, "allowlist rule category is unsupported"
	}
}

func validateAllowlistDomainRuleValue(value string) (AllowlistRuleValidationCode, string) {
	switch {
	case value == "":
		return AllowlistRuleValidationInvalidValue, "allowlist domain rule value is required"
	case strings.Contains(value, "*"):
		return AllowlistRuleValidationUnsupportedWildcard, "allowlist domain wildcards are unsupported"
	case !validAllowlistDomainName(value):
		return AllowlistRuleValidationMalformedDomain, "allowlist domain rule value is malformed"
	default:
		return "", ""
	}
}

func validateAllowlistEndpointRuleValue(value string) (AllowlistRuleValidationCode, string) {
	if value == "" {
		return AllowlistRuleValidationInvalidValue, "allowlist endpoint rule value is required"
	}
	host, port, ok := splitAllowlistEndpoint(value)
	if !ok || !validAllowlistEndpointPort(port) || !validAllowlistEndpointHost(host) {
		return AllowlistRuleValidationMalformedEndpoint, "allowlist endpoint rule value must be host:port"
	}
	return "", ""
}

func validateAllowlistReservedRuleValue(value string, invalidCode AllowlistRuleValidationCode, message string, valid func(string) bool) (AllowlistRuleValidationCode, string) {
	if valid(value) {
		return "", ""
	}
	return invalidCode, message
}

func unsafeAllowlistRuleValue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	for _, marker := range []string{
		"://",
		"@",
		"authorization",
		"bearer",
		"cookie",
		"header",
		"token",
		"secret",
		"credential",
		"password",
		"api-key",
		"api_key",
		"apikey",
		"access-key",
		"access_key",
		"private-key",
		"private_key",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return strings.ContainsAny(value, "?#\r\n\t \"'`{}<>|;&=$")
}

func validAllowlistDomainName(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || len(host) > 253 {
		return false
	}
	if strings.ContainsAny(host, ":/?#@") || strings.Contains(host, "*") {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return false
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
		for _, ch := range label {
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func splitAllowlistEndpoint(value string) (string, string, bool) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") {
		end := strings.Index(value, "]")
		if end <= 1 || len(value) <= end+2 || value[end+1] != ':' {
			return "", "", false
		}
		return value[1:end], value[end+2:], true
	}

	if strings.Count(value, ":") != 1 {
		return "", "", false
	}
	parts := strings.SplitN(value, ":", 2)
	if parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func validAllowlistEndpointPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func validAllowlistEndpointHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsValid()
	}
	return validAllowlistDomainName(host)
}

func isAllowlistPrivateRangeValue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || value == "private" || value == "rfc1918" || value == "unique_local" {
		return true
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.IsPrivate()
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return false
	}
	for _, allowed := range allowlistPrivatePrefixes() {
		if allowed.Contains(prefix.Addr()) && prefix.Bits() >= allowed.Bits() {
			return true
		}
	}
	return false
}

func isAllowlistMetadataEndpointValue(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return true
	}
	switch value {
	case "metadata.google.internal", "metadata.azure.internal":
		return true
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	for _, metadataAddr := range allowlistMetadataAddrs() {
		if addr == metadataAddr {
			return true
		}
	}
	return false
}

func isAllowlistLoopbackValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.IsLoopback()
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return false
	}
	for _, allowed := range allowlistLoopbackPrefixes() {
		if allowed.Contains(prefix.Addr()) && prefix.Bits() >= allowed.Bits() {
			return true
		}
	}
	return false
}

func isAllowlistLinkLocalValue(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	if addr, err := netip.ParseAddr(value); err == nil {
		return addr.IsLinkLocalUnicast()
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return false
	}
	for _, allowed := range allowlistLinkLocalPrefixes() {
		if allowed.Contains(prefix.Addr()) && prefix.Bits() >= allowed.Bits() {
			return true
		}
	}
	return false
}

func mergeAllowlistRuleCategories(values ...[]AllowlistRuleCategory) []AllowlistRuleCategory {
	categories := make(map[AllowlistRuleCategory]bool)
	for _, current := range values {
		for _, value := range current {
			if category := sanitizeAllowlistRuleCategory(value); category != "" {
				categories[category] = true
			}
		}
	}
	return allowlistRuleCategoriesFromSet(categories)
}

func allowlistRuleCategoriesFromSet(categories map[AllowlistRuleCategory]bool) []AllowlistRuleCategory {
	if len(categories) == 0 {
		return nil
	}
	out := make([]AllowlistRuleCategory, 0, len(categories))
	for _, category := range orderedAllowlistRuleCategories() {
		if categories[category] {
			out = append(out, category)
		}
	}
	return out
}

func operationsForAllowlistRuleCategories(categories []AllowlistRuleCategory) []string {
	if len(categories) == 0 {
		return nil
	}
	operations := make([]string, 0, len(categories))
	for _, category := range categories {
		switch sanitizeAllowlistRuleCategory(category) {
		case AllowlistRuleCategoryDomain:
			operations = append(operations, planOperationAllowlistDomain)
		case AllowlistRuleCategoryEndpoint:
			operations = append(operations, planOperationAllowlistEndpoint)
		case AllowlistRuleCategoryPrivateRange:
			operations = append(operations, planOperationAllowlistPrivateRange)
		case AllowlistRuleCategoryMetadataEndpoint:
			operations = append(operations, planOperationAllowlistMetadata)
		case AllowlistRuleCategoryLoopback:
			operations = append(operations, planOperationAllowlistLoopback)
		case AllowlistRuleCategoryLinkLocal:
			operations = append(operations, planOperationAllowlistLinkLocal)
		}
	}
	return operations
}

func appendSanitizedIdentifiers(values []string, more ...string) []string {
	for _, value := range more {
		if current := sanitizeIdentifier(value); current != "" {
			values = append(values, current)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func orderedAllowlistRuleCategories() []AllowlistRuleCategory {
	return []AllowlistRuleCategory{
		AllowlistRuleCategoryDomain,
		AllowlistRuleCategoryEndpoint,
		AllowlistRuleCategoryPrivateRange,
		AllowlistRuleCategoryMetadataEndpoint,
		AllowlistRuleCategoryLoopback,
		AllowlistRuleCategoryLinkLocal,
	}
}

func allowlistPrivatePrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
	}
}

func allowlistMetadataAddrs() []netip.Addr {
	return []netip.Addr{
		netip.MustParseAddr("169.254.169.254"),
		netip.MustParseAddr("169.254.170.2"),
		netip.MustParseAddr("fd00:ec2::254"),
	}
}

func allowlistLoopbackPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
}

func allowlistLinkLocalPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("fe80::/10"),
	}
}
