package sandbox

import (
	"net/netip"
	"strconv"
	"strings"
)

// SandboxNetworkPolicyValidationCode identifies a sanitized validation failure.
// Codes must not include raw rule values, endpoints, credentials, or queries.
type SandboxNetworkPolicyValidationCode string

const (
	SandboxNetworkPolicyValidationInvalidPreset        SandboxNetworkPolicyValidationCode = "invalid_preset"
	SandboxNetworkPolicyValidationInvalidRuleKind      SandboxNetworkPolicyValidationCode = "invalid_rule_kind"
	SandboxNetworkPolicyValidationInvalidDecision      SandboxNetworkPolicyValidationCode = "invalid_decision"
	SandboxNetworkPolicyValidationInvalidRuleValue     SandboxNetworkPolicyValidationCode = "invalid_rule_value"
	SandboxNetworkPolicyValidationUnsupportedWildcard  SandboxNetworkPolicyValidationCode = "unsupported_wildcard"
	SandboxNetworkPolicyValidationCredentialBearingURL SandboxNetworkPolicyValidationCode = "credential_bearing_url"
	SandboxNetworkPolicyValidationMalformedDomain      SandboxNetworkPolicyValidationCode = "malformed_domain"
	SandboxNetworkPolicyValidationMalformedEndpoint    SandboxNetworkPolicyValidationCode = "malformed_endpoint"
	SandboxNetworkPolicyValidationNonPrivateRange      SandboxNetworkPolicyValidationCode = "non_private_range"
	SandboxNetworkPolicyValidationNonMetadataEndpoint  SandboxNetworkPolicyValidationCode = "non_metadata_endpoint"
	SandboxNetworkPolicyValidationNonLoopback          SandboxNetworkPolicyValidationCode = "non_loopback"
	SandboxNetworkPolicyValidationNonLinkLocal         SandboxNetworkPolicyValidationCode = "non_link_local"
)

// SandboxNetworkPolicyDataDecision is a normalized data-only decision emitted
// by validation. It records policy semantics without implying enforcement.
type SandboxNetworkPolicyDataDecision string

const (
	SandboxNetworkPolicyDataDecisionDefaultDenyPosture   SandboxNetworkPolicyDataDecision = "default_deny_posture"
	SandboxNetworkPolicyDataDecisionDomainRule           SandboxNetworkPolicyDataDecision = "domain_rule"
	SandboxNetworkPolicyDataDecisionEndpointRule         SandboxNetworkPolicyDataDecision = "endpoint_rule"
	SandboxNetworkPolicyDataDecisionPrivateRangeRule     SandboxNetworkPolicyDataDecision = "private_range_rule"
	SandboxNetworkPolicyDataDecisionMetadataEndpointRule SandboxNetworkPolicyDataDecision = "metadata_endpoint_rule"
	SandboxNetworkPolicyDataDecisionLoopbackRule         SandboxNetworkPolicyDataDecision = "loopback_rule"
	SandboxNetworkPolicyDataDecisionLinkLocalRule        SandboxNetworkPolicyDataDecision = "link_local_rule"
)

// SandboxNetworkPolicyValidationError is safe to persist or return to callers.
// It intentionally omits the rejected raw rule value.
type SandboxNetworkPolicyValidationError struct {
	Code      SandboxNetworkPolicyValidationCode `json:"code"`
	RuleIndex int                                `json:"ruleIndex"`
	RuleKind  SandboxNetworkPolicyRuleKind       `json:"ruleKind,omitempty"`
	Message   string                             `json:"message,omitempty"`
}

// SandboxNetworkPolicyValidationDecision captures normalized rule semantics as
// metadata only. It does not describe runtime capability or enforcement.
type SandboxNetworkPolicyValidationDecision struct {
	Code      SandboxNetworkPolicyDataDecision `json:"code"`
	Preset    SandboxNetworkPolicyPreset       `json:"preset,omitempty"`
	RuleIndex int                              `json:"ruleIndex,omitempty"`
	RuleKind  SandboxNetworkPolicyRuleKind     `json:"ruleKind,omitempty"`
	Decision  SandboxNetworkPolicyDecision     `json:"decision,omitempty"`
}

// SandboxNetworkPolicyValidationResult is the deterministic output of pure
// policy validation. It deliberately has no enforcement or capability fields.
type SandboxNetworkPolicyValidationResult struct {
	Valid     bool                                     `json:"valid"`
	Decisions []SandboxNetworkPolicyValidationDecision `json:"decisions,omitempty"`
	Errors    []SandboxNetworkPolicyValidationError    `json:"errors,omitempty"`
}

// ValidateSandboxNetworkPolicyIntent validates requested policy data without
// performing DNS lookups, socket operations, HTTP calls, or runtime mutation.
func ValidateSandboxNetworkPolicyIntent(intent SandboxNetworkPolicyIntent) SandboxNetworkPolicyValidationResult {
	result := SandboxNetworkPolicyValidationResult{Valid: true}

	if intent.Preset != "" {
		if !validSandboxNetworkPolicyPreset(intent.Preset) {
			result.addError(-1, "", SandboxNetworkPolicyValidationInvalidPreset, "network policy preset is unsupported")
		} else if sandboxNetworkPolicyPresetNeedsDefaultDeny(intent.Preset) {
			result.Decisions = append(result.Decisions, SandboxNetworkPolicyValidationDecision{
				Code:   SandboxNetworkPolicyDataDecisionDefaultDenyPosture,
				Preset: intent.Preset,
			})
		}
	}

	for i, rule := range intent.Rules {
		result.validateRule(i, rule)
	}

	result.Valid = len(result.Errors) == 0
	return result
}

func (r *SandboxNetworkPolicyValidationResult) validateRule(index int, rule SandboxNetworkPolicyRule) {
	if !validSandboxNetworkPolicyRuleKind(rule.Kind) {
		r.addError(index, rule.Kind, SandboxNetworkPolicyValidationInvalidRuleKind, "network policy rule kind is unsupported")
		return
	}
	if !validSandboxNetworkPolicyDecision(rule.Decision) {
		r.addError(index, rule.Kind, SandboxNetworkPolicyValidationInvalidDecision, "network policy rule decision is unsupported")
		return
	}

	value := strings.TrimSpace(rule.Value)
	switch rule.Kind {
	case SandboxNetworkPolicyRuleKindDomain:
		r.validateDomainRule(index, rule, value)
	case SandboxNetworkPolicyRuleKindEndpoint:
		r.validateEndpointRule(index, rule, value)
	case SandboxNetworkPolicyRuleKindPrivateRange:
		r.validateReservedRangeRule(index, rule, value, SandboxNetworkPolicyValidationNonPrivateRange, SandboxNetworkPolicyDataDecisionPrivateRangeRule, isPrivateRangeValue)
	case SandboxNetworkPolicyRuleKindMetadataEndpoint:
		r.validateReservedRangeRule(index, rule, value, SandboxNetworkPolicyValidationNonMetadataEndpoint, SandboxNetworkPolicyDataDecisionMetadataEndpointRule, isMetadataEndpointValue)
	case SandboxNetworkPolicyRuleKindLoopback:
		r.validateReservedRangeRule(index, rule, value, SandboxNetworkPolicyValidationNonLoopback, SandboxNetworkPolicyDataDecisionLoopbackRule, isLoopbackValue)
	case SandboxNetworkPolicyRuleKindLinkLocal:
		r.validateReservedRangeRule(index, rule, value, SandboxNetworkPolicyValidationNonLinkLocal, SandboxNetworkPolicyDataDecisionLinkLocalRule, isLinkLocalValue)
	}
}

func (r *SandboxNetworkPolicyValidationResult) validateDomainRule(index int, rule SandboxNetworkPolicyRule, value string) {
	switch {
	case value == "":
		r.addError(index, rule.Kind, SandboxNetworkPolicyValidationInvalidRuleValue, "network policy domain rule value is required")
	case looksLikeCredentialBearingURL(value):
		r.addError(index, rule.Kind, SandboxNetworkPolicyValidationCredentialBearingURL, "network policy domain rule must be a hostname, not a URL")
	case strings.Contains(value, "*"):
		r.addError(index, rule.Kind, SandboxNetworkPolicyValidationUnsupportedWildcard, "network policy domain wildcards are unsupported")
	case !validPolicyDomainName(value):
		r.addError(index, rule.Kind, SandboxNetworkPolicyValidationMalformedDomain, "network policy domain rule value is malformed")
	default:
		r.addDecision(index, rule, SandboxNetworkPolicyDataDecisionDomainRule)
	}
}

func (r *SandboxNetworkPolicyValidationResult) validateEndpointRule(index int, rule SandboxNetworkPolicyRule, value string) {
	switch {
	case value == "":
		r.addError(index, rule.Kind, SandboxNetworkPolicyValidationInvalidRuleValue, "network policy endpoint rule value is required")
	case looksLikeCredentialBearingURL(value):
		r.addError(index, rule.Kind, SandboxNetworkPolicyValidationCredentialBearingURL, "network policy endpoint rule must be host and port metadata, not a URL")
	default:
		host, port, ok := splitPolicyEndpoint(value)
		if !ok || !validPolicyEndpointPort(port) || !validPolicyEndpointHost(host) {
			r.addError(index, rule.Kind, SandboxNetworkPolicyValidationMalformedEndpoint, "network policy endpoint rule value must be host:port")
			return
		}
		r.addDecision(index, rule, SandboxNetworkPolicyDataDecisionEndpointRule)
	}
}

func (r *SandboxNetworkPolicyValidationResult) validateReservedRangeRule(index int, rule SandboxNetworkPolicyRule, value string, invalidCode SandboxNetworkPolicyValidationCode, decisionCode SandboxNetworkPolicyDataDecision, valid func(string) bool) {
	switch {
	case looksLikeCredentialBearingURL(value):
		r.addError(index, rule.Kind, SandboxNetworkPolicyValidationCredentialBearingURL, "network policy reserved range rule must be metadata, not a URL")
	case !valid(value):
		r.addError(index, rule.Kind, invalidCode, "network policy reserved range rule value is unsupported")
	default:
		r.addDecision(index, rule, decisionCode)
	}
}

func (r *SandboxNetworkPolicyValidationResult) addDecision(index int, rule SandboxNetworkPolicyRule, code SandboxNetworkPolicyDataDecision) {
	r.Decisions = append(r.Decisions, SandboxNetworkPolicyValidationDecision{
		Code:      code,
		RuleIndex: index,
		RuleKind:  rule.Kind,
		Decision:  rule.Decision,
	})
}

func (r *SandboxNetworkPolicyValidationResult) addError(index int, kind SandboxNetworkPolicyRuleKind, code SandboxNetworkPolicyValidationCode, message string) {
	r.Errors = append(r.Errors, SandboxNetworkPolicyValidationError{
		Code:      code,
		RuleIndex: index,
		RuleKind:  kind,
		Message:   message,
	})
}

func validSandboxNetworkPolicyPreset(preset SandboxNetworkPolicyPreset) bool {
	switch preset {
	case SandboxNetworkPolicyPresetLegacyDefault,
		SandboxNetworkPolicyPresetAllowListed,
		SandboxNetworkPolicyPresetDenyByDefault,
		SandboxNetworkPolicyPresetDisabled,
		SandboxNetworkPolicyPresetNoPolicy:
		return true
	default:
		return false
	}
}

func validSandboxNetworkPolicyRuleKind(kind SandboxNetworkPolicyRuleKind) bool {
	switch kind {
	case SandboxNetworkPolicyRuleKindDomain,
		SandboxNetworkPolicyRuleKindEndpoint,
		SandboxNetworkPolicyRuleKindPrivateRange,
		SandboxNetworkPolicyRuleKindMetadataEndpoint,
		SandboxNetworkPolicyRuleKindLoopback,
		SandboxNetworkPolicyRuleKindLinkLocal:
		return true
	default:
		return false
	}
}

func validSandboxNetworkPolicyDecision(decision SandboxNetworkPolicyDecision) bool {
	switch decision {
	case SandboxNetworkPolicyDecisionAllow, SandboxNetworkPolicyDecisionDeny:
		return true
	default:
		return false
	}
}

func looksLikeCredentialBearingURL(value string) bool {
	value = strings.TrimSpace(value)
	return strings.Contains(value, "://") ||
		strings.Contains(value, "@") ||
		strings.Contains(value, "?") ||
		strings.Contains(value, "#")
}

func validPolicyDomainName(host string) bool {
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

func splitPolicyEndpoint(value string) (string, string, bool) {
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

func validPolicyEndpointPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func validPolicyEndpointHost(host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.IsValid()
	}
	return validPolicyDomainName(host)
}

func isPrivateRangeValue(value string) bool {
	value = strings.TrimSpace(value)
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
	for _, allowed := range privatePolicyPrefixes() {
		if allowed.Contains(prefix.Addr()) && prefix.Bits() >= allowed.Bits() {
			return true
		}
	}
	return false
}

func isMetadataEndpointValue(value string) bool {
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
	for _, metadataAddr := range metadataPolicyAddrs() {
		if addr == metadataAddr {
			return true
		}
	}
	return false
}

func isLoopbackValue(value string) bool {
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
	for _, allowed := range loopbackPolicyPrefixes() {
		if allowed.Contains(prefix.Addr()) && prefix.Bits() >= allowed.Bits() {
			return true
		}
	}
	return false
}

func isLinkLocalValue(value string) bool {
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
	for _, allowed := range linkLocalPolicyPrefixes() {
		if allowed.Contains(prefix.Addr()) && prefix.Bits() >= allowed.Bits() {
			return true
		}
	}
	return false
}

func privatePolicyPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("fc00::/7"),
	}
}

func metadataPolicyAddrs() []netip.Addr {
	return []netip.Addr{
		netip.MustParseAddr("169.254.169.254"),
		netip.MustParseAddr("169.254.170.2"),
		netip.MustParseAddr("fd00:ec2::254"),
	}
}

func loopbackPolicyPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}
}

func linkLocalPolicyPrefixes() []netip.Prefix {
	return []netip.Prefix{
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("fe80::/10"),
	}
}
