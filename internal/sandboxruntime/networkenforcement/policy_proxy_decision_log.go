package networkenforcement

import "encoding/json"

// PolicyProxyDecisionLogInput carries raw proxy request context for the
// in-memory decision logger. Raw fields are validation-only inputs and must not
// be copied into durable decision-log metadata.
type PolicyProxyDecisionLogInput struct {
	Policy         PolicyProxyDecisionPolicy
	Request        PolicyProxyDecisionRequest
	RawURL         string
	QueryString    string
	Headers        map[string]string
	Token          string
	Credential     string
	SocketPath     string
	ProviderDetail string
	LocalPath      string
}

// PolicyProxyDecisionLogRecord is the durable redaction-safe policy proxy
// decision log record. It carries only policy/rule identifiers, safe decision
// labels, destination category metadata, and counters.
type PolicyProxyDecisionLogRecord struct {
	PolicySnapshotID    string                        `json:"policySnapshotId,omitempty"`
	RuleSetID           string                        `json:"ruleSetId,omitempty"`
	RuleID              string                        `json:"ruleId,omitempty"`
	Action              PolicyProxyDecisionAction     `json:"action,omitempty"`
	ReasonCode          PolicyProxyDecisionReasonCode `json:"reasonCode,omitempty"`
	DestinationCategory AllowlistRuleCategory         `json:"destinationCategory,omitempty"`
	Count               int                           `json:"count,omitempty"`
}

// PolicyProxyDecisionLogCounters contains aggregate decision counters without
// carrying destination labels, hosts, URLs, paths, or provider-specific data.
type PolicyProxyDecisionLogCounters struct {
	Total                 int                                     `json:"total,omitempty"`
	Allowed               int                                     `json:"allowed,omitempty"`
	Denied                int                                     `json:"denied,omitempty"`
	ByDestinationCategory []PolicyProxyDestinationCategoryCounter `json:"byDestinationCategory,omitempty"`
}

// PolicyProxyDestinationCategoryCounter counts decisions for one safe
// destination category.
type PolicyProxyDestinationCategoryCounter struct {
	DestinationCategory AllowlistRuleCategory `json:"destinationCategory,omitempty"`
	Count               int                   `json:"count,omitempty"`
}

// BuildPolicyProxyDecisionLogRecord converts an in-memory proxy decision into
// durable redaction-safe decision-log metadata.
func BuildPolicyProxyDecisionLogRecord(input PolicyProxyDecisionLogInput) PolicyProxyDecisionLogRecord {
	decision := EvaluatePolicyProxyDecision(input.Policy, input.Request)
	record := PolicyProxyDecisionLogRecord{
		PolicySnapshotID:    policyProxyDecisionPolicySnapshotID(decision.PolicySnapshot),
		RuleSetID:           decision.RuleSetID,
		RuleID:              decision.RuleID,
		Action:              decision.Action,
		ReasonCode:          decision.ReasonCode,
		DestinationCategory: decision.RuleCategory,
		Count:               1,
	}
	return SanitizePolicyProxyDecisionLogRecord(record)
}

// SummarizePolicyProxyDecisionLogRecords aggregates sanitized decision-log
// counters by action and destination category.
func SummarizePolicyProxyDecisionLogRecords(records []PolicyProxyDecisionLogRecord) PolicyProxyDecisionLogCounters {
	if len(records) == 0 {
		return PolicyProxyDecisionLogCounters{}
	}
	counters := PolicyProxyDecisionLogCounters{}
	for _, record := range records {
		sanitized := SanitizePolicyProxyDecisionLogRecord(record)
		count := sanitized.Count
		if count == 0 {
			count = 1
		}
		counters.Total += count
		switch sanitized.Action {
		case PolicyProxyDecisionActionAllow:
			counters.Allowed += count
		case PolicyProxyDecisionActionDeny:
			counters.Denied += count
		}
		if sanitized.DestinationCategory != "" {
			counters.ByDestinationCategory = appendPolicyProxyDestinationCategoryCounter(
				counters.ByDestinationCategory,
				sanitized.DestinationCategory,
				count,
			)
		}
	}
	return SanitizePolicyProxyDecisionLogCounters(counters)
}

// SanitizePolicyProxyDecisionLogRecord returns a redaction-safe decision-log
// record copy.
func SanitizePolicyProxyDecisionLogRecord(record PolicyProxyDecisionLogRecord) PolicyProxyDecisionLogRecord {
	return PolicyProxyDecisionLogRecord{
		PolicySnapshotID:    sanitizeIdentifier(record.PolicySnapshotID),
		RuleSetID:           sanitizeIdentifier(record.RuleSetID),
		RuleID:              sanitizeIdentifier(record.RuleID),
		Action:              sanitizePolicyProxyDecisionAction(record.Action),
		ReasonCode:          sanitizePolicyProxyDecisionReasonCode(record.ReasonCode),
		DestinationCategory: sanitizeAllowlistRuleCategory(record.DestinationCategory),
		Count:               sanitizeDecisionLogCount(record.Count),
	}
}

// SanitizePolicyProxyDecisionLogCounters returns redaction-safe aggregate
// counters.
func SanitizePolicyProxyDecisionLogCounters(counters PolicyProxyDecisionLogCounters) PolicyProxyDecisionLogCounters {
	sanitized := PolicyProxyDecisionLogCounters{
		Total:   sanitizeDecisionLogCount(counters.Total),
		Allowed: sanitizeDecisionLogCount(counters.Allowed),
		Denied:  sanitizeDecisionLogCount(counters.Denied),
	}
	for _, counter := range counters.ByDestinationCategory {
		category := sanitizeAllowlistRuleCategory(counter.DestinationCategory)
		count := sanitizeDecisionLogCount(counter.Count)
		if category == "" || count == 0 {
			continue
		}
		sanitized.ByDestinationCategory = appendPolicyProxyDestinationCategoryCounter(
			sanitized.ByDestinationCategory,
			category,
			count,
		)
	}
	return sanitized
}

// MarshalJSON keeps durable decision-log JSON sanitized even when callers pass
// unsanitized records directly to encoding/json.
func (r PolicyProxyDecisionLogRecord) MarshalJSON() ([]byte, error) {
	type recordJSON PolicyProxyDecisionLogRecord
	sanitized := SanitizePolicyProxyDecisionLogRecord(r)
	return json.Marshal(recordJSON(sanitized))
}

// MarshalJSON keeps aggregate decision-log counter JSON sanitized.
func (c PolicyProxyDecisionLogCounters) MarshalJSON() ([]byte, error) {
	type countersJSON PolicyProxyDecisionLogCounters
	sanitized := SanitizePolicyProxyDecisionLogCounters(c)
	return json.Marshal(countersJSON(sanitized))
}

func (c PolicyProxyDestinationCategoryCounter) MarshalJSON() ([]byte, error) {
	type counterJSON PolicyProxyDestinationCategoryCounter
	sanitized := PolicyProxyDestinationCategoryCounter{
		DestinationCategory: sanitizeAllowlistRuleCategory(c.DestinationCategory),
		Count:               sanitizeDecisionLogCount(c.Count),
	}
	return json.Marshal(counterJSON(sanitized))
}

func policyProxyDecisionPolicySnapshotID(snapshot *PolicySnapshotIdentity) string {
	if snapshot == nil {
		return ""
	}
	return snapshot.ID
}

func appendPolicyProxyDestinationCategoryCounter(counters []PolicyProxyDestinationCategoryCounter, category AllowlistRuleCategory, count int) []PolicyProxyDestinationCategoryCounter {
	for i := range counters {
		if counters[i].DestinationCategory == category {
			counters[i].Count += count
			return counters
		}
	}
	return append(counters, PolicyProxyDestinationCategoryCounter{
		DestinationCategory: category,
		Count:               count,
	})
}

func sanitizeDecisionLogCount(count int) int {
	if count < 0 {
		return 0
	}
	return count
}
