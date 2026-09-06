package networkenforcement

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestPolicyProxyDecisionLogsIncludeOnlySafeAllowAndDenyMetadata(t *testing.T) {
	policy := policyProxyDecisionContractPolicy()

	tests := []struct {
		name                    string
		input                   PolicyProxyDecisionLogInput
		wantAction              PolicyProxyDecisionAction
		wantRuleID              string
		wantReason              PolicyProxyDecisionReasonCode
		wantDestinationCategory AllowlistRuleCategory
	}{
		{
			name: "allow decision log preserves safe policy rule and category metadata",
			input: policyProxyDecisionLogInput(policy, PolicyProxyDecisionRequest{
				Kind:      PolicyProxyRequestKindHTTPConnect,
				Authority: "api.example.com:443",
			}),
			wantAction:              PolicyProxyDecisionActionAllow,
			wantRuleID:              "rule-api-endpoint",
			wantReason:              PolicyProxyDecisionReasonAllowRuleMatched,
			wantDestinationCategory: AllowlistRuleCategoryEndpoint,
		},
		{
			name: "deny decision log preserves safe policy and reason metadata",
			input: policyProxyDecisionLogInput(policy, PolicyProxyDecisionRequest{
				Kind: PolicyProxyRequestKindHTTPRequestHost,
				Host: "blocked.example.com",
			}),
			wantAction:              PolicyProxyDecisionActionDeny,
			wantReason:              PolicyProxyDecisionReasonDefaultDenyNoAllowRule,
			wantDestinationCategory: AllowlistRuleCategoryDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildPolicyProxyDecisionLogRecord(tt.input)

			if got.PolicySnapshotID != "policy-snapshot-proxy-01" {
				t.Fatalf("PolicySnapshotID = %q, want policy-snapshot-proxy-01 in %#v", got.PolicySnapshotID, got)
			}
			if got.RuleSetID != "rules-proxy-01" {
				t.Fatalf("RuleSetID = %q, want rules-proxy-01 in %#v", got.RuleSetID, got)
			}
			if got.RuleID != tt.wantRuleID {
				t.Fatalf("RuleID = %q, want %q in %#v", got.RuleID, tt.wantRuleID, got)
			}
			if got.Action != tt.wantAction {
				t.Fatalf("Action = %q, want %q in %#v", got.Action, tt.wantAction, got)
			}
			if got.ReasonCode != tt.wantReason {
				t.Fatalf("ReasonCode = %q, want %q in %#v", got.ReasonCode, tt.wantReason, got)
			}
			if got.DestinationCategory != tt.wantDestinationCategory {
				t.Fatalf("DestinationCategory = %q, want %q in %#v", got.DestinationCategory, tt.wantDestinationCategory, got)
			}
			if got.Count != 1 {
				t.Fatalf("Count = %d, want 1 in %#v", got.Count, got)
			}
			assertPolicyProxyDecisionLogJSONKeys(t, got, []string{
				"action",
				"count",
				"destinationCategory",
				"policySnapshotId",
				"reasonCode",
				"ruleSetId",
			}, optionalDecisionLogKeys("ruleId", got.RuleID)...)
		})
	}
}

func TestPolicyProxyDecisionLogsOmitRawRequestProviderCredentialAndPathDetails(t *testing.T) {
	policy := policyProxyDecisionContractPolicy()
	logs := []PolicyProxyDecisionLogRecord{
		BuildPolicyProxyDecisionLogRecord(policyProxyDecisionLogInput(policy, PolicyProxyDecisionRequest{
			Kind:      PolicyProxyRequestKindHTTPConnect,
			Authority: "api.example.com:443",
		})),
		BuildPolicyProxyDecisionLogRecord(policyProxyDecisionLogInput(policy, PolicyProxyDecisionRequest{
			Kind: PolicyProxyRequestKindHTTPRequestHost,
			Host: "blocked.example.com",
		})),
	}
	counters := SummarizePolicyProxyDecisionLogRecords(logs)

	payload, err := json.Marshal(struct {
		Logs     []PolicyProxyDecisionLogRecord `json:"logs"`
		Counters PolicyProxyDecisionLogCounters `json:"counters"`
	}{Logs: logs, Counters: counters})
	if err != nil {
		t.Fatalf("Marshal(decision logs) error: %v", err)
	}

	assertPolicyProxyDecisionLogOmitsRawValues(t, string(payload), policyProxyDecisionLogForbiddenValues()...)
}

func TestPolicyProxyDecisionLogAggregateCountersUseSafeDestinationCategoriesOnly(t *testing.T) {
	policy := policyProxyDecisionContractPolicy()
	logs := []PolicyProxyDecisionLogRecord{
		BuildPolicyProxyDecisionLogRecord(policyProxyDecisionLogInput(policy, PolicyProxyDecisionRequest{
			Kind:      PolicyProxyRequestKindHTTPConnect,
			Authority: "api.example.com:443",
		})),
		BuildPolicyProxyDecisionLogRecord(policyProxyDecisionLogInput(policy, PolicyProxyDecisionRequest{
			Kind: PolicyProxyRequestKindHTTPRequestHost,
			Host: "updates.example.com",
		})),
		BuildPolicyProxyDecisionLogRecord(policyProxyDecisionLogInput(policy, PolicyProxyDecisionRequest{
			Kind: PolicyProxyRequestKindHTTPRequestHost,
			Host: "blocked.example.com",
		})),
		BuildPolicyProxyDecisionLogRecord(policyProxyDecisionLogInput(policyProxyDecisionUnsafeBlockingPolicy(), PolicyProxyDecisionRequest{
			Kind: PolicyProxyRequestKindHTTPRequestHost,
			Host: "169.254.169.254",
		})),
	}

	got := SummarizePolicyProxyDecisionLogRecords(logs)
	if got.Total != 4 {
		t.Fatalf("Total = %d, want 4 in %#v", got.Total, got)
	}
	if got.Allowed != 2 {
		t.Fatalf("Allowed = %d, want 2 in %#v", got.Allowed, got)
	}
	if got.Denied != 2 {
		t.Fatalf("Denied = %d, want 2 in %#v", got.Denied, got)
	}

	wantCategories := map[AllowlistRuleCategory]int{
		AllowlistRuleCategoryEndpoint:         1,
		AllowlistRuleCategoryDomain:           2,
		AllowlistRuleCategoryMetadataEndpoint: 1,
	}
	if gotCategories := decisionLogCategoryCounts(got.ByDestinationCategory); !reflect.DeepEqual(gotCategories, wantCategories) {
		t.Fatalf("ByDestinationCategory = %#v, want %#v in %#v", gotCategories, wantCategories, got)
	}

	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal(counters) error: %v", err)
	}
	for _, want := range []string{
		`"destinationCategory":"endpoint"`,
		`"destinationCategory":"domain"`,
		`"destinationCategory":"metadata_endpoint"`,
	} {
		if !strings.Contains(string(payload), want) {
			t.Fatalf("counter JSON %s missing %s", payload, want)
		}
	}
	assertPolicyProxyDecisionLogOmitsRawValues(t, string(payload), policyProxyDecisionLogForbiddenValues()...)
}

func policyProxyDecisionLogInput(policy PolicyProxyDecisionPolicy, request PolicyProxyDecisionRequest) PolicyProxyDecisionLogInput {
	return PolicyProxyDecisionLogInput{
		Policy:      policy,
		Request:     request,
		RawURL:      "https://api.example.com/private/path?token=raw-token-123&credential=aws-secret",
		QueryString: "token=raw-token-123&credential=aws-secret&redirect=https://blocked.example.com/next",
		Headers: map[string]string{
			"Authorization": "Bearer raw-token-123",
			"Cookie":        "session=raw-cookie",
			"X-Api-Key":     "raw-api-key",
		},
		Token:          "raw-token-123",
		Credential:     "aws_secret_access_key=raw-secret",
		SocketPath:     "/tmp/hal/policy-proxy.sock",
		ProviderDetail: "aws:security-group:sg-1234567890abcdef",
		LocalPath:      "/Users/v/work/rescience/hal/.hal/secrets/network-policy.json",
	}
}

func optionalDecisionLogKeys(key string, value string) []string {
	if value == "" {
		return nil
	}
	return []string{key}
}

func assertPolicyProxyDecisionLogJSONKeys(t *testing.T, record PolicyProxyDecisionLogRecord, required []string, optional ...string) {
	t.Helper()
	payload, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("Marshal(decision log) error: %v", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil {
		t.Fatalf("Unmarshal(decision log %s) error: %v", payload, err)
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = true
		if _, ok := fields[key]; !ok {
			t.Fatalf("decision log JSON %s missing required safe key %q", payload, key)
		}
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key := range fields {
		if !allowed[key] {
			t.Fatalf("decision log JSON %s contains non-contract key %q", payload, key)
		}
	}
}

func assertPolicyProxyDecisionLogOmitsRawValues(t *testing.T, payload string, forbiddenValues ...string) {
	t.Helper()
	lowerPayload := strings.ToLower(payload)
	for _, forbidden := range forbiddenValues {
		if forbidden == "" {
			continue
		}
		if strings.Contains(lowerPayload, strings.ToLower(forbidden)) {
			t.Fatalf("decision log JSON leaked raw value %q: %s", forbidden, payload)
		}
	}
}

func policyProxyDecisionLogForbiddenValues() []string {
	return []string{
		"api.example.com",
		"blocked.example.com",
		"169.254.169.254",
		"https://api.example.com/private/path",
		"private/path",
		"token=raw-token-123",
		"credential=aws-secret",
		"Authorization",
		"Bearer raw-token-123",
		"Cookie",
		"raw-cookie",
		"X-Api-Key",
		"raw-api-key",
		"raw-token-123",
		"aws_secret_access_key",
		"raw-secret",
		"/tmp/hal/policy-proxy.sock",
		"aws:security-group:sg-1234567890abcdef",
		"sg-1234567890abcdef",
		"/Users/v/work/rescience/hal/.hal/secrets/network-policy.json",
	}
}

func decisionLogCategoryCounts(counters []PolicyProxyDestinationCategoryCounter) map[AllowlistRuleCategory]int {
	out := make(map[AllowlistRuleCategory]int, len(counters))
	for _, counter := range counters {
		out[counter.DestinationCategory] += counter.Count
	}
	return out
}
