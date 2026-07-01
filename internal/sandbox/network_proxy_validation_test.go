package sandbox

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNetworkProxySessionValidationAndNormalization(t *testing.T) {
	got := ValidateAndNormalizeSandboxNetworkProxySessionMetadata(SandboxNetworkProxySessionMetadata{
		ID:     " proxy-session-01 ",
		Source: SandboxNetworkPolicyDecisionSource(" RUN "),
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        " policy-snapshot-01 ",
			Version:   " v1 ",
			Preset:    SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			RuleSetID: " rules-01 ",
		},
		EnforcementMode: " PROXY_FIREWALL ",
	})
	if !got.Valid {
		t.Fatalf("ValidateAndNormalizeSandboxNetworkProxySessionMetadata() valid = false, errors: %#v", got.Errors)
	}
	if got.Normalized == nil {
		t.Fatal("normalized proxy session = nil")
	}
	normalized := *got.Normalized
	if normalized.ID != "proxy-session-01" {
		t.Fatalf("normalized id = %q, want proxy-session-01", normalized.ID)
	}
	if normalized.Source != SandboxNetworkPolicyDecisionSourceRun {
		t.Fatalf("normalized source = %q, want %q", normalized.Source, SandboxNetworkPolicyDecisionSourceRun)
	}
	if normalized.EnforcementMode != SandboxNetworkEnforcementModeProxyFirewall {
		t.Fatalf("normalized enforcement mode = %q, want %q", normalized.EnforcementMode, SandboxNetworkEnforcementModeProxyFirewall)
	}
	if normalized.PolicySnapshot == nil {
		t.Fatal("normalized policy snapshot = nil")
	}
	if normalized.PolicySnapshot.ID != "policy-snapshot-01" {
		t.Fatalf("normalized policy snapshot id = %q, want policy-snapshot-01", normalized.PolicySnapshot.ID)
	}
	if normalized.PolicySnapshot.Version != "v1" {
		t.Fatalf("normalized policy snapshot version = %q, want v1", normalized.PolicySnapshot.Version)
	}
	if normalized.PolicySnapshot.Preset != SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("normalized policy snapshot preset = %q, want %q", normalized.PolicySnapshot.Preset, SandboxNetworkPolicyPresetDenyByDefault)
	}
	if normalized.PolicySnapshot.RuleSetID != "rules-01" {
		t.Fatalf("normalized policy snapshot rule set id = %q, want rules-01", normalized.PolicySnapshot.RuleSetID)
	}
}

func TestNetworkProxySessionValidationRejectsMalformedMetadata(t *testing.T) {
	secretLikeValue := "https://user:proxy-secret@example.invalid/path?token=proxy-secret"
	tests := []struct {
		name  string
		input SandboxNetworkProxySessionMetadata
		code  SandboxNetworkProxyValidationCode
		field string
	}{
		{
			name: "missing session id",
			input: SandboxNetworkProxySessionMetadata{
				ID:     " \t ",
				Source: SandboxNetworkPolicyDecisionSourceRun,
			},
			code:  SandboxNetworkProxyValidationMissingRequiredField,
			field: "id",
		},
		{
			name: "missing source",
			input: SandboxNetworkProxySessionMetadata{
				ID:     "proxy-session-01",
				Source: SandboxNetworkPolicyDecisionSource(" \t "),
			},
			code:  SandboxNetworkProxyValidationMissingRequiredField,
			field: "source",
		},
		{
			name: "invalid source",
			input: SandboxNetworkProxySessionMetadata{
				ID:     "proxy-session-01",
				Source: SandboxNetworkPolicyDecisionSource(secretLikeValue),
			},
			code:  SandboxNetworkProxyValidationInvalidSource,
			field: "source",
		},
		{
			name: "missing policy snapshot id",
			input: SandboxNetworkProxySessionMetadata{
				ID:     "proxy-session-01",
				Source: SandboxNetworkPolicyDecisionSourceAuto,
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
					ID: " \t ",
				},
			},
			code:  SandboxNetworkProxyValidationMissingRequiredField,
			field: "policySnapshot.id",
		},
		{
			name: "invalid policy snapshot preset",
			input: SandboxNetworkProxySessionMetadata{
				ID:     "proxy-session-01",
				Source: SandboxNetworkPolicyDecisionSourceFactory,
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
					ID:     "policy-snapshot-01",
					Preset: SandboxNetworkPolicyPreset(secretLikeValue),
				},
			},
			code:  SandboxNetworkProxyValidationInvalidPolicyPreset,
			field: "policySnapshot.preset",
		},
		{
			name: "invalid enforcement mode",
			input: SandboxNetworkProxySessionMetadata{
				ID:              "proxy-session-01",
				Source:          SandboxNetworkPolicyDecisionSourceWorker,
				EnforcementMode: secretLikeValue,
			},
			code:  SandboxNetworkProxyValidationInvalidEnforcement,
			field: "enforcementMode",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateAndNormalizeSandboxNetworkProxySessionMetadata(tt.input)
			if got.Valid {
				t.Fatalf("ValidateAndNormalizeSandboxNetworkProxySessionMetadata() valid = true, want false")
			}
			if got.Normalized != nil {
				t.Fatalf("normalized metadata = %#v, want nil on invalid input", got.Normalized)
			}
			if !hasNetworkProxyValidationError(got, tt.code, tt.field) {
				t.Fatalf("validation errors = %#v, want code %q field %q", got.Errors, tt.code, tt.field)
			}
			assertNetworkProxyValidationNoUnsafeLeak(t, got)
		})
	}
}

func TestNetworkProxySessionValidationDoesNotInferEnforcement(t *testing.T) {
	got := ValidateAndNormalizeSandboxNetworkProxySessionMetadata(SandboxNetworkProxySessionMetadata{
		ID:     "proxy-session-02",
		Source: SandboxNetworkPolicyDecisionSourceAuto,
	})
	if !got.Valid {
		t.Fatalf("ValidateAndNormalizeSandboxNetworkProxySessionMetadata() valid = false, errors: %#v", got.Errors)
	}
	if got.Normalized == nil {
		t.Fatal("normalized proxy session = nil")
	}
	if got.Normalized.EnforcementMode != "" {
		t.Fatalf("normalized enforcement mode = %q, want empty when absent", got.Normalized.EnforcementMode)
	}

	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	for _, forbidden := range []string{"enforcementMode", "capability", "enforced"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("validation result %s must not infer enforcement metadata %q", payload, forbidden)
		}
	}
}

func TestNetworkPolicyDecisionLogValidationAndNormalization(t *testing.T) {
	enforced := true
	got := ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecords([]SandboxNetworkPolicyDecisionLogRecord{
		{
			ID:             " decision-01 ",
			Source:         SandboxNetworkPolicyDecisionSource(" WORKER "),
			ProxySessionID: " proxy-session-01 ",
			PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
				ID:        " policy-snapshot-01 ",
				Version:   " v1 ",
				Preset:    SandboxNetworkPolicyPreset(" ALLOW_LISTED "),
				RuleSetID: " rules-01 ",
			},
			Request: &SandboxNetworkPolicyRequestSummary{
				ID:                  " request-01 ",
				Operation:           " connect ",
				DestinationCategory: SandboxNetworkPolicyDestinationCategory(" PRIVATE_NETWORK "),
			},
			Outcome:         SandboxNetworkPolicyDecisionOutcome(" DENIED "),
			ReasonCode:      SandboxNetworkPolicyDecisionReasonCode(" MATCHED_DENY_RULE "),
			RuleKind:        SandboxNetworkPolicyRuleKind(" PRIVATE_RANGE "),
			PolicyPreset:    SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
			EnforcementMode: " FIREWALL ",
			Enforced:        &enforced,
		},
	})
	if !got.Valid {
		t.Fatalf("ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecords() valid = false, errors: %#v", got.Errors)
	}
	if len(got.Normalized) != 1 {
		t.Fatalf("normalized records length = %d, want 1", len(got.Normalized))
	}
	normalized := got.Normalized[0]
	if normalized.ID != "decision-01" {
		t.Fatalf("normalized id = %q, want decision-01", normalized.ID)
	}
	if normalized.Source != SandboxNetworkPolicyDecisionSourceWorker {
		t.Fatalf("normalized source = %q, want %q", normalized.Source, SandboxNetworkPolicyDecisionSourceWorker)
	}
	if normalized.ProxySessionID != "proxy-session-01" {
		t.Fatalf("normalized proxy session id = %q, want proxy-session-01", normalized.ProxySessionID)
	}
	if normalized.Outcome != SandboxNetworkPolicyDecisionOutcomeDenied {
		t.Fatalf("normalized outcome = %q, want %q", normalized.Outcome, SandboxNetworkPolicyDecisionOutcomeDenied)
	}
	if normalized.ReasonCode != SandboxNetworkPolicyDecisionReasonMatchedDenyRule {
		t.Fatalf("normalized reason code = %q, want %q", normalized.ReasonCode, SandboxNetworkPolicyDecisionReasonMatchedDenyRule)
	}
	if normalized.RuleKind != SandboxNetworkPolicyRuleKindPrivateRange {
		t.Fatalf("normalized rule kind = %q, want %q", normalized.RuleKind, SandboxNetworkPolicyRuleKindPrivateRange)
	}
	if normalized.PolicyPreset != SandboxNetworkPolicyPresetDenyByDefault {
		t.Fatalf("normalized policy preset = %q, want %q", normalized.PolicyPreset, SandboxNetworkPolicyPresetDenyByDefault)
	}
	if normalized.EnforcementMode != SandboxNetworkEnforcementModeFirewall {
		t.Fatalf("normalized enforcement mode = %q, want %q", normalized.EnforcementMode, SandboxNetworkEnforcementModeFirewall)
	}
	if normalized.Enforced == nil || !*normalized.Enforced {
		t.Fatalf("normalized enforced = %#v, want true pointer", normalized.Enforced)
	}
	if normalized.PolicySnapshot == nil {
		t.Fatal("normalized policy snapshot = nil")
	}
	if normalized.PolicySnapshot.ID != "policy-snapshot-01" {
		t.Fatalf("normalized policy snapshot id = %q, want policy-snapshot-01", normalized.PolicySnapshot.ID)
	}
	if normalized.PolicySnapshot.Version != "v1" {
		t.Fatalf("normalized policy snapshot version = %q, want v1", normalized.PolicySnapshot.Version)
	}
	if normalized.PolicySnapshot.Preset != SandboxNetworkPolicyPresetAllowListed {
		t.Fatalf("normalized policy snapshot preset = %q, want %q", normalized.PolicySnapshot.Preset, SandboxNetworkPolicyPresetAllowListed)
	}
	if normalized.PolicySnapshot.RuleSetID != "rules-01" {
		t.Fatalf("normalized policy snapshot rule set id = %q, want rules-01", normalized.PolicySnapshot.RuleSetID)
	}
	if normalized.Request == nil {
		t.Fatal("normalized request = nil")
	}
	if normalized.Request.ID != "request-01" {
		t.Fatalf("normalized request id = %q, want request-01", normalized.Request.ID)
	}
	if normalized.Request.Operation != "connect" {
		t.Fatalf("normalized request operation = %q, want connect", normalized.Request.Operation)
	}
	if normalized.Request.DestinationCategory != SandboxNetworkPolicyDestinationPrivateNetwork {
		t.Fatalf("normalized destination category = %q, want %q", normalized.Request.DestinationCategory, SandboxNetworkPolicyDestinationPrivateNetwork)
	}
}

func TestNetworkPolicyDecisionLogValidationRejectsMalformedMetadata(t *testing.T) {
	secretLikeValue := "https://user:decision-secret@example.invalid/path?token=decision-secret"
	enforced := true
	tests := []struct {
		name   string
		mutate func(*SandboxNetworkPolicyDecisionLogRecord)
		code   SandboxNetworkPolicyDecisionLogValidationCode
		field  string
	}{
		{
			name: "invalid source",
			mutate: func(record *SandboxNetworkPolicyDecisionLogRecord) {
				record.Source = SandboxNetworkPolicyDecisionSource(secretLikeValue)
			},
			code:  SandboxNetworkPolicyDecisionLogValidationInvalidSource,
			field: "source",
		},
		{
			name: "invalid outcome",
			mutate: func(record *SandboxNetworkPolicyDecisionLogRecord) {
				record.Outcome = SandboxNetworkPolicyDecisionOutcome(secretLikeValue)
			},
			code:  SandboxNetworkPolicyDecisionLogValidationInvalidOutcome,
			field: "outcome",
		},
		{
			name: "invalid reason code",
			mutate: func(record *SandboxNetworkPolicyDecisionLogRecord) {
				record.ReasonCode = SandboxNetworkPolicyDecisionReasonCode(secretLikeValue)
			},
			code:  SandboxNetworkPolicyDecisionLogValidationInvalidReasonCode,
			field: "reasonCode",
		},
		{
			name: "invalid destination category",
			mutate: func(record *SandboxNetworkPolicyDecisionLogRecord) {
				record.Request.DestinationCategory = SandboxNetworkPolicyDestinationCategory(secretLikeValue)
			},
			code:  SandboxNetworkPolicyDecisionLogValidationInvalidDestination,
			field: "request.destinationCategory",
		},
		{
			name: "invalid rule kind",
			mutate: func(record *SandboxNetworkPolicyDecisionLogRecord) {
				record.RuleKind = SandboxNetworkPolicyRuleKind(secretLikeValue)
			},
			code:  SandboxNetworkPolicyDecisionLogValidationInvalidRuleKind,
			field: "ruleKind",
		},
		{
			name: "invalid policy preset",
			mutate: func(record *SandboxNetworkPolicyDecisionLogRecord) {
				record.PolicyPreset = SandboxNetworkPolicyPreset(secretLikeValue)
			},
			code:  SandboxNetworkPolicyDecisionLogValidationInvalidPolicyPreset,
			field: "policyPreset",
		},
		{
			name: "invalid enforcement mode",
			mutate: func(record *SandboxNetworkPolicyDecisionLogRecord) {
				record.EnforcementMode = secretLikeValue
			},
			code:  SandboxNetworkPolicyDecisionLogValidationInvalidEnforcement,
			field: "enforcementMode",
		},
		{
			name: "unsafe request operation",
			mutate: func(record *SandboxNetworkPolicyDecisionLogRecord) {
				record.Request.Operation = secretLikeValue
			},
			code:  SandboxNetworkPolicyDecisionLogValidationUnsafeRequestMetadata,
			field: "request.operation",
		},
		{
			name: "unsafe request id",
			mutate: func(record *SandboxNetworkPolicyDecisionLogRecord) {
				record.Request.ID = secretLikeValue
			},
			code:  SandboxNetworkPolicyDecisionLogValidationUnsafeRequestMetadata,
			field: "request.id",
		},
		{
			name: "enforced denied decision without enforcing mode",
			mutate: func(record *SandboxNetworkPolicyDecisionLogRecord) {
				record.Outcome = SandboxNetworkPolicyDecisionOutcomeDenied
				record.Enforced = &enforced
				record.EnforcementMode = ""
			},
			code:  SandboxNetworkPolicyDecisionLogValidationInvalidEnforcementClaim,
			field: "enforced",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invalidRecord := validNetworkPolicyDecisionLogRecord()
			tt.mutate(&invalidRecord)

			got := ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecords([]SandboxNetworkPolicyDecisionLogRecord{
				validNetworkPolicyDecisionLogRecord(),
				invalidRecord,
			})
			if got.Valid {
				t.Fatalf("ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecords() valid = true, want false")
			}
			if got.Normalized != nil {
				t.Fatalf("normalized decision logs = %#v, want nil on invalid input", got.Normalized)
			}
			if !hasNetworkPolicyDecisionLogValidationError(got, tt.code, 1, tt.field) {
				t.Fatalf("validation errors = %#v, want code %q index 1 field %q", got.Errors, tt.code, tt.field)
			}
			assertNetworkPolicyDecisionLogValidationNoUnsafeLeak(t, got)
		})
	}
}

func TestNetworkPolicyDecisionLogValidationPreservesSafeDestinationCategories(t *testing.T) {
	categories := []SandboxNetworkPolicyDestinationCategory{
		SandboxNetworkPolicyDestinationPublicInternet,
		SandboxNetworkPolicyDestinationPrivateNetwork,
		SandboxNetworkPolicyDestinationMetadataService,
		SandboxNetworkPolicyDestinationLoopback,
		SandboxNetworkPolicyDestinationUnixSocket,
		SandboxNetworkPolicyDestinationUnknown,
	}
	records := make([]SandboxNetworkPolicyDecisionLogRecord, 0, len(categories))
	for _, category := range categories {
		record := validNetworkPolicyDecisionLogRecord()
		record.Request.DestinationCategory = category
		records = append(records, record)
	}

	got := ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecords(records)
	if !got.Valid {
		t.Fatalf("ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecords() valid = false, errors: %#v", got.Errors)
	}
	if len(got.Normalized) != len(categories) {
		t.Fatalf("normalized records length = %d, want %d", len(got.Normalized), len(categories))
	}
	for i, category := range categories {
		if got.Normalized[i].Request == nil {
			t.Fatalf("normalized record %d request = nil", i)
		}
		if got.Normalized[i].Request.DestinationCategory != category {
			t.Fatalf("normalized record %d destination category = %q, want %q", i, got.Normalized[i].Request.DestinationCategory, category)
		}
	}
}

func TestNetworkPolicyDecisionLogValidationDoesNotInferDeniedEnforcement(t *testing.T) {
	got := ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecord(SandboxNetworkPolicyDecisionLogRecord{
		Source:     SandboxNetworkPolicyDecisionSourceRun,
		Outcome:    SandboxNetworkPolicyDecisionOutcomeDenied,
		ReasonCode: SandboxNetworkPolicyDecisionReasonDefaultDeny,
		Request: &SandboxNetworkPolicyRequestSummary{
			DestinationCategory: SandboxNetworkPolicyDestinationPublicInternet,
		},
	})
	if !got.Valid {
		t.Fatalf("ValidateAndNormalizeSandboxNetworkPolicyDecisionLogRecord() valid = false, errors: %#v", got.Errors)
	}
	if len(got.Normalized) != 1 {
		t.Fatalf("normalized records length = %d, want 1", len(got.Normalized))
	}
	normalized := got.Normalized[0]
	if normalized.Enforced != nil {
		t.Fatalf("normalized enforced = %#v, want nil when absent", normalized.Enforced)
	}
	if normalized.EnforcementMode != "" {
		t.Fatalf("normalized enforcement mode = %q, want empty when absent", normalized.EnforcementMode)
	}

	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	for _, forbidden := range []string{"enforced", "enforcementMode", "capability"} {
		if strings.Contains(string(payload), forbidden) {
			t.Fatalf("validation result %s must not infer enforcement metadata %q", payload, forbidden)
		}
	}
}

func TestNetworkProxySessionMetadataSanitizationRedactsSensitiveExamples(t *testing.T) {
	for _, sensitive := range networkProxySensitiveExamples() {
		t.Run(sensitive, func(t *testing.T) {
			session := SandboxNetworkProxySessionMetadata{
				ID:     sensitive,
				Source: SandboxNetworkPolicyDecisionSource(" RUN "),
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
					ID:        " policy-snapshot-01 ",
					Version:   sensitive,
					Preset:    SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT "),
					RuleSetID: sensitive,
				},
				EnforcementMode: sensitive,
			}

			sanitized := SanitizeSandboxNetworkProxySessionMetadata(session)
			payload, err := json.Marshal(sanitized)
			if err != nil {
				t.Fatalf("json.Marshal(sanitized proxy session) error: %v", err)
			}

			assertNetworkProxyPayloadNoSensitiveExamples(t, string(payload))
			assertNetworkProxyPayloadContains(t, string(payload),
				string(SandboxNetworkPolicyDecisionSourceRun),
				"policy-snapshot-01",
				string(SandboxNetworkPolicyPresetDenyByDefault),
			)
			if sanitized.ID != "" {
				t.Fatalf("sanitized id = %q, want empty for unsafe input", sanitized.ID)
			}
			if sanitized.EnforcementMode != "" {
				t.Fatalf("sanitized enforcement mode = %q, want empty for unsafe input", sanitized.EnforcementMode)
			}
			if sanitized.PolicySnapshot == nil {
				t.Fatal("sanitized policy snapshot = nil, want safe snapshot identity preserved")
			}
			if sanitized.PolicySnapshot.Version != "" || sanitized.PolicySnapshot.RuleSetID != "" {
				t.Fatalf("sanitized policy snapshot = %#v, want unsafe free-form fields cleared", sanitized.PolicySnapshot)
			}
		})
	}
}

func TestNetworkPolicyDecisionLogSanitizationRedactsSensitiveExamples(t *testing.T) {
	for _, sensitive := range networkProxySensitiveExamples() {
		t.Run(sensitive, func(t *testing.T) {
			enforced := true
			record := validNetworkPolicyDecisionLogRecord()
			record.ID = sensitive
			record.Source = SandboxNetworkPolicyDecisionSource(" FACTORY ")
			record.ProxySessionID = sensitive
			record.PolicySnapshot.Version = sensitive
			record.PolicySnapshot.RuleSetID = sensitive
			record.Request.ID = sensitive
			record.Request.Operation = sensitive
			record.Request.DestinationCategory = SandboxNetworkPolicyDestinationCategory(" METADATA_SERVICE ")
			record.Outcome = SandboxNetworkPolicyDecisionOutcome(" DENIED ")
			record.ReasonCode = SandboxNetworkPolicyDecisionReasonCode(" DEFAULT_DENY ")
			record.RuleKind = SandboxNetworkPolicyRuleKind(" METADATA_ENDPOINT ")
			record.PolicyPreset = SandboxNetworkPolicyPreset(" DENY_BY_DEFAULT ")
			record.EnforcementMode = sensitive
			record.Enforced = &enforced

			sanitized := SanitizeSandboxNetworkPolicyDecisionLogRecords([]SandboxNetworkPolicyDecisionLogRecord{record})
			payload, err := json.Marshal(sanitized)
			if err != nil {
				t.Fatalf("json.Marshal(sanitized decision logs) error: %v", err)
			}

			assertNetworkProxyPayloadNoSensitiveExamples(t, string(payload))
			assertNetworkProxyPayloadContains(t, string(payload),
				string(SandboxNetworkPolicyDecisionSourceFactory),
				"policy-snapshot-01",
				string(SandboxNetworkPolicyDestinationMetadataService),
				string(SandboxNetworkPolicyDecisionOutcomeDenied),
				string(SandboxNetworkPolicyDecisionReasonDefaultDeny),
				string(SandboxNetworkPolicyRuleKindMetadataEndpoint),
				string(SandboxNetworkPolicyPresetDenyByDefault),
			)
			if len(sanitized) != 1 {
				t.Fatalf("sanitized records length = %d, want 1", len(sanitized))
			}
			if sanitized[0].ID != "" || sanitized[0].ProxySessionID != "" {
				t.Fatalf("sanitized record identifiers = id %q proxySessionID %q, want empty for unsafe input", sanitized[0].ID, sanitized[0].ProxySessionID)
			}
			if sanitized[0].EnforcementMode != "" {
				t.Fatalf("sanitized enforcement mode = %q, want empty for unsafe input", sanitized[0].EnforcementMode)
			}
			if sanitized[0].Enforced != nil {
				t.Fatalf("sanitized enforced = %#v, want nil when enforcing metadata was cleared", sanitized[0].Enforced)
			}
			if sanitized[0].Request == nil {
				t.Fatal("sanitized request = nil, want safe destination category preserved")
			}
			if sanitized[0].Request.ID != "" || sanitized[0].Request.Operation != "" {
				t.Fatalf("sanitized request = %#v, want unsafe request metadata cleared", sanitized[0].Request)
			}
		})
	}
}

func hasNetworkProxyValidationError(result SandboxNetworkProxyValidationResult, code SandboxNetworkProxyValidationCode, field string) bool {
	for _, err := range result.Errors {
		if err.Code == code && err.Field == field {
			return true
		}
	}
	return false
}

func networkProxySensitiveExamples() []string {
	return []string{
		"api.example.com",
		"169.254.169.254",
		"https://user:secret@example.test/path?token=secret",
		"unix:///tmp/private/proxy.sock",
		"/Users/alice/project",
		"Authorization",
		"Bearer",
		"OPENAI_API_KEY",
		"X-Raw-Header: Bearer raw-header-value",
		`{"raw_body":"raw-body-value"}`,
	}
}

func assertNetworkProxyPayloadNoSensitiveExamples(t *testing.T, payload string) {
	t.Helper()
	for _, unsafe := range networkProxySensitiveExamples() {
		if strings.Contains(payload, unsafe) {
			t.Fatalf("payload leaked sensitive example %q: %s", unsafe, payload)
		}
	}
}

func assertNetworkProxyPayloadContains(t *testing.T, payload string, expected ...string) {
	t.Helper()
	for _, value := range expected {
		if !strings.Contains(payload, value) {
			t.Fatalf("payload %s does not contain expected safe value %q", payload, value)
		}
	}
}

func assertNetworkProxyValidationNoUnsafeLeak(t *testing.T, result SandboxNetworkProxyValidationResult) {
	t.Helper()

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	for _, unsafe := range []string{
		"proxy-secret",
		"user:",
		"token=",
		"example.invalid",
		"://",
		"?",
	} {
		if strings.Contains(string(payload), unsafe) {
			t.Fatalf("validation result leaked unsafe input %q: %s", unsafe, payload)
		}
	}
}

func validNetworkPolicyDecisionLogRecord() SandboxNetworkPolicyDecisionLogRecord {
	return SandboxNetworkPolicyDecisionLogRecord{
		ID:             "decision-01",
		Source:         SandboxNetworkPolicyDecisionSourceRun,
		ProxySessionID: "proxy-session-01",
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        "policy-snapshot-01",
			Version:   "v1",
			Preset:    SandboxNetworkPolicyPresetAllowListed,
			RuleSetID: "rules-01",
		},
		Request: &SandboxNetworkPolicyRequestSummary{
			ID:                  "request-01",
			Operation:           "connect",
			DestinationCategory: SandboxNetworkPolicyDestinationPublicInternet,
		},
		Outcome:         SandboxNetworkPolicyDecisionOutcomeAllowed,
		ReasonCode:      SandboxNetworkPolicyDecisionReasonMatchedAllowRule,
		RuleKind:        SandboxNetworkPolicyRuleKindDomain,
		PolicyPreset:    SandboxNetworkPolicyPresetAllowListed,
		EnforcementMode: SandboxNetworkEnforcementModeProxy,
	}
}

func hasNetworkPolicyDecisionLogValidationError(result SandboxNetworkPolicyDecisionLogValidationResult, code SandboxNetworkPolicyDecisionLogValidationCode, index int, field string) bool {
	for _, err := range result.Errors {
		if err.Code == code && err.RecordIndex == index && err.Field == field {
			return true
		}
	}
	return false
}

func assertNetworkPolicyDecisionLogValidationNoUnsafeLeak(t *testing.T, result SandboxNetworkPolicyDecisionLogValidationResult) {
	t.Helper()

	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("json.Marshal(validation result) error: %v", err)
	}
	for _, unsafe := range []string{
		"decision-secret",
		"user:",
		"token=",
		"example.invalid",
		"://",
		"?",
	} {
		if strings.Contains(string(payload), unsafe) {
			t.Fatalf("validation result leaked unsafe input %q: %s", unsafe, payload)
		}
	}
}
