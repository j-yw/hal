package sandbox

import (
	"reflect"
	"strings"
	"testing"
)

func TestNetworkProxyDecisionContractConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "source run", got: string(SandboxNetworkPolicyDecisionSourceRun), want: "run"},
		{name: "source auto", got: string(SandboxNetworkPolicyDecisionSourceAuto), want: "auto"},
		{name: "source factory", got: string(SandboxNetworkPolicyDecisionSourceFactory), want: "factory"},
		{name: "source worker", got: string(SandboxNetworkPolicyDecisionSourceWorker), want: "worker"},
		{name: "outcome allowed", got: string(SandboxNetworkPolicyDecisionOutcomeAllowed), want: "allowed"},
		{name: "outcome denied", got: string(SandboxNetworkPolicyDecisionOutcomeDenied), want: "denied"},
		{name: "outcome downgraded", got: string(SandboxNetworkPolicyDecisionOutcomeDowngraded), want: "downgraded"},
		{name: "outcome audit only", got: string(SandboxNetworkPolicyDecisionOutcomeAuditOnly), want: "audit_only"},
		{name: "reason unknown", got: string(SandboxNetworkPolicyDecisionReasonUnknown), want: "unknown"},
		{name: "reason matched allow rule", got: string(SandboxNetworkPolicyDecisionReasonMatchedAllowRule), want: "matched_allow_rule"},
		{name: "reason matched deny rule", got: string(SandboxNetworkPolicyDecisionReasonMatchedDenyRule), want: "matched_deny_rule"},
		{name: "reason default allow", got: string(SandboxNetworkPolicyDecisionReasonDefaultAllow), want: "default_allow"},
		{name: "reason default deny", got: string(SandboxNetworkPolicyDecisionReasonDefaultDeny), want: "default_deny"},
		{name: "reason policy disabled", got: string(SandboxNetworkPolicyDecisionReasonPolicyDisabled), want: "policy_disabled"},
		{name: "reason policy downgraded", got: string(SandboxNetworkPolicyDecisionReasonPolicyDowngraded), want: "policy_downgraded"},
		{name: "reason enforcement unsupported", got: string(SandboxNetworkPolicyDecisionReasonEnforcementUnsupported), want: "enforcement_unsupported"},
		{name: "reason audit only", got: string(SandboxNetworkPolicyDecisionReasonAuditOnly), want: "audit_only"},
		{name: "destination public internet", got: string(SandboxNetworkPolicyDestinationPublicInternet), want: "public_internet"},
		{name: "destination private network", got: string(SandboxNetworkPolicyDestinationPrivateNetwork), want: "private_network"},
		{name: "destination metadata service", got: string(SandboxNetworkPolicyDestinationMetadataService), want: "metadata_service"},
		{name: "destination loopback", got: string(SandboxNetworkPolicyDestinationLoopback), want: "loopback"},
		{name: "destination unix socket", got: string(SandboxNetworkPolicyDestinationUnixSocket), want: "unix_socket"},
		{name: "destination unknown", got: string(SandboxNetworkPolicyDestinationUnknown), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestNetworkProxySessionMetadataJSONSchema(t *testing.T) {
	session := SandboxNetworkProxySessionMetadata{
		ID:     "proxy-session-01",
		Source: SandboxNetworkPolicyDecisionSourceRun,
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        "policy-snapshot-01",
			Version:   "v1",
			Preset:    SandboxNetworkPolicyPresetAllowListed,
			RuleSetID: "rules-01",
		},
		EnforcementMode: SandboxNetworkEnforcementModeProxy,
	}

	got := mustMarshalObject(t, session)
	assertObjectKeys(t, got, []string{
		"id",
		"source",
		"policySnapshot",
		"enforcementMode",
	}, forbiddenNetworkProxyRawFieldNames())
	if got["id"] != "proxy-session-01" {
		t.Fatalf("id = %#v, want proxy-session-01", got["id"])
	}
	if got["source"] != string(SandboxNetworkPolicyDecisionSourceRun) {
		t.Fatalf("source = %#v, want run", got["source"])
	}

	assertObjectKeys(t, got["policySnapshot"], []string{
		"id",
		"version",
		"preset",
		"ruleSetId",
	}, forbiddenNetworkProxyRawFieldNames())

	minimalSession := mustMarshalObject(t, SandboxNetworkProxySessionMetadata{
		ID:     "proxy-session-02",
		Source: SandboxNetworkPolicyDecisionSourceAuto,
	})
	assertObjectKeys(t, minimalSession, []string{"id", "source"}, []string{
		"policySnapshot",
		"enforcementMode",
	})

	minimalSnapshot := mustMarshalObject(t, SandboxNetworkPolicySnapshotIdentity{ID: "policy-snapshot-02"})
	assertObjectKeys(t, minimalSnapshot, []string{"id"}, []string{
		"version",
		"preset",
		"ruleSetId",
	})
}

func TestNetworkPolicyDecisionLogRecordJSONSchema(t *testing.T) {
	enforced := true
	record := SandboxNetworkPolicyDecisionLogRecord{
		ID:             "decision-01",
		Source:         SandboxNetworkPolicyDecisionSourceWorker,
		ProxySessionID: "proxy-session-01",
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        "policy-snapshot-01",
			Version:   "v1",
			Preset:    SandboxNetworkPolicyPresetDenyByDefault,
			RuleSetID: "rules-01",
		},
		Request: &SandboxNetworkPolicyRequestSummary{
			ID:                  "request-01",
			Operation:           "connect",
			DestinationCategory: SandboxNetworkPolicyDestinationPrivateNetwork,
		},
		Outcome:         SandboxNetworkPolicyDecisionOutcomeDenied,
		ReasonCode:      SandboxNetworkPolicyDecisionReasonMatchedDenyRule,
		RuleKind:        SandboxNetworkPolicyRuleKindPrivateRange,
		PolicyPreset:    SandboxNetworkPolicyPresetDenyByDefault,
		EnforcementMode: SandboxNetworkEnforcementModeFirewall,
		Enforced:        &enforced,
	}

	got := mustMarshalObject(t, record)
	assertObjectKeys(t, got, []string{
		"id",
		"source",
		"proxySessionId",
		"policySnapshot",
		"request",
		"outcome",
		"reasonCode",
		"ruleKind",
		"policyPreset",
		"enforcementMode",
		"enforced",
	}, forbiddenNetworkProxyRawFieldNames())
	if got["outcome"] != string(SandboxNetworkPolicyDecisionOutcomeDenied) {
		t.Fatalf("outcome = %#v, want denied", got["outcome"])
	}

	assertObjectKeys(t, got["request"], []string{
		"id",
		"operation",
		"destinationCategory",
	}, forbiddenNetworkProxyRawFieldNames())

	minimalRecord := mustMarshalObject(t, SandboxNetworkPolicyDecisionLogRecord{
		Source:  SandboxNetworkPolicyDecisionSourceFactory,
		Outcome: SandboxNetworkPolicyDecisionOutcomeAuditOnly,
	})
	assertObjectKeys(t, minimalRecord, []string{"source", "outcome"}, []string{
		"id",
		"proxySessionId",
		"policySnapshot",
		"request",
		"reasonCode",
		"ruleKind",
		"policyPreset",
		"enforcementMode",
		"enforced",
	})

	emptyRequest := mustMarshalObject(t, SandboxNetworkPolicyRequestSummary{})
	if len(emptyRequest) != 0 {
		t.Fatalf("empty request summary = %#v, want empty object", emptyRequest)
	}
}

func TestNetworkProxyContractsExposeNoRawRequestFields(t *testing.T) {
	contractTypes := []reflect.Type{
		reflect.TypeOf(SandboxNetworkPolicySnapshotIdentity{}),
		reflect.TypeOf(SandboxNetworkProxySessionMetadata{}),
		reflect.TypeOf(SandboxNetworkPolicyRequestSummary{}),
		reflect.TypeOf(SandboxNetworkPolicyDecisionLogRecord{}),
	}
	for _, typ := range contractTypes {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				fieldName := field.Name
				jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
				for _, forbidden := range forbiddenNetworkProxyRawFieldNameFragments() {
					if strings.Contains(strings.ToLower(fieldName), forbidden) || strings.Contains(strings.ToLower(jsonName), forbidden) {
						t.Fatalf("%s.%s json %q exposes forbidden raw request field fragment %q", typ.Name(), fieldName, jsonName, forbidden)
					}
				}
			}
		})
	}
}

func forbiddenNetworkProxyRawFieldNames() []string {
	return []string{
		"host",
		"hostname",
		"ip",
		"port",
		"url",
		"uri",
		"headers",
		"body",
		"token",
		"environment",
		"env",
		"localPath",
		"remotePath",
		"path",
		"socketPath",
		"credential",
		"secret",
	}
}

func forbiddenNetworkProxyRawFieldNameFragments() []string {
	return []string{
		"host",
		"hostname",
		"ip",
		"port",
		"url",
		"uri",
		"header",
		"body",
		"token",
		"environment",
		"env",
		"localpath",
		"remotepath",
		"path",
		"socketpath",
		"credential",
		"secret",
	}
}
