package sandbox

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCredentialProxyContractConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "source run", got: string(SandboxCredentialProxySourceRun), want: "run"},
		{name: "source auto", got: string(SandboxCredentialProxySourceAuto), want: "auto"},
		{name: "source factory", got: string(SandboxCredentialProxySourceFactory), want: "factory"},
		{name: "source worker", got: string(SandboxCredentialProxySourceWorker), want: "worker"},
		{name: "mode metadata only", got: string(SandboxCredentialProxyModeMetadataOnly), want: "metadata_only"},
		{name: "mode secret broker reference", got: string(SandboxCredentialProxyModeSecretBrokerReference), want: "secret_broker_reference"},
		{name: "mode network proxy reference", got: string(SandboxCredentialProxyModeNetworkProxyReference), want: "network_proxy_reference"},
		{name: "mode brokered network reference", got: string(SandboxCredentialProxyModeBrokeredNetworkReference), want: "brokered_network_reference"},
		{name: "status planned", got: string(SandboxCredentialProxyStatusPlanned), want: "planned"},
		{name: "status ready", got: string(SandboxCredentialProxyStatusReady), want: "ready"},
		{name: "status active", got: string(SandboxCredentialProxyStatusActive), want: "active"},
		{name: "status completed", got: string(SandboxCredentialProxyStatusCompleted), want: "completed"},
		{name: "status skipped", got: string(SandboxCredentialProxyStatusSkipped), want: "skipped"},
		{name: "status failed", got: string(SandboxCredentialProxyStatusFailed), want: "failed"},
		{name: "status disabled", got: string(SandboxCredentialProxyStatusDisabled), want: "disabled"},
		{name: "outcome planned", got: string(SandboxCredentialProxyBindingOutcomePlanned), want: "planned"},
		{name: "outcome bound", got: string(SandboxCredentialProxyBindingOutcomeBound), want: "bound"},
		{name: "outcome omitted", got: string(SandboxCredentialProxyBindingOutcomeOmitted), want: "omitted"},
		{name: "outcome skipped", got: string(SandboxCredentialProxyBindingOutcomeSkipped), want: "skipped"},
		{name: "outcome failed", got: string(SandboxCredentialProxyBindingOutcomeFailed), want: "failed"},
		{name: "outcome audit only", got: string(SandboxCredentialProxyBindingOutcomeAuditOnly), want: "audit_only"},
		{name: "warning missing secret broker", got: string(SandboxCredentialProxyWarningMissingSecretBrokerSession), want: "missing_secret_broker_session"},
		{name: "warning missing network proxy", got: string(SandboxCredentialProxyWarningMissingNetworkProxySession), want: "missing_network_proxy_session"},
		{name: "warning policy snapshot unavailable", got: string(SandboxCredentialProxyWarningPolicySnapshotUnavailable), want: "policy_snapshot_unavailable"},
		{name: "warning unsupported delivery mode", got: string(SandboxCredentialProxyWarningUnsupportedDeliveryMode), want: "unsupported_delivery_mode"},
		{name: "warning binding omitted", got: string(SandboxCredentialProxyWarningBindingOmitted), want: "binding_omitted"},
		{name: "reason requested", got: string(SandboxCredentialProxyReasonRequested), want: "requested"},
		{name: "reason secret broker unavailable", got: string(SandboxCredentialProxyReasonSecretBrokerUnavailable), want: "secret_broker_unavailable"},
		{name: "reason network proxy unavailable", got: string(SandboxCredentialProxyReasonNetworkProxyUnavailable), want: "network_proxy_unavailable"},
		{name: "reason policy snapshot unavailable", got: string(SandboxCredentialProxyReasonPolicySnapshotUnavailable), want: "policy_snapshot_unavailable"},
		{name: "reason delivery mode unsupported", got: string(SandboxCredentialProxyReasonDeliveryModeUnsupported), want: "delivery_mode_unsupported"},
		{name: "reason destination category skipped", got: string(SandboxCredentialProxyReasonDestinationCategorySkipped), want: "destination_category_skipped"},
		{name: "reason disabled", got: string(SandboxCredentialProxyReasonDisabled), want: "disabled"},
		{name: "reason unknown", got: string(SandboxCredentialProxyReasonUnknown), want: "unknown"},
		{name: "delivery env", got: string(SandboxCredentialProxyDeliveryModeEnv), want: SandboxSecretModeEnv},
		{name: "delivery file tmpfs", got: string(SandboxCredentialProxyDeliveryModeFileTmpfs), want: SandboxSecretModeFileTmpfs},
		{name: "delivery ssh agent", got: string(SandboxCredentialProxyDeliveryModeSSHAgent), want: SandboxSecretModeSSHAgent},
		{name: "delivery http proxy", got: string(SandboxCredentialProxyDeliveryModeHTTPProxy), want: SandboxSecretModeHTTPProxy},
		{name: "delivery legacy auth sync", got: string(SandboxCredentialProxyDeliveryModeLegacyAuthSync), want: SandboxSecretModeLegacyAuthSync},
		{name: "request secret delivery", got: string(SandboxCredentialProxyRequestSecretDelivery), want: "secret_delivery"},
		{name: "request network auth", got: string(SandboxCredentialProxyRequestNetworkAuth), want: "network_auth"},
		{name: "request source control", got: string(SandboxCredentialProxyRequestSourceControl), want: "source_control"},
		{name: "request artifact sync", got: string(SandboxCredentialProxyRequestArtifactSync), want: "artifact_sync"},
		{name: "request unknown", got: string(SandboxCredentialProxyRequestUnknown), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestCredentialProxyPlanMetadataContract(t *testing.T) {
	plan := SandboxCredentialProxyPlanMetadata{
		ID:                    "credential-plan-01",
		Source:                SandboxCredentialProxySourceRun,
		SecretBrokerSessionID: "broker-session-01",
		NetworkProxySessionID: "network-proxy-session-01",
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID:        "policy-snapshot-01",
			Version:   "v1",
			Preset:    SandboxNetworkPolicyPresetAllowListed,
			RuleSetID: "rules-01",
		},
		BindingCount: 2,
		Mode:         SandboxCredentialProxyModeBrokeredNetworkReference,
		Status:       SandboxCredentialProxyStatusPlanned,
	}

	got := mustMarshalObject(t, plan)
	assertObjectKeys(t, got, []string{
		"id",
		"source",
		"secretBrokerSessionId",
		"networkProxySessionId",
		"policySnapshot",
		"bindingCount",
		"mode",
		"status",
	}, forbiddenCredentialProxyRawFieldNames())
	assertObjectKeys(t, got["policySnapshot"], []string{
		"id",
		"version",
		"preset",
		"ruleSetId",
	}, forbiddenCredentialProxyRawFieldNames())

	minimal := mustMarshalObject(t, SandboxCredentialProxyPlanMetadata{
		ID:     "credential-plan-02",
		Source: SandboxCredentialProxySourceAuto,
	})
	assertObjectKeys(t, minimal, []string{"id", "source"}, []string{
		"secretBrokerSessionId",
		"networkProxySessionId",
		"policySnapshot",
		"bindingCount",
		"mode",
		"status",
	})
}

func TestCredentialProxySessionMetadataContract(t *testing.T) {
	session := SandboxCredentialProxySessionMetadata{
		ID:                    "credential-session-01",
		PlanID:                "credential-plan-01",
		Source:                SandboxCredentialProxySourceFactory,
		SecretBrokerSessionID: "broker-session-01",
		NetworkProxySessionID: "network-proxy-session-01",
		PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
			ID: "policy-snapshot-01",
		},
		Status:      SandboxCredentialProxyStatusActive,
		WarningCode: SandboxCredentialProxyWarningPolicySnapshotUnavailable,
		ReasonCode:  SandboxCredentialProxyReasonPolicySnapshotUnavailable,
	}

	got := mustMarshalObject(t, session)
	assertObjectKeys(t, got, []string{
		"id",
		"planId",
		"source",
		"secretBrokerSessionId",
		"networkProxySessionId",
		"policySnapshot",
		"status",
		"warningCode",
		"reasonCode",
	}, forbiddenCredentialProxyRawFieldNames())

	minimal := mustMarshalObject(t, SandboxCredentialProxySessionMetadata{
		ID:     "credential-session-02",
		PlanID: "credential-plan-02",
		Source: SandboxCredentialProxySourceWorker,
	})
	assertObjectKeys(t, minimal, []string{"id", "planId", "source"}, []string{
		"secretBrokerSessionId",
		"networkProxySessionId",
		"policySnapshot",
		"status",
		"warningCode",
		"reasonCode",
	})
}

func TestCredentialProxyBindingMetadataContract(t *testing.T) {
	binding := SandboxCredentialProxyBindingMetadata{
		ID:                  "credential-binding-01",
		SessionID:           "credential-session-01",
		SecretID:            "secret-01",
		DeliveryMode:        SandboxCredentialProxyDeliveryModeHTTPProxy,
		RequestCategory:     SandboxCredentialProxyRequestNetworkAuth,
		DestinationCategory: SandboxNetworkPolicyDestinationPrivateNetwork,
		Outcome:             SandboxCredentialProxyBindingOutcomeBound,
		Status:              SandboxCredentialProxyStatusCompleted,
		ReasonCode:          SandboxCredentialProxyReasonRequested,
	}

	got := mustMarshalObject(t, binding)
	assertObjectKeys(t, got, []string{
		"id",
		"sessionId",
		"secretId",
		"deliveryMode",
		"requestCategory",
		"destinationCategory",
		"outcome",
		"status",
		"reasonCode",
	}, append(forbiddenCredentialProxyRawFieldNames(), "planId"))

	planBinding := mustMarshalObject(t, SandboxCredentialProxyBindingMetadata{
		ID:           "credential-binding-02",
		PlanID:       "credential-plan-01",
		SecretID:     "secret-02",
		DeliveryMode: SandboxCredentialProxyDeliveryModeEnv,
	})
	assertObjectKeys(t, planBinding, []string{"id", "planId", "secretId", "deliveryMode"}, []string{
		"sessionId",
		"requestCategory",
		"destinationCategory",
		"outcome",
		"status",
		"reasonCode",
	})
}

func TestCredentialProxyJSONTagsAreStable(t *testing.T) {
	assertCredentialProxyJSONTags(t, reflect.TypeOf(SandboxCredentialProxyPlanMetadata{}), []credentialProxyJSONTagExpectation{
		{field: "ID", name: "id"},
		{field: "Source", name: "source"},
		{field: "SecretBrokerSessionID", name: "secretBrokerSessionId", omitempty: true},
		{field: "NetworkProxySessionID", name: "networkProxySessionId", omitempty: true},
		{field: "PolicySnapshot", name: "policySnapshot", omitempty: true},
		{field: "BindingCount", name: "bindingCount", omitempty: true},
		{field: "Mode", name: "mode", omitempty: true},
		{field: "Status", name: "status", omitempty: true},
	})

	assertCredentialProxyJSONTags(t, reflect.TypeOf(SandboxCredentialProxySessionMetadata{}), []credentialProxyJSONTagExpectation{
		{field: "ID", name: "id"},
		{field: "PlanID", name: "planId"},
		{field: "Source", name: "source"},
		{field: "SecretBrokerSessionID", name: "secretBrokerSessionId", omitempty: true},
		{field: "NetworkProxySessionID", name: "networkProxySessionId", omitempty: true},
		{field: "PolicySnapshot", name: "policySnapshot", omitempty: true},
		{field: "Status", name: "status", omitempty: true},
		{field: "WarningCode", name: "warningCode", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
	})

	assertCredentialProxyJSONTags(t, reflect.TypeOf(SandboxCredentialProxyBindingMetadata{}), []credentialProxyJSONTagExpectation{
		{field: "ID", name: "id"},
		{field: "PlanID", name: "planId", omitempty: true},
		{field: "SessionID", name: "sessionId", omitempty: true},
		{field: "SecretID", name: "secretId"},
		{field: "DeliveryMode", name: "deliveryMode"},
		{field: "RequestCategory", name: "requestCategory", omitempty: true},
		{field: "DestinationCategory", name: "destinationCategory", omitempty: true},
		{field: "Outcome", name: "outcome", omitempty: true},
		{field: "Status", name: "status", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
	})
}

func TestCredentialProxyDefaultMetadataOmitsOptionalJSONFields(t *testing.T) {
	plan := mustMarshalObject(t, SandboxCredentialProxyPlanMetadata{})
	assertObjectKeys(t, plan, []string{"id", "source"}, []string{
		"secretBrokerSessionId",
		"networkProxySessionId",
		"policySnapshot",
		"bindingCount",
		"mode",
		"status",
	})

	session := mustMarshalObject(t, SandboxCredentialProxySessionMetadata{})
	assertObjectKeys(t, session, []string{"id", "planId", "source"}, []string{
		"secretBrokerSessionId",
		"networkProxySessionId",
		"policySnapshot",
		"status",
		"warningCode",
		"reasonCode",
	})

	binding := mustMarshalObject(t, SandboxCredentialProxyBindingMetadata{})
	assertObjectKeys(t, binding, []string{"id", "secretId", "deliveryMode"}, []string{
		"planId",
		"sessionId",
		"requestCategory",
		"destinationCategory",
		"outcome",
		"status",
		"reasonCode",
	})
}

func TestCredentialProxyJSONEnumValuesSerializeAsExpectedStrings(t *testing.T) {
	plan := mustMarshalObject(t, SandboxCredentialProxyPlanMetadata{
		ID:     "credential-plan-01",
		Source: SandboxCredentialProxySourceFactory,
		Mode:   SandboxCredentialProxyModeSecretBrokerReference,
		Status: SandboxCredentialProxyStatusReady,
	})
	assertCredentialProxyJSONValue(t, plan, "source", "factory")
	assertCredentialProxyJSONValue(t, plan, "mode", "secret_broker_reference")
	assertCredentialProxyJSONValue(t, plan, "status", "ready")

	session := mustMarshalObject(t, SandboxCredentialProxySessionMetadata{
		ID:          "credential-session-01",
		PlanID:      "credential-plan-01",
		Source:      SandboxCredentialProxySourceWorker,
		Status:      SandboxCredentialProxyStatusFailed,
		WarningCode: SandboxCredentialProxyWarningBindingOmitted,
		ReasonCode:  SandboxCredentialProxyReasonNetworkProxyUnavailable,
	})
	assertCredentialProxyJSONValue(t, session, "source", "worker")
	assertCredentialProxyJSONValue(t, session, "status", "failed")
	assertCredentialProxyJSONValue(t, session, "warningCode", "binding_omitted")
	assertCredentialProxyJSONValue(t, session, "reasonCode", "network_proxy_unavailable")

	binding := mustMarshalObject(t, SandboxCredentialProxyBindingMetadata{
		ID:                  "credential-binding-01",
		SecretID:            "secret-01",
		DeliveryMode:        SandboxCredentialProxyDeliveryModeFileTmpfs,
		RequestCategory:     SandboxCredentialProxyRequestArtifactSync,
		DestinationCategory: SandboxNetworkPolicyDestinationMetadataService,
		Outcome:             SandboxCredentialProxyBindingOutcomeAuditOnly,
		Status:              SandboxCredentialProxyStatusSkipped,
		ReasonCode:          SandboxCredentialProxyReasonDestinationCategorySkipped,
	})
	assertCredentialProxyJSONValue(t, binding, "deliveryMode", "file_tmpfs")
	assertCredentialProxyJSONValue(t, binding, "requestCategory", "artifact_sync")
	assertCredentialProxyJSONValue(t, binding, "destinationCategory", "metadata_service")
	assertCredentialProxyJSONValue(t, binding, "outcome", "audit_only")
	assertCredentialProxyJSONValue(t, binding, "status", "skipped")
	assertCredentialProxyJSONValue(t, binding, "reasonCode", "destination_category_skipped")
}

func TestCredentialProxySerializedMetadataContainsNoUnsafeRawFieldNames(t *testing.T) {
	samples := []struct {
		name  string
		value any
	}{
		{
			name: "plan",
			value: SandboxCredentialProxyPlanMetadata{
				ID:                    "credential-plan-01",
				Source:                SandboxCredentialProxySourceRun,
				SecretBrokerSessionID: "broker-session-01",
				NetworkProxySessionID: "network-proxy-session-01",
				PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
					ID:        "policy-snapshot-01",
					Version:   "v1",
					Preset:    SandboxNetworkPolicyPresetAllowListed,
					RuleSetID: "rules-01",
				},
				BindingCount: 1,
				Mode:         SandboxCredentialProxyModeBrokeredNetworkReference,
				Status:       SandboxCredentialProxyStatusActive,
			},
		},
		{
			name: "session",
			value: SandboxCredentialProxySessionMetadata{
				ID:                    "credential-session-01",
				PlanID:                "credential-plan-01",
				Source:                SandboxCredentialProxySourceAuto,
				SecretBrokerSessionID: "broker-session-01",
				NetworkProxySessionID: "network-proxy-session-01",
				PolicySnapshot:        &SandboxNetworkPolicySnapshotIdentity{ID: "policy-snapshot-01"},
				Status:                SandboxCredentialProxyStatusCompleted,
				WarningCode:           SandboxCredentialProxyWarningUnsupportedDeliveryMode,
				ReasonCode:            SandboxCredentialProxyReasonDeliveryModeUnsupported,
			},
		},
		{
			name: "binding",
			value: SandboxCredentialProxyBindingMetadata{
				ID:                  "credential-binding-01",
				PlanID:              "credential-plan-01",
				SessionID:           "credential-session-01",
				SecretID:            "secret-01",
				DeliveryMode:        SandboxCredentialProxyDeliveryModeSSHAgent,
				RequestCategory:     SandboxCredentialProxyRequestSourceControl,
				DestinationCategory: SandboxNetworkPolicyDestinationPublicInternet,
				Outcome:             SandboxCredentialProxyBindingOutcomeBound,
				Status:              SandboxCredentialProxyStatusReady,
				ReasonCode:          SandboxCredentialProxyReasonRequested,
			},
		},
	}

	for _, tt := range samples {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.value)
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			var decoded any
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			assertCredentialProxyJSONKeysExcludeUnsafeRawFields(t, decoded, "$")
		})
	}
}

func TestCredentialProxyContractsExposeNoRawValueFields(t *testing.T) {
	contractTypes := []reflect.Type{
		reflect.TypeOf(SandboxCredentialProxyPlanMetadata{}),
		reflect.TypeOf(SandboxCredentialProxySessionMetadata{}),
		reflect.TypeOf(SandboxCredentialProxyBindingMetadata{}),
	}
	for _, typ := range contractTypes {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				fieldName := strings.ToLower(field.Name)
				jsonName := strings.ToLower(strings.Split(field.Tag.Get("json"), ",")[0])
				for _, forbidden := range forbiddenCredentialProxyRawFieldNameFragments() {
					if strings.Contains(fieldName, forbidden) || strings.Contains(jsonName, forbidden) {
						t.Fatalf("%s.%s json %q exposes forbidden raw credential proxy field fragment %q", typ.Name(), field.Name, jsonName, forbidden)
					}
				}
			}
		})
	}
}

func forbiddenCredentialProxyRawFieldNames() []string {
	return []string{
		"host",
		"hostname",
		"ip",
		"port",
		"url",
		"uri",
		"header",
		"headers",
		"body",
		"token",
		"credential",
		"environment",
		"localPath",
		"remotePath",
		"socketPath",
		"credentialValue",
		"secretValue",
		"rawDestination",
	}
}

func forbiddenCredentialProxyRawFieldNameFragments() []string {
	return []string{
		"host",
		"hostname",
		"port",
		"url",
		"uri",
		"header",
		"body",
		"token",
		"credential",
		"environment",
		"localpath",
		"remotepath",
		"socketpath",
		"credentialvalue",
		"secretvalue",
		"raw",
	}
}

type credentialProxyJSONTagExpectation struct {
	field     string
	name      string
	omitempty bool
}

func assertCredentialProxyJSONTags(t *testing.T, typ reflect.Type, expectations []credentialProxyJSONTagExpectation) {
	t.Helper()

	if typ.NumField() != len(expectations) {
		t.Fatalf("%s field count = %d, want %d", typ.Name(), typ.NumField(), len(expectations))
	}

	expectedFields := make(map[string]struct{}, len(expectations))
	for _, expectation := range expectations {
		expectedFields[expectation.field] = struct{}{}

		field, ok := typ.FieldByName(expectation.field)
		if !ok {
			t.Fatalf("%s missing expected field %s", typ.Name(), expectation.field)
		}
		tag := field.Tag.Get("json")
		parts := strings.Split(tag, ",")
		if parts[0] != expectation.name {
			t.Fatalf("%s.%s json name = %q, want %q", typ.Name(), expectation.field, parts[0], expectation.name)
		}

		gotOmitEmpty := false
		for _, option := range parts[1:] {
			if option == "omitempty" {
				gotOmitEmpty = true
			}
		}
		if gotOmitEmpty != expectation.omitempty {
			t.Fatalf("%s.%s omitempty = %t, want %t", typ.Name(), expectation.field, gotOmitEmpty, expectation.omitempty)
		}
	}

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if _, ok := expectedFields[field.Name]; !ok {
			t.Fatalf("%s has unlocked JSON field %s with tag %q", typ.Name(), field.Name, field.Tag.Get("json"))
		}
	}
}

func assertCredentialProxyJSONValue(t *testing.T, object map[string]any, key, want string) {
	t.Helper()

	if got := object[key]; got != want {
		t.Fatalf("%s = %#v, want %q", key, got, want)
	}
}

func assertCredentialProxyJSONKeysExcludeUnsafeRawFields(t *testing.T, value any, path string) {
	t.Helper()

	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			for _, forbidden := range forbiddenCredentialProxyRawFieldNames() {
				if strings.EqualFold(key, forbidden) {
					t.Fatalf("%s contains unsafe raw field name %q", path, key)
				}
			}
			assertCredentialProxyJSONKeysExcludeUnsafeRawFields(t, child, path+"."+key)
		}
	case []any:
		for _, child := range typed {
			assertCredentialProxyJSONKeysExcludeUnsafeRawFields(t, child, path+"[]")
		}
	}
}
