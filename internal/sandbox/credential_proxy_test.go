package sandbox

import (
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
		"headers",
		"body",
		"token",
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
		"environment",
		"localpath",
		"remotepath",
		"socketpath",
		"credentialvalue",
		"secretvalue",
		"raw",
	}
}
