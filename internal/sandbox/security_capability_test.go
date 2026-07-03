package sandbox

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSecurityCapabilityReadinessContractConstants(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "readiness metadata only", got: string(SandboxSecurityCapabilityReadinessMetadataOnly), want: "metadata_only"},
		{name: "readiness unsupported", got: string(SandboxSecurityCapabilityReadinessUnsupported), want: "unsupported"},
		{name: "readiness blocked", got: string(SandboxSecurityCapabilityReadinessBlocked), want: "blocked"},
		{name: "readiness ready", got: string(SandboxSecurityCapabilityReadinessReady), want: "ready"},
		{name: "family network policy", got: string(SandboxSecurityCapabilityFamilyNetworkPolicy), want: "network_policy"},
		{name: "family network proxy", got: string(SandboxSecurityCapabilityFamilyNetworkProxy), want: "network_proxy"},
		{name: "family credential proxy", got: string(SandboxSecurityCapabilityFamilyCredentialProxy), want: "credential_proxy"},
		{name: "family secret delivery", got: string(SandboxSecurityCapabilityFamilySecretDelivery), want: "secret_delivery"},
		{name: "family isolation", got: string(SandboxSecurityCapabilityFamilyIsolation), want: "isolation"},
		{name: "family workspace", got: string(SandboxSecurityCapabilityFamilyWorkspace), want: "workspace"},
		{name: "family template", got: string(SandboxSecurityCapabilityFamilyTemplate), want: "template"},
		{name: "capability deny by default", got: string(SandboxSecurityCapabilityNetworkDenyByDefault), want: "network_deny_by_default"},
		{name: "capability network proxy", got: string(SandboxSecurityCapabilityNetworkProxyEnforcement), want: "network_proxy_enforcement"},
		{name: "capability firewall", got: string(SandboxSecurityCapabilityNetworkFirewallEnforcement), want: "network_firewall_enforcement"},
		{name: "capability runtime", got: string(SandboxSecurityCapabilityNetworkRuntimeEnforcement), want: "network_runtime_enforcement"},
		{name: "capability credential proxy", got: string(SandboxSecurityCapabilityCredentialProxy), want: "credential_proxy"},
		{name: "capability secret env", got: string(SandboxSecurityCapabilitySecretEnv), want: "secret_env"},
		{name: "capability secret file tmpfs", got: string(SandboxSecurityCapabilitySecretFileTmpfs), want: "secret_file_tmpfs"},
		{name: "capability secret ssh agent", got: string(SandboxSecurityCapabilitySecretSSHAgent), want: "secret_ssh_agent"},
		{name: "capability secret http proxy", got: string(SandboxSecurityCapabilitySecretHTTPProxy), want: "secret_http_proxy"},
		{name: "capability isolation microvm", got: string(SandboxSecurityCapabilityIsolationMicroVM), want: "isolation_microvm"},
		{name: "capability isolated workspace", got: string(SandboxSecurityCapabilityIsolatedWorkspace), want: "isolated_workspace"},
		{name: "capability direct host worktree", got: string(SandboxSecurityCapabilityDirectHostWorktree), want: "direct_host_worktree"},
		{name: "capability template lock digest", got: string(SandboxSecurityCapabilityTemplateLockDigest), want: "template_lock_digest"},
		{name: "source requested", got: string(SandboxSecurityCapabilitySourceRequested), want: "requested"},
		{name: "source metadata", got: string(SandboxSecurityCapabilitySourceMetadata), want: "metadata"},
		{name: "source runtime", got: string(SandboxSecurityCapabilitySourceRuntime), want: "runtime"},
		{name: "source worker", got: string(SandboxSecurityCapabilitySourceWorker), want: "worker"},
		{name: "reason metadata only", got: string(SandboxSecurityCapabilityReasonMetadataOnly), want: "metadata_only"},
		{name: "reason capability missing", got: string(SandboxSecurityCapabilityReasonCapabilityMissing), want: "capability_missing"},
		{name: "reason mode unsupported", got: string(SandboxSecurityCapabilityReasonModeUnsupported), want: "mode_unsupported"},
		{name: "reason capability blocked", got: string(SandboxSecurityCapabilityReasonCapabilityBlocked), want: "capability_blocked"},
		{name: "reason capability confirmed", got: string(SandboxSecurityCapabilityReasonCapabilityConfirmed), want: "capability_confirmed"},
		{name: "reason metadata enforcement unproven", got: string(SandboxSecurityCapabilityReasonMetadataEnforcementUnproven), want: "metadata_enforcement_unproven"},
		{name: "reason metadata delivery unproven", got: string(SandboxSecurityCapabilityReasonMetadataDeliveryUnproven), want: "metadata_delivery_unproven"},
		{name: "reason readiness missing", got: string(SandboxSecurityCapabilityReasonReadinessMissing), want: "readiness_missing"},
		{name: "reason microvm readiness missing", got: string(SandboxSecurityCapabilityReasonMicroVMReadinessMissing), want: "microvm_readiness_missing"},
		{name: "reason microvm support missing", got: string(SandboxSecurityCapabilityReasonMicroVMSupportMissing), want: "microvm_support_missing"},
		{name: "reason workspace isolation missing", got: string(SandboxSecurityCapabilityReasonWorkspaceIsolationMissing), want: "workspace_isolation_missing"},
		{name: "reason workspace direct host worktree", got: string(SandboxSecurityCapabilityReasonWorkspaceDirectHostWorktree), want: "workspace_direct_host_worktree"},
		{name: "reason network enforcement missing", got: string(SandboxSecurityCapabilityReasonNetworkEnforcementMissing), want: "network_enforcement_missing"},
		{name: "reason network enforcement planned only", got: string(SandboxSecurityCapabilityReasonNetworkEnforcementPlannedOnly), want: "network_enforcement_planned_only"},
		{name: "reason network enforcement best effort", got: string(SandboxSecurityCapabilityReasonNetworkEnforcementBestEffort), want: "network_enforcement_best_effort"},
		{name: "reason network enforcement partial", got: string(SandboxSecurityCapabilityReasonNetworkEnforcementPartial), want: "network_enforcement_partial"},
		{name: "reason network enforcement unsupported", got: string(SandboxSecurityCapabilityReasonNetworkEnforcementUnsupported), want: "network_enforcement_unsupported"},
		{name: "reason network enforcement failed", got: string(SandboxSecurityCapabilityReasonNetworkEnforcementFailed), want: "network_enforcement_failed"},
		{name: "reason credential activation missing", got: string(SandboxSecurityCapabilityReasonCredentialActivationMissing), want: "credential_activation_missing"},
		{name: "reason template lock digest missing", got: string(SandboxSecurityCapabilityReasonTemplateLockDigestMissing), want: "template_lock_digest_missing"},
		{name: "reason microvm readiness confirmed", got: string(SandboxSecurityCapabilityReasonMicroVMReadinessConfirmed), want: "microvm_readiness_confirmed"},
		{name: "reason workspace isolation confirmed", got: string(SandboxSecurityCapabilityReasonWorkspaceIsolationConfirmed), want: "workspace_isolation_confirmed"},
		{name: "reason network enforcement confirmed", got: string(SandboxSecurityCapabilityReasonNetworkEnforcementConfirmed), want: "network_enforcement_confirmed"},
		{name: "reason credential activation confirmed", got: string(SandboxSecurityCapabilityReasonCredentialActivationConfirmed), want: "credential_activation_confirmed"},
		{name: "reason template lock digest confirmed", got: string(SandboxSecurityCapabilityReasonTemplateLockDigestConfirmed), want: "template_lock_digest_confirmed"},
		{name: "reason unknown", got: string(SandboxSecurityCapabilityReasonUnknown), want: "unknown"},
		{name: "warning metadata not capability", got: string(SandboxSecurityCapabilityWarningMetadataNotCapability), want: "metadata_not_capability"},
		{name: "warning unsupported mode", got: string(SandboxSecurityCapabilityWarningUnsupportedMode), want: "unsupported_mode"},
		{name: "warning blocked by policy", got: string(SandboxSecurityCapabilityWarningBlockedByPolicy), want: "blocked_by_policy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %q, want %q", tt.name, tt.got, tt.want)
			}
			assertSecurityCapabilitySafeEnumValue(t, tt.got)
		})
	}
}

func TestSecurityCapabilityReadinessRequestJSONSchema(t *testing.T) {
	request := SandboxSecurityCapabilityReadinessRequest{
		Requested: []SandboxSecurityCapabilityMetadata{
			{
				ID:         "requested-network-01",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
				Mode:       SandboxNetworkEnforcementModeFirewall,
				Source:     SandboxSecurityCapabilitySourceRequested,
			},
			{
				ID:         "requested-credential-01",
				Family:     SandboxSecurityCapabilityFamilyCredentialProxy,
				Capability: SandboxSecurityCapabilityCredentialProxy,
				Mode:       SandboxSecretModeHTTPProxy,
				Source:     SandboxSecurityCapabilitySourceRequested,
			},
		},
		Ready: []SandboxSecurityCapabilityMetadata{
			{
				ID:         "ready-network-01",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkFirewallEnforcement,
				Mode:       SandboxNetworkEnforcementModeFirewall,
				Source:     SandboxSecurityCapabilitySourceRuntime,
			},
		},
		WorkerPostures: []SandboxSecurityCapabilityWorkerPostureMetadata{
			{
				WorkerKind:         SandboxHostKindWorker,
				RuntimeDriver:      SandboxRuntimeDriverRootlessPodman,
				IsolationLevel:     SandboxIsolationLevelContainer,
				NetworkPolicy:      SandboxNetworkPolicyBestEffort,
				NetworkEnforcement: SandboxNetworkEnforcementModeNone,
			},
		},
	}

	got := mustMarshalObject(t, request)
	assertObjectKeys(t, got, []string{"requested", "ready", "workerPostures"}, forbiddenSecurityCapabilityRawFieldNames())

	requested := got["requested"].([]any)
	if len(requested) != 2 {
		t.Fatalf("requested count = %d, want 2", len(requested))
	}
	assertObjectKeys(t, requested[0], []string{"id", "family", "capability", "mode", "source"}, forbiddenSecurityCapabilityRawFieldNames())
	assertSecurityCapabilityJSONValue(t, requested[0], "family", "network_policy")
	assertSecurityCapabilityJSONValue(t, requested[0], "capability", "network_deny_by_default")
	assertSecurityCapabilityJSONValue(t, requested[0], "mode", SandboxNetworkEnforcementModeFirewall)
	assertSecurityCapabilityJSONValue(t, requested[1], "family", "credential_proxy")
	assertSecurityCapabilityJSONValue(t, requested[1], "capability", "credential_proxy")
	assertSecurityCapabilityJSONValue(t, requested[1], "mode", SandboxSecretModeHTTPProxy)

	ready := got["ready"].([]any)
	if len(ready) != 1 {
		t.Fatalf("ready count = %d, want 1", len(ready))
	}
	assertObjectKeys(t, ready[0], []string{"id", "family", "capability", "mode", "source"}, forbiddenSecurityCapabilityRawFieldNames())
	assertSecurityCapabilityJSONValue(t, ready[0], "source", "runtime")

	workerPostures := got["workerPostures"].([]any)
	if len(workerPostures) != 1 {
		t.Fatalf("workerPostures count = %d, want 1", len(workerPostures))
	}
	assertObjectKeys(t, workerPostures[0], []string{
		"workerKind",
		"runtimeDriver",
		"isolationLevel",
		"networkPolicy",
		"networkEnforcement",
	}, forbiddenSecurityCapabilityRawFieldNames())
	assertSecurityCapabilityJSONValue(t, workerPostures[0], "workerKind", SandboxHostKindWorker)
	assertSecurityCapabilityJSONValue(t, workerPostures[0], "runtimeDriver", SandboxRuntimeDriverRootlessPodman)
	assertSecurityCapabilityJSONValue(t, workerPostures[0], "isolationLevel", SandboxIsolationLevelContainer)
	assertSecurityCapabilityJSONValue(t, workerPostures[0], "networkPolicy", SandboxNetworkPolicyBestEffort)
	assertSecurityCapabilityJSONValue(t, workerPostures[0], "networkEnforcement", SandboxNetworkEnforcementModeNone)
}

func TestSecurityCapabilityReadinessResultJSONSchema(t *testing.T) {
	result := SandboxSecurityCapabilityReadinessResult{
		State: SandboxSecurityCapabilityReadinessReady,
		Metadata: &SandboxSecurityCapabilityMetadata{
			ID:         "metadata-network-01",
			Family:     SandboxSecurityCapabilityFamilyNetworkProxy,
			Capability: SandboxSecurityCapabilityNetworkProxyEnforcement,
			Source:     SandboxSecurityCapabilitySourceMetadata,
			Status:     SandboxSecurityCapabilityReadinessMetadataOnly,
		},
		Requested: &SandboxSecurityCapabilityMetadata{
			ID:         "requested-network-01",
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
			Mode:       SandboxNetworkEnforcementModeFirewall,
			Source:     SandboxSecurityCapabilitySourceRequested,
		},
		Ready: &SandboxSecurityCapabilityMetadata{
			ID:         "ready-network-01",
			Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
			Capability: SandboxSecurityCapabilityNetworkFirewallEnforcement,
			Mode:       SandboxNetworkEnforcementModeFirewall,
			Source:     SandboxSecurityCapabilitySourceRuntime,
		},
		ReasonCode:   SandboxSecurityCapabilityReasonCapabilityConfirmed,
		WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
	}

	got := mustMarshalObject(t, result)
	assertObjectKeys(t, got, []string{
		"state",
		"metadata",
		"requested",
		"ready",
		"reasonCode",
		"warningCodes",
	}, forbiddenSecurityCapabilityRawFieldNames())
	assertSecurityCapabilityJSONValue(t, got, "state", "ready")
	assertSecurityCapabilityJSONValue(t, got, "reasonCode", "capability_confirmed")

	assertObjectKeys(t, got["metadata"], []string{"id", "family", "capability", "source", "status"}, forbiddenSecurityCapabilityRawFieldNames())
	assertObjectKeys(t, got["requested"], []string{"id", "family", "capability", "mode", "source"}, forbiddenSecurityCapabilityRawFieldNames())
	assertObjectKeys(t, got["ready"], []string{"id", "family", "capability", "mode", "source"}, forbiddenSecurityCapabilityRawFieldNames())

	warnings := got["warningCodes"].([]any)
	if len(warnings) != 1 || warnings[0] != "metadata_not_capability" {
		t.Fatalf("warningCodes = %#v, want metadata_not_capability", warnings)
	}
}

func TestSecurityCapabilityMetadataStatusReasonWarningJSONSchema(t *testing.T) {
	metadata := SandboxSecurityCapabilityMetadata{
		ID:           "blocked-network-01",
		Family:       SandboxSecurityCapabilityFamilyNetworkPolicy,
		Capability:   SandboxSecurityCapabilityNetworkProxyEnforcement,
		Mode:         SandboxNetworkEnforcementModeProxy,
		Source:       SandboxSecurityCapabilitySourceRuntime,
		Status:       SandboxSecurityCapabilityReadinessBlocked,
		ReasonCode:   SandboxSecurityCapabilityReasonCapabilityBlocked,
		WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningBlockedByPolicy},
	}

	got := mustMarshalObject(t, metadata)
	assertObjectKeys(t, got, []string{
		"id",
		"family",
		"capability",
		"mode",
		"source",
		"status",
		"reasonCode",
		"warningCodes",
	}, forbiddenSecurityCapabilityRawFieldNames())
	assertSecurityCapabilityJSONValue(t, got, "status", "blocked")
	assertSecurityCapabilityJSONValue(t, got, "reasonCode", "capability_blocked")

	warnings := got["warningCodes"].([]any)
	if len(warnings) != 1 || warnings[0] != "blocked_by_policy" {
		t.Fatalf("warningCodes = %#v, want blocked_by_policy", warnings)
	}
}

func TestSecurityCapabilityReadinessOutputJSONSchema(t *testing.T) {
	output := SandboxSecurityCapabilityReadinessOutput{
		Results: []SandboxSecurityCapabilityReadinessResult{
			{
				State:      SandboxSecurityCapabilityReadinessMetadataOnly,
				ReasonCode: SandboxSecurityCapabilityReasonMetadataOnly,
			},
			{
				State:      SandboxSecurityCapabilityReadinessUnsupported,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityMissing,
			},
		},
	}

	got := mustMarshalObject(t, output)
	assertObjectKeys(t, got, []string{"results"}, forbiddenSecurityCapabilityRawFieldNames())

	results := got["results"].([]any)
	if len(results) != 2 {
		t.Fatalf("results count = %d, want 2", len(results))
	}
	assertSecurityCapabilityJSONValue(t, results[0], "state", "metadata_only")
	assertSecurityCapabilityJSONValue(t, results[1], "state", "unsupported")
}

func TestSecurityCapabilityReadinessDefaultMetadataOmitsOptionalJSONFields(t *testing.T) {
	request := mustMarshalObject(t, SandboxSecurityCapabilityReadinessRequest{})
	if len(request) != 0 {
		t.Fatalf("zero readiness request = %#v, want empty object", request)
	}

	result := mustMarshalObject(t, SandboxSecurityCapabilityReadinessResult{})
	assertObjectKeys(t, result, []string{"state"}, []string{
		"requested",
		"ready",
		"reasonCode",
		"warningCodes",
	})

	output := mustMarshalObject(t, SandboxSecurityCapabilityReadinessOutput{})
	if len(output) != 0 {
		t.Fatalf("zero readiness output = %#v, want empty object", output)
	}

	metadata := mustMarshalObject(t, SandboxSecurityCapabilityMetadata{
		Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
		Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
	})
	assertObjectKeys(t, metadata, []string{"family", "capability"}, []string{
		"id",
		"mode",
		"source",
		"status",
		"reasonCode",
		"warningCodes",
	})
}

func TestSecurityCapabilityReadinessJSONTagsAreStable(t *testing.T) {
	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityMetadata{}), []securityCapabilityJSONTagExpectation{
		{field: "ID", name: "id", omitempty: true},
		{field: "Family", name: "family"},
		{field: "Capability", name: "capability"},
		{field: "Mode", name: "mode", omitempty: true},
		{field: "Source", name: "source", omitempty: true},
		{field: "Status", name: "status", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
		{field: "WarningCodes", name: "warningCodes", omitempty: true},
	})

	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityWorkerPostureMetadata{}), []securityCapabilityJSONTagExpectation{
		{field: "WorkerKind", name: "workerKind", omitempty: true},
		{field: "RuntimeDriver", name: "runtimeDriver", omitempty: true},
		{field: "IsolationLevel", name: "isolationLevel", omitempty: true},
		{field: "NetworkPolicy", name: "networkPolicy", omitempty: true},
		{field: "NetworkEnforcement", name: "networkEnforcement", omitempty: true},
		{field: "CredentialModes", name: "credentialModes", omitempty: true},
		{field: "CredentialProxyMode", name: "credentialProxyMode", omitempty: true},
	})

	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityReadinessRequest{}), []securityCapabilityJSONTagExpectation{
		{field: "Requested", name: "requested", omitempty: true},
		{field: "Ready", name: "ready", omitempty: true},
		{field: "WorkerPostures", name: "workerPostures", omitempty: true},
		{field: "NetworkProxySession", name: "networkProxySession", omitempty: true},
		{field: "NetworkPolicyDecisionLogs", name: "networkPolicyDecisionLogs", omitempty: true},
		{field: "CredentialProxyPlan", name: "credentialPlanMetadata", omitempty: true},
		{field: "CredentialProxySession", name: "credentialSessionMetadata", omitempty: true},
		{field: "CredentialProxyBindings", name: "credentialBindingMetadata", omitempty: true},
	})

	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityReadinessResult{}), []securityCapabilityJSONTagExpectation{
		{field: "State", name: "state"},
		{field: "Metadata", name: "metadata", omitempty: true},
		{field: "Requested", name: "requested", omitempty: true},
		{field: "Ready", name: "ready", omitempty: true},
		{field: "ReasonCode", name: "reasonCode", omitempty: true},
		{field: "WarningCodes", name: "warningCodes", omitempty: true},
	})

	assertSecurityCapabilityJSONTags(t, reflect.TypeOf(SandboxSecurityCapabilityReadinessOutput{}), []securityCapabilityJSONTagExpectation{
		{field: "Results", name: "results", omitempty: true},
	})
}

func TestSecurityCapabilityReadinessContractsExposeNoRawValueFields(t *testing.T) {
	contractTypes := []reflect.Type{
		reflect.TypeOf(SandboxSecurityCapabilityMetadata{}),
		reflect.TypeOf(SandboxSecurityCapabilityWorkerPostureMetadata{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessRequest{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessResult{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessOutput{}),
	}
	for _, typ := range contractTypes {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				fieldName := strings.ToLower(field.Name)
				jsonName := strings.ToLower(strings.Split(field.Tag.Get("json"), ",")[0])
				for _, forbidden := range forbiddenSecurityCapabilityRawFieldNameFragments() {
					if strings.Contains(fieldName, forbidden) || strings.Contains(jsonName, forbidden) {
						t.Fatalf("%s.%s json %q exposes forbidden raw readiness field fragment %q", typ.Name(), field.Name, jsonName, forbidden)
					}
				}
			}
		})
	}
}

func TestSecurityCapabilitySerializedReadinessContainsNoUnsafeRawFieldNames(t *testing.T) {
	samples := []struct {
		name  string
		value any
	}{
		{
			name: "metadata",
			value: SandboxSecurityCapabilityMetadata{
				ID:         "ready-network-01",
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkFirewallEnforcement,
				Mode:       SandboxNetworkEnforcementModeFirewall,
				Source:     SandboxSecurityCapabilitySourceRuntime,
			},
		},
		{
			name: "request",
			value: SandboxSecurityCapabilityReadinessRequest{
				Requested: []SandboxSecurityCapabilityMetadata{{
					ID:         "requested-credential-01",
					Family:     SandboxSecurityCapabilityFamilyCredentialProxy,
					Capability: SandboxSecurityCapabilityCredentialProxy,
					Mode:       SandboxSecretModeHTTPProxy,
					Source:     SandboxSecurityCapabilitySourceRequested,
				}},
				WorkerPostures: []SandboxSecurityCapabilityWorkerPostureMetadata{{
					WorkerKind:         SandboxHostKindLocal,
					RuntimeDriver:      SandboxRuntimeDriverRootlessPodman,
					IsolationLevel:     SandboxIsolationLevelContainer,
					NetworkPolicy:      SandboxNetworkPolicyBestEffort,
					NetworkEnforcement: SandboxNetworkEnforcementModeNone,
				}},
			},
		},
		{
			name: "result",
			value: SandboxSecurityCapabilityReadinessResult{
				State:      SandboxSecurityCapabilityReadinessBlocked,
				Requested:  &SandboxSecurityCapabilityMetadata{Family: SandboxSecurityCapabilityFamilySecretDelivery, Capability: SandboxSecurityCapabilitySecretFileTmpfs},
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
			},
		},
		{
			name: "output",
			value: SandboxSecurityCapabilityReadinessOutput{
				Results: []SandboxSecurityCapabilityReadinessResult{{
					State:      SandboxSecurityCapabilityReadinessMetadataOnly,
					ReasonCode: SandboxSecurityCapabilityReasonMetadataOnly,
				}},
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
			assertSecurityCapabilityJSONKeysExcludeUnsafeRawFields(t, decoded, "$")
		})
	}
}

func TestSecurityCapabilityReadinessOutputJSONContainsOnlySafeMetadataValues(t *testing.T) {
	output := SanitizeSandboxSecurityCapabilityReadinessOutput(SandboxSecurityCapabilityReadinessOutput{
		Results: []SandboxSecurityCapabilityReadinessResult{
			{
				State: SandboxSecurityCapabilityReadinessReady,
				Requested: &SandboxSecurityCapabilityMetadata{
					ID:         "requested-network-01",
					Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
					Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
					Mode:       SandboxNetworkEnforcementModeFirewall,
					Source:     SandboxSecurityCapabilitySourceRequested,
					Status:     SandboxSecurityCapabilityReadinessReady,
					ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
				},
				Ready: &SandboxSecurityCapabilityMetadata{
					ID:         "ready-network-01",
					Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
					Capability: SandboxSecurityCapabilityNetworkFirewallEnforcement,
					Mode:       SandboxNetworkEnforcementModeFirewall,
					Source:     SandboxSecurityCapabilitySourceRuntime,
					Status:     SandboxSecurityCapabilityReadinessReady,
					ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
				},
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
			},
			{
				State: SandboxSecurityCapabilityReadinessBlocked,
				Requested: &SandboxSecurityCapabilityMetadata{
					ID:           "requested-secret-01",
					Family:       SandboxSecurityCapabilityFamilySecretDelivery,
					Capability:   SandboxSecurityCapabilitySecretFileTmpfs,
					Mode:         SandboxSecretModeFileTmpfs,
					Source:       SandboxSecurityCapabilitySourceRequested,
					Status:       SandboxSecurityCapabilityReadinessBlocked,
					ReasonCode:   SandboxSecurityCapabilityReasonCapabilityBlocked,
					WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningBlockedByPolicy},
				},
				Ready: &SandboxSecurityCapabilityMetadata{
					ID:           "blocked-secret-01",
					Family:       SandboxSecurityCapabilityFamilySecretDelivery,
					Capability:   SandboxSecurityCapabilitySecretFileTmpfs,
					Mode:         SandboxSecretModeFileTmpfs,
					Source:       SandboxSecurityCapabilitySourceWorker,
					Status:       SandboxSecurityCapabilityReadinessBlocked,
					ReasonCode:   SandboxSecurityCapabilityReasonCapabilityBlocked,
					WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningBlockedByPolicy},
				},
				ReasonCode:   SandboxSecurityCapabilityReasonCapabilityBlocked,
				WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningBlockedByPolicy},
			},
			{
				State: SandboxSecurityCapabilityReadinessMetadataOnly,
				Metadata: &SandboxSecurityCapabilityMetadata{
					ID:           "metadata-credential-01",
					Family:       SandboxSecurityCapabilityFamilyCredentialProxy,
					Capability:   SandboxSecurityCapabilityCredentialProxy,
					Source:       SandboxSecurityCapabilitySourceMetadata,
					Status:       SandboxSecurityCapabilityReadinessMetadataOnly,
					ReasonCode:   SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
					WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
				},
				ReasonCode:   SandboxSecurityCapabilityReasonMetadataDeliveryUnproven,
				WarningCodes: []SandboxSecurityCapabilityWarningCode{SandboxSecurityCapabilityWarningMetadataNotCapability},
			},
		},
	})

	got := mustMarshalObject(t, output)
	assertSecurityCapabilityReadinessJSONOnlySafeMetadataValues(t, got, "$")
	assertSecurityCapabilityJSONKeysExcludeUnsafeRawFields(t, got, "$")
}

func TestSecurityCapabilityReadinessOutputSanitizationDropsResultsWithoutRequiredContext(t *testing.T) {
	validRequested := SandboxSecurityCapabilityMetadata{
		ID:         "requested-network-01",
		Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
		Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
		Mode:       SandboxNetworkEnforcementModeFirewall,
		Source:     SandboxSecurityCapabilitySourceRequested,
	}
	validReady := SandboxSecurityCapabilityMetadata{
		ID:         "ready-network-01",
		Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
		Capability: SandboxSecurityCapabilityNetworkFirewallEnforcement,
		Mode:       SandboxNetworkEnforcementModeFirewall,
		Source:     SandboxSecurityCapabilitySourceRuntime,
		Status:     SandboxSecurityCapabilityReadinessReady,
	}
	validMetadata := SandboxSecurityCapabilityMetadata{
		ID:         "metadata-network-01",
		Family:     SandboxSecurityCapabilityFamilyNetworkProxy,
		Capability: SandboxSecurityCapabilityNetworkProxyEnforcement,
		Mode:       SandboxNetworkEnforcementModeProxy,
		Source:     SandboxSecurityCapabilitySourceMetadata,
		Status:     SandboxSecurityCapabilityReadinessMetadataOnly,
	}
	invalidReady := validReady
	invalidReady.Mode = "https://worker.example.invalid:8443/proxy?token=raw-token"

	output := SanitizeSandboxSecurityCapabilityReadinessOutput(SandboxSecurityCapabilityReadinessOutput{
		Results: []SandboxSecurityCapabilityReadinessResult{
			{
				State:      SandboxSecurityCapabilityReadinessReady,
				Requested:  &validRequested,
				Ready:      &invalidReady,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
			},
			{
				State:      SandboxSecurityCapabilityReadinessReady,
				Requested:  &validRequested,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
			},
			{
				State:      SandboxSecurityCapabilityReadinessBlocked,
				Requested:  &validRequested,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityBlocked,
			},
			{
				State:      SandboxSecurityCapabilityReadinessUnsupported,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityMissing,
			},
			{
				State:      SandboxSecurityCapabilityReadinessMetadataOnly,
				ReasonCode: SandboxSecurityCapabilityReasonMetadataOnly,
			},
			{
				State:      SandboxSecurityCapabilityReadinessReady,
				Requested:  &validRequested,
				Ready:      &validReady,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
			},
			{
				State:      SandboxSecurityCapabilityReadinessUnsupported,
				Requested:  &validRequested,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityMissing,
			},
			{
				State:      SandboxSecurityCapabilityReadinessMetadataOnly,
				Metadata:   &validMetadata,
				ReasonCode: SandboxSecurityCapabilityReasonMetadataOnly,
			},
		},
	})

	if len(output.Results) != 3 {
		t.Fatalf("sanitized results count = %d, want only valid-context results: %#v", len(output.Results), output.Results)
	}
	if output.Results[0].State != SandboxSecurityCapabilityReadinessReady ||
		output.Results[0].Requested == nil ||
		output.Results[0].Ready == nil {
		t.Fatalf("ready result = %#v, want requested and ready context preserved", output.Results[0])
	}
	if output.Results[1].State != SandboxSecurityCapabilityReadinessUnsupported ||
		output.Results[1].Requested == nil {
		t.Fatalf("unsupported result = %#v, want requested context preserved", output.Results[1])
	}
	if output.Results[2].State != SandboxSecurityCapabilityReadinessMetadataOnly ||
		output.Results[2].Metadata == nil {
		t.Fatalf("metadata-only result = %#v, want metadata context preserved", output.Results[2])
	}

	cloned := CloneSandboxSecurityCapabilityReadinessOutputPtr(&SandboxSecurityCapabilityReadinessOutput{
		Results: []SandboxSecurityCapabilityReadinessResult{{
			State:      SandboxSecurityCapabilityReadinessReady,
			Requested:  &validRequested,
			Ready:      &invalidReady,
			ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
		}},
	})
	if cloned != nil {
		t.Fatalf("cloned invalid ready output = %#v, want nil after proof context is stripped", cloned)
	}
}

func TestSecurityCapabilityReadinessSanitizationRejectsOrOmitsRawLookingValues(t *testing.T) {
	for _, tt := range []struct {
		name  string
		value string
	}{
		{name: "hostname", value: "worker-01.example.invalid"},
		{name: "url", value: "https://user:pass@example.invalid/path?token=raw-url-token"},
		{name: "local path", value: "/Users/v/project/.hal/config.yaml"},
		{name: "socket path", value: "unix:///tmp/hal-worker.sock"},
		{name: "ip and port", value: "127.0.0.1:8443"},
		{name: "port", value: "8443"},
		{name: "credential value", value: "credentialValue=raw-credential"},
		{name: "token string", value: "ghp_raw_token_value"},
		{name: "secret value", value: "secretValue=raw-secret"},
		{name: "command output", value: "stderr: command failed token=raw-secret"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			input := securityCapabilityReadinessInputWithUnsafeValue(tt.value)

			validation := ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(input)
			if validation.Valid {
				t.Fatalf("ValidateAndNormalizeSandboxSecurityCapabilityReadinessInput(%q) valid = true, want unsafe metadata rejected", tt.value)
			}
			assertSecurityCapabilityJSONExcludes(t, validation.Errors, tt.value)
			for _, err := range validation.Errors {
				assertSecurityCapabilityTextExcludes(t, err.Error(), tt.value)
			}

			sanitized := SanitizeSandboxSecurityCapabilityReadinessInput(input)
			assertSecurityCapabilityJSONExcludes(t, sanitized, tt.value)

			output := EvaluateSandboxSecurityCapabilityReadiness(input)
			assertSecurityCapabilityJSONExcludes(t, output, tt.value)
		})
	}
}

func assertSecurityCapabilityJSONValue(t *testing.T, object any, key, want string) {
	t.Helper()

	got, ok := object.(map[string]any)
	if !ok {
		t.Fatalf("value = %#v, want JSON object", object)
	}
	if got[key] != want {
		t.Fatalf("%s = %#v, want %q", key, got[key], want)
	}
	gotString, ok := got[key].(string)
	if !ok {
		t.Fatalf("%s = %#v, want string", key, got[key])
	}
	assertSecurityCapabilitySafeEnumValue(t, gotString)
}

func assertSecurityCapabilityReadinessJSONOnlySafeMetadataValues(t *testing.T, value any, path string) {
	t.Helper()

	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := path + "." + key
			switch key {
			case "results", "metadata", "requested", "ready":
				assertSecurityCapabilityReadinessJSONOnlySafeMetadataValues(t, child, childPath)
			case "id":
				assertSecurityCapabilitySafeIdentifierValue(t, requireSecurityCapabilityJSONString(t, child, childPath))
			case "family", "capability", "mode", "source", "status", "state", "reasonCode":
				assertSecurityCapabilitySafeEnumValue(t, requireSecurityCapabilityJSONString(t, child, childPath))
			case "warningCodes":
				warnings, ok := child.([]any)
				if !ok {
					t.Fatalf("%s = %#v, want JSON array", childPath, child)
				}
				for i, warning := range warnings {
					assertSecurityCapabilitySafeEnumValue(t, requireSecurityCapabilityJSONString(t, warning, childPath+"["+securityCapabilityTestIndexString(i)+"]"))
				}
			default:
				t.Fatalf("%s contains unexpected readiness JSON key %q", path, key)
			}
		}
	case []any:
		for i, child := range typed {
			assertSecurityCapabilityReadinessJSONOnlySafeMetadataValues(t, child, path+"["+securityCapabilityTestIndexString(i)+"]")
		}
	default:
		t.Fatalf("%s = %#v, want readiness JSON object or array", path, value)
	}
}

func requireSecurityCapabilityJSONString(t *testing.T, value any, path string) string {
	t.Helper()

	got, ok := value.(string)
	if !ok {
		t.Fatalf("%s = %#v, want string", path, value)
	}
	return got
}

func assertSecurityCapabilitySafeIdentifierValue(t *testing.T, value string) {
	t.Helper()

	if value == "" {
		t.Fatal("identifier value must not be empty")
	}
	if unsafeSandboxCredentialProxyIdentifier(value) {
		t.Fatalf("identifier value %q is not redaction-safe", value)
	}
}

func assertSecurityCapabilitySafeEnumValue(t *testing.T, value string) {
	t.Helper()

	if value == "" {
		t.Fatal("enum value must not be empty")
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			continue
		}
		t.Fatalf("enum value %q is not redaction-safe snake_case", value)
	}
}

func securityCapabilityReadinessInputWithUnsafeValue(value string) SandboxSecurityCapabilityReadinessInput {
	return SandboxSecurityCapabilityReadinessInput{
		Requested: []SandboxSecurityCapabilityMetadata{
			{
				ID:         value,
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
				Mode:       SandboxNetworkEnforcementModeFirewall,
				Source:     SandboxSecurityCapabilitySourceRequested,
			},
			{
				ID:         "requested-unsafe-mode",
				Family:     SandboxSecurityCapabilityFamilyCredentialProxy,
				Capability: SandboxSecurityCapabilityCredentialProxy,
				Mode:       value,
				Source:     SandboxSecurityCapabilitySourceRequested,
			},
		},
		Ready: []SandboxSecurityCapabilityMetadata{
			{
				ID:         value,
				Family:     SandboxSecurityCapabilityFamilyNetworkPolicy,
				Capability: SandboxSecurityCapabilityNetworkDenyByDefault,
				Mode:       SandboxNetworkEnforcementModeFirewall,
				Source:     SandboxSecurityCapabilitySourceRuntime,
				Status:     SandboxSecurityCapabilityReadinessReady,
				ReasonCode: SandboxSecurityCapabilityReasonCapabilityConfirmed,
				WarningCodes: []SandboxSecurityCapabilityWarningCode{
					SandboxSecurityCapabilityWarningBlockedByPolicy,
					SandboxSecurityCapabilityWarningCode(value),
				},
			},
			{
				ID:         "ready-unsafe-reason",
				Family:     SandboxSecurityCapabilityFamilyNetworkProxy,
				Capability: SandboxSecurityCapabilityNetworkProxyEnforcement,
				Mode:       SandboxNetworkEnforcementModeProxy,
				Source:     SandboxSecurityCapabilitySourceRuntime,
				Status:     SandboxSecurityCapabilityReadinessReady,
				ReasonCode: SandboxSecurityCapabilityReasonCode(value),
			},
		},
		WorkerPostures: []SandboxSecurityCapabilityWorkerPostureMetadata{{
			WorkerKind:         value,
			RuntimeDriver:      value,
			IsolationLevel:     value,
			NetworkPolicy:      value,
			NetworkEnforcement: value,
			CredentialModes:    []string{value},
		}},
		NetworkProxySession: &SandboxNetworkProxySessionMetadata{
			ID:              value,
			Source:          SandboxNetworkPolicyDecisionSourceRun,
			EnforcementMode: SandboxNetworkEnforcementModeProxy,
		},
		NetworkPolicyDecisionLogs: []SandboxNetworkPolicyDecisionLogRecord{{
			ID:             value,
			Source:         SandboxNetworkPolicyDecisionSourceRun,
			ProxySessionID: value,
			Request: &SandboxNetworkPolicyRequestSummary{
				ID:                  value,
				Operation:           value,
				DestinationCategory: SandboxNetworkPolicyDestinationCategory(value),
			},
			Outcome:         SandboxNetworkPolicyDecisionOutcomeDenied,
			ReasonCode:      SandboxNetworkPolicyDecisionReasonDefaultDeny,
			PolicyPreset:    SandboxNetworkPolicyPresetDenyByDefault,
			EnforcementMode: SandboxNetworkEnforcementModeProxy,
		}},
		CredentialProxyPlan: &SandboxCredentialProxyPlanMetadata{
			ID:                    value,
			Source:                SandboxCredentialProxySourceRun,
			SecretBrokerSessionID: value,
			NetworkProxySessionID: value,
			Mode:                  SandboxCredentialProxyModeMetadataOnly,
			Status:                SandboxCredentialProxyStatusReady,
		},
		CredentialProxySession: &SandboxCredentialProxySessionMetadata{
			ID:         "credential-proxy-session-01",
			PlanID:     value,
			Source:     SandboxCredentialProxySourceWorker,
			Status:     SandboxCredentialProxyStatusActive,
			ReasonCode: SandboxCredentialProxyReasonRequested,
		},
		CredentialProxyBindings: []SandboxCredentialProxyBindingMetadata{{
			ID:           "credential-proxy-binding-01",
			PlanID:       "credential-proxy-plan-01",
			SecretID:     value,
			DeliveryMode: SandboxCredentialProxyDeliveryModeHTTPProxy,
			Status:       SandboxCredentialProxyStatusReady,
		}},
	}
}

func securityCapabilityTestIndexString(index int) string {
	if index == 0 {
		return "0"
	}
	var digits [20]byte
	i := len(digits)
	for index > 0 {
		i--
		digits[i] = byte('0' + index%10)
		index /= 10
	}
	return string(digits[i:])
}

func forbiddenSecurityCapabilityRawFieldNames() []string {
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
		"socketPath",
		"localPath",
		"remotePath",
		"path",
		"environment",
		"environmentValue",
		"envValue",
		"token",
		"credentialValue",
		"secretValue",
		"rawCredential",
		"rawSecret",
	}
}

func forbiddenSecurityCapabilityRawFieldNameFragments() []string {
	return []string{
		"host",
		"hostname",
		"ip",
		"port",
		"url",
		"uri",
		"header",
		"body",
		"socketpath",
		"localpath",
		"remotepath",
		"path",
		"environment",
		"envvalue",
		"token",
		"credentialvalue",
		"secretvalue",
		"raw",
	}
}

type securityCapabilityJSONTagExpectation struct {
	field     string
	name      string
	omitempty bool
}

func assertSecurityCapabilityJSONTags(t *testing.T, typ reflect.Type, expectations []securityCapabilityJSONTagExpectation) {
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

func assertSecurityCapabilityJSONKeysExcludeUnsafeRawFields(t *testing.T, value any, path string) {
	t.Helper()

	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			for _, forbidden := range forbiddenSecurityCapabilityRawFieldNames() {
				if strings.EqualFold(key, forbidden) {
					t.Fatalf("%s contains unsafe raw field name %q", path, key)
				}
			}
			assertSecurityCapabilityJSONKeysExcludeUnsafeRawFields(t, child, path+"."+key)
		}
	case []any:
		for _, child := range typed {
			assertSecurityCapabilityJSONKeysExcludeUnsafeRawFields(t, child, path+"[]")
		}
	}
}
