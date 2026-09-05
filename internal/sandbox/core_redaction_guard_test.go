package sandbox

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCoreRedactionGuardSandboxDurableFields(t *testing.T) {
	for _, typ := range sandboxCoreRedactionGuardTypes() {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.PkgPath != "" {
					continue
				}
				sandboxAssertCoreRedactionSafeFieldName(t, typ.Name()+"."+field.Name, field.Name)
				if jsonName := sandboxCoreRedactionJSONFieldName(field); jsonName != "" {
					sandboxAssertCoreRedactionSafeFieldName(t, typ.Name()+"."+field.Name+" json", jsonName)
				}
			}
		})
	}
}

func TestCoreRedactionGuardSandboxRejectsRequiredRawFieldCategories(t *testing.T) {
	for category, name := range map[string]string{
		"secret values":           "secretValue",
		"credential values":       "credentialValue",
		"raw provider metadata":   "providerMetadata",
		"raw endpoints":           "endpointURL",
		"raw local paths":         "localPath",
		"socket paths":            "socketPath",
		"environment values":      "environmentValue",
		"headers":                 "authorizationHeader",
		"tokens":                  "apiToken",
		"command lines":           "commandLine",
		"raw credential metadata": "rawCredentialMetadata",
	} {
		t.Run(category, func(t *testing.T) {
			if !sandboxCoreRedactionUnsafeName(name) {
				t.Fatalf("guard did not reject %q for %s", name, category)
			}
		})
	}
}

func TestCoreRedactionGuardSandboxAllowsSafeMetadataNames(t *testing.T) {
	for _, name := range []string{
		"ID",
		"planId",
		"policySnapshotId",
		"ruleSetId",
		"bindingId",
		"secretId",
		"deliveryMode",
		"requestedModes",
		"activeModes",
		"status",
		"warningCode",
		"reasonCode",
		"policyPreset",
		"endpointSummary",
	} {
		t.Run(name, func(t *testing.T) {
			if sandboxCoreRedactionUnsafeName(name) {
				t.Fatalf("guard rejected safe durable metadata name %q", name)
			}
		})
	}
}

func TestCoreRedactionGuardSandboxSanitizersDropUnsafeValues(t *testing.T) {
	for _, unsafeValue := range sandboxCoreRedactionUnsafeValues() {
		t.Run(unsafeValue, func(t *testing.T) {
			enforced := true
			payload := struct {
				CredentialDelivery SandboxCredentialDeliveryStatusMetadata        `json:"credentialDelivery"`
				CredentialPlan     SandboxCredentialProxyPlanMetadata             `json:"credentialPlan"`
				CredentialSession  SandboxCredentialProxySessionMetadata          `json:"credentialSession"`
				CredentialBinding  SandboxCredentialProxyBindingMetadata          `json:"credentialBinding"`
				NetworkSession     SandboxNetworkProxySessionMetadata             `json:"networkSession"`
				NetworkProof       SandboxNetworkEnforcementProofMetadata         `json:"networkProof"`
				DecisionLog        SandboxNetworkPolicyDecisionLogRecord          `json:"decisionLog"`
				Readiness          SandboxSecurityCapabilityReadinessInput        `json:"readiness"`
				ReadinessGate      SandboxSecurityCapabilityReadinessGateDecision `json:"readinessGate"`
			}{
				CredentialDelivery: SanitizeSandboxCredentialDeliveryStatusMetadata(SandboxCredentialDeliveryStatusMetadata{
					ID:             "delivery-status-01",
					RequestID:      unsafeValue,
					PlanID:         unsafeValue,
					ActivationID:   unsafeValue,
					RequestedModes: []string{SandboxSecretModeHTTPProxy, unsafeValue},
					ActiveModes:    []string{SandboxSecretModeHTTPProxy},
					Status:         "planned",
					ReasonCode:     "requested",
				}),
				CredentialPlan: SanitizeSandboxCredentialProxyPlanMetadata(SandboxCredentialProxyPlanMetadata{
					ID:                    "credential-plan-01",
					Source:                SandboxCredentialProxySourceRun,
					SecretBrokerSessionID: unsafeValue,
					NetworkProxySessionID: unsafeValue,
					PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
						ID:        unsafeValue,
						Version:   unsafeValue,
						RuleSetID: unsafeValue,
					},
					Mode:   SandboxCredentialProxyMode(unsafeValue),
					Status: SandboxCredentialProxyStatusPlanned,
				}),
				CredentialSession: SanitizeSandboxCredentialProxySessionMetadata(SandboxCredentialProxySessionMetadata{
					ID:                    "credential-session-01",
					PlanID:                "credential-plan-01",
					Source:                SandboxCredentialProxySourceRun,
					SecretBrokerSessionID: unsafeValue,
					NetworkProxySessionID: unsafeValue,
					PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
						ID:        unsafeValue,
						Version:   unsafeValue,
						RuleSetID: unsafeValue,
					},
					Status:      SandboxCredentialProxyStatusReady,
					WarningCode: SandboxCredentialProxyWarningCode(unsafeValue),
					ReasonCode:  SandboxCredentialProxyReasonRequested,
				}),
				CredentialBinding: SanitizeSandboxCredentialProxyBindingMetadata(SandboxCredentialProxyBindingMetadata{
					ID:                  "credential-binding-01",
					PlanID:              "credential-plan-01",
					SessionID:           unsafeValue,
					SecretID:            "env:GITHUB_TOKEN",
					DeliveryMode:        SandboxCredentialProxyDeliveryModeHTTPProxy,
					RequestCategory:     SandboxCredentialProxyRequestCategory(unsafeValue),
					DestinationCategory: SandboxNetworkPolicyDestinationPublicInternet,
					Outcome:             SandboxCredentialProxyBindingOutcomeBound,
					Status:              SandboxCredentialProxyStatusReady,
					ReasonCode:          SandboxCredentialProxyReasonRequested,
				}),
				NetworkSession: SanitizeSandboxNetworkProxySessionMetadata(SandboxNetworkProxySessionMetadata{
					ID:     "network-session-01",
					Source: SandboxNetworkPolicyDecisionSourceRun,
					PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
						ID:        unsafeValue,
						Version:   unsafeValue,
						RuleSetID: unsafeValue,
					},
					EnforcementMode: unsafeValue,
				}),
				NetworkProof: SanitizeSandboxNetworkEnforcementProofMetadata(SandboxNetworkEnforcementProofMetadata{
					NetworkProxySessionID:       unsafeValue,
					PolicySnapshotID:            unsafeValue,
					NetworkEnforcementPlanID:    unsafeValue,
					ProxyLifecycleStatus:        unsafeValue,
					ProxyLifecycleReasonCode:    unsafeValue,
					FirewallLifecycleStatus:     unsafeValue,
					FirewallLifecycleReasonCode: unsafeValue,
					ResultOutcome:               unsafeValue,
					ResultEnforcementMode:       unsafeValue,
					ResultSupported:             true,
				}),
				DecisionLog: SanitizeSandboxNetworkPolicyDecisionLogRecord(SandboxNetworkPolicyDecisionLogRecord{
					ID:             "decision-01",
					Source:         SandboxNetworkPolicyDecisionSourceRun,
					ProxySessionID: unsafeValue,
					PolicySnapshot: &SandboxNetworkPolicySnapshotIdentity{
						ID:        unsafeValue,
						Version:   unsafeValue,
						RuleSetID: unsafeValue,
					},
					Request: &SandboxNetworkPolicyRequestSummary{
						ID:                  unsafeValue,
						Operation:           unsafeValue,
						DestinationCategory: SandboxNetworkPolicyDestinationPublicInternet,
					},
					Outcome:         SandboxNetworkPolicyDecisionOutcomeAllowed,
					ReasonCode:      SandboxNetworkPolicyDecisionReasonDefaultAllow,
					RuleKind:        SandboxNetworkPolicyRuleKindDomain,
					PolicyPreset:    SandboxNetworkPolicyPresetDenyByDefault,
					EnforcementMode: unsafeValue,
					Enforced:        &enforced,
				}),
				Readiness: SanitizeSandboxSecurityCapabilityReadinessInput(SandboxSecurityCapabilityReadinessInput{
					Requested: []SandboxSecurityCapabilityMetadata{{
						ID:         unsafeValue,
						Family:     SandboxSecurityCapabilityFamilySecretDelivery,
						Capability: SandboxSecurityCapabilitySecretHTTPProxy,
						Mode:       unsafeValue,
						Source:     SandboxSecurityCapabilitySourceRequested,
					}},
					WorkerPostures: []SandboxSecurityCapabilityWorkerPostureMetadata{{
						WorkerKind:         unsafeValue,
						RuntimeDriver:      unsafeValue,
						IsolationLevel:     unsafeValue,
						NetworkPolicy:      unsafeValue,
						NetworkEnforcement: unsafeValue,
						CredentialModes:    []string{SandboxSecretModeHTTPProxy, unsafeValue},
					}},
				}),
				ReadinessGate: SandboxSecurityCapabilityReadinessGateDecision{
					Code:       SandboxSecurityCapabilityReadinessGateCodeBlocked,
					Outcome:    SandboxSecurityCapabilityReadinessGateOutcomeBlocked,
					PolicyMode: SandboxSecurityCapabilityReadinessGatePolicyModeStrict,
					Reason:     SandboxSecurityCapabilityReadinessGateReasonCapabilityUnsupported,
				},
			}
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			sandboxAssertCoreRedactionNoUnsafeValue(t, string(data), unsafeValue)
		})
	}
}

func sandboxCoreRedactionGuardTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(SandboxCredentialDeliveryStatusMetadata{}),
		reflect.TypeOf(SandboxCredentialProxyPlanMetadata{}),
		reflect.TypeOf(SandboxCredentialProxySessionMetadata{}),
		reflect.TypeOf(SandboxCredentialProxyBindingMetadata{}),
		reflect.TypeOf(SandboxNetworkPolicySnapshotIdentity{}),
		reflect.TypeOf(SandboxNetworkProxySessionMetadata{}),
		reflect.TypeOf(SandboxNetworkEnforcementProofMetadata{}),
		reflect.TypeOf(SandboxMicroVMIsolationProofMetadata{}),
		reflect.TypeOf(SandboxNetworkPolicyRequestSummary{}),
		reflect.TypeOf(SandboxNetworkPolicyDecisionLogRecord{}),
		reflect.TypeOf(SandboxNetworkProxyValidationError{}),
		reflect.TypeOf(SandboxNetworkProxyValidationResult{}),
		reflect.TypeOf(SandboxNetworkPolicyDecisionLogValidationError{}),
		reflect.TypeOf(SandboxNetworkPolicyDecisionLogValidationResult{}),
		reflect.TypeOf(SandboxSecretDeliveryIntent{}),
		reflect.TypeOf(SandboxSecretSecurity{}),
		reflect.TypeOf(SandboxSecurityCapabilityMetadata{}),
		reflect.TypeOf(SandboxSecurityCapabilityWorkerPostureMetadata{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessRequest{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessResult{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessOutput{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessGateCounts{}),
		reflect.TypeOf(SandboxSecurityCapabilityReadinessGateDecision{}),
	}
}

func sandboxAssertCoreRedactionSafeFieldName(t *testing.T, label string, name string) {
	t.Helper()
	if sandboxCoreRedactionUnsafeName(name) {
		t.Fatalf("%s exposes raw sandbox metadata field %q", label, name)
	}
}

func sandboxCoreRedactionUnsafeName(name string) bool {
	normalized := sandboxCoreRedactionNormalizeName(name)
	if normalized == "" {
		return false
	}
	for _, allowed := range []string{
		"id",
		"planid",
		"policysnapshotid",
		"rulesetid",
		"bindingid",
		"secretid",
		"secretbrokersessionid",
		"networkproxysessionid",
		"networkenforcementplanid",
		"proxysessionid",
		"credentialproxyplan",
		"credentialproxysession",
		"credentialproxybindings",
		"credentialproxyplanid",
		"credentialproxysessionid",
		"credentialproxybindingid",
		"credentialplanmetadata",
		"credentialsessionmetadata",
		"credentialbindingmetadata",
		"credentialmodes",
		"credentialproxymode",
		"deliverymode",
		"requestedmodes",
		"activemodes",
		"status",
		"state",
		"warningcode",
		"warningcodes",
		"reasoncode",
		"reason",
		"policyid",
		"policypreset",
		"policymode",
		"endpointsummary",
		"resultsupported",
		"unsupported",
	} {
		if normalized == allowed {
			return false
		}
	}
	for _, forbidden := range []string{
		"secretvalue",
		"secretvalues",
		"credentialvalue",
		"credentialvalues",
		"rawvalue",
		"payload",
		"body",
		"providermetadata",
		"providerpayload",
		"providercredential",
		"providercredentials",
		"endpoint",
		"address",
		"hostname",
		"port",
		"url",
		"uri",
		"localpath",
		"sourcepath",
		"storedpath",
		"workspacepath",
		"temppath",
		"socketpath",
		"socket",
		"environmentvalue",
		"environmentvalues",
		"envvalue",
		"envvalues",
		"rawenv",
		"rawenvironment",
		"header",
		"authorization",
		"token",
		"apikey",
		"bearer",
		"commandline",
		"command",
		"args",
		"argv",
		"rawcredential",
		"credentialmetadata",
		"credentialpayload",
	} {
		if strings.Contains(normalized, forbidden) {
			return true
		}
	}
	return false
}

func sandboxCoreRedactionJSONFieldName(field reflect.StructField) string {
	tag := field.Tag.Get("json")
	if tag == "" || tag == "-" {
		return ""
	}
	name := strings.Split(tag, ",")[0]
	if name == "-" {
		return ""
	}
	return name
}

func sandboxCoreRedactionNormalizeName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func sandboxCoreRedactionUnsafeValues() []string {
	return []string{
		"secretValue=plain-secret-123",
		"credentialValue=raw-credential-123",
		"providerMetadata=aws-account-prod",
		"https://user:secret@example.invalid/api?token=raw",
		"/Users/alice/.config/hal/secret.json",
		"/tmp/credential-proxy.sock",
		"OPENAI_API_KEY=sk-raw-secret",
		"Authorization: Bearer raw-token",
		"ghp_raw_token_123456",
		"git clone https://token@example.invalid/repo.git",
	}
}

func sandboxAssertCoreRedactionNoUnsafeValue(t *testing.T, payload string, unsafeValue string) {
	t.Helper()
	for _, forbidden := range []string{unsafeValue, sandboxCoreRedactionJSONEscapedStringFragment(t, unsafeValue)} {
		if forbidden != "" && strings.Contains(payload, forbidden) {
			t.Fatalf("durable sandbox metadata leaked unsafe value %q in %s", unsafeValue, payload)
		}
	}
}

func sandboxCoreRedactionJSONEscapedStringFragment(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%q) error = %v", value, err)
	}
	return strings.Trim(string(data), `"`)
}
