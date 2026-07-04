package credentialdelivery

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestCoreRedactionGuardCredentialDeliveryDurableFields(t *testing.T) {
	for _, typ := range credentialDeliveryCoreRedactionGuardTypes() {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.PkgPath != "" {
					continue
				}
				credentialDeliveryAssertCoreRedactionSafeFieldName(t, typ.Name()+"."+field.Name, field.Name)
				if jsonName := credentialDeliveryJSONFieldName(field); jsonName != "" {
					credentialDeliveryAssertCoreRedactionSafeFieldName(t, typ.Name()+"."+field.Name+" json", jsonName)
				}
			}
		})
	}
}

func TestCoreRedactionGuardCredentialDeliveryRejectsRequiredRawFieldCategories(t *testing.T) {
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
			if !credentialDeliveryCoreRedactionUnsafeName(name) {
				t.Fatalf("guard did not reject %q for %s", name, category)
			}
		})
	}
}

func TestCoreRedactionGuardCredentialDeliveryAllowsSafeMetadataNames(t *testing.T) {
	for _, name := range []string{
		"ID",
		"requestId",
		"planId",
		"policySnapshotId",
		"bindingId",
		"secretRef",
		"secretId",
		"deliveryMode",
		"requestedModes",
		"activeModes",
		"status",
		"warningCode",
		"reasonCode",
		"errorCount",
	} {
		t.Run(name, func(t *testing.T) {
			if credentialDeliveryCoreRedactionUnsafeName(name) {
				t.Fatalf("guard rejected safe durable metadata name %q", name)
			}
		})
	}
}

func TestCoreRedactionGuardCredentialDeliverySanitizersDropUnsafeValues(t *testing.T) {
	for _, unsafeValue := range credentialDeliveryCoreRedactionUnsafeValues() {
		t.Run(unsafeValue, func(t *testing.T) {
			payload := struct {
				Request Request          `json:"request"`
				Plan    Plan             `json:"plan"`
				Status  StatusMetadata   `json:"status"`
				Result  ActivationResult `json:"result"`
			}{
				Request: SanitizeRequestMetadata(Request{
					ID:             "delivery-request-01",
					Source:         SourceRun,
					RequestedModes: []Mode{ModeHTTPProxy, Mode(unsafeValue)},
					ActiveModes:    []Mode{ModeHTTPProxy},
					Bindings: []Binding{{
						ID:                    "delivery-binding-01",
						RequestID:             unsafeValue,
						PlanID:                "delivery-plan-01",
						PolicySnapshotID:      unsafeValue,
						SecretRef:             "env:GITHUB_TOKEN",
						NetworkProxySessionID: unsafeValue,
						ServiceID:             unsafeValue,
						ServiceLabels:         []string{"github", unsafeValue},
						DomainLabels:          []string{"source-control", unsafeValue},
						DestinationCategory:   DestinationPublicInternet,
						DeliveryMode:          ModeHTTPProxy,
						Status:                StatusPlanned,
						ReasonCode:            ReasonRequested,
					}},
					Status: StatusRequested,
				}),
				Plan: SanitizePlanMetadata(Plan{
					ID:                    "delivery-plan-01",
					RequestID:             unsafeValue,
					NetworkProxySessionID: unsafeValue,
					HTTPProxyProof: &HTTPProxyProof{
						BindingID:                unsafeValue,
						SecretID:                 unsafeValue,
						SecretBrokerSessionID:    unsafeValue,
						CredentialProxyPlanID:    unsafeValue,
						CredentialProxySessionID: unsafeValue,
						CredentialProxyBindingID: unsafeValue,
					},
					RequestedModes: []Mode{ModeHTTPProxy, Mode(unsafeValue)},
					ActiveModes:    []Mode{ModeHTTPProxy},
					Status:         StatusPlanned,
					Warnings: []Warning{{
						Code:       WarningAdapterUnavailable,
						BindingID:  unsafeValue,
						ReasonCode: ReasonActivationUnavailable,
					}},
					Errors: []SanitizedError{{
						Code:       ErrorUnsafeMetadata,
						Field:      unsafeValue,
						BindingID:  unsafeValue,
						ReasonCode: ReasonActivationUnavailable,
					}},
				}),
				Status: SanitizeStatusMetadata(StatusMetadata{
					ID:             "delivery-status-01",
					RequestID:      unsafeValue,
					PlanID:         unsafeValue,
					ActivationID:   unsafeValue,
					RequestedModes: []Mode{ModeHTTPProxy, Mode(unsafeValue)},
					Status:         StatusPlanned,
					ReasonCode:     ReasonRequested,
				}),
				Result: SanitizeActivationResultMetadata(ActivationResult{
					ID:             "delivery-activation-01",
					PlanID:         "delivery-plan-01",
					RequestedModes: []Mode{ModeHTTPProxy, Mode(unsafeValue)},
					ActiveModes:    []Mode{ModeHTTPProxy},
					Bindings: []BindingActivationResult{{
						BindingID:    unsafeValue,
						DeliveryMode: ModeHTTPProxy,
						Status:       StatusActive,
						ReasonCode:   ReasonRequested,
						ProofRef:     unsafeValue,
					}},
					ProofRefs: []ActivationProofReference{{
						ProofID:      unsafeValue,
						BindingID:    unsafeValue,
						DeliveryMode: ModeHTTPProxy,
					}},
					Status:     StatusActive,
					ReasonCode: ReasonRequested,
				}),
			}
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			credentialDeliveryAssertCoreRedactionNoUnsafeValue(t, string(data), unsafeValue)
		})
	}
}

func credentialDeliveryCoreRedactionGuardTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(Request{}),
		reflect.TypeOf(Binding{}),
		reflect.TypeOf(SecretReference{}),
		reflect.TypeOf(BrokerSecretMetadata{}),
		reflect.TypeOf(ResolvedBindingSecretMetadata{}),
		reflect.TypeOf(SecretResolutionResult{}),
		reflect.TypeOf(Plan{}),
		reflect.TypeOf(HTTPProxyProof{}),
		reflect.TypeOf(ActivationRequest{}),
		reflect.TypeOf(ActivationResult{}),
		reflect.TypeOf(BindingActivationResult{}),
		reflect.TypeOf(ActivationProofReference{}),
		reflect.TypeOf(StatusMetadata{}),
		reflect.TypeOf(Warning{}),
		reflect.TypeOf(SanitizedError{}),
		reflect.TypeOf(ValidationResult{}),
	}
}

func credentialDeliveryAssertCoreRedactionSafeFieldName(t *testing.T, label string, name string) {
	t.Helper()
	if credentialDeliveryCoreRedactionUnsafeName(name) {
		t.Fatalf("%s exposes raw credential delivery metadata field %q", label, name)
	}
}

func credentialDeliveryCoreRedactionUnsafeName(name string) bool {
	normalized := credentialDeliveryCoreRedactionNormalizeName(name)
	if normalized == "" {
		return false
	}
	for _, allowed := range []string{
		"id",
		"requestid",
		"planid",
		"policysnapshotid",
		"bindingid",
		"secretref",
		"secretid",
		"secretbrokersessionid",
		"credentialproxyplanid",
		"credentialproxysessionid",
		"credentialproxybindingid",
		"networkproxysessionid",
		"networkenforcementplanid",
		"deliverymode",
		"requestedmodes",
		"activemodes",
		"status",
		"warningcode",
		"proofid",
		"proofref",
		"reasoncode",
		"errorcount",
		"warningcount",
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

func credentialDeliveryJSONFieldName(field reflect.StructField) string {
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

func credentialDeliveryCoreRedactionNormalizeName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func credentialDeliveryCoreRedactionUnsafeValues() []string {
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

func credentialDeliveryAssertCoreRedactionNoUnsafeValue(t *testing.T, payload string, unsafeValue string) {
	t.Helper()
	for _, forbidden := range []string{unsafeValue, credentialDeliveryCoreRedactionJSONEscapedStringFragment(t, unsafeValue)} {
		if forbidden != "" && strings.Contains(payload, forbidden) {
			t.Fatalf("durable credential delivery metadata leaked unsafe value %q in %s", unsafeValue, payload)
		}
	}
}

func credentialDeliveryCoreRedactionJSONEscapedStringFragment(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%q) error = %v", value, err)
	}
	return strings.Trim(string(data), `"`)
}
