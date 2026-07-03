package factory

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestCoreRedactionGuardFactoryDurableCredentialFields(t *testing.T) {
	for _, typ := range factoryCoreRedactionGuardTypes() {
		t.Run(typ.Name(), func(t *testing.T) {
			for i := 0; i < typ.NumField(); i++ {
				field := typ.Field(i)
				if field.PkgPath != "" {
					continue
				}
				factoryAssertCoreRedactionSafeFieldName(t, typ.Name()+"."+field.Name, field.Name)
				if jsonName := factoryCoreRedactionJSONFieldName(field); jsonName != "" {
					factoryAssertCoreRedactionSafeFieldName(t, typ.Name()+"."+field.Name+" json", jsonName)
				}
			}
		})
	}
}

func TestCoreRedactionGuardFactorySandboxCredentialMetadataFields(t *testing.T) {
	typ := reflect.TypeOf(SandboxMetadata{})
	for _, fieldName := range []string{
		"Security",
		"NetworkProxySession",
		"CredentialProxyPlan",
		"CredentialProxySession",
		"CredentialProxyBindings",
		"CredentialDelivery",
	} {
		field, ok := typ.FieldByName(fieldName)
		if !ok {
			t.Fatalf("SandboxMetadata missing expected credential metadata field %s", fieldName)
		}
		factoryAssertCoreRedactionSafeFieldName(t, "SandboxMetadata."+field.Name, field.Name)
		if jsonName := factoryCoreRedactionJSONFieldName(field); jsonName != "" {
			factoryAssertCoreRedactionSafeFieldName(t, "SandboxMetadata."+field.Name+" json", jsonName)
		}
	}
}

func TestCoreRedactionGuardFactoryRejectsRequiredRawFieldCategories(t *testing.T) {
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
			if !factoryCoreRedactionUnsafeName(name) {
				t.Fatalf("guard did not reject %q for %s", name, category)
			}
		})
	}
}

func TestCoreRedactionGuardFactoryAllowsSafeMetadataNames(t *testing.T) {
	for _, name := range []string{
		"ID",
		"name",
		"source",
		"required",
		"present",
		"planId",
		"bindingId",
		"secretId",
		"deliveryMode",
		"requestedModes",
		"activeModes",
		"status",
		"warningCode",
		"reasonCode",
		"policyId",
		"credentialDelivery",
	} {
		t.Run(name, func(t *testing.T) {
			if factoryCoreRedactionUnsafeName(name) {
				t.Fatalf("guard rejected safe durable metadata name %q", name)
			}
		})
	}
}

func TestCoreRedactionGuardFactorySecretBrokerMetadataDropsRawValues(t *testing.T) {
	for _, unsafeValue := range factoryCoreRedactionUnsafeValues() {
		t.Run(unsafeValue, func(t *testing.T) {
			broker := NewInMemorySecretBroker()
			session, err := broker.CreateSession(SecretBrokerSessionRequest{
				ID: "secret-broker-session-01",
				RequestedInputs: []RunSecretInput{{
					Name:     "OPTIONAL_SECRET",
					Source:   RunSecretSourceEnv,
					Required: false,
				}},
				ResolvedSecrets: []ResolvedRunSecret{{
					Name:     "GITHUB_TOKEN",
					Source:   RunSecretSourceEnv,
					Required: true,
					Value:    unsafeValue,
				}},
				RequestedDeliveryModes: []string{SecretBrokerDeliveryModeHTTPProxy},
				ActiveDeliveryModes:    []string{SecretBrokerDeliveryModeHTTPProxy},
			})
			if err != nil {
				t.Fatalf("CreateSession() error = %v", err)
			}

			networkSession := sandbox.SanitizeSandboxNetworkProxySessionMetadata(sandbox.SandboxNetworkProxySessionMetadata{
				ID:     "network-session-01",
				Source: sandbox.SandboxNetworkPolicyDecisionSourceFactory,
				PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
					ID:        unsafeValue,
					Version:   unsafeValue,
					RuleSetID: unsafeValue,
				},
				EnforcementMode: unsafeValue,
			})
			projection := ProjectCredentialProxyMetadata(CredentialProxyProjectionRequest{
				PlanID:              "credential-plan-01",
				SessionID:           "credential-session-01",
				BindingIDPrefix:     "credential-binding",
				Source:              sandbox.SandboxCredentialProxySourceFactory,
				SecretBrokerSession: &session,
				NetworkProxySession: &networkSession,
				RequestCategory:     sandbox.SandboxCredentialProxyRequestNetworkAuth,
				DestinationCategory: sandbox.SandboxNetworkPolicyDestinationPublicInternet,
			})
			credentialDelivery := sandbox.ProjectSandboxCredentialDeliveryStatusMetadata(sandbox.SandboxCredentialDeliveryStatusProjectionRequest{
				Plan:           projection.Plan,
				Bindings:       projection.Bindings,
				RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
			})
			payload := struct {
				Session            SecretBrokerSessionMetadata                      `json:"session"`
				RunSecrets         []RunSecretMetadata                              `json:"runSecrets"`
				DeliveryModes      *SecretBrokerDeliveryModeMetadata                `json:"deliveryModes,omitempty"`
				SandboxSecretModes SandboxSecretSecurityMetadata                    `json:"sandboxSecretModes"`
				SandboxCredential  *sandbox.SandboxCredentialDeliveryStatusMetadata `json:"sandboxCredential,omitempty"`
				CredentialProxy    sandbox.SandboxCredentialProxyProjection         `json:"credentialProxy"`
			}{
				Session:            session,
				RunSecrets:         []RunSecretMetadata{session.Secrets[0].RunSecretMetadata()},
				DeliveryModes:      session.DeliveryModes,
				SandboxSecretModes: SandboxSecretSecurityMetadata{RequestedModes: []string{SecretBrokerDeliveryModeHTTPProxy}, ActiveModes: []string{SecretBrokerDeliveryModeHTTPProxy}},
				SandboxCredential:  credentialDelivery,
				CredentialProxy:    projection,
			}
			data, err := json.Marshal(payload)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			factoryAssertCoreRedactionNoUnsafeValue(t, string(data), unsafeValue)
		})
	}
}

func factoryCoreRedactionGuardTypes() []reflect.Type {
	return []reflect.Type{
		reflect.TypeOf(RunSecretInput{}),
		reflect.TypeOf(RunSecretMetadata{}),
		reflect.TypeOf(SecretBrokerSessionMetadata{}),
		reflect.TypeOf(SecretBrokerSecretMetadata{}),
		reflect.TypeOf(SecretBrokerDeliveryModeMetadata{}),
		reflect.TypeOf(SandboxNetworkSecurityMetadata{}),
		reflect.TypeOf(SandboxSecretSecurityMetadata{}),
		reflect.TypeOf(SandboxSecurityMetadata{}),
		reflect.TypeOf(PolicyDecisionMetadata{}),
	}
}

func factoryAssertCoreRedactionSafeFieldName(t *testing.T, label string, name string) {
	t.Helper()
	if factoryCoreRedactionUnsafeName(name) {
		t.Fatalf("%s exposes raw factory credential metadata field %q", label, name)
	}
}

func factoryCoreRedactionUnsafeName(name string) bool {
	normalized := factoryCoreRedactionNormalizeName(name)
	if normalized == "" {
		return false
	}
	for _, allowed := range []string{
		"id",
		"name",
		"source",
		"required",
		"present",
		"planid",
		"bindingid",
		"secretid",
		"secretbrokersessionid",
		"networkproxysessionid",
		"credentialproxyplan",
		"credentialproxysession",
		"credentialproxybindings",
		"credentialdelivery",
		"deliverymodes",
		"deliverymode",
		"requestedmodes",
		"activemodes",
		"security",
		"status",
		"warningcode",
		"warningcodes",
		"reasoncode",
		"reason",
		"policyid",
		"policymode",
		"policyfield",
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

func factoryCoreRedactionJSONFieldName(field reflect.StructField) string {
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

func factoryCoreRedactionNormalizeName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func factoryCoreRedactionUnsafeValues() []string {
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

func factoryAssertCoreRedactionNoUnsafeValue(t *testing.T, payload string, unsafeValue string) {
	t.Helper()
	for _, forbidden := range []string{unsafeValue, factoryCoreRedactionJSONEscapedStringFragment(t, unsafeValue)} {
		if forbidden != "" && strings.Contains(payload, forbidden) {
			t.Fatalf("durable factory credential metadata leaked unsafe value %q in %s", unsafeValue, payload)
		}
	}
}

func factoryCoreRedactionJSONEscapedStringFragment(t *testing.T, value string) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%q) error = %v", value, err)
	}
	return strings.Trim(string(data), `"`)
}
