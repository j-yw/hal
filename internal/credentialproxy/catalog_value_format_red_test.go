package credentialproxy

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestL8CredentialProxyCatalogValueFormsDenyLiveInspection(t *testing.T) {
	forms := []struct {
		name string
		make func(*StaticServiceCatalog) any
	}{
		{name: "pointer", make: func(catalog *StaticServiceCatalog) any { return catalog }},
		{name: "value", make: func(catalog *StaticServiceCatalog) any { return *catalog }},
		{name: "pointer interface", make: func(catalog *StaticServiceCatalog) any { var value any = catalog; return value }},
		{name: "value interface", make: func(catalog *StaticServiceCatalog) any { var value any = *catalog; return value }},
	}
	for _, tt := range forms {
		t.Run(tt.name, func(t *testing.T) {
			catalog, err := NewStaticServiceCatalog(
				"raw-catalog-secret",
				CatalogOwnerHostAdmin,
				l8FixtureAzureDefinition(t),
			)
			if err != nil {
				t.Fatalf("NewStaticServiceCatalog() error = %v", err)
			}
			assertCredentialProxyCatalogFormDenied(t, tt.make(catalog))
		})
	}
}

func assertCredentialProxyCatalogFormDenied(t *testing.T, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if len(payload) != 0 || !errors.Is(err, ErrLiveCatalogStateNotSerializable) {
		t.Errorf("json.Marshal(%T) = %q, %v, want stable live-state denial", value, payload, err)
	}
	if marshaler, ok := value.(json.Marshaler); !ok {
		t.Errorf("%T does not implement json.Marshaler", value)
	} else if payload, marshalErr := marshaler.MarshalJSON(); len(payload) != 0 || marshalErr != ErrLiveCatalogStateNotSerializable {
		t.Errorf("MarshalJSON(%T) = %q, %v, want stable live-state denial", value, payload, marshalErr)
	}
	if marshaler, ok := value.(encoding.TextMarshaler); !ok {
		t.Errorf("%T does not implement encoding.TextMarshaler", value)
	} else if payload, marshalErr := marshaler.MarshalText(); len(payload) != 0 || marshalErr != ErrLiveCatalogStateNotSerializable {
		t.Errorf("MarshalText(%T) = %q, %v, want stable live-state denial", value, payload, marshalErr)
	}
	if errorValue, ok := value.(error); !ok {
		t.Errorf("%T does not implement safe error rendering", value)
	} else {
		assertCredentialProxyCatalogTextOmitsSealedValues(t, errorValue.Error())
	}
	if stringer, ok := value.(fmt.Stringer); !ok {
		t.Errorf("%T does not implement fmt.Stringer", value)
	} else {
		assertCredentialProxyCatalogTextOmitsSealedValues(t, stringer.String())
	}
	if stringer, ok := value.(fmt.GoStringer); !ok {
		t.Errorf("%T does not implement fmt.GoStringer", value)
	} else {
		assertCredentialProxyCatalogTextOmitsSealedValues(t, stringer.GoString())
	}
	if _, ok := value.(fmt.Formatter); !ok {
		t.Errorf("%T does not implement safe fmt.Formatter rendering", value)
	}
	for _, format := range credentialProxyCatalogPoisonFormats() {
		rendered := fmt.Sprintf(format, value)
		assertCredentialProxyCatalogTextOmitsSealedValues(t, rendered)
		if strings.Contains(rendered, "raw-catalog-secret") {
			t.Errorf("fmt.Sprintf(%q, %T) traversed poison catalog state: %q", format, value, rendered)
		}
		if want := "credentialproxy.StaticServiceCatalog{sealed:true}"; rendered != want {
			t.Errorf("fmt.Sprintf(%q, %T) = %q, want %q", format, value, rendered, want)
		}
	}
}

func TestL8CredentialProxyCatalogNilPointerFormattingStaysSafe(t *testing.T) {
	var pointer *StaticServiceCatalog
	forms := []struct {
		name  string
		value any
	}{
		{name: "pointer", value: pointer},
		{name: "pointer interface", value: any(pointer)},
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			for _, format := range credentialProxyCatalogPoisonFormats() {
				if got := fmt.Sprintf(format, form.value); got != "<nil>" {
					t.Errorf("fmt.Sprintf(%q, nil *StaticServiceCatalog) = %q, want safe nil rendering", format, got)
				}
			}
		})
	}
}

func TestL8CredentialProxySealedValuesUseFixedAllVerbFormatting(t *testing.T) {
	tlsPolicy := SealedTLSPolicy{
		serverName: "sealed-tls-name.private.example.test",
		rootPolicy: TLSRootPolicy("sealed-root-policy"),
		alpn:       []string{"sealed-alpn"},
	}
	invocationPolicy := SealedInvocationPolicy{
		provider:                 "sealed-provider",
		model:                    "sealed-model",
		arguments:                []string{"--model", "sealed-deployment"},
		environmentPolicy:        EnvironmentPolicy("sealed-environment-policy"),
		transientEnvironmentKeys: []string{"SEALED_TRANSIENT_ENV"},
		clearedEnvironmentKeys:   []string{"SEALED_CLEARED_ENV"},
	}
	definition := ServiceDefinition{
		serviceID:  ServiceIDAzureOpenAIResponsesV1,
		authority:  "sealed-authority.private.example.test",
		tls:        tlsPolicy,
		deployment: "sealed-deployment",
		apiVersion: "sealed-api-version",
		consumer:   invocationPolicy,
	}

	tests := []struct {
		name  string
		value any
		want  string
	}{
		{name: "service definition value", value: definition, want: "credentialproxy.ServiceDefinition{serviceId:azure-openai-responses-v1,sealed:true}"},
		{name: "service definition pointer", value: &definition, want: "credentialproxy.ServiceDefinition{serviceId:azure-openai-responses-v1,sealed:true}"},
		{name: "service definition value interface", value: any(definition), want: "credentialproxy.ServiceDefinition{serviceId:azure-openai-responses-v1,sealed:true}"},
		{name: "service definition pointer interface", value: any(&definition), want: "credentialproxy.ServiceDefinition{serviceId:azure-openai-responses-v1,sealed:true}"},
		{name: "TLS policy value", value: tlsPolicy, want: "credentialproxy.SealedTLSPolicy{sealed:true}"},
		{name: "TLS policy pointer", value: &tlsPolicy, want: "credentialproxy.SealedTLSPolicy{sealed:true}"},
		{name: "TLS policy value interface", value: any(tlsPolicy), want: "credentialproxy.SealedTLSPolicy{sealed:true}"},
		{name: "TLS policy pointer interface", value: any(&tlsPolicy), want: "credentialproxy.SealedTLSPolicy{sealed:true}"},
		{name: "invocation policy value", value: invocationPolicy, want: "credentialproxy.SealedInvocationPolicy{sealed:true}"},
		{name: "invocation policy pointer", value: &invocationPolicy, want: "credentialproxy.SealedInvocationPolicy{sealed:true}"},
		{name: "invocation policy value interface", value: any(invocationPolicy), want: "credentialproxy.SealedInvocationPolicy{sealed:true}"},
		{name: "invocation policy pointer interface", value: any(&invocationPolicy), want: "credentialproxy.SealedInvocationPolicy{sealed:true}"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := tt.value.(fmt.Formatter); !ok {
				t.Errorf("%T does not implement safe fmt.Formatter rendering", tt.value)
			}
			for _, format := range credentialProxyCatalogPoisonFormats() {
				rendered := fmt.Sprintf(format, tt.value)
				assertCredentialProxyCatalogTextOmitsSealedValues(t, rendered)
				if rendered != tt.want {
					t.Errorf("fmt.Sprintf(%q, %T) = %q, want %q", format, tt.value, rendered, tt.want)
				}
			}
		})
	}
}

func TestL8CredentialProxySealedValueNilPointerFormattingStaysSafe(t *testing.T) {
	var definition *ServiceDefinition
	var tlsPolicy *SealedTLSPolicy
	var invocationPolicy *SealedInvocationPolicy
	forms := []struct {
		name  string
		value any
	}{
		{name: "service definition pointer", value: definition},
		{name: "service definition pointer interface", value: any(definition)},
		{name: "TLS policy pointer", value: tlsPolicy},
		{name: "TLS policy pointer interface", value: any(tlsPolicy)},
		{name: "invocation policy pointer", value: invocationPolicy},
		{name: "invocation policy pointer interface", value: any(invocationPolicy)},
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			for _, format := range credentialProxyCatalogPoisonFormats() {
				if got := fmt.Sprintf(format, form.value); got != "<nil>" {
					t.Errorf("fmt.Sprintf(%q, %T) = %q, want safe nil rendering", format, form.value, got)
				}
			}
		})
	}
}

func credentialProxyCatalogPoisonFormats() []string {
	return []string{
		"%t", "%b", "%c", "%d", "%o", "%O", "%U",
		"%e", "%E", "%f", "%F", "%g", "%G", "%x", "%X",
		"%s", "%q", "%v", "%+v", "%#v",
		"%+d", "%#d", "% d", "%-20d", "%020d", "%.8d", "%[1]d",
	}
}
