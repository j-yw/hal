package credentialproxy

import (
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestL8CredentialProxyInitialCatalogLocksAzureResponsesPolicy(t *testing.T) {
	definition := l8FixtureAzureDefinition(t)

	if got, want := string(definition.ServiceID()), "azure-openai-responses-v1"; got != want {
		t.Fatalf("ServiceID() = %q, want %q", got, want)
	}
	if definition.SealedAuthority() != l8FixtureAuthority || definition.SealedPort() != 443 {
		t.Fatalf("sealed authority = %q:%d, want fixture host-owned authority on 443", definition.SealedAuthority(), definition.SealedPort())
	}
	tlsPolicy := definition.SealedTLS()
	if tlsPolicy.ServerName() != l8FixtureTLSServerName || tlsPolicy.RootPolicy() != TLSRootPolicySystem {
		t.Fatalf("TLS policy server/root = %q/%q, want sealed server name and system roots", tlsPolicy.ServerName(), tlsPolicy.RootPolicy())
	}
	if got, want := tlsPolicy.ALPN(), []string{"http/1.1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("TLS ALPN = %#v, want %#v", got, want)
	}
	if definition.SealedDeployment() != l8FixtureDeployment || definition.SealedAPIVersion() != l8FixtureAPIVersion {
		t.Fatalf("deployment/version = %q/%q, want sealed fixture values", definition.SealedDeployment(), definition.SealedAPIVersion())
	}
	if got, want := definition.AllowedMethods(), []string{"POST"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("AllowedMethods() = %#v, want %#v", got, want)
	}
	if got, want := definition.LocalPathTemplate(), "/.well-known/hal/credential-http/v1/azure-openai-responses-v1/deployments/{deployment}/responses"; got != want {
		t.Fatalf("LocalPathTemplate() = %q, want %q", got, want)
	}
	if got, want := definition.UpstreamPathTemplate(), "/openai/deployments/{deployment}/responses"; got != want {
		t.Fatalf("UpstreamPathTemplate() = %q, want %q", got, want)
	}
	if definition.QueryKey() != "api-version" || definition.TicketHeader() != "api-key" || definition.UpstreamAuthenticationHeader() != "api-key" {
		t.Fatalf("query/auth transform = %q/%q/%q, want exact api-version and api-key mapping", definition.QueryKey(), definition.TicketHeader(), definition.UpstreamAuthenticationHeader())
	}
	if definition.AuthenticationTransform() != AuthenticationTransformReplaceTicket {
		t.Fatalf("AuthenticationTransform() = %q, want replace-ticket", definition.AuthenticationTransform())
	}
	if got, want := definition.RequestContentTypes(), []string{"application/json"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("RequestContentTypes() = %#v, want %#v", got, want)
	}
	if got, want := definition.ResponseContentTypes(), []string{"application/json", "text/event-stream"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ResponseContentTypes() = %#v, want %#v", got, want)
	}
	if definition.RedirectPolicy() != RedirectPolicyDisabled {
		t.Fatalf("RedirectPolicy() = %q, want disabled", definition.RedirectPolicy())
	}

	wantLimits := ServiceLimits{
		MaxRequestHeaderBytes:    32 << 10,
		MaxRequestBodyBytes:      16 << 20,
		MaxResponseHeaderBytes:   32 << 10,
		MaxResponseBodyBytes:     64 << 20,
		MaxSSEEventBytes:         2 << 20,
		ReadIdleTimeout:          5 * time.Minute,
		MaxRequestsPerConnection: 1,
		MaxRetries:               0,
	}
	if got := definition.Limits(); !reflect.DeepEqual(got, wantLimits) {
		t.Fatalf("Limits() = %#v, want %#v", got, wantLimits)
	}
	if err := ValidateServiceDefinition(definition); err != nil {
		t.Fatalf("ValidateServiceDefinition() error = %v", err)
	}
}

func TestL8CredentialProxyCatalogIsHostOwnedImmutableAndDeterministic(t *testing.T) {
	definition := l8FixtureAzureDefinition(t)
	catalog, err := NewStaticServiceCatalog(" catalog-generation-01 ", CatalogOwnerHostAdmin, definition)
	if err != nil {
		t.Fatalf("NewStaticServiceCatalog() error = %v", err)
	}
	if got, want := catalog.Generation(), "catalog-generation-01"; got != want {
		t.Fatalf("Generation() = %q, want %q", got, want)
	}
	if got, want := catalog.ServiceIDs(), []ServiceID{ServiceIDAzureOpenAIResponsesV1}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ServiceIDs() = %#v, want %#v", got, want)
	}

	// Caller mutations to a definition and all accessor-returned slices cannot
	// mutate the host-owned generation snapshot.
	definition.authority = l8FixtureReplacementAuthority
	definition.methods[0] = "DELETE"
	definition.tls.alpn[0] = "h2"
	got, err := catalog.Lookup(ServiceIDAzureOpenAIResponsesV1)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	if got.SealedAuthority() != l8FixtureAuthority || !reflect.DeepEqual(got.AllowedMethods(), []string{"POST"}) || !reflect.DeepEqual(got.SealedTLS().ALPN(), []string{"http/1.1"}) {
		t.Fatalf("Lookup() returned mutable construction state")
	}
	methods := got.AllowedMethods()
	methods[0] = "PATCH"
	alpn := got.SealedTLS().ALPN()
	alpn[0] = "h2"
	again, err := catalog.Lookup(ServiceIDAzureOpenAIResponsesV1)
	if err != nil {
		t.Fatalf("second Lookup() error = %v", err)
	}
	if again.SealedAuthority() != l8FixtureAuthority || !reflect.DeepEqual(again.AllowedMethods(), []string{"POST"}) || !reflect.DeepEqual(again.SealedTLS().ALPN(), []string{"http/1.1"}) {
		t.Fatalf("second Lookup() returned caller-mutated state")
	}

	ids := catalog.ServiceIDs()
	ids[0] = ServiceID("mutated")
	if got := catalog.ServiceIDs(); !reflect.DeepEqual(got, []ServiceID{ServiceIDAzureOpenAIResponsesV1}) {
		t.Fatalf("ServiceIDs() after caller mutation = %#v", got)
	}
}

func TestL8CredentialProxyCatalogHasNoProjectOverrideSurface(t *testing.T) {
	definition := l8FixtureAzureDefinition(t)
	for _, owner := range []CatalogOwner{"", CatalogOwner("project"), CatalogOwner("template"), CatalogOwner("request")} {
		catalog, err := NewStaticServiceCatalog("catalog-generation-01", owner, definition)
		if !errors.Is(err, ErrCatalogOwnerRequired) {
			t.Fatalf("NewStaticServiceCatalog(owner=%q) error = %v, want ErrCatalogOwnerRequired", owner, err)
		}
		if catalog != nil {
			t.Fatalf("NewStaticServiceCatalog(owner=%q) catalog = %#v, want nil", owner, catalog)
		}
		assertCredentialProxyCatalogErrorSafe(t, err)
	}

	production := credentialProxyCatalogProductionSource(t)
	for _, forbidden := range []string{
		"ProjectOverrides",
		"ProjectOverride",
		"ServiceOverride",
		"CatalogOwnerProject",
		"TemplateOverride",
		"RequestOverride",
	} {
		if strings.Contains(production, forbidden) {
			t.Fatalf("catalog production source contains forbidden override surface %q", forbidden)
		}
	}
}

func TestL8CredentialProxyCatalogRejectsCollisionsAndUnknownServices(t *testing.T) {
	definition := l8FixtureAzureDefinition(t)
	for _, tt := range []struct {
		name       string
		generation string
		services   []ServiceDefinition
		want       error
	}{
		{name: "missing generation", services: []ServiceDefinition{definition}, want: ErrCatalogGenerationRequired},
		{name: "empty catalog", generation: "catalog-generation-01", want: ErrCatalogEmpty},
	} {
		t.Run(tt.name, func(t *testing.T) {
			catalog, err := NewStaticServiceCatalog(tt.generation, CatalogOwnerHostAdmin, tt.services...)
			if !errors.Is(err, tt.want) {
				t.Fatalf("NewStaticServiceCatalog() error = %v, want %v", err, tt.want)
			}
			if catalog != nil {
				t.Fatalf("NewStaticServiceCatalog() catalog = %#v, want nil", catalog)
			}
			assertCredentialProxyCatalogErrorSafe(t, err)
		})
	}

	catalog, err := NewStaticServiceCatalog("catalog-generation-01", CatalogOwnerHostAdmin, definition, definition)
	if !errors.Is(err, ErrServiceCollision) {
		t.Fatalf("NewStaticServiceCatalog(duplicate) error = %v, want ErrServiceCollision", err)
	}
	if catalog != nil {
		t.Fatalf("NewStaticServiceCatalog(duplicate) catalog = %#v, want nil", catalog)
	}
	assertCredentialProxyCatalogErrorSafe(t, err)

	catalog, err = NewStaticServiceCatalog("catalog-generation-01", CatalogOwnerHostAdmin, definition)
	if err != nil {
		t.Fatalf("NewStaticServiceCatalog() error = %v", err)
	}
	if _, err := catalog.Lookup(ServiceID("unknown")); !errors.Is(err, ErrServiceUnknown) {
		t.Fatalf("Lookup(unknown) error = %v, want ErrServiceUnknown", err)
	}
	if _, err := catalog.SafeReference(ServiceID("unknown")); !errors.Is(err, ErrServiceUnknown) {
		t.Fatalf("SafeReference(unknown) error = %v, want ErrServiceUnknown", err)
	}
}

func TestL8CredentialProxyCatalogNormalizationValidationAndSanitizedErrors(t *testing.T) {
	definition, err := NewAzureOpenAIResponsesV1Definition(
		"  "+strings.ToUpper(l8FixtureAuthority)+"  ",
		443,
		"  "+strings.ToUpper(l8FixtureTLSServerName)+"  ",
		TLSRootPolicySystem,
		"  "+l8FixtureDeployment+"  ",
		"  "+l8FixtureAPIVersion+"  ",
	)
	if err != nil {
		t.Fatalf("NewAzureOpenAIResponsesV1Definition() error = %v", err)
	}
	if definition.SealedAuthority() != l8FixtureAuthority || definition.SealedTLS().ServerName() != l8FixtureTLSServerName {
		t.Fatalf("normalized authority/TLS = %q/%q", definition.SealedAuthority(), definition.SealedTLS().ServerName())
	}
	if definition.SealedDeployment() != l8FixtureDeployment || definition.SealedAPIVersion() != l8FixtureAPIVersion {
		t.Fatalf("normalized deployment/version = %q/%q", definition.SealedDeployment(), definition.SealedAPIVersion())
	}

	unsafe := definition
	unsafe.authority = l8FixtureUnsafeAuthority
	err = ValidateServiceDefinition(unsafe)
	if !errors.Is(err, ErrInvalidServiceDefinition) {
		t.Fatalf("ValidateServiceDefinition() error = %v, want ErrInvalidServiceDefinition", err)
	}
	assertCredentialProxyCatalogErrorSafe(t, err)
}

func TestL8CredentialProxyCatalogValidationRejectsPolicyWeakening(t *testing.T) {
	valid := l8FixtureAzureDefinition(t)
	tests := []struct {
		name   string
		mutate func(*ServiceDefinition)
	}{
		{name: "authority contains scheme", mutate: func(got *ServiceDefinition) { got.authority = l8FixtureUnsafeAuthority }},
		{name: "missing TLS name", mutate: func(got *ServiceDefinition) { got.tls.serverName = "" }},
		{name: "plaintext port", mutate: func(got *ServiceDefinition) { got.port = 80 }},
		{name: "HTTP2 ALPN", mutate: func(got *ServiceDefinition) { got.tls.alpn = []string{"h2"} }},
		{name: "unsafe deployment", mutate: func(got *ServiceDefinition) { got.deployment = "../other" }},
		{name: "unsafe API version", mutate: func(got *ServiceDefinition) { got.apiVersion = "v1&next=other" }},
		{name: "additional method", mutate: func(got *ServiceDefinition) { got.methods = []string{"POST", "GET"} }},
		{name: "path override", mutate: func(got *ServiceDefinition) { got.localPathTemplate = "/project/override" }},
		{name: "ticket header override", mutate: func(got *ServiceDefinition) { got.ticketHeader = "authorization" }},
		{name: "content override", mutate: func(got *ServiceDefinition) { got.responseContentTypes = []string{"text/html"} }},
		{name: "redirects enabled", mutate: func(got *ServiceDefinition) { got.redirectPolicy = RedirectPolicyFollow }},
		{name: "request header raised", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestHeaderBytes++ }},
		{name: "request body raised", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestBodyBytes++ }},
		{name: "response header raised", mutate: func(got *ServiceDefinition) { got.limits.MaxResponseHeaderBytes++ }},
		{name: "response body raised", mutate: func(got *ServiceDefinition) { got.limits.MaxResponseBodyBytes++ }},
		{name: "SSE event raised", mutate: func(got *ServiceDefinition) { got.limits.MaxSSEEventBytes++ }},
		{name: "idle raised", mutate: func(got *ServiceDefinition) { got.limits.ReadIdleTimeout++ }},
		{name: "multiple requests", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestsPerConnection = 2 }},
		{name: "retry enabled", mutate: func(got *ServiceDefinition) { got.limits.MaxRetries = 1 }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cloneL8FixtureServiceDefinition(valid)
			tt.mutate(&got)
			err := ValidateServiceDefinition(got)
			if !errors.Is(err, ErrInvalidServiceDefinition) {
				t.Fatalf("ValidateServiceDefinition() error = %v, want ErrInvalidServiceDefinition", err)
			}
			assertCredentialProxyCatalogErrorSafe(t, err)
		})
	}
}

func TestL8CredentialProxyCatalogLiveDefinitionCannotBecomeDurable(t *testing.T) {
	definition := l8FixtureAzureDefinition(t)
	if got, want := ErrLiveCatalogStateNotSerializable.Error(), "credential proxy live catalog state is not serializable"; got != want {
		t.Fatalf("ErrLiveCatalogStateNotSerializable = %q, want %q", got, want)
	}
	assertOnlyUnexportedCatalogFields(t, reflect.TypeOf(definition))
	assertOnlyUnexportedCatalogFields(t, reflect.TypeOf(definition.SealedTLS()))
	assertOnlyUnexportedCatalogFields(t, reflect.TypeOf(definition.SealedInvocationPolicy()))
	assertL8LiveCatalogValueDenied(t, "sealed TLS", definition.SealedTLS())

	payload, err := json.Marshal(definition)
	if !errors.Is(err, ErrLiveCatalogStateNotSerializable) {
		t.Fatalf("json.Marshal(ServiceDefinition) = %q, %v, want ErrLiveCatalogStateNotSerializable", payload, err)
	}
	jsonMarshaler, ok := any(definition).(json.Marshaler)
	if !ok {
		t.Fatal("ServiceDefinition does not implement json.Marshaler fail-closed behavior")
	}
	payload, err = jsonMarshaler.MarshalJSON()
	if len(payload) != 0 || err != ErrLiveCatalogStateNotSerializable {
		t.Fatalf("MarshalJSON(ServiceDefinition) = %q, %v, want empty payload and stable denial", payload, err)
	}
	textMarshaler, ok := any(definition).(encoding.TextMarshaler)
	if !ok {
		t.Fatal("ServiceDefinition does not implement encoding.TextMarshaler fail-closed behavior")
	}
	textPayload, err := textMarshaler.MarshalText()
	if len(textPayload) != 0 || err != ErrLiveCatalogStateNotSerializable {
		t.Fatalf("MarshalText(ServiceDefinition) = %q, %v, want empty payload and stable denial", textPayload, err)
	}
	for _, rendered := range []string{
		fmt.Sprintf("%v", definition),
		fmt.Sprintf("%+v", definition),
		fmt.Sprintf("%#v", definition),
		definition.String(),
	} {
		assertCredentialProxyCatalogTextOmitsSealedValues(t, rendered)
		if !strings.Contains(rendered, string(ServiceIDAzureOpenAIResponsesV1)) {
			t.Fatalf("safe definition rendering %q omits service ID", rendered)
		}
	}
	policy := definition.SealedInvocationPolicy()
	policyJSON, err := json.Marshal(policy)
	if !errors.Is(err, ErrLiveCatalogStateNotSerializable) {
		t.Fatalf("json.Marshal(SealedInvocationPolicy) = %q, %v, want ErrLiveCatalogStateNotSerializable", policyJSON, err)
	}
	policyJSONMarshaler, ok := any(policy).(json.Marshaler)
	if !ok {
		t.Fatal("SealedInvocationPolicy does not implement json.Marshaler fail-closed behavior")
	}
	policyJSON, err = policyJSONMarshaler.MarshalJSON()
	if len(policyJSON) != 0 || err != ErrLiveCatalogStateNotSerializable {
		t.Fatalf("MarshalJSON(SealedInvocationPolicy) = %q, %v, want empty payload and stable denial", policyJSON, err)
	}
	policyTextMarshaler, ok := any(policy).(encoding.TextMarshaler)
	if !ok {
		t.Fatal("SealedInvocationPolicy does not implement encoding.TextMarshaler fail-closed behavior")
	}
	policyText, err := policyTextMarshaler.MarshalText()
	if len(policyText) != 0 || err != ErrLiveCatalogStateNotSerializable {
		t.Fatalf("MarshalText(SealedInvocationPolicy) = %q, %v, want empty payload and stable denial", policyText, err)
	}

	catalog, err := NewStaticServiceCatalog("catalog-generation-01", CatalogOwnerHostAdmin, definition)
	if err != nil {
		t.Fatalf("NewStaticServiceCatalog() error = %v", err)
	}
	assertOnlyUnexportedCatalogFields(t, reflect.TypeOf(catalog).Elem())
	assertL8LiveCatalogValueDenied(t, "static catalog", catalog)
	reference, err := catalog.SafeReference(ServiceIDAzureOpenAIResponsesV1)
	if err != nil {
		t.Fatalf("SafeReference() error = %v", err)
	}
	if got, want := reference, (CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1, CatalogGeneration: "catalog-generation-01"}); got != want {
		t.Fatalf("SafeReference() = %#v, want %#v", got, want)
	}
	referenceJSON, err := json.Marshal(reference)
	if err != nil {
		t.Fatalf("json.Marshal(CatalogServiceReference) error = %v", err)
	}
	if got, want := string(referenceJSON), `{"serviceId":"azure-openai-responses-v1","catalogGeneration":"catalog-generation-01"}`; got != want {
		t.Fatalf("safe reference JSON = %s, want %s", got, want)
	}
	assertCredentialProxyCatalogTextOmitsSealedValues(t, string(referenceJSON))

	typ := reflect.TypeOf(CatalogServiceReference{})
	if typ.NumField() != 2 {
		t.Fatalf("CatalogServiceReference fields = %d, want exactly service ID and catalog generation", typ.NumField())
	}
}

func TestL8CredentialProxyPiSealedInvocationPolicyIsCleanAndWorkspaceExplicit(t *testing.T) {
	policy := l8FixtureAzureDefinition(t).SealedInvocationPolicy()
	if policy.Provider() != "azure-openai-responses" || policy.Model() != l8FixtureDeployment {
		t.Fatalf("provider/model = %q/%q, want sealed Azure Responses consumer", policy.Provider(), policy.Model())
	}
	wantArgs := []string{
		"--provider", "azure-openai-responses",
		"--model", l8FixtureDeployment,
		"--offline",
		"--no-extensions",
		"--no-prompt-templates",
		"--no-themes",
		"--no-session",
	}
	if got := policy.Arguments(); !reflect.DeepEqual(got, wantArgs) {
		t.Fatalf("sealed Pi arguments = %#v, want %#v", got, wantArgs)
	}
	for _, forbidden := range []string{"--api-key", "--no-context-files", "--no-skills", "xai"} {
		if containsString(policy.Arguments(), forbidden) {
			t.Fatalf("sealed Pi arguments contain forbidden flag/provider %q: %#v", forbidden, policy.Arguments())
		}
	}
	if policy.InheritHostEnvironment() {
		t.Fatal("InheritHostEnvironment() = true, want clean fixed guest baseline")
	}
	if !policy.RequireOwnedEmptyCodingAgentDir() {
		t.Fatal("RequireOwnedEmptyCodingAgentDir() = false, want private empty PI_CODING_AGENT_DIR")
	}
	if !policy.AllowContextFiles() || !policy.AllowTextSkills() {
		t.Fatalf("workspace text policy = context:%t skills:%t, want both explicitly allowed", policy.AllowContextFiles(), policy.AllowTextSkills())
	}

	wantInjected := []string{
		"AZURE_OPENAI_API_KEY",
		"AZURE_OPENAI_API_VERSION",
		"AZURE_OPENAI_BASE_URL",
		"PI_CODING_AGENT_DIR",
	}
	if got := policy.TransientEnvironmentKeys(); !reflect.DeepEqual(got, wantInjected) {
		t.Fatalf("transient environment keys = %#v, want %#v", got, wantInjected)
	}
	cleared := policy.ClearedEnvironmentKeys()
	for _, required := range []string{
		"ALL_PROXY",
		"AZURE_OPENAI_API_KEY",
		"AZURE_OPENAI_API_VERSION",
		"AZURE_OPENAI_BASE_URL",
		"AZURE_OPENAI_DEPLOYMENT",
		"AZURE_OPENAI_RESOURCE",
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"NO_PROXY",
		"OPENAI_API_KEY",
		"OPENAI_BASE_URL",
	} {
		if !containsString(cleared, required) {
			t.Errorf("cleared environment keys %#v omit %q", cleared, required)
		}
	}
	if !sort.StringsAreSorted(cleared) || hasDuplicateStrings(cleared) {
		t.Fatalf("cleared environment keys must be sorted and unique: %#v", cleared)
	}

	// Policy is live sealed state too: formatting cannot reveal model/deployment.
	for _, rendered := range []string{fmt.Sprintf("%v", policy), fmt.Sprintf("%#v", policy), policy.String()} {
		assertCredentialProxyCatalogTextOmitsSealedValues(t, rendered)
	}
}

const (
	l8FixtureAuthority            = "azure-fixture.invalid"
	l8FixtureTLSServerName        = "tls.azure-fixture.invalid"
	l8FixtureDeployment           = "sealed-responses-model"
	l8FixtureAPIVersion           = "2026-01-01"
	l8FixtureReplacementAuthority = "replacement.invalid"
	l8FixtureUnsafeAuthority      = "https://user:raw-catalog-secret@unsafe.invalid/private"
)

func l8FixtureAzureDefinition(t *testing.T) ServiceDefinition {
	t.Helper()
	definition, err := NewAzureOpenAIResponsesV1Definition(
		l8FixtureAuthority,
		443,
		l8FixtureTLSServerName,
		TLSRootPolicySystem,
		l8FixtureDeployment,
		l8FixtureAPIVersion,
	)
	if err != nil {
		t.Fatalf("NewAzureOpenAIResponsesV1Definition() error = %v", err)
	}
	return definition
}

func cloneL8FixtureServiceDefinition(input ServiceDefinition) ServiceDefinition {
	out := input
	out.tls.alpn = append([]string(nil), input.tls.alpn...)
	out.methods = append([]string(nil), input.methods...)
	out.requestContentTypes = append([]string(nil), input.requestContentTypes...)
	out.responseContentTypes = append([]string(nil), input.responseContentTypes...)
	out.consumer.arguments = append([]string(nil), input.consumer.arguments...)
	out.consumer.transientEnvironmentKeys = append([]string(nil), input.consumer.transientEnvironmentKeys...)
	out.consumer.clearedEnvironmentKeys = append([]string(nil), input.consumer.clearedEnvironmentKeys...)
	return out
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func hasDuplicateStrings(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func assertOnlyUnexportedCatalogFields(t *testing.T, typ reflect.Type) {
	t.Helper()
	if typ.Kind() != reflect.Struct {
		t.Fatalf("sealed catalog type %s kind = %s, want struct", typ, typ.Kind())
	}
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.IsExported() {
			t.Errorf("sealed catalog type %s exposes field %s", typ, field.Name)
		}
	}
}

func assertL8LiveCatalogValueDenied(t *testing.T, label string, value any) {
	t.Helper()
	payload, err := json.Marshal(value)
	if !errors.Is(err, ErrLiveCatalogStateNotSerializable) {
		t.Fatalf("json.Marshal(%s) = %q, %v, want ErrLiveCatalogStateNotSerializable", label, payload, err)
	}
	jsonMarshaler, ok := value.(json.Marshaler)
	if !ok {
		t.Fatalf("%s does not implement json.Marshaler fail-closed behavior", label)
	}
	payload, err = jsonMarshaler.MarshalJSON()
	if len(payload) != 0 || err != ErrLiveCatalogStateNotSerializable {
		t.Fatalf("MarshalJSON(%s) = %q, %v, want empty payload and stable denial", label, payload, err)
	}
	textMarshaler, ok := value.(encoding.TextMarshaler)
	if !ok {
		t.Fatalf("%s does not implement encoding.TextMarshaler fail-closed behavior", label)
	}
	payload, err = textMarshaler.MarshalText()
	if len(payload) != 0 || err != ErrLiveCatalogStateNotSerializable {
		t.Fatalf("MarshalText(%s) = %q, %v, want empty payload and stable denial", label, payload, err)
	}
	if _, ok := value.(fmt.Stringer); !ok {
		t.Fatalf("%s does not implement safe fmt.Stringer", label)
	}
	if _, ok := value.(fmt.GoStringer); !ok {
		t.Fatalf("%s does not implement safe fmt.GoStringer", label)
	}
	for _, rendered := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%+v", value), fmt.Sprintf("%#v", value)} {
		assertCredentialProxyCatalogTextOmitsSealedValues(t, rendered)
	}
}

func credentialProxyCatalogProductionSource(t *testing.T) string {
	t.Helper()
	var source strings.Builder
	for _, path := range credentialProxyCatalogProductionFiles(t) {
		payload, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error: %v", path, err)
		}
		source.Write(payload)
	}
	return source.String()
}

func assertCredentialProxyCatalogErrorSafe(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil, want sanitized catalog error")
	}
	assertCredentialProxyCatalogTextOmitsSealedValues(t, err.Error())
}

func assertCredentialProxyCatalogTextOmitsSealedValues(t *testing.T, text string) {
	t.Helper()
	for _, unsafe := range []string{
		"raw-catalog-secret",
		"user:",
		l8FixtureAuthority,
		l8FixtureTLSServerName,
		l8FixtureDeployment,
		l8FixtureAPIVersion,
		l8FixtureUnsafeAuthority,
		"https://",
		"/private",
	} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("catalog text %q contains sealed value %q", text, unsafe)
		}
	}
}
