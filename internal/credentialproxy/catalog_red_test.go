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
	if got, want := definition.UpstreamPathTemplate(), "/openai/v1/responses"; got != want {
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
	definition.requestContentTypes[0] = "text/plain"
	definition.responseContentTypes[0] = "text/html"
	definition.consumer.arguments[0] = "--api-key"
	definition.consumer.transientEnvironmentKeys[0] = "RAW_SECRET"
	definition.consumer.clearedEnvironmentKeys[0] = "MUTATED_PROVIDER_KEY"
	got, err := catalog.Lookup(ServiceIDAzureOpenAIResponsesV1)
	if err != nil {
		t.Fatalf("Lookup() error = %v", err)
	}
	assertL8FixtureDefinitionSlices(t, got)
	methods := got.AllowedMethods()
	methods[0] = "PATCH"
	alpn := got.SealedTLS().ALPN()
	alpn[0] = "h2"
	requestTypes := got.RequestContentTypes()
	requestTypes[0] = "text/plain"
	responseTypes := got.ResponseContentTypes()
	responseTypes[0] = "text/html"
	arguments := got.SealedInvocationPolicy().Arguments()
	arguments[0] = "--api-key"
	transientKeys := got.SealedInvocationPolicy().TransientEnvironmentKeys()
	transientKeys[0] = "RAW_SECRET"
	clearedKeys := got.SealedInvocationPolicy().ClearedEnvironmentKeys()
	wantClearedKeys := append([]string(nil), clearedKeys...)
	clearedKeys[0] = "MUTATED_PROVIDER_KEY"
	again, err := catalog.Lookup(ServiceIDAzureOpenAIResponsesV1)
	if err != nil {
		t.Fatalf("second Lookup() error = %v", err)
	}
	assertL8FixtureDefinitionSlices(t, again)
	if got := again.SealedInvocationPolicy().ClearedEnvironmentKeys(); !reflect.DeepEqual(got, wantClearedKeys) {
		t.Fatalf("cleared environment keys after caller mutation = %#v, want %#v", got, wantClearedKeys)
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
	rawServiceID := ServiceID("https://user:raw-secret@private.example.test/service")
	if _, err := catalog.Lookup(rawServiceID); !errors.Is(err, ErrServiceUnknown) {
		t.Fatalf("Lookup(raw-looking service ID) error = %v, want ErrServiceUnknown", err)
	} else {
		assertCredentialProxyCatalogErrorSafe(t, err)
		assertCredentialProxyCatalogRejectedValueOmitted(t, err, string(rawServiceID))
	}
	if _, err := catalog.SafeReference(rawServiceID); !errors.Is(err, ErrServiceUnknown) {
		t.Fatalf("SafeReference(raw-looking service ID) error = %v, want ErrServiceUnknown", err)
	} else {
		assertCredentialProxyCatalogErrorSafe(t, err)
		assertCredentialProxyCatalogRejectedValueOmitted(t, err, string(rawServiceID))
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

func TestL8CredentialProxyCatalogConstructorsFailClosedOnUnsafeInputsAndPolicyWeakening(t *testing.T) {
	valid := l8FixtureAzureDefinition(t)
	type catalogConstructorTest struct {
		name       string
		generation string
		owner      CatalogOwner
		definition ServiceDefinition
		want       error
		raw        string
	}
	tests := []catalogConstructorTest{
		{
			name:       "unsafe generation",
			generation: "https://user:raw-secret@private.example.test/generation",
			owner:      CatalogOwnerHostAdmin,
			definition: valid,
			want:       ErrCatalogGenerationRequired,
			raw:        "raw-secret",
		},
		{
			name:       "invalid owner",
			generation: "catalog-generation-01",
			owner:      CatalogOwner("project/raw-secret"),
			definition: valid,
			want:       ErrCatalogOwnerRequired,
			raw:        "project/raw-secret",
		},
	}
	invalidDefinition := cloneL8FixtureServiceDefinition(valid)
	invalidDefinition.authority = l8FixtureUnsafeAuthority
	tests = append(tests, catalogConstructorTest{
		name:       "invalid definition",
		generation: "catalog-generation-01",
		owner:      CatalogOwnerHostAdmin,
		definition: invalidDefinition,
		want:       ErrInvalidServiceDefinition,
		raw:        "raw-catalog-secret",
	})

	weakenedArguments := cloneL8FixtureServiceDefinition(valid)
	weakenedArguments.consumer.arguments = append(weakenedArguments.consumer.arguments, "--api-key", "raw-secret")
	weakenedTransientEnvironment := cloneL8FixtureServiceDefinition(valid)
	weakenedTransientEnvironment.consumer.transientEnvironmentKeys = append(
		weakenedTransientEnvironment.consumer.transientEnvironmentKeys,
		"OPENAI_API_KEY",
	)
	weakenedClearing := cloneL8FixtureServiceDefinition(valid)
	weakenedClearing.consumer.clearedEnvironmentKeys = []string{"AZURE_OPENAI_API_KEY"}
	for _, weakened := range []struct {
		name       string
		definition ServiceDefinition
		raw        string
	}{
		{name: "consumer arguments", definition: weakenedArguments, raw: "raw-secret"},
		{name: "transient provider environment", definition: weakenedTransientEnvironment, raw: "OPENAI_API_KEY"},
		{name: "provider clearing", definition: weakenedClearing},
	} {
		tests = append(tests, catalogConstructorTest{
			name:       "weakened invocation policy " + weakened.name,
			generation: "catalog-generation-01",
			owner:      CatalogOwnerHostAdmin,
			definition: weakened.definition,
			want:       ErrInvalidServiceDefinition,
			raw:        weakened.raw,
		})
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			catalog, err := NewStaticServiceCatalog(tt.generation, tt.owner, tt.definition)
			if !errors.Is(err, tt.want) {
				t.Fatalf("NewStaticServiceCatalog() error = %v, want %v", err, tt.want)
			}
			if catalog != nil {
				t.Fatalf("NewStaticServiceCatalog() catalog = %#v, want nil", catalog)
			}
			assertCredentialProxyCatalogErrorSafe(t, err)
			assertCredentialProxyCatalogRejectedValueOmitted(t, err, tt.raw)
		})
	}

	azureInputTests := []struct {
		name       string
		authority  string
		deployment string
		apiVersion string
		raw        string
	}{
		{name: "missing authority", deployment: l8FixtureDeployment, apiVersion: l8FixtureAPIVersion},
		{name: "unsafe authority", authority: "https://user:raw-secret@private.example.test/path", deployment: l8FixtureDeployment, apiVersion: l8FixtureAPIVersion, raw: "raw-secret"},
		{name: "missing deployment", authority: l8FixtureAuthority, apiVersion: l8FixtureAPIVersion},
		{name: "unsafe deployment", authority: l8FixtureAuthority, deployment: "../raw-secret/deployment", apiVersion: l8FixtureAPIVersion, raw: "raw-secret"},
		{name: "missing API version", authority: l8FixtureAuthority, deployment: l8FixtureDeployment},
		{name: "unsafe API version", authority: l8FixtureAuthority, deployment: l8FixtureDeployment, apiVersion: "2026-01-01&api-key=raw-secret", raw: "raw-secret"},
	}
	for _, tt := range azureInputTests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewAzureOpenAIResponsesV1Definition(
				tt.authority,
				443,
				l8FixtureTLSServerName,
				TLSRootPolicySystem,
				tt.deployment,
				tt.apiVersion,
			)
			if err != ErrInvalidServiceDefinition {
				t.Fatalf("NewAzureOpenAIResponsesV1Definition() error = %v, want stable ErrInvalidServiceDefinition", err)
			}
			assertCredentialProxyCatalogErrorSafe(t, err)
			assertCredentialProxyCatalogRejectedValueOmitted(t, err, tt.raw)
		})
	}
}

func TestL8CredentialProxyCatalogValidationRejectsPolicyWeakening(t *testing.T) {
	valid := l8FixtureAzureDefinition(t)
	if got, want := ErrInvalidServiceDefinition.Error(), "credential proxy service definition invalid"; got != want {
		t.Fatalf("ErrInvalidServiceDefinition = %q, want %q", got, want)
	}
	tests := []struct {
		name   string
		mutate func(*ServiceDefinition)
	}{
		{name: "authority contains scheme", mutate: func(got *ServiceDefinition) { got.authority = l8FixtureUnsafeAuthority }},
		{name: "authority contains port", mutate: func(got *ServiceDefinition) { got.authority = "azure-fixture.invalid:443" }},
		{name: "authority contains userinfo", mutate: func(got *ServiceDefinition) { got.authority = "user:raw-secret@azure-fixture.invalid" }},
		{name: "authority contains slash", mutate: func(got *ServiceDefinition) { got.authority = "azure-fixture.invalid/private" }},
		{name: "authority contains backslash", mutate: func(got *ServiceDefinition) { got.authority = `azure-fixture.invalid\private` }},
		{name: "authority contains query", mutate: func(got *ServiceDefinition) { got.authority = "azure-fixture.invalid?token=raw-secret" }},
		{name: "authority contains fragment", mutate: func(got *ServiceDefinition) { got.authority = "azure-fixture.invalid#private" }},
		{name: "authority contains control", mutate: func(got *ServiceDefinition) { got.authority = "azure-fixture.invalid\nraw-secret" }},
		{name: "authority contains whitespace", mutate: func(got *ServiceDefinition) { got.authority = "azure fixture.invalid" }},
		{name: "authority has trailing dot", mutate: func(got *ServiceDefinition) { got.authority = "azure-fixture.invalid." }},
		{name: "authority has noncanonical case", mutate: func(got *ServiceDefinition) { got.authority = "AZURE-FIXTURE.INVALID" }},
		{name: "missing TLS name", mutate: func(got *ServiceDefinition) { got.tls.serverName = "" }},
		{name: "TLS name wildcard", mutate: func(got *ServiceDefinition) { got.tls.serverName = "*.azure-fixture.invalid" }},
		{name: "TLS name contains port", mutate: func(got *ServiceDefinition) { got.tls.serverName = "tls.azure-fixture.invalid:443" }},
		{name: "TLS name contains slash", mutate: func(got *ServiceDefinition) { got.tls.serverName = "tls.azure-fixture.invalid/private" }},
		{name: "TLS name contains control", mutate: func(got *ServiceDefinition) { got.tls.serverName = "tls.azure-fixture.invalid\nraw-secret" }},
		{name: "TLS name has trailing dot", mutate: func(got *ServiceDefinition) { got.tls.serverName = "tls.azure-fixture.invalid." }},
		{name: "TLS name has noncanonical case", mutate: func(got *ServiceDefinition) { got.tls.serverName = "TLS.AZURE-FIXTURE.INVALID" }},
		{name: "missing TLS root policy", mutate: func(got *ServiceDefinition) { got.tls.rootPolicy = "" }},
		{name: "unknown TLS root policy", mutate: func(got *ServiceDefinition) { got.tls.rootPolicy = TLSRootPolicy("project_roots") }},
		{name: "zero port", mutate: func(got *ServiceDefinition) { got.port = 0 }},
		{name: "plaintext port", mutate: func(got *ServiceDefinition) { got.port = 80 }},
		{name: "alternate TLS port", mutate: func(got *ServiceDefinition) { got.port = 8443 }},
		{name: "missing ALPN", mutate: func(got *ServiceDefinition) { got.tls.alpn = nil }},
		{name: "HTTP2 ALPN", mutate: func(got *ServiceDefinition) { got.tls.alpn = []string{"h2"} }},
		{name: "additional ALPN", mutate: func(got *ServiceDefinition) { got.tls.alpn = []string{"http/1.1", "h2"} }},
		{name: "unsafe deployment", mutate: func(got *ServiceDefinition) { got.deployment = "../other" }},
		{name: "unsafe API version", mutate: func(got *ServiceDefinition) { got.apiVersion = "v1&next=other" }},
		{name: "missing method", mutate: func(got *ServiceDefinition) { got.methods = nil }},
		{name: "noncanonical method", mutate: func(got *ServiceDefinition) { got.methods = []string{"post"} }},
		{name: "additional method", mutate: func(got *ServiceDefinition) { got.methods = []string{"POST", "GET"} }},
		{name: "local path override", mutate: func(got *ServiceDefinition) { got.localPathTemplate = "/project/override" }},
		{name: "upstream path override", mutate: func(got *ServiceDefinition) { got.upstreamPathTemplate = "/project/override" }},
		{name: "query key override", mutate: func(got *ServiceDefinition) { got.queryKey = "version" }},
		{name: "ticket header override", mutate: func(got *ServiceDefinition) { got.ticketHeader = "authorization" }},
		{name: "upstream auth header override", mutate: func(got *ServiceDefinition) { got.upstreamAuthenticationHeader = "authorization" }},
		{name: "auth transform override", mutate: func(got *ServiceDefinition) { got.authenticationTransform = AuthenticationTransform("forward_ticket") }},
		{name: "missing request content", mutate: func(got *ServiceDefinition) { got.requestContentTypes = nil }},
		{name: "request content override", mutate: func(got *ServiceDefinition) { got.requestContentTypes = []string{"text/plain"} }},
		{name: "additional request content", mutate: func(got *ServiceDefinition) { got.requestContentTypes = []string{"application/json", "text/plain"} }},
		{name: "missing response content", mutate: func(got *ServiceDefinition) { got.responseContentTypes = nil }},
		{name: "response content override", mutate: func(got *ServiceDefinition) { got.responseContentTypes = []string{"text/html"} }},
		{name: "missing event stream content", mutate: func(got *ServiceDefinition) { got.responseContentTypes = []string{"application/json"} }},
		{name: "additional response content", mutate: func(got *ServiceDefinition) {
			got.responseContentTypes = []string{"application/json", "text/event-stream", "text/plain"}
		}},
		{name: "redirects enabled", mutate: func(got *ServiceDefinition) { got.redirectPolicy = RedirectPolicyFollow }},
		{name: "request header zero", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestHeaderBytes = 0 }},
		{name: "request header negative", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestHeaderBytes = -1 }},
		{name: "request header raised", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestHeaderBytes++ }},
		{name: "request body zero", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestBodyBytes = 0 }},
		{name: "request body negative", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestBodyBytes = -1 }},
		{name: "request body raised", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestBodyBytes++ }},
		{name: "response header zero", mutate: func(got *ServiceDefinition) { got.limits.MaxResponseHeaderBytes = 0 }},
		{name: "response header negative", mutate: func(got *ServiceDefinition) { got.limits.MaxResponseHeaderBytes = -1 }},
		{name: "response header raised", mutate: func(got *ServiceDefinition) { got.limits.MaxResponseHeaderBytes++ }},
		{name: "response body zero", mutate: func(got *ServiceDefinition) { got.limits.MaxResponseBodyBytes = 0 }},
		{name: "response body negative", mutate: func(got *ServiceDefinition) { got.limits.MaxResponseBodyBytes = -1 }},
		{name: "response body raised", mutate: func(got *ServiceDefinition) { got.limits.MaxResponseBodyBytes++ }},
		{name: "SSE event zero", mutate: func(got *ServiceDefinition) { got.limits.MaxSSEEventBytes = 0 }},
		{name: "SSE event negative", mutate: func(got *ServiceDefinition) { got.limits.MaxSSEEventBytes = -1 }},
		{name: "SSE event raised", mutate: func(got *ServiceDefinition) { got.limits.MaxSSEEventBytes++ }},
		{name: "idle zero", mutate: func(got *ServiceDefinition) { got.limits.ReadIdleTimeout = 0 }},
		{name: "idle negative", mutate: func(got *ServiceDefinition) { got.limits.ReadIdleTimeout = -1 }},
		{name: "idle raised", mutate: func(got *ServiceDefinition) { got.limits.ReadIdleTimeout++ }},
		{name: "requests per connection zero", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestsPerConnection = 0 }},
		{name: "requests per connection negative", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestsPerConnection = -1 }},
		{name: "multiple requests", mutate: func(got *ServiceDefinition) { got.limits.MaxRequestsPerConnection = 2 }},
		{name: "negative retries", mutate: func(got *ServiceDefinition) { got.limits.MaxRetries = -1 }},
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
			if got := err.Error(); got != ErrInvalidServiceDefinition.Error() {
				t.Fatalf("ValidateServiceDefinition() error text = %q, want stable %q", got, ErrInvalidServiceDefinition.Error())
			}
			if unwrapped := errors.Unwrap(err); unwrapped != nil {
				t.Fatalf("ValidateServiceDefinition() unwrap = %v, want nil", unwrapped)
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
	if err := ValidateCatalogServiceReference(reference); err != nil {
		t.Fatalf("ValidateCatalogServiceReference(safe) error = %v", err)
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

func TestL8CredentialProxyCatalogServiceReferenceRejectsUnsafeDirectLiterals(t *testing.T) {
	if got, want := ErrInvalidCatalogServiceReference.Error(), "credential proxy catalog service reference invalid"; got != want {
		t.Fatalf("ErrInvalidCatalogServiceReference = %q, want %q", got, want)
	}
	tests := []struct {
		name      string
		reference CatalogServiceReference
	}{
		{name: "missing service ID", reference: CatalogServiceReference{CatalogGeneration: "catalog-generation-01"}},
		{name: "missing generation", reference: CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1}},
		{name: "service endpoint", reference: CatalogServiceReference{ServiceID: "https://user:raw-secret@unsafe.invalid", CatalogGeneration: "catalog-generation-01"}},
		{name: "service hostname", reference: CatalogServiceReference{ServiceID: "unsafe.invalid", CatalogGeneration: "catalog-generation-01"}},
		{name: "service path", reference: CatalogServiceReference{ServiceID: "../private/service", CatalogGeneration: "catalog-generation-01"}},
		{name: "service secret assignment", reference: CatalogServiceReference{ServiceID: "token=raw-secret", CatalogGeneration: "catalog-generation-01"}},
		{name: "service whitespace", reference: CatalogServiceReference{ServiceID: "unsafe service", CatalogGeneration: "catalog-generation-01"}},
		{name: "service control", reference: CatalogServiceReference{ServiceID: "unsafe\nraw-secret", CatalogGeneration: "catalog-generation-01"}},
		{name: "service uppercase", reference: CatalogServiceReference{ServiceID: "Azure-OpenAI-Responses-v1", CatalogGeneration: "catalog-generation-01"}},
		{name: "service leading hyphen", reference: CatalogServiceReference{ServiceID: "-unsafe-service", CatalogGeneration: "catalog-generation-01"}},
		{name: "service trailing hyphen", reference: CatalogServiceReference{ServiceID: "unsafe-service-", CatalogGeneration: "catalog-generation-01"}},
		{name: "service oversized", reference: CatalogServiceReference{ServiceID: ServiceID(strings.Repeat("a", 129)), CatalogGeneration: "catalog-generation-01"}},
		{name: "generation endpoint", reference: CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1, CatalogGeneration: "https://unsafe.invalid/raw-secret"}},
		{name: "generation hostname", reference: CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1, CatalogGeneration: "unsafe.invalid"}},
		{name: "generation path", reference: CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1, CatalogGeneration: "/Users/alice/private"}},
		{name: "generation secret assignment", reference: CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1, CatalogGeneration: "api-key=raw-secret"}},
		{name: "generation whitespace", reference: CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1, CatalogGeneration: "catalog generation"}},
		{name: "generation control", reference: CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1, CatalogGeneration: "catalog\traw-secret"}},
		{name: "generation uppercase", reference: CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1, CatalogGeneration: "Catalog-Generation-01"}},
		{name: "generation leading hyphen", reference: CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1, CatalogGeneration: "-catalog-generation"}},
		{name: "generation trailing hyphen", reference: CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1, CatalogGeneration: "catalog-generation-"}},
		{name: "generation oversized", reference: CatalogServiceReference{ServiceID: ServiceIDAzureOpenAIResponsesV1, CatalogGeneration: strings.Repeat("g", 129)}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCatalogServiceReference(tt.reference)
			if err != ErrInvalidCatalogServiceReference {
				t.Fatalf("ValidateCatalogServiceReference() error = %v, want stable sentinel", err)
			}
			if errors.Unwrap(err) != nil {
				t.Fatalf("ValidateCatalogServiceReference() unwrap = %v, want nil", errors.Unwrap(err))
			}

			payload, marshalErr := json.Marshal(tt.reference)
			if !errors.Is(marshalErr, ErrInvalidCatalogServiceReference) {
				t.Fatalf("json.Marshal(unsafe reference) = %q, %v, want ErrInvalidCatalogServiceReference", payload, marshalErr)
			}
			marshaler, ok := any(tt.reference).(json.Marshaler)
			if !ok {
				t.Fatal("CatalogServiceReference does not implement validating json.Marshaler")
			}
			payload, marshalErr = marshaler.MarshalJSON()
			if len(payload) != 0 || marshalErr != ErrInvalidCatalogServiceReference {
				t.Fatalf("MarshalJSON(unsafe reference) = %q, %v, want empty payload and stable sentinel", payload, marshalErr)
			}
			assertCredentialProxyCatalogTextOmitsSealedValues(t, marshalErr.Error())
			for _, raw := range []string{string(tt.reference.ServiceID), tt.reference.CatalogGeneration} {
				if raw != "" && strings.Contains(marshalErr.Error(), raw) {
					t.Fatalf("reference error %q contains raw rejected value %q", marshalErr, raw)
				}
			}
		})
	}
}

func TestL8CredentialProxyCatalogSanitizedErrorContractIsStable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "catalog generation required", err: ErrCatalogGenerationRequired, want: "credential proxy catalog generation is required"},
		{name: "catalog owner required", err: ErrCatalogOwnerRequired, want: "credential proxy catalog owner is required"},
		{name: "catalog empty", err: ErrCatalogEmpty, want: "credential proxy catalog is empty"},
		{name: "service collision", err: ErrServiceCollision, want: "credential proxy service collision"},
		{name: "service unknown", err: ErrServiceUnknown, want: "credential proxy service unknown"},
		{name: "invalid service definition", err: ErrInvalidServiceDefinition, want: "credential proxy service definition invalid"},
		{name: "live catalog state serialization", err: ErrLiveCatalogStateNotSerializable, want: "credential proxy live catalog state is not serializable"},
		{name: "invalid catalog service reference", err: ErrInvalidCatalogServiceReference, want: "credential proxy catalog service reference invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Fatalf("error text = %q, want %q", got, tt.want)
			}
			if errors.Unwrap(tt.err) != nil {
				t.Fatalf("sentinel unwrap = %v, want nil", errors.Unwrap(tt.err))
			}
			assertCredentialProxyCatalogErrorSafe(t, tt.err)
		})
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
	if got := policy.EnvironmentPolicy(); got != EnvironmentPolicyFixedAllowlist {
		t.Fatalf("EnvironmentPolicy() = %q, want fixed allowlist", got)
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
		"AZURE_OPENAI_DEPLOYMENT_NAME_MAP",
		"AZURE_OPENAI_RESOURCE_NAME",
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
	for _, obsolete := range []string{"AZURE_OPENAI_DEPLOYMENT", "AZURE_OPENAI_RESOURCE"} {
		if containsString(cleared, obsolete) {
			t.Errorf("cleared environment keys include obsolete Pi variable %q: %#v", obsolete, cleared)
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

func assertL8FixtureDefinitionSlices(t *testing.T, definition ServiceDefinition) {
	t.Helper()
	if definition.SealedAuthority() != l8FixtureAuthority {
		t.Fatalf("SealedAuthority() = %q, want immutable fixture authority", definition.SealedAuthority())
	}
	checks := []struct {
		name string
		got  []string
		want []string
	}{
		{name: "TLS ALPN", got: definition.SealedTLS().ALPN(), want: []string{"http/1.1"}},
		{name: "methods", got: definition.AllowedMethods(), want: []string{"POST"}},
		{name: "request content types", got: definition.RequestContentTypes(), want: []string{"application/json"}},
		{name: "response content types", got: definition.ResponseContentTypes(), want: []string{"application/json", "text/event-stream"}},
		{
			name: "Pi arguments",
			got:  definition.SealedInvocationPolicy().Arguments(),
			want: []string{
				"--provider", "azure-openai-responses",
				"--model", l8FixtureDeployment,
				"--offline",
				"--no-extensions",
				"--no-prompt-templates",
				"--no-themes",
				"--no-session",
			},
		},
		{
			name: "transient environment keys",
			got:  definition.SealedInvocationPolicy().TransientEnvironmentKeys(),
			want: []string{"AZURE_OPENAI_API_KEY", "AZURE_OPENAI_API_VERSION", "AZURE_OPENAI_BASE_URL", "PI_CODING_AGENT_DIR"},
		},
	}
	for _, check := range checks {
		if !reflect.DeepEqual(check.got, check.want) {
			t.Errorf("%s = %#v, want %#v", check.name, check.got, check.want)
		}
	}
	cleared := definition.SealedInvocationPolicy().ClearedEnvironmentKeys()
	for _, forbidden := range []string{"MUTATED_PROVIDER_KEY", "RAW_SECRET"} {
		if containsString(cleared, forbidden) {
			t.Errorf("cleared environment keys contain caller mutation %q: %#v", forbidden, cleared)
		}
	}
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
	for _, path := range credentialProxyProductionFiles(t) {
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

func assertCredentialProxyCatalogRejectedValueOmitted(t *testing.T, err error, raw string) {
	t.Helper()
	if raw != "" && strings.Contains(err.Error(), raw) {
		t.Fatalf("catalog error %q contains rejected raw value %q", err, raw)
	}
}

func assertCredentialProxyCatalogTextOmitsSealedValues(t *testing.T, text string) {
	t.Helper()
	for _, unsafe := range []string{
		"raw-catalog-secret",
		"raw-secret",
		"user:",
		l8FixtureAuthority,
		l8FixtureTLSServerName,
		l8FixtureDeployment,
		l8FixtureAPIVersion,
		l8FixtureUnsafeAuthority,
		"https://",
		"api-key=",
		"/private",
	} {
		if strings.Contains(text, unsafe) {
			t.Fatalf("catalog text %q contains sealed value %q", text, unsafe)
		}
	}
}
