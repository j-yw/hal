package registry_test

import (
	"context"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
)

func TestL9BearerAuthUsesExactRealmServiceScopeAndOriginCredentialPair(t *testing.T) {
	fixture := newRegistryFixture(t)
	const tokenOrigin = "https://tokens.example"
	var mu sync.Mutex
	var calls []string
	credentials := &recordingCredentialProvider{credential: registry.Credential{
		Username: "fixture-user",
		Password: "fixture-password",
	}}
	client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		calls = append(calls, request.Method+" "+request.URL.String())
		mu.Unlock()
		switch request.URL.Host {
		case "registry.example":
			if request.Header.Get("Authorization") == "Bearer fixture-token" {
				if strings.Contains(request.URL.Path, "/blobs/") {
					return registryResponse(http.StatusOK, registry.MediaTypeTemplateYAML, fixture.template, nil), nil
				}
				return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, nil), nil
			}
			return registryResponse(http.StatusUnauthorized, "", nil, map[string]string{
				"WWW-Authenticate": `Bearer realm="` + tokenOrigin + `/token",service="registry.example",scope="repository:hal/template:pull"`,
			}), nil
		case "tokens.example":
			if got := request.Header.Get("Authorization"); got != "Basic "+base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-password")) {
				t.Fatalf("token Authorization = %q", got)
			}
			return registryResponse(http.StatusOK, "application/json", []byte(`{"token":"fixture-token"}`), nil), nil
		default:
			t.Fatalf("unexpected origin %q", request.URL.Host)
			return nil, nil
		}
	})
	resolver, err := registry.NewResolver(registry.Options{
		Client:                 client,
		AllowedRegistryOrigins: []string{registryOrigin},
		AllowedTokenOrigins: map[string]registry.TokenOriginPolicy{
			registryOrigin: {
				Origin:  tokenOrigin,
				Service: "registry.example",
			},
		},
		CredentialProvider: credentials,
	})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	if _, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest")); err != nil {
		t.Fatalf("ResolveOCIArtifact() error = %v", err)
	}
	if len(credentials.calls) == 0 {
		t.Fatal("credential provider was not called")
	}
	for _, call := range credentials.calls {
		if call.RegistryOrigin != registryOrigin || call.TokenOrigin != tokenOrigin {
			t.Fatalf("credential lookup pair = %#v, want exact registry/token origins", call)
		}
	}
}

func TestL9BearerAuthRejectsChallengeConfusionAndBounds(t *testing.T) {
	fixture := newRegistryFixture(t)
	tests := []struct {
		name      string
		challenge string
		tokenBody []byte
		want      registry.ErrorCode
	}{
		{"unconfigured realm", `Bearer realm="https://evil.example/token",service="registry.example",scope="repository:hal/template:pull"`, nil, registry.ErrorCodeAuthenticationChallengeInvalid},
		{"plaintext realm", `Bearer realm="http://tokens.example/token",service="registry.example",scope="repository:hal/template:pull"`, nil, registry.ErrorCodeAuthenticationChallengeInvalid},
		{"userinfo realm", `Bearer realm="https://user:pass@tokens.example/token",service="registry.example",scope="repository:hal/template:pull"`, nil, registry.ErrorCodeAuthenticationChallengeInvalid},
		{"wrong service", `Bearer realm="https://tokens.example/token",service="other",scope="repository:hal/template:pull"`, nil, registry.ErrorCodeAuthenticationChallengeInvalid},
		{"broader scope", `Bearer realm="https://tokens.example/token",service="registry.example",scope="repository:hal/template:push,pull"`, nil, registry.ErrorCodeAuthenticationChallengeInvalid},
		{"repeated scope", `Bearer realm="https://tokens.example/token",service="registry.example",scope="repository:hal/template:pull",scope="repository:hal/template:pull"`, nil, registry.ErrorCodeAuthenticationChallengeInvalid},
		{"oversize challenge", "Bearer " + strings.Repeat("x", registry.DefaultMaxChallengeBytes+1), nil, registry.ErrorCodeAuthenticationChallengeInvalid},
		{"oversize token", `Bearer realm="https://tokens.example/token",service="registry.example",scope="repository:hal/template:pull"`, make([]byte, registry.DefaultMaxTokenBytes+1), registry.ErrorCodeAuthenticationResponseOversize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
				if request.URL.Host == "tokens.example" {
					return registryResponse(http.StatusOK, "application/json", tt.tokenBody, nil), nil
				}
				return registryResponse(http.StatusUnauthorized, "", fixture.manifest, map[string]string{
					"WWW-Authenticate": tt.challenge,
				}), nil
			})
			resolver, err := registry.NewResolver(registry.Options{
				Client:                 client,
				AllowedRegistryOrigins: []string{registryOrigin},
				AllowedTokenOrigins: map[string]registry.TokenOriginPolicy{
					registryOrigin: {Origin: "https://tokens.example", Service: "registry.example"},
				},
				CredentialProvider: &recordingCredentialProvider{},
			})
			if err != nil {
				t.Fatalf("NewResolver() error = %v", err)
			}
			_, resolveErr := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
			requireRegistryErrorCode(t, resolveErr, tt.want)
		})
	}
}

func TestL9AuthenticationRetryIsBoundedAndFailsClosed(t *testing.T) {
	calls := 0
	client := fakeHTTPDoer(func(*http.Request) (*http.Response, error) {
		calls++
		return registryResponse(http.StatusUnauthorized, "", nil, map[string]string{
			"WWW-Authenticate": `Basic realm="registry"`,
		}), nil
	})
	resolver, err := registry.NewResolver(registry.Options{
		Client:                 client,
		AllowedRegistryOrigins: []string{registryOrigin},
		CredentialProvider:     &recordingCredentialProvider{credential: registry.Credential{Username: "u", Password: "p"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, resolveErr := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
	requireRegistryErrorCode(t, resolveErr, registry.ErrorCodeAuthenticationFailed)
	if calls != 2 {
		t.Fatalf("registry calls = %d, want initial plus one retry", calls)
	}
}

func TestL9BlobRedirectPolicyStripsAuthorizationAndRejectsUnsafeHops(t *testing.T) {
	fixture := newRegistryFixture(t)
	const blobOrigin = "https://objects.example"
	tests := []struct {
		name     string
		location string
		allowed  bool
		want     registry.ErrorCode
	}{
		{"allowlisted https", blobOrigin + "/verified-layer", true, ""},
		{"unconfigured origin", "https://evil.example/layer", false, registry.ErrorCodeRedirectRejected},
		{"TLS downgrade", "http://objects.example/layer", false, registry.ErrorCodeRedirectRejected},
		{"userinfo", "https://user:pass@objects.example/layer", false, registry.ErrorCodeRedirectRejected},
		{"fragment", blobOrigin + "/layer#fragment", false, registry.ErrorCodeRedirectRejected},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manifestCalls := 0
			client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
				switch {
				case request.URL.Host == "objects.example":
					if request.Header.Get("Authorization") != "" {
						t.Fatal("Authorization forwarded to cross-origin blob redirect")
					}
					return registryResponse(http.StatusOK, registry.MediaTypeTemplateYAML, fixture.template, nil), nil
				case strings.Contains(request.URL.Path, "/manifests/"):
					manifestCalls++
					return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, nil), nil
				case strings.Contains(request.URL.Path, "/blobs/"):
					if request.Header.Get("Authorization") == "" {
						t.Fatal("registry blob request should retain registry authorization")
					}
					return registryResponse(http.StatusTemporaryRedirect, "", nil, map[string]string{"Location": tt.location}), nil
				default:
					return registryResponse(http.StatusNotFound, "", nil, nil), nil
				}
			})
			resolver, err := registry.NewResolver(registry.Options{
				Client:                 client,
				AllowedRegistryOrigins: []string{registryOrigin},
				AllowedBlobOrigins:     map[string][]string{registryOrigin: {blobOrigin}},
				CredentialProvider: &recordingCredentialProvider{credential: registry.Credential{
					Username: "fixture-user",
					Password: "fixture-password",
				}},
				PreemptiveBasicAuthOrigins: []string{registryOrigin},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, resolveErr := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
			if tt.allowed {
				if resolveErr != nil {
					t.Fatalf("ResolveOCIArtifact() error = %v", resolveErr)
				}
				return
			}
			requireRegistryErrorCode(t, resolveErr, tt.want)
		})
	}
}

func TestL9RedirectPolicyRejectsMoreThanThreeHops(t *testing.T) {
	fixture := newRegistryFixture(t)
	hop := 0
	client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(request.URL.Path, "/manifests/") {
			return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, nil), nil
		}
		if strings.Contains(request.URL.Path, "/blobs/") || strings.Contains(request.URL.Path, "/hop/") {
			hop++
			return registryResponse(http.StatusTemporaryRedirect, "", nil, map[string]string{
				"Location": registryOrigin + "/hop/" + strconv.Itoa(hop),
			}), nil
		}
		return registryResponse(http.StatusNotFound, "", nil, nil), nil
	})
	resolver := mustRegistryResolver(t, client, nil)
	_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
	requireRegistryErrorCode(t, err, registry.ErrorCodeRedirectRejected)
	if hop != registry.DefaultMaxRedirects+1 {
		t.Fatalf("redirect requests = %d, want rejection at hop %d", hop, registry.DefaultMaxRedirects+1)
	}
}

func TestL9OriginValidationRunsForRegistryRedirectBlobAndTokenRequests(t *testing.T) {
	fixture := newRegistryFixture(t)
	validator := &recordingOriginValidator{}
	const tokenOrigin = "https://tokens.example"
	const blobOrigin = "https://objects.example"
	client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
		switch request.URL.Host {
		case "registry.example":
			if strings.Contains(request.URL.Path, "/manifests/") {
				if request.Header.Get("Authorization") == "" {
					return registryResponse(http.StatusUnauthorized, "", nil, map[string]string{
						"WWW-Authenticate": `Bearer realm="` + tokenOrigin + `/token",service="registry.example",scope="repository:hal/template:pull"`,
					}), nil
				}
				return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, nil), nil
			}
			return registryResponse(http.StatusTemporaryRedirect, "", nil, map[string]string{
				"Location": blobOrigin + "/layer",
			}), nil
		case "tokens.example":
			return registryResponse(http.StatusOK, "application/json", []byte(`{"token":"fixture-token"}`), nil), nil
		case "objects.example":
			return registryResponse(http.StatusOK, registry.MediaTypeTemplateYAML, fixture.template, nil), nil
		default:
			return registryResponse(http.StatusNotFound, "", nil, nil), nil
		}
	})
	resolver, err := registry.NewResolver(registry.Options{
		Client:                 client,
		AllowedRegistryOrigins: []string{registryOrigin},
		AllowedTokenOrigins: map[string]registry.TokenOriginPolicy{
			registryOrigin: {Origin: tokenOrigin, Service: "registry.example"},
		},
		AllowedBlobOrigins: map[string][]string{registryOrigin: {blobOrigin}},
		CredentialProvider: &recordingCredentialProvider{},
		OriginValidator:    validator,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest")); err != nil {
		t.Fatalf("ResolveOCIArtifact() error = %v", err)
	}
	validator.mu.Lock()
	defer validator.mu.Unlock()
	for _, kind := range []registry.RequestOriginKind{
		registry.RequestOriginRegistry,
		registry.RequestOriginToken,
		registry.RequestOriginBlobRedirect,
	} {
		if validator.counts[kind] == 0 {
			t.Errorf("origin validator calls[%q] = 0", kind)
		}
	}
}

type recordingCredentialProvider struct {
	mu         sync.Mutex
	credential registry.Credential
	calls      []registry.CredentialRequest
}

func (p *recordingCredentialProvider) LookupCredential(_ context.Context, request registry.CredentialRequest) (registry.Credential, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = append(p.calls, request)
	return p.credential, nil
}

type recordingOriginValidator struct {
	mu     sync.Mutex
	counts map[registry.RequestOriginKind]int
}

func (v *recordingOriginValidator) ValidateRequestOrigin(_ context.Context, request registry.RequestOriginValidationRequest) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.counts == nil {
		v.counts = make(map[registry.RequestOriginKind]int)
	}
	v.counts[request.Kind]++
	return nil
}
