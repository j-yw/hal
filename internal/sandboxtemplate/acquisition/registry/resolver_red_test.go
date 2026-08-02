package registry_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxtemplate"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition"
	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
)

const registryOrigin = "https://registry.example"

func TestL9RegistryResolverVerifiesBytesAndCachesOnlyLayerByManifestDigest(t *testing.T) {
	fixture := newRegistryFixture(t)
	var mu sync.Mutex
	manifestGets := 0
	blobGets := 0
	client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if got := request.Header.Get("Accept"); got != registry.MediaTypeOCIManifest && strings.Contains(request.URL.Path, "/manifests/") {
			t.Fatalf("manifest Accept = %q", got)
		}
		switch {
		case strings.Contains(request.URL.Path, "/manifests/"):
			manifestGets++
			return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, map[string]string{
				"Docker-Content-Digest": fixture.manifestDigest,
				"Content-Length":        "1", // Deliberately false; body bytes remain authoritative.
			}), nil
		case strings.Contains(request.URL.Path, "/blobs/"):
			blobGets++
			return registryResponse(http.StatusOK, registry.MediaTypeTemplateYAML, fixture.template, nil), nil
		default:
			return registryResponse(http.StatusNotFound, "text/plain", nil, nil), nil
		}
	})
	resolver := mustRegistryResolver(t, client, newPrivateFileCache(t))
	request := tagRequest("registry.example/hal/template:latest")

	for i := 0; i < 2; i++ {
		result, err := resolver.ResolveOCIArtifact(context.Background(), request)
		if err != nil {
			t.Fatalf("ResolveOCIArtifact(%d) error = %v", i, err)
		}
		requireDigest(t, result.TemplateArtifactDigest, fixture.manifestDigest)
		requireDigest(t, result.DocumentDigest, fixture.layerDigest)
		if !bytes.Equal(result.ArtifactManifestBytes, fixture.manifest) {
			t.Fatal("manifest evidence bytes differ from verified response")
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if manifestGets != 4 {
		t.Fatalf("manifest GETs = %d, want 4 live resolutions", manifestGets)
	}
	if blobGets != 1 {
		t.Fatalf("blob GETs = %d, want one verified cache fill", blobGets)
	}
}

func TestL9RegistryResolverDigestPinnedGETMatchesRequestedBytes(t *testing.T) {
	fixture := newRegistryFixture(t)
	client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(request.URL.Path, "/manifests/") {
			if !strings.HasSuffix(request.URL.Path, "/manifests/"+fixture.manifestDigest) {
				t.Fatalf("manifest path = %q, want digest selector", request.URL.Path)
			}
			return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, nil), nil
		}
		if strings.Contains(request.URL.Path, "/blobs/") {
			return registryResponse(http.StatusOK, registry.MediaTypeTemplateYAML, fixture.template, nil), nil
		}
		return registryResponse(http.StatusNotFound, "", nil, nil), nil
	})
	resolver := mustRegistryResolver(t, client, nil)
	requests := []acquisition.OCIArtifactResolveRequest{
		digestRequest("registry.example/hal/template", fixture.manifest),
		tagRequest("registry.example/hal/template@" + fixture.manifestDigest),
	}
	for _, request := range requests {
		result, err := resolver.ResolveOCIArtifact(context.Background(), request)
		if err != nil {
			t.Fatalf("ResolveOCIArtifact() error = %v", err)
		}
		requireDigest(t, result.TemplateArtifactDigest, fixture.manifestDigest)
	}
}

func TestL9RegistryResolverSeparatesHeaderAndRequestedDigestMismatch(t *testing.T) {
	fixture := newRegistryFixture(t)
	tests := []struct {
		name    string
		request acquisition.OCIArtifactResolveRequest
		header  string
		want    registry.ErrorCode
	}{
		{
			name:    "captured header disagrees with bytes",
			request: tagRequest("registry.example/hal/template:latest"),
			header:  "sha256:" + strings.Repeat("f", 64),
			want:    registry.ErrorCodeManifestDigestMismatch,
		},
		{
			name:    "requested digest disagrees with bytes",
			request: digestRequest("registry.example/hal/template", []byte("different manifest")),
			want:    registry.ErrorCodeManifestDigestMismatch,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fakeHTTPDoer(func(*http.Request) (*http.Response, error) {
				headers := map[string]string{}
				if tt.header != "" {
					headers["Docker-Content-Digest"] = tt.header
				}
				return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, headers), nil
			})
			resolver := mustRegistryResolver(t, client, nil)
			_, err := resolver.ResolveOCIArtifact(context.Background(), tt.request)
			requireRegistryErrorCode(t, err, tt.want)
		})
	}
}

func TestL9RegistryResolverFailsClosedOnValidTagMutation(t *testing.T) {
	fixture := newRegistryFixture(t)
	mutated := append([]byte(" "), fixture.manifest...) // Still valid JSON, distinct verified bytes.
	manifestGets := 0
	client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
		switch {
		case strings.Contains(request.URL.Path, "/manifests/"):
			manifestGets++
			body := fixture.manifest
			if manifestGets == 2 {
				body = mutated
			}
			return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, body, nil), nil
		case strings.Contains(request.URL.Path, "/blobs/"):
			return registryResponse(http.StatusOK, registry.MediaTypeTemplateYAML, fixture.template, nil), nil
		default:
			return registryResponse(http.StatusNotFound, "", nil, nil), nil
		}
	})
	resolver := mustRegistryResolver(t, client, nil)
	_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
	requireRegistryErrorCode(t, err, registry.ErrorCodeTagMutated)
}

func TestL9RegistryResolverRejectsResponseAndBodyBoundaryViolations(t *testing.T) {
	fixture := newRegistryFixture(t)
	tests := []struct {
		name        string
		status      int
		contentType string
		headers     map[string]string
		body        []byte
		want        registry.ErrorCode
	}{
		{"status", http.StatusInternalServerError, "text/plain", nil, nil, registry.ErrorCodeRegistryUnavailable},
		{"content type mismatch", http.StatusOK, registry.MediaTypeTemplateYAML, nil, fixture.manifest, registry.ErrorCodeManifestMediaTypeUnsupported},
		{"encoded response", http.StatusOK, registry.MediaTypeOCIManifest, map[string]string{"Content-Encoding": "gzip"}, fixture.manifest, registry.ErrorCodeManifestInvalid},
		{"actual body oversize without length", http.StatusOK, registry.MediaTypeOCIManifest, nil, bytes.Repeat([]byte("x"), registry.DefaultMaxManifestBytes+1), registry.ErrorCodeManifestOversize},
		{"actual body oversize with false length", http.StatusOK, registry.MediaTypeOCIManifest, map[string]string{"Content-Length": "1"}, bytes.Repeat([]byte("x"), registry.DefaultMaxManifestBytes+1), registry.ErrorCodeManifestOversize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fakeHTTPDoer(func(*http.Request) (*http.Response, error) {
				return registryResponse(tt.status, tt.contentType, tt.body, tt.headers), nil
			})
			resolver := mustRegistryResolver(t, client, nil)
			_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
			requireRegistryErrorCode(t, err, tt.want)
		})
	}
}

func TestL9RegistryResolverRejectsResponseHeaderBytesOverLimit(t *testing.T) {
	fixture := newRegistryFixture(t)
	client := fakeHTTPDoer(func(*http.Request) (*http.Response, error) {
		return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, map[string]string{
			"X-Oversized-Response": strings.Repeat("x", registry.DefaultMaxResponseHeaderBytes+1),
		}), nil
	})
	resolver := mustRegistryResolver(t, client, nil)
	_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
	requireRegistryErrorCode(t, err, registry.ErrorCodeResponseHeadersOversize)
}

func TestL9RegistryResolverRejectsUnsupportedManifestShapesAndDescriptors(t *testing.T) {
	fixture := newRegistryFixture(t)
	tests := []struct {
		name   string
		mutate func(map[string]any)
		want   registry.ErrorCode
	}{
		{"schema", func(m map[string]any) { m["schemaVersion"] = 1 }, registry.ErrorCodeManifestInvalid},
		{"manifest media", func(m map[string]any) { m["mediaType"] = "application/vnd.oci.image.index.v1+json" }, registry.ErrorCodeManifestMediaTypeUnsupported},
		{"artifact type", func(m map[string]any) { m["artifactType"] = "application/unknown" }, registry.ErrorCodeArtifactTypeUnsupported},
		{"manifest extension", func(m map[string]any) { m["annotations"] = map[string]string{"x": "y"} }, registry.ErrorCodeManifestInvalid},
		{"subject", func(m map[string]any) { m["subject"] = map[string]any{} }, registry.ErrorCodeManifestInvalid},
		{"config extension", func(m map[string]any) { m["config"].(map[string]any)["urls"] = []string{"https://foreign.invalid"} }, registry.ErrorCodeManifestInvalid},
		{"config media", func(m map[string]any) { m["config"].(map[string]any)["mediaType"] = "application/json" }, registry.ErrorCodeManifestInvalid},
		{"config oversize", func(m map[string]any) { m["config"].(map[string]any)["size"] = float64(3) }, registry.ErrorCodeManifestInvalid},
		{"no layers", func(m map[string]any) { m["layers"] = []any{} }, registry.ErrorCodeLayerCountInvalid},
		{"two layers", func(m map[string]any) { layer := m["layers"].([]any)[0]; m["layers"] = []any{layer, layer} }, registry.ErrorCodeLayerCountInvalid},
		{"foreign layer URL", func(m map[string]any) {
			m["layers"].([]any)[0].(map[string]any)["urls"] = []string{"https://foreign.invalid"}
		}, registry.ErrorCodeManifestInvalid},
		{"layer media", func(m map[string]any) {
			m["layers"].([]any)[0].(map[string]any)["mediaType"] = "application/octet-stream"
		}, registry.ErrorCodeLayerMediaTypeUnsupported},
		{"layer oversize", func(m map[string]any) {
			m["layers"].([]any)[0].(map[string]any)["size"] = float64(registry.DefaultMaxLayerBytes + 1)
		}, registry.ErrorCodeLayerOversize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var manifest map[string]any
			if err := json.Unmarshal(fixture.manifest, &manifest); err != nil {
				t.Fatal(err)
			}
			tt.mutate(manifest)
			body, err := json.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			client := fakeHTTPDoer(func(*http.Request) (*http.Response, error) {
				return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, body, nil), nil
			})
			resolver := mustRegistryResolver(t, client, nil)
			_, resolveErr := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
			requireRegistryErrorCode(t, resolveErr, tt.want)
		})
	}
}

func TestL9RegistryResolverRejectsLayerDigestMismatchWithoutFallback(t *testing.T) {
	fixture := newRegistryFixture(t)
	client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(request.URL.Path, "/manifests/") {
			return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, nil), nil
		}
		return registryResponse(http.StatusOK, registry.MediaTypeTemplateYAML, []byte("wrong bytes"), nil), nil
	})
	resolver := mustRegistryResolver(t, client, nil)
	_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
	requireRegistryErrorCode(t, err, registry.ErrorCodeLayerDigestMismatch)
}

func TestL9RegistryResolverCancellationAndDeadlineHaveDistinctCodes(t *testing.T) {
	fixture := newRegistryFixture(t)
	tests := []struct {
		name string
		ctx  func() context.Context
		err  error
		want registry.ErrorCode
	}{
		{"canceled", func() context.Context { ctx, cancel := context.WithCancel(context.Background()); cancel(); return ctx }, context.Canceled, registry.ErrorCodeRequestCanceled},
		{"timeout", func() context.Context { return context.Background() }, context.DeadlineExceeded, registry.ErrorCodeRequestTimeout},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := fakeHTTPDoer(func(*http.Request) (*http.Response, error) {
				return nil, tt.err
			})
			resolver := mustRegistryResolver(t, client, nil)
			_, err := resolver.ResolveOCIArtifact(tt.ctx(), tagRequest("registry.example/hal/template:latest"))
			requireRegistryErrorCode(t, err, tt.want)
			_ = fixture
		})
	}
}

func TestL9RegistryResolverDeadlineDuringSharedLayerFetchIsRequestTimeout(t *testing.T) {
	fixture := newRegistryFixture(t)
	client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(request.URL.Path, "/manifests/") {
			return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, nil), nil
		}
		<-request.Context().Done()
		return nil, request.Context().Err()
	})
	resolver, err := registry.NewResolver(registry.Options{
		Client:                 client,
		AllowedRegistryOrigins: []string{registryOrigin},
		RequestTimeout:         20 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	_, err = resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
	requireRegistryErrorCode(t, err, registry.ErrorCodeRequestTimeout)
}

func TestL9RegistryResolverRechecksCancellationAfterCachePublicationWork(t *testing.T) {
	fixture := newRegistryFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cache := &cancelingRegistryCache{cancel: cancel}
	client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(request.URL.Path, "/manifests/") {
			return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, nil), nil
		}
		return registryResponse(http.StatusOK, registry.MediaTypeTemplateYAML, fixture.template, nil), nil
	})
	resolver := mustRegistryResolver(t, client, cache)
	result, err := resolver.ResolveOCIArtifact(ctx, tagRequest("registry.example/hal/template:latest"))
	requireRegistryErrorCode(t, err, registry.ErrorCodeRequestCanceled)
	if len(result.TemplateBytes) != 0 || result.TemplateArtifactDigest != nil {
		t.Fatalf("canceled resolution returned selection evidence: %#v", result)
	}
	if cache.stores != 1 {
		t.Fatalf("cache stores = %d, want one cancellation seam", cache.stores)
	}
}

func TestL9RegistryErrorsNeverExposeDynamicInputs(t *testing.T) {
	canary := "ghp_l9_registry_secret"
	client := fakeHTTPDoer(func(*http.Request) (*http.Response, error) {
		return registryResponse(http.StatusUnauthorized, "", nil, map[string]string{
			"WWW-Authenticate": `Bearer realm="https://invalid.example/token?token=` + canary + `"`,
		}), nil
	})
	resolver := mustRegistryResolver(t, client, nil)
	reference := "registry.example/private/template:latest"
	_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest(reference))
	if err == nil {
		t.Fatal("ResolveOCIArtifact() error = nil")
	}
	for _, forbidden := range []string{reference, registryOrigin, canary, "invalid.example", "private/template"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked %q: %v", forbidden, err)
		}
	}
}

func TestL9RegistryResolverDoesNotFallbackToCacheWhenLiveManifestUnavailable(t *testing.T) {
	fixture := newRegistryFixture(t)
	cache := newPrivateFileCache(t)
	if err := cache.Store(context.Background(), registry.CacheEntry{
		ManifestDigest: fixture.manifestDigest,
		LayerDigest:    fixture.layerDigest,
		MediaType:      registry.MediaTypeTemplateYAML,
		LayerBytes:     fixture.template,
	}); err != nil {
		t.Fatalf("seed cache: %v", err)
	}
	client := fakeHTTPDoer(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})
	resolver := mustRegistryResolver(t, client, cache)
	_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
	requireRegistryErrorCode(t, err, registry.ErrorCodeRegistryUnavailable)
}

func TestL9TagDescriptorMutationPublishesNeitherFirstResultNorCacheEntry(t *testing.T) {
	fixture := newRegistryFixture(t)
	secondTemplate := append([]byte(nil), fixture.template...)
	secondTemplate = append(secondTemplate, []byte("\n# second valid template")...)
	secondLayerDigest := registryDigest(secondTemplate)
	var manifest map[string]any
	if err := json.Unmarshal(fixture.manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	layer := manifest["layers"].([]any)[0].(map[string]any)
	layer["digest"] = secondLayerDigest
	layer["size"] = len(secondTemplate)
	secondManifest, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestGets := 0
	client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
		if strings.Contains(request.URL.Path, "/manifests/") {
			manifestGets++
			body := fixture.manifest
			if manifestGets == 2 {
				body = secondManifest
			}
			return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, body, nil), nil
		}
		return registryResponse(http.StatusOK, registry.MediaTypeTemplateYAML, fixture.template, nil), nil
	})
	cache := newPrivateFileCache(t)
	resolver := mustRegistryResolver(t, client, cache)
	result, resolveErr := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
	requireRegistryErrorCode(t, resolveErr, registry.ErrorCodeTagMutated)
	if result.TemplateArtifactDigest != nil || len(result.TemplateBytes) != 0 {
		t.Fatalf("mutation returned first selection: %#v", result)
	}
	_, hit, loadErr := cache.Load(context.Background(), registry.CacheLookup{
		ManifestDigest: fixture.manifestDigest,
		LayerDigest:    fixture.layerDigest,
		MediaType:      registry.MediaTypeTemplateYAML,
		SizeBytes:      int64(len(fixture.template)),
	})
	if loadErr != nil {
		t.Fatalf("Load() after mutation error = %v", loadErr)
	}
	if hit {
		t.Fatal("tag mutation published first layer into cache")
	}
}

func TestL9ConcurrentResolverSelectionsCoalesceBlobFetchWithoutSkippingLiveManifest(t *testing.T) {
	for round := 0; round < 20; round++ {
		t.Run(strconv.Itoa(round), testL9ConcurrentResolverSelectionsCoalesceBlobFetch)
	}
}

func testL9ConcurrentResolverSelectionsCoalesceBlobFetch(t *testing.T) {
	fixture := newRegistryFixture(t)
	var mu sync.Mutex
	manifestGets := 0
	blobGets := 0
	client := fakeHTTPDoer(func(request *http.Request) (*http.Response, error) {
		mu.Lock()
		defer mu.Unlock()
		if strings.Contains(request.URL.Path, "/manifests/") {
			manifestGets++
			return registryResponse(http.StatusOK, registry.MediaTypeOCIManifest, fixture.manifest, nil), nil
		}
		blobGets++
		return registryResponse(http.StatusOK, registry.MediaTypeTemplateYAML, fixture.template, nil), nil
	})
	resolver := mustRegistryResolver(t, client, newPrivateFileCache(t))
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest("registry.example/hal/template:latest"))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent ResolveOCIArtifact() error = %v", err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if manifestGets != 24 {
		t.Fatalf("manifest GETs = %d, want live first/second resolution per caller", manifestGets)
	}
	if blobGets != 1 {
		t.Fatalf("blob GETs = %d, want one coalesced fetch", blobGets)
	}
}

type registryFixture struct {
	template       []byte
	manifest       []byte
	layerDigest    string
	manifestDigest string
}

func newRegistryFixture(t *testing.T) registryFixture {
	t.Helper()
	templateBytes := []byte(`apiVersion: sandbox-template.hal.dev/v1
kind: SandboxTemplate
metadata:
  id: local-registry-template
runtime:
  driver: microvm
  isolationLevel: vm
`)
	layerDigest := registryDigest(templateBytes)
	manifestObject := map[string]any{
		"schemaVersion": 2,
		"mediaType":     registry.MediaTypeOCIManifest,
		"artifactType":  registry.MediaTypeTemplateArtifact,
		"config": map[string]any{
			"mediaType": registry.MediaTypeOCIEmptyConfig,
			"digest":    "sha256:" + strings.Repeat("0", 64),
			"size":      2,
		},
		"layers": []any{map[string]any{
			"mediaType": registry.MediaTypeTemplateYAML,
			"digest":    layerDigest,
			"size":      len(templateBytes),
		}},
	}
	manifestBytes, err := json.Marshal(manifestObject)
	if err != nil {
		t.Fatalf("Marshal(manifest) error = %v", err)
	}
	return registryFixture{
		template:       templateBytes,
		manifest:       manifestBytes,
		layerDigest:    layerDigest,
		manifestDigest: registryDigest(manifestBytes),
	}
}

func mustRegistryResolver(t *testing.T, client registry.HTTPDoer, cache registry.Cache) *registry.Resolver {
	t.Helper()
	resolver, err := registry.NewResolver(registry.Options{
		Client:                 client,
		AllowedRegistryOrigins: []string{registryOrigin},
		Cache:                  cache,
		RequestTimeout:         registry.DefaultRequestTimeout,
	})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	return resolver
}

func tagRequest(ref string) acquisition.OCIArtifactResolveRequest {
	return acquisition.OCIArtifactResolveRequest{Reference: sandboxtemplate.ImmutableRef{
		Kind: sandboxtemplate.ReferenceKindOCIArtifact,
		Ref:  ref,
	}}
}

func digestRequest(ref string, expected []byte) acquisition.OCIArtifactResolveRequest {
	return acquisition.OCIArtifactResolveRequest{Reference: sandboxtemplate.ImmutableRef{
		Kind:   sandboxtemplate.ReferenceKindOCIArtifact,
		Ref:    ref,
		Digest: registryTestDigest(expected),
	}}
}

func registryResponse(status int, mediaType string, body []byte, headers map[string]string) *http.Response {
	header := make(http.Header)
	if mediaType != "" {
		header.Set("Content-Type", mediaType)
	}
	for key, value := range headers {
		header.Set(key, value)
	}
	return &http.Response{
		StatusCode: status,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

type fakeHTTPDoer func(*http.Request) (*http.Response, error)

func (f fakeHTTPDoer) Do(request *http.Request) (*http.Response, error) {
	return f(request)
}

type cancelingRegistryCache struct {
	cancel context.CancelFunc
	stores int
}

func (*cancelingRegistryCache) Load(context.Context, registry.CacheLookup) ([]byte, bool, error) {
	return nil, false, nil
}

func (c *cancelingRegistryCache) Store(context.Context, registry.CacheEntry) error {
	c.stores++
	c.cancel()
	return nil
}

func registryDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func registryTestDigest(data []byte) *sandboxtemplate.DigestMetadata {
	sum := sha256.Sum256(data)
	return &sandboxtemplate.DigestMetadata{
		Algorithm: sandboxtemplate.DigestAlgorithmSHA256,
		Value:     hex.EncodeToString(sum[:]),
	}
}

func requireDigest(t *testing.T, got *sandboxtemplate.DigestMetadata, want string) {
	t.Helper()
	if got == nil || "sha256:"+got.Value != want {
		t.Fatalf("digest = %#v, want %s", got, want)
	}
}

func requireRegistryErrorCode(t *testing.T, err error, code registry.ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}
	if !strings.Contains(err.Error(), string(code)) {
		t.Fatalf("error = %q, want safe code %s", err, code)
	}
	for _, forbidden := range []string{"registry.example", "127.0.0.1", "ghp_", "token="} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("error leaked %q: %v", forbidden, err)
		}
	}
}
