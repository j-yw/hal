//go:build template_oci_integration

package registry_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxtemplate/acquisition/registry"
)

func TestOCIRegistryIntegrationStrictTrust(t *testing.T) {
	fixture := newRegistryFixture(t)
	local := newDisposableRegistry(t)
	server := httptest.NewServer(local)
	cacheRoot, err := os.MkdirTemp("", "hal-l9-oci-cache-")
	if err != nil {
		t.Fatal(err)
	}
	cleaned := false
	t.Cleanup(func() {
		server.Close()
		if err := os.RemoveAll(cacheRoot); err != nil {
			t.Errorf("remove cache root: %v", err)
		}
		if _, err := os.Lstat(cacheRoot); !os.IsNotExist(err) {
			t.Errorf("cache root remains after cleanup: %v", err)
		}
		if _, err := server.Client().Get(server.URL); err == nil {
			t.Error("loopback registry listener remains reachable after Close")
		}
		cleaned = true
	})

	pushRegistryFixture(t, server.Client(), server.URL, fixture)
	origin := server.URL
	resolver, err := registry.NewResolver(registry.Options{
		Client:                     server.Client(),
		AllowedRegistryOrigins:     []string{origin},
		PlainHTTPOrigins:           []string{origin},
		AllowedNonPublicOrigins:    []string{origin},
		Cache:                      registry.NewFileCache(cacheRoot),
		CredentialProvider:         &recordingCredentialProvider{credential: registry.Credential{Username: "fixture-user", Password: "fixture-password"}},
		PreemptiveBasicAuthOrigins: []string{origin},
	})
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}
	reference := strings.TrimPrefix(origin, "http://") + "/hal/template:latest"
	for i := 0; i < 2; i++ {
		result, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest(reference))
		if err != nil {
			t.Fatalf("strict local selection %d: %v", i, err)
		}
		requireDigest(t, result.TemplateArtifactDigest, fixture.manifestDigest)
		requireDigest(t, result.DocumentDigest, fixture.layerDigest)
	}
	local.mu.Lock()
	if local.blobGets != 1 {
		t.Fatalf("blob GETs = %d, want verified cache hit", local.blobGets)
	}
	if local.manifestGets != 4 {
		t.Fatalf("manifest GETs = %d, want live resolution plus tag check each time", local.manifestGets)
	}
	local.mu.Unlock()

	t.Run("tag mutation", func(t *testing.T) {
		local.setMode(registryModeTagMutation)
		_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest(reference))
		requireRegistryErrorCode(t, err, registry.ErrorCodeTagMutated)
		local.setMode(registryModeNormal)
	})
	t.Run("auth", func(t *testing.T) {
		local.setMode(registryModeAuthFailure)
		_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest(reference))
		requireRegistryErrorCode(t, err, registry.ErrorCodeAuthenticationFailed)
		local.setMode(registryModeNormal)
	})
	t.Run("digest", func(t *testing.T) {
		local.setMode(registryModeDigestMismatch)
		_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest(reference))
		requireRegistryErrorCode(t, err, registry.ErrorCodeManifestDigestMismatch)
		local.setMode(registryModeNormal)
	})
	t.Run("media", func(t *testing.T) {
		local.setMode(registryModeMediaMismatch)
		_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest(reference))
		requireRegistryErrorCode(t, err, registry.ErrorCodeManifestMediaTypeUnsupported)
		local.setMode(registryModeNormal)
	})
	t.Run("size", func(t *testing.T) {
		local.setMode(registryModeOversize)
		_, err := resolver.ResolveOCIArtifact(context.Background(), tagRequest(reference))
		requireRegistryErrorCode(t, err, registry.ErrorCodeManifestOversize)
		local.setMode(registryModeNormal)
	})

	if cleaned {
		t.Fatal("cleanup ran before integration assertions completed")
	}
}

type registryMode string

const (
	registryModeNormal         registryMode = ""
	registryModeTagMutation    registryMode = "tag_mutation"
	registryModeAuthFailure    registryMode = "auth_failure"
	registryModeDigestMismatch registryMode = "digest_mismatch"
	registryModeMediaMismatch  registryMode = "media_mismatch"
	registryModeOversize       registryMode = "oversize"
)

type disposableRegistry struct {
	t            *testing.T
	mu           sync.Mutex
	manifests    map[string][]byte
	blobs        map[string][]byte
	mode         registryMode
	manifestGets int
	blobGets     int
}

func newDisposableRegistry(t *testing.T) *disposableRegistry {
	return &disposableRegistry{
		t:         t,
		manifests: make(map[string][]byte),
		blobs:     make(map[string][]byte),
	}
}

func (r *disposableRegistry) setMode(mode registryMode) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mode = mode
	r.manifestGets = 0
}

func (r *disposableRegistry) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if request.Method == http.MethodPut {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			r.t.Errorf("read pushed body: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch {
		case strings.Contains(request.URL.Path, "/manifests/"):
			r.manifests[pathTail(request.URL.Path)] = body
		case strings.Contains(request.URL.Path, "/blobs/"):
			r.blobs[pathTail(request.URL.Path)] = body
		default:
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusCreated)
		return
	}

	if r.mode == registryModeAuthFailure {
		w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("fixture-user:fixture-password"))
	if request.Header.Get("Authorization") != wantAuth {
		w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	switch {
	case strings.Contains(request.URL.Path, "/manifests/"):
		r.manifestGets++
		body := append([]byte(nil), r.manifests[pathTail(request.URL.Path)]...)
		if len(body) == 0 {
			body = append([]byte(nil), r.manifests["latest"]...)
		}
		switch r.mode {
		case registryModeTagMutation:
			if r.manifestGets == 2 {
				body = append([]byte(" "), body...)
			}
		case registryModeDigestMismatch:
			w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("f", 64))
		case registryModeMediaMismatch:
			w.Header().Set("Content-Type", registry.MediaTypeTemplateYAML)
		case registryModeOversize:
			body = bytes.Repeat([]byte("x"), registry.DefaultMaxManifestBytes+1)
		}
		if w.Header().Get("Content-Type") == "" {
			w.Header().Set("Content-Type", registry.MediaTypeOCIManifest)
		}
		_, _ = w.Write(body)
	case strings.Contains(request.URL.Path, "/blobs/"):
		r.blobGets++
		w.Header().Set("Content-Type", registry.MediaTypeTemplateYAML)
		body := r.blobs[pathTail(request.URL.Path)]
		if len(body) == 0 {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func pushRegistryFixture(t *testing.T, client *http.Client, origin string, fixture registryFixture) {
	t.Helper()
	for path, body := range map[string][]byte{
		"/v2/hal/template/blobs/" + fixture.layerDigest:        fixture.template,
		"/v2/hal/template/manifests/latest":                    fixture.manifest,
		"/v2/hal/template/manifests/" + fixture.manifestDigest: fixture.manifest,
	} {
		request, err := http.NewRequest(http.MethodPut, origin+path, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("push %s: %v", path, err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusCreated {
			t.Fatalf("push %s status = %d", path, response.StatusCode)
		}
	}
}

func pathTail(path string) string {
	index := strings.LastIndex(path, "/")
	if index < 0 {
		return path
	}
	return path[index+1:]
}
