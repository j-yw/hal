package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxexecution"
)

var phase25NonFactoryCredentialProxyJSONFields = []string{
	"credentialProxy",
	"credentialProxyPlan",
	"credentialProxySession",
	"credentialProxyBindings",
}

func TestRunAndAutoSandboxManifestsOmitCredentialProxyMetadataInPhase25(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 12, 20, 0, 0, time.UTC)

	runStore := sandboxexecution.NewStore(t.TempDir())
	if err := saveRunSandboxManifest(runStore, runSandboxRequest{
		ExecutionID: "run-no-credential-proxy-metadata",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveRunSandboxManifest() error = %v", err)
	}
	assertSandboxManifestOmitsCredentialProxyMetadata(t, mustLoadSandboxExecutionManifest(t, runStore, "run-no-credential-proxy-metadata"))

	autoStore := sandboxexecution.NewStore(t.TempDir())
	if err := saveAutoSandboxManifest(autoStore, autoSandboxRequest{
		ExecutionID: "auto-no-credential-proxy-metadata",
		ProjectDir:  "/repo",
	}, sandboxexecution.StatusRunning, startedAt, nil, nil); err != nil {
		t.Fatalf("saveAutoSandboxManifest() error = %v", err)
	}
	assertSandboxManifestOmitsCredentialProxyMetadata(t, mustLoadSandboxExecutionManifest(t, autoStore, "auto-no-credential-proxy-metadata"))
}

func TestPhase25NonFactoryManifestSourcesDoNotPersistCredentialProxyMetadata(t *testing.T) {
	files := []string{
		"run_sandbox.go",
		"auto_sandbox.go",
		filepath.Join("..", "internal", "sandboxexecution", "types.go"),
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			content, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("ReadFile(%s) error = %v", file, err)
			}
			source := string(content)
			for _, marker := range phase25NonFactoryCredentialProxySourceMarkers() {
				if strings.Contains(source, marker) {
					t.Fatalf("%s contains Phase 25 credential proxy persistence marker %q", file, marker)
				}
			}
		})
	}
}

func assertSandboxManifestOmitsCredentialProxyMetadata(t *testing.T, manifest *sandboxexecution.Manifest) {
	t.Helper()
	fields := sandboxManifestJSONFields(t, manifest)
	for _, field := range phase25NonFactoryCredentialProxyJSONFields {
		if _, ok := fields[field]; ok {
			encoded, err := json.Marshal(manifest)
			if err != nil {
				t.Fatalf("Marshal(manifest) error = %v", err)
			}
			t.Fatalf("manifest unexpectedly includes Phase 25 credential proxy field %q: %s", field, encoded)
		}
	}
}

func phase25NonFactoryCredentialProxySourceMarkers() []string {
	markers := make([]string, 0, len(phase25NonFactoryCredentialProxyJSONFields)*3)
	for _, field := range phase25NonFactoryCredentialProxyJSONFields {
		markers = append(markers, `json:"`+field)
		if suffix, ok := strings.CutPrefix(field, "credential"); ok {
			camel := "Credential" + suffix
			markers = append(markers,
				camel+":",
				"\t"+camel+" ",
				"\t"+camel+"\t",
			)
		}
	}
	return markers
}
