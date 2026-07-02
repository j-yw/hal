package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
)

var phase25CredentialProxyJSONFields = []string{
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
			for _, marker := range phase25CredentialProxySourceMarkers() {
				if strings.Contains(source, marker) {
					t.Fatalf("%s contains Phase 25 credential proxy persistence marker %q", file, marker)
				}
			}
		})
	}
}

func TestFactoryPersistenceOmitsCredentialProxyMetadataInPhase25(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 12, 45, 0, 0, time.UTC)
	_, metadata := factorySandboxPersistentMetadataFromState(factorySandboxExecutorRequest{}, factory.RunRecord{}, &sandbox.SandboxState{
		Name:     "factory-no-credential-proxy-metadata",
		Provider: "fake",
		Status:   sandbox.StatusRunning,
	})
	if metadata == nil {
		t.Fatal("factorySandboxPersistentMetadataFromState() metadata = nil")
	}
	assertJSONOmitsCredentialProxyMetadata(t, "factory sandbox metadata", metadata)

	record := factory.RunRecord{
		RunID:        "run-no-credential-proxy-metadata",
		Status:       factory.RunStatusRunning,
		ExecutorMode: factory.ExecutorModeSandbox,
		Source: factory.SourceMetadata{
			Kind: factory.SourceKindPRD,
			Path: ".hal/prd.json",
		},
		RepoPath:    "/repo",
		RepoRemote:  "origin",
		BranchName:  "hal/phase-25-credential-proxy-plan",
		BaseBranch:  "main",
		SandboxName: metadata.Name,
		Sandbox:     metadata,
		CurrentStep: "run",
		CreatedAt:   startedAt,
		UpdatedAt:   startedAt,
	}
	assertJSONOmitsCredentialProxyMetadata(t, "factory run record", record)

	event := factory.EventRecord{
		Sequence:  1,
		RunID:     record.RunID,
		EventType: factory.EventTypeRunCreated,
		Timestamp: startedAt,
		Message:   "factory run created",
		Metadata: map[string]any{
			"executorMode": factory.ExecutorModeSandbox,
			"sandboxName":  metadata.Name,
		},
	}
	assertJSONOmitsCredentialProxyMetadata(t, "factory timeline event", event)
}

func TestPhase25FactorySourcesDoNotPersistCredentialProxyMetadata(t *testing.T) {
	files := []string{
		filepath.Join("..", "internal", "factory", "types.go"),
		"factory.go",
		"factory_sandbox_executor.go",
	}
	for _, file := range files {
		t.Run(file, func(t *testing.T) {
			content, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("ReadFile(%s) error = %v", file, err)
			}
			source := string(content)
			for _, marker := range phase25CredentialProxySourceMarkers() {
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
	for _, field := range phase25CredentialProxyJSONFields {
		if _, ok := fields[field]; ok {
			encoded, err := json.Marshal(manifest)
			if err != nil {
				t.Fatalf("Marshal(manifest) error = %v", err)
			}
			t.Fatalf("manifest unexpectedly includes Phase 25 credential proxy field %q: %s", field, encoded)
		}
	}
}

func assertJSONOmitsCredentialProxyMetadata(t *testing.T, label string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error = %v", label, err)
	}
	encoded := string(data)
	for _, field := range phase25CredentialProxyJSONFields {
		if strings.Contains(encoded, `"`+field+`"`) {
			t.Fatalf("%s unexpectedly includes Phase 25 credential proxy field %q: %s", label, field, encoded)
		}
	}
}

func phase25CredentialProxySourceMarkers() []string {
	markers := make([]string, 0, len(phase25CredentialProxyJSONFields)*3)
	for _, field := range phase25CredentialProxyJSONFields {
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
