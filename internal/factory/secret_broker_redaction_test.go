package factory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecretBrokerMarshalSafety(t *testing.T) {
	secretValue := "p@ss word 123"
	broker := NewInMemorySecretBroker()

	metadata, err := broker.CreateSession(SecretBrokerSessionRequest{
		ID: "session-marshal-safe",
		RequestedInputs: []RunSecretInput{{
			Name:     "DEPLOY_TOKEN",
			Source:   RunSecretSourceEnv,
			Required: true,
		}},
		ResolvedSecrets: []ResolvedRunSecret{{
			Name:     "DEPLOY_TOKEN",
			Source:   RunSecretSourceEnv,
			Required: true,
			Value:    secretValue,
		}},
		RequestedDeliveryModes: []string{SecretBrokerDeliveryModeEnv},
		ActiveDeliveryModes:    []string{SecretBrokerDeliveryModeEnv},
	})
	if err != nil {
		t.Fatalf("CreateSession() unexpected error: %v", err)
	}

	resolved, ok := broker.LookupSecretByName(metadata.ID, "DEPLOY_TOKEN")
	if !ok {
		t.Fatalf("LookupSecretByName() missing live secret")
	}
	if resolved.Value != secretValue {
		t.Fatalf("LookupSecretByName() value = %q, want raw live value", resolved.Value)
	}

	record := testRunRecord("run-secret-broker-marshal")
	record.Secrets = []RunSecretMetadata{metadata.Secrets[0].RunSecretMetadata()}
	commandJSON := struct {
		Run    RunRecord                   `json:"run"`
		Broker SecretBrokerSessionMetadata `json:"broker"`
		Input  RunSecretInput              `json:"input"`
	}{
		Run:    record,
		Broker: metadata,
		Input:  metadata.Secrets[0].RunSecretInput(),
	}

	encoded := mustMarshalSecretBrokerRedactionJSON(t, commandJSON)
	assertNoSecretBrokerPayloadLeak(t, encoded, secretValue)
	if strings.Contains(encoded, `"value"`) || strings.Contains(encoded, `"Value"`) {
		t.Fatalf("durable broker JSON should not contain a value field: %s", encoded)
	}
}

func TestSecretBrokerRedactionAcrossDurableFactorySurfaces(t *testing.T) {
	secretValue := "p@ss word 123"
	encodedSecret := url.QueryEscape(secretValue)
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{{
		Name:     "DEPLOY_TOKEN",
		Source:   RunSecretSourceEnv,
		Required: true,
		Value:    secretValue,
	}})

	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	record := testRunRecord("run-secret-broker-redaction")
	record.RepoRemote = fmt.Sprintf("https://git:%s@example.invalid/repo.git", encodedSecret)
	record.Failure = &FailureSummary{
		Step:             RunDurationStepEngineRun,
		Category:         FailureCategoryRun,
		Message:          "engine failed with " + secretValue,
		Recoverable:      true,
		SuggestedCommand: "retry with " + encodedSecret,
	}
	record.Artifacts = []ArtifactReference{{
		ID:       "output-" + secretValue,
		Name:     "output-" + secretValue,
		Type:     "json",
		Path:     ".hal/reports/" + secretValue + ".json",
		Summary:  map[string]any{"token": secretValue, "nested": []map[string]string{{"encoded": encodedSecret}}},
		Warnings: []string{"warning includes " + secretValue},
	}}
	record.Secrets = []RunSecretMetadata{{
		Name:     "DEPLOY_TOKEN",
		Source:   RunSecretSourceEnv,
		Required: true,
		Present:  true,
	}}
	if err := store.SaveRunWithRedactor(&record, redactor); err != nil {
		t.Fatalf("SaveRunWithRedactor() unexpected error: %v", err)
	}

	sourcePath := filepath.Join(t.TempDir(), "artifact-"+secretValue+".json")
	sourcePayload := fmt.Sprintf(`{"token":%q,"encoded":%q}`+"\n", secretValue, encodedSecret)
	if err := os.WriteFile(sourcePath, []byte(sourcePayload), 0o600); err != nil {
		t.Fatalf("write source artifact: %v", err)
	}
	if _, err := store.SaveArtifactFileWithRedactor(record.RunID, ArtifactReference{
		ID:       "artifact-" + secretValue,
		Name:     "artifact-" + secretValue,
		Type:     "json",
		Path:     ".hal/reports/artifact-" + secretValue + ".json",
		Summary:  map[string]any{"token": secretValue},
		Warnings: []string{"artifact warning " + encodedSecret},
	}, sourcePath, redactor); err != nil {
		t.Fatalf("SaveArtifactFileWithRedactor() unexpected error: %v", err)
	}

	event := EventRecord{
		Sequence:  1,
		RunID:     record.RunID,
		EventType: EventTypeCommandOutputSummary,
		Timestamp: time.Date(2026, 7, 2, 2, 40, 0, 0, time.UTC),
		Message:   "command emitted " + secretValue,
		Summary:   "summary contains " + encodedSecret,
		Metadata: map[string]any{
			"plain":       secretValue,
			"encoded":     encodedSecret,
			"nested":      []map[string]string{{"token": secretValue}},
			secretValue:   "secret key redacted",
			"safeControl": EventTypeCommandOutputSummary,
		},
	}
	if err := store.AppendEventWithRedactor(&event, redactor); err != nil {
		t.Fatalf("AppendEventWithRedactor() unexpected error: %v", err)
	}

	chunk := LogChunk{
		RunID:     record.RunID,
		Stream:    LogStreamStderr,
		Source:    LogSourceEngine,
		Text:      "stderr includes " + secretValue,
		Summary:   "summary includes " + encodedSecret,
		CreatedAt: time.Date(2026, 7, 2, 2, 41, 0, 0, time.UTC),
	}
	if err := store.AppendLogChunkWithRedactor(&chunk, redactor); err != nil {
		t.Fatalf("AppendLogChunkWithRedactor() unexpected error: %v", err)
	}

	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() unexpected error: %v", err)
	}
	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() unexpected error: %v", err)
	}
	chunks, err := store.LoadLogChunks(record.RunID)
	if err != nil {
		t.Fatalf("LoadLogChunks() unexpected error: %v", err)
	}

	commandJSON := struct {
		Run      RunRecord     `json:"run"`
		Timeline []EventRecord `json:"timeline"`
		Logs     []LogChunk    `json:"logs"`
	}{
		Run:      *loaded,
		Timeline: events,
		Logs:     chunks,
	}
	assertNoSecretBrokerPayloadLeak(t, mustMarshalSecretBrokerRedactionJSON(t, commandJSON), secretValue)

	runPath, err := store.runRecordPath(record.RunID)
	if err != nil {
		t.Fatalf("runRecordPath() error: %v", err)
	}
	assertFileHasNoSecretBrokerPayload(t, runPath, secretValue)
	timelinePath, err := store.timelinePath(record.RunID)
	if err != nil {
		t.Fatalf("timelinePath() error: %v", err)
	}
	assertFileHasNoSecretBrokerPayload(t, timelinePath, secretValue)
	logPath, err := store.logPath(record.RunID)
	if err != nil {
		t.Fatalf("logPath() error: %v", err)
	}
	assertFileHasNoSecretBrokerPayload(t, logPath, secretValue)

	artifact := requireStoredArtifact(t, store, record.RunID, loaded.Artifacts, ".hal/reports/artifact-"+RunSecretRedactionPlaceholder+".json")
	assertNoSecretBrokerPayloadLeak(t, mustMarshalSecretBrokerRedactionJSON(t, artifact), secretValue)
	assertNoSecretBrokerPayloadLeak(t, readStoredArtifact(t, store, record.RunID, artifact), secretValue)
}

func TestSecretBrokerErrorSafety(t *testing.T) {
	secretValue := "p@ss word 123"
	encodedSecret := url.QueryEscape(secretValue)
	redactor := NewRunSecretRedactor([]ResolvedRunSecret{{
		Name:     "DEPLOY_TOKEN",
		Source:   RunSecretSourceEnv,
		Required: true,
		Value:    secretValue,
	}})

	cause := errors.New("provider returned token " + secretValue + " encoded " + encodedSecret)
	safeErr := redactor.RedactError(cause)
	if !errors.Is(safeErr, cause) {
		t.Fatalf("RedactError() should preserve unwrap chain")
	}
	assertNoSecretBrokerPayloadLeak(t, safeErr.Error(), secretValue)
	if !strings.Contains(safeErr.Error(), RunSecretRedactionPlaceholder) {
		t.Fatalf("RedactError() = %q, want redaction placeholder", safeErr.Error())
	}

	_, err := ValidateSecretBrokerDeliveryModes(SecretBrokerDeliveryModeValidationRequest{
		RequestedModes: []string{"unsupported-" + secretValue},
	})
	if err == nil {
		t.Fatalf("ValidateSecretBrokerDeliveryModes() expected error")
	}
	assertNoSecretBrokerPayloadLeak(t, err.Error(), secretValue)

	_, err = NewInMemorySecretBroker().CreateSession(SecretBrokerSessionRequest{
		ID: "session-error-safe",
		ResolvedSecrets: []ResolvedRunSecret{
			{Name: "DEPLOY_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: secretValue},
			{Name: "DEPLOY_TOKEN", Source: RunSecretSourceEnv, Required: true, Value: secretValue},
		},
	})
	if err == nil {
		t.Fatalf("CreateSession() expected duplicate resolved secret error")
	}
	assertNoSecretBrokerPayloadLeak(t, err.Error(), secretValue)

	copyErr := errors.New("copy failed for " + secretValue)
	_, err = CollectSandboxArtifactsWithRedactor(context.Background(), NewStore(filepath.Join(t.TempDir(), "factory")), "run-secret-broker-error", &fakeSandboxArtifactCopier{
		fileErrs: map[string]error{
			"/workspace/" + secretValue + "/factory.log": copyErr,
		},
	}, []SandboxArtifactRequest{{
		ID:         "factory-log",
		Name:       "factory-log-" + secretValue,
		Type:       "text",
		RemotePath: "/workspace/" + secretValue + "/factory.log",
		Path:       ".hal/reports/factory.log",
	}}, redactor)
	if !errors.Is(err, copyErr) {
		t.Fatalf("CollectSandboxArtifactsWithRedactor() error = %v, want wrapped copy error", err)
	}
	assertNoSecretBrokerPayloadLeak(t, err.Error(), secretValue)
}

func mustMarshalSecretBrokerRedactionJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	return string(data)
}

func assertFileHasNoSecretBrokerPayload(t *testing.T, path string, secretValue string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q) error: %v", path, err)
	}
	assertNoSecretBrokerPayloadLeak(t, string(data), secretValue)
}

func assertNoSecretBrokerPayloadLeak(t *testing.T, value string, secretValue string) {
	t.Helper()
	for _, needle := range []string{
		secretValue,
		url.QueryEscape(secretValue),
		url.PathEscape(secretValue),
		strings.TrimPrefix(url.UserPassword("__hal_secret__", secretValue).String(), "__hal_secret__:"),
	} {
		if strings.TrimSpace(needle) == "" {
			continue
		}
		if strings.Contains(value, needle) {
			t.Fatalf("value leaked secret payload %q in: %s", needle, value)
		}
	}
}
