package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/credentialdelivery"
	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestFactorySandboxCredentialActivationMetadataProjection(t *testing.T) {
	_, metadata := factorySandboxPersistentMetadataFromState(factorySandboxExecutorRequest{
		Security:                     phase51CredentialActivationSecurity(),
		NetworkProxySession:          phase51CredentialActivationNetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceFactory),
		CredentialDeliveryActivation: phase51CredentialActivationSkippedResult(),
	}, factory.RunRecord{RunID: "run-factory-credential-activation-metadata"}, phase51FactoryCredentialActivationTarget())
	if metadata == nil {
		t.Fatal("factorySandboxPersistentMetadataFromState() metadata = nil")
	}

	assertPhase51CredentialActivationStatus(t, "factory sandbox metadata", metadata.CredentialDelivery, credentialdelivery.StatusSkipped, credentialdelivery.ReasonActivationUnavailable, 1, 0)
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "factory sandbox metadata", metadata)
	assertPhase51FactoryCredentialActivationRuntimeAndWorkerMetadataRedacted(t, metadata.CredentialDelivery)
	assertPhase51FactoryCredentialActivationDiagnosticsRedacted(t, metadata.Security)
}

func TestFactorySandboxCredentialActivationRunRecordProjection(t *testing.T) {
	result := runPhase51FactoryCredentialActivationExecutor(t, phase51CredentialActivationSkippedResult(), phase51FactoryCredentialActivationSecrets(), nil)

	storedRun := result.loadRun(t)
	if storedRun.Sandbox == nil {
		t.Fatal("stored run sandbox metadata = nil")
	}
	assertPhase51CredentialActivationStatus(t, "stored factory run", storedRun.Sandbox.CredentialDelivery, credentialdelivery.StatusSkipped, credentialdelivery.ReasonActivationUnavailable, 1, 0)
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "stored factory run", storedRun)
	assertPhase51FactoryCredentialActivationStoreFilesRedacted(t, result.store)

	var statusJSON bytes.Buffer
	if err := renderFactoryStatusJSON(&statusJSON, *storedRun, result.loadEvents(t), nil); err != nil {
		t.Fatalf("renderFactoryStatusJSON() error = %v", err)
	}
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "factory status json", statusJSON.String())
	if !strings.Contains(statusJSON.String(), `"credentialDelivery"`) || !strings.Contains(statusJSON.String(), `"activationId"`) {
		t.Fatalf("factory status json omitted compact activation status: %s", statusJSON.String())
	}
}

func TestFactorySandboxCredentialActivationTimelineEventProjection(t *testing.T) {
	result := runPhase51FactoryCredentialActivationExecutor(t, phase51CredentialActivationFailedResult(), phase51FactoryCredentialActivationSecrets(), nil)

	events := result.loadEvents(t)
	status := requirePhase51FactoryCredentialActivationEventStatus(t, events)
	assertPhase51CredentialActivationStatus(t, "factory timeline event", status, credentialdelivery.StatusFailed, credentialdelivery.ReasonActivationUnavailable, 1, 1)
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "factory timeline events", events)

	var statusJSON bytes.Buffer
	if err := renderFactoryStatusJSON(&statusJSON, *result.loadRun(t), events, nil); err != nil {
		t.Fatalf("renderFactoryStatusJSON() error = %v", err)
	}
	renderedStatus := requirePhase51FactoryCredentialActivationRenderedEventStatus(t, statusJSON.Bytes())
	assertPhase51CredentialActivationStatus(t, "rendered factory timeline event", renderedStatus, credentialdelivery.StatusFailed, credentialdelivery.ReasonActivationUnavailable, 1, 1)
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "rendered factory timeline events", statusJSON.String())
}

func TestFactorySandboxCredentialActivationLogRedaction(t *testing.T) {
	result := runPhase51FactoryCredentialActivationExecutor(t, phase51CredentialActivationSkippedResult(), phase51FactoryCredentialActivationSecrets(), func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
		_, err := io.WriteString(req.Stdout, "credential activation output ghp_phase51_secret sk-phase51-secret PHASE51_SECRET_VALUE\n")
		return &sandboxruntime.ExecResult{}, err
	})

	if strings.Contains(result.userOutput.String(), "ghp_phase51_secret") ||
		strings.Contains(result.userOutput.String(), "sk-phase51-secret") ||
		strings.Contains(result.userOutput.String(), "PHASE51_SECRET_VALUE") {
		t.Fatalf("factory user output leaked Phase 51 secret markers: %q", result.userOutput.String())
	}
	chunks := result.loadLogChunks(t)
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "factory log chunks", chunks)
	if !phase51FactoryCredentialActivationLogStatusPresent(chunks) {
		t.Fatalf("factory logs omitted compact credential activation status: %#v", chunks)
	}
	assertPhase51FactoryCredentialActivationStoreFilesRedacted(t, result.store)
}

func TestFactorySandboxCredentialActivationDefaultOmission(t *testing.T) {
	result := runPhase51FactoryCredentialActivationExecutor(t, credentialdelivery.ActivationResult{}, nil, nil)

	storedRun := result.loadRun(t)
	if storedRun.Sandbox == nil {
		t.Fatal("stored run sandbox metadata = nil")
	}
	if storedRun.Sandbox.CredentialDelivery != nil {
		t.Fatalf("default factory run credentialDelivery = %#v, want omitted", storedRun.Sandbox.CredentialDelivery)
	}
	events := result.loadEvents(t)
	chunks := result.loadLogChunks(t)
	payload := mustPhase51FactoryCredentialActivationJSON(t, "default factory surfaces", struct {
		Run    *factory.RunRecord    `json:"run"`
		Events []factory.EventRecord `json:"events"`
		Logs   []factory.LogChunk    `json:"logs"`
	}{Run: storedRun, Events: events, Logs: chunks})
	for _, forbidden := range []string{"credentialDelivery", "activationId", "credentialActivation", "activationResult"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("default factory surfaces included activation field %q: %s", forbidden, payload)
		}
	}
}

func TestFactorySandboxCredentialActivationSanitizedFailureStatus(t *testing.T) {
	execErr := errors.New("remote activation failed with ghp_phase51_secret sk-phase51-secret PHASE51_SECRET_VALUE")
	result := runPhase51FactoryCredentialActivationExecutor(t, phase51CredentialActivationFailedResult(), phase51FactoryCredentialActivationSecrets(), func(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
		_, _ = io.WriteString(req.Stderr, execErr.Error()+"\n")
		return nil, execErr
	})

	if result.err == nil {
		t.Fatal("runFactorySandboxExecutorWithDeps() error = nil, want sanitized failure")
	}
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "factory executor error", result.err.Error())
	storedRun := result.loadRun(t)
	if storedRun.Sandbox == nil {
		t.Fatal("stored run sandbox metadata = nil")
	}
	assertPhase51CredentialActivationStatus(t, "failed factory run", storedRun.Sandbox.CredentialDelivery, credentialdelivery.StatusFailed, credentialdelivery.ReasonActivationUnavailable, 1, 1)
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "failed factory run", storedRun)
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "failed factory timeline", result.loadEvents(t))
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "failed factory logs", result.loadLogChunks(t))
	assertPhase51FactoryCredentialActivationStoreFilesRedacted(t, result.store)
}

type phase51FactoryCredentialActivationRun struct {
	store      factory.Store
	runID      string
	userOutput bytes.Buffer
	err        error
}

func runPhase51FactoryCredentialActivationExecutor(t *testing.T, activation credentialdelivery.ActivationResult, secrets []factory.ResolvedRunSecret, execFn func(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error)) phase51FactoryCredentialActivationRun {
	t.Helper()
	now := time.Date(2026, 7, 4, 4, 0, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	target := phase51FactoryCredentialActivationTarget()
	runID := "run-factory-credential-activation"
	record := factory.RunRecord{
		RunID:      runID,
		Status:     factory.RunStatusRunning,
		RepoRemote: "git@github.com:example/repo.git",
		BaseBranch: "main",
		BranchName: "hal/phase51-credential-activation",
		Secrets: []factory.RunSecretMetadata{{
			Name:     "GITHUB_TOKEN",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
			Present:  true,
		}, {
			Name:     "OPENAI_API_KEY",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
			Present:  true,
		}, {
			Name:     "PHASE51_SECRET",
			Source:   factory.RunSecretSourceEnv,
			Required: true,
			Present:  true,
		}},
	}
	req := factorySandboxExecutorRequest{
		ProjectDir:                   t.TempDir(),
		SandboxName:                  target.Name,
		RunRecord:                    record,
		Security:                     phase51CredentialActivationSecurity(),
		NetworkProxySession:          phase51CredentialActivationNetworkProxySession(sandbox.SandboxNetworkPolicyDecisionSourceFactory),
		CredentialDeliveryActivation: activation,
		ResolvedSecrets:              secrets,
		RemoteAuto:                   factoryRunAutoRequest{BaseBranch: "main"},
		DeferSuccessCleanup:          true,
	}
	if credentialdelivery.SanitizeActivationResultMetadata(activation).ID == "" {
		req.Security = sandbox.SecurityEvaluationRequest{}
		req.NetworkProxySession = nil
	}
	var userOutput bytes.Buffer
	req.RemoteOutput = &userOutput

	err := runFactorySandboxExecutorWithDeps(context.Background(), req, factorySandboxExecutorDeps{
		defaultStore:    func() (factory.Store, error) { return store, nil },
		now:             func() time.Time { return now },
		loadSandbox:     func(string) (*sandbox.SandboxState, error) { return target, nil },
		resolveProvider: func(string) (sandbox.Provider, error) { return fakeFactorySandboxProvider{}, nil },
		resolveRuntimeDriver: func(sandboxruntime.Target) (sandboxruntime.Driver, error) {
			return fakeFactorySandboxRuntimeDriver{execFn: execFn}, nil
		},
		engineAuthFiles: func() []factorySandboxAuthFile { return nil },
		bootstrap: func(context.Context, factory.BootstrapRequest, factory.BootstrapDeps) (factory.BootstrapResult, error) {
			return factory.BootstrapResult{}, nil
		},
	})
	return phase51FactoryCredentialActivationRun{
		store:      store,
		runID:      runID,
		userOutput: userOutput,
		err:        err,
	}
}

func (r phase51FactoryCredentialActivationRun) loadRun(t *testing.T) *factory.RunRecord {
	t.Helper()
	record, err := r.store.LoadRun(r.runID)
	if err != nil {
		t.Fatalf("LoadRun(%s) error = %v", r.runID, err)
	}
	return record
}

func (r phase51FactoryCredentialActivationRun) loadEvents(t *testing.T) []factory.EventRecord {
	t.Helper()
	events, err := r.store.LoadEvents(r.runID)
	if err != nil {
		t.Fatalf("LoadEvents(%s) error = %v", r.runID, err)
	}
	return events
}

func (r phase51FactoryCredentialActivationRun) loadLogChunks(t *testing.T) []factory.LogChunk {
	t.Helper()
	chunks, err := r.store.LoadLogChunks(r.runID)
	if err != nil {
		t.Fatalf("LoadLogChunks(%s) error = %v", r.runID, err)
	}
	return chunks
}

func phase51FactoryCredentialActivationTarget() *sandbox.SandboxState {
	return &sandbox.SandboxState{
		Name:     "factory-phase51-activation",
		Provider: "daytona",
		Status:   sandbox.StatusRunning,
	}
}

func phase51FactoryCredentialActivationSecrets() []factory.ResolvedRunSecret {
	return []factory.ResolvedRunSecret{
		{Name: "GITHUB_TOKEN", Source: factory.RunSecretSourceEnv, Required: true, Value: "ghp_phase51_secret"},
		{Name: "OPENAI_API_KEY", Source: factory.RunSecretSourceEnv, Required: true, Value: "sk-phase51-secret"},
		{Name: "PHASE51_SECRET", Source: factory.RunSecretSourceEnv, Required: true, Value: "PHASE51_SECRET_VALUE"},
	}
}

func requirePhase51FactoryCredentialActivationEventStatus(t *testing.T, events []factory.EventRecord) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	t.Helper()
	for _, event := range events {
		if event.EventType != factory.EventTypePolicyDecision || event.Metadata == nil {
			continue
		}
		raw, ok := event.Metadata["credentialDelivery"]
		if !ok {
			continue
		}
		return decodePhase51FactoryCredentialActivationStatus(t, "factory timeline credentialDelivery", raw)
	}
	t.Fatalf("factory timeline events omitted credentialDelivery activation status: %#v", events)
	return nil
}

func requirePhase51FactoryCredentialActivationRenderedEventStatus(t *testing.T, payload []byte) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	t.Helper()
	var response struct {
		Timeline []factory.EventRecord `json:"timeline"`
	}
	if err := json.Unmarshal(payload, &response); err != nil {
		t.Fatalf("Unmarshal(factory status json) error = %v\n%s", err, string(payload))
	}
	return requirePhase51FactoryCredentialActivationEventStatus(t, response.Timeline)
}

func decodePhase51FactoryCredentialActivationStatus(t *testing.T, label string, value any) *sandbox.SandboxCredentialDeliveryStatusMetadata {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error = %v", label, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("Unmarshal(%s fields) error = %v\n%s", label, err, string(data))
	}
	assertPhase51CredentialActivationNoFullResultFields(t, label, fields)
	var status sandbox.SandboxCredentialDeliveryStatusMetadata
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatalf("Unmarshal(%s status) error = %v\n%s", label, err, string(data))
	}
	return &status
}

func phase51FactoryCredentialActivationLogStatusPresent(chunks []factory.LogChunk) bool {
	for _, chunk := range chunks {
		text := chunk.Summary + " " + chunk.Text
		if strings.Contains(text, "Credential delivery activation") &&
			(strings.Contains(text, "skipped") || strings.Contains(text, "failed") || strings.Contains(text, "active")) {
			return true
		}
	}
	return false
}

func assertPhase51FactoryCredentialActivationRuntimeAndWorkerMetadataRedacted(t *testing.T, status *sandbox.SandboxCredentialDeliveryStatusMetadata) {
	t.Helper()
	if status == nil {
		t.Fatal("credentialDelivery status = nil")
	}
	runtimeStatus := &sandboxruntime.RuntimeCredentialDeliveryMetadata{
		ID:             status.ID,
		RequestID:      status.RequestID,
		PlanID:         status.PlanID,
		ActivationID:   status.ActivationID,
		RequestedModes: append([]string(nil), status.RequestedModes...),
		ActiveModes:    append([]string(nil), status.ActiveModes...),
		Status:         status.Status,
		ReasonCode:     status.ReasonCode,
		WarningCount:   status.WarningCount,
		ErrorCount:     status.ErrorCount,
	}
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "runtime metadata", sandboxruntime.RuntimeMetadata{CredentialDelivery: runtimeStatus})
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "worker metadata", sandboxworker.SecurityControls{CredentialDelivery: runtimeStatus})
}

func assertPhase51FactoryCredentialActivationDiagnosticsRedacted(t *testing.T, security *factory.SandboxSecurityMetadata) {
	t.Helper()
	if security == nil {
		return
	}
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "factory readiness diagnostics", security.CapabilityReadinessDiagnostics)
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "factory readiness output", security.CapabilityReadiness)
}

func assertPhase51FactoryCredentialActivationStoreFilesRedacted(t *testing.T, store factory.Store) {
	t.Helper()
	payload := phase51FactoryCredentialActivationStorePayload(t, store)
	assertPhase51FactoryCredentialActivationPayloadRedacted(t, "factory store files", payload)
}

func phase51FactoryCredentialActivationStorePayload(t *testing.T, store factory.Store) string {
	t.Helper()
	var out strings.Builder
	for _, dir := range []string{store.RunsDir(), store.TimelinesDir(), store.LogsDir()} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatalf("read factory store file %s/%s: %v", dir, entry.Name(), err)
			}
			out.Write(data)
			out.WriteByte('\n')
		}
	}
	return out.String()
}

func assertPhase51FactoryCredentialActivationPayloadRedacted(t *testing.T, label string, value any) {
	t.Helper()
	payload := mustPhase51FactoryCredentialActivationJSON(t, label, value)
	for _, forbidden := range []string{
		"ghp_phase51_secret",
		"sk-phase51-secret",
		"PHASE51_SECRET_VALUE",
		"credentialActivation",
		"activationResult",
		"proofRefs",
		"bindings",
		"Authorization",
		"Bearer",
		"https://",
		"api.example.com",
		"127.0.0.1",
		":8080",
		"/Users/",
		"/tmp/",
		"unix://",
		"providerHandle",
	} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("%s leaked forbidden activation payload %q in %s", label, forbidden, payload)
		}
	}
}

func mustPhase51FactoryCredentialActivationJSON(t *testing.T, label string, value any) string {
	t.Helper()
	switch typed := value.(type) {
	case string:
		return typed
	default:
		data, err := json.Marshal(typed)
		if err != nil {
			t.Fatalf("Marshal(%s) error = %v", label, err)
		}
		return string(data)
	}
}
