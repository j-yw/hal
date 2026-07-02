package cmd

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	rootlesspodman "github.com/jywlabs/hal/internal/sandboxruntime/rootlesspodman"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

var phase26CredentialProxyJSONFields = []string{
	"credentialProxy",
	"credentialProxyPlan",
	"credentialProxySession",
	"credentialProxyBindings",
}

func TestRunAndAutoSandboxManifestsOmitCredentialProxyMetadataByDefault(t *testing.T) {
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

func TestFactoryPersistenceOmitsCredentialProxyMetadataByDefault(t *testing.T) {
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

func TestPhase26CredentialProxyLegacyJSONCompatibility(t *testing.T) {
	t.Run("sandbox execution manifest", func(t *testing.T) {
		const executionID = "legacy-run-manifest"
		store := sandboxexecution.NewStore(t.TempDir())
		writeSandboxExecutionManifestFixture(t, store, executionID, `{
			"id": "legacy-run-manifest",
			"purpose": "run",
			"sandboxName": "phase24-run",
			"projectDir": "/repo",
			"command": ["hal", "run", "--sandbox"],
			"workDir": "/repo",
			"status": "succeeded",
			"startedAt": "2026-07-01T08:00:00Z",
			"finishedAt": "2026-07-01T08:30:00Z",
			"networkProxySession": {
				"id": "proxy-session-01",
				"source": "run",
				"policySnapshot": {
					"id": "policy-snapshot-01",
					"preset": "deny_by_default"
				},
				"enforcementMode": "proxy"
			},
			"networkPolicyDecisionLogs": [{
				"id": "decision-01",
				"source": "run",
				"proxySessionId": "proxy-session-01",
				"policySnapshot": {
					"id": "policy-snapshot-01",
					"preset": "deny_by_default"
				},
				"request": {
					"id": "request-01",
					"operation": "connect",
					"destinationCategory": "public_internet"
				},
				"outcome": "allowed",
				"reasonCode": "matched_allow_rule",
				"policyPreset": "deny_by_default",
				"enforcementMode": "proxy"
			}],
			"artifacts": [{
				"id": "stdout",
				"name": "stdout",
				"type": "text",
				"path": "legacy-run-manifest/artifacts/stdout.txt",
				"storedPath": "legacy-run-manifest/artifacts/stdout.txt"
			}]
		}`)

		manifest := mustLoadSandboxExecutionManifest(t, store, executionID)
		if manifest.NetworkProxySession == nil || manifest.NetworkProxySession.ID != "proxy-session-01" {
			t.Fatalf("NetworkProxySession = %#v, want legacy proxy metadata", manifest.NetworkProxySession)
		}
		if len(manifest.NetworkPolicyDecisionLogs) != 1 {
			t.Fatalf("NetworkPolicyDecisionLogs = %#v, want one legacy decision log", manifest.NetworkPolicyDecisionLogs)
		}
		assertSandboxManifestOmitsCredentialProxyMetadata(t, manifest)

		if err := store.SaveManifest(manifest); err != nil {
			t.Fatalf("SaveManifest(legacy manifest) error = %v", err)
		}
		assertSandboxManifestOmitsCredentialProxyMetadata(t, mustLoadSandboxExecutionManifest(t, store, executionID))
	})

	t.Run("factory run record", func(t *testing.T) {
		const runID = "run-legacy-factory-record"
		store := factory.NewStore(t.TempDir())
		writeFactoryRunRecordFixture(t, store, runID, `{
			"runId": "run-legacy-factory-record",
			"status": "running",
			"executorMode": "sandbox",
			"engine": "codex",
			"source": {"kind": "prd", "path": ".hal/prd.json"},
			"repoPath": "/repo",
			"repoRemote": "origin",
			"branchName": "hal/phase-24-network-proxy-policy-log",
			"baseBranch": "main",
			"sandboxName": "factory-legacy",
			"sandbox": {
				"name": "factory-legacy",
				"provider": "fake",
				"size": "medium",
				"status": "running",
				"connection": {
					"address": "100.64.0.10",
					"tailscaleHostname": "factory-legacy.tailnet.ts.net",
					"tailscaleLockdown": true
				},
				"networkProxySession": {
					"id": "proxy-session-factory",
					"source": "factory",
					"policySnapshot": {
						"id": "policy-snapshot-factory",
						"preset": "deny_by_default"
					},
					"enforcementMode": "proxy"
				}
			},
			"currentStep": "run",
			"createdAt": "2026-07-01T09:00:00Z",
			"updatedAt": "2026-07-01T09:15:00Z"
		}`)

		record, err := store.LoadRun(runID)
		if err != nil {
			t.Fatalf("LoadRun(legacy record) error = %v", err)
		}
		if record.Sandbox == nil || record.Sandbox.NetworkProxySession == nil {
			t.Fatalf("sandbox metadata = %#v, want legacy proxy metadata", record.Sandbox)
		}
		assertJSONOmitsCredentialProxyMetadata(t, "loaded legacy factory run record", record)

		if err := store.SaveRun(record); err != nil {
			t.Fatalf("SaveRun(legacy record) error = %v", err)
		}
		roundTripped, err := store.LoadRun(runID)
		if err != nil {
			t.Fatalf("LoadRun(round-tripped legacy record) error = %v", err)
		}
		assertJSONOmitsCredentialProxyMetadata(t, "round-tripped legacy factory run record", roundTripped)
	})

	t.Run("factory timeline events", func(t *testing.T) {
		const runID = "run-legacy-factory-timeline"
		store := factory.NewStore(t.TempDir())
		writeFactoryTimelineFixture(t, store, runID, `[{
			"sequence": 1,
			"runId": "run-legacy-factory-timeline",
			"eventType": "run_created",
			"timestamp": "2026-07-01T10:00:00Z",
			"message": "factory run created",
			"metadata": {
				"executorMode": "sandbox",
				"sandboxName": "factory-legacy"
			}
		}, {
			"sequence": 2,
			"runId": "run-legacy-factory-timeline",
			"eventType": "policy_decision",
			"timestamp": "2026-07-01T10:01:00Z",
			"summary": "network policy decision recorded",
			"metadata": {
				"policyField": "sandbox.networkPolicy",
				"decision": "passed_gate",
				"outcome": "passed",
				"reason": "policy_metadata_only"
			},
			"networkPolicyDecisionLogs": [{
				"id": "decision-factory-01",
				"source": "factory",
				"proxySessionId": "proxy-session-factory",
				"policySnapshot": {
					"id": "policy-snapshot-factory",
					"preset": "deny_by_default"
				},
				"request": {
					"id": "request-factory-01",
					"operation": "connect",
					"destinationCategory": "public_internet"
				},
				"outcome": "allowed",
				"reasonCode": "matched_allow_rule",
				"policyPreset": "deny_by_default",
				"enforcementMode": "proxy"
			}]
		}]`)

		events, err := store.LoadEvents(runID)
		if err != nil {
			t.Fatalf("LoadEvents(legacy timeline) error = %v", err)
		}
		if len(events) != 2 {
			t.Fatalf("events = %d, want 2", len(events))
		}
		assertJSONOmitsCredentialProxyMetadata(t, "loaded legacy factory timeline events", events)

		roundTripStore := factory.NewStore(t.TempDir())
		for i := range events {
			if err := roundTripStore.AppendEvent(&events[i]); err != nil {
				t.Fatalf("AppendEvent(legacy event %d) error = %v", i, err)
			}
		}
		roundTripped, err := roundTripStore.LoadEvents(runID)
		if err != nil {
			t.Fatalf("LoadEvents(round-tripped legacy timeline) error = %v", err)
		}
		assertJSONOmitsCredentialProxyMetadata(t, "round-tripped legacy factory timeline events", roundTripped)
	})
}

func TestPhase26CredentialProxyFactoryTimelineOmissionAfterSanitization(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 14, 10, 0, 0, time.UTC)
	redactor, metadata, forbidden := phase26FactoryTimelineCredentialProxySeed()

	event := redactFactoryTimelineEvent(factoryTimelineEvent{
		EventType: factory.EventTypePolicyDecision,
		Summary:   "Sandbox policy metadata recorded",
		Metadata:  metadata,
	}, redactor)
	if event.Metadata["safeDetail"] != "kept" {
		t.Fatalf("sanitized timeline metadata lost safe field: %#v", event.Metadata)
	}
	sanitizedRecord := factory.EventRecord{
		Sequence:  1,
		RunID:     "run-timeline-sanitize",
		EventType: event.EventType,
		Timestamp: startedAt,
		Summary:   event.Summary,
		Metadata:  event.Metadata,
	}
	assertFactoryTimelineOmitsCredentialProxyClaims(t, "sanitized factory timeline event", sanitizedRecord, forbidden)

	_, legacyMetadata, legacyForbidden := phase26FactoryTimelineCredentialProxySeed()
	normalized := normalizeFactoryTimelineEventsForContractV1([]factory.EventRecord{{
		Sequence:  2,
		RunID:     "run-timeline-normalize",
		EventType: factory.EventTypePolicyDecision,
		Timestamp: startedAt,
		Summary:   "Legacy policy metadata recorded",
		Metadata:  legacyMetadata,
	}})
	if len(normalized) != 1 {
		t.Fatalf("normalized events = %d, want 1", len(normalized))
	}
	if normalized[0].Metadata["safeDetail"] != "kept" {
		t.Fatalf("normalized timeline metadata lost safe field: %#v", normalized[0].Metadata)
	}
	assertFactoryTimelineOmitsCredentialProxyClaims(t, "normalized factory timeline event", normalized[0], legacyForbidden)
}

func TestPhase26CredentialProxyFactoryTimelinePersistenceAndRenderingOmitMetadata(t *testing.T) {
	startedAt := time.Date(2026, 7, 2, 14, 30, 0, 0, time.UTC)
	store := factory.NewStore(t.TempDir())
	record := factory.RunRecord{
		RunID:        "run-timeline-credential-proxy-omission",
		Status:       factory.RunStatusRunning,
		ExecutorMode: factory.ExecutorModeSandbox,
		Source: factory.SourceMetadata{
			Kind: factory.SourceKindPRD,
			Path: ".hal/prd.json",
		},
		RepoPath:    "/repo",
		RepoRemote:  "origin",
		BranchName:  "hal/phase-26-credential-proxy-plumbing",
		BaseBranch:  "main",
		CurrentStep: "run",
		CreatedAt:   startedAt,
		UpdatedAt:   startedAt,
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error = %v", err)
	}

	redactor, metadata, forbidden := phase26FactoryTimelineCredentialProxySeed()
	if err := appendFactoryRunTimelineEventWithRedactor(store, record.RunID, startedAt, factoryTimelineEvent{
		EventType: factory.EventTypePolicyDecision,
		Summary:   "Sandbox policy metadata recorded",
		Metadata:  metadata,
	}, redactor); err != nil {
		t.Fatalf("appendFactoryRunTimelineEventWithRedactor() error = %v", err)
	}
	events, err := store.LoadEvents(record.RunID)
	if err != nil {
		t.Fatalf("LoadEvents() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Metadata["safeDetail"] != "kept" {
		t.Fatalf("persisted timeline metadata lost safe field: %#v", events[0].Metadata)
	}
	assertFactoryTimelineOmitsCredentialProxyClaims(t, "persisted factory timeline event", events[0], forbidden)

	_, legacyMetadata, legacyForbidden := phase26FactoryTimelineCredentialProxySeed()
	var statusJSON bytes.Buffer
	if err := renderFactoryStatusJSON(&statusJSON, record, []factory.EventRecord{{
		Sequence:  2,
		RunID:     record.RunID,
		EventType: factory.EventTypePolicyDecision,
		Timestamp: startedAt.Add(time.Minute),
		Summary:   "Legacy policy metadata recorded",
		Metadata:  legacyMetadata,
	}}, nil); err != nil {
		t.Fatalf("renderFactoryStatusJSON() error = %v", err)
	}
	assertFactoryTimelinePayloadOmitsCredentialProxyClaims(t, "factory status timeline JSON", statusJSON.String(), legacyForbidden)
}

func TestPhase26CredentialProxyFactoryTimelineDocsStateOmission(t *testing.T) {
	timelineDoc := readPhase26CredentialProxyContractDoc(t, filepath.Join("..", "docs", "contracts", "factory-timeline-v1.md"))
	statusDoc := readPhase26CredentialProxyContractDoc(t, filepath.Join("..", "docs", "contracts", "factory-status-v1.md"))
	requiredTimeline := []string{
		"Phase 26 credential proxy persistence is limited to non-factory sandbox execution manifests and factory sandbox metadata.",
		"Factory timeline events do not add `credentialProxy`, `credentialProxyPlan`, `credentialProxySession`, or `credentialProxyBindings`.",
		"Timeline metadata must not be used to claim credential delivery, credential proxy delivery, proxy enforcement, network enforcement, SSH-agent forwarding, tmpfs writes, or runtime support.",
	}
	for _, want := range requiredTimeline {
		if !phase26CredentialProxyDocContains(timelineDoc, want) {
			t.Fatalf("factory timeline contract missing %q", want)
		}
	}
	if !phase26CredentialProxyDocContains(statusDoc, "credential proxy persistence is limited to non-factory sandbox execution manifests and factory sandbox metadata") {
		t.Fatal("factory status contract must state Phase 26 credential proxy persistence is limited to non-factory manifests and factory sandbox metadata")
	}
	if !phase26CredentialProxyDocContains(statusDoc, "factory timeline events do not mirror credential proxy plan, session, or binding metadata") {
		t.Fatal("factory status contract must state factory timeline events do not mirror credential proxy metadata")
	}
}

func TestPhase26CredentialProxyPersistenceFieldsUseApprovedSurfaces(t *testing.T) {
	violations := findCredentialProxyPersistenceFieldViolations(t)
	if len(violations) > 0 {
		t.Fatalf("credential proxy JSON fields are only approved on sandboxexecution.Manifest and factory.SandboxMetadata:\n%s", strings.Join(violations, "\n"))
	}

	assertApprovedCredentialProxySurfaceFields(t, reflect.TypeOf(sandboxexecution.Manifest{}))
	assertApprovedCredentialProxySurfaceFields(t, reflect.TypeOf(factory.SandboxMetadata{}))
}

func TestPhase26CredentialProxyMetadataRejectedFromUnapprovedSurfaces(t *testing.T) {
	unapproved := []struct {
		label string
		typ   reflect.Type
	}{
		{label: "factory EventRecord", typ: reflect.TypeOf(factory.EventRecord{})},
		{label: "worker Status", typ: reflect.TypeOf(sandboxworker.Status{})},
		{label: "worker Capabilities", typ: reflect.TypeOf(sandboxworker.Capabilities{})},
		{label: "worker RuntimeDriver", typ: reflect.TypeOf(sandboxworker.RuntimeDriver{})},
		{label: "worker SecurityPolicy", typ: reflect.TypeOf(sandboxworker.SecurityPolicy{})},
		{label: "worker SecurityControls", typ: reflect.TypeOf(sandboxworker.SecurityControls{})},
		{label: "worker Target", typ: reflect.TypeOf(sandboxworker.Target{})},
		{label: "worker RuntimeTarget", typ: reflect.TypeOf(sandboxworker.RuntimeTarget{})},
		{label: "worker Response", typ: reflect.TypeOf(sandboxworker.Response{})},
		{label: "sandbox runtime Target", typ: reflect.TypeOf(sandboxruntime.Target{})},
		{label: "sandbox runtime RuntimeState", typ: reflect.TypeOf(sandboxruntime.RuntimeState{})},
		{label: "rootless podman RuntimeMetadata", typ: reflect.TypeOf(rootlesspodman.RuntimeMetadata{})},
		{label: "sandbox host metadata", typ: reflect.TypeOf(sandbox.SandboxHost{})},
		{label: "sandbox runtime metadata", typ: reflect.TypeOf(sandbox.SandboxRuntimeState{})},
		{label: "sandbox worker routing metadata", typ: reflect.TypeOf(sandbox.WorkerRoutingMetadata{})},
		{label: "sandbox provider config", typ: reflect.TypeOf(sandbox.ProviderConfig{})},
		{label: "daytona provider", typ: reflect.TypeOf(sandbox.DaytonaProvider{})},
		{label: "hetzner provider", typ: reflect.TypeOf(sandbox.HetznerProvider{})},
		{label: "digitalocean provider", typ: reflect.TypeOf(sandbox.DigitalOceanProvider{})},
		{label: "lightsail provider", typ: reflect.TypeOf(sandbox.LightsailProvider{})},
	}
	for _, tc := range unapproved {
		t.Run(tc.label, func(t *testing.T) {
			assertNoDirectCredentialProxyJSONFields(t, tc.label, tc.typ)
		})
	}
}

func TestPhase26CredentialProxyMetadataRejectedFromCommandResultEnvelopes(t *testing.T) {
	envelopes := []struct {
		label string
		typ   reflect.Type
	}{
		{label: "run sandbox execution result", typ: reflect.TypeOf(runSandboxExecutionResult{})},
		{label: "auto sandbox execution result", typ: reflect.TypeOf(autoSandboxExecutionResult{})},
		{label: "factory run execution result", typ: reflect.TypeOf(factoryRunExecutionResult{})},
		{label: "FactoryRunResponse", typ: reflect.TypeOf(FactoryRunResponse{})},
		{label: "FactoryStatusResponse", typ: reflect.TypeOf(FactoryStatusResponse{})},
		{label: "FactoryStatusRun", typ: reflect.TypeOf(FactoryStatusRun{})},
		{label: "FactoryArtifactsResponse", typ: reflect.TypeOf(FactoryArtifactsResponse{})},
		{label: "FactoryLogsResponse", typ: reflect.TypeOf(FactoryLogsResponse{})},
		{label: "FactoryListResponse", typ: reflect.TypeOf(FactoryListResponse{})},
		{label: "FactoryQueueAddResponse", typ: reflect.TypeOf(FactoryQueueAddResponse{})},
		{label: "FactoryQueueListResponse", typ: reflect.TypeOf(FactoryQueueListResponse{})},
		{label: "FactoryQueueWorkResponse", typ: reflect.TypeOf(FactoryQueueWorkResponse{})},
		{label: "FactoryOpenResponse", typ: reflect.TypeOf(FactoryOpenResponse{})},
		{label: "FactoryTriggerResponse", typ: reflect.TypeOf(FactoryTriggerResponse{})},
		{label: "RunResult", typ: reflect.TypeOf(RunResult{})},
		{label: "AutoResult", typ: reflect.TypeOf(AutoResult{})},
		{label: "PlanResult", typ: reflect.TypeOf(PlanResult{})},
		{label: "ConvertResult", typ: reflect.TypeOf(ConvertResult{})},
		{label: "ContinueResult", typ: reflect.TypeOf(ContinueResult{})},
		{label: "ReportResult", typ: reflect.TypeOf(ReportResult{})},
		{label: "PRDAuditResult", typ: reflect.TypeOf(PRDAuditResult{})},
		{label: "CleanupResult", typ: reflect.TypeOf(CleanupResult{})},
		{label: "RepairResult", typ: reflect.TypeOf(RepairResult{})},
		{label: "InitResult", typ: reflect.TypeOf(InitResult{})},
		{label: "LinksResult", typ: reflect.TypeOf(LinksResult{})},
		{label: "ExplodeResult", typ: reflect.TypeOf(ExplodeResult{})},
		{label: "ArchiveCreateResult", typ: reflect.TypeOf(ArchiveCreateResult{})},
		{label: "ArchiveListResult", typ: reflect.TypeOf(ArchiveListResult{})},
		{label: "SandboxListResponse", typ: reflect.TypeOf(SandboxListResponse{})},
		{label: "SandboxHostListResponse", typ: reflect.TypeOf(SandboxHostListResponse{})},
		{label: "SandboxHostStatusResponse", typ: reflect.TypeOf(SandboxHostStatusResponse{})},
		{label: "SandboxRuntimeListResponse", typ: reflect.TypeOf(SandboxRuntimeListResponse{})},
		{label: "SandboxRuntimeStatusResponse", typ: reflect.TypeOf(SandboxRuntimeStatusResponse{})},
		{label: "live status result", typ: reflect.TypeOf(liveStatusResult{})},
		{label: "sandbox auth sync result", typ: reflect.TypeOf(sandboxAuthSyncResult{})},
		{label: "sandbox delete result", typ: reflect.TypeOf(deleteResult{})},
		{label: "sandbox start result", typ: reflect.TypeOf(startResult{})},
		{label: "sandbox stop result", typ: reflect.TypeOf(stopResult{})},
		{label: "sandbox batch result", typ: reflect.TypeOf(batchResult{})},
	}
	for _, tc := range envelopes {
		t.Run(tc.label, func(t *testing.T) {
			assertNoDirectCredentialProxyJSONFields(t, tc.label, tc.typ)
		})
	}
}

func assertSandboxManifestOmitsCredentialProxyMetadata(t *testing.T, manifest *sandboxexecution.Manifest) {
	t.Helper()
	fields := sandboxManifestJSONFields(t, manifest)
	for _, field := range phase26CredentialProxyJSONFields {
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
	for _, field := range phase26CredentialProxyJSONFields {
		if strings.Contains(encoded, `"`+field+`"`) {
			t.Fatalf("%s unexpectedly includes credential proxy field %q: %s", label, field, encoded)
		}
	}
}

func writeSandboxExecutionManifestFixture(t *testing.T, store sandboxexecution.Store, executionID string, payload string) {
	t.Helper()
	if err := store.Ensure(executionID); err != nil {
		t.Fatalf("Ensure(%s) error = %v", executionID, err)
	}
	path, err := store.ManifestPath(executionID)
	if err != nil {
		t.Fatalf("ManifestPath(%s) error = %v", executionID, err)
	}
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func writeFactoryRunRecordFixture(t *testing.T, store factory.Store, runID string, payload string) {
	t.Helper()
	if err := store.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	path := filepath.Join(store.RunsDir(), runID+".json")
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func writeFactoryTimelineFixture(t *testing.T, store factory.Store, runID string, payload string) {
	t.Helper()
	if err := store.Ensure(); err != nil {
		t.Fatalf("Ensure() error = %v", err)
	}
	path := filepath.Join(store.TimelinesDir(), runID+".json")
	if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}

func assertFactoryTimelineOmitsCredentialProxyClaims(t *testing.T, label string, value any, forbiddenValues []string) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal(%s) error = %v", label, err)
	}
	assertFactoryTimelinePayloadOmitsCredentialProxyClaims(t, label, string(data), forbiddenValues)
}

func assertFactoryTimelinePayloadOmitsCredentialProxyClaims(t *testing.T, label string, payload string, forbiddenValues []string) {
	t.Helper()
	for _, field := range phase26CredentialProxyJSONFields {
		if strings.Contains(payload, `"`+field+`"`) {
			t.Fatalf("%s unexpectedly includes credential proxy field %q: %s", label, field, payload)
		}
	}
	for _, forbidden := range forbiddenValues {
		if forbidden == "" {
			continue
		}
		if strings.Contains(payload, forbidden) {
			t.Fatalf("%s leaked credential proxy timeline value %q: %s", label, forbidden, payload)
		}
	}
}

func phase26FactoryTimelineCredentialProxySeed() (factory.RunSecretRedactor, map[string]any, []string) {
	rawSecret := "phase26-raw-secret-token-123"
	rawEnvValue := "AWS_SECRET_ACCESS_KEY=phase26-secret-value-123"
	rawURL := "https://api.example.invalid:443/path?token=phase26-raw-secret-token-123"
	rawHeader := "Authorization: Bearer phase26-raw-secret-token-123"
	socketPath := "/tmp/phase26-credential-proxy.sock"
	localPath := "/Users/v/.ssh/phase26_id_rsa"
	redactor := factory.NewRunSecretRedactor([]factory.ResolvedRunSecret{{
		Name:  "PHASE26_TOKEN",
		Value: rawSecret,
	}, {
		Name:  "PHASE26_ENV_VALUE",
		Value: "phase26-secret-value-123",
	}})
	plan := sandbox.SandboxCredentialProxyPlanMetadata{
		ID:                    "timeline-plan-01",
		Source:                sandbox.SandboxCredentialProxySourceFactory,
		SecretBrokerSessionID: rawSecret,
		NetworkProxySessionID: rawURL,
		PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
			ID:        "timeline-policy-01",
			RuleSetID: rawURL,
		},
		Mode:   sandbox.SandboxCredentialProxyModeBrokeredNetworkReference,
		Status: sandbox.SandboxCredentialProxyStatusActive,
	}
	session := sandbox.SandboxCredentialProxySessionMetadata{
		ID:                    "timeline-session-01",
		PlanID:                "timeline-plan-01",
		Source:                sandbox.SandboxCredentialProxySourceFactory,
		SecretBrokerSessionID: rawHeader,
		NetworkProxySessionID: socketPath,
		Status:                sandbox.SandboxCredentialProxyStatusActive,
	}
	bindings := []sandbox.SandboxCredentialProxyBindingMetadata{{
		ID:              "timeline-binding-01",
		PlanID:          "timeline-plan-01",
		SessionID:       "timeline-session-01",
		SecretID:        "env:GITHUB_TOKEN",
		DeliveryMode:    sandbox.SandboxCredentialProxyDeliveryModeSSHAgent,
		RequestCategory: sandbox.SandboxCredentialProxyRequestSecretDelivery,
		Outcome:         sandbox.SandboxCredentialProxyBindingOutcomeBound,
		Status:          sandbox.SandboxCredentialProxyStatusActive,
	}}
	metadata := map[string]any{
		"safeDetail":                  "kept",
		"credentialProxy":             map[string]any{"rawURL": rawURL},
		"credentialProxyMode":         true,
		"credentialProxyPlan":         plan,
		"credentialProxyDelivery":     "active " + rawHeader,
		"credentialDelivery":          "delivered " + rawEnvValue,
		"proxyEnforcement":            sandbox.SandboxNetworkEnforcementModeProxyFirewall,
		"networkEnforcement":          sandbox.SandboxNetworkPolicyDenyByDefault,
		"sshAgentForwarding":          true,
		"tmpfsWrites":                 true,
		"runtimeSupport":              "rootless_podman",
		"credentialProxyProjection":   sandbox.SandboxCredentialProxyProjection{Plan: &plan, Session: &session, Bindings: bindings},
		"credentialProxyUnsafePath":   localPath,
		"credential_proxy_delivery":   "active",
		"credential-delivery-status":  "complete",
		"nested":                      map[string]any{"credentialProxySession": &session, "credentialProxyBindings": bindings},
		"nestedCredentialProxyRecord": []sandbox.SandboxCredentialProxyBindingMetadata(bindings),
	}
	forbidden := []string{
		rawSecret,
		rawEnvValue,
		rawURL,
		rawHeader,
		socketPath,
		localPath,
		"phase26-secret-value-123",
		"credentialProxyMode",
		"credentialProxyDelivery",
		"credentialDelivery",
		"credential_proxy_delivery",
		"credential-delivery-status",
		"proxyEnforcement",
		"networkEnforcement",
		"sshAgentForwarding",
		"tmpfsWrites",
		"runtimeSupport",
		"rootless_podman",
		string(sandbox.SandboxNetworkEnforcementModeProxyFirewall),
		string(sandbox.SandboxNetworkPolicyDenyByDefault),
		string(sandbox.SandboxCredentialProxyStatusActive),
		string(sandbox.SandboxCredentialProxyBindingOutcomeBound),
		string(sandbox.SandboxCredentialProxyDeliveryModeSSHAgent),
		string(sandbox.SandboxCredentialProxyDeliveryModeFileTmpfs),
	}
	return redactor, metadata, forbidden
}

func readPhase26CredentialProxyContractDoc(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	return string(data)
}

func phase26CredentialProxyDocContains(doc, want string) bool {
	return strings.Contains(doc, want) || strings.Contains(strings.Join(strings.Fields(doc), " "), want)
}

func findCredentialProxyPersistenceFieldViolations(t *testing.T) []string {
	t.Helper()
	var violations []string
	fset := token.NewFileSet()
	for _, root := range []string{".", filepath.Join("..", "internal")} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case ".git", ".hal", "vendor":
					return filepath.SkipDir
				default:
					return nil
				}
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}

			file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				typeSpec, ok := node.(*ast.TypeSpec)
				if !ok {
					return true
				}
				structType, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					return false
				}
				for _, field := range structType.Fields.List {
					if field.Tag == nil {
						continue
					}
					jsonName := jsonFieldNameFromTag(field.Tag.Value)
					if !phase26IsCredentialProxyJSONField(jsonName) {
						continue
					}
					if !phase26ApprovedCredentialProxySurface(file.Name.Name, typeSpec.Name.Name) {
						pos := fset.Position(field.Pos())
						violations = append(violations, pos.String()+": "+file.Name.Name+"."+typeSpec.Name.Name+" has unapproved credential proxy JSON field "+jsonName)
					}
				}
				return false
			})
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s for credential proxy JSON fields: %v", root, err)
		}
	}
	return violations
}

func assertApprovedCredentialProxySurfaceFields(t *testing.T, typ reflect.Type) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
		if !phase26IsCredentialProxyJSONField(jsonName) {
			continue
		}
		if !phase26KnownCredentialProxyJSONField(jsonName) {
			t.Fatalf("%s.%s uses unapproved credential proxy JSON field %q", typ.Name(), field.Name, jsonName)
		}
		if !strings.Contains(","+field.Tag.Get("json")+",", ",omitempty,") {
			t.Fatalf("%s.%s json tag %q must use omitempty", typ.Name(), field.Name, field.Tag.Get("json"))
		}
		if !phase26AllowedCredentialProxyPersistenceType(jsonName, field.Type) {
			t.Fatalf("%s.%s has credential proxy field type %s, want Phase 25 sandbox credential proxy contract type or sanitized wrapper", typ.Name(), field.Name, field.Type)
		}
	}
}

func assertNoDirectCredentialProxyJSONFields(t *testing.T, label string, typ reflect.Type) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		jsonName := strings.Split(field.Tag.Get("json"), ",")[0]
		if phase26IsCredentialProxyJSONField(jsonName) {
			t.Fatalf("%s must not define direct credential proxy JSON field %q on %s.%s", label, jsonName, typ.Name(), field.Name)
		}
	}
}

func phase26ApprovedCredentialProxySurface(pkgName, typeName string) bool {
	return (pkgName == "sandboxexecution" && typeName == "Manifest") ||
		(pkgName == "factory" && typeName == "SandboxMetadata")
}

func phase26IsCredentialProxyJSONField(name string) bool {
	return strings.HasPrefix(name, "credentialProxy") && name != "credentialProxyMode"
}

func phase26KnownCredentialProxyJSONField(name string) bool {
	for _, field := range phase26CredentialProxyJSONFields {
		if name == field {
			return true
		}
	}
	return false
}

func phase26AllowedCredentialProxyPersistenceType(jsonName string, typ reflect.Type) bool {
	base, plural := phase26CredentialProxyPersistenceBaseType(typ)
	if base == nil {
		return false
	}
	if base.PkgPath() != "github.com/jywlabs/hal/internal/sandbox" || !strings.HasPrefix(base.Name(), "SandboxCredentialProxy") {
		return false
	}
	switch jsonName {
	case "credentialProxyPlan":
		return !plural && strings.Contains(base.Name(), "Plan")
	case "credentialProxySession":
		return !plural && strings.Contains(base.Name(), "Session")
	case "credentialProxyBindings":
		return plural && strings.Contains(base.Name(), "Binding")
	case "credentialProxy":
		return true
	default:
		return false
	}
}

func phase26CredentialProxyPersistenceBaseType(typ reflect.Type) (reflect.Type, bool) {
	plural := false
	for {
		switch typ.Kind() {
		case reflect.Pointer:
			typ = typ.Elem()
		case reflect.Slice, reflect.Array:
			plural = true
			typ = typ.Elem()
		default:
			return typ, plural
		}
	}
}

func jsonFieldNameFromTag(rawTag string) string {
	tag := strings.Trim(rawTag, "`")
	return strings.Split(reflect.StructTag(tag).Get("json"), ",")[0]
}
