package sandboxexecution

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestArtifactJSONFieldsAndOmitEmptyOptionals(t *testing.T) {
	size := int64(42)
	createdAt := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	got := mustJSONMap(t, Artifact{
		ID:         "report",
		Name:       "Report",
		Type:       "markdown",
		Path:       "exec-1/artifacts/report.md",
		StoredPath: "exec-1/artifacts/report.md",
		SizeBytes:  &size,
		CreatedAt:  &createdAt,
	})
	assertJSONKeys(t, got, []string{"id", "name", "type", "path", "storedPath", "sizeBytes", "createdAt"})

	emptyOptional := mustJSONMap(t, Artifact{
		Name: "Report",
		Type: "markdown",
	})
	assertJSONKeys(t, emptyOptional, []string{"name", "type"})
}

func TestArtifactMetadataJSONFieldsAndOmitEmptyOptionals(t *testing.T) {
	size := int64(42)
	createdAt := time.Date(2026, 6, 30, 1, 2, 3, 0, time.UTC)
	got := mustJSONMap(t, ArtifactMetadata{
		Collected: []ArtifactMetadataEntry{{
			ID:         "prd",
			Name:       "PRD",
			Type:       "json",
			Path:       ".hal/prd.json",
			StoredPath: "exec-1/artifacts/hal-prd.json",
			SizeBytes:  &size,
			CreatedAt:  &createdAt,
		}},
		Partial: []ArtifactMetadataEntry{{
			Path: ".hal/reports.tar",
		}},
		Warnings: []ArtifactWarning{{
			Phase:   "reports-archive",
			Message: "reports directory missing",
			Artifact: ArtifactMetadataEntry{
				Path: ".hal/reports.tar",
			},
		}},
	})
	assertJSONKeys(t, got, []string{"collected", "partial", "warnings"})

	collected := firstJSONArrayObject(t, got, "collected")
	assertJSONKeys(t, collected, []string{"id", "name", "type", "path", "storedPath", "sizeBytes", "createdAt"})
	for _, unsafeKey := range []string{"sourcePath", "localPath", "remotePath"} {
		if _, ok := collected[unsafeKey]; ok {
			t.Fatalf("artifact metadata should not include host temp path field %q: %#v", unsafeKey, collected)
		}
	}

	partial := firstJSONArrayObject(t, got, "partial")
	assertJSONKeys(t, partial, []string{"path"})

	warning := firstJSONArrayObject(t, got, "warnings")
	assertJSONKeys(t, warning, []string{"phase", "message", "artifact"})
	artifact, ok := warning["artifact"].(map[string]any)
	if !ok {
		t.Fatalf("warning artifact should be an object, got %T", warning["artifact"])
	}
	assertJSONKeys(t, artifact, []string{"path"})
}

func TestManifestJSONFieldsAndSandboxMetadataTypes(t *testing.T) {
	manifestType := reflect.TypeOf(Manifest{})
	assertFieldType(t, manifestType, "Workspace", reflect.TypeOf((*sandbox.SandboxWorkspace)(nil)))
	assertFieldType(t, manifestType, "Host", reflect.TypeOf((*sandbox.SandboxHost)(nil)))
	assertFieldType(t, manifestType, "Runtime", reflect.TypeOf((*sandbox.SandboxRuntimeState)(nil)))
	assertFieldType(t, manifestType, "Security", reflect.TypeOf((*sandbox.SandboxSecurity)(nil)))
	assertFieldType(t, manifestType, "NetworkProxySession", reflect.TypeOf((*sandbox.SandboxNetworkProxySessionMetadata)(nil)))
	assertFieldType(t, manifestType, "NetworkPolicyDecisionLogs", reflect.TypeOf([]sandbox.SandboxNetworkPolicyDecisionLogRecord(nil)))
	assertFieldType(t, manifestType, "CredentialProxyPlan", reflect.TypeOf((*sandbox.SandboxCredentialProxyPlanMetadata)(nil)))
	assertFieldType(t, manifestType, "CredentialProxySession", reflect.TypeOf((*sandbox.SandboxCredentialProxySessionMetadata)(nil)))
	assertFieldType(t, manifestType, "CredentialProxyBindings", reflect.TypeOf([]sandbox.SandboxCredentialProxyBindingMetadata(nil)))
	assertFieldType(t, manifestType, "CredentialDelivery", reflect.TypeOf((*sandbox.SandboxCredentialDeliveryStatusMetadata)(nil)))
	assertFieldType(t, manifestType, "Lease", reflect.TypeOf((*sandbox.SandboxLeaseRef)(nil)))
	assertFieldType(t, manifestType, "WorkerRouting", reflect.TypeOf((*sandbox.WorkerRoutingMetadata)(nil)))

	finishedAt := time.Date(2026, 6, 30, 3, 4, 5, 0, time.UTC)
	manifest := Manifest{
		ID:          "exec-1",
		Purpose:     PurposeRun,
		SandboxName: "dev",
		ProjectDir:  "/repo",
		Command:     []string{"go", "test", "./..."},
		WorkDir:     "/repo",
		Status:      StatusSucceeded,
		StartedAt:   time.Date(2026, 6, 30, 2, 0, 0, 0, time.UTC),
		FinishedAt:  &finishedAt,
		Workspace: &sandbox.SandboxWorkspace{
			Mode:        sandbox.SandboxWorkspaceModeClone,
			InputSource: sandbox.SandboxWorkspaceInputSourceRemoteRef,
			Repo:        "git@example.com:repo.git",
			Branch:      "main",
			SyncRef:     "abc123",
		},
		Host: &sandbox.SandboxHost{
			ID:   "host-1",
			Name: "worker",
			Kind: sandbox.SandboxHostKindWorker,
		},
		Runtime: &sandbox.SandboxRuntimeState{
			Driver:         sandbox.SandboxRuntimeDriverSSHMachine,
			IsolationLevel: sandbox.SandboxIsolationLevelVM,
			RuntimeID:      "runtime-1",
			Image:          "hal",
			WorkerID:       "worker-1",
		},
		Security: &sandbox.SandboxSecurity{
			Network: &sandbox.SandboxNetworkSecurity{
				PolicyRequested: "default",
				PolicyEnforced:  "default",
				EnforcementMode: sandbox.SandboxNetworkEnforcementModeBestEffort,
			},
		},
		NetworkProxySession: &sandbox.SandboxNetworkProxySessionMetadata{
			ID:     "proxy-session-01",
			Source: sandbox.SandboxNetworkPolicyDecisionSourceRun,
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:     "policy-snapshot-01",
				Preset: sandbox.SandboxNetworkPolicyPresetDenyByDefault,
			},
			EnforcementMode: sandbox.SandboxNetworkEnforcementModeProxy,
		},
		NetworkPolicyDecisionLogs: []sandbox.SandboxNetworkPolicyDecisionLogRecord{{
			ID:             "decision-01",
			Source:         sandbox.SandboxNetworkPolicyDecisionSourceRun,
			ProxySessionID: "proxy-session-01",
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:     "policy-snapshot-01",
				Preset: sandbox.SandboxNetworkPolicyPresetDenyByDefault,
			},
			Request: &sandbox.SandboxNetworkPolicyRequestSummary{
				ID:                  "request-01",
				Operation:           "connect",
				DestinationCategory: sandbox.SandboxNetworkPolicyDestinationPublicInternet,
			},
			Outcome:         sandbox.SandboxNetworkPolicyDecisionOutcomeAllowed,
			ReasonCode:      sandbox.SandboxNetworkPolicyDecisionReasonMatchedAllowRule,
			RuleKind:        sandbox.SandboxNetworkPolicyRuleKindDomain,
			PolicyPreset:    sandbox.SandboxNetworkPolicyPresetDenyByDefault,
			EnforcementMode: sandbox.SandboxNetworkEnforcementModeProxy,
		}},
		CredentialProxyPlan: &sandbox.SandboxCredentialProxyPlanMetadata{
			ID:                    "credential-plan-01",
			Source:                sandbox.SandboxCredentialProxySourceRun,
			SecretBrokerSessionID: "secret-session-01",
			NetworkProxySessionID: "proxy-session-01",
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:     "policy-snapshot-01",
				Preset: sandbox.SandboxNetworkPolicyPresetDenyByDefault,
			},
			BindingCount: 1,
			Mode:         sandbox.SandboxCredentialProxyModeBrokeredNetworkReference,
			Status:       sandbox.SandboxCredentialProxyStatusPlanned,
		},
		CredentialProxySession: &sandbox.SandboxCredentialProxySessionMetadata{
			ID:                    "credential-session-01",
			PlanID:                "credential-plan-01",
			Source:                sandbox.SandboxCredentialProxySourceRun,
			SecretBrokerSessionID: "secret-session-01",
			NetworkProxySessionID: "proxy-session-01",
			PolicySnapshot: &sandbox.SandboxNetworkPolicySnapshotIdentity{
				ID:     "policy-snapshot-01",
				Preset: sandbox.SandboxNetworkPolicyPresetDenyByDefault,
			},
			Status:      sandbox.SandboxCredentialProxyStatusActive,
			WarningCode: sandbox.SandboxCredentialProxyWarningBindingOmitted,
			ReasonCode:  sandbox.SandboxCredentialProxyReasonRequested,
		},
		CredentialProxyBindings: []sandbox.SandboxCredentialProxyBindingMetadata{{
			ID:                  "credential-binding-01",
			PlanID:              "credential-plan-01",
			SessionID:           "credential-session-01",
			SecretID:            "env:GITHUB_TOKEN",
			DeliveryMode:        sandbox.SandboxCredentialProxyDeliveryModeHTTPProxy,
			RequestCategory:     sandbox.SandboxCredentialProxyRequestNetworkAuth,
			DestinationCategory: sandbox.SandboxNetworkPolicyDestinationPublicInternet,
			Outcome:             sandbox.SandboxCredentialProxyBindingOutcomeBound,
			Status:              sandbox.SandboxCredentialProxyStatusActive,
			ReasonCode:          sandbox.SandboxCredentialProxyReasonRequested,
		}},
		CredentialDelivery: &sandbox.SandboxCredentialDeliveryStatusMetadata{
			ID:             "credential-plan-01",
			PlanID:         "credential-plan-01",
			RequestedModes: []string{sandbox.SandboxSecretModeHTTPProxy},
			Status:         "planned",
			WarningCount:   1,
		},
		Lease: &sandbox.SandboxLeaseRef{
			ID:            "lease-1",
			HostID:        "host-1",
			HostName:      "worker",
			RuntimeDriver: sandbox.SandboxRuntimeDriverSSHMachine,
			ResourceKey:   "sandbox:dev",
			Holder:        "hal",
			Purpose:       sandbox.SandboxLeasePurposeRun,
			RunID:         "exec-1",
			AcquiredAt:    time.Date(2026, 6, 30, 3, 0, 0, 0, time.UTC),
			ExpiresAt:     time.Date(2026, 6, 30, 4, 0, 0, 0, time.UTC),
		},
		WorkerRouting: &sandbox.WorkerRoutingMetadata{
			SelectedWorkerHostID:   "host-1",
			SelectedWorkerHostName: "worker",
			RuntimeDriverID:        sandbox.SandboxRuntimeDriverRootlessPodman,
			IsolationLevel:         sandbox.SandboxIsolationLevelContainer,
			EndpointSummary:        "local Unix socket",
		},
		Artifacts: []Artifact{{ID: "log", Name: "Log", Type: "text"}},
		ArtifactMetadata: &ArtifactMetadata{
			Collected: []ArtifactMetadataEntry{{
				ID:         "prd",
				Name:       "PRD",
				Type:       "json",
				Path:       ".hal/prd.json",
				StoredPath: "exec-1/artifacts/hal-prd.json",
			}},
			Partial: []ArtifactMetadataEntry{{
				ID:   "reports",
				Name: "Reports",
				Path: ".hal/reports.tar",
			}},
			Warnings: []ArtifactWarning{{
				Phase:   "reports-archive",
				Message: "reports directory missing",
				Artifact: ArtifactMetadataEntry{
					ID:   "reports",
					Name: "Reports",
					Path: ".hal/reports.tar",
				},
			}},
		},
	}

	got := mustJSONMap(t, manifest)
	assertJSONKeys(t, got, []string{
		"id", "purpose", "sandboxName", "projectDir", "command", "workDir",
		"status", "startedAt", "finishedAt", "workspace", "host", "runtime",
		"security", "networkProxySession", "networkPolicyDecisionLogs",
		"credentialProxyPlan", "credentialProxySession", "credentialProxyBindings", "credentialDelivery",
		"lease", "workerRouting", "artifacts", "artifactMetadata",
	})
	proxySession, ok := got["networkProxySession"].(map[string]any)
	if !ok {
		t.Fatalf("networkProxySession should be an object, got %T", got["networkProxySession"])
	}
	assertJSONKeys(t, proxySession, []string{
		"id", "source", "policySnapshot", "enforcementMode",
	})
	decisionLog := firstJSONArrayObject(t, got, "networkPolicyDecisionLogs")
	assertJSONKeys(t, decisionLog, []string{
		"id", "source", "proxySessionId", "policySnapshot", "request", "outcome",
		"reasonCode", "ruleKind", "policyPreset", "enforcementMode",
	})
	credentialProxyPlan, ok := got["credentialProxyPlan"].(map[string]any)
	if !ok {
		t.Fatalf("credentialProxyPlan should be an object, got %T", got["credentialProxyPlan"])
	}
	assertJSONKeys(t, credentialProxyPlan, []string{
		"id", "source", "secretBrokerSessionId", "networkProxySessionId",
		"policySnapshot", "bindingCount", "mode", "status",
	})
	credentialProxySession, ok := got["credentialProxySession"].(map[string]any)
	if !ok {
		t.Fatalf("credentialProxySession should be an object, got %T", got["credentialProxySession"])
	}
	assertJSONKeys(t, credentialProxySession, []string{
		"id", "planId", "source", "secretBrokerSessionId", "networkProxySessionId",
		"policySnapshot", "status", "warningCode", "reasonCode",
	})
	credentialProxyBinding := firstJSONArrayObject(t, got, "credentialProxyBindings")
	assertJSONKeys(t, credentialProxyBinding, []string{
		"id", "planId", "sessionId", "secretId", "deliveryMode", "requestCategory",
		"destinationCategory", "outcome", "status", "reasonCode",
	})
	credentialDelivery, ok := got["credentialDelivery"].(map[string]any)
	if !ok {
		t.Fatalf("credentialDelivery should be an object, got %T", got["credentialDelivery"])
	}
	assertJSONKeys(t, credentialDelivery, []string{
		"id", "planId", "requestedModes", "status", "warningCount",
	})
	if _, ok := credentialDelivery["activeModes"]; ok {
		t.Fatalf("plan-only credentialDelivery must not include activeModes: %#v", credentialDelivery)
	}
	lease, ok := got["lease"].(map[string]any)
	if !ok {
		t.Fatalf("lease should be an object, got %T", got["lease"])
	}
	assertJSONKeys(t, lease, []string{
		"id", "hostId", "hostName", "runtimeDriver", "resourceKey", "purpose",
		"runId", "acquiredAt", "expiresAt",
	})
	if _, ok := lease["holder"]; ok {
		t.Fatalf("lease holder must not be serialized: %#v", lease)
	}
	workerRouting, ok := got["workerRouting"].(map[string]any)
	if !ok {
		t.Fatalf("workerRouting should be an object, got %T", got["workerRouting"])
	}
	assertJSONKeys(t, workerRouting, []string{
		"selectedWorkerHostId",
		"selectedWorkerHostName",
		"runtimeDriverId",
		"isolationLevel",
		"endpointSummary",
	})

	emptyOptional := mustJSONMap(t, Manifest{
		ID:        "exec-1",
		Purpose:   PurposeRun,
		Status:    StatusRunning,
		StartedAt: time.Date(2026, 6, 30, 2, 0, 0, 0, time.UTC),
	})
	assertJSONKeys(t, emptyOptional, []string{"id", "purpose", "status", "startedAt"})
}

func TestManifestUnmarshalWithoutArtifactMetadata(t *testing.T) {
	data := []byte(`{
		"id": "exec-1",
		"purpose": "run",
		"status": "running",
		"startedAt": "2026-06-30T02:00:00Z",
		"artifacts": [
			{"id": "log", "name": "Log", "type": "text", "storedPath": "exec-1/artifacts/log.txt"}
		]
	}`)

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	if manifest.ArtifactMetadata != nil {
		t.Fatalf("ArtifactMetadata = %#v, want nil for legacy manifest", manifest.ArtifactMetadata)
	}
	if manifest.WorkerRouting != nil {
		t.Fatalf("WorkerRouting = %#v, want nil for legacy manifest", manifest.WorkerRouting)
	}
	if manifest.NetworkProxySession != nil {
		t.Fatalf("NetworkProxySession = %#v, want nil for legacy manifest", manifest.NetworkProxySession)
	}
	if len(manifest.NetworkPolicyDecisionLogs) != 0 {
		t.Fatalf("NetworkPolicyDecisionLogs = %#v, want empty for legacy manifest", manifest.NetworkPolicyDecisionLogs)
	}
	if manifest.CredentialProxyPlan != nil {
		t.Fatalf("CredentialProxyPlan = %#v, want nil for legacy manifest", manifest.CredentialProxyPlan)
	}
	if manifest.CredentialProxySession != nil {
		t.Fatalf("CredentialProxySession = %#v, want nil for legacy manifest", manifest.CredentialProxySession)
	}
	if len(manifest.CredentialProxyBindings) != 0 {
		t.Fatalf("CredentialProxyBindings = %#v, want empty for legacy manifest", manifest.CredentialProxyBindings)
	}
	if manifest.CredentialDelivery != nil {
		t.Fatalf("CredentialDelivery = %#v, want nil for legacy manifest", manifest.CredentialDelivery)
	}
	if len(manifest.Artifacts) != 1 || manifest.Artifacts[0].StoredPath != "exec-1/artifacts/log.txt" {
		t.Fatalf("legacy artifacts = %#v, want preserved artifact", manifest.Artifacts)
	}
}

func TestManifestPurposeAndStatusConstants(t *testing.T) {
	if PurposeRun != "run" || PurposeAuto != "auto" {
		t.Fatalf("purpose constants = %q/%q, want run/auto", PurposeRun, PurposeAuto)
	}
	if StatusRunning != "running" || StatusSucceeded != "succeeded" || StatusFailed != "failed" || StatusCanceled != "canceled" {
		t.Fatalf("status constants = %q/%q/%q/%q, want running/succeeded/failed/canceled", StatusRunning, StatusSucceeded, StatusFailed, StatusCanceled)
	}
}

func firstJSONArrayObject(t *testing.T, values map[string]any, key string) map[string]any {
	t.Helper()
	items, ok := values[key].([]any)
	if !ok {
		t.Fatalf("%s should be an array, got %T", key, values[key])
	}
	if len(items) == 0 {
		t.Fatalf("%s should not be empty", key)
	}
	first, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("%s[0] should be an object, got %T", key, items[0])
	}
	return first
}

func assertFieldType(t *testing.T, typ reflect.Type, fieldName string, want reflect.Type) {
	t.Helper()
	field, ok := typ.FieldByName(fieldName)
	if !ok {
		t.Fatalf("Manifest.%s field missing", fieldName)
	}
	if field.Type != want {
		t.Fatalf("Manifest.%s type = %v, want %v", fieldName, field.Type, want)
	}
}

func mustJSONMap(t *testing.T, value any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error: %v", err)
	}
	return got
}

func assertJSONKeys(t *testing.T, got map[string]any, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("keys = %v, want %v", mapKeys(got), want)
	}
	for _, key := range want {
		if _, ok := got[key]; !ok {
			t.Fatalf("key %q missing from %v", key, mapKeys(got))
		}
	}
}

func mapKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}
