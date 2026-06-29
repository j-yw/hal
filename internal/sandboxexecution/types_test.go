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

func TestManifestJSONFieldsAndSandboxMetadataTypes(t *testing.T) {
	manifestType := reflect.TypeOf(Manifest{})
	assertFieldType(t, manifestType, "Workspace", reflect.TypeOf((*sandbox.SandboxWorkspace)(nil)))
	assertFieldType(t, manifestType, "Host", reflect.TypeOf((*sandbox.SandboxHost)(nil)))
	assertFieldType(t, manifestType, "Runtime", reflect.TypeOf((*sandbox.SandboxRuntimeState)(nil)))
	assertFieldType(t, manifestType, "Security", reflect.TypeOf((*sandbox.SandboxSecurity)(nil)))
	assertFieldType(t, manifestType, "Lease", reflect.TypeOf((*sandbox.SandboxLeaseRef)(nil)))

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
		Lease: &sandbox.SandboxLeaseRef{
			ID:          "lease-1",
			ResourceKey: "sandbox:dev",
			Holder:      "hal",
			Purpose:     sandbox.SandboxLeasePurposeRun,
			RunID:       "exec-1",
			ExpiresAt:   time.Date(2026, 6, 30, 4, 0, 0, 0, time.UTC),
		},
		Artifacts: []Artifact{{ID: "log", Name: "Log", Type: "text"}},
	}

	got := mustJSONMap(t, manifest)
	assertJSONKeys(t, got, []string{
		"id", "purpose", "sandboxName", "projectDir", "command", "workDir",
		"status", "startedAt", "finishedAt", "workspace", "host", "runtime",
		"security", "lease", "artifacts",
	})

	emptyOptional := mustJSONMap(t, Manifest{
		ID:        "exec-1",
		Purpose:   PurposeRun,
		Status:    StatusRunning,
		StartedAt: time.Date(2026, 6, 30, 2, 0, 0, 0, time.UTC),
	})
	assertJSONKeys(t, emptyOptional, []string{"id", "purpose", "status", "startedAt"})
}

func TestManifestPurposeAndStatusConstants(t *testing.T) {
	if PurposeRun != "run" || PurposeAuto != "auto" {
		t.Fatalf("purpose constants = %q/%q, want run/auto", PurposeRun, PurposeAuto)
	}
	if StatusRunning != "running" || StatusSucceeded != "succeeded" || StatusFailed != "failed" || StatusCanceled != "canceled" {
		t.Fatalf("status constants = %q/%q/%q/%q, want running/succeeded/failed/canceled", StatusRunning, StatusSucceeded, StatusFailed, StatusCanceled)
	}
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
