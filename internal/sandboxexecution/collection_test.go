package sandboxexecution

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

func TestCollectRuntimeArtifactsUsesExecAndCopyOutBoundary(t *testing.T) {
	store := newTestStore(t)
	runtime := &recordingArtifactRuntime{}
	target := sandboxruntime.Target{
		ID:       "target-1",
		Name:     "phase-dev",
		Provider: "daytona",
		Runtime: sandboxruntime.RuntimeState{
			Driver: sandboxruntime.DriverSSHMachine,
		},
		Connection: sandboxruntime.ConnectionInfo{
			WorkspaceID: "workspace-1",
		},
	}

	result, err := CollectRuntimeArtifacts(context.Background(), RuntimeCollectionRequest{
		ExecutionID: "exec-1",
		Store:       store,
		Runtime:     runtime,
		Target:      target,
		Artifacts: []RuntimeArtifactRequest{
			{
				Area: ArtifactStoreAreaRecovery,
				Artifact: ArtifactMetadataEntry{
					ID:   "recovery",
					Name: "Recovery Patch",
					Type: "patch",
					Path: ".hal/recovery/recovery.patch",
				},
				PayloadPath: "patches/recovery.patch",
				RemotePath:  "/workspace/repo/.hal/recovery/recovery.patch",
				Generate: &RuntimeArtifactGeneration{
					Args:    []string{"sh", "-lc", "git diff > .hal/recovery/recovery.patch"},
					WorkDir: "/workspace/repo",
					Env: map[string]string{
						"HAL_PURPOSE": "run",
					},
				},
			},
			{
				Artifact: ArtifactMetadataEntry{
					ID:   "prd",
					Name: "PRD",
					Type: "json",
					Path: ".hal/prd.json",
				},
				PayloadPath: "core/hal-prd.json",
				RemotePath:  "/workspace/repo/.hal/prd.json",
			},
		},
	})
	if err != nil {
		t.Fatalf("CollectRuntimeArtifacts() error: %v", err)
	}

	if len(runtime.execs) != 1 {
		t.Fatalf("Exec calls = %d, want 1", len(runtime.execs))
	}
	exec := runtime.execs[0]
	if exec.Target.Name != "phase-dev" || exec.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("Exec target = %#v, want runtime target", exec.Target)
	}
	if !reflect.DeepEqual(exec.Args, []string{"sh", "-lc", "git diff > .hal/recovery/recovery.patch"}) {
		t.Fatalf("Exec args = %#v", exec.Args)
	}
	if exec.WorkDir != "/workspace/repo" || exec.Env["HAL_PURPOSE"] != "run" {
		t.Fatalf("Exec workdir/env = %q/%#v", exec.WorkDir, exec.Env)
	}

	if len(runtime.copyOuts) != 2 {
		t.Fatalf("CopyOut calls = %d, want 2", len(runtime.copyOuts))
	}
	if got, want := runtime.copyOuts[0].SourcePath, "/workspace/repo/.hal/recovery/recovery.patch"; got != want {
		t.Fatalf("first CopyOut source = %q, want %q", got, want)
	}
	if got, want := runtime.copyOuts[1].SourcePath, "/workspace/repo/.hal/prd.json"; got != want {
		t.Fatalf("second CopyOut source = %q, want %q", got, want)
	}
	for _, copyOut := range runtime.copyOuts {
		if copyOut.Target.Name != "phase-dev" || copyOut.Target.Connection.WorkspaceID != "workspace-1" {
			t.Fatalf("CopyOut target = %#v, want runtime target", copyOut.Target)
		}
	}

	collected := result.ArtifactMetadata.Collected
	if len(collected) != 2 {
		t.Fatalf("collected metadata = %#v, want 2 entries", collected)
	}
	if got, want := collected[0].StoredPath, "exec-1/recovery/patches/recovery.patch"; got != want {
		t.Fatalf("recovery storedPath = %q, want %q", got, want)
	}
	if got, want := collected[1].StoredPath, "exec-1/artifacts/core/hal-prd.json"; got != want {
		t.Fatalf("prd storedPath = %q, want %q", got, want)
	}
	for _, artifact := range collected {
		if artifact.SizeBytes == nil || *artifact.SizeBytes == 0 {
			t.Fatalf("artifact %q size = %v, want copied payload size", artifact.Path, artifact.SizeBytes)
		}
		if artifact.CreatedAt == nil || artifact.CreatedAt.IsZero() {
			t.Fatalf("artifact %q createdAt = %v, want stored timestamp", artifact.Path, artifact.CreatedAt)
		}
	}

	recoveryBytes := readStoreFile(t, store, collected[0].StoredPath)
	if !strings.Contains(recoveryBytes, "copied:/workspace/repo/.hal/recovery/recovery.patch") {
		t.Fatalf("stored recovery payload = %q, want copied remote payload", recoveryBytes)
	}
	prdBytes := readStoreFile(t, store, collected[1].StoredPath)
	if !strings.Contains(prdBytes, "copied:/workspace/repo/.hal/prd.json") {
		t.Fatalf("stored prd payload = %q, want copied remote payload", prdBytes)
	}

	encoded := string(mustJSONBytes(t, result.ArtifactMetadata))
	for _, forbidden := range []string{
		"/workspace/repo/.hal/recovery/recovery.patch",
		"/workspace/repo/.hal/prd.json",
		runtime.copyOuts[0].DestinationPath,
		runtime.copyOuts[1].DestinationPath,
		"DestinationPath",
		"SourcePath",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("collection metadata leaked runtime path %q: %s", forbidden, encoded)
		}
	}
}

func TestCollectRuntimeArtifactsRejectsInvalidInputBeforeRuntimeCalls(t *testing.T) {
	store := newTestStore(t)
	runtime := &recordingArtifactRuntime{}

	_, err := CollectRuntimeArtifacts(context.Background(), RuntimeCollectionRequest{
		ExecutionID: "exec-1",
		Store:       store,
		Runtime:     runtime,
		Artifacts: []RuntimeArtifactRequest{{
			Artifact:    ArtifactMetadataEntry{Path: ".hal/prd.json"},
			PayloadPath: "../escape",
			RemotePath:  "/workspace/repo/.hal/prd.json",
		}},
	})
	if err == nil {
		t.Fatalf("CollectRuntimeArtifacts() expected validation error")
	}
	if len(runtime.execs) != 0 || len(runtime.copyOuts) != 0 {
		t.Fatalf("runtime calls = exec:%d copyOut:%d, want none", len(runtime.execs), len(runtime.copyOuts))
	}
	assertPathMissing(t, store.Root())
}

func TestCollectRuntimeArtifactsClassifiesCopyOutResults(t *testing.T) {
	copyOutFailure := errors.New("remote copy failed with token-secret at /workspace/repo/.hal/reports.tar")

	cases := []struct {
		name               string
		optional           bool
		copyOutErr         error
		storeRootIsFile    bool
		wantErr            bool
		wantCollected      int
		wantPartial        int
		wantWarnings       int
		wantWarningPhase   string
		wantWarningMessage string
	}{
		{
			name:          "required present",
			wantCollected: 1,
		},
		{
			name:          "optional present",
			optional:      true,
			wantCollected: 1,
		},
		{
			name:               "optional missing",
			optional:           true,
			copyOutErr:         fs.ErrNotExist,
			wantPartial:        1,
			wantWarnings:       1,
			wantWarningPhase:   "copy_out",
			wantWarningMessage: "optional sandbox execution artifact is missing",
		},
		{
			name:       "required missing",
			copyOutErr: fs.ErrNotExist,
			wantErr:    true,
		},
		{
			name:               "optional copyout failure",
			optional:           true,
			copyOutErr:         copyOutFailure,
			wantPartial:        1,
			wantWarnings:       1,
			wantWarningPhase:   "copy_out",
			wantWarningMessage: "optional sandbox execution artifact copy failed",
		},
		{
			name:               "optional store persistence failure",
			optional:           true,
			storeRootIsFile:    true,
			wantPartial:        1,
			wantWarnings:       1,
			wantWarningPhase:   "store",
			wantWarningMessage: "optional sandbox execution artifact persistence failed",
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			if tt.storeRootIsFile {
				rootFile := filepath.Join(t.TempDir(), "sandbox-executions")
				if err := os.WriteFile(rootFile, []byte("not a directory\n"), 0o600); err != nil {
					t.Fatalf("WriteFile(store root) error: %v", err)
				}
				store = NewStore(rootFile)
			}
			runtime := &recordingArtifactRuntime{copyOutErr: tt.copyOutErr}

			result, err := CollectRuntimeArtifacts(context.Background(), RuntimeCollectionRequest{
				ExecutionID: "exec-1",
				Store:       store,
				Runtime:     runtime,
				Artifacts: []RuntimeArtifactRequest{{
					Optional: tt.optional,
					Artifact: ArtifactMetadataEntry{
						ID:   "reports",
						Name: "Reports Archive",
						Type: "tar",
						Path: ".hal/reports.tar",
					},
					PayloadPath: "reports/reports.tar",
					RemotePath:  "/workspace/repo/.hal/reports.tar",
				}},
			})

			if tt.wantErr {
				if err == nil {
					t.Fatalf("CollectRuntimeArtifacts() expected error")
				}
				if len(runtime.copyOuts) != 1 {
					t.Fatalf("CopyOut calls = %d, want 1", len(runtime.copyOuts))
				}
				return
			}
			if err != nil {
				t.Fatalf("CollectRuntimeArtifacts() error: %v", err)
			}
			if len(runtime.copyOuts) != 1 {
				t.Fatalf("CopyOut calls = %d, want 1", len(runtime.copyOuts))
			}
			metadata := result.ArtifactMetadata
			if len(metadata.Collected) != tt.wantCollected {
				t.Fatalf("collected = %#v, want %d entries", metadata.Collected, tt.wantCollected)
			}
			if len(metadata.Partial) != tt.wantPartial {
				t.Fatalf("partial = %#v, want %d entries", metadata.Partial, tt.wantPartial)
			}
			if len(metadata.Warnings) != tt.wantWarnings {
				t.Fatalf("warnings = %#v, want %d entries", metadata.Warnings, tt.wantWarnings)
			}

			if tt.wantCollected == 1 {
				collected := metadata.Collected[0]
				if got, want := collected.Path, ".hal/reports.tar"; got != want {
					t.Fatalf("collected path = %q, want %q", got, want)
				}
				if got, want := collected.StoredPath, "exec-1/artifacts/reports/reports.tar"; got != want {
					t.Fatalf("collected storedPath = %q, want %q", got, want)
				}
				if collected.SizeBytes == nil || collected.CreatedAt == nil {
					t.Fatalf("collected metadata missing size/time: %#v", collected)
				}
			}

			if tt.wantPartial == 1 {
				partial := metadata.Partial[0]
				if got, want := partial.Path, ".hal/reports.tar"; got != want {
					t.Fatalf("partial path = %q, want %q", got, want)
				}
				if partial.StoredPath != "" || partial.SizeBytes != nil || partial.CreatedAt != nil {
					t.Fatalf("partial metadata should not include stored fields: %#v", partial)
				}
				warning := metadata.Warnings[0]
				if warning.Phase != tt.wantWarningPhase || warning.Message != tt.wantWarningMessage {
					t.Fatalf("warning = %#v, want phase %q message %q", warning, tt.wantWarningPhase, tt.wantWarningMessage)
				}
				if warning.Artifact != partial {
					t.Fatalf("warning artifact = %#v, want partial %#v", warning.Artifact, partial)
				}

				encoded := string(mustJSONBytes(t, metadata))
				for _, forbidden := range []string{
					"/workspace/repo/.hal/reports.tar",
					"token-secret",
					"SourcePath",
					"DestinationPath",
				} {
					if strings.Contains(encoded, forbidden) {
						t.Fatalf("partial metadata leaked %q: %s", forbidden, encoded)
					}
				}
			}
		})
	}
}

func TestCollectCoreStateArtifactsRunCollectsStateAndPersistsManifest(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-1", time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	runtime := &recordingArtifactRuntime{}

	result, err := CollectCoreStateArtifacts(context.Background(), CoreStateCollectionRequest{
		ExecutionID:        "exec-1",
		Store:              store,
		Runtime:            runtime,
		Purpose:            PurposeRun,
		RemoteWorkspaceDir: "/workspace/repo",
	})
	if err != nil {
		t.Fatalf("CollectCoreStateArtifacts() error: %v", err)
	}

	if len(runtime.execs) != 0 {
		t.Fatalf("Exec calls = %d, want none for core state files", len(runtime.execs))
	}
	if got, want := copyOutSources(runtime.copyOuts), []string{"/workspace/repo/.hal/prd.json", "/workspace/repo/.hal/progress.txt"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CopyOut sources = %#v, want %#v", got, want)
	}
	if len(result.ArtifactMetadata.Collected) != 2 {
		t.Fatalf("collected = %#v, want PRD and progress artifacts", result.ArtifactMetadata.Collected)
	}
	assertCollectedCoreArtifact(t, result.ArtifactMetadata.Collected[0], ".hal/prd.json", "exec-1/artifacts/core/hal-prd.json")
	assertCollectedCoreArtifact(t, result.ArtifactMetadata.Collected[1], ".hal/progress.txt", "exec-1/artifacts/core/hal-progress.txt")
	if len(result.ArtifactMetadata.Partial) != 0 || len(result.ArtifactMetadata.Warnings) != 0 {
		t.Fatalf("run core metadata partial/warnings = %#v/%#v, want none", result.ArtifactMetadata.Partial, result.ArtifactMetadata.Warnings)
	}

	loaded, err := store.LoadManifest("exec-1")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if loaded.ArtifactMetadata == nil {
		t.Fatalf("manifest ArtifactMetadata = nil, want persisted core state metadata")
	}
	if !reflect.DeepEqual(loaded.ArtifactMetadata.Collected, result.ArtifactMetadata.Collected) {
		t.Fatalf("manifest collected = %#v, want %#v", loaded.ArtifactMetadata.Collected, result.ArtifactMetadata.Collected)
	}
	if len(loaded.ArtifactMetadata.Warnings) != 0 {
		t.Fatalf("manifest warnings = %#v, want none for missing run auto-state", loaded.ArtifactMetadata.Warnings)
	}
	for _, source := range copyOutSources(runtime.copyOuts) {
		if strings.Contains(source, "auto-state") {
			t.Fatalf("run core state copied auto-state source %q, want auto-state omitted", source)
		}
	}

	encoded := string(mustJSONBytes(t, loaded.ArtifactMetadata))
	for _, forbidden := range []string{"/workspace/repo/.hal/prd.json", "/workspace/repo/.hal/progress.txt", "SourcePath", "DestinationPath"} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("manifest core metadata leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestCollectCoreStateArtifactsAutoCollectsAutoState(t *testing.T) {
	store := newTestStore(t)
	manifest := testManifest("exec-1", time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC))
	manifest.Purpose = PurposeAuto
	if err := store.SaveManifest(manifest); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	runtime := &recordingArtifactRuntime{}

	result, err := CollectCoreStateArtifacts(context.Background(), CoreStateCollectionRequest{
		ExecutionID:        "exec-1",
		Store:              store,
		Runtime:            runtime,
		Purpose:            PurposeAuto,
		RemoteWorkspaceDir: "/workspace/repo",
	})
	if err != nil {
		t.Fatalf("CollectCoreStateArtifacts() error: %v", err)
	}

	if got, want := copyOutSources(runtime.copyOuts), []string{"/workspace/repo/.hal/prd.json", "/workspace/repo/.hal/progress.txt", "/workspace/repo/.hal/auto-state.json"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("CopyOut sources = %#v, want %#v", got, want)
	}
	if len(result.ArtifactMetadata.Collected) != 3 {
		t.Fatalf("collected = %#v, want PRD, progress, and auto-state artifacts", result.ArtifactMetadata.Collected)
	}
	assertCollectedCoreArtifact(t, result.ArtifactMetadata.Collected[2], ".hal/auto-state.json", "exec-1/artifacts/core/hal-auto-state.json")

	loaded, err := store.LoadManifest("exec-1")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if loaded.ArtifactMetadata == nil || len(loaded.ArtifactMetadata.Collected) != 3 {
		t.Fatalf("manifest collected = %#v, want 3 persisted core state artifacts", loaded.ArtifactMetadata)
	}
}

func TestCollectCoreStateArtifactsMissingRequiredPRDReturnsError(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-1", time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	runtime := &recordingArtifactRuntime{copyOutErr: fs.ErrNotExist}

	_, err := CollectCoreStateArtifacts(context.Background(), CoreStateCollectionRequest{
		ExecutionID:        "exec-1",
		Store:              store,
		Runtime:            runtime,
		Purpose:            PurposeRun,
		RemoteWorkspaceDir: "/workspace/repo",
	})
	if err == nil {
		t.Fatalf("CollectCoreStateArtifacts() expected missing PRD error")
	}
	if len(runtime.copyOuts) != 1 {
		t.Fatalf("CopyOut calls = %d, want only required PRD attempt", len(runtime.copyOuts))
	}
	if got, want := runtime.copyOuts[0].SourcePath, "/workspace/repo/.hal/prd.json"; got != want {
		t.Fatalf("CopyOut source = %q, want %q", got, want)
	}
	loaded, err := store.LoadManifest("exec-1")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if loaded.ArtifactMetadata != nil {
		t.Fatalf("manifest ArtifactMetadata = %#v, want no persisted metadata after fatal PRD failure", loaded.ArtifactMetadata)
	}
}

func TestCollectRecoveryArtifactsGeneratesCopiesAndPersistsManifest(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveManifest(testManifest("exec-1", time.Date(2026, 6, 30, 1, 0, 0, 0, time.UTC))); err != nil {
		t.Fatalf("SaveManifest() error: %v", err)
	}
	runtime := &recordingArtifactRuntime{}
	target := sandboxruntime.Target{
		ID:       "target-1",
		Name:     "phase-dev",
		Provider: "daytona",
		Runtime: sandboxruntime.RuntimeState{
			Driver: sandboxruntime.DriverSSHMachine,
		},
		Connection: sandboxruntime.ConnectionInfo{
			WorkspaceID: "workspace-1",
		},
	}

	result, err := CollectRecoveryArtifacts(context.Background(), RecoveryArtifactCollectionRequest{
		ExecutionID:        "exec-1",
		Store:              store,
		Runtime:            runtime,
		Target:             target,
		RemoteWorkspaceDir: "/workspace/repo",
	})
	if err != nil {
		t.Fatalf("CollectRecoveryArtifacts() error: %v", err)
	}

	if got, want := runtime.events, []string{"exec", "copy_out"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("runtime events = %#v, want %#v", got, want)
	}
	if len(runtime.execs) != 1 {
		t.Fatalf("Exec calls = %d, want 1", len(runtime.execs))
	}
	exec := runtime.execs[0]
	if !reflect.DeepEqual(exec.Args, []string{"sh", "-c", recoveryPatchGenerationScript()}) {
		t.Fatalf("Exec args = %#v, want recovery patch generation script", exec.Args)
	}
	if exec.WorkDir != "/workspace/repo" {
		t.Fatalf("Exec workdir = %q, want remote workspace", exec.WorkDir)
	}
	if exec.Target.Name != "phase-dev" || exec.Target.Runtime.Driver != sandboxruntime.DriverSSHMachine {
		t.Fatalf("Exec target = %#v, want runtime target", exec.Target)
	}
	if len(runtime.copyOuts) != 1 {
		t.Fatalf("CopyOut calls = %d, want 1", len(runtime.copyOuts))
	}
	copyOut := runtime.copyOuts[0]
	if got, want := copyOut.SourcePath, "/workspace/repo/.hal/recovery/workspace.patch"; got != want {
		t.Fatalf("CopyOut source = %q, want %q", got, want)
	}
	if copyOut.Target.Name != "phase-dev" || copyOut.Target.Connection.WorkspaceID != "workspace-1" {
		t.Fatalf("CopyOut target = %#v, want runtime target", copyOut.Target)
	}

	if len(result.ArtifactMetadata.Collected) != 1 {
		t.Fatalf("collected metadata = %#v, want recovery patch", result.ArtifactMetadata.Collected)
	}
	recovery := result.ArtifactMetadata.Collected[0]
	if recovery.ID != "recovery-patch" || recovery.Name != "Recovery Patch" || recovery.Type != "patch" {
		t.Fatalf("recovery metadata identity = %#v, want recovery patch metadata", recovery)
	}
	if got, want := recovery.Path, ".hal/recovery/workspace.patch"; got != want {
		t.Fatalf("recovery path = %q, want %q", got, want)
	}
	if got, want := recovery.StoredPath, "exec-1/recovery/workspace.patch"; got != want {
		t.Fatalf("recovery storedPath = %q, want %q", got, want)
	}
	if recovery.SizeBytes == nil || *recovery.SizeBytes == 0 {
		t.Fatalf("recovery size = %v, want copied payload size", recovery.SizeBytes)
	}
	if recovery.CreatedAt == nil || recovery.CreatedAt.IsZero() {
		t.Fatalf("recovery createdAt = %v, want stored timestamp", recovery.CreatedAt)
	}
	if payload := readStoreFile(t, store, recovery.StoredPath); !strings.Contains(payload, "copied:/workspace/repo/.hal/recovery/workspace.patch") {
		t.Fatalf("stored recovery payload = %q, want copied remote payload", payload)
	}

	loaded, err := store.LoadManifest("exec-1")
	if err != nil {
		t.Fatalf("LoadManifest() error: %v", err)
	}
	if loaded.ArtifactMetadata == nil || len(loaded.ArtifactMetadata.Collected) != 1 {
		t.Fatalf("manifest recovery metadata = %#v, want persisted recovery artifact", loaded.ArtifactMetadata)
	}
	if !reflect.DeepEqual(loaded.ArtifactMetadata.Collected[0], recovery) {
		t.Fatalf("manifest recovery metadata = %#v, want %#v", loaded.ArtifactMetadata.Collected[0], recovery)
	}

	encoded := string(mustJSONBytes(t, loaded.ArtifactMetadata))
	for _, forbidden := range []string{
		"/workspace/repo/.hal/recovery/workspace.patch",
		copyOut.DestinationPath,
		"SourcePath",
		"DestinationPath",
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("manifest recovery metadata leaked runtime path %q: %s", forbidden, encoded)
		}
	}
}

func readStoreFile(t *testing.T, store Store, storedPath string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(storedPath)))
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", storedPath, err)
	}
	return string(data)
}

func copyOutSources(copyOuts []sandboxruntime.CopyRequest) []string {
	sources := make([]string, 0, len(copyOuts))
	for _, copyOut := range copyOuts {
		sources = append(sources, copyOut.SourcePath)
	}
	return sources
}

func assertCollectedCoreArtifact(t *testing.T, artifact ArtifactMetadataEntry, wantPath, wantStoredPath string) {
	t.Helper()
	if artifact.Path != wantPath {
		t.Fatalf("artifact path = %q, want %q", artifact.Path, wantPath)
	}
	if artifact.StoredPath != wantStoredPath {
		t.Fatalf("artifact storedPath = %q, want %q", artifact.StoredPath, wantStoredPath)
	}
	if artifact.SizeBytes == nil || *artifact.SizeBytes == 0 {
		t.Fatalf("artifact size = %v, want copied payload size", artifact.SizeBytes)
	}
	if artifact.CreatedAt == nil || artifact.CreatedAt.IsZero() {
		t.Fatalf("artifact createdAt = %v, want stored timestamp", artifact.CreatedAt)
	}
}

type recordingArtifactRuntime struct {
	execs      []sandboxruntime.ExecRequest
	copyOuts   []sandboxruntime.CopyRequest
	copyOutErr error
	events     []string
}

func (r *recordingArtifactRuntime) Exec(_ context.Context, req sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error) {
	req.Args = append([]string(nil), req.Args...)
	if req.Env != nil {
		env := make(map[string]string, len(req.Env))
		for key, value := range req.Env {
			env[key] = value
		}
		req.Env = env
	}
	r.execs = append(r.execs, req)
	r.events = append(r.events, "exec")
	return &sandboxruntime.ExecResult{ExitCode: 0}, nil
}

func (r *recordingArtifactRuntime) CopyOut(_ context.Context, req sandboxruntime.CopyRequest) error {
	r.copyOuts = append(r.copyOuts, req)
	r.events = append(r.events, "copy_out")
	if r.copyOutErr != nil {
		return r.copyOutErr
	}
	if err := os.MkdirAll(filepath.Dir(req.DestinationPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(req.DestinationPath, []byte("copied:"+req.SourcePath+"\n"), 0o600)
}
