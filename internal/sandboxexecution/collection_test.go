package sandboxexecution

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

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

func readStoreFile(t *testing.T, store Store, storedPath string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(store.Root(), filepath.FromSlash(storedPath)))
	if err != nil {
		t.Fatalf("ReadFile(%s) error: %v", storedPath, err)
	}
	return string(data)
}

type recordingArtifactRuntime struct {
	execs    []sandboxruntime.ExecRequest
	copyOuts []sandboxruntime.CopyRequest
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
	return &sandboxruntime.ExecResult{ExitCode: 0}, nil
}

func (r *recordingArtifactRuntime) CopyOut(_ context.Context, req sandboxruntime.CopyRequest) error {
	r.copyOuts = append(r.copyOuts, req)
	if err := os.MkdirAll(filepath.Dir(req.DestinationPath), 0o700); err != nil {
		return err
	}
	return os.WriteFile(req.DestinationPath, []byte("copied:"+req.SourcePath+"\n"), 0o600)
}
