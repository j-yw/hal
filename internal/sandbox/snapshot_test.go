package sandbox

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
)

func TestReadDockerfile(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T, dir string) string
		wantErr string
		wantLen int // minimum expected content length
	}{
		{
			name: "reads existing Dockerfile",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "Dockerfile")
				os.WriteFile(path, []byte("FROM ubuntu:22.04\nRUN echo hello"), 0644)
				return path
			},
			wantLen: 10,
		},
		{
			name: "error when Dockerfile does not exist",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				return filepath.Join(dir, "nonexistent", "Dockerfile")
			},
			wantErr: "Dockerfile not found",
		},
		{
			name: "reads empty Dockerfile",
			setup: func(t *testing.T, dir string) string {
				t.Helper()
				path := filepath.Join(dir, "Dockerfile")
				os.WriteFile(path, []byte(""), 0644)
				return path
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := tt.setup(t, dir)

			content, err := ReadDockerfile(path)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(content) < tt.wantLen {
				t.Errorf("content length %d, want at least %d", len(content), tt.wantLen)
			}
		})
	}
}

func TestCreateSnapshot_SucceedsWhenFinalStateIsActive(t *testing.T) {
	t.Helper()

	type createCall struct {
		called bool
		params *types.CreateSnapshotParams
	}
	type getCall struct {
		called   bool
		nameOrID string
	}

	createRecorder := &createCall{}
	getRecorder := &getCall{}
	createFn := func(ctx context.Context, params *types.CreateSnapshotParams) (*types.Snapshot, <-chan string, error) {
		createRecorder.called = true
		createRecorder.params = params

		logChan := make(chan string, 2)
		logChan <- "pulling image"
		logChan <- "build complete"
		close(logChan)

		return &types.Snapshot{ID: "snap-123"}, logChan, nil
	}
	getFn := func(ctx context.Context, nameOrID string) (*types.Snapshot, error) {
		getRecorder.called = true
		getRecorder.nameOrID = nameOrID
		return &types.Snapshot{ID: "snap-123", State: snapshotStateActive}, nil
	}

	var out bytes.Buffer
	gotID, err := createSnapshot(context.Background(), "hal-dev", "ghcr.io/jywlabs/hal-sandbox:latest", &out, createFn, getFn)
	if err != nil {
		t.Fatalf("createSnapshot returned error: %v", err)
	}
	if gotID != "snap-123" {
		t.Fatalf("snapshot ID = %q, want %q", gotID, "snap-123")
	}
	if !createRecorder.called {
		t.Fatal("createFn was not called")
	}
	if createRecorder.params == nil {
		t.Fatal("create params were not captured")
	}
	if createRecorder.params.Name != "hal-dev" {
		t.Fatalf("params.Name = %q, want %q", createRecorder.params.Name, "hal-dev")
	}
	if createRecorder.params.Image == nil {
		t.Fatal("params.Image should not be nil")
	}
	if !getRecorder.called {
		t.Fatal("getFn was not called")
	}
	if getRecorder.nameOrID != "snap-123" {
		t.Fatalf("get nameOrID = %q, want %q", getRecorder.nameOrID, "snap-123")
	}
	if !strings.Contains(out.String(), "pulling image") || !strings.Contains(out.String(), "build complete") {
		t.Fatalf("log output did not contain expected lines: %q", out.String())
	}
}

func TestCreateSnapshot_FailsWhenFinalStateIsBuildFailed(t *testing.T) {
	t.Helper()

	createFn := func(ctx context.Context, params *types.CreateSnapshotParams) (*types.Snapshot, <-chan string, error) {
		logChan := make(chan string)
		close(logChan)
		return &types.Snapshot{ID: "snap-456"}, logChan, nil
	}

	reason := "invalid image reference"
	getFn := func(ctx context.Context, nameOrID string) (*types.Snapshot, error) {
		return &types.Snapshot{
			ID:          "snap-456",
			State:       "build_failed",
			ErrorReason: &reason,
		}, nil
	}

	_, err := createSnapshot(context.Background(), "bad-snap", "bad:image", &bytes.Buffer{}, createFn, getFn)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "build_failed") {
		t.Fatalf("error %q does not contain state", err.Error())
	}
	if !strings.Contains(err.Error(), reason) {
		t.Fatalf("error %q does not contain reason %q", err.Error(), reason)
	}
}

func TestCreateSnapshot_FailsWhenStatusLookupFails(t *testing.T) {
	t.Helper()

	createFn := func(ctx context.Context, params *types.CreateSnapshotParams) (*types.Snapshot, <-chan string, error) {
		logChan := make(chan string)
		close(logChan)
		return &types.Snapshot{ID: "snap-789"}, logChan, nil
	}

	getFn := func(ctx context.Context, nameOrID string) (*types.Snapshot, error) {
		return nil, errors.New("request timeout")
	}

	_, err := createSnapshot(context.Background(), "snap", "ubuntu:22.04", &bytes.Buffer{}, createFn, getFn)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "checking snapshot") {
		t.Fatalf("error %q does not contain status-check prefix", err.Error())
	}
}
