package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/template"
)

// fakeSnapshotCreator returns a snapshotCreator that captures the call args and returns the given values.
func fakeSnapshotCreator(returnID string, returnErr error) (snapshotCreator, *snapshotCreateCall) {
	call := &snapshotCreateCall{}
	fn := func(ctx context.Context, apiKey, serverURL, name, dockerfileContent string, out io.Writer) (string, error) {
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.name = name
		call.dockerfileContent = dockerfileContent
		call.called = true
		return returnID, returnErr
	}
	return fn, call
}

type snapshotCreateCall struct {
	called            bool
	apiKey            string
	serverURL         string
	name              string
	dockerfileContent string
}

func setupSnapshotTest(t *testing.T, dir string, apiKey, serverURL string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	cfg := &compound.DaytonaConfig{APIKey: apiKey, ServerURL: serverURL}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
}

func writeDockerfile(t *testing.T, dir, relPath, content string) {
	t.Helper()
	fullPath := filepath.Join(dir, relPath)
	os.MkdirAll(filepath.Dir(fullPath), 0755)
	if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestRunSnapshotCreate(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		dockerfile string
		snapName   string
		creatorID  string
		creatorErr error
		wantErr    string
		wantOutput string
		checkFn    func(t *testing.T, call *snapshotCreateCall)
	}{
		{
			name: "creates snapshot with default Dockerfile path",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "test-key", "https://api.example.com")
				writeDockerfile(t, dir, defaultDockerfilePath, "FROM ubuntu:22.04\nRUN echo hello")
			},
			creatorID:  "snap-123",
			wantOutput: "Snapshot created: snap-123",
			checkFn: func(t *testing.T, call *snapshotCreateCall) {
				if !call.called {
					t.Error("creator was not called")
				}
				if call.apiKey != "test-key" {
					t.Errorf("apiKey = %q, want %q", call.apiKey, "test-key")
				}
				if call.serverURL != "https://api.example.com" {
					t.Errorf("serverURL = %q, want %q", call.serverURL, "https://api.example.com")
				}
				if call.name != "sandbox" {
					t.Errorf("name = %q, want %q", call.name, "sandbox")
				}
				if !strings.Contains(call.dockerfileContent, "FROM ubuntu:22.04") {
					t.Errorf("dockerfileContent does not contain FROM line: %q", call.dockerfileContent)
				}
			},
		},
		{
			name: "creates snapshot with custom Dockerfile path",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key2", "https://api2.example.com")
				writeDockerfile(t, dir, "custom/Dockerfile.dev", "FROM node:18\nRUN npm install")
			},
			dockerfile: "custom/Dockerfile.dev",
			creatorID:  "snap-456",
			wantOutput: "Snapshot created: snap-456",
			checkFn: func(t *testing.T, call *snapshotCreateCall) {
				if call.name != "custom" {
					t.Errorf("name = %q, want %q (derived from directory)", call.name, "custom")
				}
				if !strings.Contains(call.dockerfileContent, "FROM node:18") {
					t.Errorf("dockerfileContent does not contain FROM line: %q", call.dockerfileContent)
				}
			},
		},
		{
			name: "uses explicit snapshot name",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key3", "")
				writeDockerfile(t, dir, defaultDockerfilePath, "FROM alpine")
			},
			snapName:   "my-snapshot",
			creatorID:  "snap-789",
			wantOutput: "Snapshot created: snap-789",
			checkFn: func(t *testing.T, call *snapshotCreateCall) {
				if call.name != "my-snapshot" {
					t.Errorf("name = %q, want %q", call.name, "my-snapshot")
				}
			},
		},
		{
			name: "error when .hal/ does not exist",
			setup: func(t *testing.T, dir string) {
				// don't create .hal/
			},
			wantErr: ".hal/ not found",
		},
		{
			name: "error when Dockerfile does not exist",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key4", "")
				// don't create Dockerfile
			},
			wantErr: "Dockerfile not found",
		},
		{
			name: "error when snapshot creation fails",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key5", "")
				writeDockerfile(t, dir, defaultDockerfilePath, "FROM ubuntu:22.04")
			},
			creatorErr: fmt.Errorf("API error: quota exceeded"),
			wantErr:    "snapshot creation failed",
		},
		{
			name: "prints creating message with Dockerfile path",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key6", "")
				writeDockerfile(t, dir, defaultDockerfilePath, "FROM ubuntu:22.04")
			},
			creatorID:  "snap-abc",
			wantOutput: "Creating snapshot",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.setup != nil {
				tt.setup(t, dir)
			}

			creator, call := fakeSnapshotCreator(tt.creatorID, tt.creatorErr)
			var out bytes.Buffer

			err := runSnapshotCreate(dir, tt.dockerfile, tt.snapName, &out, creator)

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

			if tt.wantOutput != "" && !strings.Contains(out.String(), tt.wantOutput) {
				t.Errorf("output %q does not contain %q", out.String(), tt.wantOutput)
			}

			if tt.checkFn != nil {
				tt.checkFn(t, call)
			}
		})
	}
}

// fakeSnapshotDeleter returns a snapshotDeleter that captures the call args and returns the given error.
func fakeSnapshotDeleter(returnErr error) (snapshotDeleter, *snapshotDeleteCall) {
	call := &snapshotDeleteCall{}
	fn := func(ctx context.Context, apiKey, serverURL, snapshotID string) error {
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.snapshotID = snapshotID
		call.called = true
		return returnErr
	}
	return fn, call
}

type snapshotDeleteCall struct {
	called     bool
	apiKey     string
	serverURL  string
	snapshotID string
}

func TestRunSnapshotDelete(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		snapshotID string
		deleterErr error
		wantErr    string
		wantOutput string
		checkFn    func(t *testing.T, call *snapshotDeleteCall)
	}{
		{
			name: "deletes snapshot by ID",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "test-key", "https://api.example.com")
			},
			snapshotID: "snap-123",
			wantOutput: "Snapshot \"snap-123\" deleted.",
			checkFn: func(t *testing.T, call *snapshotDeleteCall) {
				if !call.called {
					t.Error("deleter was not called")
				}
				if call.apiKey != "test-key" {
					t.Errorf("apiKey = %q, want %q", call.apiKey, "test-key")
				}
				if call.serverURL != "https://api.example.com" {
					t.Errorf("serverURL = %q, want %q", call.serverURL, "https://api.example.com")
				}
				if call.snapshotID != "snap-123" {
					t.Errorf("snapshotID = %q, want %q", call.snapshotID, "snap-123")
				}
			},
		},
		{
			name: "passes credentials to deleter",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "my-api-key", "https://custom.server.com")
			},
			snapshotID: "snap-456",
			wantOutput: "Snapshot \"snap-456\" deleted.",
			checkFn: func(t *testing.T, call *snapshotDeleteCall) {
				if call.apiKey != "my-api-key" {
					t.Errorf("apiKey = %q, want %q", call.apiKey, "my-api-key")
				}
				if call.serverURL != "https://custom.server.com" {
					t.Errorf("serverURL = %q, want %q", call.serverURL, "https://custom.server.com")
				}
			},
		},
		{
			name: "error when .hal/ does not exist",
			setup: func(t *testing.T, dir string) {
				// don't create .hal/
			},
			snapshotID: "snap-123",
			wantErr:    ".hal/ not found",
		},
		{
			name: "error when snapshot ID is empty",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key", "")
			},
			snapshotID: "",
			wantErr:    "snapshot ID is required",
		},
		{
			name: "error when snapshot deletion fails",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key2", "")
			},
			snapshotID: "snap-bad",
			deleterErr: fmt.Errorf("API error: not found"),
			wantErr:    "snapshot deletion failed",
		},
		{
			name: "prints deleting message",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key3", "")
			},
			snapshotID: "snap-abc",
			wantOutput: "Deleting snapshot \"snap-abc\"...",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.setup != nil {
				tt.setup(t, dir)
			}

			deleter, call := fakeSnapshotDeleter(tt.deleterErr)
			var out bytes.Buffer

			err := runSnapshotDelete(dir, tt.snapshotID, &out, deleter)

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

			if tt.wantOutput != "" && !strings.Contains(out.String(), tt.wantOutput) {
				t.Errorf("output %q does not contain %q", out.String(), tt.wantOutput)
			}

			if tt.checkFn != nil {
				tt.checkFn(t, call)
			}
		})
	}
}

func TestRunSnapshotDelete_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Save empty API key to config
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	deleter, _ := fakeSnapshotDeleter(nil)
	var out bytes.Buffer

	err := runSnapshotDelete(dir, "snap-123", &out, deleter)

	// Should fail because EnsureAuth will try interactive setup with os.Stdin
	// which doesn't have data, but the key will remain empty
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}

func TestRunSnapshotCreate_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Save empty API key to config
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	writeDockerfile(t, dir, defaultDockerfilePath, "FROM ubuntu:22.04")
	creator, _ := fakeSnapshotCreator("snap-id", nil)
	var out bytes.Buffer

	err := runSnapshotCreate(dir, "", "", &out, creator)

	// Should fail because EnsureAuth will try interactive setup with os.Stdin
	// which doesn't have data, but the key will remain empty
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}
