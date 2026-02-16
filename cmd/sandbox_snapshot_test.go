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
	fn := func(ctx context.Context, apiKey, serverURL, name, imageRef string, out io.Writer) (string, error) {
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.name = name
		call.imageRef = imageRef
		call.called = true
		return returnID, returnErr
	}
	return fn, call
}

type snapshotCreateCall struct {
	called    bool
	apiKey    string
	serverURL string
	name      string
	imageRef  string
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

func TestRunSnapshotCreate(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string)
		imageRef   string
		snapName   string
		creatorID  string
		creatorErr error
		wantErr    string
		wantOutput string
		checkFn    func(t *testing.T, call *snapshotCreateCall)
	}{
		{
			name: "creates snapshot with explicit registry image",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "test-key", "https://api.example.com")
			},
			imageRef:   "ghcr.io/jywlabs/hal-sandbox:latest",
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
				if call.name != "hal-sandbox" {
					t.Errorf("name = %q, want %q (derived from image ref)", call.name, "hal-sandbox")
				}
				if call.imageRef != "ghcr.io/jywlabs/hal-sandbox:latest" {
					t.Errorf("imageRef = %q, want %q", call.imageRef, "ghcr.io/jywlabs/hal-sandbox:latest")
				}
			},
		},
		{
			name: "creates snapshot with custom registry image",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key2", "https://api2.example.com")
			},
			imageRef:   "ghcr.io/jywlabs/hal-sandbox:0.1",
			creatorID:  "snap-456",
			wantOutput: "Snapshot created: snap-456",
			checkFn: func(t *testing.T, call *snapshotCreateCall) {
				if call.name != "hal-sandbox" {
					t.Errorf("name = %q, want %q (derived from image ref)", call.name, "hal-sandbox")
				}
				if call.imageRef != "ghcr.io/jywlabs/hal-sandbox:0.1" {
					t.Errorf("imageRef = %q, want %q", call.imageRef, "ghcr.io/jywlabs/hal-sandbox:0.1")
				}
			},
		},
		{
			name: "uses explicit snapshot name",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key3", "")
			},
			imageRef:   "docker.io/library/ubuntu:22.04",
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
			name: "error when image ref is empty",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key-empty", "")
			},
			wantErr: "image reference is required",
		},
		{
			name: "error when image ref is not registry-qualified",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key-local", "")
			},
			imageRef: "hal-sandbox:latest",
			wantErr:  "must include a registry host",
		},
		{
			name: "error when snapshot creation fails",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key5", "")
			},
			imageRef:   "ghcr.io/library/ubuntu:22.04",
			creatorErr: fmt.Errorf("API error: quota exceeded"),
			wantErr:    "snapshot creation failed",
		},
		{
			name: "prints creating message with image ref",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key6", "")
			},
			imageRef:   "ghcr.io/jywlabs/hal-sandbox:latest",
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

			err := runSnapshotCreate(dir, tt.imageRef, tt.snapName, &out, creator)

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

func TestImageNameFromRef(t *testing.T) {
	tests := []struct {
		ref  string
		want string
	}{
		{"hal-sandbox:latest", "hal-sandbox"},
		{"hal-sandbox:0.1", "hal-sandbox"},
		{"hal-sandbox", "hal-sandbox"},
		{"ghcr.io/jywlabs/hal-sandbox:latest", "hal-sandbox"},
		{"docker.io/library/ubuntu:22.04", "ubuntu"},
		{"ubuntu:22.04", "ubuntu"},
		{"ubuntu", "ubuntu"},
		{"localhost:5000/hal-sandbox", "hal-sandbox"},
		{"localhost:5000/hal-sandbox:1.0", "hal-sandbox"},
		{"localhost:5000/jywlabs/hal-sandbox:latest", "hal-sandbox"},
		{"ghcr.io/jywlabs/hal-sandbox@sha256:abcdef", "hal-sandbox"},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			got := imageNameFromRef(tt.ref)
			if got != tt.want {
				t.Errorf("imageNameFromRef(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}
}

func TestIsRegistryQualifiedImageRef(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{"ghcr.io/jywlabs/hal-sandbox:latest", true},
		{"docker.io/library/ubuntu:22.04", true},
		{"localhost:5000/hal-sandbox:1.0", true},
		{"localhost/hal-sandbox:1.0", true},
		{"hal-sandbox:latest", false},
		{"ubuntu:22.04", false},
		{"ubuntu", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			got := isRegistryQualifiedImageRef(tt.ref)
			if got != tt.want {
				t.Errorf("isRegistryQualifiedImageRef(%q) = %v, want %v", tt.ref, got, tt.want)
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

	creator, _ := fakeSnapshotCreator("snap-id", nil)
	var out bytes.Buffer

	err := runSnapshotCreate(dir, "docker.io/library/ubuntu:22.04", "", &out, creator)

	// Should fail because EnsureAuth will try interactive setup with os.Stdin
	// which doesn't have data, but the key will remain empty
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}
