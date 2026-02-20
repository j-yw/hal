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
	"time"

	daytonatypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/template"
)

type snapshotDockerfileCreateCall struct {
	called         bool
	apiKey         string
	serverURL      string
	name           string
	dockerfilePath string
	contextPath    string
}

func fakeSnapshotDockerfileCreator(returnID string, returnErr error) (snapshotFromDockerfileCreator, *snapshotDockerfileCreateCall) {
	call := &snapshotDockerfileCreateCall{}
	fn := func(ctx context.Context, apiKey, serverURL, name, dockerfilePath, contextPath string, out io.Writer) (string, error) {
		call.called = true
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.name = name
		call.dockerfilePath = dockerfilePath
		call.contextPath = contextPath
		return returnID, returnErr
	}
	return fn, call
}

type snapshotListCall struct {
	called    bool
	apiKey    string
	serverURL string
}

func fakeSnapshotLister(returnSnapshots []*daytonatypes.Snapshot, returnErr error) (snapshotLister, *snapshotListCall) {
	call := &snapshotListCall{}
	fn := func(ctx context.Context, apiKey, serverURL string) ([]*daytonatypes.Snapshot, error) {
		call.called = true
		call.apiKey = apiKey
		call.serverURL = serverURL
		return returnSnapshots, returnErr
	}
	return fn, call
}

func setupSnapshotTest(t *testing.T, dir string, apiKey, serverURL string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := &compound.DaytonaConfig{APIKey: apiKey, ServerURL: serverURL}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
}

func writeSnapshotTemplateDockerfile(t *testing.T, dir string) string {
	t.Helper()
	dockerfilePath := filepath.Join(dir, defaultSandboxDockerfile)
	if err := os.MkdirAll(filepath.Dir(dockerfilePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dockerfilePath, []byte("FROM ubuntu:22.04\n"), 0644); err != nil {
		t.Fatal(err)
	}
	return dockerfilePath
}

func TestRunSnapshotCreate(t *testing.T) {
	tests := []struct {
		name       string
		setup      func(t *testing.T, dir string) string
		snapshots  []*daytonatypes.Snapshot
		creatorID  string
		creatorErr error
		wantErr    string
		checkFn    func(t *testing.T, dir string, out string, listerCall *snapshotListCall, creatorCall *snapshotDockerfileCreateCall)
	}{
		{
			name: "creates template snapshot when missing",
			setup: func(t *testing.T, dir string) string {
				setupSnapshotTest(t, dir, "test-key", "https://api.example.com")
				return writeSnapshotTemplateDockerfile(t, dir)
			},
			snapshots: []*daytonatypes.Snapshot{},
			creatorID: "snap-123",
			checkFn: func(t *testing.T, dir string, out string, listerCall *snapshotListCall, creatorCall *snapshotDockerfileCreateCall) {
				if !listerCall.called {
					t.Fatal("snapshot lister was not called")
				}
				if listerCall.apiKey != "test-key" {
					t.Fatalf("apiKey = %q, want %q", listerCall.apiKey, "test-key")
				}
				if !creatorCall.called {
					t.Fatal("dockerfile creator was not called")
				}
				if creatorCall.name != sandboxTemplateSnapshotName {
					t.Fatalf("snapshot name = %q, want %q", creatorCall.name, sandboxTemplateSnapshotName)
				}
				if creatorCall.dockerfilePath != filepath.Join(dir, defaultSandboxDockerfile) {
					t.Fatalf("dockerfile path = %q, want %q", creatorCall.dockerfilePath, filepath.Join(dir, defaultSandboxDockerfile))
				}
				if creatorCall.contextPath != dir {
					t.Fatalf("context path = %q, want %q", creatorCall.contextPath, dir)
				}
				if !strings.Contains(out, "Template snapshot \"hal\" not found; creating from sandbox/Dockerfile") {
					t.Fatalf("output missing create message: %q", out)
				}
				if !strings.Contains(out, "Template snapshot ready: snap-123") {
					t.Fatalf("output missing ready message: %q", out)
				}
			},
		},
		{
			name: "reuses active template snapshot",
			setup: func(t *testing.T, dir string) string {
				setupSnapshotTest(t, dir, "key2", "")
				return ""
			},
			snapshots: []*daytonatypes.Snapshot{{ID: "snap-existing", Name: sandboxTemplateSnapshotName, State: "active"}},
			checkFn: func(t *testing.T, dir string, out string, listerCall *snapshotListCall, creatorCall *snapshotDockerfileCreateCall) {
				if !listerCall.called {
					t.Fatal("snapshot lister was not called")
				}
				if creatorCall.called {
					t.Fatal("dockerfile creator should not be called")
				}
				if !strings.Contains(out, "Template snapshot \"hal\" is active; reusing snap-existing") {
					t.Fatalf("output missing reuse message: %q", out)
				}
				if !strings.Contains(out, "Template snapshot ready: snap-existing") {
					t.Fatalf("output missing ready message: %q", out)
				}
			},
		},
		{
			name: "errors when .hal is missing",
			setup: func(t *testing.T, dir string) string {
				return ""
			},
			wantErr: ".hal/ not found",
		},
		{
			name: "errors when template snapshot is not active",
			setup: func(t *testing.T, dir string) string {
				setupSnapshotTest(t, dir, "key3", "")
				return ""
			},
			snapshots: []*daytonatypes.Snapshot{{ID: "snap-building", Name: sandboxTemplateSnapshotName, State: "building"}},
			wantErr:   "exists but is in state building",
		},
		{
			name: "errors when dockerfile is missing",
			setup: func(t *testing.T, dir string) string {
				setupSnapshotTest(t, dir, "key4", "")
				return ""
			},
			snapshots: []*daytonatypes.Snapshot{},
			wantErr:   "Dockerfile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				_ = tt.setup(t, dir)
			}

			lister, listerCall := fakeSnapshotLister(tt.snapshots, nil)
			creator, creatorCall := fakeSnapshotDockerfileCreator(tt.creatorID, tt.creatorErr)
			var out bytes.Buffer

			err := runSnapshotCreate(dir, &out, lister, creator)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.checkFn != nil {
				tt.checkFn(t, dir, out.String(), listerCall, creatorCall)
			}
		})
	}
}

func TestRunSnapshotCreate_ConflictReusesConcurrentlyCreatedTemplate(t *testing.T) {
	dir := t.TempDir()
	setupSnapshotTest(t, dir, "key", "")
	_ = writeSnapshotTemplateDockerfile(t, dir)

	listCalls := 0
	lister := func(ctx context.Context, apiKey, serverURL string) ([]*daytonatypes.Snapshot, error) {
		listCalls++
		if listCalls == 1 {
			return []*daytonatypes.Snapshot{}, nil
		}
		return []*daytonatypes.Snapshot{{ID: "snap-race", Name: sandboxTemplateSnapshotName, State: "active"}}, nil
	}
	creator, _ := fakeSnapshotDockerfileCreator("", fmt.Errorf("Daytona error (status 409): conflict"))

	var out bytes.Buffer
	err := runSnapshotCreate(dir, &out, lister, creator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if listCalls != 2 {
		t.Fatalf("list call count = %d, want 2", listCalls)
	}
	if !strings.Contains(out.String(), "created concurrently; reusing") {
		t.Fatalf("output missing concurrent reuse message: %q", out.String())
	}
	if !strings.Contains(out.String(), "Template snapshot ready: snap-race") {
		t.Fatalf("output missing ready message: %q", out.String())
	}
}

func TestRunSnapshotList(t *testing.T) {
	now := time.Date(2026, 2, 20, 8, 0, 0, 0, time.UTC)

	tests := []struct {
		name         string
		setup        func(t *testing.T, dir string)
		snapshots    []*daytonatypes.Snapshot
		listerErr    error
		wantErr      string
		wantContains []string
	}{
		{
			name: "lists snapshots",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "test-key", "https://api.example.com")
			},
			snapshots: []*daytonatypes.Snapshot{
				{ID: "snap-old", Name: "old", State: "active", UpdatedAt: now.Add(-time.Hour)},
				{ID: "snap-new", Name: "new", State: "active", UpdatedAt: now},
			},
			wantContains: []string{"ID\tNAME\tSTATE\tUPDATED", "snap-new", "snap-old"},
		},
		{
			name: "prints no snapshots message",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key2", "")
			},
			snapshots:    []*daytonatypes.Snapshot{},
			wantContains: []string{"No snapshots found."},
		},
		{
			name: "error when .hal missing",
			setup: func(t *testing.T, dir string) {
				// no setup
			},
			wantErr: ".hal/ not found",
		},
		{
			name: "error when lister fails",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "key3", "")
			},
			listerErr: fmt.Errorf("API unavailable"),
			wantErr:   "listing snapshots failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}

			lister, _ := fakeSnapshotLister(tt.snapshots, tt.listerErr)
			var out bytes.Buffer

			err := runSnapshotList(dir, &out, lister)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for _, want := range tt.wantContains {
				if !strings.Contains(out.String(), want) {
					t.Fatalf("output %q does not contain %q", out.String(), want)
				}
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
	}{
		{
			name: "deletes snapshot by ID",
			setup: func(t *testing.T, dir string) {
				setupSnapshotTest(t, dir, "test-key", "https://api.example.com")
			},
			snapshotID: "snap-123",
			wantOutput: "Snapshot \"snap-123\" deleted.",
		},
		{
			name: "error when .hal/ does not exist",
			setup: func(t *testing.T, dir string) {
				// no setup
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if tt.setup != nil {
				tt.setup(t, dir)
			}

			deleter, _ := fakeSnapshotDeleter(tt.deleterErr)
			var out bytes.Buffer

			err := runSnapshotDelete(dir, tt.snapshotID, &out, deleter)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantOutput != "" && !strings.Contains(out.String(), tt.wantOutput) {
				t.Fatalf("output %q does not contain %q", out.String(), tt.wantOutput)
			}
		})
	}
}

func TestRunSnapshotDelete_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	deleter, _ := fakeSnapshotDeleter(nil)
	var out bytes.Buffer

	err := runSnapshotDelete(dir, "snap-123", &out, deleter)
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}

func TestRunSnapshotCreate_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	lister, _ := fakeSnapshotLister(nil, nil)
	creator, _ := fakeSnapshotDockerfileCreator("snap-id", nil)
	var out bytes.Buffer

	err := runSnapshotCreate(dir, &out, lister, creator)
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}

func TestSnapshotCreateCommandFlags(t *testing.T) {
	if snapshotCreateCmd.Flags().Lookup("name") != nil {
		t.Fatal("--name flag should not exist")
	}
	if snapshotCreateCmd.Flags().Lookup("image") != nil {
		t.Fatal("--image flag should not exist")
	}
	if snapshotCreateCmd.Flags().Lookup("snapshot-name") != nil {
		t.Fatal("--snapshot-name flag should not exist")
	}
	if snapshotCreateCmd.Flags().Lookup("dockerfile") != nil {
		t.Fatal("--dockerfile flag should not exist")
	}
	if snapshotCreateCmd.Flags().Lookup("context") != nil {
		t.Fatal("--context flag should not exist")
	}
}
