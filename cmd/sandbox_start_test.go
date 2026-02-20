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

	daytonatypes "github.com/daytonaio/daytona/libs/sdk-go/pkg/types"
	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

type sandboxStartCall struct {
	called     bool
	apiKey     string
	serverURL  string
	name       string
	snapshotID string
}

func fakeSandboxStarter(returnResult *sandbox.CreateSandboxResult, returnErr error) (sandboxStarter, *sandboxStartCall) {
	call := &sandboxStartCall{}
	fn := func(ctx context.Context, apiKey, serverURL, name, snapshotID string, out io.Writer) (*sandbox.CreateSandboxResult, error) {
		call.called = true
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.name = name
		call.snapshotID = snapshotID
		return returnResult, returnErr
	}
	return fn, call
}

type startSnapshotCreateCall struct {
	called    bool
	apiKey    string
	serverURL string
	name      string
	imageRef  string
}

func fakeStartSnapshotCreator(returnID string, returnErr error) (snapshotCreator, *startSnapshotCreateCall) {
	call := &startSnapshotCreateCall{}
	fn := func(ctx context.Context, apiKey, serverURL, name, imageRef string, out io.Writer) (string, error) {
		call.called = true
		call.apiKey = apiKey
		call.serverURL = serverURL
		call.name = name
		call.imageRef = imageRef
		return returnID, returnErr
	}
	return fn, call
}

type startDockerfileSnapshotCreateCall struct {
	called         bool
	apiKey         string
	serverURL      string
	name           string
	dockerfilePath string
	contextPath    string
}

func fakeStartDockerfileSnapshotCreator(returnID string, returnErr error) (snapshotFromDockerfileCreator, *startDockerfileSnapshotCreateCall) {
	call := &startDockerfileSnapshotCreateCall{}
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

type startSnapshotListCall struct {
	called    bool
	apiKey    string
	serverURL string
}

func fakeStartSnapshotLister(returnSnapshots []*daytonatypes.Snapshot, returnErr error) (snapshotLister, *startSnapshotListCall) {
	call := &startSnapshotListCall{}
	fn := func(ctx context.Context, apiKey, serverURL string) ([]*daytonatypes.Snapshot, error) {
		call.called = true
		call.apiKey = apiKey
		call.serverURL = serverURL
		return returnSnapshots, returnErr
	}
	return fn, call
}

func setupStartTest(t *testing.T, dir string, apiKey, serverURL string) {
	t.Helper()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	cfg := &compound.DaytonaConfig{APIKey: apiKey, ServerURL: serverURL}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}
}

func fakeBranchResolver(branch string, err error) branchResolver {
	return func() (string, error) {
		return branch, err
	}
}

func TestRunSandboxStart(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T, dir string)
		sandboxName  string
		snapshotID   string
		branch       string
		branchErr    error
		resultID     string
		resultName   string
		resultStatus string
		starterErr   error
		wantErr      string
		wantOutput   string
		checkFn      func(t *testing.T, dir string, call *sandboxStartCall)
	}{
		{
			name: "starts sandbox with name from git branch",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "test-key", "https://api.example.com")
			},
			snapshotID:   "snap-123",
			branch:       "hal/feature-auth",
			resultID:     "sb-001",
			resultName:   "hal-feature-auth",
			resultStatus: "STARTED",
			wantOutput:   "Sandbox started: hal-feature-auth",
			checkFn: func(t *testing.T, dir string, call *sandboxStartCall) {
				if !call.called {
					t.Error("starter was not called")
				}
				if call.apiKey != "test-key" {
					t.Errorf("apiKey = %q, want %q", call.apiKey, "test-key")
				}
				if call.serverURL != "https://api.example.com" {
					t.Errorf("serverURL = %q, want %q", call.serverURL, "https://api.example.com")
				}
				if call.name != "hal-feature-auth" {
					t.Errorf("name = %q, want %q", call.name, "hal-feature-auth")
				}
				if call.snapshotID != "snap-123" {
					t.Errorf("snapshotID = %q, want %q", call.snapshotID, "snap-123")
				}
				// Verify state was saved
				halDir := filepath.Join(dir, template.HalDir)
				state, err := sandbox.LoadState(halDir)
				if err != nil {
					t.Fatalf("failed to load saved state: %v", err)
				}
				if state.Name != "hal-feature-auth" {
					t.Errorf("state.Name = %q, want %q", state.Name, "hal-feature-auth")
				}
				if state.SnapshotID != "snap-123" {
					t.Errorf("state.SnapshotID = %q, want %q", state.SnapshotID, "snap-123")
				}
				if state.WorkspaceID != "sb-001" {
					t.Errorf("state.WorkspaceID = %q, want %q", state.WorkspaceID, "sb-001")
				}
				if state.Status != "STARTED" {
					t.Errorf("state.Status = %q, want %q", state.Status, "STARTED")
				}
			},
		},
		{
			name: "uses explicit --name flag",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key2", "")
			},
			sandboxName:  "my-sandbox",
			snapshotID:   "snap-456",
			resultID:     "sb-002",
			resultName:   "my-sandbox",
			resultStatus: "STARTED",
			wantOutput:   "Sandbox started: my-sandbox",
			checkFn: func(t *testing.T, dir string, call *sandboxStartCall) {
				if call.name != "my-sandbox" {
					t.Errorf("name = %q, want %q", call.name, "my-sandbox")
				}
			},
		},
		{
			name: "branch with nested slashes",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key3", "")
			},
			snapshotID:   "snap-789",
			branch:       "feature/auth/oauth",
			resultID:     "sb-003",
			resultName:   "feature-auth-oauth",
			resultStatus: "STARTED",
			wantOutput:   "Sandbox started: feature-auth-oauth",
			checkFn: func(t *testing.T, dir string, call *sandboxStartCall) {
				if call.name != "feature-auth-oauth" {
					t.Errorf("name = %q, want %q", call.name, "feature-auth-oauth")
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
			name: "error when snapshot and image are both missing",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key4", "")
			},
			sandboxName: "my-sandbox",
			snapshotID:  "",
			wantErr:     "either --snapshot or --image flag is required",
		},
		{
			name: "error when git branch cannot be determined",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key5", "")
			},
			snapshotID: "snap-123",
			branchErr:  fmt.Errorf("not on a branch"),
			wantErr:    "could not determine sandbox name from git branch",
		},
		{
			name: "error when sandbox creation fails",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key6", "")
			},
			sandboxName: "my-sandbox",
			snapshotID:  "snap-123",
			starterErr:  fmt.Errorf("API error: quota exceeded"),
			wantErr:     "sandbox creation failed",
		},
		{
			name: "prints starting message with sandbox name and snapshot",
			setup: func(t *testing.T, dir string) {
				setupStartTest(t, dir, "key7", "")
			},
			sandboxName:  "test-box",
			snapshotID:   "snap-abc",
			resultID:     "sb-004",
			resultName:   "test-box",
			resultStatus: "STARTED",
			wantOutput:   `Starting sandbox "test-box" from snapshot "snap-abc"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			if tt.setup != nil {
				tt.setup(t, dir)
			}

			var result *sandbox.CreateSandboxResult
			if tt.starterErr == nil && tt.resultID != "" {
				result = &sandbox.CreateSandboxResult{
					ID:     tt.resultID,
					Name:   tt.resultName,
					Status: tt.resultStatus,
				}
			}

			starter, call := fakeSandboxStarter(result, tt.starterErr)
			var out bytes.Buffer

			var getBranch branchResolver
			if tt.branch != "" || tt.branchErr != nil {
				getBranch = fakeBranchResolver(tt.branch, tt.branchErr)
			}

			err := runSandboxStart(dir, tt.sandboxName, tt.snapshotID, &out, starter, getBranch)

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
				tt.checkFn(t, dir, call)
			}
		})
	}
}

func TestRunSandboxStartWithImage(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "img-key", "https://api.example.com")

	starterResult := &sandbox.CreateSandboxResult{ID: "sb-img", Name: "hal-feature-image", Status: "STARTED"}
	starter, startCall := fakeSandboxStarter(starterResult, nil)
	creator, createCall := fakeStartSnapshotCreator("snap-created", nil)

	var out bytes.Buffer
	getBranch := fakeBranchResolver("hal/feature-image", nil)

	err := runSandboxStartWithDeps(
		dir,
		"",
		"",
		"ghcr.io/jywlabs/hal-sandbox:latest",
		"",
		defaultSandboxDockerfile,
		defaultSandboxContext,
		&out,
		starter,
		getBranch,
		creator,
		nil,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !createCall.called {
		t.Fatal("snapshot creator was not called")
	}
	if createCall.name != "hal-sandbox" {
		t.Fatalf("snapshot name = %q, want %q", createCall.name, "hal-sandbox")
	}
	if createCall.imageRef != "ghcr.io/jywlabs/hal-sandbox:latest" {
		t.Fatalf("imageRef = %q", createCall.imageRef)
	}

	if !startCall.called {
		t.Fatal("sandbox starter was not called")
	}
	if startCall.snapshotID != "snap-created" {
		t.Fatalf("starter snapshotID = %q, want %q", startCall.snapshotID, "snap-created")
	}
	if !strings.Contains(out.String(), "Snapshot created: snap-created") {
		t.Fatalf("output missing snapshot creation line: %q", out.String())
	}
}

func TestRunSandboxStartWithImage_BothSnapshotAndImageError(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "key", "")

	starter, _ := fakeSandboxStarter(nil, nil)
	creator, _ := fakeStartSnapshotCreator("snap-created", nil)

	err := runSandboxStartWithDeps(dir, "box", "snap-1", "ubuntu:22.04", "", defaultSandboxDockerfile, defaultSandboxContext, io.Discard, starter, nil, creator, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "use either --snapshot or --image") {
		t.Fatalf("error %q does not contain expected text", err.Error())
	}
}

func TestRunSandboxStartWithImage_SnapshotCreationError(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "key", "")

	starter, startCall := fakeSandboxStarter(nil, nil)
	creator, _ := fakeStartSnapshotCreator("", fmt.Errorf("quota exceeded"))

	err := runSandboxStartWithDeps(dir, "box", "", "ubuntu:22.04", "", defaultSandboxDockerfile, defaultSandboxContext, io.Discard, starter, nil, creator, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "snapshot creation failed") {
		t.Fatalf("error %q does not contain expected text", err.Error())
	}
	if startCall.called {
		t.Fatal("sandbox starter should not be called when snapshot creation fails")
	}
}

func TestRunSandboxStartWithImage_ConflictReusesExistingSnapshot(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "img-key", "https://api.example.com")

	starterResult := &sandbox.CreateSandboxResult{ID: "sb-img", Name: "hal-feature-image", Status: "STARTED"}
	starter, startCall := fakeSandboxStarter(starterResult, nil)
	creator, _ := fakeStartSnapshotCreator("", fmt.Errorf("Daytona error (status 409): conflict"))
	lister, listCall := fakeStartSnapshotLister([]*daytonatypes.Snapshot{{ID: "snap-existing", Name: "hal-sandbox", State: "active"}}, nil)

	var out bytes.Buffer
	getBranch := fakeBranchResolver("hal/feature-image", nil)

	err := runSandboxStartWithDeps(
		dir,
		"",
		"",
		"ghcr.io/jywlabs/hal-sandbox:latest",
		"",
		defaultSandboxDockerfile,
		defaultSandboxContext,
		&out,
		starter,
		getBranch,
		creator,
		nil,
		lister,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !listCall.called {
		t.Fatal("snapshot lister was not called")
	}
	if !startCall.called {
		t.Fatal("sandbox starter was not called")
	}
	if startCall.snapshotID != "snap-existing" {
		t.Fatalf("starter snapshotID = %q, want %q", startCall.snapshotID, "snap-existing")
	}
	if !strings.Contains(out.String(), "already exists; reusing") {
		t.Fatalf("output missing reuse message: %q", out.String())
	}
}

func TestRunSandboxStartWithImage_ConflictWithNonActiveSnapshotErrors(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "img-key", "")

	starter, startCall := fakeSandboxStarter(nil, nil)
	creator, _ := fakeStartSnapshotCreator("", fmt.Errorf("Daytona error (status 409): conflict"))
	lister, _ := fakeStartSnapshotLister([]*daytonatypes.Snapshot{{ID: "snap-existing", Name: "hal-sandbox", State: "building"}}, nil)

	err := runSandboxStartWithDeps(
		dir,
		"box",
		"",
		"ghcr.io/jywlabs/hal-sandbox:latest",
		"",
		defaultSandboxDockerfile,
		defaultSandboxContext,
		io.Discard,
		starter,
		nil,
		creator,
		nil,
		lister,
	)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "already exists but is in state building") {
		t.Fatalf("error %q does not contain expected text", err.Error())
	}
	if startCall.called {
		t.Fatal("sandbox starter should not be called when conflict snapshot is not active")
	}
}

func TestRunSandboxStartWithImage_ConflictWithBuildFailedCreatesReplacement(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "img-key", "")

	starterResult := &sandbox.CreateSandboxResult{ID: "sb-img", Name: "hal-feature-image", Status: "STARTED"}
	starter, startCall := fakeSandboxStarter(starterResult, nil)

	var createNames []string
	creator := func(ctx context.Context, apiKey, serverURL, name, imageRef string, out io.Writer) (string, error) {
		createNames = append(createNames, name)
		if len(createNames) == 1 {
			return "", fmt.Errorf("Daytona error (status 409): conflict")
		}
		return "snap-replacement", nil
	}
	lister, _ := fakeStartSnapshotLister([]*daytonatypes.Snapshot{{ID: "snap-failed", Name: "hal-sandbox", State: "build_failed"}}, nil)

	var out bytes.Buffer
	err := runSandboxStartWithDeps(
		dir,
		"box",
		"",
		"ghcr.io/jywlabs/hal-sandbox:latest",
		"",
		defaultSandboxDockerfile,
		defaultSandboxContext,
		&out,
		starter,
		nil,
		creator,
		nil,
		lister,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(createNames) != 2 {
		t.Fatalf("creator call count = %d, want 2", len(createNames))
	}
	if createNames[0] != "hal-sandbox" {
		t.Fatalf("first snapshot name = %q, want %q", createNames[0], "hal-sandbox")
	}
	if !strings.HasPrefix(createNames[1], "hal-sandbox-") {
		t.Fatalf("second snapshot name = %q, want prefix %q", createNames[1], "hal-sandbox-")
	}
	if !startCall.called {
		t.Fatal("sandbox starter was not called")
	}
	if startCall.snapshotID != "snap-replacement" {
		t.Fatalf("starter snapshotID = %q, want %q", startCall.snapshotID, "snap-replacement")
	}
	if !strings.Contains(out.String(), "creating replacement snapshot") {
		t.Fatalf("output missing replacement message: %q", out.String())
	}
}

func TestRunSandboxStartWithDockerfileAuto(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "df-key", "https://api.example.com")

	dockerfilePath := filepath.Join(dir, defaultSandboxDockerfile)
	if err := os.MkdirAll(filepath.Dir(dockerfilePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dockerfilePath, []byte("FROM ubuntu:22.04\n"), 0644); err != nil {
		t.Fatal(err)
	}

	starterResult := &sandbox.CreateSandboxResult{ID: "sb-df", Name: "hal-feature-dockerfile", Status: "STARTED"}
	starter, startCall := fakeSandboxStarter(starterResult, nil)
	dockerCreator, dockerCall := fakeStartDockerfileSnapshotCreator("snap-df", nil)

	var out bytes.Buffer
	getBranch := fakeBranchResolver("hal/feature-dockerfile", nil)

	err := runSandboxStartWithDeps(
		dir,
		"",
		"",
		"",
		"",
		defaultSandboxDockerfile,
		defaultSandboxContext,
		&out,
		starter,
		getBranch,
		nil,
		dockerCreator,
		nil,
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !dockerCall.called {
		t.Fatal("dockerfile snapshot creator was not called")
	}
	if dockerCall.name != "hal-feature-dockerfile-snapshot" {
		t.Fatalf("snapshot name = %q, want %q", dockerCall.name, "hal-feature-dockerfile-snapshot")
	}
	if dockerCall.dockerfilePath != dockerfilePath {
		t.Fatalf("dockerfile path = %q, want %q", dockerCall.dockerfilePath, dockerfilePath)
	}
	if dockerCall.contextPath != "." {
		t.Fatalf("context path = %q, want %q", dockerCall.contextPath, ".")
	}

	if !startCall.called {
		t.Fatal("sandbox starter was not called")
	}
	if startCall.snapshotID != "snap-df" {
		t.Fatalf("starter snapshotID = %q, want %q", startCall.snapshotID, "snap-df")
	}
	if !strings.Contains(out.String(), "No snapshot/image provided; creating snapshot") {
		t.Fatalf("output missing dockerfile snapshot line: %q", out.String())
	}
}

func TestRunSandboxStartWithDockerfileAuto_SnapshotCreationError(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "df-key", "")

	dockerfilePath := filepath.Join(dir, defaultSandboxDockerfile)
	if err := os.MkdirAll(filepath.Dir(dockerfilePath), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dockerfilePath, []byte("FROM ubuntu:22.04\n"), 0644); err != nil {
		t.Fatal(err)
	}

	starter, startCall := fakeSandboxStarter(nil, nil)
	dockerCreator, _ := fakeStartDockerfileSnapshotCreator("", fmt.Errorf("build failed"))

	err := runSandboxStartWithDeps(dir, "box", "", "", "", defaultSandboxDockerfile, defaultSandboxContext, io.Discard, starter, nil, nil, dockerCreator, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "snapshot creation failed") {
		t.Fatalf("error %q does not contain expected text", err.Error())
	}
	if startCall.called {
		t.Fatal("sandbox starter should not be called when dockerfile snapshot creation fails")
	}
}

func TestRunSandboxStart_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	os.MkdirAll(halDir, 0755)
	// Save empty API key to config
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	result := &sandbox.CreateSandboxResult{ID: "sb-id", Name: "test", Status: "STARTED"}
	starter, _ := fakeSandboxStarter(result, nil)
	var out bytes.Buffer
	getBranch := fakeBranchResolver("main", nil)

	err := runSandboxStart(dir, "test", "snap-123", &out, starter, getBranch)

	// Should fail because EnsureAuth will try interactive setup with os.Stdin
	// which doesn't have data, but the key will remain empty
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}
