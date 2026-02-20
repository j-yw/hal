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
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
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

func writeTemplateDockerfile(t *testing.T, dir string) string {
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

func TestRunSandboxStart_ReusesActiveTemplateSnapshot(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "test-key", "https://api.example.com")

	starterResult := &sandbox.CreateSandboxResult{ID: "sb-001", Name: "hal-feature-auth", Status: "STARTED"}
	starter, startCall := fakeSandboxStarter(starterResult, nil)
	lister, listCall := fakeStartSnapshotLister([]*daytonatypes.Snapshot{{ID: "snap-123", Name: sandboxTemplateSnapshotName, State: "active"}}, nil)
	getBranch := fakeBranchResolver("hal/feature-auth", nil)

	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "", &out, starter, getBranch, lister, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !listCall.called {
		t.Fatal("snapshot lister was not called")
	}
	if !startCall.called {
		t.Fatal("sandbox starter was not called")
	}
	if startCall.name != "hal-feature-auth" {
		t.Fatalf("starter name = %q, want %q", startCall.name, "hal-feature-auth")
	}
	if startCall.snapshotID != "snap-123" {
		t.Fatalf("starter snapshotID = %q, want %q", startCall.snapshotID, "snap-123")
	}
	if !strings.Contains(out.String(), "Template snapshot \"hal\" is active; reusing") {
		t.Fatalf("output missing reuse line: %q", out.String())
	}
	if !strings.Contains(out.String(), "Starting sandbox \"hal-feature-auth\" from template snapshot \"hal\" (snap-123)") {
		t.Fatalf("output missing start line: %q", out.String())
	}

	halDir := filepath.Join(dir, template.HalDir)
	state, err := sandbox.LoadState(halDir)
	if err != nil {
		t.Fatalf("failed to load saved state: %v", err)
	}
	if state.Name != "hal-feature-auth" {
		t.Fatalf("state.Name = %q, want %q", state.Name, "hal-feature-auth")
	}
	if state.SnapshotID != "snap-123" {
		t.Fatalf("state.SnapshotID = %q, want %q", state.SnapshotID, "snap-123")
	}
	if state.WorkspaceID != "sb-001" {
		t.Fatalf("state.WorkspaceID = %q, want %q", state.WorkspaceID, "sb-001")
	}
}

func TestRunSandboxStart_UsesExplicitName(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "key2", "")

	starterResult := &sandbox.CreateSandboxResult{ID: "sb-002", Name: "my-sandbox", Status: "STARTED"}
	starter, call := fakeSandboxStarter(starterResult, nil)
	lister, _ := fakeStartSnapshotLister([]*daytonatypes.Snapshot{{ID: "snap-456", Name: sandboxTemplateSnapshotName, State: "active"}}, nil)

	err := runSandboxStartWithDeps(dir, "my-sandbox", io.Discard, starter, nil, lister, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.name != "my-sandbox" {
		t.Fatalf("starter name = %q, want %q", call.name, "my-sandbox")
	}
}

func TestRunSandboxStart_CreatesTemplateSnapshotWhenMissing(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "df-key", "https://api.example.com")
	dockerfilePath := writeTemplateDockerfile(t, dir)

	starterResult := &sandbox.CreateSandboxResult{ID: "sb-df", Name: "my-box", Status: "STARTED"}
	starter, startCall := fakeSandboxStarter(starterResult, nil)
	dockerCreator, dockerCall := fakeStartDockerfileSnapshotCreator("snap-df", nil)
	lister, _ := fakeStartSnapshotLister([]*daytonatypes.Snapshot{}, nil)

	err := runSandboxStartWithDeps(dir, "my-box", io.Discard, starter, nil, lister, dockerCreator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !dockerCall.called {
		t.Fatal("dockerfile snapshot creator was not called")
	}
	if dockerCall.name != sandboxTemplateSnapshotName {
		t.Fatalf("snapshot name = %q, want %q", dockerCall.name, sandboxTemplateSnapshotName)
	}
	if dockerCall.dockerfilePath != dockerfilePath {
		t.Fatalf("dockerfile path = %q, want %q", dockerCall.dockerfilePath, dockerfilePath)
	}
	if dockerCall.contextPath != dir {
		t.Fatalf("context path = %q, want %q", dockerCall.contextPath, dir)
	}
	if !startCall.called {
		t.Fatal("sandbox starter was not called")
	}
	if startCall.snapshotID != "snap-df" {
		t.Fatalf("starter snapshotID = %q, want %q", startCall.snapshotID, "snap-df")
	}
}

func TestRunSandboxStart_FailsWhenDockerfileMissingAndTemplateAbsent(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "key", "")

	starter, startCall := fakeSandboxStarter(nil, nil)
	lister, _ := fakeStartSnapshotLister([]*daytonatypes.Snapshot{}, nil)

	err := runSandboxStartWithDeps(dir, "box", io.Discard, starter, nil, lister, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "Dockerfile") {
		t.Fatalf("error %q does not mention Dockerfile", err.Error())
	}
	if startCall.called {
		t.Fatal("sandbox starter should not be called")
	}
}

func TestRunSandboxStart_FailsWhenTemplateSnapshotUnusable(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "key", "")

	starter, startCall := fakeSandboxStarter(nil, nil)
	lister, _ := fakeStartSnapshotLister([]*daytonatypes.Snapshot{{ID: "snap-bad", Name: sandboxTemplateSnapshotName, State: "building"}}, nil)

	err := runSandboxStartWithDeps(dir, "box", io.Discard, starter, nil, lister, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "exists but is in state building") {
		t.Fatalf("error %q does not contain expected state message", err.Error())
	}
	if startCall.called {
		t.Fatal("sandbox starter should not be called")
	}
}

func TestRunSandboxStart_FailsWhenBranchCannotBeDetermined(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "key", "")

	starter, _ := fakeSandboxStarter(nil, nil)
	branchErr := fmt.Errorf("not on a branch")

	err := runSandboxStartWithDeps(dir, "", io.Discard, starter, fakeBranchResolver("", branchErr), nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "could not determine sandbox name from git branch") {
		t.Fatalf("error %q missing branch failure text", err.Error())
	}
}

func TestRunSandboxStart_ConflictReusesConcurrentlyCreatedTemplate(t *testing.T) {
	dir := t.TempDir()
	setupStartTest(t, dir, "key", "")
	_ = writeTemplateDockerfile(t, dir)

	starterResult := &sandbox.CreateSandboxResult{ID: "sb-race", Name: "race-box", Status: "STARTED"}
	starter, startCall := fakeSandboxStarter(starterResult, nil)
	dockerCreator, _ := fakeStartDockerfileSnapshotCreator("", fmt.Errorf("Daytona error (status 409): conflict"))

	listCalls := 0
	lister := func(ctx context.Context, apiKey, serverURL string) ([]*daytonatypes.Snapshot, error) {
		listCalls++
		if listCalls == 1 {
			return []*daytonatypes.Snapshot{}, nil
		}
		return []*daytonatypes.Snapshot{{ID: "snap-race", Name: sandboxTemplateSnapshotName, State: "active"}}, nil
	}

	var out bytes.Buffer
	err := runSandboxStartWithDeps(dir, "race-box", &out, starter, nil, lister, dockerCreator)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if listCalls != 2 {
		t.Fatalf("list call count = %d, want 2", listCalls)
	}
	if !startCall.called {
		t.Fatal("sandbox starter was not called")
	}
	if startCall.snapshotID != "snap-race" {
		t.Fatalf("starter snapshotID = %q, want %q", startCall.snapshotID, "snap-race")
	}
	if !strings.Contains(out.String(), "created concurrently; reusing") {
		t.Fatalf("output missing concurrent reuse message: %q", out.String())
	}
}

func TestRunSandboxStart_EnsureAuthCalled(t *testing.T) {
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatal(err)
	}
	cfg := &compound.DaytonaConfig{APIKey: "", ServerURL: ""}
	if err := compound.SaveConfig(dir, cfg); err != nil {
		t.Fatal(err)
	}

	result := &sandbox.CreateSandboxResult{ID: "sb-id", Name: "test", Status: "STARTED"}
	starter, _ := fakeSandboxStarter(result, nil)
	var out bytes.Buffer

	err := runSandboxStart(dir, "test", &out, starter, fakeBranchResolver("main", nil))
	if err == nil {
		t.Fatal("expected error for empty API key, got nil")
	}
}

func TestRunSandboxStart_ErrorWhenHalDirMissing(t *testing.T) {
	dir := t.TempDir()
	starter, _ := fakeSandboxStarter(nil, nil)
	err := runSandboxStartWithDeps(dir, "box", io.Discard, starter, nil, nil, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), ".hal/ not found") {
		t.Fatalf("error %q does not contain .hal guidance", err.Error())
	}
}

func TestSandboxStartCommandFlags(t *testing.T) {
	if sandboxStartCmd.Flags().Lookup("name") == nil {
		t.Fatal("--name flag should exist")
	}
	if sandboxStartCmd.Flags().Lookup("snapshot") != nil {
		t.Fatal("--snapshot flag should not exist")
	}
	if sandboxStartCmd.Flags().Lookup("image") != nil {
		t.Fatal("--image flag should not exist")
	}
	if sandboxStartCmd.Flags().Lookup("snapshot-name") != nil {
		t.Fatal("--snapshot-name flag should not exist")
	}
	if sandboxStartCmd.Flags().Lookup("dockerfile") != nil {
		t.Fatal("--dockerfile flag should not exist")
	}
	if sandboxStartCmd.Flags().Lookup("context") != nil {
		t.Fatal("--context flag should not exist")
	}
}
