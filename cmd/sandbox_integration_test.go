//go:build integration

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

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/template"
)

func TestSandboxCommandIntegration(t *testing.T) {
	apiKey := os.Getenv("DAYTONA_API_KEY")
	if apiKey == "" {
		t.Skip("DAYTONA_API_KEY not set; skipping sandbox command integration test")
	}

	serverURL := os.Getenv("DAYTONA_SERVER_URL")
	dir := t.TempDir()
	halDir := filepath.Join(dir, template.HalDir)
	if err := os.MkdirAll(halDir, 0755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", halDir, err)
	}

	if err := compound.SaveConfig(dir, &compound.DaytonaConfig{
		APIKey:    apiKey,
		ServerURL: serverURL,
	}); err != nil {
		t.Fatalf("SaveConfig(): %v", err)
	}

	repoRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatalf("filepath.Abs(..): %v", err)
	}

	snapshotID, err := resolveTemplateSnapshot(repoRoot, apiKey, serverURL, io.Discard, nil, nil)
	if err != nil {
		t.Fatalf("resolveTemplateSnapshot(): %v", err)
	}

	name := fmt.Sprintf("hal-cmd-int-%d", time.Now().UnixNano())
	client, err := sandbox.NewClient(apiKey, serverURL)
	if err != nil {
		t.Fatalf("sandbox.NewClient(): %v", err)
	}

	needsCleanup := true
	t.Cleanup(func() {
		if !needsCleanup {
			return
		}

		ctx := context.Background()
		_ = sandbox.StopSandbox(ctx, client, name, io.Discard)
		_ = sandbox.DeleteSandbox(ctx, client, name, io.Discard)
	})

	var out bytes.Buffer
	if err := runSandboxStart(dir, name, nil, &out, nil, nil); err != nil {
		t.Fatalf("runSandboxStart(): %v\noutput:\n%s", err, out.String())
	}

	state, err := sandbox.LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState() after start: %v", err)
	}
	if state.Name != name {
		t.Fatalf("state.Name = %q, want %q", state.Name, name)
	}
	if state.SnapshotID != snapshotID {
		t.Fatalf("state.SnapshotID = %q, want %q", state.SnapshotID, snapshotID)
	}
	if strings.TrimSpace(state.WorkspaceID) == "" {
		t.Fatal("state.WorkspaceID is empty after start")
	}

	out.Reset()
	if err := runSandboxStatus(dir, "", &out, nil); err != nil {
		t.Fatalf("runSandboxStatus(): %v\noutput:\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "Name:       "+name) {
		t.Fatalf("status output missing sandbox name:\n%s", out.String())
	}

	out.Reset()
	if err := runSandboxStop(dir, "", &out, nil); err != nil {
		t.Fatalf("runSandboxStop(): %v\noutput:\n%s", err, out.String())
	}

	state, err = sandbox.LoadState(halDir)
	if err != nil {
		t.Fatalf("LoadState() after stop: %v", err)
	}
	if state.Status != "STOPPED" {
		t.Fatalf("state.Status = %q, want %q", state.Status, "STOPPED")
	}

	out.Reset()
	if err := runSandboxDelete(dir, "", &out, nil); err != nil {
		t.Fatalf("runSandboxDelete(): %v\noutput:\n%s", err, out.String())
	}
	needsCleanup = false

	if _, err := sandbox.LoadState(halDir); err == nil {
		t.Fatal("LoadState() succeeded after delete; want missing sandbox state")
	}
}
