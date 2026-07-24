package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexecution"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestL3SelectionRejectsExecutionFromReplacedSandboxInstance(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	now := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	if err := sandbox.ForceWriteInstance(&sandbox.SandboxState{
		ID:        "sandbox-alpha-replacement",
		Name:      "alpha",
		Provider:  "worker",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("save replacement sandbox: %v", err)
	}
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	saveL3Manifest(t, store, l3Manifest(
		"run-alpha-stale",
		"alpha",
		now,
		"job-alpha-stale",
		sandboxworker.JobStateRunning,
		0,
	))

	t.Run("explicit run", func(t *testing.T) {
		_, manifest, err := selectSandboxL3Execution(
			"alpha",
			"run-alpha-stale",
			sandboxL3SelectionObserve,
		)
		if manifest != nil {
			t.Errorf("selected stale manifest = %q, want nil", manifest.ID)
		}
		requireL3ErrorCode(t, err, "execution_sandbox_mismatch")
	})

	t.Run("implicit run", func(t *testing.T) {
		_, manifest, err := selectSandboxL3Execution(
			"alpha",
			"",
			sandboxL3SelectionObserve,
		)
		if manifest != nil {
			t.Errorf("selected stale manifest = %q, want nil", manifest.ID)
		}
		requireL3ErrorCode(t, err, "execution_not_found")
	})
}

func TestL3LiveListDoesNotObserveExecutionFromReplacedSandboxInstance(t *testing.T) {
	t.Setenv("HAL_CONFIG_HOME", t.TempDir())
	now := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	store, err := sandboxexecution.DefaultStore()
	if err != nil {
		t.Fatalf("open execution store: %v", err)
	}
	saveL3Manifest(t, store, l3Manifest(
		"run-alpha-stale",
		"alpha",
		now,
		"job-alpha-stale",
		sandboxworker.JobStateRunning,
		0,
	))
	replacement := &sandbox.SandboxState{
		ID:        "sandbox-alpha-replacement",
		Name:      "alpha",
		Provider:  "worker",
		Status:    sandbox.StatusRunning,
		CreatedAt: now.Add(time.Hour),
	}

	originalClientFactory := sandboxL3NewWorkerClient
	workerCalls := 0
	sandboxL3NewWorkerClient = func(string) (*sandboxworker.Client, error) {
		workerCalls++
		return nil, nil
	}
	t.Cleanup(func() {
		sandboxL3NewWorkerClient = originalClientFactory
	})

	var out bytes.Buffer
	if err := renderSandboxL3LiveListJSON(context.Background(), &out, []*sandbox.SandboxState{replacement}); err != nil {
		t.Fatalf("render live list: %v", err)
	}
	if workerCalls != 0 {
		t.Fatalf("stale execution caused %d worker calls, want none", workerCalls)
	}
	payload := decodeL3JSONDocument(t, out.Bytes())
	sandboxes, ok := payload["sandboxes"].([]any)
	if !ok || len(sandboxes) != 1 {
		t.Fatalf("sandboxes = %#v, want one replacement sandbox", payload["sandboxes"])
	}
	entry, ok := sandboxes[0].(map[string]any)
	if !ok {
		t.Fatalf("sandbox entry = %#v, want object", sandboxes[0])
	}
	if _, exists := entry["execution"]; exists {
		t.Fatalf("replacement sandbox inherited stale execution: %#v", entry["execution"])
	}
}

func TestL3RunAndAutoManifestsPersistStableSandboxInstanceID(t *testing.T) {
	now := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	target := &sandbox.SandboxState{
		ID:        "sandbox-stable-id",
		Name:      "alpha",
		Provider:  "worker",
		Status:    sandbox.StatusRunning,
		CreatedAt: now,
	}
	tests := []struct {
		name        string
		executionID string
		save        func(sandboxexecution.Store) error
	}{
		{
			name:        "run",
			executionID: "run-lineage",
			save: func(store sandboxexecution.Store) error {
				return saveRunSandboxManifest(store, runSandboxRequest{
					ExecutionID: "run-lineage",
					SandboxName: "alpha",
				}, sandboxexecution.StatusRunning, now, nil, target)
			},
		},
		{
			name:        "auto",
			executionID: "auto-lineage",
			save: func(store sandboxexecution.Store) error {
				return saveAutoSandboxManifest(store, autoSandboxRequest{
					ExecutionID: "auto-lineage",
					SandboxName: "alpha",
				}, sandboxexecution.StatusRunning, now, nil, target)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := sandboxexecution.NewStore(filepath.Join(t.TempDir(), "store"))
			if err := tt.save(store); err != nil {
				t.Fatalf("save %s manifest: %v", tt.name, err)
			}
			path, err := store.ManifestPath(tt.executionID)
			if err != nil {
				t.Fatalf("resolve manifest path: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read manifest: %v", err)
			}
			decoder := json.NewDecoder(bytes.NewReader(data))
			var raw map[string]any
			if err := decoder.Decode(&raw); err != nil {
				t.Fatalf("decode manifest: %v", err)
			}
			if err := decoder.Decode(&struct{}{}); err != io.EOF {
				t.Fatalf("manifest trailing JSON: %v", err)
			}
			sandboxID, _ := raw["sandboxId"].(string)
			if got := strings.TrimSpace(sandboxID); got != target.ID {
				t.Fatalf("sandboxId = %q, want %q", got, target.ID)
			}
		})
	}
}
