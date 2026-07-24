package sandboxexecution

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestL3InterruptedAndUnknownManifestStatusesRoundTrip(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 1, 0, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Minute)

	for _, status := range []Status{StatusInterrupted, StatusUnknown} {
		t.Run(string(status), func(t *testing.T) {
			store := newTestStore(t)
			manifest := testManifest("exec-"+string(status), startedAt)
			manifest.Status = status
			manifest.FinishedAt = &finishedAt

			if err := store.SaveManifest(manifest); err != nil {
				t.Fatalf("SaveManifest() error: %v", err)
			}
			loaded, err := store.LoadManifest(manifest.ID)
			if err != nil {
				t.Fatalf("LoadManifest() error: %v", err)
			}
			if loaded.Status != status {
				t.Fatalf("LoadManifest() status = %q, want %q", loaded.Status, status)
			}
		})
	}
}

func TestL3FinalizationIntentAndCheckpointsJSONRoundTrip(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 2, 0, 0, 0, time.UTC)
	updatedAt := startedAt.Add(time.Minute)
	artifactCompletedAt := updatedAt.Add(time.Minute)
	syncOutCompletedAt := artifactCompletedAt.Add(time.Minute)
	leaseCompletedAt := syncOutCompletedAt.Add(time.Minute)

	manifest := testManifest("exec-finalization", startedAt)
	manifest.Finalization = &FinalizationMetadata{
		ContractVersion:  FinalizationContractVersion,
		State:            FinalizationStateFinalizing,
		SyncOutRequested: true,
		TerminalJobState: "succeeded",
		Checkpoints: FinalizationCheckpoints{
			Artifacts: FinalizationCheckpoint{
				Completed:   true,
				CompletedAt: &artifactCompletedAt,
			},
			SyncOut: FinalizationCheckpoint{
				Completed:   true,
				CompletedAt: &syncOutCompletedAt,
			},
			LeaseRelease: FinalizationCheckpoint{
				Completed:   true,
				CompletedAt: &leaseCompletedAt,
			},
			TerminalPublication: FinalizationCheckpoint{},
		},
		ReasonCode: "terminal_publication_pending",
		StartedAt:  &startedAt,
		UpdatedAt:  updatedAt,
	}

	encoded, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}
	var object map[string]any
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatalf("Unmarshal(object) error: %v", err)
	}
	finalization, ok := object["finalization"].(map[string]any)
	if !ok {
		t.Fatalf("manifest finalization = %T, want object: %s", object["finalization"], encoded)
	}
	assertJSONKeys(t, finalization, []string{
		"contractVersion", "state", "syncOutRequested", "terminalJobState",
		"checkpoints", "reasonCode", "startedAt", "updatedAt",
	})
	for _, unsafeKey := range []string{
		"command", "env", "endpoint", "hostPath", "localPath", "remotePath",
		"socketPath", "credential", "secret", "token",
	} {
		if _, exists := finalization[unsafeKey]; exists {
			t.Fatalf("finalization JSON contains unsafe key %q: %s", unsafeKey, encoded)
		}
	}

	checkpoints, ok := finalization["checkpoints"].(map[string]any)
	if !ok {
		t.Fatalf("finalization checkpoints = %T, want object", finalization["checkpoints"])
	}
	assertJSONKeys(t, checkpoints, []string{
		"artifacts", "syncOut", "leaseRelease", "terminalPublication",
	})

	var roundTrip Manifest
	if err := json.Unmarshal(encoded, &roundTrip); err != nil {
		t.Fatalf("Unmarshal(round trip) error: %v", err)
	}
	if roundTrip.Finalization == nil {
		t.Fatal("round-trip Finalization = nil")
	}
	if roundTrip.Finalization.ContractVersion != FinalizationContractVersion {
		t.Fatalf("round-trip contractVersion = %q", roundTrip.Finalization.ContractVersion)
	}
	if !roundTrip.Finalization.Checkpoints.Artifacts.Completed {
		t.Fatal("round-trip artifacts checkpoint not completed")
	}
}

func TestL3FinalizationLifecycleValidation(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 3, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Minute)

	validCompleted := FinalizationMetadata{
		ContractVersion:  FinalizationContractVersion,
		State:            FinalizationStateCompleted,
		TerminalJobState: "succeeded",
		Checkpoints: FinalizationCheckpoints{
			Artifacts: FinalizationCheckpoint{
				Completed:   true,
				CompletedAt: &completedAt,
			},
			LeaseRelease: FinalizationCheckpoint{
				Completed:   true,
				CompletedAt: &completedAt,
			},
			TerminalPublication: FinalizationCheckpoint{
				Completed:   true,
				CompletedAt: &completedAt,
			},
		},
		StartedAt:   &startedAt,
		UpdatedAt:   completedAt,
		CompletedAt: &completedAt,
	}

	tests := []struct {
		name         string
		finalization FinalizationMetadata
		wantError    bool
	}{
		{name: "completed without unrequested sync-out", finalization: validCompleted},
		{
			name: "completed requested sync-out",
			finalization: func() FinalizationMetadata {
				value := validCompleted
				value.SyncOutRequested = true
				value.Checkpoints.SyncOut = FinalizationCheckpoint{
					Completed:   true,
					CompletedAt: &completedAt,
				}
				return value
			}(),
		},
		{
			name: "unsupported contract",
			finalization: func() FinalizationMetadata {
				value := validCompleted
				value.ContractVersion = "sandbox-finalization-v0"
				return value
			}(),
			wantError: true,
		},
		{
			name: "completed before required checkpoint",
			finalization: func() FinalizationMetadata {
				value := validCompleted
				value.Checkpoints.LeaseRelease = FinalizationCheckpoint{}
				return value
			}(),
			wantError: true,
		},
		{
			name: "completed requested sync-out before checkpoint",
			finalization: func() FinalizationMetadata {
				value := validCompleted
				value.SyncOutRequested = true
				return value
			}(),
			wantError: true,
		},
		{
			name: "checkpoint timestamp without completion",
			finalization: func() FinalizationMetadata {
				value := validCompleted
				value.State = FinalizationStateFinalizing
				value.CompletedAt = nil
				value.Checkpoints.SyncOut = FinalizationCheckpoint{CompletedAt: &completedAt}
				return value
			}(),
			wantError: true,
		},
		{
			name: "blocked without reason code",
			finalization: func() FinalizationMetadata {
				value := validCompleted
				value.State = FinalizationStateBlocked
				value.CompletedAt = nil
				value.ReasonCode = ""
				return value
			}(),
			wantError: true,
		},
		{
			name: "unsafe reason code",
			finalization: func() FinalizationMetadata {
				value := validCompleted
				value.State = FinalizationStateBlocked
				value.CompletedAt = nil
				value.ReasonCode = "token=top-secret"
				return value
			}(),
			wantError: true,
		},
		{
			name: "nonterminal worker state",
			finalization: func() FinalizationMetadata {
				value := validCompleted
				value.TerminalJobState = "running"
				return value
			}(),
			wantError: true,
		},
		{
			name: "completed timestamp before update",
			finalization: func() FinalizationMetadata {
				value := validCompleted
				before := startedAt.Add(-time.Minute)
				value.CompletedAt = &before
				return value
			}(),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			manifest := testManifest("exec-finalization", startedAt)
			manifest.Finalization = &tt.finalization
			err := store.SaveManifest(manifest)
			if tt.wantError && err == nil {
				t.Fatal("SaveManifest() expected finalization validation error")
			}
			if !tt.wantError && err != nil {
				t.Fatalf("SaveManifest() error: %v", err)
			}
		})
	}
}

func TestL3LoadManifestRejectsMalformedFinalizationWithoutLeakingValues(t *testing.T) {
	store := newTestStore(t)
	if err := store.Ensure("exec-corrupt"); err != nil {
		t.Fatalf("Ensure() error: %v", err)
	}
	path, err := store.ManifestPath("exec-corrupt")
	if err != nil {
		t.Fatalf("ManifestPath() error: %v", err)
	}
	const unsafeValue = "https://user:top-secret@example.invalid/private.sock"
	payload := []byte(`{
  "id": "exec-corrupt",
  "purpose": "run",
  "status": "running",
  "startedAt": "2026-07-25T04:00:00Z",
  "finalization": {
    "contractVersion": "sandbox-finalization-v1",
    "state": "blocked",
    "checkpoints": {
      "artifacts": {"completed": false},
      "syncOut": {"completed": false},
      "leaseRelease": {"completed": false},
      "terminalPublication": {"completed": false}
    },
    "reasonCode": "` + unsafeValue + `",
    "updatedAt": "2026-07-25T04:01:00Z"
  }
}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("WriteFile() error: %v", err)
	}

	_, err = store.LoadManifest("exec-corrupt")
	if err == nil {
		t.Fatal("LoadManifest() expected malformed finalization error")
	}
	if !strings.Contains(err.Error(), "exec-corrupt") || !strings.Contains(err.Error(), "finalization") {
		t.Fatalf("LoadManifest() error = %q, want safe execution/finalization context", err)
	}
	if strings.Contains(err.Error(), unsafeValue) || strings.Contains(err.Error(), "top-secret") {
		t.Fatalf("LoadManifest() error leaked unsafe finalization value: %q", err)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatalf("ReadFile() error: %v", readErr)
	}
	if string(got) != string(payload) {
		t.Fatal("LoadManifest() modified malformed committed manifest")
	}
}
