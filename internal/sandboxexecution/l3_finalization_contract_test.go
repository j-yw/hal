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
	artifactCompletedAt := startedAt.Add(time.Minute)
	syncOutCompletedAt := artifactCompletedAt.Add(time.Minute)
	leaseCompletedAt := syncOutCompletedAt.Add(time.Minute)
	updatedAt := leaseCompletedAt.Add(time.Minute)

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

func TestL3CompletedPublicationRejectsContradictoryManifestState(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 4, 30, 0, 0, time.UTC)
	finishedAt := startedAt.Add(time.Minute)
	completedAt := finishedAt.Add(time.Second)
	terminalJob := &WorkerJobReference{
		ContractVersion: WorkerJobContractVersion,
		JobID:           "job-terminal",
		WorkerID:        "worker-terminal",
		RuntimeDriver:   "rootless_podman",
		State:           "succeeded",
		SubmittedAt:     startedAt,
		StartedAt:       &startedAt,
		HeartbeatAt:     &startedAt,
		FinishedAt:      &finishedAt,
	}
	valid := testManifest("exec-terminal-publication", startedAt)
	valid.Status = StatusSucceeded
	valid.FinishedAt = &finishedAt
	valid.WorkerJob = terminalJob
	completed := l3CompletedFinalizationFixture(finishedAt, completedAt)
	valid.Finalization = &completed

	tests := []struct {
		name   string
		mutate func(*Manifest)
	}{
		{
			name: "execution status remains running",
			mutate: func(manifest *Manifest) {
				manifest.Status = StatusRunning
			},
		},
		{
			name: "worker job state disagrees",
			mutate: func(manifest *Manifest) {
				manifest.WorkerJob.State = "failed"
			},
		},
		{
			name: "execution finish time disagrees",
			mutate: func(manifest *Manifest) {
				different := finishedAt.Add(time.Second)
				manifest.FinishedAt = &different
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := newTestStore(t)
			manifest := *valid
			worker := *valid.WorkerJob
			finalization := *valid.Finalization
			manifest.WorkerJob = &worker
			manifest.Finalization = &finalization
			tt.mutate(&manifest)
			if err := store.SaveManifest(&manifest); err == nil {
				t.Fatal("SaveManifest() accepted contradictory completed publication")
			}
		})
	}
}

func TestL3CompletedFinalizationRequiresProvenTerminalJobState(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 5, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Minute)
	for _, terminalState := range []string{"unknown", "interrupted"} {
		t.Run(terminalState, func(t *testing.T) {
			metadata := l3CompletedFinalizationFixture(startedAt, completedAt)
			metadata.TerminalJobState = terminalState
			err := validateFinalizationMetadata(&metadata)
			if err == nil {
				t.Fatalf("validateFinalizationMetadata() accepted completed %q terminal proof", terminalState)
			}
			if !strings.Contains(err.Error(), "terminal proof") {
				t.Fatalf("validateFinalizationMetadata() error = %q, want terminal proof context", err)
			}
		})
	}
}

func TestL3UnprovenTerminalStateCannotCompleteFinalizationCheckpoints(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 6, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Minute)
	for _, terminalState := range []string{"unknown", "interrupted"} {
		for _, checkpoint := range []string{"artifacts", "syncOut", "leaseRelease", "terminalPublication"} {
			t.Run(terminalState+"/"+checkpoint, func(t *testing.T) {
				metadata := FinalizationMetadata{
					ContractVersion:  FinalizationContractVersion,
					State:            FinalizationStateBlocked,
					SyncOutRequested: true,
					TerminalJobState: terminalState,
					ReasonCode:       "worker_terminal_state_unproven",
					StartedAt:        &startedAt,
					UpdatedAt:        completedAt,
				}
				completed := FinalizationCheckpoint{Completed: true, CompletedAt: &completedAt}
				switch checkpoint {
				case "artifacts":
					metadata.Checkpoints.Artifacts = completed
				case "syncOut":
					metadata.Checkpoints.SyncOut = completed
				case "leaseRelease":
					metadata.Checkpoints.LeaseRelease = completed
				case "terminalPublication":
					metadata.Checkpoints.TerminalPublication = completed
				}

				err := validateFinalizationMetadata(&metadata)
				if err == nil {
					t.Fatalf("validateFinalizationMetadata() accepted %q with completed %s checkpoint", terminalState, checkpoint)
				}
				if !strings.Contains(err.Error(), "unproven terminal job state") {
					t.Fatalf("validateFinalizationMetadata() error = %q, want unproven terminal state context", err)
				}
			})
		}
	}
}

func TestL3UnprovenTerminalStateSupportsBlockedHandoffWithoutCheckpoints(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 7, 0, 0, 0, time.UTC)
	updatedAt := startedAt.Add(time.Minute)
	for _, terminalState := range []string{"unknown", "interrupted"} {
		t.Run(terminalState, func(t *testing.T) {
			store := newTestStore(t)
			manifest := testManifest("exec-blocked-"+terminalState, startedAt)
			manifest.Finalization = &FinalizationMetadata{
				ContractVersion:  FinalizationContractVersion,
				State:            FinalizationStateBlocked,
				TerminalJobState: terminalState,
				ReasonCode:       "worker_terminal_state_unproven",
				StartedAt:        &startedAt,
				UpdatedAt:        updatedAt,
			}
			if err := store.SaveManifest(manifest); err != nil {
				t.Fatalf("SaveManifest() error: %v", err)
			}
			loaded, err := store.LoadManifest(manifest.ID)
			if err != nil {
				t.Fatalf("LoadManifest() error: %v", err)
			}
			if loaded.Finalization == nil || loaded.Finalization.TerminalJobState != terminalState {
				t.Fatalf("loaded Finalization = %#v, want blocked %q handoff", loaded.Finalization, terminalState)
			}
		})
	}
}

func TestL3UnrequestedSyncOutCheckpointCannotComplete(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 8, 0, 0, 0, time.UTC)
	completedAt := startedAt.Add(time.Minute)
	metadata := FinalizationMetadata{
		ContractVersion:  FinalizationContractVersion,
		State:            FinalizationStateFinalizing,
		TerminalJobState: "succeeded",
		Checkpoints: FinalizationCheckpoints{
			Artifacts: FinalizationCheckpoint{Completed: true, CompletedAt: &completedAt},
			SyncOut:   FinalizationCheckpoint{Completed: true, CompletedAt: &completedAt},
		},
		StartedAt: &startedAt,
		UpdatedAt: completedAt,
	}
	err := validateFinalizationMetadata(&metadata)
	if err == nil {
		t.Fatal("validateFinalizationMetadata() accepted completed syncOut checkpoint without intent")
	}
	if !strings.Contains(err.Error(), "without requested intent") {
		t.Fatalf("validateFinalizationMetadata() error = %q, want missing sync-out intent context", err)
	}
}

func TestL3CompletedCheckpointTimestampsStayInsideFinalizationWindow(t *testing.T) {
	startedAt := time.Date(2026, 7, 25, 9, 0, 0, 0, time.UTC)
	updatedAt := startedAt.Add(2 * time.Minute)
	tests := []struct {
		name      string
		timestamp time.Time
		want      string
	}{
		{name: "before startedAt", timestamp: startedAt.Add(-time.Second), want: "precedes startedAt"},
		{name: "after updatedAt", timestamp: updatedAt.Add(time.Second), want: "follows updatedAt"},
	}
	for _, checkpoint := range []string{"artifacts", "syncOut", "leaseRelease", "terminalPublication"} {
		for _, tt := range tests {
			t.Run(checkpoint+"/"+tt.name, func(t *testing.T) {
				metadata := FinalizationMetadata{
					ContractVersion:  FinalizationContractVersion,
					State:            FinalizationStateFinalizing,
					SyncOutRequested: true,
					TerminalJobState: "succeeded",
					StartedAt:        &startedAt,
					UpdatedAt:        updatedAt,
				}
				completed := FinalizationCheckpoint{Completed: true, CompletedAt: &tt.timestamp}
				switch checkpoint {
				case "artifacts":
					metadata.Checkpoints.Artifacts = completed
				case "syncOut":
					metadata.Checkpoints.SyncOut = completed
				case "leaseRelease":
					metadata.Checkpoints.LeaseRelease = completed
				case "terminalPublication":
					metadata.Checkpoints.TerminalPublication = completed
				}

				err := validateFinalizationMetadata(&metadata)
				if err == nil {
					t.Fatalf("validateFinalizationMetadata() accepted %s checkpoint %s", checkpoint, tt.name)
				}
				if !strings.Contains(err.Error(), checkpoint) || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("validateFinalizationMetadata() error = %q, want %s %s", err, checkpoint, tt.want)
				}
			})
		}
	}
}

func l3CompletedFinalizationFixture(startedAt, completedAt time.Time) FinalizationMetadata {
	completed := FinalizationCheckpoint{Completed: true, CompletedAt: &completedAt}
	return FinalizationMetadata{
		ContractVersion:  FinalizationContractVersion,
		State:            FinalizationStateCompleted,
		TerminalJobState: "succeeded",
		Checkpoints: FinalizationCheckpoints{
			Artifacts:           completed,
			LeaseRelease:        completed,
			TerminalPublication: completed,
		},
		StartedAt:   &startedAt,
		UpdatedAt:   completedAt,
		CompletedAt: &completedAt,
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
