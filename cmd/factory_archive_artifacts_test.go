package cmd

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/factory"
)

func TestFactorySandboxArtifactRequestsFromTimelineUsesCollisionResolvedArchive(t *testing.T) {
	store, record := newFactoryArchiveArtifactTestStore(t, "factory-archive-path")
	appendFactoryArchiveOutputEvent(t, store, record.RunID, "Archived state to 2026-07-14-keyboard-game-2")
	requests := []factory.SandboxArtifactRequest{
		{ID: "sandbox-prd", RemotePath: ".hal/prd.json", Path: ".hal/prd.json"},
		{ID: "sandbox-auto-state", RemotePath: ".hal/auto-state.json", Path: ".hal/auto-state.json"},
		{ID: "sandbox-progress", RemotePath: ".hal/progress.txt", Path: ".hal/progress.txt"},
		{ID: "sandbox-reports", RemotePath: ".hal/reports", Path: ".hal/reports"},
	}

	got, err := factorySandboxArtifactRequestsFromTimeline(store, record.RunID, requests)
	if err != nil {
		t.Fatalf("factorySandboxArtifactRequestsFromTimeline() error: %v", err)
	}
	wantRemotePaths := []string{
		".hal/archive/2026-07-14-keyboard-game-2/prd.json",
		".hal/archive/2026-07-14-keyboard-game-2/auto-state.json",
		".hal/archive/2026-07-14-keyboard-game-2/progress.txt",
		".hal/reports",
	}
	if gotPaths := factorySandboxArtifactRemotePaths(got); !reflect.DeepEqual(gotPaths, wantRemotePaths) {
		t.Fatalf("RemotePaths = %#v, want %#v", gotPaths, wantRemotePaths)
	}
	for i := range got {
		if got[i].ID != requests[i].ID || got[i].Path != requests[i].Path {
			t.Fatalf("request[%d] identity/display path changed: got %#v want %#v", i, got[i], requests[i])
		}
	}
}

func TestFactorySandboxArtifactRequestsFromTimelineFallsBackToRoot(t *testing.T) {
	store, record := newFactoryArchiveArtifactTestStore(t, "factory-archive-root-fallback")
	requests := factoryArchiveCoreArtifactRequests()

	got, err := factorySandboxArtifactRequestsFromTimeline(store, record.RunID, requests)
	if err != nil {
		t.Fatalf("factorySandboxArtifactRequestsFromTimeline() error: %v", err)
	}
	if !reflect.DeepEqual(got, requests) {
		t.Fatalf("requests = %#v, want unchanged root fallback %#v", got, requests)
	}
}

func TestFactorySandboxArtifactRequestsFromTimelineRejectsUnsafeArchiveOutput(t *testing.T) {
	tests := []string{
		"Archived state to /tmp/absolute",
		"Archived state to ../../outside",
		"Archived state to nested/child",
	}
	for _, output := range tests {
		t.Run(output, func(t *testing.T) {
			store, record := newFactoryArchiveArtifactTestStore(t, "factory-archive-unsafe")
			appendFactoryArchiveOutputEvent(t, store, record.RunID, output)

			_, err := factorySandboxArtifactRequestsFromTimeline(store, record.RunID, factoryArchiveCoreArtifactRequests())
			if err == nil || !strings.Contains(err.Error(), "archive path") {
				t.Fatalf("factorySandboxArtifactRequestsFromTimeline() error = %v, want archive path validation failure", err)
			}
		})
	}
}

func TestCollectAndStoreFactorySandboxArtifactsCollectsArchivedCoreWithoutPartials(t *testing.T) {
	store, record := newFactoryArchiveArtifactTestStore(t, "factory-archive-collect")
	appendFactoryArchiveOutputEvent(t, store, record.RunID, "Archived state to 2026-07-14-keyboard-game-2")
	copier := &fakeFactorySandboxArtifactCopier{files: map[string]string{
		".hal/archive/2026-07-14-keyboard-game-2/prd.json":        `{"project":"keyboard-game"}` + "\n",
		".hal/archive/2026-07-14-keyboard-game-2/auto-state.json": `{"step":"done"}` + "\n",
		".hal/archive/2026-07-14-keyboard-game-2/progress.txt":    "complete\n",
	}}

	err := collectAndStoreFactorySandboxArtifacts(context.Background(), store, t.TempDir(), factoryRunRequest{}, record, factoryRunDeps{
		now:           func() time.Time { return time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC) },
		sandboxCopier: copier,
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
			return factoryArchiveCoreArtifactRequests()
		},
	})
	if err != nil {
		t.Fatalf("collectAndStoreFactorySandboxArtifacts() error: %v", err)
	}
	wantCalls := []string{
		".hal/archive/2026-07-14-keyboard-game-2/prd.json",
		".hal/archive/2026-07-14-keyboard-game-2/auto-state.json",
		".hal/archive/2026-07-14-keyboard-game-2/progress.txt",
	}
	if !reflect.DeepEqual(copier.fileCalls, wantCalls) {
		t.Fatalf("CopyFile calls = %#v, want archived sources %#v", copier.fileCalls, wantCalls)
	}
	loaded, err := store.LoadRun(record.RunID)
	if err != nil {
		t.Fatalf("LoadRun() error: %v", err)
	}
	for _, displayPath := range []string{".hal/prd.json", ".hal/auto-state.json", ".hal/progress.txt"} {
		artifact := requireFactoryArtifactPath(t, loaded.Artifacts, displayPath)
		if artifact.Partial || artifact.StoredPath == "" || len(artifact.Warnings) != 0 {
			t.Fatalf("artifact %q = %#v, want stored non-partial artifact without warnings", displayPath, artifact)
		}
	}
}

func TestCollectAndStoreFactorySandboxArtifactsInvalidArchiveOutputFailsBeforeCopy(t *testing.T) {
	store, record := newFactoryArchiveArtifactTestStore(t, "factory-archive-invalid")
	appendFactoryArchiveOutputEvent(t, store, record.RunID, "Archived state to ../outside")
	copier := &fakeFactorySandboxArtifactCopier{files: map[string]string{}}

	err := collectAndStoreFactorySandboxArtifacts(context.Background(), store, t.TempDir(), factoryRunRequest{}, record, factoryRunDeps{
		now:           func() time.Time { return time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC) },
		sandboxCopier: copier,
		sandboxRequests: func(string, factory.RunRecord) []factory.SandboxArtifactRequest {
			return factoryArchiveCoreArtifactRequests()
		},
	})
	if err == nil || !strings.Contains(err.Error(), "archive path") {
		t.Fatalf("collectAndStoreFactorySandboxArtifacts() error = %v, want archive path failure", err)
	}
	if len(copier.fileCalls) != 0 || len(copier.dirCalls) != 0 {
		t.Fatalf("copier calls = %#v/%#v, want none", copier.fileCalls, copier.dirCalls)
	}
	events, loadErr := store.LoadEvents(record.RunID)
	if loadErr != nil {
		t.Fatalf("LoadEvents() error: %v", loadErr)
	}
	if events[len(events)-1].EventType != factory.EventTypeArtifactSync || events[len(events)-1].Metadata["status"] != factory.RunStatusFailed {
		t.Fatalf("last event = %#v, want failed artifact sync event", events[len(events)-1])
	}
}

func newFactoryArchiveArtifactTestStore(t *testing.T, runID string) (factory.Store, factory.RunRecord) {
	t.Helper()
	store := factory.NewStore(t.TempDir())
	record := factory.RunRecord{
		RunID:        runID,
		ExecutorMode: factory.ExecutorModeSandbox,
		CreatedAt:    time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC),
		UpdatedAt:    time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC),
	}
	if err := store.SaveRun(&record); err != nil {
		t.Fatalf("SaveRun() error: %v", err)
	}
	return store, record
}

func appendFactoryArchiveOutputEvent(t *testing.T, store factory.Store, runID, message string) {
	t.Helper()
	if err := store.AppendEvent(&factory.EventRecord{
		Sequence:  1,
		RunID:     runID,
		EventType: factory.EventTypeCommandOutputSummary,
		Timestamp: time.Date(2026, 7, 14, 0, 30, 0, 0, time.UTC),
		Message:   message,
		Summary:   "Remote sandbox output",
		Metadata: map[string]any{
			"source": factory.LogSourceRemoteSandbox,
		},
	}); err != nil {
		t.Fatalf("AppendEvent() error: %v", err)
	}
}

func factoryArchiveCoreArtifactRequests() []factory.SandboxArtifactRequest {
	return []factory.SandboxArtifactRequest{
		{ID: "sandbox-prd", Name: "sandbox-prd", Type: "json", RemotePath: ".hal/prd.json", Path: ".hal/prd.json", Optional: true},
		{ID: "sandbox-auto-state", Name: "sandbox-auto-state", Type: "json", RemotePath: ".hal/auto-state.json", Path: ".hal/auto-state.json", Optional: true},
		{ID: "sandbox-progress", Name: "sandbox-progress", Type: "text", RemotePath: ".hal/progress.txt", Path: ".hal/progress.txt", Optional: true},
	}
}

func factorySandboxArtifactRemotePaths(requests []factory.SandboxArtifactRequest) []string {
	paths := make([]string, len(requests))
	for i := range requests {
		paths[i] = requests[i].RemotePath
	}
	return paths
}
