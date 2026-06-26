package factory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultQueuePathUsesGlobalFactoryStore(t *testing.T) {
	global := filepath.Join(t.TempDir(), "global-hal")
	t.Setenv("HAL_CONFIG_HOME", global)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("HOME", t.TempDir())

	store, err := DefaultStore()
	if err != nil {
		t.Fatalf("DefaultStore() unexpected error: %v", err)
	}

	want := filepath.Join(global, factoryStoreDirName, queueFileName)
	if store.QueuePath() != want {
		t.Fatalf("QueuePath() = %q, want %q", store.QueuePath(), want)
	}
	if strings.Contains(store.QueuePath(), string(filepath.Separator)+".hal"+string(filepath.Separator)) {
		t.Fatalf("QueuePath() = %q, should use global config dir, not project .hal", store.QueuePath())
	}
}

func TestLoadQueueTreatsMissingFileAsEmpty(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))

	got, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("LoadQueue() = %v, want empty", got)
	}
	if _, err := os.Stat(store.Root()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("LoadQueue() should not create store root, stat error = %v", err)
	}
}

func TestSaveQueueAndLoadQueueRoundTripWithNewStore(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	entries := []QueueEntry{
		testQueueEntry("queue-001", "run-001", time.Date(2026, 6, 20, 17, 0, 0, 0, time.UTC)),
		testQueueEntry("queue-002", "run-002", time.Date(2026, 6, 20, 17, 5, 0, 0, time.UTC)),
	}

	if err := store.SaveQueue(entries); err != nil {
		t.Fatalf("SaveQueue() unexpected error: %v", err)
	}

	info, err := os.Stat(store.QueuePath())
	if err != nil {
		t.Fatalf("expected committed queue state: %v", err)
	}
	if info.IsDir() {
		t.Fatalf("queue path should be a file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("queue permissions = %o, want %o", info.Mode().Perm(), 0o600)
	}
	if _, err := os.Stat(store.QueuePath() + storeTempFileExt); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("temp file should not remain after SaveQueue(), stat error = %v", err)
	}

	reloadedStore := NewStore(store.Root())
	got, err := reloadedStore.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(got, entries) {
		t.Fatalf("LoadQueue() = %#v, want %#v", got, entries)
	}
}

func TestLoadQueueCorruptJSONReturnsErrorAndPreservesFile(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	if err := os.MkdirAll(store.Root(), 0o700); err != nil {
		t.Fatalf("mkdir store root: %v", err)
	}

	contents := []byte(`{"entries":` + "\n")
	if err := os.WriteFile(store.QueuePath(), contents, 0o600); err != nil {
		t.Fatalf("write corrupt queue: %v", err)
	}

	_, err := store.LoadQueue()
	if err == nil {
		t.Fatalf("LoadQueue() expected parse error")
	}
	if !strings.Contains(err.Error(), "parse factory queue") {
		t.Fatalf("LoadQueue() error = %q, want clear parse factory queue error", err.Error())
	}

	after, readErr := os.ReadFile(store.QueuePath())
	if readErr != nil {
		t.Fatalf("queue file should remain readable after parse failure: %v", readErr)
	}
	if !reflect.DeepEqual(after, contents) {
		t.Fatalf("queue file changed after parse failure: got %q, want %q", after, contents)
	}
}

func TestSaveQueueFailurePreservesCommittedState(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	original := []QueueEntry{
		testQueueEntry("queue-001", "run-001", time.Date(2026, 6, 20, 17, 0, 0, 0, time.UTC)),
	}
	next := []QueueEntry{
		testQueueEntry("queue-002", "run-002", time.Date(2026, 6, 20, 17, 5, 0, 0, time.UTC)),
	}

	if err := store.SaveQueue(original); err != nil {
		t.Fatalf("initial SaveQueue() unexpected error: %v", err)
	}
	before, err := os.ReadFile(store.QueuePath())
	if err != nil {
		t.Fatalf("read initial queue: %v", err)
	}

	originalSaveQueueFile := saveQueueFile
	t.Cleanup(func() {
		saveQueueFile = originalSaveQueueFile
	})
	saveQueueFile = func(_, _ string) error {
		return fmt.Errorf("forced queue save failure")
	}

	err = store.SaveQueue(next)
	if err == nil {
		t.Fatalf("SaveQueue() expected error")
	}
	if !strings.Contains(err.Error(), "save factory queue") {
		t.Fatalf("SaveQueue() error = %q, want save factory queue context", err.Error())
	}

	after, err := os.ReadFile(store.QueuePath())
	if err != nil {
		t.Fatalf("read queue after failed save: %v", err)
	}
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("committed queue changed after failed save:\ngot  %s\nwant %s", after, before)
	}
	if _, err := os.Stat(store.QueuePath() + storeTempFileExt); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("temp file should be removed after failed SaveQueue(), stat error = %v", err)
	}

	reloaded, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() after failed save unexpected error: %v", err)
	}
	if !reflect.DeepEqual(reloaded, original) {
		t.Fatalf("LoadQueue() after failed save = %#v, want %#v", reloaded, original)
	}
}

func TestUpdateQueueSerializesConcurrentMutations(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	const workerCount = 24

	start := make(chan struct{})
	errs := make(chan error, workerCount)
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start

			_, err := store.UpdateQueue(func(entries []QueueEntry) ([]QueueEntry, error) {
				time.Sleep(time.Millisecond)
				createdAt := time.Date(2026, 6, 20, 17, i, 0, 0, time.UTC)
				entry := testQueueEntry(
					fmt.Sprintf("queue-%03d", i),
					fmt.Sprintf("run-%03d", i),
					createdAt,
				)
				return append(entries, entry), nil
			})
			errs <- err
		}()
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("UpdateQueue() concurrent mutation unexpected error: %v", err)
		}
	}

	got, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() unexpected error: %v", err)
	}
	if len(got) != workerCount {
		t.Fatalf("LoadQueue() entries len = %d, want %d; entries = %#v", len(got), workerCount, got)
	}

	seen := make(map[string]bool, workerCount)
	for _, entry := range got {
		seen[entry.QueueID] = true
	}
	for i := 0; i < workerCount; i++ {
		queueID := fmt.Sprintf("queue-%03d", i)
		if !seen[queueID] {
			t.Fatalf("queue entry %q missing after concurrent mutations; entries = %#v", queueID, got)
		}
	}
}

func TestEnqueueQueueEntryCreatesSingleQueuedEntryWithInjectedSources(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 9, 15, 0, 0, time.FixedZone("CST", 8*60*60))

	got, err := store.EnqueueQueueEntry("run-001", ExecutorModeLocal, QueueOperationOptions{
		Now: func() time.Time { return createdAt },
		NewQueueID: func() (string, error) {
			return "queue-001", nil
		},
	})
	if err != nil {
		t.Fatalf("EnqueueQueueEntry() unexpected error: %v", err)
	}

	want := QueueEntry{
		QueueID:      "queue-001",
		RunID:        "run-001",
		ExecutorMode: ExecutorModeLocal,
		Status:       QueueStatusQueued,
		CreatedAt:    createdAt.UTC(),
		AttemptCount: 0,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("EnqueueQueueEntry() = %#v, want %#v", got, want)
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(entries, []QueueEntry{want}) {
		t.Fatalf("LoadQueue() = %#v, want one queued entry %#v", entries, want)
	}
}

func TestEnqueueQueueEntryRejectsDuplicateActiveRunEntry(t *testing.T) {
	tests := []struct {
		name   string
		status string
	}{
		{name: "queued", status: QueueStatusQueued},
		{name: "claimed", status: QueueStatusClaimed},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			store := NewStore(filepath.Join(t.TempDir(), "factory"))
			createdAt := time.Date(2026, 6, 21, 9, 30, 0, 0, time.UTC)
			existing := testQueueEntryWithStatus("queue-existing", "run-duplicate", tt.status, createdAt)
			if err := store.SaveQueue([]QueueEntry{existing}); err != nil {
				t.Fatalf("SaveQueue() unexpected error: %v", err)
			}

			_, err := store.EnqueueQueueEntry("run-duplicate", ExecutorModeLocal, QueueOperationOptions{
				Now: func() time.Time { return createdAt.Add(time.Minute) },
				NewQueueID: func() (string, error) {
					return "queue-new", nil
				},
			})
			if err == nil {
				t.Fatalf("EnqueueQueueEntry() error = nil, want duplicate active run error")
			}
			if want := `factory run "run-duplicate" already has active queue entry "queue-existing"`; err.Error() != want {
				t.Fatalf("EnqueueQueueEntry() error = %q, want %q", err.Error(), want)
			}

			entries, err := store.LoadQueue()
			if err != nil {
				t.Fatalf("LoadQueue() unexpected error: %v", err)
			}
			if !reflect.DeepEqual(entries, []QueueEntry{existing}) {
				t.Fatalf("LoadQueue() = %#v, want unchanged %#v", entries, []QueueEntry{existing})
			}
		})
	}
}

func TestEnqueueQueueEntryAllowsRunAfterTerminalQueueEntry(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 9, 45, 0, 0, time.UTC)
	existing := testQueueEntryWithStatus("queue-existing", "run-retry", QueueStatusFailed, createdAt)
	if err := store.SaveQueue([]QueueEntry{existing}); err != nil {
		t.Fatalf("SaveQueue() unexpected error: %v", err)
	}

	got, err := store.EnqueueQueueEntry("run-retry", ExecutorModeLocal, QueueOperationOptions{
		Now: func() time.Time { return createdAt.Add(time.Minute) },
		NewQueueID: func() (string, error) {
			return "queue-new", nil
		},
	})
	if err != nil {
		t.Fatalf("EnqueueQueueEntry() unexpected error: %v", err)
	}
	if got.QueueID != "queue-new" {
		t.Fatalf("EnqueueQueueEntry() queueID = %q, want queue-new", got.QueueID)
	}

	entries, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("LoadQueue() entries len = %d, want 2: %#v", len(entries), entries)
	}
}

func TestListQueueReturnsFIFOOrder(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 10, 0, 0, 0, time.UTC)
	entries := []QueueEntry{
		testQueueEntry("queue-003", "run-new", base.Add(10*time.Minute)),
		testQueueEntry("queue-002", "run-tie-b", base),
		testQueueEntry("queue-001", "run-old", base.Add(-10*time.Minute)),
		testQueueEntry("queue-004", "run-tie-a", base),
	}
	if err := store.SaveQueue(entries); err != nil {
		t.Fatalf("SaveQueue() unexpected error: %v", err)
	}

	got, err := store.ListQueue()
	if err != nil {
		t.Fatalf("ListQueue() unexpected error: %v", err)
	}

	gotQueueIDs := make([]string, 0, len(got))
	for _, entry := range got {
		gotQueueIDs = append(gotQueueIDs, entry.QueueID)
	}
	wantQueueIDs := []string{"queue-001", "queue-002", "queue-004", "queue-003"}
	if !reflect.DeepEqual(gotQueueIDs, wantQueueIDs) {
		t.Fatalf("ListQueue() queue IDs = %v, want FIFO %v", gotQueueIDs, wantQueueIDs)
	}
}

func TestClaimNextQueueEntrySelectsOldestQueuedEntry(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 11, 0, 0, 0, time.UTC)
	entries := []QueueEntry{
		testQueueEntryWithStatus("queue-failed-old", "run-failed", QueueStatusFailed, base.Add(-30*time.Minute)),
		testQueueEntryWithStatus("queue-queued-new", "run-new", QueueStatusQueued, base.Add(10*time.Minute)),
		testQueueEntryWithStatus("queue-claimed-old", "run-claimed", QueueStatusClaimed, base.Add(-20*time.Minute)),
		testQueueEntryWithStatus("queue-queued-old", "run-old", QueueStatusQueued, base.Add(-10*time.Minute)),
	}
	if err := store.SaveQueue(entries); err != nil {
		t.Fatalf("SaveQueue() unexpected error: %v", err)
	}

	claimedAt := base.Add(30 * time.Minute)
	claim := QueueClaim{WorkerID: "worker-a", PID: 4242, Hostname: "factory-host"}
	got, err := store.ClaimNextQueueEntry(QueueOperationOptions{
		Now:   func() time.Time { return claimedAt },
		Claim: &claim,
	})
	if err != nil {
		t.Fatalf("ClaimNextQueueEntry() unexpected error: %v", err)
	}
	if got == nil {
		t.Fatalf("ClaimNextQueueEntry() = nil, want claimed entry")
	}
	if got.QueueID != "queue-queued-old" {
		t.Fatalf("ClaimNextQueueEntry() queue ID = %q, want oldest queued entry", got.QueueID)
	}
	if got.Status != QueueStatusClaimed {
		t.Fatalf("ClaimNextQueueEntry() status = %q, want %q", got.Status, QueueStatusClaimed)
	}
	if got.ClaimedAt == nil || !got.ClaimedAt.Equal(claimedAt.UTC()) {
		t.Fatalf("ClaimNextQueueEntry() claimedAt = %v, want %v", got.ClaimedAt, claimedAt.UTC())
	}
	if got.Claim == nil || !reflect.DeepEqual(*got.Claim, claim) {
		t.Fatalf("ClaimNextQueueEntry() claim = %#v, want %#v", got.Claim, claim)
	}
	if got.AttemptCount != 1 {
		t.Fatalf("ClaimNextQueueEntry() attemptCount = %d, want 1", got.AttemptCount)
	}

	reloaded, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() unexpected error: %v", err)
	}
	byQueueID := queueEntriesByID(reloaded)
	claimedEntry := byQueueID["queue-queued-old"]
	if claimedEntry.Status != QueueStatusClaimed {
		t.Fatalf("oldest queued entry status = %q, want claimed", claimedEntry.Status)
	}
	if claimedEntry.ClaimedAt == nil || !claimedEntry.ClaimedAt.Equal(claimedAt.UTC()) {
		t.Fatalf("oldest queued entry claimedAt = %v, want %v", claimedEntry.ClaimedAt, claimedAt.UTC())
	}
	if claimedEntry.Claim == nil || !reflect.DeepEqual(*claimedEntry.Claim, claim) {
		t.Fatalf("oldest queued entry claim = %#v, want %#v", claimedEntry.Claim, claim)
	}
	if claimedEntry.AttemptCount != 1 {
		t.Fatalf("oldest queued entry attemptCount = %d, want 1", claimedEntry.AttemptCount)
	}
	if byQueueID["queue-queued-new"].Status != QueueStatusQueued {
		t.Fatalf("newer queued entry status = %q, want still queued", byQueueID["queue-queued-new"].Status)
	}
	if byQueueID["queue-failed-old"].Status != QueueStatusFailed {
		t.Fatalf("failed entry status = %q, want unchanged", byQueueID["queue-failed-old"].Status)
	}
	if byQueueID["queue-claimed-old"].Status != QueueStatusClaimed {
		t.Fatalf("claimed entry status = %q, want unchanged", byQueueID["queue-claimed-old"].Status)
	}
}

func TestClaimNextQueueEntryReturnsNilWhenNoQueuedEntries(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	entries := []QueueEntry{
		testQueueEntryWithStatus("queue-claimed", "run-claimed", QueueStatusClaimed, base),
		testQueueEntryWithStatus("queue-failed", "run-failed", QueueStatusFailed, base.Add(time.Minute)),
	}
	if err := store.SaveQueue(entries); err != nil {
		t.Fatalf("SaveQueue() unexpected error: %v", err)
	}

	got, err := store.ClaimNextQueueEntry(QueueOperationOptions{})
	if err != nil {
		t.Fatalf("ClaimNextQueueEntry() unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("ClaimNextQueueEntry() = %#v, want nil", got)
	}

	reloaded, err := store.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() unexpected error: %v", err)
	}
	if !reflect.DeepEqual(reloaded, entries) {
		t.Fatalf("LoadQueue() = %#v, want unchanged %#v", reloaded, entries)
	}
}

func TestMarkQueueEntrySucceededRecordsTerminalState(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 13, 0, 0, 0, time.UTC)
	claimedAt := createdAt.Add(5 * time.Minute)
	completedAt := createdAt.Add(30 * time.Minute)
	claim := QueueClaim{WorkerID: "worker-success", PID: 4343, Hostname: "factory-host"}
	entry := testQueueEntryWithStatus("queue-success", "run-success", QueueStatusClaimed, createdAt)
	entry.ClaimedAt = &claimedAt
	entry.Claim = &claim
	entry.AttemptCount = 1
	entry.LastError = "old failure"
	if err := store.SaveQueue([]QueueEntry{entry}); err != nil {
		t.Fatalf("SaveQueue() unexpected error: %v", err)
	}

	got, err := store.MarkQueueEntrySucceeded("queue-success", QueueOperationOptions{
		Now: func() time.Time { return completedAt },
	})
	if err != nil {
		t.Fatalf("MarkQueueEntrySucceeded() unexpected error: %v", err)
	}

	if got.Status != QueueStatusSucceeded {
		t.Fatalf("MarkQueueEntrySucceeded() status = %q, want %q", got.Status, QueueStatusSucceeded)
	}
	if got.CompletedAt == nil || !got.CompletedAt.Equal(completedAt.UTC()) {
		t.Fatalf("MarkQueueEntrySucceeded() completedAt = %v, want %v", got.CompletedAt, completedAt.UTC())
	}
	if got.AttemptCount != 1 {
		t.Fatalf("MarkQueueEntrySucceeded() attemptCount = %d, want 1", got.AttemptCount)
	}
	if got.LastError != "" {
		t.Fatalf("MarkQueueEntrySucceeded() lastError = %q, want empty", got.LastError)
	}

	listed, err := store.ListQueue()
	if err != nil {
		t.Fatalf("ListQueue() unexpected error: %v", err)
	}
	if len(listed) != 1 || listed[0].Status != QueueStatusSucceeded {
		t.Fatalf("ListQueue() = %#v, want retained succeeded entry", listed)
	}
}

func TestMarkQueueEntryFailedRecordsInspectableState(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	createdAt := time.Date(2026, 6, 21, 14, 0, 0, 0, time.UTC)
	claimedAt := createdAt.Add(3 * time.Minute)
	completedAt := createdAt.Add(25 * time.Minute)
	claim := QueueClaim{WorkerID: "worker-failed", PID: 4444, Hostname: "factory-host"}
	entry := testQueueEntryWithStatus("queue-failed", "run-failed", QueueStatusClaimed, createdAt)
	entry.ClaimedAt = &claimedAt
	entry.Claim = &claim
	if err := store.SaveQueue([]QueueEntry{entry}); err != nil {
		t.Fatalf("SaveQueue() unexpected error: %v", err)
	}

	got, err := store.MarkQueueEntryFailed("queue-failed", " unit tests failed ", QueueOperationOptions{
		Now: func() time.Time { return completedAt },
	})
	if err != nil {
		t.Fatalf("MarkQueueEntryFailed() unexpected error: %v", err)
	}

	if got.Status != QueueStatusFailed {
		t.Fatalf("MarkQueueEntryFailed() status = %q, want %q", got.Status, QueueStatusFailed)
	}
	if got.CompletedAt == nil || !got.CompletedAt.Equal(completedAt.UTC()) {
		t.Fatalf("MarkQueueEntryFailed() completedAt = %v, want %v", got.CompletedAt, completedAt.UTC())
	}
	if got.AttemptCount != 1 {
		t.Fatalf("MarkQueueEntryFailed() attemptCount = %d, want 1", got.AttemptCount)
	}
	if got.LastError != "unit tests failed" {
		t.Fatalf("MarkQueueEntryFailed() lastError = %q, want trimmed error", got.LastError)
	}

	reloadedStore := NewStore(store.Root())
	reloaded, err := reloadedStore.ListQueue()
	if err != nil {
		t.Fatalf("ListQueue() after reload unexpected error: %v", err)
	}
	if len(reloaded) != 1 {
		t.Fatalf("ListQueue() after reload len = %d, want 1", len(reloaded))
	}
	if !reflect.DeepEqual(reloaded[0], got) {
		t.Fatalf("ListQueue() after reload = %#v, want retained failed entry %#v", reloaded[0], got)
	}
}

func TestQueueLifecycleStateSurvivesReload(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "factory"))
	base := time.Date(2026, 6, 21, 15, 0, 0, 0, time.UTC)
	entries := []QueueEntry{
		testQueueEntry("queue-claimed", "run-claimed", base),
		testQueueEntry("queue-failed", "run-failed", base.Add(time.Minute)),
	}
	if err := store.SaveQueue(entries); err != nil {
		t.Fatalf("SaveQueue() unexpected error: %v", err)
	}

	claimedAt := base.Add(10 * time.Minute)
	claim := QueueClaim{WorkerID: "worker-reload", PID: 4545, Hostname: "factory-host"}
	claimed, err := store.ClaimNextQueueEntry(QueueOperationOptions{
		Now:   func() time.Time { return claimedAt },
		Claim: &claim,
	})
	if err != nil {
		t.Fatalf("ClaimNextQueueEntry() unexpected error: %v", err)
	}
	if claimed == nil {
		t.Fatalf("ClaimNextQueueEntry() = nil, want claimed entry")
	}

	secondClaimedAt := base.Add(12 * time.Minute)
	secondClaimed, err := store.ClaimNextQueueEntry(QueueOperationOptions{
		Now:   func() time.Time { return secondClaimedAt },
		Claim: &claim,
	})
	if err != nil {
		t.Fatalf("second ClaimNextQueueEntry() unexpected error: %v", err)
	}
	if secondClaimed == nil {
		t.Fatalf("second ClaimNextQueueEntry() = nil, want claimed entry")
	}
	failedAt := base.Add(40 * time.Minute)
	failed, err := store.MarkQueueEntryFailed(secondClaimed.QueueID, "executor failed", QueueOperationOptions{
		Now: func() time.Time { return failedAt },
	})
	if err != nil {
		t.Fatalf("MarkQueueEntryFailed() unexpected error: %v", err)
	}

	reloadedStore := NewStore(store.Root())
	reloaded, err := reloadedStore.LoadQueue()
	if err != nil {
		t.Fatalf("LoadQueue() after restart unexpected error: %v", err)
	}
	byQueueID := queueEntriesByID(reloaded)
	if !reflect.DeepEqual(byQueueID[claimed.QueueID], *claimed) {
		t.Fatalf("reloaded claimed entry = %#v, want %#v", byQueueID[claimed.QueueID], *claimed)
	}
	if !reflect.DeepEqual(byQueueID[failed.QueueID], failed) {
		t.Fatalf("reloaded failed entry = %#v, want %#v", byQueueID[failed.QueueID], failed)
	}
}

func testQueueEntry(queueID, runID string, createdAt time.Time) QueueEntry {
	return QueueEntry{
		QueueID:      queueID,
		RunID:        runID,
		ExecutorMode: ExecutorModeLocal,
		Status:       QueueStatusQueued,
		CreatedAt:    createdAt,
		AttemptCount: 0,
	}
}

func testQueueEntryWithStatus(queueID, runID, status string, createdAt time.Time) QueueEntry {
	entry := testQueueEntry(queueID, runID, createdAt)
	entry.Status = status
	return entry
}

func queueEntriesByID(entries []QueueEntry) map[string]QueueEntry {
	byQueueID := make(map[string]QueueEntry, len(entries))
	for _, entry := range entries {
		byQueueID[entry.QueueID] = entry
	}
	return byQueueID
}
