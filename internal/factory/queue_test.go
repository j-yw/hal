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
