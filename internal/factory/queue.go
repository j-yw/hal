package factory

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const (
	queueFileName        = "queue.json"
	queueLockDirName     = "queue.lock"
	queueLockWaitTimeout = 5 * time.Second
	queueLockRetryDelay  = 10 * time.Millisecond
)

var saveQueueFile = saveStoreFile

// queueState is the durable on-disk representation of the local factory queue.
type queueState struct {
	Entries []QueueEntry `json:"entries"`
}

// QueueUpdateFunc applies a read-modify-write mutation to queue entries.
type QueueUpdateFunc func([]QueueEntry) ([]QueueEntry, error)

// QueuePath returns the committed queue state file path.
func (s Store) QueuePath() string {
	if s.root == "" {
		return ""
	}
	return filepath.Join(s.root, queueFileName)
}

// LoadQueue loads the committed queue state. A missing queue file is empty
// state and does not create global config directories.
func (s Store) LoadQueue() ([]QueueEntry, error) {
	return s.loadQueue()
}

// SaveQueue persists the queue state under Hal's global factory store.
func (s Store) SaveQueue(entries []QueueEntry) error {
	return s.withQueueLock(func() error {
		return s.saveQueue(entries)
	})
}

// UpdateQueue serializes a queue read-modify-write mutation under the local
// queue lock. Future queue commands should use this instead of separate
// LoadQueue and SaveQueue calls.
func (s Store) UpdateQueue(update QueueUpdateFunc) ([]QueueEntry, error) {
	if update == nil {
		return nil, fmt.Errorf("factory queue update function is required")
	}

	var updated []QueueEntry
	if err := s.withQueueLock(func() error {
		entries, err := s.loadQueue()
		if err != nil {
			return err
		}

		next, err := update(copyQueueEntries(entries))
		if err != nil {
			return err
		}
		if err := s.saveQueue(next); err != nil {
			return err
		}

		updated = copyQueueEntries(next)
		return nil
	}); err != nil {
		return nil, err
	}

	if updated == nil {
		return []QueueEntry{}, nil
	}
	return updated, nil
}

func (s Store) loadQueue() ([]QueueEntry, error) {
	path := s.QueuePath()
	if path == "" {
		return nil, errStoreDirUnavailable
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return []QueueEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read factory queue: %w", err)
	}

	var state queueState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse factory queue: %w", err)
	}
	if state.Entries == nil {
		return []QueueEntry{}, nil
	}

	return copyQueueEntries(state.Entries), nil
}

func (s Store) saveQueue(entries []QueueEntry) error {
	path := s.QueuePath()
	if path == "" {
		return errStoreDirUnavailable
	}

	state := queueState{Entries: copyQueueEntries(entries)}
	if state.Entries == nil {
		state.Entries = []QueueEntry{}
	}

	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory queue: %w", err)
	}
	data = append(data, '\n')

	tmpPath := path + storeTempFileExt
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("write factory queue: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("chmod factory queue: %w", err)
	}
	if err := saveQueueFile(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("save factory queue: %w", err)
	}

	return nil
}

func (s Store) queueLockPath() string {
	if s.root == "" {
		return ""
	}
	return filepath.Join(s.root, queueLockDirName)
}

func (s Store) withQueueLock(fn func() error) error {
	if fn == nil {
		return fmt.Errorf("factory queue lock function is required")
	}
	if err := s.Ensure(); err != nil {
		return err
	}

	release, err := acquireQueueLock(s.queueLockPath())
	if err != nil {
		return err
	}
	defer release()

	return fn()
}

func acquireQueueLock(path string) (func(), error) {
	if path == "" {
		return nil, errStoreDirUnavailable
	}

	deadline := time.Now().Add(queueLockWaitTimeout)
	for {
		err := os.Mkdir(path, 0o700)
		if err == nil {
			return func() {
				_ = os.Remove(path)
			}, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("acquire factory queue lock: %w", err)
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("acquire factory queue lock: %w", err)
		}
		time.Sleep(queueLockRetryDelay)
	}
}

func copyQueueEntries(entries []QueueEntry) []QueueEntry {
	if entries == nil {
		return nil
	}

	out := make([]QueueEntry, len(entries))
	copy(out, entries)
	for i := range out {
		if out[i].Claim == nil {
			continue
		}
		claim := *out[i].Claim
		out[i].Claim = &claim
	}
	return out
}
