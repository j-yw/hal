package factory

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const queueFileName = "queue.json"

// queueState is the durable on-disk representation of the local factory queue.
type queueState struct {
	Entries []QueueEntry `json:"entries"`
}

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

	return state.Entries, nil
}

// SaveQueue persists the queue state under Hal's global factory store.
func (s Store) SaveQueue(entries []QueueEntry) error {
	path := s.QueuePath()
	if path == "" {
		return errStoreDirUnavailable
	}
	if err := s.Ensure(); err != nil {
		return err
	}

	state := queueState{Entries: append([]QueueEntry(nil), entries...)}
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
	if err := saveStoreFile(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("save factory queue: %w", err)
	}

	return nil
}
