package factory

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
)

const (
	factoryStoreDirName = "factory"
	runsDirName         = "runs"
	timelinesDirName    = "timelines"
	runRecordFileExt    = ".json"
)

var errStoreDirUnavailable = errors.New("no global hal config home found")

// Store addresses durable factory state under Hal's global config directory.
type Store struct {
	root string
}

// NewStore returns a store rooted at root. Tests and future migration helpers
// can use this to operate on isolated directories.
func NewStore(root string) Store {
	return Store{root: root}
}

// DefaultStore returns the factory store rooted under Hal's global config dir.
func DefaultStore() (Store, error) {
	root, err := defaultStoreRoot()
	if err != nil {
		return Store{}, err
	}
	return NewStore(root), nil
}

// StoreDir returns the default factory store directory, or an empty string when
// no global Hal config directory can be resolved.
func StoreDir() string {
	root, err := defaultStoreRoot()
	if err != nil {
		return ""
	}
	return root
}

// EnsureStoreDir creates the default factory store directories.
func EnsureStoreDir() error {
	store, err := DefaultStore()
	if err != nil {
		return err
	}
	return store.Ensure()
}

// Root returns the root directory for this store.
func (s Store) Root() string {
	return s.root
}

// RunsDir returns the directory containing committed run records.
func (s Store) RunsDir() string {
	if s.root == "" {
		return ""
	}
	return filepath.Join(s.root, runsDirName)
}

// TimelinesDir returns the directory containing committed event timelines.
func (s Store) TimelinesDir() string {
	if s.root == "" {
		return ""
	}
	return filepath.Join(s.root, timelinesDirName)
}

// Ensure creates the store root and known subdirectories using restrictive
// permissions consistent with the global sandbox registry.
func (s Store) Ensure() error {
	if strings.TrimSpace(s.root) == "" {
		return errStoreDirUnavailable
	}

	dirs := []struct {
		name string
		path string
	}{
		{name: "factory store", path: s.root},
		{name: "factory runs", path: s.RunsDir()},
		{name: "factory timelines", path: s.TimelinesDir()},
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir.path, 0o700); err != nil {
			return fmt.Errorf("create %s dir: %w", dir.name, err)
		}
	}
	return nil
}

// ListRunIDs returns known run IDs in deterministic order. Missing store
// directories are empty state so read-only callers do not create global files.
func (s Store) ListRunIDs() ([]string, error) {
	runsDir := s.RunsDir()
	if runsDir == "" {
		return nil, errStoreDirUnavailable
	}

	entries, err := os.ReadDir(runsDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read factory runs dir: %w", err)
	}

	runIDs := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			runIDs = append(runIDs, entry.Name())
			continue
		}
		if filepath.Ext(entry.Name()) != runRecordFileExt {
			continue
		}
		runIDs = append(runIDs, strings.TrimSuffix(entry.Name(), runRecordFileExt))
	}

	sort.Strings(runIDs)
	return runIDs, nil
}

func defaultStoreRoot() (string, error) {
	globalDir := sandbox.GlobalDir()
	if globalDir == "" {
		return "", errStoreDirUnavailable
	}
	return filepath.Join(globalDir, factoryStoreDirName), nil
}
