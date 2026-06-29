package sandboxexecution

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
)

const (
	storeDirName     = "sandbox-executions"
	manifestFileName = "manifest.json"
	tempFileSuffix   = ".tmp"
	backupFileSuffix = ".bak"
	logsDirName      = "logs"
	artifactsDirName = "artifacts"
	handoffDirName   = "handoff"
	recoveryDirName  = "recovery"
)

var errStoreRootUnavailable = errors.New("no sandbox execution store root available")

// Store addresses durable local non-factory sandbox execution records.
type Store struct {
	root string
}

// NewStore returns a store rooted at root. Tests use this to operate in temp
// directories without touching the user's global Hal state.
func NewStore(root string) Store {
	return Store{root: root}
}

// DefaultStore returns a store rooted under Hal's global sandbox directory.
func DefaultStore() (Store, error) {
	root := StoreDir()
	if root == "" {
		return Store{}, errStoreRootUnavailable
	}
	return NewStore(root), nil
}

// StoreDir returns the default non-factory sandbox execution store directory.
func StoreDir() string {
	globalDir := sandbox.GlobalDir()
	if globalDir == "" {
		return ""
	}
	return filepath.Join(globalDir, storeDirName)
}

// Root returns the local filesystem root for this store.
func (s Store) Root() string {
	return s.root
}

// Ensure creates the store root, execution directory, and known payload
// subdirectories for executionID.
func (s Store) Ensure(executionID string) error {
	executionID, err := validateExecutionID(executionID)
	if err != nil {
		return err
	}
	executionDir, err := s.executionDir(executionID)
	if err != nil {
		return err
	}

	dirs := []struct {
		name string
		path string
	}{
		{name: "sandbox execution store", path: s.root},
		{name: "sandbox execution", path: executionDir},
		{name: "sandbox execution logs", path: filepath.Join(executionDir, logsDirName)},
		{name: "sandbox execution artifacts", path: filepath.Join(executionDir, artifactsDirName)},
		{name: "sandbox execution handoff", path: filepath.Join(executionDir, handoffDirName)},
		{name: "sandbox execution recovery", path: filepath.Join(executionDir, recoveryDirName)},
	}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir.path, 0o700); err != nil {
			return fmt.Errorf("create %s dir: %w", dir.name, err)
		}
	}
	return nil
}

// ManifestPath returns the absolute path for an execution's manifest.
func (s Store) ManifestPath(executionID string) (string, error) {
	executionDir, err := s.executionDir(executionID)
	if err != nil {
		return "", err
	}
	return filepath.Join(executionDir, manifestFileName), nil
}

// SaveManifest atomically persists manifest as manifest.json under its
// execution directory.
func (s Store) SaveManifest(manifest *Manifest) error {
	if err := validateManifestForSave(manifest); err != nil {
		return err
	}
	path, err := s.ManifestPath(manifest.ID)
	if err != nil {
		return err
	}
	if err := s.Ensure(manifest.ID); err != nil {
		return err
	}

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal sandbox execution manifest %q: %w", manifest.ID, err)
	}
	data = append(data, '\n')

	if err := writeStoreFileAtomic(path, data, 0o600); err != nil {
		return fmt.Errorf("save sandbox execution manifest %q: %w", manifest.ID, err)
	}
	return nil
}

// LoadManifest loads a committed manifest by execution ID.
func (s Store) LoadManifest(executionID string) (*Manifest, error) {
	path, err := s.ManifestPath(executionID)
	if err != nil {
		return nil, err
	}
	manifest, err := loadManifestFile(path, executionID)
	if err == nil {
		return manifest, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("sandbox execution manifest %q does not exist: %w", executionID, err)
	}
	return nil, err
}

// ListManifests returns committed manifests sorted by started time, then ID.
func (s Store) ListManifests() ([]Manifest, error) {
	if strings.TrimSpace(s.root) == "" {
		return nil, errStoreRootUnavailable
	}
	entries, err := os.ReadDir(s.root)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read sandbox execution store: %w", err)
	}

	manifests := make([]Manifest, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		executionID, err := validateExecutionID(entry.Name())
		if err != nil {
			continue
		}
		path := filepath.Join(s.root, executionID, manifestFileName)
		manifest, err := loadManifestFile(path, executionID)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		manifests = append(manifests, *manifest)
	}

	sort.Slice(manifests, func(i, j int) bool {
		if !manifests[i].StartedAt.Equal(manifests[j].StartedAt) {
			return manifests[i].StartedAt.Before(manifests[j].StartedAt)
		}
		return manifests[i].ID < manifests[j].ID
	})

	return manifests, nil
}

// Remove removes one execution directory and all locally stored payloads.
func (s Store) Remove(executionID string) error {
	executionDir, err := s.executionDir(executionID)
	if err != nil {
		return err
	}
	info, err := os.Lstat(executionDir)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("sandbox execution %q does not exist: %w", executionID, err)
	}
	if err != nil {
		return fmt.Errorf("stat sandbox execution %q: %w", executionID, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("sandbox execution %q is not a directory", executionID)
	}
	if err := os.RemoveAll(executionDir); err != nil {
		return fmt.Errorf("remove sandbox execution %q: %w", executionID, err)
	}
	return nil
}

func (s Store) executionDir(executionID string) (string, error) {
	if strings.TrimSpace(s.root) == "" {
		return "", errStoreRootUnavailable
	}
	executionID, err := validateExecutionID(executionID)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.root, executionID), nil
}

func validateManifestForSave(manifest *Manifest) error {
	if manifest == nil {
		return fmt.Errorf("sandbox execution manifest is required")
	}
	if _, err := validateExecutionID(manifest.ID); err != nil {
		return err
	}
	if !validPurpose(manifest.Purpose) {
		return fmt.Errorf("sandbox execution purpose %q is invalid", manifest.Purpose)
	}
	if !validStatus(manifest.Status) {
		return fmt.Errorf("sandbox execution status %q is invalid", manifest.Status)
	}
	if manifest.StartedAt.IsZero() {
		return fmt.Errorf("sandbox execution startedAt is required")
	}
	return nil
}

func loadManifestFile(path, executionID string) (*Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sandbox execution manifest %q: %w", executionID, err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parse sandbox execution manifest %q: %w", executionID, err)
	}
	return &manifest, nil
}

func validateExecutionID(executionID string) (string, error) {
	trimmed := strings.TrimSpace(executionID)
	if trimmed == "" {
		return "", fmt.Errorf("sandbox execution ID is required")
	}
	if trimmed != executionID {
		return "", fmt.Errorf("sandbox execution ID %q is invalid", executionID)
	}
	if filepath.IsAbs(executionID) || pathpkg.IsAbs(executionID) {
		return "", fmt.Errorf("sandbox execution ID %q is invalid", executionID)
	}
	clean := filepath.Clean(executionID)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("sandbox execution ID %q is invalid", executionID)
	}
	if strings.Contains(executionID, "/") || strings.Contains(executionID, "\\") {
		return "", fmt.Errorf("sandbox execution ID %q must not contain path separators", executionID)
	}
	return executionID, nil
}

func writeStoreFileAtomic(path string, data []byte, mode fs.FileMode) error {
	tmpPath := path + tempFileSuffix
	if err := os.WriteFile(tmpPath, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, mode); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := renameStoreFile(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func renameStoreFile(tmpPath, path string) error {
	if err := os.Rename(tmpPath, path); err == nil {
		return nil
	} else if !isRenameNoReplaceError(err) {
		return err
	}

	backupPath := path + backupFileSuffix
	if err := os.Remove(backupPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := os.Rename(path, backupPath); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if restoreErr := os.Rename(backupPath, path); restoreErr != nil {
			return fmt.Errorf("%w (restore failed: %v)", err, restoreErr)
		}
		return err
	}
	_ = os.Remove(backupPath)
	return nil
}

func isRenameNoReplaceError(err error) bool {
	return errors.Is(err, fs.ErrExist) || os.IsExist(err)
}
