package sandboxexecution

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	root      string
	lockScope *executionLockScope
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

// ResolveStoredPath returns the local filesystem path for a store-relative
// artifact payload that is already scoped to executionID.
func (s Store) ResolveStoredPath(executionID, storedPath string) (string, error) {
	file, err := s.OpenStoredFile(executionID, storedPath)
	if err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close sandbox execution stored payload")
	}
	clean, _ := validateStoreRelativePath(storedPath)
	return filepath.Join(s.root, filepath.FromSlash(clean)), nil
}

// OpenStoredFile opens a verified regular payload without following a final
// symlink. Callers should consume the returned descriptor rather than reopen
// the path after validation.
func (s Store) OpenStoredFile(executionID, storedPath string) (*os.File, error) {
	executionID, err := validateExecutionID(executionID)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(s.root) == "" {
		return nil, errStoreRootUnavailable
	}
	clean, err := validateStoreRelativePath(storedPath)
	if err != nil {
		return nil, fmt.Errorf("sandbox execution stored path is invalid: %w", err)
	}
	if clean == executionID || !strings.HasPrefix(clean, executionID+"/") {
		return nil, fmt.Errorf("sandbox execution stored path is not scoped under execution %q", executionID)
	}
	parts := strings.Split(clean, "/")
	if len(parts) < 3 || !validPayloadArea(parts[1]) {
		return nil, fmt.Errorf("sandbox execution stored path is not a payload")
	}
	return openVerifiedContainedPrivateRegularFile(s.root, parts, "sandbox execution stored payload")
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
		{name: "sandbox execution", path: executionDir},
		{name: "sandbox execution logs", path: filepath.Join(executionDir, logsDirName)},
		{name: "sandbox execution artifacts", path: filepath.Join(executionDir, artifactsDirName)},
		{name: "sandbox execution handoff", path: filepath.Join(executionDir, handoffDirName)},
		{name: "sandbox execution recovery", path: filepath.Join(executionDir, recoveryDirName)},
	}
	if err := ensurePrivateStoreRoot(s.root); err != nil {
		return err
	}
	// Validate every existing component before creating anything so an unsafe
	// partial layout is rejected without chmod, deletion, or additive mutation.
	for _, dir := range dirs {
		info, err := os.Lstat(dir.path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return filesystemUnavailable(dir.name, err)
		}
		if err := validatePrivateDirectoryInfo(info, dir.name); err != nil {
			return err
		}
	}
	for _, dir := range dirs {
		if err := ensurePrivateDirectory(dir.path, dir.name); err != nil {
			return err
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
	if err := validatePrivateStoreRoot(s.root); err != nil {
		return nil, err
	}
	if err := validatePrivateDirectory(filepath.Dir(path), "sandbox execution"); err != nil {
		return nil, err
	}
	manifest, err := loadManifestFile(s.root, executionID)
	if err == nil {
		return manifest, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("sandbox execution manifest %q does not exist: %w", executionID, err)
	}
	return nil, err
}

// AppendArtifactMetadata appends additive collection metadata to an existing
// execution manifest. It does not modify the legacy top-level artifacts array.
func (s Store) AppendArtifactMetadata(executionID string, metadata ArtifactMetadata) error {
	executionID, err := validateExecutionID(executionID)
	if err != nil {
		return err
	}
	if isArtifactMetadataEmpty(metadata) {
		return nil
	}

	return s.UpdateManifest(executionID, func(manifest *Manifest) error {
		if manifest.ArtifactMetadata == nil {
			manifest.ArtifactMetadata = &ArtifactMetadata{}
		}
		manifest.ArtifactMetadata.Collected = append(manifest.ArtifactMetadata.Collected, metadata.Collected...)
		manifest.ArtifactMetadata.Partial = append(manifest.ArtifactMetadata.Partial, metadata.Partial...)
		manifest.ArtifactMetadata.Warnings = append(manifest.ArtifactMetadata.Warnings, metadata.Warnings...)
		return nil
	})
}

// UpdateManifest atomically loads, mutates, validates, and saves one manifest
// while holding its per-execution OS lock.
func (s Store) UpdateManifest(executionID string, update func(*Manifest) error) error {
	executionID, err := validateExecutionID(executionID)
	if err != nil {
		return err
	}
	if update == nil {
		return fmt.Errorf("sandbox execution manifest update callback is required")
	}
	if s.lockScopeActive(executionID) {
		return s.updateManifestUnlocked(executionID, update)
	}
	return s.WithExecutionLock(executionID, func() error {
		return s.updateManifestUnlocked(executionID, update)
	})
}

func (s Store) updateManifestUnlocked(executionID string, update func(*Manifest) error) error {
	manifest, err := s.LoadManifest(executionID)
	if err != nil {
		return err
	}
	if manifest.ID != executionID {
		return fmt.Errorf("sandbox execution manifest %q has mismatched ID", executionID)
	}
	if err := update(manifest); err != nil {
		return err
	}
	if manifest.ID != executionID {
		return fmt.Errorf("sandbox execution manifest update changed ID")
	}
	return s.SaveManifest(manifest)
}

// UpsertArtifactMetadata merges retry-safe artifact metadata under the
// execution lock. Stable artifact identities replace retry entries in place
// while unrelated metadata and ordering are preserved.
func (s Store) UpsertArtifactMetadata(executionID string, metadata ArtifactMetadata) error {
	executionID, err := validateExecutionID(executionID)
	if err != nil {
		return err
	}
	if isArtifactMetadataEmpty(metadata) {
		return nil
	}
	if err := validateArtifactCollectionMetadata(executionID, &metadata); err != nil {
		return err
	}
	return s.UpdateManifest(executionID, func(manifest *Manifest) error {
		existing := ArtifactMetadata{}
		if manifest.ArtifactMetadata != nil {
			existing = *manifest.ArtifactMetadata
		}
		existing.Collected = upsertArtifactEntries(existing.Collected, metadata.Collected)
		existing.Partial = upsertArtifactEntries(existing.Partial, metadata.Partial)
		existing.Partial = removeCollectedArtifactEntries(existing.Partial, existing.Collected)
		existing.Warnings = upsertArtifactWarnings(existing.Warnings, metadata.Warnings)
		manifest.ArtifactMetadata = &existing
		return nil
	})
}

// ListManifests returns committed manifests sorted by started time, then ID.
func (s Store) ListManifests() ([]Manifest, error) {
	if strings.TrimSpace(s.root) == "" {
		return nil, errStoreRootUnavailable
	}
	if err := validatePrivateStoreRoot(s.root); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
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
		if entry.Type()&fs.ModeSymlink != 0 {
			if _, err := validateExecutionID(entry.Name()); err == nil {
				return nil, fmt.Errorf("sandbox execution is a symlink")
			}
			continue
		}
		if !entry.IsDir() {
			continue
		}
		executionID, err := validateExecutionID(entry.Name())
		if err != nil {
			continue
		}
		if err := validatePrivateDirectory(filepath.Join(s.root, executionID), "sandbox execution"); err != nil {
			return nil, err
		}
		manifest, err := loadManifestFile(s.root, executionID)
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
	if err := validatePrivateStoreRoot(s.root); err != nil {
		return err
	}
	if err := validatePrivateDirectory(executionDir, "sandbox execution"); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("sandbox execution %q does not exist: %w", executionID, fs.ErrNotExist)
		}
		return err
	}
	if err := os.RemoveAll(executionDir); err != nil {
		return fmt.Errorf("remove sandbox execution %q: %w", executionID, err)
	}
	return nil
}

func (s Store) executionDir(executionID string) (string, error) {
	executionID, err := validateExecutionID(executionID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(s.root) == "" {
		return "", errStoreRootUnavailable
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
	if err := validateWorkerJobReference(manifest.WorkerJob); err != nil {
		return err
	}
	if err := validateFinalizationMetadata(manifest.Finalization); err != nil {
		return err
	}
	for _, artifact := range manifest.Artifacts {
		if err := validateArtifactMetadata(manifest.ID, artifact); err != nil {
			return err
		}
	}
	if err := validateArtifactCollectionMetadata(manifest.ID, manifest.ArtifactMetadata); err != nil {
		return err
	}
	return nil
}

func isArtifactMetadataEmpty(metadata ArtifactMetadata) bool {
	return len(metadata.Collected) == 0 && len(metadata.Partial) == 0 && len(metadata.Warnings) == 0
}

func upsertArtifactEntries(existing, incoming []ArtifactMetadataEntry) []ArtifactMetadataEntry {
	merged := make([]ArtifactMetadataEntry, 0, len(existing)+len(incoming))
	indexes := make(map[string]int, len(existing)+len(incoming))
	for _, entry := range append(append([]ArtifactMetadataEntry(nil), existing...), incoming...) {
		key := artifactMetadataEntryStableKey(entry)
		if index, ok := indexes[key]; ok {
			merged[index] = entry
			continue
		}
		indexes[key] = len(merged)
		merged = append(merged, entry)
	}
	return merged
}

func upsertArtifactWarnings(existing, incoming []ArtifactWarning) []ArtifactWarning {
	merged := make([]ArtifactWarning, 0, len(existing)+len(incoming))
	indexes := make(map[string]int, len(existing)+len(incoming))
	for _, warning := range append(append([]ArtifactWarning(nil), existing...), incoming...) {
		key := strings.TrimSpace(warning.Phase) + "\x00" + artifactMetadataEntryStableKey(warning.Artifact)
		if index, ok := indexes[key]; ok {
			merged[index] = warning
			continue
		}
		indexes[key] = len(merged)
		merged = append(merged, warning)
	}
	return merged
}

func removeCollectedArtifactEntries(partial, collected []ArtifactMetadataEntry) []ArtifactMetadataEntry {
	collectedKeys := make(map[string]struct{}, len(collected))
	for _, entry := range collected {
		collectedKeys[artifactMetadataEntryStableKey(entry)] = struct{}{}
	}
	filtered := make([]ArtifactMetadataEntry, 0, len(partial))
	for _, entry := range partial {
		if _, collected := collectedKeys[artifactMetadataEntryStableKey(entry)]; collected {
			continue
		}
		filtered = append(filtered, entry)
	}
	return filtered
}

func artifactMetadataEntryStableKey(entry ArtifactMetadataEntry) string {
	if id := strings.TrimSpace(entry.ID); id != "" {
		return "id:" + id
	}
	return "path:" + entry.Path
}

func loadManifestFile(root, executionID string) (*Manifest, error) {
	file, err := openVerifiedContainedPrivateRegularFile(root, []string{executionID, manifestFileName}, "sandbox execution manifest")
	if err != nil {
		return nil, fmt.Errorf("read sandbox execution manifest %q: %w", executionID, err)
	}
	data, err := io.ReadAll(file)
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		return nil, fmt.Errorf("read sandbox execution manifest %q", executionID)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		if strings.Contains(err.Error(), "finalization") {
			return nil, fmt.Errorf("parse sandbox execution manifest %q: finalization metadata is invalid", executionID)
		}
		if strings.Contains(err.Error(), "workerJob") {
			return nil, fmt.Errorf("parse sandbox execution manifest %q: workerJob metadata is invalid", executionID)
		}
		return nil, fmt.Errorf("parse sandbox execution manifest %q: manifest JSON is invalid", executionID)
	}
	if err := validateManifestForSave(&manifest); err != nil {
		return nil, fmt.Errorf("sandbox execution manifest %q is invalid", executionID)
	}
	if manifest.ID != executionID {
		return nil, fmt.Errorf("sandbox execution manifest %q has mismatched ID", executionID)
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

func validateArtifactMetadata(executionID string, artifact Artifact) error {
	if artifact.Path != "" {
		if err := validateArtifactStoreRelativePath(executionID, artifact.Path); err != nil {
			return fmt.Errorf("sandbox execution artifact path %q is invalid: %w", artifact.Path, err)
		}
	}
	if artifact.StoredPath != "" {
		if err := validateArtifactStoreRelativePath(executionID, artifact.StoredPath); err != nil {
			return fmt.Errorf("sandbox execution artifact storedPath %q is invalid: %w", artifact.StoredPath, err)
		}
	}
	return nil
}

func validateArtifactCollectionMetadata(executionID string, metadata *ArtifactMetadata) error {
	if metadata == nil {
		return nil
	}
	for i, artifact := range metadata.Collected {
		if err := validateArtifactMetadataEntry(executionID, artifact, true); err != nil {
			return fmt.Errorf("sandbox execution artifact metadata collected[%d] is invalid: %w", i, err)
		}
	}
	for i, artifact := range metadata.Partial {
		if err := validateArtifactMetadataEntry(executionID, artifact, false); err != nil {
			return fmt.Errorf("sandbox execution artifact metadata partial[%d] is invalid: %w", i, err)
		}
	}
	for i, warning := range metadata.Warnings {
		if err := validateArtifactWarning(executionID, warning); err != nil {
			return fmt.Errorf("sandbox execution artifact metadata warnings[%d] is invalid: %w", i, err)
		}
	}
	return nil
}

func validateArtifactMetadataEntry(executionID string, artifact ArtifactMetadataEntry, requireStoredPath bool) error {
	if strings.TrimSpace(artifact.Path) == "" {
		return fmt.Errorf("artifact path is required")
	}
	if err := validateArtifactDisplayPath(artifact.Path); err != nil {
		return fmt.Errorf("artifact path %q is invalid: %w", artifact.Path, err)
	}
	if requireStoredPath && strings.TrimSpace(artifact.StoredPath) == "" {
		return fmt.Errorf("artifact storedPath is required")
	}
	if artifact.StoredPath != "" {
		if err := validateArtifactStoreRelativePath(executionID, artifact.StoredPath); err != nil {
			return fmt.Errorf("artifact storedPath %q is invalid: %w", artifact.StoredPath, err)
		}
	}
	return nil
}

func validateArtifactWarning(executionID string, warning ArtifactWarning) error {
	if strings.TrimSpace(warning.Phase) == "" {
		return fmt.Errorf("warning phase is required")
	}
	if strings.TrimSpace(warning.Phase) != warning.Phase {
		return fmt.Errorf("warning phase %q is invalid", warning.Phase)
	}
	if strings.TrimSpace(warning.Message) == "" {
		return fmt.Errorf("warning message is required")
	}
	if strings.TrimSpace(warning.Message) != warning.Message {
		return fmt.Errorf("warning message is invalid")
	}
	if err := validateArtifactMetadataEntry(executionID, warning.Artifact, false); err != nil {
		return fmt.Errorf("warning artifact is invalid: %w", err)
	}
	return nil
}

func validateArtifactDisplayPath(value string) error {
	_, err := validateStoreRelativePath(value)
	return err
}

func validateArtifactStoreRelativePath(executionID, value string) error {
	clean, err := validateStoreRelativePath(value)
	if err != nil {
		return err
	}
	if clean == executionID || !strings.HasPrefix(clean, executionID+"/") {
		return fmt.Errorf("must be scoped under execution %q", executionID)
	}
	return nil
}

func validateStoreRelativePath(value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("path is required")
	}
	if trimmed != value {
		return "", fmt.Errorf("path must not have leading or trailing whitespace")
	}
	if filepath.IsAbs(value) || pathpkg.IsAbs(value) {
		return "", fmt.Errorf("path must be relative")
	}
	if strings.Contains(value, "\\") {
		return "", fmt.Errorf("path must not contain backslash separators")
	}
	for _, part := range strings.Split(value, "/") {
		if part == ".." {
			return "", fmt.Errorf("path must not contain traversal")
		}
	}
	clean := pathpkg.Clean(value)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("path is invalid")
	}
	return clean, nil
}

func writeStoreFileAtomic(path string, data []byte, mode fs.FileMode) error {
	if err := validateOptionalPrivateRegularFile(path, "sandbox execution store file"); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+tempFileSuffix+"-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := renameStoreFile(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	removeTemp = false
	_, err = validatePrivateRegularFile(path, "sandbox execution store file")
	return err
}

func validPayloadArea(area string) bool {
	switch area {
	case logsDirName, artifactsDirName, handoffDirName, recoveryDirName:
		return true
	default:
		return false
	}
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
