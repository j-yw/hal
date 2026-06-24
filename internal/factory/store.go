package factory

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/sandbox"
)

const (
	factoryStoreDirName = "factory"
	runsDirName         = "runs"
	timelinesDirName    = "timelines"
	artifactsDirName    = "artifacts"
	runRecordFileExt    = ".json"
	storeTempFileExt    = ".tmp"
	storeLockFileExt    = ".lock"
	storeBackupFileExt  = ".bak"

	artifactFileNameMaxLength    = 240
	artifactFileNameHashBytes    = 6
	artifactFileNameMaxExtLength = 64
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

// ArtifactsDir returns the directory containing stored artifact payloads.
func (s Store) ArtifactsDir() string {
	if s.root == "" {
		return ""
	}
	return filepath.Join(s.root, artifactsDirName)
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
		{name: "factory artifacts", path: s.ArtifactsDir()},
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir.path, 0o700); err != nil {
			return fmt.Errorf("create %s dir: %w", dir.name, err)
		}
	}
	return nil
}

// SaveArtifactFile copies a source file into this store and records the stored
// artifact metadata on the run record. The stored path is deterministic and
// scoped under artifacts/<run-id>/.
func (s Store) SaveArtifactFile(runID string, artifact ArtifactReference, sourcePath string) (ArtifactReference, error) {
	runID, err := validateRunID(runID)
	if err != nil {
		return ArtifactReference{}, err
	}
	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return ArtifactReference{}, fmt.Errorf("artifact source path is required")
	}

	record, err := s.LoadRun(runID)
	if err != nil {
		return ArtifactReference{}, err
	}
	if err := s.Ensure(); err != nil {
		return ArtifactReference{}, err
	}

	info, err := os.Lstat(sourcePath)
	if err != nil {
		return ArtifactReference{}, fmt.Errorf("stat artifact source %q: %w", sourcePath, err)
	}
	if info.IsDir() {
		return ArtifactReference{}, fmt.Errorf("artifact source %q is a directory", sourcePath)
	}
	if info.Mode()&fs.ModeSymlink != 0 {
		return ArtifactReference{}, fmt.Errorf("artifact source %q is a symlink", sourcePath)
	}
	if !info.Mode().IsRegular() {
		return ArtifactReference{}, fmt.Errorf("artifact source %q is not a regular file", sourcePath)
	}

	artifact.Name = strings.TrimSpace(artifact.Name)
	artifact.Type = strings.TrimSpace(artifact.Type)
	if artifact.Name == "" {
		return ArtifactReference{}, fmt.Errorf("artifact name is required")
	}
	if artifact.Type == "" {
		return ArtifactReference{}, fmt.Errorf("artifact type is required")
	}

	storedPath := filepath.ToSlash(filepath.Join(artifactsDirName, runID, artifactFileName(artifactFileBaseName(artifact), sourcePath)))
	absoluteStoredPath, err := s.ResolveArtifactPath(runID, storedPath)
	if err != nil {
		return ArtifactReference{}, err
	}
	if err := ensureStoreDirectory(s.root, filepath.Dir(absoluteStoredPath), 0o700); err != nil {
		return ArtifactReference{}, fmt.Errorf("create factory artifact dir: %w", err)
	}
	copiedInfo, err := copyStoreFile(sourcePath, absoluteStoredPath, 0o600, info)
	if err != nil {
		return ArtifactReference{}, fmt.Errorf("write factory artifact %q: %w", artifact.Name, err)
	}

	size := copiedInfo.Size()
	createdAt := copiedInfo.ModTime().UTC()
	artifact.SourcePath = sourcePath
	artifact.StoredPath = storedPath
	artifact.SizeBytes = &size
	artifact.CreatedAt = &createdAt

	record.Artifacts = upsertArtifact(record.Artifacts, artifact)
	if err := s.SaveRun(record); err != nil {
		return ArtifactReference{}, fmt.Errorf("save factory artifact metadata %q: %w", artifact.Name, err)
	}

	return artifact, nil
}

// ResolveArtifactPath resolves a stored artifact path to an absolute local path
// and rejects paths outside artifacts/<run-id>/.
func (s Store) ResolveArtifactPath(runID, storedPath string) (string, error) {
	if strings.TrimSpace(s.root) == "" {
		return "", errStoreDirUnavailable
	}
	runID, err := validateRunID(runID)
	if err != nil {
		return "", err
	}
	storedPath = strings.TrimSpace(storedPath)
	if storedPath == "" {
		return "", fmt.Errorf("factory artifact stored path is required")
	}
	if filepath.IsAbs(storedPath) || strings.ContainsAny(storedPath, `\`) {
		return "", fmt.Errorf("factory artifact stored path %q is invalid", storedPath)
	}

	cleanStoredPath := filepath.Clean(filepath.FromSlash(storedPath))
	runPrefix := filepath.Join(artifactsDirName, runID)
	if cleanStoredPath == "." || cleanStoredPath == runPrefix || !strings.HasPrefix(cleanStoredPath, runPrefix+string(filepath.Separator)) {
		return "", fmt.Errorf("factory artifact stored path %q is outside run %q", storedPath, runID)
	}

	return filepath.Join(s.root, cleanStoredPath), nil
}

// SaveRun persists a factory run record by its stable run ID.
func (s Store) SaveRun(record *RunRecord) error {
	if record == nil {
		return fmt.Errorf("factory run record is required")
	}

	path, err := s.runRecordPath(record.RunID)
	if err != nil {
		return err
	}
	if err := s.Ensure(); err != nil {
		return err
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory run %q: %w", record.RunID, err)
	}
	data = append(data, '\n')

	tmpPath, err := writeStoreTempFile(path, data)
	if err != nil {
		return fmt.Errorf("write factory run %q: %w", record.RunID, err)
	}
	if err := saveStoreFile(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("save factory run %q: %w", record.RunID, err)
	}

	return nil
}

// LoadRun loads a committed factory run record by run ID.
func (s Store) LoadRun(runID string) (*RunRecord, error) {
	path, err := s.runRecordPath(runID)
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("factory run %q does not exist: %w", runID, err)
	}
	if err != nil {
		return nil, fmt.Errorf("read factory run %q: %w", runID, err)
	}

	var record RunRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return nil, fmt.Errorf("parse factory run %q: %w", runID, err)
	}

	return &record, nil
}

// AppendEvent durably appends an event to a run's timeline.
func (s Store) AppendEvent(event *EventRecord) error {
	if event == nil {
		return fmt.Errorf("factory event record is required")
	}

	path, err := s.timelinePath(event.RunID)
	if err != nil {
		return err
	}
	if err := s.Ensure(); err != nil {
		return err
	}

	lock, err := lockStoreFile(path + storeLockFileExt)
	if err != nil {
		return fmt.Errorf("lock factory timeline %q: %w", event.RunID, err)
	}
	defer func() {
		_ = lock.Close()
	}()

	events, err := s.loadEvents(event.RunID, path)
	if err != nil {
		return err
	}
	events = append(events, *event)

	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal factory timeline %q: %w", event.RunID, err)
	}
	data = append(data, '\n')

	tmpPath, err := writeStoreTempFile(path, data)
	if err != nil {
		return fmt.Errorf("write factory timeline %q: %w", event.RunID, err)
	}
	if err := saveStoreFile(tmpPath, path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("save factory timeline %q: %w", event.RunID, err)
	}

	return nil
}

// LoadEvents loads a run's committed timeline events in append order.
func (s Store) LoadEvents(runID string) ([]EventRecord, error) {
	path, err := s.timelinePath(runID)
	if err != nil {
		return nil, err
	}
	return s.loadEvents(runID, path)
}

// ListRuns returns committed run records ordered newest-first by their latest
// creation or update timestamp, with run ID as a stable tie-breaker.
func (s Store) ListRuns() ([]RunRecord, error) {
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

	records := make([]RunRecord, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isCommittedStoreFile(entry.Name()) {
			continue
		}

		runID := strings.TrimSuffix(entry.Name(), runRecordFileExt)
		record, err := s.LoadRun(runID)
		if err != nil {
			return nil, err
		}
		records = append(records, *record)
	}

	sort.Slice(records, func(i, j int) bool {
		leftTime := runRecordListTimestamp(records[i])
		rightTime := runRecordListTimestamp(records[j])
		if !leftTime.Equal(rightTime) {
			return leftTime.After(rightTime)
		}
		return records[i].RunID < records[j].RunID
	})

	return records, nil
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
		if entry.IsDir() || !isCommittedStoreFile(entry.Name()) {
			continue
		}
		runIDs = append(runIDs, strings.TrimSuffix(entry.Name(), runRecordFileExt))
	}

	sort.Strings(runIDs)
	return runIDs, nil
}

func (s Store) runRecordPath(runID string) (string, error) {
	runsDir := s.RunsDir()
	if runsDir == "" {
		return "", errStoreDirUnavailable
	}

	runID, err := validateRunID(runID)
	if err != nil {
		return "", err
	}

	return filepath.Join(runsDir, runID+runRecordFileExt), nil
}

func (s Store) timelinePath(runID string) (string, error) {
	timelinesDir := s.TimelinesDir()
	if timelinesDir == "" {
		return "", errStoreDirUnavailable
	}

	runID, err := validateRunID(runID)
	if err != nil {
		return "", err
	}

	return filepath.Join(timelinesDir, runID+runRecordFileExt), nil
}

func validateRunID(runID string) (string, error) {
	trimmedRunID := strings.TrimSpace(runID)
	if trimmedRunID == "" {
		return "", fmt.Errorf("factory run ID is required")
	}
	if runID != trimmedRunID {
		return "", fmt.Errorf("factory run ID %q is invalid", runID)
	}
	runID = trimmedRunID
	if runID == "." || runID == ".." || strings.ContainsAny(runID, `/\`) {
		return "", fmt.Errorf("factory run ID %q is invalid", runID)
	}

	return runID, nil
}

func (s Store) loadEvents(runID, path string) ([]EventRecord, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read factory timeline %q: %w", runID, err)
	}

	var events []EventRecord
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, fmt.Errorf("parse factory timeline %q: %w", runID, err)
	}

	return events, nil
}

func runRecordListTimestamp(record RunRecord) time.Time {
	timestamp := record.CreatedAt
	if record.UpdatedAt.After(timestamp) {
		timestamp = record.UpdatedAt
	}
	return timestamp
}

func isCommittedStoreFile(name string) bool {
	if strings.HasSuffix(name, storeTempFileExt) || strings.HasSuffix(name, storeBackupFileExt) {
		return false
	}
	return filepath.Ext(name) == runRecordFileExt
}

func writeStoreTempFile(path string, data []byte) (string, error) {
	tmpFile, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*"+storeTempFileExt)
	if err != nil {
		return "", err
	}
	tmpPath := tmpFile.Name()

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return "", err
	}
	if err := tmpFile.Chmod(0o600); err != nil {
		_ = tmpFile.Close()
		return "", err
	}
	if err := tmpFile.Close(); err != nil {
		return "", err
	}

	cleanup = false
	return tmpPath, nil
}

func ensureStoreDirectory(root, dir string, mode fs.FileMode) error {
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absRoot, absDir)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("store directory %q is outside store root %q", dir, root)
	}

	current := absRoot
	for _, part := range strings.Split(rel, string(filepath.Separator)) {
		if part == "" || part == "." {
			continue
		}
		current = filepath.Join(current, part)
		for {
			info, err := os.Lstat(current)
			if err == nil {
				if info.Mode()&fs.ModeSymlink != 0 {
					return fmt.Errorf("store directory %q is a symlink", current)
				}
				if !info.IsDir() {
					return fmt.Errorf("store path %q is not a directory", current)
				}
				break
			}
			if !errors.Is(err, fs.ErrNotExist) {
				return err
			}
			if err := os.Mkdir(current, mode); err != nil {
				if errors.Is(err, fs.ErrExist) || os.IsExist(err) {
					continue
				}
				return err
			}
			break
		}
	}
	return nil
}

func saveStoreFile(tmpPath, path string) error {
	if err := os.Rename(tmpPath, path); err == nil {
		return nil
	} else if !isStoreRenameNoReplaceError(err) {
		return err
	}

	backupPath := path + storeBackupFileExt
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

func isStoreRenameNoReplaceError(err error) bool {
	return errors.Is(err, fs.ErrExist) || os.IsExist(err)
}

func copyStoreFile(sourcePath, destPath string, mode fs.FileMode, expectedInfo fs.FileInfo) (fs.FileInfo, error) {
	source, err := os.Open(sourcePath)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	sourceInfo, err := source.Stat()
	if err != nil {
		return nil, err
	}
	if !sourceInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("artifact source %q is not a regular file", sourcePath)
	}
	if expectedInfo != nil && !os.SameFile(expectedInfo, sourceInfo) {
		return nil, fmt.Errorf("artifact source %q changed during copy", sourcePath)
	}

	dest, err := os.CreateTemp(filepath.Dir(destPath), ".artifact-*"+storeTempFileExt)
	if err != nil {
		return nil, err
	}
	tmpPath := dest.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := io.Copy(dest, source); err != nil {
		_ = dest.Close()
		return nil, err
	}
	if err := dest.Chmod(mode); err != nil {
		_ = dest.Close()
		return nil, err
	}
	if err := dest.Close(); err != nil {
		return nil, err
	}
	if err := saveStoreFile(tmpPath, destPath); err != nil {
		return nil, err
	}
	cleanup = false
	return sourceInfo, nil
}

func artifactFileName(name, sourcePath string) string {
	name = strings.Trim(sanitizeArtifactPathComponent(name), ".")
	if name == "" {
		name = "artifact"
	}
	ext := filepath.Ext(sourcePath)
	if ext != "" && filepath.Ext(name) == "" {
		name += ext
	}
	if len(name) > artifactFileNameMaxLength {
		name = cappedArtifactFileName(name)
	}
	return name
}

func cappedArtifactFileName(name string) string {
	originalExt := filepath.Ext(name)
	if originalExt == name {
		originalExt = ""
	}
	base := strings.TrimSuffix(name, originalExt)
	ext := originalExt
	if len(ext) > artifactFileNameMaxExtLength {
		ext = ext[:artifactFileNameMaxExtLength]
	}

	hash := artifactFileNameHash(name)
	suffix := "-" + hash + ext
	maxBaseLength := artifactFileNameMaxLength - len(suffix)
	if maxBaseLength < 1 {
		ext = ""
		suffix = "-" + hash
		maxBaseLength = artifactFileNameMaxLength - len(suffix)
	}

	if len(base) > maxBaseLength {
		base = base[:maxBaseLength]
	}
	base = strings.Trim(base, ".-")
	if base == "" {
		base = "artifact"
		if len(base) > maxBaseLength {
			base = base[:maxBaseLength]
		}
	}

	return base + suffix
}

func artifactFileNameHash(name string) string {
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%x", sum[:artifactFileNameHashBytes])
}

func artifactFileBaseName(artifact ArtifactReference) string {
	if name := strings.TrimSpace(artifact.ID); name != "" {
		return name
	}
	return artifact.Name
}

func sanitizeArtifactPathComponent(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	var builder strings.Builder
	lastHyphen := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '.' || r == '_' {
			builder.WriteRune(r)
			lastHyphen = false
			continue
		}
		if !lastHyphen {
			builder.WriteByte('-')
			lastHyphen = true
		}
	}
	return strings.Trim(builder.String(), "-")
}

func upsertArtifact(artifacts []ArtifactReference, artifact ArtifactReference) []ArtifactReference {
	for i := range artifacts {
		if artifact.ID != "" && artifacts[i].ID == artifact.ID {
			artifacts[i] = artifact
			return artifacts
		}
		if artifact.StoredPath != "" && artifacts[i].StoredPath == artifact.StoredPath {
			artifacts[i] = artifact
			return artifacts
		}
	}
	return append(artifacts, artifact)
}

func defaultStoreRoot() (string, error) {
	globalDir := sandbox.GlobalDir()
	if globalDir == "" {
		return "", errStoreDirUnavailable
	}
	return filepath.Join(globalDir, factoryStoreDirName), nil
}
