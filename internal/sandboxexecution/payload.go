package sandboxexecution

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"time"
)

// StoredFile describes a payload persisted under the execution store.
type StoredFile struct {
	Path      string    `json:"path"`
	SizeBytes int64     `json:"sizeBytes"`
	CreatedAt time.Time `json:"createdAt"`
}

// WriteLog writes a payload under an execution's logs directory.
func (s Store) WriteLog(executionID, payloadPath string, data []byte) (StoredFile, error) {
	return s.writePayload(executionID, logsDirName, payloadPath, data)
}

// WriteArtifactPayload writes a payload under an execution's artifacts
// directory without updating manifest artifact metadata.
func (s Store) WriteArtifactPayload(executionID, payloadPath string, data []byte) (StoredFile, error) {
	return s.writePayload(executionID, artifactsDirName, payloadPath, data)
}

// WriteHandoff writes a payload under an execution's handoff directory.
func (s Store) WriteHandoff(executionID, payloadPath string, data []byte) (StoredFile, error) {
	return s.writePayload(executionID, handoffDirName, payloadPath, data)
}

// WriteRecovery writes a payload under an execution's recovery directory.
func (s Store) WriteRecovery(executionID, payloadPath string, data []byte) (StoredFile, error) {
	return s.writePayload(executionID, recoveryDirName, payloadPath, data)
}

// CopyLog copies a regular source file under an execution's logs directory.
func (s Store) CopyLog(executionID, payloadPath, sourcePath string) (StoredFile, error) {
	return s.copyPayload(executionID, logsDirName, payloadPath, sourcePath)
}

// CopyArtifactPayload copies a regular source file under an execution's
// artifacts directory without updating manifest artifact metadata.
func (s Store) CopyArtifactPayload(executionID, payloadPath, sourcePath string) (StoredFile, error) {
	return s.copyPayload(executionID, artifactsDirName, payloadPath, sourcePath)
}

// SaveArtifactFile copies a regular source file under an execution's artifacts
// directory and returns collection metadata with a caller-facing display path
// plus a store-relative stored path. It does not update the manifest.
func (s Store) SaveArtifactFile(executionID string, artifact ArtifactMetadataEntry, payloadPath, sourcePath string) (ArtifactMetadataEntry, error) {
	return s.saveMetadataFile(executionID, artifactsDirName, "save sandbox execution artifact payload", artifact, payloadPath, sourcePath)
}

// SaveHandoffFile copies a regular source file under an execution's handoff
// directory and returns collection metadata with a caller-facing display path
// plus a store-relative stored path. It does not update the manifest.
func (s Store) SaveHandoffFile(executionID string, artifact ArtifactMetadataEntry, payloadPath, sourcePath string) (ArtifactMetadataEntry, error) {
	return s.saveMetadataFile(executionID, handoffDirName, "save sandbox execution handoff payload", artifact, payloadPath, sourcePath)
}

// SaveRecoveryFile copies a regular source file under an execution's recovery
// directory and returns collection metadata with a caller-facing display path
// plus a store-relative stored path. It does not update the manifest.
func (s Store) SaveRecoveryFile(executionID string, artifact ArtifactMetadataEntry, payloadPath, sourcePath string) (ArtifactMetadataEntry, error) {
	return s.saveMetadataFile(executionID, recoveryDirName, "save sandbox execution recovery payload", artifact, payloadPath, sourcePath)
}

func (s Store) saveMetadataFile(executionID, area, operation string, artifact ArtifactMetadataEntry, payloadPath, sourcePath string) (ArtifactMetadataEntry, error) {
	executionID, err := validateExecutionID(executionID)
	if err != nil {
		return ArtifactMetadataEntry{}, err
	}
	if err := validateArtifactFileMetadataInput(artifact); err != nil {
		return ArtifactMetadataEntry{}, err
	}
	if _, _, err := s.payloadPath(executionID, area, payloadPath); err != nil {
		return ArtifactMetadataEntry{}, err
	}

	stored, err := s.copyPayloadRedactingSourcePath(executionID, area, payloadPath, sourcePath)
	if err != nil {
		return ArtifactMetadataEntry{}, fmt.Errorf("%s: %w", operation, err)
	}
	artifact = artifactMetadataWithStoredFile(artifact, stored)
	if err := validateArtifactMetadataEntry(executionID, artifact, true); err != nil {
		return ArtifactMetadataEntry{}, err
	}
	return artifact, nil
}

// CopyHandoff copies a regular source file under an execution's handoff
// directory.
func (s Store) CopyHandoff(executionID, payloadPath, sourcePath string) (StoredFile, error) {
	return s.copyPayload(executionID, handoffDirName, payloadPath, sourcePath)
}

// CopyRecovery copies a regular source file under an execution's recovery
// directory.
func (s Store) CopyRecovery(executionID, payloadPath, sourcePath string) (StoredFile, error) {
	return s.copyPayload(executionID, recoveryDirName, payloadPath, sourcePath)
}

// SaveArtifact writes an artifact payload and upserts its metadata into the
// execution manifest by artifact ID.
func (s Store) SaveArtifact(executionID string, artifact Artifact, payloadPath string, data []byte) (Artifact, error) {
	executionID, err := validateExecutionID(executionID)
	if err != nil {
		return Artifact{}, err
	}
	if err := validateArtifactForSave(artifact); err != nil {
		return Artifact{}, err
	}
	if _, _, err := s.payloadPath(executionID, artifactsDirName, payloadPath); err != nil {
		return Artifact{}, err
	}

	manifest, err := s.LoadManifest(executionID)
	if err != nil {
		return Artifact{}, err
	}
	if manifest.ID != executionID {
		return Artifact{}, fmt.Errorf("sandbox execution manifest %q has ID %q", executionID, manifest.ID)
	}
	if err := validateManifestForSave(manifest); err != nil {
		return Artifact{}, err
	}

	stored, err := s.WriteArtifactPayload(executionID, payloadPath, data)
	if err != nil {
		return Artifact{}, err
	}
	artifact = artifactWithStoredFile(artifact, stored)
	manifest.Artifacts = upsertArtifact(manifest.Artifacts, artifact)
	if err := s.SaveManifest(manifest); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

// CopyArtifact copies a regular source file into artifact storage and upserts
// its metadata into the execution manifest by artifact ID.
func (s Store) CopyArtifact(executionID string, artifact Artifact, payloadPath, sourcePath string) (Artifact, error) {
	executionID, err := validateExecutionID(executionID)
	if err != nil {
		return Artifact{}, err
	}
	if err := validateArtifactForSave(artifact); err != nil {
		return Artifact{}, err
	}
	if _, _, err := s.payloadPath(executionID, artifactsDirName, payloadPath); err != nil {
		return Artifact{}, err
	}

	manifest, err := s.LoadManifest(executionID)
	if err != nil {
		return Artifact{}, err
	}
	if manifest.ID != executionID {
		return Artifact{}, fmt.Errorf("sandbox execution manifest %q has ID %q", executionID, manifest.ID)
	}
	if err := validateManifestForSave(manifest); err != nil {
		return Artifact{}, err
	}

	stored, err := s.CopyArtifactPayload(executionID, payloadPath, sourcePath)
	if err != nil {
		return Artifact{}, err
	}
	artifact = artifactWithStoredFile(artifact, stored)
	manifest.Artifacts = upsertArtifact(manifest.Artifacts, artifact)
	if err := s.SaveManifest(manifest); err != nil {
		return Artifact{}, err
	}
	return artifact, nil
}

func (s Store) writePayload(executionID, area, payloadPath string, data []byte) (StoredFile, error) {
	absolutePath, storeRelativePath, err := s.payloadPath(executionID, area, payloadPath)
	if err != nil {
		return StoredFile{}, err
	}
	relativePayloadPath, err := validatePayloadPath(payloadPath)
	if err != nil {
		return StoredFile{}, err
	}
	executionID, err = validateExecutionID(executionID)
	if err != nil {
		return StoredFile{}, err
	}
	if err := s.Ensure(executionID); err != nil {
		return StoredFile{}, err
	}
	info, err := writeStoreBytesAtomic(
		s.root,
		payloadStoreComponents(executionID, area, relativePayloadPath),
		absolutePath,
		data,
		0o600,
		true,
	)
	if err != nil {
		return StoredFile{}, fmt.Errorf("write sandbox execution payload %q: %w", storeRelativePath, err)
	}
	return StoredFile{Path: storeRelativePath, SizeBytes: info.Size(), CreatedAt: info.ModTime().UTC()}, nil
}

func (s Store) copyPayload(executionID, area, payloadPath, sourcePath string) (StoredFile, error) {
	absolutePath, storeRelativePath, err := s.payloadPath(executionID, area, payloadPath)
	if err != nil {
		return StoredFile{}, err
	}
	relativePayloadPath, err := validatePayloadPath(payloadPath)
	if err != nil {
		return StoredFile{}, err
	}
	executionID, err = validateExecutionID(executionID)
	if err != nil {
		return StoredFile{}, err
	}

	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return StoredFile{}, fmt.Errorf("sandbox execution payload source path is required")
	}
	sourceInfo, err := os.Lstat(sourcePath)
	if err != nil {
		return StoredFile{}, fmt.Errorf("stat sandbox execution payload source %q: %w", sourcePath, err)
	}
	if sourceInfo.Mode()&fs.ModeSymlink != 0 {
		return StoredFile{}, fmt.Errorf("sandbox execution payload source %q is a symlink", sourcePath)
	}
	if !sourceInfo.Mode().IsRegular() {
		return StoredFile{}, fmt.Errorf("sandbox execution payload source %q is not a regular file", sourcePath)
	}

	if err := s.Ensure(executionID); err != nil {
		return StoredFile{}, err
	}

	info, err := copyStoreFileAtomic(
		sourcePath,
		s.root,
		payloadStoreComponents(executionID, area, relativePayloadPath),
		absolutePath,
		0o600,
		sourceInfo,
	)
	if err != nil {
		return StoredFile{}, fmt.Errorf("copy sandbox execution payload %q: %w", storeRelativePath, err)
	}
	return StoredFile{Path: storeRelativePath, SizeBytes: info.Size(), CreatedAt: info.ModTime().UTC()}, nil
}

func (s Store) copyPayloadRedactingSourcePath(executionID, area, payloadPath, sourcePath string) (StoredFile, error) {
	absolutePath, storeRelativePath, err := s.payloadPath(executionID, area, payloadPath)
	if err != nil {
		return StoredFile{}, err
	}
	relativePayloadPath, err := validatePayloadPath(payloadPath)
	if err != nil {
		return StoredFile{}, err
	}
	executionID, err = validateExecutionID(executionID)
	if err != nil {
		return StoredFile{}, err
	}

	sourcePath = strings.TrimSpace(sourcePath)
	if sourcePath == "" {
		return StoredFile{}, fmt.Errorf("sandbox execution payload source path is required")
	}
	sourceInfo, err := os.Lstat(sourcePath)
	if err != nil {
		return StoredFile{}, fmt.Errorf("stat sandbox execution payload source: %w", redactPathError(err))
	}
	if sourceInfo.Mode()&fs.ModeSymlink != 0 {
		return StoredFile{}, fmt.Errorf("sandbox execution payload source is a symlink")
	}
	if !sourceInfo.Mode().IsRegular() {
		return StoredFile{}, fmt.Errorf("sandbox execution payload source is not a regular file")
	}

	if err := s.Ensure(executionID); err != nil {
		return StoredFile{}, err
	}

	info, err := copyStoreFileAtomicRedactingSourcePath(
		sourcePath,
		s.root,
		payloadStoreComponents(executionID, area, relativePayloadPath),
		absolutePath,
		0o600,
		sourceInfo,
	)
	if err != nil {
		return StoredFile{}, fmt.Errorf("copy sandbox execution payload %q: %w", storeRelativePath, redactPathError(err))
	}
	return StoredFile{Path: storeRelativePath, SizeBytes: info.Size(), CreatedAt: info.ModTime().UTC()}, nil
}

func (s Store) payloadPath(executionID, area, payloadPath string) (string, string, error) {
	executionID, err := validateExecutionID(executionID)
	if err != nil {
		return "", "", err
	}
	if strings.TrimSpace(s.root) == "" {
		return "", "", errStoreRootUnavailable
	}
	relPath, err := validatePayloadPath(payloadPath)
	if err != nil {
		return "", "", err
	}
	base := filepath.Join(s.root, executionID, area)
	absolutePath := filepath.Join(base, filepath.FromSlash(relPath))
	storeRelativePath := filepath.ToSlash(filepath.Join(executionID, area, filepath.FromSlash(relPath)))
	return absolutePath, storeRelativePath, nil
}

func validatePayloadPath(payloadPath string) (string, error) {
	trimmed := strings.TrimSpace(payloadPath)
	if trimmed == "" {
		return "", fmt.Errorf("sandbox execution payload path is required")
	}
	if trimmed != payloadPath {
		return "", fmt.Errorf("sandbox execution payload path %q is invalid", payloadPath)
	}
	if filepath.IsAbs(payloadPath) || pathpkg.IsAbs(payloadPath) {
		return "", fmt.Errorf("sandbox execution payload path %q must be relative", payloadPath)
	}
	if strings.Contains(payloadPath, "\\") {
		return "", fmt.Errorf("sandbox execution payload path %q must not contain backslash separators", payloadPath)
	}
	for _, part := range strings.Split(payloadPath, "/") {
		if part == ".." {
			return "", fmt.Errorf("sandbox execution payload path %q must not contain traversal", payloadPath)
		}
	}
	clean := pathpkg.Clean(payloadPath)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("sandbox execution payload path %q is invalid", payloadPath)
	}
	return clean, nil
}

func payloadStoreComponents(executionID, area, relativePayloadPath string) []string {
	components := []string{executionID, area}
	return append(components, strings.Split(relativePayloadPath, "/")...)
}

func copyStoreFileAtomic(
	sourcePath string,
	root string,
	components []string,
	destPath string,
	mode fs.FileMode,
	expectedInfo fs.FileInfo,
) (fs.FileInfo, error) {
	source, err := openFileNoFollow(sourcePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	sourceInfo, err := source.Stat()
	if err != nil {
		return nil, err
	}
	if !sourceInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("source %q is not a regular file", sourcePath)
	}
	if expectedInfo != nil && !os.SameFile(expectedInfo, sourceInfo) {
		return nil, fmt.Errorf("source %q changed during copy", sourcePath)
	}
	return publishStoreFileAtomic(root, components, destPath, mode, true, func(dest *os.File) error {
		_, err := io.Copy(dest, source)
		return err
	})
}

func copyStoreFileAtomicRedactingSourcePath(
	sourcePath string,
	root string,
	components []string,
	destPath string,
	mode fs.FileMode,
	expectedInfo fs.FileInfo,
) (fs.FileInfo, error) {
	source, err := openFileNoFollow(sourcePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, redactPathError(err)
	}
	defer source.Close()
	sourceInfo, err := source.Stat()
	if err != nil {
		return nil, redactPathError(err)
	}
	if !sourceInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("source is not a regular file")
	}
	if expectedInfo != nil && !os.SameFile(expectedInfo, sourceInfo) {
		return nil, fmt.Errorf("source changed during copy")
	}
	info, err := publishStoreFileAtomic(root, components, destPath, mode, true, func(dest *os.File) error {
		_, err := io.Copy(dest, source)
		return err
	})
	if err != nil {
		return nil, redactPathError(err)
	}
	return info, nil
}

func validateArtifactForSave(artifact Artifact) error {
	if strings.TrimSpace(artifact.ID) == "" {
		return fmt.Errorf("sandbox execution artifact ID is required")
	}
	if strings.TrimSpace(artifact.ID) != artifact.ID {
		return fmt.Errorf("sandbox execution artifact ID %q is invalid", artifact.ID)
	}
	if strings.TrimSpace(artifact.Name) == "" {
		return fmt.Errorf("sandbox execution artifact name is required")
	}
	if strings.TrimSpace(artifact.Type) == "" {
		return fmt.Errorf("sandbox execution artifact type is required")
	}
	return nil
}

func validateArtifactFileMetadataInput(artifact ArtifactMetadataEntry) error {
	if strings.TrimSpace(artifact.Path) == "" {
		return fmt.Errorf("sandbox execution artifact display path is required")
	}
	if err := validateArtifactDisplayPath(artifact.Path); err != nil {
		return fmt.Errorf("sandbox execution artifact display path %q is invalid: %w", artifact.Path, err)
	}
	if strings.TrimSpace(artifact.StoredPath) != "" {
		return fmt.Errorf("sandbox execution artifact storedPath is managed by the store")
	}
	return nil
}

func artifactWithStoredFile(artifact Artifact, stored StoredFile) Artifact {
	size := stored.SizeBytes
	createdAt := stored.CreatedAt
	artifact.Path = stored.Path
	artifact.StoredPath = stored.Path
	artifact.SizeBytes = &size
	if !createdAt.IsZero() {
		artifact.CreatedAt = &createdAt
	}
	return artifact
}

func artifactMetadataWithStoredFile(artifact ArtifactMetadataEntry, stored StoredFile) ArtifactMetadataEntry {
	size := stored.SizeBytes
	createdAt := stored.CreatedAt
	artifact.StoredPath = stored.Path
	artifact.SizeBytes = &size
	if !createdAt.IsZero() {
		artifact.CreatedAt = &createdAt
	}
	return artifact
}

func upsertArtifact(artifacts []Artifact, artifact Artifact) []Artifact {
	for i := range artifacts {
		if artifacts[i].ID == artifact.ID {
			artifacts[i] = artifact
			return artifacts
		}
	}
	return append(artifacts, artifact)
}

func redactPathError(err error) error {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		redacted := *pathErr
		redacted.Path = "<redacted>"
		return &redacted
	}
	return err
}
