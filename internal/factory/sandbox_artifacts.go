package factory

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ErrSandboxArtifactNotFound marks an optional sandbox artifact as unavailable.
var ErrSandboxArtifactNotFound = errors.New("sandbox artifact not found")

// SandboxArtifactCopier copies artifact payloads from a sandbox workspace into
// a local destination owned by the factory collector.
type SandboxArtifactCopier interface {
	CopyFile(ctx context.Context, remotePath, localPath string) error
	CopyDir(ctx context.Context, remotePath, localPath string) error
}

// SandboxArtifactRequest describes one sandbox artifact to copy. RemotePath is
// only an input to the copier; Path is the safe display path persisted in run
// metadata.
type SandboxArtifactRequest struct {
	ID         string
	Name       string
	Type       string
	RemotePath string
	Path       string
	Directory  bool
	Optional   bool
	Summary    map[string]any
}

// CollectSandboxArtifacts copies sandbox artifacts through copier, stores the
// resulting local payloads in the factory store, and records artifact metadata
// on the run. Missing optional artifacts become warning-only partial records.
func CollectSandboxArtifacts(ctx context.Context, store Store, runID string, copier SandboxArtifactCopier, requests []SandboxArtifactRequest) ([]ArtifactReference, error) {
	return CollectSandboxArtifactsWithRedactor(ctx, store, runID, copier, requests, RunSecretRedactor{})
}

// CollectSandboxArtifactsWithRedactor copies sandbox artifacts and records
// artifact metadata after removing run-scoped secret values.
func CollectSandboxArtifactsWithRedactor(ctx context.Context, store Store, runID string, copier SandboxArtifactCopier, requests []SandboxArtifactRequest, redactor RunSecretRedactor) ([]ArtifactReference, error) {
	if copier == nil {
		return nil, fmt.Errorf("sandbox artifact copier is required")
	}
	runID, err := validateRunID(runID)
	if err != nil {
		return nil, err
	}
	if len(requests) == 0 {
		return nil, nil
	}

	tempDir, err := os.MkdirTemp("", "hal-factory-sandbox-artifacts-*")
	if err != nil {
		return nil, fmt.Errorf("create sandbox artifact temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	collected := make([]ArtifactReference, 0, len(requests))
	partials := make([]ArtifactReference, 0)
	for _, request := range requests {
		artifacts, warnings, err := collectSandboxArtifact(ctx, store, runID, copier, tempDir, request, redactor)
		if err != nil {
			return nil, err
		}
		collected = append(collected, artifacts...)
		partials = append(partials, warnings...)
	}

	if len(partials) > 0 || len(collected) > 0 {
		record, err := store.LoadRun(runID)
		if err != nil {
			return nil, fmt.Errorf("load factory run for sandbox artifact metadata: %w", err)
		}
		for _, artifact := range collected {
			record.Artifacts = upsertArtifact(record.Artifacts, artifact)
		}
		for _, artifact := range partials {
			record.Artifacts = upsertArtifact(record.Artifacts, artifact)
		}
		if err := store.SaveRun(record); err != nil {
			return nil, fmt.Errorf("record sandbox artifact metadata: %w", err)
		}
	}

	return append(collected, partials...), nil
}

func collectSandboxArtifact(ctx context.Context, store Store, runID string, copier SandboxArtifactCopier, tempDir string, request SandboxArtifactRequest, redactor RunSecretRedactor) ([]ArtifactReference, []ArtifactReference, error) {
	request.Name = strings.TrimSpace(request.Name)
	request.Type = strings.TrimSpace(request.Type)
	request.RemotePath = strings.TrimSpace(request.RemotePath)
	request.Path = filepath.ToSlash(strings.TrimSpace(request.Path))
	request.ID = strings.TrimSpace(request.ID)
	if request.Name == "" {
		return nil, nil, fmt.Errorf("sandbox artifact name is required")
	}
	if request.Type == "" {
		request.Type = "file"
	}
	if request.RemotePath == "" {
		return nil, nil, redactSandboxArtifactError(fmt.Errorf("sandbox artifact %q remote path is required", request.Name), redactor)
	}
	if request.Path == "" {
		request.Path = sandboxArtifactDisplayPath(request)
	}

	localPath := filepath.Join(tempDir, sandboxArtifactLocalName(request))
	var copyErr error
	if request.Directory {
		copyErr = copier.CopyDir(ctx, request.RemotePath, localPath)
	} else {
		if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
			return nil, nil, fmt.Errorf("create sandbox artifact temp destination: %w", err)
		}
		copyErr = copier.CopyFile(ctx, request.RemotePath, localPath)
	}
	if copyErr != nil {
		if request.Optional && errors.Is(copyErr, ErrSandboxArtifactNotFound) {
			return nil, []ArtifactReference{redactor.RedactArtifactReference(missingSandboxArtifact(request))}, nil
		}
		return nil, nil, redactSandboxArtifactError(fmt.Errorf("copy sandbox artifact %q: %w", request.Name, copyErr), redactor)
	}

	if request.Directory {
		return storeSandboxArtifactDir(store, runID, request, localPath, redactor)
	}
	artifact := ArtifactReference{
		ID:      sandboxArtifactID(request, ""),
		Name:    request.Name,
		Type:    request.Type,
		Path:    request.Path,
		Summary: request.Summary,
	}
	stored, err := saveSandboxArtifactFile(store, runID, artifact, localPath, redactor)
	if err != nil {
		return nil, nil, redactSandboxArtifactError(fmt.Errorf("store sandbox artifact %q: %w", request.Name, err), redactor)
	}
	return []ArtifactReference{stored}, nil, nil
}

func storeSandboxArtifactDir(store Store, runID string, request SandboxArtifactRequest, localDir string, redactor RunSecretRedactor) ([]ArtifactReference, []ArtifactReference, error) {
	info, err := os.Stat(localDir)
	if err != nil {
		return nil, nil, redactSandboxArtifactError(fmt.Errorf("stat sandbox artifact directory %q: %w", request.Name, err), redactor)
	}
	if !info.IsDir() {
		return nil, nil, redactSandboxArtifactError(fmt.Errorf("sandbox artifact %q copied directory destination is not a directory", request.Name), redactor)
	}

	var stored []ArtifactReference
	err = filepath.WalkDir(localDir, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !sandboxArtifactPathInsideDir(localDir, filePath) {
			return fmt.Errorf("sandbox artifact path %q is outside copied directory", filePath)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(localDir, filePath)
		if err != nil {
			return err
		}
		displayPath := path.Join(filepath.ToSlash(request.Path), filepath.ToSlash(rel))
		artifact := ArtifactReference{
			ID:      sandboxArtifactID(request, rel),
			Name:    sandboxArtifactChildName(request.Name, rel),
			Type:    sandboxArtifactFileType(request.Type, filePath),
			Path:    displayPath,
			Summary: request.Summary,
		}
		saved, err := saveSandboxArtifactFile(store, runID, artifact, filePath, redactor)
		if err != nil {
			return redactSandboxArtifactError(fmt.Errorf("store sandbox artifact %q: %w", artifact.Name, err), redactor)
		}
		stored = append(stored, saved)
		return nil
	})
	if err != nil {
		return nil, nil, redactSandboxArtifactError(err, redactor)
	}
	return stored, nil, nil
}

type sandboxArtifactRedactedError struct {
	message string
	cause   error
}

func (e sandboxArtifactRedactedError) Error() string {
	return e.message
}

func (e sandboxArtifactRedactedError) Unwrap() error {
	return e.cause
}

func redactSandboxArtifactError(err error, redactor RunSecretRedactor) error {
	if err == nil {
		return nil
	}
	message := redactor.RedactString(err.Error())
	if message == err.Error() {
		return err
	}
	return sandboxArtifactRedactedError{
		message: message,
		cause:   err,
	}
}

func sandboxArtifactPathInsideDir(root, candidate string) bool {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil {
		return false
	}
	return rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func saveSandboxArtifactFile(store Store, runID string, artifact ArtifactReference, sourcePath string, redactor RunSecretRedactor) (ArtifactReference, error) {
	stored, err := store.SaveArtifactFileWithRedactor(runID, artifact, sourcePath, redactor)
	if err != nil {
		return ArtifactReference{}, err
	}
	stored.SourcePath = ""

	record, err := store.LoadRun(runID)
	if err != nil {
		return ArtifactReference{}, fmt.Errorf("load factory run for sandbox artifact metadata: %w", err)
	}
	record.Artifacts = upsertArtifact(record.Artifacts, stored)
	if err := store.SaveRun(record); err != nil {
		return ArtifactReference{}, fmt.Errorf("record sandbox artifact metadata: %w", err)
	}

	return stored, nil
}

func missingSandboxArtifact(request SandboxArtifactRequest) ArtifactReference {
	return ArtifactReference{
		ID:      sandboxArtifactID(request, ""),
		Name:    request.Name,
		Type:    request.Type,
		Path:    request.Path,
		Partial: true,
		Summary: mergeArtifactSummary(request.Summary, map[string]any{
			"collectionStatus": "missing",
		}),
		Warnings: []string{fmt.Sprintf("optional sandbox artifact not found: %s", request.Path)},
	}
}

func sandboxArtifactDisplayPath(request SandboxArtifactRequest) string {
	name := sanitizeArtifactPathComponent(request.Name)
	if name == "" {
		name = "artifact"
	}
	if request.Directory {
		return path.Join("sandbox", name)
	}
	return path.Join("sandbox", artifactFileName(name, request.RemotePath))
}

func sandboxArtifactLocalName(request SandboxArtifactRequest) string {
	if request.Directory {
		return sandboxArtifactID(request, "")
	}
	return artifactFileName(sandboxArtifactID(request, ""), request.RemotePath)
}

func sandboxArtifactID(request SandboxArtifactRequest, relPath string) string {
	base := strings.TrimSpace(request.ID)
	if base == "" {
		base = request.Path
	}
	if relPath != "" {
		base = strings.TrimSuffix(base, "/") + "/" + filepath.ToSlash(relPath)
	}
	id := sanitizeArtifactPathComponent(filepath.ToSlash(base))
	if id == "" {
		id = "artifact"
	}
	if relPath != "" {
		sum := sha256.Sum256([]byte(filepath.ToSlash(relPath)))
		id = fmt.Sprintf("%s-%x", id, sum[:4])
	}
	return id
}

func sandboxArtifactChildName(name, relPath string) string {
	relPath = filepath.ToSlash(strings.TrimSpace(relPath))
	if relPath == "" {
		return name
	}
	return name + "/" + relPath
}

func sandboxArtifactFileType(defaultType, filePath string) string {
	switch strings.ToLower(filepath.Ext(filePath)) {
	case ".json":
		return "json"
	case ".md", ".markdown":
		return "markdown"
	case ".log", ".txt":
		return "text"
	default:
		if strings.TrimSpace(defaultType) != "" && defaultType != "directory" {
			return defaultType
		}
		return "file"
	}
}

func mergeArtifactSummary(existing map[string]any, values map[string]any) map[string]any {
	if len(existing) == 0 && len(values) == 0 {
		return nil
	}
	merged := make(map[string]any, len(existing)+len(values))
	for key, value := range existing {
		merged[key] = value
	}
	for key, value := range values {
		merged[key] = value
	}
	return merged
}
