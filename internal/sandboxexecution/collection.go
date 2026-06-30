package sandboxexecution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/template"
)

// RuntimeArtifactCollector is the runtime boundary needed by non-factory
// artifact collection. sandboxruntime.Driver satisfies this interface.
type RuntimeArtifactCollector interface {
	Exec(context.Context, sandboxruntime.ExecRequest) (*sandboxruntime.ExecResult, error)
	CopyOut(context.Context, sandboxruntime.CopyRequest) error
}

// ArtifactStoreArea selects where a copied artifact payload is persisted.
type ArtifactStoreArea string

const (
	ArtifactStoreAreaArtifacts ArtifactStoreArea = "artifacts"
	ArtifactStoreAreaHandoff   ArtifactStoreArea = "handoff"
	ArtifactStoreAreaRecovery  ArtifactStoreArea = "recovery"
)

// RuntimeArtifactGeneration describes a remote command that produces an
// artifact before it is copied out.
type RuntimeArtifactGeneration struct {
	Args    []string
	WorkDir string
	Env     map[string]string
}

// RuntimeArtifactRequest describes one remote artifact to collect.
type RuntimeArtifactRequest struct {
	Area        ArtifactStoreArea
	Optional    bool
	Artifact    ArtifactMetadataEntry
	PayloadPath string
	RemotePath  string
	Generate    *RuntimeArtifactGeneration
}

// RuntimeCollectionRequest carries runtime and store boundaries into artifact
// collection.
type RuntimeCollectionRequest struct {
	ExecutionID string
	Store       Store
	Runtime     RuntimeArtifactCollector
	Target      sandboxruntime.Target
	Artifacts   []RuntimeArtifactRequest
	TempDir     string
}

// RuntimeCollectionResult contains additive manifest metadata produced by a
// collection pass.
type RuntimeCollectionResult struct {
	ArtifactMetadata ArtifactMetadata
}

// CoreStateCollectionRequest carries the runtime context needed to collect
// standard Hal state files from a non-factory sandbox workspace.
type CoreStateCollectionRequest struct {
	ExecutionID        string
	Store              Store
	Runtime            RuntimeArtifactCollector
	Target             sandboxruntime.Target
	Purpose            Purpose
	RemoteWorkspaceDir string
	TempDir            string
}

// RecoveryArtifactCollectionRequest carries the runtime context needed to
// generate and collect the standard non-factory sandbox recovery patch.
type RecoveryArtifactCollectionRequest struct {
	ExecutionID        string
	Store              Store
	Runtime            RuntimeArtifactCollector
	Target             sandboxruntime.Target
	RemoteWorkspaceDir string
	TempDir            string
}

// ReportsArchiveCollectionRequest carries the runtime context needed to
// generate and collect the standard non-factory sandbox reports archive.
type ReportsArchiveCollectionRequest struct {
	ExecutionID        string
	Store              Store
	Runtime            RuntimeArtifactCollector
	Target             sandboxruntime.Target
	RemoteWorkspaceDir string
	TempDir            string
}

const (
	recoveryArtifactID       = "recovery-patch"
	recoveryArtifactName     = "Recovery Patch"
	recoveryArtifactType     = "patch"
	recoveryArtifactDir      = "recovery"
	recoveryArtifactFileName = "workspace.patch"

	reportsArchiveID       = "reports-archive"
	reportsArchiveName     = "Reports Archive"
	reportsArchiveType     = "tar"
	reportsArchiveDir      = "reports"
	reportsArchiveFileName = "reports.tar"
)

// CollectRuntimeArtifacts generates requested remote artifacts, copies remote
// artifact files to local temp files through the runtime driver, and persists
// them into the execution store.
func CollectRuntimeArtifacts(ctx context.Context, req RuntimeCollectionRequest) (RuntimeCollectionResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	executionID, err := validateExecutionID(req.ExecutionID)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if req.Runtime == nil {
		return RuntimeCollectionResult{}, fmt.Errorf("sandbox execution artifact runtime is required")
	}
	for i, artifact := range req.Artifacts {
		if err := validateRuntimeArtifactRequest(artifact); err != nil {
			return RuntimeCollectionResult{}, fmt.Errorf("sandbox execution artifact request[%d] is invalid: %w", i, err)
		}
	}
	if len(req.Artifacts) == 0 {
		return RuntimeCollectionResult{}, nil
	}

	tempDir, err := os.MkdirTemp(req.TempDir, "hal-sandbox-artifacts-*")
	if err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("create sandbox execution artifact temp dir: %w", redactPathError(err))
	}
	defer os.RemoveAll(tempDir)

	result := RuntimeCollectionResult{}
	for i, artifact := range req.Artifacts {
		if artifact.Generate != nil {
			if err := runRuntimeArtifactGeneration(ctx, req.Runtime, req.Target, *artifact.Generate); err != nil {
				return RuntimeCollectionResult{}, fmt.Errorf("generate sandbox execution artifact %q: %w", artifact.Artifact.Path, err)
			}
		}

		localPath := filepath.Join(tempDir, fmt.Sprintf("%03d-%s", i, filepath.Base(filepath.FromSlash(artifact.PayloadPath))))
		if err := req.Runtime.CopyOut(ctx, sandboxruntime.CopyRequest{
			Target:          req.Target,
			SourcePath:      artifact.RemotePath,
			DestinationPath: localPath,
		}); err != nil {
			if artifact.Optional {
				addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, "copy_out", runtimeArtifactCopyOutWarningMessage(err))
				continue
			}
			return RuntimeCollectionResult{}, fmt.Errorf("copy sandbox execution artifact %q: %w", artifact.Artifact.Path, redactPathError(err))
		}

		collected, err := saveRuntimeArtifactFile(req.Store, executionID, artifact, localPath)
		if err != nil {
			if artifact.Optional {
				addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, "store", "optional sandbox execution artifact persistence failed")
				continue
			}
			return RuntimeCollectionResult{}, err
		}
		result.ArtifactMetadata.Collected = append(result.ArtifactMetadata.Collected, collected)
	}
	return result, nil
}

// CollectRecoveryArtifacts generates a deterministic remote recovery patch,
// copies it out through the runtime driver, stores it under recovery/, and
// records the collected metadata on the manifest.
func CollectRecoveryArtifacts(ctx context.Context, req RecoveryArtifactCollectionRequest) (RuntimeCollectionResult, error) {
	if _, err := req.Store.LoadManifest(req.ExecutionID); err != nil {
		return RuntimeCollectionResult{}, err
	}
	artifact, err := recoveryArtifactRequest(req.RemoteWorkspaceDir)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	result, err := CollectRuntimeArtifacts(ctx, RuntimeCollectionRequest{
		ExecutionID: req.ExecutionID,
		Store:       req.Store,
		Runtime:     req.Runtime,
		Target:      req.Target,
		Artifacts:   []RuntimeArtifactRequest{artifact},
		TempDir:     req.TempDir,
	})
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if err := req.Store.AppendArtifactMetadata(req.ExecutionID, result.ArtifactMetadata); err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("persist sandbox execution recovery metadata: %w", err)
	}
	return result, nil
}

// CollectReportsArchiveArtifacts creates a deterministic remote tar archive of
// .hal/reports when it exists, copies it out through the runtime driver, stores
// it under artifacts/, and records collected or partial metadata on the manifest.
func CollectReportsArchiveArtifacts(ctx context.Context, req ReportsArchiveCollectionRequest) (RuntimeCollectionResult, error) {
	if _, err := req.Store.LoadManifest(req.ExecutionID); err != nil {
		return RuntimeCollectionResult{}, err
	}
	artifact, err := reportsArchiveArtifactRequest(req.RemoteWorkspaceDir)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	result, err := CollectRuntimeArtifacts(ctx, RuntimeCollectionRequest{
		ExecutionID: req.ExecutionID,
		Store:       req.Store,
		Runtime:     req.Runtime,
		Target:      req.Target,
		Artifacts:   []RuntimeArtifactRequest{artifact},
		TempDir:     req.TempDir,
	})
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if err := req.Store.AppendArtifactMetadata(req.ExecutionID, result.ArtifactMetadata); err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("persist sandbox execution reports archive metadata: %w", err)
	}
	return result, nil
}

// CollectCoreStateArtifacts collects the core .hal state files for a run or
// auto sandbox execution and records the collected metadata on the manifest.
func CollectCoreStateArtifacts(ctx context.Context, req CoreStateCollectionRequest) (RuntimeCollectionResult, error) {
	if !validPurpose(req.Purpose) {
		return RuntimeCollectionResult{}, fmt.Errorf("sandbox execution purpose %q is invalid", req.Purpose)
	}
	if _, err := req.Store.LoadManifest(req.ExecutionID); err != nil {
		return RuntimeCollectionResult{}, err
	}
	artifacts, err := coreStateArtifactRequests(req.Purpose, req.RemoteWorkspaceDir)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	result, err := CollectRuntimeArtifacts(ctx, RuntimeCollectionRequest{
		ExecutionID: req.ExecutionID,
		Store:       req.Store,
		Runtime:     req.Runtime,
		Target:      req.Target,
		Artifacts:   artifacts,
		TempDir:     req.TempDir,
	})
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if err := req.Store.AppendArtifactMetadata(req.ExecutionID, result.ArtifactMetadata); err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("persist sandbox execution core state metadata: %w", err)
	}
	return result, nil
}

func recoveryArtifactRequest(remoteWorkspaceDir string) (RuntimeArtifactRequest, error) {
	remoteWorkspaceDir = strings.TrimSpace(remoteWorkspaceDir)
	if remoteWorkspaceDir == "" {
		return RuntimeArtifactRequest{}, fmt.Errorf("sandbox execution remote workspace dir is required")
	}
	displayPath := recoveryArtifactDisplayPath()
	return RuntimeArtifactRequest{
		Area: ArtifactStoreAreaRecovery,
		Artifact: ArtifactMetadataEntry{
			ID:   recoveryArtifactID,
			Name: recoveryArtifactName,
			Type: recoveryArtifactType,
			Path: displayPath,
		},
		PayloadPath: recoveryArtifactFileName,
		RemotePath:  pathpkg.Join(remoteWorkspaceDir, displayPath),
		Generate: &RuntimeArtifactGeneration{
			Args:    []string{"sh", "-c", recoveryPatchGenerationScript()},
			WorkDir: remoteWorkspaceDir,
		},
	}, nil
}

func reportsArchiveArtifactRequest(remoteWorkspaceDir string) (RuntimeArtifactRequest, error) {
	remoteWorkspaceDir = strings.TrimSpace(remoteWorkspaceDir)
	if remoteWorkspaceDir == "" {
		return RuntimeArtifactRequest{}, fmt.Errorf("sandbox execution remote workspace dir is required")
	}
	displayPath := reportsArchiveDisplayPath()
	return RuntimeArtifactRequest{
		Optional: true,
		Artifact: ArtifactMetadataEntry{
			ID:   reportsArchiveID,
			Name: reportsArchiveName,
			Type: reportsArchiveType,
			Path: displayPath,
		},
		PayloadPath: pathpkg.Join(reportsArchiveDir, reportsArchiveFileName),
		RemotePath:  pathpkg.Join(remoteWorkspaceDir, displayPath),
		Generate: &RuntimeArtifactGeneration{
			Args:    []string{"sh", "-c", reportsArchiveGenerationScript()},
			WorkDir: remoteWorkspaceDir,
		},
	}, nil
}

func reportsArchiveDisplayPath() string {
	return pathpkg.Join(template.HalDir, reportsArchiveFileName)
}

func reportsArchiveSourceDir() string {
	return pathpkg.Join(template.HalDir, reportsArchiveDir)
}

func reportsArchiveGenerationScript() string {
	reportsDir := reportsArchiveSourceDir()
	archivePath := reportsArchiveDisplayPath()
	tmpPath := archivePath + ".tmp"
	return strings.Join([]string{
		"set -eu",
		fmt.Sprintf("reports_dir=%q", reportsDir),
		fmt.Sprintf("archive_path=%q", archivePath),
		fmt.Sprintf("tmp_path=%q", tmpPath),
		`rm -f "$tmp_path" "$archive_path"`,
		`if [ ! -d "$reports_dir" ]; then`,
		"\texit 0",
		"fi",
		`if command -v gtar >/dev/null 2>&1; then`,
		"\ttar_cmd=gtar",
		"else",
		"\ttar_cmd=tar",
		"fi",
		`if "$tar_cmd" --version 2>/dev/null | grep -qi 'gnu tar'; then`,
		`"$tar_cmd" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf "$tmp_path" -C ".hal" "reports"`,
		"else",
		`(cd ".hal" && find "reports" -print | LC_ALL=C sort | "$tar_cmd" -cf "../$tmp_path" -T -)`,
		"fi",
		`mv "$tmp_path" "$archive_path"`,
	}, "\n")
}

func recoveryArtifactDisplayPath() string {
	return pathpkg.Join(template.HalDir, recoveryArtifactDir, recoveryArtifactFileName)
}

func recoveryPatchGenerationScript() string {
	recoveryPath := recoveryArtifactDisplayPath()
	tmpPath := recoveryPath + ".tmp"
	return strings.Join([]string{
		"set -eu",
		fmt.Sprintf("recovery_path=%q", recoveryPath),
		fmt.Sprintf("tmp_path=%q", tmpPath),
		fmt.Sprintf("mkdir -p %q", pathpkg.Dir(recoveryPath)),
		`rm -f "$tmp_path"`,
		"if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then",
		"\t{",
		"\t\tgit diff --binary --no-ext-diff",
		"\t\tgit diff --cached --binary --no-ext-diff",
		"\t} > \"$tmp_path\"",
		"else",
		"\t: > \"$tmp_path\"",
		"fi",
		`mv "$tmp_path" "$recovery_path"`,
	}, "\n")
}

func runRuntimeArtifactGeneration(ctx context.Context, runtime RuntimeArtifactCollector, target sandboxruntime.Target, generation RuntimeArtifactGeneration) error {
	result, err := runtime.Exec(ctx, sandboxruntime.ExecRequest{
		Target:  target,
		Args:    append([]string(nil), generation.Args...),
		WorkDir: strings.TrimSpace(generation.WorkDir),
		Env:     cloneCollectionStringMap(generation.Env),
		Stdout:  io.Discard,
		Stderr:  io.Discard,
	})
	if err != nil {
		return err
	}
	if result != nil && result.ExitCode != 0 {
		return fmt.Errorf("runtime command exited with status %d", result.ExitCode)
	}
	return nil
}

func coreStateArtifactRequests(purpose Purpose, remoteWorkspaceDir string) ([]RuntimeArtifactRequest, error) {
	remoteWorkspaceDir = strings.TrimSpace(remoteWorkspaceDir)
	if remoteWorkspaceDir == "" {
		return nil, fmt.Errorf("sandbox execution remote workspace dir is required")
	}
	artifacts := []RuntimeArtifactRequest{
		coreStateArtifactRequest("prd", "PRD", "json", template.PRDFile, "hal-prd.json", remoteWorkspaceDir),
		coreStateArtifactRequest("progress", "Progress", "text", template.ProgressFile, "hal-progress.txt", remoteWorkspaceDir),
	}
	if purpose == PurposeAuto {
		artifacts = append(artifacts, coreStateArtifactRequest("auto-state", "Auto State", "json", template.AutoStateFile, "hal-auto-state.json", remoteWorkspaceDir))
	}
	return artifacts, nil
}

func coreStateArtifactRequest(id, name, artifactType, fileName, payloadName, remoteWorkspaceDir string) RuntimeArtifactRequest {
	displayPath := pathpkg.Join(template.HalDir, fileName)
	return RuntimeArtifactRequest{
		Artifact: ArtifactMetadataEntry{
			ID:   id,
			Name: name,
			Type: artifactType,
			Path: displayPath,
		},
		PayloadPath: pathpkg.Join("core", payloadName),
		RemotePath:  pathpkg.Join(remoteWorkspaceDir, displayPath),
	}
}

func saveRuntimeArtifactFile(store Store, executionID string, req RuntimeArtifactRequest, localPath string) (ArtifactMetadataEntry, error) {
	area := req.Area
	if area == "" {
		area = ArtifactStoreAreaArtifacts
	}
	switch area {
	case ArtifactStoreAreaArtifacts:
		return store.SaveArtifactFile(executionID, req.Artifact, req.PayloadPath, localPath)
	case ArtifactStoreAreaHandoff:
		return store.SaveHandoffFile(executionID, req.Artifact, req.PayloadPath, localPath)
	case ArtifactStoreAreaRecovery:
		return store.SaveRecoveryFile(executionID, req.Artifact, req.PayloadPath, localPath)
	default:
		return ArtifactMetadataEntry{}, fmt.Errorf("sandbox execution artifact store area %q is invalid", req.Area)
	}
}

func validateRuntimeArtifactRequest(req RuntimeArtifactRequest) error {
	if err := validateArtifactFileMetadataInput(req.Artifact); err != nil {
		return err
	}
	if _, err := validatePayloadPath(req.PayloadPath); err != nil {
		return err
	}
	if strings.TrimSpace(req.RemotePath) == "" {
		return fmt.Errorf("sandbox execution artifact remote path is required")
	}
	if strings.TrimSpace(req.RemotePath) != req.RemotePath {
		return fmt.Errorf("sandbox execution artifact remote path is invalid")
	}
	if req.Generate != nil && len(req.Generate.Args) == 0 {
		return fmt.Errorf("sandbox execution artifact generation args are required")
	}
	if req.Area != "" {
		switch req.Area {
		case ArtifactStoreAreaArtifacts, ArtifactStoreAreaHandoff, ArtifactStoreAreaRecovery:
		default:
			return fmt.Errorf("sandbox execution artifact store area %q is invalid", req.Area)
		}
	}
	return nil
}

func addRuntimeArtifactPartialWarning(metadata *ArtifactMetadata, req RuntimeArtifactRequest, phase, message string) {
	partial := req.Artifact
	partial.StoredPath = ""
	partial.SizeBytes = nil
	partial.CreatedAt = nil
	metadata.Partial = append(metadata.Partial, partial)
	metadata.Warnings = append(metadata.Warnings, ArtifactWarning{
		Phase:    phase,
		Message:  message,
		Artifact: partial,
	})
}

func runtimeArtifactCopyOutWarningMessage(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "optional sandbox execution artifact is missing"
	}
	return "optional sandbox execution artifact copy failed"
}

func cloneCollectionStringMap(values map[string]string) map[string]string {
	if values == nil {
		return nil
	}
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}
