package sandboxexecution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime"
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
