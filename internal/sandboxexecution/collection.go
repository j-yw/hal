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

// ArtifactCollectionError exposes safe artifact warning metadata for command
// boundaries that choose to keep artifact copy failures non-fatal.
type ArtifactCollectionError struct {
	Phase    string
	Message  string
	Artifact ArtifactMetadataEntry
	Err      error
}

func (e *ArtifactCollectionError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Message
}

func (e *ArtifactCollectionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *ArtifactCollectionError) Warning() ArtifactWarning {
	if e == nil {
		return ArtifactWarning{}
	}
	artifact := e.Artifact
	artifact.StoredPath = ""
	artifact.SizeBytes = nil
	artifact.CreatedAt = nil
	return ArtifactWarning{
		Phase:    e.Phase,
		Message:  e.Message,
		Artifact: artifact,
	}
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
	RemoteArchivePath  string
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

// CommittedSyncOutCollectionRequest carries the runtime context and prepared
// workspace baseline needed to collect committed sandbox changes separately
// from working-tree recovery state.
type CommittedSyncOutCollectionRequest struct {
	ExecutionID        string
	Store              Store
	Runtime            RuntimeArtifactCollector
	Target             sandboxruntime.Target
	RemoteWorkspaceDir string
	SyncRef            string
	TempDir            string
}

// UncommittedSyncOutCollectionRequest carries the runtime context needed to
// collect tracked sandbox worktree changes separately from committed output.
type UncommittedSyncOutCollectionRequest struct {
	ExecutionID        string
	Store              Store
	Runtime            RuntimeArtifactCollector
	Target             sandboxruntime.Target
	RemoteWorkspaceDir string
	TempDir            string
}

// UntrackedSyncOutCollectionRequest carries the runtime context needed to
// collect untracked sandbox files as handoff-only archive and file-list
// artifacts.
type UntrackedSyncOutCollectionRequest struct {
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

// CommandOutputSummaryArtifactsRequest carries sanitized command output
// summaries that should be stored as additive manifest artifacts.
type CommandOutputSummaryArtifactsRequest struct {
	ExecutionID   string
	Store         Store
	StdoutSummary string
	StderrSummary string
}

const (
	ArtifactWarningPhaseCopyOut = "copy_out"

	recoveryArtifactID       = "recovery-patch"
	recoveryArtifactName     = "Recovery Patch"
	recoveryArtifactType     = "patch"
	recoveryArtifactDir      = "recovery"
	recoveryArtifactFileName = "workspace.patch"

	recoveryGenerationWarningPhase = "recovery-generation"
	recoveryCopyOutWarningPhase    = "recovery-copyout"
	recoveryPersistWarningPhase    = "recovery-persist"

	committedSyncOutArtifactName     = "Committed Patch"
	committedSyncOutArtifactType     = "patch"
	committedSyncOutArtifactDir      = "sync"
	committedSyncOutArtifactFileName = "committed.patch"

	committedSyncOutGenerationWarningPhase = "sync-out-generation"
	committedSyncOutCopyOutWarningPhase    = "sync-out-copyout"
	committedSyncOutPersistWarningPhase    = "sync-out-persist"

	uncommittedSyncOutArtifactName     = "Uncommitted Diff"
	uncommittedSyncOutArtifactType     = "diff"
	uncommittedSyncOutArtifactFileName = "uncommitted.diff"

	uncommittedSyncOutGenerationWarningPhase = "sync-out-uncommitted-generation"
	uncommittedSyncOutCopyOutWarningPhase    = "sync-out-uncommitted-copyout"
	uncommittedSyncOutPersistWarningPhase    = "sync-out-uncommitted-persist"

	untrackedSyncOutArchiveName     = "Untracked Files Archive"
	untrackedSyncOutArchiveType     = "tar"
	untrackedSyncOutArchiveFileName = "untracked.tar"
	untrackedSyncOutListName        = "Untracked Files"
	untrackedSyncOutListType        = "text"
	untrackedSyncOutListFileName    = "untracked.txt"

	untrackedSyncOutGenerationWarningPhase = "sync-out-untracked-generation"
	untrackedSyncOutCopyOutWarningPhase    = "sync-out-untracked-copyout"
	untrackedSyncOutPersistWarningPhase    = "sync-out-untracked-persist"

	reportsArchiveID       = "reports-archive"
	reportsArchiveName     = "Reports Archive"
	reportsArchiveType     = "tar"
	reportsArchiveDir      = "reports"
	reportsArchiveFileName = "reports.tar"

	commandOutputSummaryArtifactType = "text"
	commandOutputSummaryDir          = "output"
	stdoutSummaryArtifactID          = "stdout-summary"
	stdoutSummaryArtifactName        = "Stdout Summary"
	stdoutSummaryArtifactFileName    = "stdout-summary.txt"
	stderrSummaryArtifactID          = "stderr-summary"
	stderrSummaryArtifactName        = "Stderr Summary"
	stderrSummaryArtifactFileName    = "stderr-summary.txt"
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
				addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, ArtifactWarningPhaseCopyOut, runtimeArtifactCopyOutWarningMessage(err))
				continue
			}
			collectionErr := &ArtifactCollectionError{
				Phase:    ArtifactWarningPhaseCopyOut,
				Message:  requiredRuntimeArtifactCopyOutWarningMessage(artifact, err),
				Artifact: artifact.Artifact,
				Err:      redactPathError(err),
			}
			return RuntimeCollectionResult{}, fmt.Errorf("copy sandbox execution artifact %q: %w", artifact.Artifact.Path, collectionErr)
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
	if err := req.Store.UpsertArtifactMetadata(req.ExecutionID, result.ArtifactMetadata); err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("persist sandbox execution recovery metadata: %w", err)
	}
	return result, nil
}

// CollectRecoveryArtifactsBestEffort attempts to generate and collect the
// standard recovery patch after a command failure. Collection failures are
// recorded as partial metadata and warnings instead of being returned.
func CollectRecoveryArtifactsBestEffort(ctx context.Context, req RecoveryArtifactCollectionRequest) (RuntimeCollectionResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	executionID, err := validateExecutionID(req.ExecutionID)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if _, err := req.Store.LoadManifest(executionID); err != nil {
		return RuntimeCollectionResult{}, err
	}
	if req.Runtime == nil {
		return RuntimeCollectionResult{}, fmt.Errorf("sandbox execution artifact runtime is required")
	}
	artifact, err := recoveryArtifactRequest(req.RemoteWorkspaceDir)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if err := validateRuntimeArtifactRequest(artifact); err != nil {
		return RuntimeCollectionResult{}, err
	}

	tempDir, err := os.MkdirTemp(req.TempDir, "hal-sandbox-recovery-*")
	if err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("create sandbox execution recovery temp dir: %w", redactPathError(err))
	}
	defer os.RemoveAll(tempDir)

	result := RuntimeCollectionResult{}
	if artifact.Generate != nil {
		if err := runRuntimeArtifactGeneration(ctx, req.Runtime, req.Target, *artifact.Generate); err != nil {
			addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, recoveryGenerationWarningPhase, "sandbox execution recovery artifact generation failed")
			return appendRecoveryArtifactMetadata(req.Store, executionID, result, artifact)
		}
	}

	localPath := filepath.Join(tempDir, filepath.Base(filepath.FromSlash(artifact.PayloadPath)))
	if err := req.Runtime.CopyOut(ctx, sandboxruntime.CopyRequest{
		Target:          req.Target,
		SourcePath:      artifact.RemotePath,
		DestinationPath: localPath,
	}); err != nil {
		addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, recoveryCopyOutWarningPhase, recoveryArtifactCopyOutWarningMessage(err))
		return appendRecoveryArtifactMetadata(req.Store, executionID, result, artifact)
	}

	collected, err := saveRuntimeArtifactFile(req.Store, executionID, artifact, localPath)
	if err != nil {
		addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, recoveryPersistWarningPhase, "sandbox execution recovery artifact persistence failed")
		return appendRecoveryArtifactMetadata(req.Store, executionID, result, artifact)
	}
	result.ArtifactMetadata.Collected = append(result.ArtifactMetadata.Collected, collected)
	return appendRecoveryArtifactMetadata(req.Store, executionID, result, artifact)
}

// CollectCommittedSyncOutArtifactBestEffort generates a patch containing only
// commits after the prepared workspace baseline. An empty patch is omitted;
// generation, copy, and persistence failures become durable handoff warnings.
func CollectCommittedSyncOutArtifactBestEffort(ctx context.Context, req CommittedSyncOutCollectionRequest) (RuntimeCollectionResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	executionID, err := validateExecutionID(req.ExecutionID)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if _, err := req.Store.LoadManifest(executionID); err != nil {
		return RuntimeCollectionResult{}, err
	}
	if req.Runtime == nil {
		return RuntimeCollectionResult{}, fmt.Errorf("sandbox execution artifact runtime is required")
	}
	artifact, err := committedSyncOutArtifactRequest(req.RemoteWorkspaceDir, req.SyncRef)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if err := validateRuntimeArtifactRequest(artifact); err != nil {
		return RuntimeCollectionResult{}, err
	}

	tempDir, err := os.MkdirTemp(req.TempDir, "hal-sandbox-sync-out-*")
	if err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("create sandbox execution sync-out temp dir: %w", redactPathError(err))
	}
	defer os.RemoveAll(tempDir)

	result := RuntimeCollectionResult{}
	if err := runRuntimeArtifactGeneration(ctx, req.Runtime, req.Target, *artifact.Generate); err != nil {
		addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, committedSyncOutGenerationWarningPhase, "sandbox committed sync-out artifact generation failed")
		return appendCommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
	}

	localPath := filepath.Join(tempDir, filepath.Base(filepath.FromSlash(artifact.PayloadPath)))
	if err := req.Runtime.CopyOut(ctx, sandboxruntime.CopyRequest{
		Target:          req.Target,
		SourcePath:      artifact.RemotePath,
		DestinationPath: localPath,
	}); err != nil {
		addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, committedSyncOutCopyOutWarningPhase, "sandbox committed sync-out artifact is missing")
		return appendCommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
	}
	info, err := os.Stat(localPath)
	if err != nil {
		addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, committedSyncOutPersistWarningPhase, "sandbox committed sync-out artifact inspection failed")
		return appendCommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
	}
	if info.Size() == 0 {
		return appendCommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
	}

	collected, err := saveRuntimeArtifactFile(req.Store, executionID, artifact, localPath)
	if err != nil {
		addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, committedSyncOutPersistWarningPhase, "sandbox committed sync-out artifact persistence failed")
		return appendCommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
	}
	result.ArtifactMetadata.Collected = append(result.ArtifactMetadata.Collected, collected)
	return appendCommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
}

// CollectUncommittedSyncOutArtifactBestEffort generates a handoff-only diff of
// tracked staged and unstaged changes. An empty diff is omitted; generation,
// copy, and persistence failures become durable handoff warnings.
func CollectUncommittedSyncOutArtifactBestEffort(ctx context.Context, req UncommittedSyncOutCollectionRequest) (RuntimeCollectionResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	executionID, err := validateExecutionID(req.ExecutionID)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if _, err := req.Store.LoadManifest(executionID); err != nil {
		return RuntimeCollectionResult{}, err
	}
	if req.Runtime == nil {
		return RuntimeCollectionResult{}, fmt.Errorf("sandbox execution artifact runtime is required")
	}
	artifact, err := uncommittedSyncOutArtifactRequest(req.RemoteWorkspaceDir)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if err := validateRuntimeArtifactRequest(artifact); err != nil {
		return RuntimeCollectionResult{}, err
	}

	tempDir, err := os.MkdirTemp(req.TempDir, "hal-sandbox-sync-out-uncommitted-*")
	if err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("create sandbox execution uncommitted sync-out temp dir: %w", redactPathError(err))
	}
	defer os.RemoveAll(tempDir)

	result := RuntimeCollectionResult{}
	if err := runRuntimeArtifactGeneration(ctx, req.Runtime, req.Target, *artifact.Generate); err != nil {
		addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, uncommittedSyncOutGenerationWarningPhase, "sandbox uncommitted sync-out artifact generation failed")
		return appendUncommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
	}

	localPath := filepath.Join(tempDir, filepath.Base(filepath.FromSlash(artifact.PayloadPath)))
	if err := req.Runtime.CopyOut(ctx, sandboxruntime.CopyRequest{
		Target:          req.Target,
		SourcePath:      artifact.RemotePath,
		DestinationPath: localPath,
	}); err != nil {
		addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, uncommittedSyncOutCopyOutWarningPhase, "sandbox uncommitted sync-out artifact is missing")
		return appendUncommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
	}
	info, err := os.Stat(localPath)
	if err != nil {
		addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, uncommittedSyncOutPersistWarningPhase, "sandbox uncommitted sync-out artifact inspection failed")
		return appendUncommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
	}
	if info.Size() == 0 {
		return appendUncommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
	}

	collected, err := saveRuntimeArtifactFile(req.Store, executionID, artifact, localPath)
	if err != nil {
		addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, uncommittedSyncOutPersistWarningPhase, "sandbox uncommitted sync-out artifact persistence failed")
		return appendUncommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
	}
	result.ArtifactMetadata.Collected = append(result.ArtifactMetadata.Collected, collected)
	return appendUncommittedSyncOutArtifactMetadata(req.Store, executionID, result, artifact)
}

// CollectUntrackedSyncOutArtifactsBestEffort generates a handoff-only tar
// archive and quoted file list for Git-visible untracked files. Empty output is
// omitted; generation, copy, and persistence failures become durable warnings.
func CollectUntrackedSyncOutArtifactsBestEffort(ctx context.Context, req UntrackedSyncOutCollectionRequest) (RuntimeCollectionResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	executionID, err := validateExecutionID(req.ExecutionID)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if _, err := req.Store.LoadManifest(executionID); err != nil {
		return RuntimeCollectionResult{}, err
	}
	if req.Runtime == nil {
		return RuntimeCollectionResult{}, fmt.Errorf("sandbox execution artifact runtime is required")
	}
	artifacts, err := untrackedSyncOutArtifactRequests(req.RemoteWorkspaceDir)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	for _, artifact := range artifacts {
		if err := validateRuntimeArtifactRequest(artifact); err != nil {
			return RuntimeCollectionResult{}, err
		}
	}

	tempDir, err := os.MkdirTemp(req.TempDir, "hal-sandbox-sync-out-untracked-*")
	if err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("create sandbox execution untracked sync-out temp dir: %w", redactPathError(err))
	}
	defer os.RemoveAll(tempDir)

	result := RuntimeCollectionResult{}
	if err := runRuntimeArtifactGeneration(ctx, req.Runtime, req.Target, *artifacts[0].Generate); err != nil {
		for _, artifact := range artifacts {
			addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, untrackedSyncOutGenerationWarningPhase, "sandbox untracked sync-out artifact generation failed")
		}
		return appendUntrackedSyncOutArtifactMetadata(req.Store, executionID, result, artifacts...)
	}

	for i, artifact := range artifacts {
		localPath := filepath.Join(tempDir, fmt.Sprintf("%03d-%s", i, filepath.Base(filepath.FromSlash(artifact.PayloadPath))))
		if err := req.Runtime.CopyOut(ctx, sandboxruntime.CopyRequest{
			Target:          req.Target,
			SourcePath:      artifact.RemotePath,
			DestinationPath: localPath,
		}); err != nil {
			addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, untrackedSyncOutCopyOutWarningPhase, "sandbox untracked sync-out artifact is missing")
			continue
		}
		info, err := os.Stat(localPath)
		if err != nil {
			addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, untrackedSyncOutPersistWarningPhase, "sandbox untracked sync-out artifact inspection failed")
			continue
		}
		if info.Size() == 0 {
			continue
		}

		collected, err := saveRuntimeArtifactFile(req.Store, executionID, artifact, localPath)
		if err != nil {
			addRuntimeArtifactPartialWarning(&result.ArtifactMetadata, artifact, untrackedSyncOutPersistWarningPhase, "sandbox untracked sync-out artifact persistence failed")
			continue
		}
		result.ArtifactMetadata.Collected = append(result.ArtifactMetadata.Collected, collected)
	}

	return appendUntrackedSyncOutArtifactMetadata(req.Store, executionID, result, artifacts...)
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
	if err := req.Store.UpsertArtifactMetadata(req.ExecutionID, result.ArtifactMetadata); err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("persist sandbox execution reports archive metadata: %w", err)
	}
	return result, nil
}

// SaveCommandOutputSummaryArtifacts stores sanitized stdout/stderr summaries
// under artifacts/ and records additive metadata on the execution manifest.
func SaveCommandOutputSummaryArtifacts(req CommandOutputSummaryArtifactsRequest) (RuntimeCollectionResult, error) {
	executionID, err := validateExecutionID(req.ExecutionID)
	if err != nil {
		return RuntimeCollectionResult{}, err
	}
	if _, err := req.Store.LoadManifest(executionID); err != nil {
		return RuntimeCollectionResult{}, err
	}

	summaries := []struct {
		value    string
		artifact ArtifactMetadataEntry
		payload  string
	}{
		{
			value: req.StdoutSummary,
			artifact: commandOutputSummaryArtifact(
				stdoutSummaryArtifactID,
				stdoutSummaryArtifactName,
				stdoutSummaryArtifactFileName,
			),
			payload: pathpkg.Join(commandOutputSummaryDir, stdoutSummaryArtifactFileName),
		},
		{
			value: req.StderrSummary,
			artifact: commandOutputSummaryArtifact(
				stderrSummaryArtifactID,
				stderrSummaryArtifactName,
				stderrSummaryArtifactFileName,
			),
			payload: pathpkg.Join(commandOutputSummaryDir, stderrSummaryArtifactFileName),
		},
	}

	result := RuntimeCollectionResult{}
	for _, summary := range summaries {
		if strings.TrimSpace(summary.value) == "" {
			continue
		}
		collected, err := saveCommandOutputSummaryArtifact(req.Store, executionID, summary.artifact, summary.payload, []byte(summary.value))
		if err != nil {
			return RuntimeCollectionResult{}, err
		}
		result.ArtifactMetadata.Collected = append(result.ArtifactMetadata.Collected, collected)
	}

	if err := req.Store.UpsertArtifactMetadata(executionID, result.ArtifactMetadata); err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("persist sandbox execution output summary metadata: %w", err)
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
	artifacts, err := coreStateArtifactRequests(req.Purpose, req.RemoteWorkspaceDir, req.RemoteArchivePath)
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
	if err := req.Store.UpsertArtifactMetadata(req.ExecutionID, result.ArtifactMetadata); err != nil {
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

func committedSyncOutArtifactRequest(remoteWorkspaceDir, syncRef string) (RuntimeArtifactRequest, error) {
	remoteWorkspaceDir = strings.TrimSpace(remoteWorkspaceDir)
	if remoteWorkspaceDir == "" {
		return RuntimeArtifactRequest{}, fmt.Errorf("sandbox execution remote workspace dir is required")
	}
	syncRef = strings.TrimSpace(syncRef)
	if syncRef == "" {
		return RuntimeArtifactRequest{}, fmt.Errorf("sandbox committed sync-out ref is required")
	}
	displayPath := pathpkg.Join(template.HalDir, committedSyncOutArtifactDir, committedSyncOutArtifactFileName)
	return RuntimeArtifactRequest{
		Artifact: ArtifactMetadataEntry{
			ID:   syncOutCommittedPatchID,
			Name: committedSyncOutArtifactName,
			Type: committedSyncOutArtifactType,
			Path: displayPath,
		},
		PayloadPath: pathpkg.Join(committedSyncOutArtifactDir, committedSyncOutArtifactFileName),
		RemotePath:  pathpkg.Join(remoteWorkspaceDir, displayPath),
		Generate: &RuntimeArtifactGeneration{
			Args:    []string{"sh", "-c", committedSyncOutPatchGenerationScript(), "hal-sync-out", syncRef},
			WorkDir: remoteWorkspaceDir,
		},
	}, nil
}

func uncommittedSyncOutArtifactRequest(remoteWorkspaceDir string) (RuntimeArtifactRequest, error) {
	remoteWorkspaceDir = strings.TrimSpace(remoteWorkspaceDir)
	if remoteWorkspaceDir == "" {
		return RuntimeArtifactRequest{}, fmt.Errorf("sandbox execution remote workspace dir is required")
	}
	displayPath := pathpkg.Join(template.HalDir, committedSyncOutArtifactDir, uncommittedSyncOutArtifactFileName)
	return RuntimeArtifactRequest{
		Artifact: ArtifactMetadataEntry{
			ID:   syncOutUncommittedDiffID,
			Name: uncommittedSyncOutArtifactName,
			Type: uncommittedSyncOutArtifactType,
			Path: displayPath,
		},
		PayloadPath: pathpkg.Join(committedSyncOutArtifactDir, uncommittedSyncOutArtifactFileName),
		RemotePath:  pathpkg.Join(remoteWorkspaceDir, displayPath),
		Generate: &RuntimeArtifactGeneration{
			Args:    []string{"sh", "-c", uncommittedSyncOutDiffGenerationScript()},
			WorkDir: remoteWorkspaceDir,
		},
	}, nil
}

func untrackedSyncOutArtifactRequests(remoteWorkspaceDir string) ([]RuntimeArtifactRequest, error) {
	remoteWorkspaceDir = strings.TrimSpace(remoteWorkspaceDir)
	if remoteWorkspaceDir == "" {
		return nil, fmt.Errorf("sandbox execution remote workspace dir is required")
	}
	archiveDisplayPath := pathpkg.Join(template.HalDir, committedSyncOutArtifactDir, untrackedSyncOutArchiveFileName)
	listDisplayPath := pathpkg.Join(template.HalDir, committedSyncOutArtifactDir, untrackedSyncOutListFileName)
	return []RuntimeArtifactRequest{
		{
			Artifact: ArtifactMetadataEntry{
				ID:   syncOutUntrackedArchiveID,
				Name: untrackedSyncOutArchiveName,
				Type: untrackedSyncOutArchiveType,
				Path: archiveDisplayPath,
			},
			PayloadPath: pathpkg.Join(committedSyncOutArtifactDir, untrackedSyncOutArchiveFileName),
			RemotePath:  pathpkg.Join(remoteWorkspaceDir, archiveDisplayPath),
			Generate: &RuntimeArtifactGeneration{
				Args:    []string{"sh", "-c", untrackedSyncOutArtifactsGenerationScript()},
				WorkDir: remoteWorkspaceDir,
			},
		},
		{
			Artifact: ArtifactMetadataEntry{
				ID:   syncOutUntrackedListID,
				Name: untrackedSyncOutListName,
				Type: untrackedSyncOutListType,
				Path: listDisplayPath,
			},
			PayloadPath: pathpkg.Join(committedSyncOutArtifactDir, untrackedSyncOutListFileName),
			RemotePath:  pathpkg.Join(remoteWorkspaceDir, listDisplayPath),
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

func committedSyncOutPatchGenerationScript() string {
	syncPath := pathpkg.Join(template.HalDir, committedSyncOutArtifactDir, committedSyncOutArtifactFileName)
	tmpPath := syncPath + ".tmp"
	return strings.Join([]string{
		"set -eu",
		`base_ref=$1`,
		fmt.Sprintf("sync_path=%q", syncPath),
		fmt.Sprintf("tmp_path=%q", tmpPath),
		fmt.Sprintf("mkdir -p %q", pathpkg.Dir(syncPath)),
		`rm -f "$tmp_path" "$sync_path"`,
		`case "$base_ref" in ""|-*) echo "invalid sandbox sync-out base ref" >&2; exit 2 ;; esac`,
		`base_commit=$(git rev-parse --verify "$base_ref^{commit}")`,
		`git diff --binary --no-ext-diff "$base_commit"..HEAD -- > "$tmp_path"`,
		`mv "$tmp_path" "$sync_path"`,
	}, "\n")
}

func uncommittedSyncOutDiffGenerationScript() string {
	syncPath := pathpkg.Join(template.HalDir, committedSyncOutArtifactDir, uncommittedSyncOutArtifactFileName)
	tmpPath := syncPath + ".tmp"
	return strings.Join([]string{
		"set -eu",
		fmt.Sprintf("sync_path=%q", syncPath),
		fmt.Sprintf("tmp_path=%q", tmpPath),
		fmt.Sprintf("mkdir -p %q", pathpkg.Dir(syncPath)),
		`rm -f "$tmp_path" "$sync_path"`,
		"if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then",
		"\t{",
		"\t\tgit diff --binary --no-ext-diff",
		"\t\tgit diff --cached --binary --no-ext-diff",
		"\t} > \"$tmp_path\"",
		"else",
		"\t: > \"$tmp_path\"",
		"fi",
		`mv "$tmp_path" "$sync_path"`,
	}, "\n")
}

func untrackedSyncOutArtifactsGenerationScript() string {
	archivePath := pathpkg.Join(template.HalDir, committedSyncOutArtifactDir, untrackedSyncOutArchiveFileName)
	listPath := pathpkg.Join(template.HalDir, committedSyncOutArtifactDir, untrackedSyncOutListFileName)
	return strings.Join([]string{
		"set -eu",
		fmt.Sprintf("archive_path=%q", archivePath),
		fmt.Sprintf("list_path=%q", listPath),
		`nul_tmp=$(git rev-parse --git-path hal-sync-out-untracked.nul)`,
		`archive_tmp=$(git rev-parse --git-path hal-sync-out-untracked.tar)`,
		`list_tmp=$(git rev-parse --git-path hal-sync-out-untracked.txt)`,
		`cleanup() { rm -f "$nul_tmp" "$archive_tmp" "$list_tmp"; }`,
		`trap cleanup EXIT HUP INT TERM`,
		fmt.Sprintf("mkdir -p %q", pathpkg.Dir(archivePath)),
		`rm -f "$archive_path" "$list_path"`,
		`cleanup`,
		`git ls-files --others --exclude-standard -z -- . ':(exclude).hal' ':(exclude).hal/**' > "$nul_tmp"`,
		`if [ -s "$nul_tmp" ]; then`,
		`  git ls-files --others --exclude-standard -- . ':(exclude).hal' ':(exclude).hal/**' > "$list_tmp"`,
		`  tar --create --file="$archive_tmp" --null --verbatim-files-from --files-from="$nul_tmp"`,
		`else`,
		`  : > "$list_tmp"`,
		`  : > "$archive_tmp"`,
		`fi`,
		`mv "$archive_tmp" "$archive_path"`,
		`mv "$list_tmp" "$list_path"`,
		`rm -f "$nul_tmp"`,
		`trap - EXIT HUP INT TERM`,
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

func coreStateArtifactRequests(purpose Purpose, remoteWorkspaceDir string, remoteArchivePath string) ([]RuntimeArtifactRequest, error) {
	remoteWorkspaceDir = strings.TrimSpace(remoteWorkspaceDir)
	if remoteWorkspaceDir == "" {
		return nil, fmt.Errorf("sandbox execution remote workspace dir is required")
	}
	remoteStateDir := pathpkg.Join(remoteWorkspaceDir, template.HalDir)
	if purpose == PurposeAuto && strings.TrimSpace(remoteArchivePath) != "" {
		remoteArchivePath = strings.TrimSpace(remoteArchivePath)
		if err := ValidateAutoArchivePath(remoteArchivePath); err != nil {
			return nil, err
		}
		remoteStateDir = pathpkg.Join(remoteWorkspaceDir, remoteArchivePath)
	}
	artifacts := []RuntimeArtifactRequest{
		coreStateArtifactRequest("prd", "PRD", "json", template.PRDFile, "hal-prd.json", remoteStateDir),
		coreStateArtifactRequest("progress", "Progress", "text", template.ProgressFile, "hal-progress.txt", remoteStateDir),
	}
	if purpose == PurposeAuto {
		artifacts = append(artifacts, coreStateArtifactRequest("auto-state", "Auto State", "json", template.AutoStateFile, "hal-auto-state.json", remoteStateDir))
	}
	return artifacts, nil
}

// ValidateAutoArchivePath restricts a remote auto result to the single archive
// directory shape produced by archive.CreateWithOptions.
func ValidateAutoArchivePath(archivePath string) error {
	archivePath = strings.TrimSpace(archivePath)
	if archivePath == "" {
		return nil
	}
	if strings.Contains(archivePath, "\\") {
		return fmt.Errorf("sandbox auto archive path must use slash separators")
	}
	if pathpkg.IsAbs(archivePath) {
		return fmt.Errorf("sandbox auto archive path must be relative")
	}
	if clean := pathpkg.Clean(archivePath); clean != archivePath {
		return fmt.Errorf("sandbox auto archive path must be clean and traversal-free")
	}
	archiveRoot := pathpkg.Join(template.HalDir, "archive")
	if pathpkg.Dir(archivePath) != archiveRoot || pathpkg.Base(archivePath) == "." {
		return fmt.Errorf("sandbox auto archive path must name a direct child of %s", archiveRoot)
	}
	return nil
}

func coreStateArtifactRequest(id, name, artifactType, fileName, payloadName, remoteStateDir string) RuntimeArtifactRequest {
	displayPath := pathpkg.Join(template.HalDir, fileName)
	return RuntimeArtifactRequest{
		Artifact: ArtifactMetadataEntry{
			ID:   id,
			Name: name,
			Type: artifactType,
			Path: displayPath,
		},
		PayloadPath: pathpkg.Join("core", payloadName),
		RemotePath:  pathpkg.Join(remoteStateDir, fileName),
	}
}

func commandOutputSummaryArtifact(id, name, fileName string) ArtifactMetadataEntry {
	return ArtifactMetadataEntry{
		ID:   id,
		Name: name,
		Type: commandOutputSummaryArtifactType,
		Path: pathpkg.Join(commandOutputSummaryDir, fileName),
	}
}

func saveCommandOutputSummaryArtifact(store Store, executionID string, artifact ArtifactMetadataEntry, payloadPath string, data []byte) (ArtifactMetadataEntry, error) {
	if err := validateArtifactFileMetadataInput(artifact); err != nil {
		return ArtifactMetadataEntry{}, err
	}
	if _, err := validatePayloadPath(payloadPath); err != nil {
		return ArtifactMetadataEntry{}, err
	}
	stored, err := store.WriteArtifactPayload(executionID, payloadPath, data)
	if err != nil {
		return ArtifactMetadataEntry{}, fmt.Errorf("save sandbox execution output summary payload: %w", err)
	}
	artifact = artifactMetadataWithStoredFile(artifact, stored)
	if err := validateArtifactMetadataEntry(executionID, artifact, true); err != nil {
		return ArtifactMetadataEntry{}, err
	}
	return artifact, nil
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

func appendRecoveryArtifactMetadata(store Store, executionID string, result RuntimeCollectionResult, attempted ...RuntimeArtifactRequest) (RuntimeCollectionResult, error) {
	if err := replaceRuntimeArtifactAttemptMetadata(store, executionID, result.ArtifactMetadata, attempted); err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("persist sandbox execution recovery metadata: %w", err)
	}
	return result, nil
}

func appendCommittedSyncOutArtifactMetadata(store Store, executionID string, result RuntimeCollectionResult, attempted ...RuntimeArtifactRequest) (RuntimeCollectionResult, error) {
	if err := replaceRuntimeArtifactAttemptMetadata(store, executionID, result.ArtifactMetadata, attempted); err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("persist sandbox execution committed sync-out metadata: %w", err)
	}
	return result, nil
}

func appendUncommittedSyncOutArtifactMetadata(store Store, executionID string, result RuntimeCollectionResult, attempted ...RuntimeArtifactRequest) (RuntimeCollectionResult, error) {
	if err := replaceRuntimeArtifactAttemptMetadata(store, executionID, result.ArtifactMetadata, attempted); err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("persist sandbox execution uncommitted sync-out metadata: %w", err)
	}
	return result, nil
}

func appendUntrackedSyncOutArtifactMetadata(store Store, executionID string, result RuntimeCollectionResult, attempted ...RuntimeArtifactRequest) (RuntimeCollectionResult, error) {
	if err := replaceRuntimeArtifactAttemptMetadata(store, executionID, result.ArtifactMetadata, attempted); err != nil {
		return RuntimeCollectionResult{}, fmt.Errorf("persist sandbox execution untracked sync-out metadata: %w", err)
	}
	return result, nil
}

func replaceRuntimeArtifactAttemptMetadata(
	store Store,
	executionID string,
	metadata ArtifactMetadata,
	attempted []RuntimeArtifactRequest,
) error {
	artifacts := make([]ArtifactMetadataEntry, 0, len(attempted))
	for _, request := range attempted {
		artifacts = append(artifacts, request.Artifact)
	}
	return store.ReplaceArtifactAttemptMetadata(executionID, artifacts, metadata)
}

func recoveryArtifactCopyOutWarningMessage(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "sandbox execution recovery artifact is missing"
	}
	return "sandbox execution recovery artifact copy failed"
}

func runtimeArtifactCopyOutWarningMessage(err error) string {
	if errors.Is(err, fs.ErrNotExist) {
		return "optional sandbox execution artifact is missing"
	}
	return "optional sandbox execution artifact copy failed"
}

func requiredRuntimeArtifactCopyOutWarningMessage(req RuntimeArtifactRequest, err error) string {
	if req.Artifact.ID == recoveryArtifactID {
		return recoveryArtifactCopyOutWarningMessage(err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return "sandbox execution artifact is missing"
	}
	return "sandbox execution artifact copy failed"
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
