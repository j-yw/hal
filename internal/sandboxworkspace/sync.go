package sandboxworkspace

import (
	"context"
	"io"
	"strings"
)

// WorkspaceMaterializer materializes a planned workspace into a sandbox target.
type WorkspaceMaterializer interface {
	MaterializeWorkspace(context.Context, MaterializeRequest) (MaterializationResult, error)
}

// MaterializerFunc adapts a function to WorkspaceMaterializer.
type MaterializerFunc func(context.Context, MaterializeRequest) (MaterializationResult, error)

func (f MaterializerFunc) MaterializeWorkspace(ctx context.Context, req MaterializeRequest) (MaterializationResult, error) {
	return f(ctx, req)
}

// LocalGit is the host-side Git boundary required for bundle-backed materialization.
type LocalGit interface {
	CreateBundle(context.Context, CreateBundleRequest) (CreateBundleResult, error)
	VerifyBundle(context.Context, VerifyBundleRequest) error
}

// RemoteCopier copies files from the host into a sandbox target.
type RemoteCopier interface {
	CopyIn(context.Context, RemoteCopyRequest) error
}

// RemoteCommandRunner runs commands inside a sandbox target.
type RemoteCommandRunner interface {
	Exec(context.Context, RemoteCommandRequest) (RemoteCommandResult, error)
}

// RemoteClient combines the narrow remote operations needed by workspace sync.
type RemoteClient interface {
	RemoteCopier
	RemoteCommandRunner
}

// MaterializeRequest carries a workspace plan and command-agnostic target data.
type MaterializeRequest struct {
	Plan                 Plan
	Target               RemoteTarget
	WorkspaceDir         string
	BundleDestinationDir string
}

// RemoteTarget identifies a sandbox target without depending on provider structs.
type RemoteTarget struct {
	ID            string
	Name          string
	Provider      string
	RuntimeDriver string
	Address       string
	WorkspaceID   string
}

// CreateBundleRequest asks the local Git adapter to create a bundle for a plan.
type CreateBundleRequest struct {
	Plan            Plan
	DestinationPath string
}

// CreateBundleResult returns the local bundle path plus safe identifiers.
type CreateBundleResult struct {
	Path    string
	ID      string
	SyncRef string
}

// VerifyBundleRequest asks the local Git adapter to verify a bundle.
type VerifyBundleRequest struct {
	Plan    Plan
	Path    string
	SyncRef string
}

// RemoteCopyRequest describes a host-to-sandbox file copy.
type RemoteCopyRequest struct {
	Target          RemoteTarget
	SourcePath      string
	DestinationPath string
}

// RemoteCommandRequest describes a command run inside a sandbox target.
type RemoteCommandRequest struct {
	Target  RemoteTarget
	Args    []string
	WorkDir string
	Env     map[string]string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// RemoteCommandResult describes a completed remote command.
type RemoteCommandResult struct {
	ExitCode int
}

type MaterializationPhase string

const (
	MaterializationPhaseRemoteRef     MaterializationPhase = "remote_ref"
	MaterializationPhaseBundleCreate  MaterializationPhase = "bundle_create"
	MaterializationPhaseBundleVerify  MaterializationPhase = "bundle_verify"
	MaterializationPhaseBundleCopy    MaterializationPhase = "bundle_copy"
	MaterializationPhaseBundleApply   MaterializationPhase = "bundle_apply"
	MaterializationPhaseCommandConfig MaterializationPhase = "command_config"
)

// MaterializationResult is redaction-safe metadata about a materialized workspace.
type MaterializationResult struct {
	Mode         string                     `json:"mode"`
	InputSource  string                     `json:"inputSource"`
	Repository   string                     `json:"repo"`
	Branch       string                     `json:"branch"`
	SyncRef      string                     `json:"syncRef"`
	WorkspaceDir string                     `json:"workspaceDir,omitempty"`
	Bundle       *BundleMaterialization     `json:"bundle,omitempty"`
	Operations   []MaterializationOperation `json:"operations,omitempty"`
}

// MaterializationDetails carries safe metadata collected during materialization.
type MaterializationDetails struct {
	WorkspaceDir string
	Bundle       *BundleMaterialization
	Operations   []MaterializationOperation
}

// BundleMaterialization omits host-local bundle paths and stores sandbox-safe identifiers only.
type BundleMaterialization struct {
	ID         string `json:"id,omitempty"`
	RemotePath string `json:"remotePath,omitempty"`
	SyncRef    string `json:"syncRef,omitempty"`
}

// MaterializationOperation records a high-level sync step without raw command output.
type MaterializationOperation struct {
	Phase   MaterializationPhase `json:"phase"`
	Summary string               `json:"summary,omitempty"`
}

// NewMaterializationResult maps plan metadata plus safe materialization details
// into the result shape used by command manifests and future sync callers.
func NewMaterializationResult(plan Plan, details MaterializationDetails) MaterializationResult {
	return MaterializationResult{
		Mode:         strings.TrimSpace(plan.Mode),
		InputSource:  strings.TrimSpace(plan.InputSource),
		Repository:   strings.TrimSpace(plan.Repository),
		Branch:       strings.TrimSpace(plan.Branch),
		SyncRef:      strings.TrimSpace(plan.SyncRef),
		WorkspaceDir: strings.TrimSpace(details.WorkspaceDir),
		Bundle:       cloneBundleMaterialization(details.Bundle),
		Operations:   cloneMaterializationOperations(details.Operations),
	}
}

// BundleMaterializationFromCreateResult converts a local bundle result to safe
// durable metadata, intentionally dropping CreateBundleResult.Path.
func BundleMaterializationFromCreateResult(result CreateBundleResult, remotePath string) *BundleMaterialization {
	return &BundleMaterialization{
		ID:         strings.TrimSpace(result.ID),
		RemotePath: strings.TrimSpace(remotePath),
		SyncRef:    strings.TrimSpace(result.SyncRef),
	}
}

func cloneBundleMaterialization(bundle *BundleMaterialization) *BundleMaterialization {
	if bundle == nil {
		return nil
	}
	cloned := *bundle
	cloned.ID = strings.TrimSpace(cloned.ID)
	cloned.RemotePath = strings.TrimSpace(cloned.RemotePath)
	cloned.SyncRef = strings.TrimSpace(cloned.SyncRef)
	return &cloned
}

func cloneMaterializationOperations(operations []MaterializationOperation) []MaterializationOperation {
	if len(operations) == 0 {
		return nil
	}
	cloned := make([]MaterializationOperation, 0, len(operations))
	for _, operation := range operations {
		cloned = append(cloned, MaterializationOperation{
			Phase:   operation.Phase,
			Summary: strings.TrimSpace(operation.Summary),
		})
	}
	return cloned
}
