package sandboxworkspace

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/jywlabs/hal/internal/sandbox"
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

// PrepareLocalBundleRequest carries the bundle-backed workspace plan plus a
// host-local directory controlled by the sync primitive.
type PrepareLocalBundleRequest struct {
	Plan      Plan
	BundleDir string
}

// CopyLocalBundleRequest carries a verified host-local bundle plus the sandbox
// destination where it should be copied.
type CopyLocalBundleRequest struct {
	Plan                 Plan
	Target               RemoteTarget
	Bundle               LocalBundleResult
	BundleDestinationDir string
}

// LocalBundleResult carries host-local bundle state for the next sync step.
// LocalPath is intentionally excluded from JSON because durable metadata must
// use Bundle instead.
type LocalBundleResult struct {
	LocalPath  string `json:"-"`
	ID         string `json:"id,omitempty"`
	SyncRef    string `json:"syncRef,omitempty"`
	Bundle     *BundleMaterialization
	Operations []MaterializationOperation
}

// RemoteBundleResult carries redaction-safe bundle metadata after copy-in.
type RemoteBundleResult struct {
	Bundle     *BundleMaterialization
	Operations []MaterializationOperation
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

// PrepareLocalBundle validates a bundle-backed plan, chooses a deterministic
// host-local bundle path, then delegates create and verify behavior to LocalGit.
func PrepareLocalBundle(ctx context.Context, git LocalGit, req PrepareLocalBundleRequest) (LocalBundleResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if git == nil {
		return LocalBundleResult{}, ErrLocalGitRequired
	}
	plan := req.Plan
	if plan.Dirty.Any() {
		return LocalBundleResult{}, planningError(ErrDirtyWorktree, Request{
			ProjectDir:    plan.ProjectDir,
			WorkspaceMode: plan.Mode,
		}, plan.Dirty, nil)
	}
	if strings.TrimSpace(plan.InputSource) != sandbox.SandboxWorkspaceInputSourceGitBundle {
		return LocalBundleResult{}, ErrGitBundlePlanRequired
	}

	bundleID := localBundleID(plan)
	bundlePath, err := localBundlePath(req.BundleDir, bundleID)
	if err != nil {
		return LocalBundleResult{}, err
	}
	createResult, err := git.CreateBundle(ctx, CreateBundleRequest{
		Plan:            plan,
		DestinationPath: bundlePath,
	})
	if err != nil {
		return LocalBundleResult{}, fmt.Errorf("workspace bundle create: %w", err)
	}
	createResult.Path = firstNonEmpty(createResult.Path, bundlePath)
	createResult.ID = firstNonEmpty(createResult.ID, bundleID)
	createResult.SyncRef = firstNonEmpty(createResult.SyncRef, plan.SyncRef)

	if err := git.VerifyBundle(ctx, VerifyBundleRequest{
		Plan:    plan,
		Path:    createResult.Path,
		SyncRef: createResult.SyncRef,
	}); err != nil {
		return LocalBundleResult{}, fmt.Errorf("workspace bundle verify: %w", err)
	}

	operations := []MaterializationOperation{
		{Phase: MaterializationPhaseBundleCreate, Summary: "created local git bundle"},
		{Phase: MaterializationPhaseBundleVerify, Summary: "verified local git bundle"},
	}
	return LocalBundleResult{
		LocalPath:  createResult.Path,
		ID:         createResult.ID,
		SyncRef:    createResult.SyncRef,
		Bundle:     BundleMaterializationFromCreateResult(createResult, ""),
		Operations: operations,
	}, nil
}

// CopyLocalBundle copies a verified host-local bundle into the sandbox through
// the narrow remote copy boundary and returns sandbox-safe metadata only.
func CopyLocalBundle(ctx context.Context, remote RemoteCopier, req CopyLocalBundleRequest) (RemoteBundleResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if remote == nil {
		return RemoteBundleResult{}, ErrRemoteCopierRequired
	}
	plan := req.Plan
	if strings.TrimSpace(plan.InputSource) != sandbox.SandboxWorkspaceInputSourceGitBundle {
		return RemoteBundleResult{}, ErrGitBundlePlanRequired
	}
	localPath := strings.TrimSpace(req.Bundle.LocalPath)
	if localPath == "" {
		return RemoteBundleResult{}, ErrLocalBundleRequired
	}

	bundleID := firstNonEmpty(req.Bundle.ID, bundleIDFromMaterialization(req.Bundle.Bundle), localBundleID(plan))
	syncRef := firstNonEmpty(req.Bundle.SyncRef, bundleSyncRefFromMaterialization(req.Bundle.Bundle), plan.SyncRef)
	remotePath := remoteBundlePath(req.BundleDestinationDir, bundleID)
	if err := remote.CopyIn(ctx, RemoteCopyRequest{
		Target:          req.Target,
		SourcePath:      localPath,
		DestinationPath: remotePath,
	}); err != nil {
		return RemoteBundleResult{}, fmt.Errorf("workspace bundle copy: %w", sanitizedRemoteOperationError("remote copy", err))
	}

	bundle := BundleMaterializationFromCreateResult(CreateBundleResult{
		ID:      bundleID,
		SyncRef: syncRef,
	}, remotePath)
	operations := cloneMaterializationOperations(req.Bundle.Operations)
	operations = append(operations, MaterializationOperation{
		Phase:   MaterializationPhaseBundleCopy,
		Summary: "copied git bundle to sandbox",
	})
	return RemoteBundleResult{
		Bundle:     bundle,
		Operations: operations,
	}, nil
}

func localBundlePath(bundleDir string, bundleID string) (string, error) {
	bundleDir = strings.TrimSpace(bundleDir)
	if bundleDir == "" {
		bundleDir = filepath.Join(os.TempDir(), "hal-workspace-bundles")
	}
	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		return "", fmt.Errorf("workspace bundle directory: %w", err)
	}
	return filepath.Join(bundleDir, bundleID+".bundle"), nil
}

func remoteBundlePath(destinationDir string, bundleID string) string {
	destinationDir = strings.TrimSpace(destinationDir)
	if destinationDir == "" {
		destinationDir = "/tmp/hal-workspace-bundles"
	}
	fileName := safeBundleSegment(bundleID)
	if !strings.HasSuffix(fileName, ".bundle") {
		fileName += ".bundle"
	}
	return path.Join(destinationDir, fileName)
}

func localBundleID(plan Plan) string {
	return safeBundleSegment(firstNonEmpty(plan.SyncRef, plan.Branch, "HEAD"))
}

func bundleIDFromMaterialization(bundle *BundleMaterialization) string {
	if bundle == nil {
		return ""
	}
	return bundle.ID
}

func bundleSyncRefFromMaterialization(bundle *BundleMaterialization) string {
	if bundle == nil {
		return ""
	}
	return bundle.SyncRef
}

func sanitizedRemoteOperationError(operation string, err error) error {
	detail := sanitizePathDetail(err.Error())
	if detail == "" {
		return fmt.Errorf("%s failed", operation)
	}
	return fmt.Errorf("%s failed: %s", operation, detail)
}

func safeBundleSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "HEAD"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range value {
		switch {
		case r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
			lastDash = false
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	safe := strings.Trim(b.String(), "-.")
	if safe == "" {
		return "HEAD"
	}
	return safe
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
