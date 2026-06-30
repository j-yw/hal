package sandboxexec

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
)

// WorkspaceMaterializationRequest carries command-prepared workspace metadata
// into the shared sandbox workspace materialization helper.
type WorkspaceMaterializationRequest struct {
	Workspace            sandbox.SandboxWorkspace
	ProjectDir           string
	WorkspaceDir         string
	BundleDir            string
	BundleDestinationDir string
	LocalGit             sandboxworkspace.LocalGit
}

// MaterializeBundleWorkspace creates, copies, and applies a git-bundle
// workspace using the already resolved sandbox runtime driver.
func MaterializeBundleWorkspace(ctx context.Context, prep PrepareContext, req WorkspaceMaterializationRequest) (sandboxworkspace.MaterializationResult, error) {
	if prep.Driver == nil {
		return sandboxworkspace.MaterializationResult{}, fmt.Errorf("sandbox runtime driver is required")
	}
	localGit := req.LocalGit
	if localGit == nil {
		localGit = sandboxworkspace.GitCLIInspector{}
	}
	plan := workspacePlanFromMetadata(req.Workspace, req.ProjectDir)
	return (sandboxworkspace.BundleMaterializer{
		LocalGit:  localGit,
		Remote:    RuntimeWorkspaceClient{Driver: prep.Driver, Target: prep.Target},
		BundleDir: req.BundleDir,
	}).MaterializeWorkspace(ctx, sandboxworkspace.MaterializeRequest{
		Plan:                 plan,
		Target:               remoteTargetFromRuntime(prep.Target),
		WorkspaceDir:         req.WorkspaceDir,
		BundleDestinationDir: req.BundleDestinationDir,
	})
}

// RuntimeWorkspaceClient adapts sandboxruntime.Driver file and exec operations
// to sandboxworkspace's narrow remote client.
type RuntimeWorkspaceClient struct {
	Driver sandboxruntime.Driver
	Target sandboxruntime.Target
}

func (c RuntimeWorkspaceClient) CopyIn(ctx context.Context, req sandboxworkspace.RemoteCopyRequest) error {
	if c.Driver == nil {
		return fmt.Errorf("sandbox runtime driver is required")
	}
	return c.Driver.CopyIn(ctx, sandboxruntime.CopyRequest{
		Target:          c.Target,
		SourcePath:      req.SourcePath,
		DestinationPath: req.DestinationPath,
	})
}

func (c RuntimeWorkspaceClient) Exec(ctx context.Context, req sandboxworkspace.RemoteCommandRequest) (sandboxworkspace.RemoteCommandResult, error) {
	if c.Driver == nil {
		return sandboxworkspace.RemoteCommandResult{}, fmt.Errorf("sandbox runtime driver is required")
	}
	result, err := c.Driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target:  c.Target,
		Args:    append([]string(nil), req.Args...),
		WorkDir: req.WorkDir,
		Env:     cloneStringMap(req.Env),
		Stdin:   req.Stdin,
		Stdout:  writerOrDiscard(req.Stdout),
		Stderr:  writerOrDiscard(req.Stderr),
	})
	if err != nil {
		return sandboxworkspace.RemoteCommandResult{}, err
	}
	if result == nil {
		return sandboxworkspace.RemoteCommandResult{}, nil
	}
	return sandboxworkspace.RemoteCommandResult{ExitCode: result.ExitCode}, nil
}

func workspacePlanFromMetadata(workspace sandbox.SandboxWorkspace, projectDir string) sandboxworkspace.Plan {
	mode := strings.TrimSpace(workspace.Mode)
	if mode == "" {
		mode = sandbox.SandboxWorkspaceModeClone
	}
	inputSource := strings.TrimSpace(workspace.InputSource)
	return sandboxworkspace.Plan{
		Mode:           mode,
		InputSource:    inputSource,
		ProjectDir:     strings.TrimSpace(projectDir),
		Repository:     strings.TrimSpace(workspace.Repo),
		Branch:         strings.TrimSpace(workspace.Branch),
		SyncRef:        strings.TrimSpace(workspace.SyncRef),
		RequiresBundle: inputSource == sandbox.SandboxWorkspaceInputSourceGitBundle,
	}
}

func remoteTargetFromRuntime(target sandboxruntime.Target) sandboxworkspace.RemoteTarget {
	return sandboxworkspace.RemoteTarget{
		ID:            strings.TrimSpace(target.ID),
		Name:          strings.TrimSpace(target.Name),
		Provider:      strings.TrimSpace(target.Provider),
		RuntimeDriver: strings.TrimSpace(target.Runtime.Driver),
		Address:       strings.TrimSpace(target.Connection.Address),
		WorkspaceID:   strings.TrimSpace(target.Connection.WorkspaceID),
	}
}

func writerOrDiscard(writer io.Writer) io.Writer {
	if writer == nil {
		return io.Discard
	}
	return writer
}
