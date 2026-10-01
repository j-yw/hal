package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
	"github.com/jywlabs/hal/internal/sandboxexec"
	"github.com/jywlabs/hal/internal/sandboxworkspace"
	"github.com/jywlabs/hal/internal/template"
)

// Provider bootstrap checks out the repository before it runs hal init. Copy
// here, not before bootstrap, so a clone/checkout cannot overwrite host config.
type factorySandboxConfigBootstrapExecutor struct {
	Executor   factory.BootstrapCommandExecutor
	copyConfig func(context.Context) error
}

func (e *factorySandboxConfigBootstrapExecutor) Run(ctx context.Context, command factory.BootstrapCommand) (factory.BootstrapCommandResult, error) {
	if command.Name == "hal" && len(command.Args) > 0 && command.Args[0] == "init" {
		if err := e.copyConfig(ctx); err != nil {
			return factory.BootstrapCommandResult{}, err
		}
	}
	return e.Executor.Run(ctx, command)
}

func factorySandboxConfigExists(projectDir string) (bool, error) {
	info, err := os.Lstat(filepath.Join(projectDir, template.HalDir, template.ConfigFile))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("inspect factory sandbox config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("factory sandbox config is not a regular file")
	}
	return true, nil
}

func factorySandboxCopyConfigToRemote(ctx context.Context, projectDir, workspaceDir string, provider sandbox.Provider, connectInfo *sandbox.ConnectInfo, out io.Writer, deps factorySandboxExecutorDeps) error {
	exists, err := factorySandboxConfigExists(projectDir)
	if err != nil || !exists {
		return err
	}
	_, _, err = factorySandboxCopyInputToRemoteWithMode(ctx, projectDir, filepath.Join(template.HalDir, template.ConfigFile), workspaceDir, provider, connectInfo, out, deps, "0644")
	return err
}

func factorySandboxCopyConfigRuntime(ctx context.Context, prep sandboxexec.PrepareContext, projectDir, workspaceDir string) error {
	exists, err := factorySandboxConfigExists(projectDir)
	if err != nil || !exists {
		return err
	}
	return copySandboxBundleCommandContextFileWithMode(ctx, prep, filepath.Join(projectDir, template.HalDir, template.ConfigFile), workspaceDir, template.ConfigFile, "0644")
}

func prepareFactorySandboxCommandContextRuntime(ctx context.Context, prep sandboxexec.PrepareContext, projectDir, workspaceDir string, out io.Writer) (sandboxworkspace.MaterializationOperation, error) {
	if err := factorySandboxCopyConfigRuntime(ctx, prep, projectDir, workspaceDir); err != nil {
		return sandboxworkspace.MaterializationOperation{}, err
	}
	// The generic run/auto context resets missing files. Factory's config is an
	// optional overlay: absence must leave a committed config untouched.
	files := make([]string, 0, len(sandboxCommandContextFiles)-1)
	for _, name := range sandboxCommandContextFiles {
		if name != template.ConfigFile {
			files = append(files, name)
		}
	}
	return prepareSandboxCommandContextFilesRuntime(ctx, prep, projectDir, workspaceDir, out, files)
}
