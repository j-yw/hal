package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandboxruntime"
)

type factoryRuntimeSandboxArtifactCopier struct {
	driver  sandboxruntime.Driver
	target  sandboxruntime.Target
	baseDir string
}

func (c *factoryRuntimeSandboxArtifactCopier) CopyFile(ctx context.Context, remotePath, localPath string) error {
	resolved, err := c.resolveSandboxArtifactPath(remotePath)
	if err != nil {
		return err
	}
	exists, err := c.pathExists(ctx, resolved.resolvedPath, "-f")
	if err != nil {
		return err
	}
	if !exists {
		return factory.ErrSandboxArtifactNotFound
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return fmt.Errorf("create sandbox artifact destination: %w", err)
	}
	if err := c.driver.CopyOut(ctx, sandboxruntime.CopyRequest{
		Target:          c.target,
		SourcePath:      resolved.resolvedPath,
		DestinationPath: localPath,
	}); err != nil {
		_ = os.Remove(localPath)
		return fmt.Errorf("copy sandbox artifact file: %w", err)
	}
	return nil
}

func (c *factoryRuntimeSandboxArtifactCopier) CopyDir(ctx context.Context, remotePath, localPath string) error {
	resolved, err := c.resolveSandboxArtifactPath(remotePath)
	if err != nil {
		return err
	}
	exists, err := c.pathExists(ctx, resolved.resolvedPath, "-d")
	if err != nil {
		return err
	}
	if !exists {
		return factory.ErrSandboxArtifactNotFound
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return fmt.Errorf("create sandbox artifact destination: %w", err)
	}
	remoteTar := pathpkg.Join("/tmp", factorySandboxRemoteTempBase(resolved.resolvedPath, nil)+".tar")
	if _, err := c.driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: c.target,
		Args: []string{
			"sh", "-c",
			"set -eu\nrm -f " + shellQuote(remoteTar) + "\ntar -C " + shellQuote(resolved.resolvedPath) + " -cf " + shellQuote(remoteTar) + " .",
		},
		Stdout: io.Discard,
		Stderr: io.Discard,
	}); err != nil {
		return fmt.Errorf("archive sandbox artifact directory: %w", err)
	}
	defer c.removeRemoteTemp(ctx, remoteTar)

	tarFile, err := os.CreateTemp(filepath.Dir(localPath), "sandbox-runtime-artifact-*.tar")
	if err != nil {
		return fmt.Errorf("create sandbox artifact archive: %w", err)
	}
	tarPath := tarFile.Name()
	if err := tarFile.Close(); err != nil {
		_ = os.Remove(tarPath)
		return fmt.Errorf("create sandbox artifact archive: %w", err)
	}
	defer os.Remove(tarPath)
	if err := c.driver.CopyOut(ctx, sandboxruntime.CopyRequest{
		Target:          c.target,
		SourcePath:      remoteTar,
		DestinationPath: tarPath,
	}); err != nil {
		return fmt.Errorf("copy sandbox artifact directory archive: %w", err)
	}
	if err := extractFactorySandboxArtifactTar(tarPath, localPath); err != nil {
		_ = os.RemoveAll(localPath)
		return err
	}
	return nil
}

func (c *factoryRuntimeSandboxArtifactCopier) resolveSandboxArtifactPath(remotePath string) (factorySandboxArtifactRemotePath, error) {
	return (&factorySandboxArtifactCopier{baseDir: c.baseDir}).resolveSandboxArtifactPath(remotePath)
}

func (c *factoryRuntimeSandboxArtifactCopier) pathExists(ctx context.Context, remotePath, testFlag string) (bool, error) {
	if c == nil || c.driver == nil {
		return false, fmt.Errorf("sandbox runtime artifact copier requires a driver")
	}
	result, err := c.driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target: c.target,
		Args:   []string{"test", testFlag, remotePath},
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	if err == nil {
		return true, nil
	}
	if result != nil && result.ExitCode == 1 {
		return false, nil
	}
	return false, fmt.Errorf("inspect sandbox artifact path: %w", err)
}

func (c *factoryRuntimeSandboxArtifactCopier) removeRemoteTemp(ctx context.Context, remotePath string) {
	if c == nil || c.driver == nil || strings.TrimSpace(remotePath) == "" {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, _ = c.driver.Exec(cleanupCtx, sandboxruntime.ExecRequest{
		Target: c.target,
		Args:   []string{"rm", "-f", remotePath},
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
}
