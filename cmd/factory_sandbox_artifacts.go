package cmd

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

type factorySandboxArtifactCopier struct {
	provider sandbox.Provider
	info     *sandbox.ConnectInfo
	baseDir  string
}

func newFactorySandboxArtifactCopier(dir string, record factory.RunRecord) (factory.SandboxArtifactCopier, error) {
	sandboxName := strings.TrimSpace(record.SandboxName)
	if sandboxName == "" {
		return nil, fmt.Errorf("sandbox name is required")
	}
	target, err := sandbox.LoadActiveInstance(sandboxName)
	if err != nil {
		return nil, fmt.Errorf("load sandbox %q: %w", sandboxName, err)
	}
	provider, err := resolveProviderFromState(dir, target)
	if err != nil {
		return nil, fmt.Errorf("resolve sandbox provider for %q: %w", sandboxName, err)
	}
	info := sandbox.ConnectInfoFromState(target)
	if info == nil {
		return nil, fmt.Errorf("sandbox connection info is required")
	}
	return &factorySandboxArtifactCopier{
		provider: provider,
		info:     info,
		baseDir:  strings.TrimSpace(record.RepoPath),
	}, nil
}

func (c *factorySandboxArtifactCopier) CopyFile(ctx context.Context, remotePath, localPath string) error {
	resolvedRemotePath, err := c.resolveRemotePath(remotePath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return fmt.Errorf("create sandbox artifact destination: %w", err)
	}

	file, err := os.Create(localPath)
	if err != nil {
		return fmt.Errorf("create sandbox artifact file: %w", err)
	}
	var stderr bytes.Buffer
	runErr := c.run(ctx, []string{
		"sh",
		"-c",
		`path=$1
if [ ! -f "$path" ]; then
	exit 44
fi
cat -- "$path"`,
		"hal-copy-file",
		resolvedRemotePath,
	}, file, &stderr)
	closeErr := file.Close()
	if runErr != nil {
		_ = os.Remove(localPath)
		return factorySandboxArtifactCopyError(resolvedRemotePath, stderr.String(), runErr)
	}
	if closeErr != nil {
		_ = os.Remove(localPath)
		return fmt.Errorf("write sandbox artifact file: %w", closeErr)
	}
	return nil
}

func (c *factorySandboxArtifactCopier) CopyDir(ctx context.Context, remotePath, localPath string) error {
	resolvedRemotePath, err := c.resolveRemotePath(remotePath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(localPath), 0o700); err != nil {
		return fmt.Errorf("create sandbox artifact destination: %w", err)
	}

	tarFile, err := os.CreateTemp(filepath.Dir(localPath), "sandbox-artifact-*.tar")
	if err != nil {
		return fmt.Errorf("create sandbox artifact archive: %w", err)
	}
	tarPath := tarFile.Name()
	defer os.Remove(tarPath)

	var stderr bytes.Buffer
	runErr := c.run(ctx, []string{
		"sh",
		"-c",
		`path=$1
if [ ! -d "$path" ]; then
	exit 44
fi
tar -C "$path" -cf - .`,
		"hal-copy-dir",
		resolvedRemotePath,
	}, tarFile, &stderr)
	closeErr := tarFile.Close()
	if runErr != nil {
		_ = os.RemoveAll(localPath)
		return factorySandboxArtifactCopyError(resolvedRemotePath, stderr.String(), runErr)
	}
	if closeErr != nil {
		_ = os.RemoveAll(localPath)
		return fmt.Errorf("write sandbox artifact archive: %w", closeErr)
	}
	if err := extractFactorySandboxArtifactTar(tarPath, localPath); err != nil {
		_ = os.RemoveAll(localPath)
		return err
	}
	return nil
}

func (c *factorySandboxArtifactCopier) resolveRemotePath(remotePath string) (string, error) {
	remotePath = strings.TrimSpace(filepath.ToSlash(remotePath))
	if remotePath == "" {
		return "", fmt.Errorf("sandbox artifact remote path is required")
	}
	if path.IsAbs(remotePath) {
		return path.Clean(remotePath), nil
	}
	baseDir := strings.TrimSpace(filepath.ToSlash(c.baseDir))
	if baseDir == "" {
		return "", fmt.Errorf("sandbox workspace directory is required for relative artifact path %q", remotePath)
	}
	return path.Clean(path.Join(baseDir, remotePath)), nil
}

func (c *factorySandboxArtifactCopier) run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if c.provider == nil {
		return fmt.Errorf("sandbox provider is required")
	}
	cmd, err := c.provider.Exec(c.info, args)
	if err != nil {
		return err
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return runFactorySandboxArtifactCommand(ctx, cmd)
}

func runFactorySandboxArtifactCommand(ctx context.Context, cmd *exec.Cmd) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		return err
	}

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	select {
	case err := <-waitCh:
		return err
	case <-ctx.Done():
		if cmd.Cancel != nil {
			if err := cmd.Cancel(); err != nil && cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
		} else if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return errors.Join(ctx.Err(), <-waitCh)
	}
}

func factorySandboxArtifactCopyError(remotePath, stderr string, err error) error {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 44 {
		return factory.ErrSandboxArtifactNotFound
	}
	stderr = strings.TrimSpace(stderr)
	if stderr != "" {
		return fmt.Errorf("copy sandbox artifact %q: %w: %s", remotePath, err, stderr)
	}
	return fmt.Errorf("copy sandbox artifact %q: %w", remotePath, err)
}

func extractFactorySandboxArtifactTar(tarPath, localPath string) error {
	file, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("open sandbox artifact archive: %w", err)
	}
	defer file.Close()

	if err := os.MkdirAll(localPath, 0o700); err != nil {
		return fmt.Errorf("create sandbox artifact directory: %w", err)
	}

	reader := tar.NewReader(file)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read sandbox artifact archive: %w", err)
		}

		relPath := cleanFactorySandboxArtifactTarPath(header.Name)
		if relPath == "" {
			continue
		}
		targetPath := filepath.Join(localPath, filepath.FromSlash(relPath))
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(targetPath, 0o700); err != nil {
				return fmt.Errorf("create sandbox artifact directory entry: %w", err)
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
				return fmt.Errorf("create sandbox artifact file parent: %w", err)
			}
			if err := writeFactorySandboxArtifactTarFile(targetPath, reader); err != nil {
				return err
			}
		}
	}
}

func cleanFactorySandboxArtifactTarPath(name string) string {
	clean := strings.TrimPrefix(path.Clean("/"+filepath.ToSlash(name)), "/")
	if clean == "." || clean == "" {
		return ""
	}
	return clean
}

func writeFactorySandboxArtifactTarFile(targetPath string, reader io.Reader) error {
	file, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create sandbox artifact file entry: %w", err)
	}
	if _, err := io.Copy(file, reader); err != nil {
		_ = file.Close()
		return fmt.Errorf("write sandbox artifact file entry: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close sandbox artifact file entry: %w", err)
	}
	return nil
}
