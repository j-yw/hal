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

const factorySandboxArtifactPythonRunner = `script=$1
path=$2
if command -v python3 >/dev/null 2>&1; then
	exec python3 -c "$script" "$path"
fi
if command -v python >/dev/null 2>&1 && python -c 'import sys; sys.exit(0 if sys.version_info[0] == 3 else 1)' >/dev/null 2>&1; then
	exec python -c "$script" "$path"
fi
echo "python3 is required to copy sandbox artifacts without following symlinks" >&2
exit 46`

const factorySandboxArtifactCopyFilePythonScript = `import errno
import os
import stat
import sys

path = sys.argv[1]

def fail(message, code):
    if message:
        os.write(2, (message + "\n").encode("utf-8"))
    sys.exit(code)

no_follow = getattr(os, "O_NOFOLLOW", None)
if no_follow is None:
    fail("O_NOFOLLOW is required to copy sandbox artifacts without following symlinks", 46)

try:
    fd = os.open(path, os.O_RDONLY | no_follow)
except OSError as err:
    if err.errno == errno.ELOOP:
        fail("sandbox artifact path is a symlink", 45)
    if err.errno in (errno.ENOENT, errno.ENOTDIR):
        sys.exit(44)
    raise

try:
    file_stat = os.fstat(fd)
    if not stat.S_ISREG(file_stat.st_mode):
        sys.exit(44)
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        os.write(1, chunk)
finally:
    os.close(fd)`

const factorySandboxArtifactCopyDirPythonScript = `import errno
import os
import stat
import sys
import tarfile

path = sys.argv[1]

def fail(message, code):
    if message:
        os.write(2, (message + "\n").encode("utf-8"))
    sys.exit(code)

def is_symlink_path(candidate):
    try:
        return stat.S_ISLNK(os.lstat(candidate).st_mode)
    except OSError:
        return False

no_follow = getattr(os, "O_NOFOLLOW", None)
directory_flag = getattr(os, "O_DIRECTORY", 0)
if no_follow is None:
    fail("O_NOFOLLOW is required to copy sandbox artifacts without following symlinks", 46)

def add_dir_entry(tar, rel_path, entry_stat):
    info = tarfile.TarInfo(rel_path + "/")
    info.type = tarfile.DIRTYPE
    info.mode = entry_stat.st_mode & 0o777
    info.mtime = int(entry_stat.st_mtime)
    tar.addfile(info)

def add_file(tar, dir_fd, name, rel_path):
    try:
        file_fd = os.open(name, os.O_RDONLY | no_follow, dir_fd=dir_fd)
    except OSError as err:
        if err.errno in (errno.ELOOP, errno.ENOENT, errno.ENOTDIR):
            return
        raise
    try:
        file_stat = os.fstat(file_fd)
        if not stat.S_ISREG(file_stat.st_mode):
            return
        info = tarfile.TarInfo(rel_path)
        info.size = file_stat.st_size
        info.mode = file_stat.st_mode & 0o777
        info.mtime = int(file_stat.st_mtime)
        with os.fdopen(os.dup(file_fd), "rb") as file_obj:
            tar.addfile(info, file_obj)
    finally:
        os.close(file_fd)

def add_dir(tar, dir_fd, rel_path):
    for name in sorted(os.listdir(dir_fd)):
        if name in (".", ".."):
            continue
        entry_path = name if not rel_path else rel_path + "/" + name
        try:
            entry_stat = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        except OSError as err:
            if err.errno in (errno.ENOENT, errno.ENOTDIR):
                continue
            raise
        if stat.S_ISLNK(entry_stat.st_mode):
            continue
        if stat.S_ISDIR(entry_stat.st_mode):
            try:
                child_fd = os.open(name, os.O_RDONLY | directory_flag | no_follow, dir_fd=dir_fd)
            except OSError as err:
                if err.errno in (errno.ELOOP, errno.ENOENT, errno.ENOTDIR):
                    continue
                raise
            try:
                child_stat = os.fstat(child_fd)
                if not stat.S_ISDIR(child_stat.st_mode):
                    continue
                add_dir_entry(tar, entry_path, child_stat)
                add_dir(tar, child_fd, entry_path)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(entry_stat.st_mode):
            add_file(tar, dir_fd, name, entry_path)

try:
    root_fd = os.open(path, os.O_RDONLY | directory_flag | no_follow)
except OSError as err:
    if err.errno == errno.ELOOP or is_symlink_path(path):
        fail("sandbox artifact path is a symlink", 45)
    if err.errno in (errno.ENOENT, errno.ENOTDIR):
        sys.exit(44)
    raise

try:
    root_stat = os.fstat(root_fd)
    if not stat.S_ISDIR(root_stat.st_mode):
        sys.exit(44)
    out = os.fdopen(os.dup(1), "wb")
    try:
        tar = tarfile.open(fileobj=out, mode="w|")
        try:
            add_dir(tar, root_fd, "")
        finally:
            tar.close()
        out.flush()
    finally:
        out.close()
finally:
    os.close(root_fd)`

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
	runErr := c.run(ctx, factorySandboxArtifactPythonCommand(factorySandboxArtifactCopyFilePythonScript, resolvedRemotePath), file, &stderr)
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
	runErr := c.run(ctx, factorySandboxArtifactPythonCommand(factorySandboxArtifactCopyDirPythonScript, resolvedRemotePath), tarFile, &stderr)
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

func factorySandboxArtifactPythonCommand(script, remotePath string) []string {
	return []string{
		"sh",
		"-c",
		factorySandboxArtifactPythonRunner,
		"hal-copy-artifact",
		script,
		remotePath,
	}
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
