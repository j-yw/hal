//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	sandboxdRuntimeDirName       = "hal-sd"
	sandboxdJobStateDirName      = "jobs"
	sandboxdMaxUnixSocketPathLen = 100
)

func defaultSandboxdRuntimePaths() sandboxdRuntimePaths {
	runtimeRoot := defaultSandboxdRuntimeRoot()
	return sandboxdRuntimePaths{
		socketPath:  filepath.Join(runtimeRoot, sandboxdDefaultSocketName),
		jobStateDir: filepath.Join(runtimeRoot, sandboxdJobStateDirName),
	}
}

func defaultSandboxdRuntimeRoot() string {
	if xdgRuntimeDir, ok := validatedSandboxdXDGBase(os.Getenv("XDG_RUNTIME_DIR")); ok {
		runtimeRoot := filepath.Join(xdgRuntimeDir, sandboxdRuntimeDirName)
		if len([]byte(filepath.Join(runtimeRoot, sandboxdDefaultSocketName))) <= sandboxdMaxUnixSocketPathLen {
			return runtimeRoot
		}
	}
	tempRoot := filepath.Clean(os.TempDir())
	if resolved, err := filepath.EvalSymlinks(tempRoot); err == nil && filepath.IsAbs(resolved) {
		tempRoot = filepath.Clean(resolved)
	}
	return filepath.Join(tempRoot, fmt.Sprintf("%s-%d", sandboxdRuntimeDirName, os.Geteuid()))
}

func validatedSandboxdXDGBase(value string) (string, bool) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", false
	}
	path := filepath.Clean(value)
	if !filepath.IsAbs(path) || sandboxdFilesystemRoot(path) ||
		sandboxdPathHasControl(path) || sandboxdPathHasUnsafeDetail(path) {
		return "", false
	}
	info, err := os.Lstat(path)
	if err != nil || !sandboxdPrivateRuntimeDirectoryInfo(info) {
		return "", false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(resolved) != path {
		return "", false
	}
	return path, true
}

func prepareSandboxdDefaultRuntime(socketPath string) error {
	socketPath = filepath.Clean(strings.TrimSpace(socketPath))
	if !filepath.IsAbs(socketPath) ||
		filepath.Base(socketPath) != sandboxdDefaultSocketName ||
		sandboxdPathHasControl(socketPath) ||
		sandboxdPathHasUnsafeDetail(socketPath) ||
		len([]byte(socketPath)) > sandboxdMaxUnixSocketPathLen {
		return fmt.Errorf("sandboxd private runtime directory is invalid")
	}
	runtimeDir := filepath.Dir(socketPath)
	if runtimeDir == string(filepath.Separator) {
		return fmt.Errorf("sandboxd private runtime directory is invalid")
	}
	if err := validateSandboxdRuntimeParent(filepath.Dir(runtimeDir)); err != nil {
		return err
	}
	if err := ensureSandboxdPrivateRuntimeDirectory(runtimeDir); err != nil {
		return err
	}
	return nil
}

func validateSandboxdRuntimeParent(parent string) error {
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("sandboxd private runtime parent is invalid")
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || filepath.Clean(resolved) != parent {
		return fmt.Errorf("sandboxd private runtime parent is invalid")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("sandboxd private runtime parent is invalid")
	}
	currentOwnedPrivate := stat.Uid == uint32(os.Geteuid()) && info.Mode().Perm() == 0o700
	stickyShared := stat.Uid == 0 && info.Mode()&os.ModeSticky != 0 && info.Mode().Perm()&0o002 != 0
	if !currentOwnedPrivate && !stickyShared {
		return fmt.Errorf("sandboxd private runtime parent is invalid")
	}
	current, err := os.Lstat(parent)
	if err != nil || !os.SameFile(info, current) {
		return fmt.Errorf("sandboxd private runtime parent changed during validation")
	}
	return nil
}

func ensureSandboxdPrivateRuntimeDirectory(runtimeDir string) error {
	info, err := os.Lstat(runtimeDir)
	switch {
	case err == nil:
		return validateSandboxdPrivateRuntimeDirectory(runtimeDir, info)
	case !errors.Is(err, fs.ErrNotExist):
		return fmt.Errorf("sandboxd private runtime directory is unavailable")
	}

	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		return fmt.Errorf("sandboxd private runtime directory is unavailable")
	}
	info, err = os.Lstat(runtimeDir)
	if err != nil {
		return fmt.Errorf("sandboxd private runtime directory is unavailable")
	}
	return validateSandboxdPrivateRuntimeDirectory(runtimeDir, info)
}

func validateSandboxdPrivateRuntimeDirectory(runtimeDir string, info fs.FileInfo) error {
	if !sandboxdPrivateRuntimeDirectoryInfo(info) {
		return fmt.Errorf("sandboxd private runtime directory is invalid")
	}
	resolved, err := filepath.EvalSymlinks(runtimeDir)
	if err != nil || filepath.Clean(resolved) != runtimeDir {
		return fmt.Errorf("sandboxd private runtime directory is invalid")
	}
	current, err := os.Lstat(runtimeDir)
	if err != nil || !os.SameFile(info, current) || !sandboxdPrivateRuntimeDirectoryInfo(current) {
		return fmt.Errorf("sandboxd private runtime directory changed during validation")
	}
	return nil
}

func sandboxdPrivateRuntimeDirectoryInfo(info fs.FileInfo) bool {
	if info == nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
