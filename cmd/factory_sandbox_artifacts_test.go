package cmd

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
	"github.com/jywlabs/hal/internal/sandbox"
)

func TestFactorySandboxArtifactCopierRejectsTopLevelFileSymlink(t *testing.T) {
	remoteRoot := t.TempDir()
	halDir := filepath.Join(remoteRoot, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	secretPath := filepath.Join(remoteRoot, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("sandbox-secret"), 0o600); err != nil {
		t.Fatalf("WriteFile(secret) error = %v", err)
	}
	linkPath := filepath.Join(halDir, "progress.txt")
	if err := os.Symlink(secretPath, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	localPath := filepath.Join(t.TempDir(), "progress.txt")
	copier := &factorySandboxArtifactCopier{
		provider: localExecSandboxArtifactProvider{},
		info:     &sandbox.ConnectInfo{Name: "local"},
	}
	err := copier.CopyFile(context.Background(), linkPath, localPath)
	requireSymlinkSandboxArtifactCopyError(t, err)
	if data, readErr := os.ReadFile(localPath); readErr == nil {
		t.Fatalf("CopyFile() copied symlink target content: %q", data)
	} else if !os.IsNotExist(readErr) {
		t.Fatalf("ReadFile(localPath) error = %v, want not exist", readErr)
	}
}

func TestFactorySandboxArtifactCopierRejectsTopLevelDirSymlink(t *testing.T) {
	remoteRoot := t.TempDir()
	halDir := filepath.Join(remoteRoot, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	secretDir := filepath.Join(remoteRoot, "secret-reports")
	if err := os.MkdirAll(secretDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(secretDir) error = %v", err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "token.txt"), []byte("sandbox-secret"), 0o600); err != nil {
		t.Fatalf("WriteFile(secret file) error = %v", err)
	}
	linkPath := filepath.Join(halDir, "reports")
	if err := os.Symlink(secretDir, linkPath); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	localPath := filepath.Join(t.TempDir(), "reports")
	copier := &factorySandboxArtifactCopier{
		provider: localExecSandboxArtifactProvider{},
		info:     &sandbox.ConnectInfo{Name: "local"},
	}
	err := copier.CopyDir(context.Background(), linkPath, localPath)
	requireSymlinkSandboxArtifactCopyError(t, err)
	if _, statErr := os.Stat(localPath); statErr == nil {
		t.Fatalf("CopyDir() created local directory for symlinked artifact")
	} else if !os.IsNotExist(statErr) {
		t.Fatalf("Stat(localPath) error = %v, want not exist", statErr)
	}
}

func requireSymlinkSandboxArtifactCopyError(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("copy error = nil, want symlink rejection")
	}
	if errors.Is(err, factory.ErrSandboxArtifactNotFound) {
		t.Fatalf("copy error = %v, want non-missing symlink rejection", err)
	}
	if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("copy error = %v, want symlink details", err)
	}
}

type localExecSandboxArtifactProvider struct{}

func (localExecSandboxArtifactProvider) Create(context.Context, string, map[string]string, io.Writer) (*sandbox.SandboxResult, error) {
	return nil, nil
}

func (localExecSandboxArtifactProvider) Stop(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (localExecSandboxArtifactProvider) Start(context.Context, *sandbox.ConnectInfo, io.Writer) (*sandbox.LifecycleResult, error) {
	return nil, nil
}

func (localExecSandboxArtifactProvider) Delete(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}

func (localExecSandboxArtifactProvider) SSH(*sandbox.ConnectInfo) (*exec.Cmd, error) {
	return nil, nil
}

func (localExecSandboxArtifactProvider) Exec(_ *sandbox.ConnectInfo, args []string) (*exec.Cmd, error) {
	return exec.Command(args[0], args[1:]...), nil
}

func (localExecSandboxArtifactProvider) Status(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}
