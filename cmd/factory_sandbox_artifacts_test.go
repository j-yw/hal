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
	requireLocalSandboxArtifactCopierRuntime(t)

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

func TestFactorySandboxArtifactCopierDoesNotReusePathAfterFileCheck(t *testing.T) {
	requireLocalSandboxArtifactCopierRuntime(t)

	remoteRoot := t.TempDir()
	halDir := filepath.Join(remoteRoot, ".hal")
	if err := os.MkdirAll(halDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	artifactPath := filepath.Join(halDir, "progress.txt")
	if err := os.WriteFile(artifactPath, []byte("safe-progress"), 0o600); err != nil {
		t.Fatalf("WriteFile(artifact) error = %v", err)
	}
	secretPath := filepath.Join(remoteRoot, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("sandbox-secret"), 0o600); err != nil {
		t.Fatalf("WriteFile(secret) error = %v", err)
	}

	binDir := t.TempDir()
	fakeCat := filepath.Join(binDir, "cat")
	fakeCatScript := `#!/bin/sh
path=$1
if [ "$path" = "--" ]; then
	path=$2
fi
rm -f "$path"
ln -s "$SECRET_PATH" "$path"
exec /bin/cat "$@"
`
	if err := os.WriteFile(fakeCat, []byte(fakeCatScript), 0o700); err != nil {
		t.Fatalf("WriteFile(fake cat) error = %v", err)
	}

	localPath := filepath.Join(t.TempDir(), "progress.txt")
	copier := &factorySandboxArtifactCopier{
		provider: localExecSandboxArtifactProvider{
			env: []string{
				"PATH=" + binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
				"SECRET_PATH=" + secretPath,
			},
		},
		info: &sandbox.ConnectInfo{Name: "local"},
	}
	if err := copier.CopyFile(context.Background(), artifactPath, localPath); err != nil {
		t.Fatalf("CopyFile() unexpected error = %v", err)
	}
	data, err := os.ReadFile(localPath)
	if err != nil {
		t.Fatalf("ReadFile(localPath) error = %v", err)
	}
	if string(data) != "safe-progress" {
		t.Fatalf("CopyFile() copied %q, want original artifact content", data)
	}
}

func TestFactorySandboxArtifactCopierRejectsTopLevelDirSymlink(t *testing.T) {
	requireLocalSandboxArtifactCopierRuntime(t)

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

func requireLocalSandboxArtifactCopierRuntime(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skipf("sh unavailable: %v", err)
	}
	cmd := exec.Command("sh", "-c", factorySandboxArtifactPythonRunner, "hal-copy-artifact", `import os, sys
sys.exit(0 if getattr(os, "O_NOFOLLOW", None) is not None else 1)`, ".")
	if err := cmd.Run(); err != nil {
		t.Skipf("python O_NOFOLLOW unavailable: %v", err)
	}
}

type localExecSandboxArtifactProvider struct {
	env []string
}

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

func (p localExecSandboxArtifactProvider) Exec(_ *sandbox.ConnectInfo, args []string) (*exec.Cmd, error) {
	cmd := exec.Command(args[0], args[1:]...)
	if len(p.env) > 0 {
		cmd.Env = append(os.Environ(), p.env...)
	}
	return cmd, nil
}

func (localExecSandboxArtifactProvider) Status(context.Context, *sandbox.ConnectInfo, io.Writer) error {
	return nil
}
