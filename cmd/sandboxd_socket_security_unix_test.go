//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxworker"
)

func TestSandboxdDefaultStartupCreatesPrivateRuntimeLayout(t *testing.T) {
	xdgRuntimeDir := sandboxdResolvedPrivateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", xdgRuntimeDir)

	wantRuntimeDir := filepath.Join(xdgRuntimeDir, "hal-sd")
	wantSocketPath := filepath.Join(wantRuntimeDir, sandboxdDefaultSocketName)
	wantJobStateDir := filepath.Join(wantRuntimeDir, "jobs")
	flags := defaultSandboxdFlags()
	if flags.socketPath != wantSocketPath {
		t.Fatalf("default socket path = %q, want private XDG runtime socket", flags.socketPath)
	}
	if flags.jobStateDir != wantJobStateDir || flags.jobStateDir == flags.socketPath+".jobs" {
		t.Fatalf("default job state dir = %q, want separate runtime child", flags.jobStateDir)
	}

	cmd, _, _ := newTestSandboxdCommand(sandboxdPrivateRuntimeTestDeps())
	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandboxd Execute() error: %v", err)
	}
	assertSandboxdPrivateDirectory(t, wantRuntimeDir)
	assertSandboxdPrivateDirectory(t, wantJobStateDir)
}

func TestSandboxdDefaultFallsBackFromUnsafeXDGToResolvedUIDScopedTemp(t *testing.T) {
	unsafeXDG := sandboxdResolvedPrivateTempDir(t)
	if err := os.Chmod(unsafeXDG, 0o755); err != nil {
		t.Fatalf("Chmod(unsafe XDG runtime dir) error: %v", err)
	}
	tempRoot := sandboxdResolvedPrivateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", unsafeXDG)
	t.Setenv("TMPDIR", tempRoot)

	wantRuntimeDir := filepath.Join(tempRoot, fmt.Sprintf("hal-sd-%d", os.Geteuid()))
	flags := defaultSandboxdFlags()
	if filepath.Dir(flags.socketPath) != wantRuntimeDir {
		t.Fatalf("default socket parent = %q, want UID-scoped resolved temp fallback", filepath.Dir(flags.socketPath))
	}
	if flags.jobStateDir != filepath.Join(wantRuntimeDir, "jobs") {
		t.Fatalf("default job state dir = %q, want fallback runtime child", flags.jobStateDir)
	}
}

func TestSandboxdDefaultFallsBackFromOverlongXDG(t *testing.T) {
	base := sandboxdResolvedPrivateTempDir(t)
	xdgRuntimeDir := filepath.Join(base, strings.Repeat("x", 70))
	if err := os.Mkdir(xdgRuntimeDir, 0o700); err != nil {
		t.Fatalf("Mkdir(overlong XDG runtime dir) error: %v", err)
	}
	tempRoot := sandboxdResolvedPrivateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", xdgRuntimeDir)
	t.Setenv("TMPDIR", tempRoot)

	wantRuntimeDir := filepath.Join(tempRoot, fmt.Sprintf("hal-sd-%d", os.Geteuid()))
	if got := filepath.Dir(defaultSandboxdFlags().socketPath); got != wantRuntimeDir {
		t.Fatalf("default socket parent = %q, want short temp fallback", got)
	}
}

func TestSandboxdDefaultRejectsUnsafePreexistingRuntimeWithoutMutation(t *testing.T) {
	xdgRuntimeDir := sandboxdResolvedPrivateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", xdgRuntimeDir)
	runtimeDir := filepath.Join(xdgRuntimeDir, "hal-sd")
	if err := os.Mkdir(runtimeDir, 0o755); err != nil {
		t.Fatalf("Mkdir(unsafe runtime dir) error: %v", err)
	}

	serviceCalled := false
	cmd, _, stderr := newTestSandboxdCommand(sandboxdPrivateRuntimeTestDepsWithService(func(sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
		serviceCalled = true
		return &recordingSandboxdHandler{}, nil
	}))
	if err := cmd.Execute(); err == nil {
		t.Fatal("sandboxd Execute() error = nil, want unsafe runtime rejection")
	}
	if serviceCalled {
		t.Fatal("sandboxd created its service after unsafe runtime rejection")
	}
	info, err := os.Lstat(runtimeDir)
	if err != nil {
		t.Fatalf("Lstat(unsafe runtime dir) error: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("unsafe runtime dir mode = %#o, want unchanged 0755", got)
	}
	if output := stderr.String(); strings.Contains(output, runtimeDir) || strings.Contains(output, xdgRuntimeDir) {
		t.Fatalf("sandboxd error exposed a runtime path: %q", output)
	}
}

func TestSandboxdDefaultRejectsSymlinkRuntimeWithoutRemovingTarget(t *testing.T) {
	xdgRuntimeDir := sandboxdResolvedPrivateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", xdgRuntimeDir)
	target := sandboxdResolvedPrivateTempDir(t)
	runtimeDir := filepath.Join(xdgRuntimeDir, "hal-sd")
	if err := os.Symlink(target, runtimeDir); err != nil {
		t.Fatalf("Symlink(runtime dir) error: %v", err)
	}

	cmd, _, stderr := newTestSandboxdCommand(sandboxdPrivateRuntimeTestDeps())
	if err := cmd.Execute(); err == nil {
		t.Fatal("sandboxd Execute() error = nil, want symlink runtime rejection")
	}
	info, err := os.Lstat(runtimeDir)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("runtime symlink was changed or removed: info=%v err=%v", info, err)
	}
	assertSandboxdPrivateDirectory(t, target)
	if output := stderr.String(); strings.Contains(output, runtimeDir) || strings.Contains(output, target) {
		t.Fatalf("sandboxd error exposed a runtime path: %q", output)
	}
}

func TestSandboxdDefaultRevalidatesRuntimeParentAtStartup(t *testing.T) {
	xdgRuntimeDir := sandboxdResolvedPrivateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", xdgRuntimeDir)
	cmd, _, stderr := newTestSandboxdCommand(sandboxdPrivateRuntimeTestDeps())
	if err := os.Chmod(xdgRuntimeDir, 0o755); err != nil {
		t.Fatalf("Chmod(XDG runtime dir after command creation) error: %v", err)
	}

	if err := cmd.Execute(); err == nil {
		t.Fatal("sandboxd Execute() error = nil, want changed runtime parent rejection")
	}
	if _, err := os.Lstat(filepath.Join(xdgRuntimeDir, "hal-sd")); !os.IsNotExist(err) {
		t.Fatalf("changed runtime parent gained a daemon directory: %v", err)
	}
	if output := stderr.String(); strings.Contains(output, xdgRuntimeDir) {
		t.Fatalf("sandboxd error exposed the changed runtime parent: %q", output)
	}
}

func TestSandboxdDefaultRejectsUnsafeJobStateWithoutChangingIt(t *testing.T) {
	xdgRuntimeDir := sandboxdResolvedPrivateTempDir(t)
	t.Setenv("XDG_RUNTIME_DIR", xdgRuntimeDir)
	runtimeDir := filepath.Join(xdgRuntimeDir, "hal-sd")
	if err := os.Mkdir(runtimeDir, 0o700); err != nil {
		t.Fatalf("Mkdir(runtime dir) error: %v", err)
	}
	jobStateDir := filepath.Join(runtimeDir, "jobs")
	if err := os.Mkdir(jobStateDir, 0o755); err != nil {
		t.Fatalf("Mkdir(unsafe job state dir) error: %v", err)
	}

	cmd, _, stderr := newTestSandboxdCommand(sandboxdPrivateRuntimeTestDeps())
	if err := cmd.Execute(); err == nil {
		t.Fatal("sandboxd Execute() error = nil, want unsafe job state rejection")
	}
	info, err := os.Lstat(jobStateDir)
	if err != nil {
		t.Fatalf("Lstat(unsafe job state dir) error: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("unsafe job state dir mode = %#o, want unchanged 0755", got)
	}
	if output := stderr.String(); strings.Contains(output, jobStateDir) || strings.Contains(output, runtimeDir) {
		t.Fatalf("sandboxd error exposed a private state path: %q", output)
	}
}

func TestSandboxdExplicitSocketDoesNotChangeParentPermissions(t *testing.T) {
	parent := sandboxdResolvedPrivateTempDir(t)
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatalf("Chmod(explicit socket parent) error: %v", err)
	}
	socketPath := filepath.Join(parent, "explicit.sock")
	cmd, _, _ := newTestSandboxdCommand(sandboxdPrivateRuntimeTestDeps())
	cmd.SetArgs([]string{"--socket", socketPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("sandboxd Execute(explicit socket) error: %v", err)
	}
	info, err := os.Lstat(parent)
	if err != nil {
		t.Fatalf("Lstat(explicit socket parent) error: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("explicit socket parent mode = %#o, want unchanged 0755", got)
	}
}

func TestSandboxdDefaultRejectsOverlongSocketPathBeforeServiceCreation(t *testing.T) {
	tempRoot := sandboxdResolvedPrivateTempDir(t)
	longTempRoot := filepath.Join(tempRoot, strings.Repeat("x", 80))
	if err := os.Mkdir(longTempRoot, 0o700); err != nil {
		t.Fatalf("Mkdir(long temp root) error: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", longTempRoot)

	serviceCalled := false
	cmd, _, stderr := newTestSandboxdCommand(sandboxdPrivateRuntimeTestDepsWithService(func(sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
		serviceCalled = true
		return &recordingSandboxdHandler{}, nil
	}))
	if err := cmd.Execute(); err == nil {
		t.Fatal("sandboxd Execute() error = nil, want overlong default socket rejection")
	}
	if serviceCalled {
		t.Fatal("sandboxd created its service for an overlong default socket")
	}
	if output := stderr.String(); strings.Contains(output, longTempRoot) {
		t.Fatalf("sandboxd error exposed the overlong runtime path: %q", output)
	}
}

func TestSandboxdDefaultRejectsUnsafeTempBaseWithoutCreatingRuntime(t *testing.T) {
	tempRoot := sandboxdResolvedPrivateTempDir(t)
	if err := os.Chmod(tempRoot, 0o777); err != nil {
		t.Fatalf("Chmod(unsafe temp root) error: %v", err)
	}
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("TMPDIR", tempRoot)
	runtimeDir := filepath.Join(tempRoot, fmt.Sprintf("hal-sd-%d", os.Geteuid()))

	serviceCalled := false
	cmd, _, stderr := newTestSandboxdCommand(sandboxdPrivateRuntimeTestDepsWithService(func(sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
		serviceCalled = true
		return &recordingSandboxdHandler{}, nil
	}))
	if err := cmd.Execute(); err == nil {
		t.Fatal("sandboxd Execute() error = nil, want unsafe temp base rejection")
	}
	if serviceCalled {
		t.Fatal("sandboxd created its service after unsafe temp base rejection")
	}
	if _, err := os.Lstat(runtimeDir); !os.IsNotExist(err) {
		t.Fatalf("unsafe temp base gained a runtime directory: %v", err)
	}
	info, err := os.Lstat(tempRoot)
	if err != nil {
		t.Fatalf("Lstat(unsafe temp root) error: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o777 {
		t.Fatalf("unsafe temp root mode = %#o, want unchanged 0777", got)
	}
	if output := stderr.String(); strings.Contains(output, tempRoot) {
		t.Fatalf("sandboxd error exposed the unsafe temp root: %q", output)
	}
}

func TestSandboxdPrivateRuntimeDirectoryRejectsDifferentOwner(t *testing.T) {
	dir := sandboxdResolvedPrivateTempDir(t)
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatalf("Lstat(private temp dir) error: %v", err)
	}
	stat := *info.Sys().(*syscall.Stat_t)
	stat.Uid = uint32(os.Geteuid()) + 1
	if sandboxdPrivateRuntimeDirectoryInfo(sandboxdFileInfoWithSystem{FileInfo: info, system: &stat}) {
		t.Fatal("private runtime directory accepted a different owner")
	}
}

func sandboxdPrivateRuntimeTestDeps() sandboxdDeps {
	return sandboxdPrivateRuntimeTestDepsWithService(func(options sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error) {
		return sandboxworker.NewService(options)
	})
}

func sandboxdPrivateRuntimeTestDepsWithService(newService func(sandboxworker.ServiceOptions) (sandboxworker.RequestHandler, error)) sandboxdDeps {
	return sandboxdDeps{
		newService: newService,
		newServer: func(sandboxworker.ServerOptions) (sandboxdServer, error) {
			return sandboxdServerFunc(func(context.Context) error { return nil }), nil
		},
		rootlessPodmanAvailable: func(context.Context, sandboxdRootlessPodmanConfig) error {
			return nil
		},
		newRootlessPodmanDriver: func(sandboxdRootlessPodmanConfig) sandboxruntime.Driver {
			return fakeSandboxdRuntimeDriver{id: sandboxruntime.DriverRootlessPodman}
		},
		workerID: func(string) string {
			return "worker-private-runtime-test"
		},
	}
}

func sandboxdResolvedPrivateTempDir(t *testing.T) string {
	t.Helper()
	tempRoot, err := filepath.EvalSymlinks(os.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(system temp root) error: %v", err)
	}
	dir, err := os.MkdirTemp(tempRoot, "hsd-")
	if err != nil {
		t.Fatalf("MkdirTemp(private test dir) error: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func assertSandboxdPrivateDirectory(t *testing.T, path string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(private directory) error: %v", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0o700 {
		t.Fatalf("private directory mode = %v, want non-symlink 0700 directory", info.Mode())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		t.Fatalf("private directory owner is not the current effective user")
	}
}

type sandboxdFileInfoWithSystem struct {
	os.FileInfo
	system any
}

func (info sandboxdFileInfoWithSystem) Sys() any {
	return info.system
}
