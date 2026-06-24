package cmd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandbox"
)

func TestCollectSandboxAuthFilesSelectsAuthProfilesOnly(t *testing.T) {
	clearSandboxAuthCodexHome(t)
	home := t.TempDir()
	writeSandboxAuthTestFile(t, home, ".codex/auth.json", "codex-auth")
	writeSandboxAuthTestFile(t, home, ".codex/config.toml", "model = 'x'")
	writeSandboxAuthTestFile(t, home, ".codex/logs_2.sqlite", "large logs should not sync")
	writeSandboxAuthTestFile(t, home, ".pi/agent/auth.json", "pi-auth")
	writeSandboxAuthTestFile(t, home, ".pi/agent/settings.json", "{}")
	writeSandboxAuthTestFile(t, home, ".pi/agent/sessions/session.json", "session should not sync")
	writeSandboxAuthTestFile(t, home, ".claude.json", "{}")

	files, err := collectSandboxAuthFiles(home, sandboxAuthSyncOptions{})
	if err != nil {
		t.Fatalf("collectSandboxAuthFiles() error: %v", err)
	}
	got := sandboxAuthArchivePaths(files)
	want := []string{
		".codex/auth.json",
		".codex/config.toml",
		".pi/agent/auth.json",
		".pi/agent/settings.json",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("paths = %#v, want %#v", got, want)
	}
	for _, file := range files {
		if file.ArchivePath == ".codex/logs_2.sqlite" || strings.Contains(file.ArchivePath, "sessions") || strings.HasPrefix(file.ArchivePath, ".claude") {
			t.Fatalf("unexpected synced file: %#v", file)
		}
	}
}

func TestCollectSandboxAuthFilesUsesCodexHomeForCodexSources(t *testing.T) {
	home := t.TempDir()
	codexHome := t.TempDir()
	t.Setenv("CODEX_HOME", codexHome)
	writeSandboxAuthTestFile(t, home, ".codex/auth.json", "stale-default-home-auth")
	writeSandboxAuthTestFile(t, codexHome, "auth.json", "active-codex-auth")
	writeSandboxAuthTestFile(t, home, ".pi/agent/auth.json", "pi-auth")

	files, err := collectSandboxAuthFiles(home, sandboxAuthSyncOptions{})
	if err != nil {
		t.Fatalf("collectSandboxAuthFiles() error: %v", err)
	}
	got := sandboxAuthArchivePaths(files)
	want := []string{
		".codex/auth.json",
		".pi/agent/auth.json",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("paths = %#v, want %#v", got, want)
	}

	codexFile := findSandboxAuthFile(t, files, ".codex/auth.json")
	if wantLocal := filepath.Join(codexHome, "auth.json"); codexFile.LocalPath != wantLocal {
		t.Fatalf("codex local path = %q, want %q", codexFile.LocalPath, wantLocal)
	}
	piFile := findSandboxAuthFile(t, files, ".pi/agent/auth.json")
	if wantLocal := filepath.Join(home, ".pi", "agent", "auth.json"); piFile.LocalPath != wantLocal {
		t.Fatalf("pi local path = %q, want %q", piFile.LocalPath, wantLocal)
	}

	archive, err := buildSandboxAuthArchive(files)
	if err != nil {
		t.Fatalf("buildSandboxAuthArchive() error: %v", err)
	}
	headers := readSandboxAuthArchiveHeaders(t, archive)
	if _, ok := headers[".codex/auth.json"]; !ok {
		t.Fatalf("archive missing .codex/auth.json: %#v", headers)
	}
	if _, ok := headers[codexHome+"/auth.json"]; ok {
		t.Fatalf("archive used local CODEX_HOME path: %#v", headers)
	}
}

func TestCollectSandboxAuthFilesIncludesClaudeWhenRequested(t *testing.T) {
	clearSandboxAuthCodexHome(t)
	home := t.TempDir()
	writeSandboxAuthTestFile(t, home, ".claude.json", "{}")

	files, err := collectSandboxAuthFiles(home, sandboxAuthSyncOptions{IncludeClaude: true})
	if err != nil {
		t.Fatalf("collectSandboxAuthFiles() error: %v", err)
	}
	if got := sandboxAuthArchivePaths(files); strings.Join(got, ",") != ".claude.json" {
		t.Fatalf("paths = %#v, want .claude.json", got)
	}
}

func TestBuildSandboxAuthArchiveUsesRelativePrivatePaths(t *testing.T) {
	clearSandboxAuthCodexHome(t)
	home := t.TempDir()
	writeSandboxAuthTestFile(t, home, ".codex/auth.json", "codex-auth")
	writeSandboxAuthTestFile(t, home, ".pi/agent/auth.json", "pi-auth")

	files, err := collectSandboxAuthFiles(home, sandboxAuthSyncOptions{})
	if err != nil {
		t.Fatalf("collectSandboxAuthFiles() error: %v", err)
	}
	archive, err := buildSandboxAuthArchive(files)
	if err != nil {
		t.Fatalf("buildSandboxAuthArchive() error: %v", err)
	}

	headers := readSandboxAuthArchiveHeaders(t, archive)
	if _, ok := headers[".codex/auth.json"]; !ok {
		t.Fatalf("archive missing .codex/auth.json: %#v", headers)
	}
	if _, ok := headers[".pi/agent/auth.json"]; !ok {
		t.Fatalf("archive missing .pi/agent/auth.json: %#v", headers)
	}
	for name, mode := range headers {
		if strings.HasPrefix(name, "/") || strings.Contains(name, "..") {
			t.Fatalf("archive contains unsafe path %q", name)
		}
		if mode&0o077 != 0 {
			t.Fatalf("archive path %q mode %o should not be group/world readable", name, mode)
		}
	}
}

func TestRunSandboxAuthSyncToTargetTransfersArchive(t *testing.T) {
	clearSandboxAuthCodexHome(t)
	home := t.TempDir()
	writeSandboxAuthTestFile(t, home, ".codex/auth.json", "codex-auth")
	writeSandboxAuthTestFile(t, home, ".pi/agent/auth.json", "pi-auth")
	target := &sandbox.SandboxState{Name: "auth-box", Provider: "digitalocean", Status: sandbox.StatusRunning, IP: "10.0.0.1"}

	var gotInfo *sandbox.ConnectInfo
	var gotArchive []byte
	var out bytes.Buffer
	result, err := runSandboxAuthSyncToTarget(context.Background(), target, fakeFactorySandboxProvider{}, sandboxAuthSyncOptions{}, &out, sandboxAuthSyncDeps{
		homeDir: func() (string, error) { return home, nil },
		runRemote: func(_ sandbox.Provider, info *sandbox.ConnectInfo, archive []byte, _ io.Writer) error {
			gotInfo = info
			gotArchive = append([]byte(nil), archive...)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runSandboxAuthSyncToTarget() error: %v", err)
	}
	if gotInfo == nil || gotInfo.Name != "auth-box" || gotInfo.IP != "10.0.0.1" {
		t.Fatalf("connect info = %#v", gotInfo)
	}
	if result.FileCount != 2 || result.Profiles["codex"] != 1 || result.Profiles["pi"] != 1 {
		t.Fatalf("result = %#v", result)
	}
	headers := readSandboxAuthArchiveHeaders(t, gotArchive)
	for _, name := range []string{".codex/auth.json", ".pi/agent/auth.json"} {
		if _, ok := headers[name]; !ok {
			t.Fatalf("archive missing %s: %#v", name, headers)
		}
	}
	if !strings.Contains(out.String(), "Synced sandbox auth to auth-box") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestRunSandboxAuthSyncToTargetSkipsWhenNoAuthFiles(t *testing.T) {
	clearSandboxAuthCodexHome(t)
	target := &sandbox.SandboxState{Name: "auth-box", Provider: "digitalocean", Status: sandbox.StatusRunning}
	called := false
	var out bytes.Buffer

	result, err := runSandboxAuthSyncToTarget(context.Background(), target, fakeFactorySandboxProvider{}, sandboxAuthSyncOptions{}, &out, sandboxAuthSyncDeps{
		homeDir: func() (string, error) { return t.TempDir(), nil },
		runRemote: func(sandbox.Provider, *sandbox.ConnectInfo, []byte, io.Writer) error {
			called = true
			return nil
		},
	})
	if err != nil {
		t.Fatalf("runSandboxAuthSyncToTarget() error: %v", err)
	}
	if called {
		t.Fatalf("runRemote should not be called when there are no auth files")
	}
	if result.FileCount != 0 {
		t.Fatalf("FileCount = %d, want 0", result.FileCount)
	}
	if !strings.Contains(out.String(), "No local Codex/pi auth files found") {
		t.Fatalf("output = %q", out.String())
	}
}

func TestSandboxAuthRemoteInstallScriptExtractsPrivateArchive(t *testing.T) {
	script := sandboxAuthRemoteInstallScript()
	for _, want := range []string{
		"tar -C \"$HOME\" -xzf -",
		"chmod -R go-rwx",
		"export HOME=\"$remote_home\"",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("sandboxAuthRemoteInstallScript() missing %q:\n%s", want, script)
		}
	}
}

func TestSandboxAuthRemoteInstallScriptExtractsIntoExecUserHome(t *testing.T) {
	clearSandboxAuthCodexHome(t)
	localHome := t.TempDir()
	writeSandboxAuthTestFile(t, localHome, ".codex/auth.json", "codex-auth")
	writeSandboxAuthTestFile(t, localHome, ".pi/agent/auth.json", "pi-auth")

	files, err := collectSandboxAuthFiles(localHome, sandboxAuthSyncOptions{})
	if err != nil {
		t.Fatalf("collectSandboxAuthFiles() error: %v", err)
	}
	archive, err := buildSandboxAuthArchive(files)
	if err != nil {
		t.Fatalf("buildSandboxAuthArchive() error: %v", err)
	}

	remoteHome := t.TempDir()
	cmd := exec.Command("sh", "-lc", sandboxAuthRemoteInstallScript())
	cmd.Env = append(os.Environ(), "HOME="+remoteHome)
	cmd.Stdin = bytes.NewReader(archive)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("remote install script error: %v\n%s", err, output)
	}

	for _, rel := range []string{".codex/auth.json", ".pi/agent/auth.json"} {
		path := filepath.Join(remoteHome, filepath.FromSlash(rel))
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected auth file under exec user home %s: %v", path, err)
		}
	}
}

func clearSandboxAuthCodexHome(t *testing.T) {
	t.Helper()
	t.Setenv("CODEX_HOME", "")
}

func writeSandboxAuthTestFile(t *testing.T, home, rel, content string) {
	t.Helper()
	path := filepath.Join(home, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%q) error: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile(%q) error: %v", path, err)
	}
}

func sandboxAuthArchivePaths(files []sandboxAuthFile) []string {
	paths := make([]string, 0, len(files))
	for _, file := range files {
		paths = append(paths, file.ArchivePath)
	}
	sort.Strings(paths)
	return paths
}

func findSandboxAuthFile(t *testing.T, files []sandboxAuthFile, archivePath string) sandboxAuthFile {
	t.Helper()
	for _, file := range files {
		if file.ArchivePath == archivePath {
			return file
		}
	}
	t.Fatalf("missing auth file %q in %#v", archivePath, files)
	return sandboxAuthFile{}
}

func readSandboxAuthArchiveHeaders(t *testing.T, data []byte) map[string]int64 {
	t.Helper()
	gr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("gzip.NewReader() error: %v", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	headers := map[string]int64{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar.Next() error: %v", err)
		}
		headers[header.Name] = header.Mode
	}
	return headers
}
