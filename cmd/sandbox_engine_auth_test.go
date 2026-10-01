package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func writeSandboxEngineAuthFixture(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("MkdirAll(%s): %v", path, err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

// A sandboxed Claude run needs the Claude login, but Claude credentials are
// delivered only when Claude is the selected engine, and the broad
// ~/.claude.json state file (MCP tokens, project history) is never copied.
func TestSandboxEngineAuthFilesDeliverClaudeCredentialsOnlyForClaude(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	credentials := filepath.Join(home, ".claude", ".credentials.json")
	writeSandboxEngineAuthFixture(t, credentials)
	writeSandboxEngineAuthFixture(t, filepath.Join(home, ".claude.json"))
	base := func() []factorySandboxAuthFile {
		return []factorySandboxAuthFile{{SourcePath: "codex-auth", RemotePath: ".codex/auth.json"}}
	}

	claudeFiles := sandboxEngineAuthFilesFor("claude", base)()
	if !containsSandboxAuthFile(claudeFiles, credentials, ".claude/.credentials.json") {
		t.Fatalf("claude engine auth files = %#v, want Claude credentials", claudeFiles)
	}
	if !containsSandboxAuthFile(claudeFiles, "codex-auth", ".codex/auth.json") {
		t.Fatalf("claude engine auth files = %#v, want base engine files kept", claudeFiles)
	}
	for _, file := range claudeFiles {
		if file.RemotePath == ".claude.json" {
			t.Fatalf("claude engine auth files include the broad ~/.claude.json state file: %#v", claudeFiles)
		}
	}

	for _, engineName := range []string{"codex", "pi", ""} {
		for _, file := range sandboxEngineAuthFilesFor(engineName, base)() {
			if file.SourcePath == credentials {
				t.Fatalf("engine %q received Claude credentials: %#v", engineName, file)
			}
		}
	}
}

func TestSandboxEffectiveEngineUsesProjectConfigWithoutFlag(t *testing.T) {
	projectDir := t.TempDir()
	writeSandboxEngineAuthFixture(t, filepath.Join(projectDir, ".hal", "config.yaml"))
	if err := os.WriteFile(filepath.Join(projectDir, ".hal", "config.yaml"), []byte("engine: claude\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if got := sandboxEffectiveEngine("", false, projectDir); got != "claude" {
		t.Fatalf("sandboxEffectiveEngine(config) = %q, want claude", got)
	}
	if got := sandboxEffectiveEngine("pi", true, projectDir); got != "pi" {
		t.Fatalf("sandboxEffectiveEngine(flag) = %q, want explicit pi", got)
	}
}

func containsSandboxAuthFile(files []factorySandboxAuthFile, source, remote string) bool {
	for _, file := range files {
		if file.SourcePath == source && file.RemotePath == remote {
			return true
		}
	}
	return false
}
