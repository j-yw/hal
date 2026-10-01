package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/factory"
)

func TestFactorySandboxEngineAuthDepsDeliverClaudeCredentialsOnlyForClaude(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	credentials := filepath.Join(home, ".claude", ".credentials.json")
	writeSandboxEngineAuthFixture(t, credentials)
	repo := t.TempDir()
	writeSandboxEngineAuthFixture(t, filepath.Join(repo, ".hal", "config.yaml"))
	if err := os.WriteFile(filepath.Join(repo, ".hal", "config.yaml"), []byte("engine: claude\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	deps := factorySandboxExecutorDeps{engineAuthFiles: func() []factorySandboxAuthFile { return nil }}

	for _, tc := range []struct {
		name    string
		engine  string
		repo    string
		wantKey bool
	}{
		{name: "explicit claude", engine: "claude", repo: t.TempDir(), wantKey: true},
		{name: "explicit codex", engine: "codex", repo: repo, wantKey: false},
		{name: "configured claude", engine: "", repo: repo, wantKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := factorySandboxEngineAuthDeps(factorySandboxExecutorRequest{
				RunRecord:  factory.RunRecord{RepoPath: tc.repo},
				RemoteAuto: factoryRunAutoRequest{Engine: tc.engine},
			}, deps).engineAuthFiles()
			if has := containsSandboxAuthFile(got, credentials, ".claude/.credentials.json"); has != tc.wantKey {
				t.Fatalf("factory engine auth files include Claude credentials = %v, want %v: %#v", has, tc.wantKey, got)
			}
		})
	}
}
