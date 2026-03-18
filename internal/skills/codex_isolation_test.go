package skills

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCodexLinkerRespectsHOMEEnv verifies that the CodexLinker uses $HOME
// for global paths instead of the cached os.UserHomeDir(), ensuring test
// isolation — tests that set HOME to a temp dir won't leak into ~/.codex.
func TestCodexLinkerRespectsHOMEEnv(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)

	linker := &CodexLinker{}

	skillsDir := linker.SkillsDir()
	want := filepath.Join(fakeHome, ".codex", "skills")
	if skillsDir != want {
		t.Fatalf("SkillsDir() = %q, want %q (should respect $HOME)", skillsDir, want)
	}

	cmdsDir := linker.CommandsDir()
	wantCmds := filepath.Join(fakeHome, ".codex", "commands", "hal")
	if cmdsDir != wantCmds {
		t.Fatalf("CommandsDir() = %q, want %q (should respect $HOME)", cmdsDir, wantCmds)
	}
}

// TestCodexLinkerLinkDoesNotPollutRealHome verifies that Link/Unlink
// with $HOME set to a temp dir only writes to that temp dir.
func TestCodexLinkerLinkDoesNotPolluteRealHome(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)

	projectDir := t.TempDir()
	halSkillsDir := filepath.Join(projectDir, ".hal", "skills")
	if err := os.MkdirAll(halSkillsDir, 0755); err != nil {
		t.Fatal(err)
	}
	testSkillDir := filepath.Join(halSkillsDir, "prd")
	if err := os.MkdirAll(testSkillDir, 0755); err != nil {
		t.Fatal(err)
	}

	linker := &CodexLinker{}

	if err := linker.Link(projectDir, []string{"prd"}); err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	// Verify link was created under fake home
	linkPath := filepath.Join(fakeHome, ".codex", "skills", "prd")
	if _, err := os.Lstat(linkPath); err != nil {
		t.Fatalf("expected symlink at %s: %v", linkPath, err)
	}

	// Verify real home was NOT touched
	realHome, _ := os.UserHomeDir()
	if realHome != fakeHome {
		// Real home might be cached, but the link should be under fakeHome
		realLink := filepath.Join(realHome, ".codex", "skills", "prd")
		if info, err := os.Lstat(realLink); err == nil {
			target, _ := os.Readlink(realLink)
			absProject, _ := filepath.Abs(projectDir)
			expectedTarget := filepath.Join(absProject, ".hal", "skills", "prd")
			if target == expectedTarget {
				t.Fatalf("Link() wrote to real home dir %s (info: %v) — test isolation broken", realLink, info.Mode())
			}
		}
	}

	// Clean up
	if err := linker.Unlink(projectDir); err != nil {
		t.Fatalf("Unlink() error = %v", err)
	}
}
