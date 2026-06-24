package skills

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jywlabs/hal/internal/template"
)

func TestCodexHomePrefersCODEXHOMEOverHOME(t *testing.T) {
	codexRoot := t.TempDir()
	home := t.TempDir()
	t.Setenv("CODEX_HOME", codexRoot)
	t.Setenv("HOME", home)

	if got := codexHome(); got != codexRoot {
		t.Fatalf("codexHome() = %q, want %q", got, codexRoot)
	}
}

func TestCodexHomeUsesHOMEFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("CODEX_HOME", "")
	t.Setenv("HOME", home)

	want := filepath.Join(home, ".codex")
	if got := codexHome(); got != want {
		t.Fatalf("codexHome() = %q, want %q", got, want)
	}
}

func TestCodexHomeUsesUserHomeDirFallback(t *testing.T) {
	oldUserHomeDir := userHomeDir
	t.Cleanup(func() {
		userHomeDir = oldUserHomeDir
	})

	fallbackHome := t.TempDir()
	userHomeDir = func() (string, error) {
		return fallbackHome, nil
	}
	t.Setenv("CODEX_HOME", "")
	t.Setenv("HOME", "")

	want := filepath.Join(fallbackHome, ".codex")
	if got := codexHome(); got != want {
		t.Fatalf("codexHome() = %q, want %q", got, want)
	}
}

func TestCodexLinkerRespectsCODEXHOMEEnv(t *testing.T) {
	codexRoot := t.TempDir()
	home := t.TempDir()
	t.Setenv("CODEX_HOME", codexRoot)
	t.Setenv("HOME", home)

	linker := &CodexLinker{}

	skillsDir := linker.SkillsDir()
	wantSkills := filepath.Join(codexRoot, "skills")
	if skillsDir != wantSkills {
		t.Fatalf("SkillsDir() = %q, want %q", skillsDir, wantSkills)
	}

	cmdsDir := linker.CommandsDir()
	wantCmds := filepath.Join(codexRoot, "commands", "hal")
	if cmdsDir != wantCmds {
		t.Fatalf("CommandsDir() = %q, want %q", cmdsDir, wantCmds)
	}
}

// TestCodexLinkerRespectsHOMEEnv verifies that the CodexLinker uses $HOME
// for global paths when $CODEX_HOME is unset, ensuring test isolation.
func TestCodexLinkerRespectsHOMEEnv(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("CODEX_HOME", "")
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

func TestCodexLinkerCreatesLinksUnderActiveCodexHome(t *testing.T) {
	tests := []struct {
		name         string
		setCodexHome bool
	}{
		{name: "CODEX_HOME", setCodexHome: true},
		{name: "HOME fallback", setCodexHome: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codexRoot := t.TempDir()
			home := t.TempDir()
			if tt.setCodexHome {
				t.Setenv("CODEX_HOME", codexRoot)
			} else {
				t.Setenv("CODEX_HOME", "")
			}
			t.Setenv("HOME", home)

			wantRoot := filepath.Join(home, ".codex")
			if tt.setCodexHome {
				wantRoot = codexRoot
			}

			projectDir := newCodexLinkProject(t)
			linker := &CodexLinker{}

			if err := linker.Link(projectDir, []string{"prd"}); err != nil {
				t.Fatalf("Link() error = %v", err)
			}
			if err := linker.LinkCommands(projectDir); err != nil {
				t.Fatalf("LinkCommands() error = %v", err)
			}

			absProjectDir, err := filepath.Abs(projectDir)
			if err != nil {
				t.Fatalf("Abs(%q) error = %v", projectDir, err)
			}
			assertSymlinkTarget(t,
				filepath.Join(wantRoot, "skills", "prd"),
				filepath.Join(absProjectDir, template.HalDir, "skills", "prd"),
			)
			assertSymlinkTarget(t,
				filepath.Join(wantRoot, "commands", "hal"),
				filepath.Join(absProjectDir, template.HalDir, "commands"),
			)

			if tt.setCodexHome {
				assertMissing(t, filepath.Join(home, ".codex", "skills", "prd"))
				assertMissing(t, filepath.Join(home, ".codex", "commands", "hal"))
			}
		})
	}
}

// TestCodexLinkerLinkDoesNotPolluteRealHome verifies that Link/Unlink
// with $HOME set to a temp dir only writes to that temp dir.
func TestCodexLinkerLinkDoesNotPolluteRealHome(t *testing.T) {
	fakeHome := t.TempDir()
	t.Setenv("CODEX_HOME", "")
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

func newCodexLinkProject(t *testing.T) string {
	t.Helper()

	projectDir := t.TempDir()
	for _, dir := range []string{
		filepath.Join(projectDir, template.HalDir, "skills", "prd"),
		filepath.Join(projectDir, template.HalDir, "commands"),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("failed to create %s: %v", dir, err)
		}
	}

	return projectDir
}

func assertSymlinkTarget(t *testing.T, link, wantTarget string) {
	t.Helper()

	info, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("expected symlink at %s: %v", link, err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("%s is not a symlink", link)
	}
	target, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("Readlink(%s) error = %v", link, err)
	}
	if target != wantTarget {
		t.Fatalf("Readlink(%s) = %q, want %q", link, target, wantTarget)
	}
}

func assertMissing(t *testing.T, path string) {
	t.Helper()

	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("%s should not exist; err=%v", path, err)
	}
}
