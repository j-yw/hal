package skills

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPiLinkerName(t *testing.T) {
	linker := &PiLinker{}
	if got := linker.Name(); got != "pi" {
		t.Errorf("Name() = %q, want %q", got, "pi")
	}
}

func TestPiLinkerSkillsDir(t *testing.T) {
	linker := &PiLinker{}
	if got := linker.SkillsDir(); got != ".pi/skills" {
		t.Errorf("SkillsDir() = %q, want %q", got, ".pi/skills")
	}
}

func TestPiLinkerLink(t *testing.T) {
	projectDir := t.TempDir()
	halSkillsDir := filepath.Join(projectDir, ".hal", "skills", "testskill")
	if err := os.MkdirAll(halSkillsDir, 0755); err != nil {
		t.Fatalf("failed to create .hal/skills/testskill: %v", err)
	}

	linker := &PiLinker{}
	if err := linker.Link(projectDir, []string{"testskill"}); err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	// Verify symlink was created
	linkPath := filepath.Join(projectDir, ".pi", "skills", "testskill")
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("Symlink not created: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("Created file is not a symlink")
	}

	// Verify symlink target is relative
	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("Could not read symlink: %v", err)
	}
	expected := filepath.Join("..", "..", ".hal", "skills", "testskill")
	if target != expected {
		t.Errorf("Symlink target = %q, want %q", target, expected)
	}

	// Verify symlink resolves to the actual directory
	resolved, err := filepath.EvalSymlinks(linkPath)
	if err != nil {
		t.Fatalf("Could not resolve symlink: %v", err)
	}
	wantResolved := halSkillsDir
	if resolved != wantResolved {
		t.Errorf("Resolved symlink = %q, want %q", resolved, wantResolved)
	}
}

func TestPiLinkerLinkIdempotent(t *testing.T) {
	projectDir := t.TempDir()
	halSkillsDir := filepath.Join(projectDir, ".hal", "skills", "testskill")
	if err := os.MkdirAll(halSkillsDir, 0755); err != nil {
		t.Fatalf("failed to create .hal/skills/testskill: %v", err)
	}

	linker := &PiLinker{}

	// Link twice — should not error
	if err := linker.Link(projectDir, []string{"testskill"}); err != nil {
		t.Fatalf("First Link() error = %v", err)
	}
	if err := linker.Link(projectDir, []string{"testskill"}); err != nil {
		t.Fatalf("Second Link() error = %v", err)
	}
}

func TestPiLinkerUnlink(t *testing.T) {
	projectDir := t.TempDir()
	halSkillsDir := filepath.Join(projectDir, ".hal", "skills", "prd")
	if err := os.MkdirAll(halSkillsDir, 0755); err != nil {
		t.Fatalf("failed to create .hal/skills/prd: %v", err)
	}

	linker := &PiLinker{}

	// Link first
	if err := linker.Link(projectDir, []string{"prd"}); err != nil {
		t.Fatalf("Link() error = %v", err)
	}

	// Verify it exists
	linkPath := filepath.Join(projectDir, ".pi", "skills", "prd")
	if _, err := os.Lstat(linkPath); err != nil {
		t.Fatalf("Symlink should exist after Link: %v", err)
	}

	// Unlink
	if err := linker.Unlink(projectDir); err != nil {
		t.Fatalf("Unlink() error = %v", err)
	}

	// Verify symlink was removed
	if _, err := os.Lstat(linkPath); !os.IsNotExist(err) {
		t.Error("Symlink should have been removed after Unlink")
	}
}

func TestPiLinkerRegistered(t *testing.T) {
	linker := GetLinker("pi")
	if linker == nil {
		t.Error("PiLinker should be registered via init()")
	}
}
