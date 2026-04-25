package skills

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveLegacyManagedSkillSymlinksPreservesUnrelatedSymlink(t *testing.T) {
	projectDir := t.TempDir()
	skillsDir := filepath.Join(projectDir, ".pi", "skills")
	if err := os.MkdirAll(skillsDir, 0755); err != nil {
		t.Fatalf("failed to create skills dir: %v", err)
	}

	userTarget := filepath.Join(projectDir, "user-skills", "product")
	if err := os.MkdirAll(userTarget, 0755); err != nil {
		t.Fatalf("failed to create user target: %v", err)
	}
	link := filepath.Join(skillsDir, "product")
	if err := os.Symlink(userTarget, link); err != nil {
		t.Fatalf("failed to create user product symlink: %v", err)
	}

	if err := removeLegacyManagedSkillSymlinks(skillsDir, projectDir); err != nil {
		t.Fatalf("removeLegacyManagedSkillSymlinks() error = %v", err)
	}

	if got, err := os.Readlink(link); err != nil || got != userTarget {
		t.Fatalf("unrelated product symlink should be preserved, got %q err %v", got, err)
	}
}

func TestRemoveLegacyManagedSkillSymlinksRemovesProjectLegacySymlink(t *testing.T) {
	projectDir := t.TempDir()
	skillsDir := filepath.Join(projectDir, ".pi", "skills")
	if err := os.MkdirAll(skillsDir, 0755); err != nil {
		t.Fatalf("failed to create skills dir: %v", err)
	}

	link := filepath.Join(skillsDir, "product")
	if err := os.Symlink(filepath.Join("..", "..", ".hal", "skills", "product"), link); err != nil {
		t.Fatalf("failed to create legacy product symlink: %v", err)
	}

	if err := removeLegacyManagedSkillSymlinks(skillsDir, projectDir); err != nil {
		t.Fatalf("removeLegacyManagedSkillSymlinks() error = %v", err)
	}

	if _, err := os.Lstat(link); !os.IsNotExist(err) {
		t.Fatalf("legacy managed product symlink should be removed")
	}
}
