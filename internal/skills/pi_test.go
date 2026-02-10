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

func TestPiLinkerCommandsDir(t *testing.T) {
	linker := &PiLinker{}
	if got := linker.CommandsDir(); got != ".pi/prompts" {
		t.Errorf("CommandsDir() = %q, want %q", got, ".pi/prompts")
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

	resolvedInfo, err := os.Stat(resolved)
	if err != nil {
		t.Fatalf("Could not stat resolved symlink target %q: %v", resolved, err)
	}
	wantInfo, err := os.Stat(halSkillsDir)
	if err != nil {
		t.Fatalf("Could not stat expected target %q: %v", halSkillsDir, err)
	}
	if !os.SameFile(resolvedInfo, wantInfo) {
		t.Errorf("Resolved symlink target %q does not match expected directory %q", resolved, halSkillsDir)
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

func TestPiLinkerLinkCommands(t *testing.T) {
	projectDir := t.TempDir()
	halCommandsDir := filepath.Join(projectDir, ".hal", "commands")
	if err := os.MkdirAll(halCommandsDir, 0755); err != nil {
		t.Fatalf("failed to create .hal/commands: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halCommandsDir, "discover-standards.md"), []byte("discover"), 0644); err != nil {
		t.Fatalf("failed to write discover-standards.md: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halCommandsDir, "ignore.txt"), []byte("ignore"), 0644); err != nil {
		t.Fatalf("failed to write ignore.txt: %v", err)
	}

	promptsDir := filepath.Join(projectDir, ".pi", "prompts")
	if err := os.MkdirAll(promptsDir, 0755); err != nil {
		t.Fatalf("failed to create .pi/prompts: %v", err)
	}
	customPrompt := filepath.Join(promptsDir, "custom.md")
	if err := os.WriteFile(customPrompt, []byte("custom"), 0644); err != nil {
		t.Fatalf("failed to write custom prompt: %v", err)
	}

	// Simulate stale managed prompt materialized as a regular file
	// (e.g., from a symlink checkout fallback).
	staleManagedPrompt := filepath.Join(promptsDir, "discover-standards.md")
	if err := os.WriteFile(staleManagedPrompt, []byte("stale"), 0644); err != nil {
		t.Fatalf("failed to write stale managed prompt: %v", err)
	}

	legacyCommandsDir := filepath.Join(projectDir, ".pi", "commands")
	if err := os.MkdirAll(legacyCommandsDir, 0755); err != nil {
		t.Fatalf("failed to create .pi/commands: %v", err)
	}
	legacyLink := filepath.Join(legacyCommandsDir, "hal")
	if err := os.Symlink(filepath.Join("..", "..", ".hal", "commands"), legacyLink); err != nil {
		t.Fatalf("failed to create legacy link: %v", err)
	}

	linker := &PiLinker{}
	if err := linker.LinkCommands(projectDir); err != nil {
		t.Fatalf("LinkCommands() error = %v", err)
	}

	linkPath := filepath.Join(promptsDir, "discover-standards.md")
	info, err := os.Lstat(linkPath)
	if err != nil {
		t.Fatalf("expected command prompt link to exist: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("expected %s to be a symlink", linkPath)
	}

	target, err := os.Readlink(linkPath)
	if err != nil {
		t.Fatalf("failed to read command prompt link: %v", err)
	}
	expectedTarget := filepath.Join("..", "..", ".hal", "commands", "discover-standards.md")
	if target != expectedTarget {
		t.Fatalf("command prompt target = %q, want %q", target, expectedTarget)
	}

	if _, err := os.Stat(customPrompt); err != nil {
		t.Fatalf("custom prompt should be preserved: %v", err)
	}
	if info, err := os.Lstat(customPrompt); err != nil {
		t.Fatalf("failed to stat custom prompt: %v", err)
	} else if info.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("custom prompt should not be replaced with symlink")
	}

	if _, err := os.Lstat(legacyLink); !os.IsNotExist(err) {
		t.Fatalf("legacy .pi/commands/hal link should be removed")
	}
}

func TestPiLinkerUnlink(t *testing.T) {
	projectDir := t.TempDir()
	halSkillsDir := filepath.Join(projectDir, ".hal", "skills", "prd")
	if err := os.MkdirAll(halSkillsDir, 0755); err != nil {
		t.Fatalf("failed to create .hal/skills/prd: %v", err)
	}
	halCommandsDir := filepath.Join(projectDir, ".hal", "commands")
	if err := os.MkdirAll(halCommandsDir, 0755); err != nil {
		t.Fatalf("failed to create .hal/commands: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halCommandsDir, "discover-standards.md"), []byte("discover"), 0644); err != nil {
		t.Fatalf("failed to write discover-standards.md: %v", err)
	}
	if err := os.WriteFile(filepath.Join(halCommandsDir, "custom-command.md"), []byte("custom command"), 0644); err != nil {
		t.Fatalf("failed to write custom-command.md: %v", err)
	}

	linker := &PiLinker{}

	// Link first
	if err := linker.Link(projectDir, []string{"prd"}); err != nil {
		t.Fatalf("Link() error = %v", err)
	}
	if err := linker.LinkCommands(projectDir); err != nil {
		t.Fatalf("LinkCommands() error = %v", err)
	}

	// Verify links exist
	skillLinkPath := filepath.Join(projectDir, ".pi", "skills", "prd")
	if _, err := os.Lstat(skillLinkPath); err != nil {
		t.Fatalf("skill symlink should exist after Link: %v", err)
	}
	commandLinkPath := filepath.Join(projectDir, ".pi", "prompts", "discover-standards.md")
	if _, err := os.Lstat(commandLinkPath); err != nil {
		t.Fatalf("command symlink should exist after LinkCommands: %v", err)
	}
	customCommandLinkPath := filepath.Join(projectDir, ".pi", "prompts", "custom-command.md")
	if _, err := os.Lstat(customCommandLinkPath); err != nil {
		t.Fatalf("custom command symlink should exist after LinkCommands: %v", err)
	}

	customPromptPath := filepath.Join(projectDir, ".pi", "prompts", "custom.md")
	if err := os.WriteFile(customPromptPath, []byte("custom"), 0644); err != nil {
		t.Fatalf("failed to write custom prompt: %v", err)
	}

	// Unlink
	if err := linker.Unlink(projectDir); err != nil {
		t.Fatalf("Unlink() error = %v", err)
	}

	// Verify managed symlinks were removed
	if _, err := os.Lstat(skillLinkPath); !os.IsNotExist(err) {
		t.Error("skill symlink should have been removed after Unlink")
	}
	if _, err := os.Lstat(commandLinkPath); !os.IsNotExist(err) {
		t.Error("command symlink should have been removed after Unlink")
	}
	if _, err := os.Lstat(customCommandLinkPath); !os.IsNotExist(err) {
		t.Error("custom command symlink should have been removed after Unlink")
	}

	// Verify user prompt file is preserved
	if _, err := os.Stat(customPromptPath); err != nil {
		t.Fatalf("custom prompt should be preserved after Unlink: %v", err)
	}
}

func TestPiLinkerRegistered(t *testing.T) {
	linker := GetLinker("pi")
	if linker == nil {
		t.Error("PiLinker should be registered via init()")
	}
}
