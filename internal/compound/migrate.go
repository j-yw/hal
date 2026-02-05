package compound

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/template"
)

// DisplayWriter is an interface for display output used during migration.
// It is satisfied by *engine.Display.
type DisplayWriter interface {
	ShowInfo(format string, args ...any)
}

// MigrateAutoProgress migrates content from legacy auto-progress.txt to unified progress.txt.
// If auto-progress.txt exists, its content is appended to progress.txt and the legacy file is deleted.
// If display is nil, no status messages are printed.
func MigrateAutoProgress(dir string, display DisplayWriter) error {
	halDir := filepath.Join(dir, template.HalDir)
	autoProgressPath := filepath.Join(halDir, "auto-progress.txt")
	progressPath := filepath.Join(halDir, template.ProgressFile)

	// Check if legacy auto-progress.txt exists
	autoProgressData, err := os.ReadFile(autoProgressPath)
	if os.IsNotExist(err) {
		// No legacy file to migrate
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read auto-progress.txt: %w", err)
	}

	autoContent := string(autoProgressData)
	// Skip if auto-progress.txt is empty or just the default template
	if autoContent == "" || autoContent == template.DefaultProgress {
		// Remove empty/default legacy file
		if err := os.Remove(autoProgressPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove empty auto-progress.txt: %w", err)
		}
		if display != nil {
			display.ShowInfo("   Removed empty auto-progress.txt\n")
		}
		return nil
	}

	// Read current progress.txt content
	progressData, err := os.ReadFile(progressPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read progress.txt: %w", err)
	}
	progressContent := string(progressData)

	// Determine if progress.txt has meaningful content
	progressIsEmpty := progressContent == "" || progressContent == template.DefaultProgress

	var newContent string
	if progressIsEmpty {
		// Replace default/empty with auto-progress content
		newContent = autoContent
	} else {
		// Append auto-progress content with separator
		newContent = progressContent
		if !strings.HasSuffix(newContent, "\n") {
			newContent += "\n"
		}
		newContent += "\n---\n\n## Migrated from auto-progress.txt\n\n" + autoContent
	}

	// Write merged content to progress.txt
	if err := os.MkdirAll(halDir, 0755); err != nil {
		return fmt.Errorf("failed to create .hal directory: %w", err)
	}
	if err := os.WriteFile(progressPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write merged progress.txt: %w", err)
	}

	// Remove legacy auto-progress.txt
	if err := os.Remove(autoProgressPath); err != nil {
		return fmt.Errorf("failed to remove auto-progress.txt after migration: %w", err)
	}

	if display != nil {
		display.ShowInfo("   Migrated auto-progress.txt to progress.txt\n")
	}
	return nil
}
