package compound

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/template"
)

// DisplayWriter is an interface for display output used during migration.
// It is satisfied by *engine.Display.
type DisplayWriter interface {
	ShowInfo(format string, args ...any)
}

// MigrateLegacyAutoPRD migrates .hal/auto-prd.json to .hal/prd.json.
//
// Rules:
//   - If auto-prd.json exists and prd.json does not, auto-prd.json is renamed to prd.json.
//   - If both files exist and are semantically equal JSON, auto-prd.json is deleted.
//   - If both files exist and differ (or cannot be compared), auto-prd.json is preserved as
//     auto-prd.legacy-<ts>.json and a warning is emitted to errOut (if provided).
func MigrateLegacyAutoPRD(dir string, errOut io.Writer) error {
	return migrateLegacyAutoPRDWithNow(dir, errOut, time.Now)
}

func migrateLegacyAutoPRDWithNow(dir string, errOut io.Writer, nowFn func() time.Time) error {
	halDir := filepath.Join(dir, template.HalDir)
	autoPRDPath := filepath.Join(halDir, template.AutoPRDFile)
	prdPath := filepath.Join(halDir, template.PRDFile)

	autoData, err := os.ReadFile(autoPRDPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", template.AutoPRDFile, err)
	}

	prdData, err := os.ReadFile(prdPath)
	if os.IsNotExist(err) {
		if err := os.Rename(autoPRDPath, prdPath); err != nil {
			return fmt.Errorf("failed to migrate %s to %s: %w", template.AutoPRDFile, template.PRDFile, err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("failed to read %s: %w", template.PRDFile, err)
	}

	equal, cmpErr := jsonSemanticallyEqual(prdData, autoData)
	if cmpErr == nil && equal {
		if err := os.Remove(autoPRDPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove legacy %s: %w", template.AutoPRDFile, err)
		}
		return nil
	}

	legacyPath, err := nextLegacyAutoPRDPath(halDir, nowFn)
	if err != nil {
		return err
	}

	if err := os.Rename(autoPRDPath, legacyPath); err != nil {
		return fmt.Errorf("failed to preserve legacy %s: %w", template.AutoPRDFile, err)
	}

	if errOut != nil {
		preservedPath := filepath.Join(template.HalDir, filepath.Base(legacyPath))
		if cmpErr != nil {
			fmt.Fprintf(errOut, "warning: could not compare %s to %s (%v); preserved legacy file at %s\n", template.AutoPRDFile, template.PRDFile, cmpErr, preservedPath)
		} else {
			fmt.Fprintf(errOut, "warning: %s differs from %s; preserved legacy file at %s\n", template.AutoPRDFile, template.PRDFile, preservedPath)
		}
	}

	return nil
}

func nextLegacyAutoPRDPath(halDir string, nowFn func() time.Time) (string, error) {
	ext := filepath.Ext(template.AutoPRDFile)
	if ext == "" {
		ext = ".json"
	}
	base := strings.TrimSuffix(template.AutoPRDFile, ext)
	timestamp := nowFn().UTC().Format("20060102-150405")

	for i := 0; i < 1000; i++ {
		suffix := ""
		if i > 0 {
			suffix = fmt.Sprintf("-%d", i+1)
		}

		name := fmt.Sprintf("%s.legacy-%s%s%s", base, timestamp, suffix, ext)
		path := filepath.Join(halDir, name)

		if _, err := os.Stat(path); os.IsNotExist(err) {
			return path, nil
		} else if err != nil {
			return "", fmt.Errorf("failed to check legacy auto PRD path %q: %w", path, err)
		}
	}

	return "", fmt.Errorf("failed to allocate legacy backup path for %s", template.AutoPRDFile)
}

func jsonSemanticallyEqual(left, right []byte) (bool, error) {
	var leftValue any
	if err := json.Unmarshal(left, &leftValue); err != nil {
		return false, err
	}

	var rightValue any
	if err := json.Unmarshal(right, &rightValue); err != nil {
		return false, err
	}

	return reflect.DeepEqual(leftValue, rightValue), nil
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
