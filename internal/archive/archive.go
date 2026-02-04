package archive

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/template"
)

// featureStateFiles are the files that belong to a feature and should be archived.
// Reports are handled separately via glob.
var featureStateFiles = []string{
	template.PRDFile,
	template.AutoPRDFile,
	template.ProgressFile,
	template.AutoProgressFile,
	template.AutoStateFile,
}

// protectedPaths are paths that must never be archived.
var protectedPaths = map[string]bool{
	template.ConfigFile: true,
	template.PromptFile: true,
	"skills":            true,
	"archive":           true,
	"rules":             true,
}

// Create moves all feature state files from halDir into halDir/archive/<date>-<name>/.
// It returns the archive directory path on success.
// If no prd.json and no auto-prd.json exist, it returns an error (no feature state to archive).
func Create(halDir, name string, w io.Writer) (string, error) {
	// Check that at least one PRD file exists
	hasPRD := fileExists(filepath.Join(halDir, template.PRDFile))
	hasAutoPRD := fileExists(filepath.Join(halDir, template.AutoPRDFile))
	if !hasPRD && !hasAutoPRD {
		return "", fmt.Errorf("no feature state to archive (no %s or %s found)", template.PRDFile, template.AutoPRDFile)
	}

	// Build archive directory name
	datePart := time.Now().Format("2006-01-02")
	baseName := fmt.Sprintf("%s-%s", datePart, name)
	archiveDir := filepath.Join(halDir, "archive", baseName)

	// Handle name collision
	archiveDir = resolveCollision(archiveDir)

	// Create archive directory
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create archive directory: %w", err)
	}

	moved := 0

	// Move known state files
	for _, f := range featureStateFiles {
		src := filepath.Join(halDir, f)
		if !fileExists(src) {
			continue
		}
		dst := filepath.Join(archiveDir, f)
		if err := os.Rename(src, dst); err != nil {
			return "", fmt.Errorf("failed to move %s: %w", f, err)
		}
		fmt.Fprintf(w, "  archived %s\n", f)
		moved++
	}

	// Move prd-*.md files (glob)
	prdMDs, _ := filepath.Glob(filepath.Join(halDir, "prd-*.md"))
	for _, src := range prdMDs {
		base := filepath.Base(src)
		dst := filepath.Join(archiveDir, base)
		if err := os.Rename(src, dst); err != nil {
			return "", fmt.Errorf("failed to move %s: %w", base, err)
		}
		fmt.Fprintf(w, "  archived %s\n", base)
		moved++
	}

	// Move reports/*.md (but NOT .gitkeep)
	reportsDir := filepath.Join(halDir, "reports")
	if dirExists(reportsDir) {
		reportFiles, _ := filepath.Glob(filepath.Join(reportsDir, "*.md"))
		if len(reportFiles) > 0 {
			archiveReportsDir := filepath.Join(archiveDir, "reports")
			if err := os.MkdirAll(archiveReportsDir, 0755); err != nil {
				return "", fmt.Errorf("failed to create archive reports directory: %w", err)
			}
			for _, src := range reportFiles {
				base := filepath.Base(src)
				dst := filepath.Join(archiveReportsDir, base)
				if err := os.Rename(src, dst); err != nil {
					return "", fmt.Errorf("failed to move reports/%s: %w", base, err)
				}
				fmt.Fprintf(w, "  archived reports/%s\n", base)
				moved++
			}
		}
	}

	if moved == 0 {
		// Clean up empty archive dir
		os.Remove(archiveDir)
		return "", fmt.Errorf("no feature state files found to archive")
	}

	fmt.Fprintf(w, "  archived to %s\n", filepath.Base(archiveDir))
	return archiveDir, nil
}

// FeatureFromBranch trims the hal/ prefix from a branch name.
func FeatureFromBranch(branchName string) string {
	return strings.TrimPrefix(branchName, "hal/")
}

// resolveCollision appends -2, -3, etc. if the directory already exists.
func resolveCollision(dir string) string {
	if !dirExists(dir) {
		return dir
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", dir, i)
		if !dirExists(candidate) {
			return candidate
		}
	}
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
