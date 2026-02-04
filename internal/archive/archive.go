package archive

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jywlabs/hal/internal/engine"
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

// ArchiveInfo holds metadata about a single archive entry.
type ArchiveInfo struct {
	Name       string // Full directory name (e.g., "2026-02-04-my-feature")
	Date       string // Parsed date portion
	Feature    string // Parsed feature portion
	Dir        string // Full path to archive directory
	BranchName string // Branch name from prd.json
	Completed  int    // Stories with passes=true
	Total      int    // Total stories
}

// List scans halDir/archive/ and returns metadata for each archive directory.
// Returns an empty slice (not error) when no archives exist.
func List(halDir string) ([]ArchiveInfo, error) {
	archiveRoot := filepath.Join(halDir, "archive")
	entries, err := os.ReadDir(archiveRoot)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to read archive directory: %w", err)
	}

	var archives []ArchiveInfo
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		dir := filepath.Join(archiveRoot, name)

		info := ArchiveInfo{
			Name: name,
			Dir:  dir,
		}

		// Parse date and feature from name (YYYY-MM-DD-feature)
		if len(name) >= 10 {
			info.Date = name[:10]
			if len(name) > 11 {
				info.Feature = name[11:]
			}
		}

		// Try to load PRD for stats
		info.loadPRDStats()

		archives = append(archives, info)
	}

	// Sort by name (date-first means chronological)
	sort.Slice(archives, func(i, j int) bool {
		return archives[i].Name < archives[j].Name
	})

	return archives, nil
}

// loadPRDStats loads prd.json (or auto-prd.json fallback) from the archive dir.
func (a *ArchiveInfo) loadPRDStats() {
	for _, prdFile := range []string{template.PRDFile, template.AutoPRDFile} {
		data, err := os.ReadFile(filepath.Join(a.Dir, prdFile))
		if err != nil {
			continue
		}
		var prd engine.PRD
		if err := json.Unmarshal(data, &prd); err != nil {
			continue
		}
		a.BranchName = prd.BranchName
		completed, total := prd.Progress()
		a.Completed = completed
		a.Total = total
		return
	}
}

// FormatList prints a formatted table of archives.
func FormatList(archives []ArchiveInfo, w io.Writer, verbose bool) {
	if len(archives) == 0 {
		fmt.Fprintln(w, "No archives found.")
		return
	}

	if verbose {
		fmt.Fprintf(w, "%-30s  %-12s  %-10s  %-30s  %s\n", "NAME", "DATE", "PROGRESS", "BRANCH", "PATH")
		fmt.Fprintf(w, "%-30s  %-12s  %-10s  %-30s  %s\n",
			strings.Repeat("-", 30), strings.Repeat("-", 12), strings.Repeat("-", 10),
			strings.Repeat("-", 30), strings.Repeat("-", 4))
		for _, a := range archives {
			progress := fmt.Sprintf("%d/%d", a.Completed, a.Total)
			fmt.Fprintf(w, "%-30s  %-12s  %-10s  %-30s  %s\n", a.Name, a.Date, progress, a.BranchName, a.Dir)
		}
	} else {
		fmt.Fprintf(w, "%-30s  %-12s  %s\n", "NAME", "DATE", "PROGRESS")
		fmt.Fprintf(w, "%-30s  %-12s  %s\n",
			strings.Repeat("-", 30), strings.Repeat("-", 12), strings.Repeat("-", 8))
		for _, a := range archives {
			progress := fmt.Sprintf("%d/%d", a.Completed, a.Total)
			fmt.Fprintf(w, "%-30s  %-12s  %s\n", a.Name, a.Date, progress)
		}
	}
}

// Restore moves files from the named archive directory back into halDir.
// If current feature state exists, it auto-archives it first via Create.
func Restore(halDir, name string, w io.Writer) error {
	archiveDir := filepath.Join(halDir, "archive", name)
	if !dirExists(archiveDir) {
		return fmt.Errorf("archive %q does not exist", name)
	}

	// If current state exists, auto-archive it first
	hasPRD := fileExists(filepath.Join(halDir, template.PRDFile))
	hasAutoPRD := fileExists(filepath.Join(halDir, template.AutoPRDFile))
	if hasPRD || hasAutoPRD {
		fmt.Fprintln(w, "  auto-archiving current state...")
		_, err := Create(halDir, "auto-saved", w)
		if err != nil {
			return fmt.Errorf("failed to auto-archive current state: %w", err)
		}
	}

	// Move all files from archive back to halDir
	entries, err := os.ReadDir(archiveDir)
	if err != nil {
		return fmt.Errorf("failed to read archive directory: %w", err)
	}

	for _, entry := range entries {
		src := filepath.Join(archiveDir, entry.Name())
		dst := filepath.Join(halDir, entry.Name())

		if entry.IsDir() {
			// For directories like reports/, move contents
			if err := restoreDir(src, dst); err != nil {
				return fmt.Errorf("failed to restore %s: %w", entry.Name(), err)
			}
		} else {
			if err := os.Rename(src, dst); err != nil {
				return fmt.Errorf("failed to restore %s: %w", entry.Name(), err)
			}
		}
		fmt.Fprintf(w, "  restored %s\n", entry.Name())
	}

	// Remove the now-empty archive directory
	if err := os.Remove(archiveDir); err != nil {
		return fmt.Errorf("failed to remove archive directory: %w", err)
	}

	fmt.Fprintf(w, "  restored from %s\n", name)
	return nil
}

// restoreDir moves all files from src dir into dst dir.
func restoreDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		if err := os.Rename(srcPath, dstPath); err != nil {
			return err
		}
	}
	return os.Remove(src)
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
