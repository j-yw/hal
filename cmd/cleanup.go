package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var (
	cleanupDryRun  bool
	cleanupJSONFlag bool
)

// CleanupResult is the machine-readable output of hal cleanup --json.
type CleanupResult struct {
	ContractVersion int      `json:"contractVersion"`
	OK              bool     `json:"ok"`
	Removed         []string `json:"removed,omitempty"`
	DryRun          bool     `json:"dryRun"`
	Summary         string   `json:"summary"`
}

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Remove orphaned and deprecated files",
	Args:  noArgsValidation(),
	Long: `Remove orphaned and deprecated files from .hal/ and engine link directories.

This command removes:
  - .hal/auto-progress.txt (replaced by unified progress.txt)
  - .hal/rules/ directory (replaced by standards/)
  - .claude/skills/ralph (deprecated alias)
  - .pi/skills/ralph (deprecated alias)

Use --dry-run to preview what would be removed without making changes.

This command is idempotent and safe to run multiple times.`,
	Example: `  hal cleanup --dry-run
  hal cleanup
  hal cleanup --json`,
	RunE: runCleanup,
}

func init() {
	cleanupCmd.Flags().BoolVar(&cleanupDryRun, "dry-run", false, "Preview changes without removing files")
	cleanupCmd.Flags().BoolVar(&cleanupJSONFlag, "json", false, "Output machine-readable JSON result")
	rootCmd.AddCommand(cleanupCmd)
}

// orphanedFiles lists files that are no longer used and can be safely removed.
var orphanedFiles = []string{
	"auto-progress.txt", // Replaced by unified progress.txt
}

// orphanedDirs lists directories that are no longer used and can be safely removed.
var orphanedDirs = []string{
	"rules", // Replaced by standards/
}

func runCleanup(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	if cmd != nil {
		out = cmd.OutOrStdout()
	}
	if cleanupJSONFlag {
		return runCleanupJSON(template.HalDir, cleanupDryRun, out)
	}
	return runCleanupFn(template.HalDir, cleanupDryRun, out)
}

func runCleanupJSON(halDir string, dryRun bool, out io.Writer) error {
	var removed []string

	for _, file := range orphanedFiles {
		path := filepath.Join(halDir, file)
		info, err := os.Stat(path)
		if os.IsNotExist(err) || (err == nil && info.IsDir()) {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", file, err)
		}
		if !dryRun {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("failed to remove %s: %w", file, err)
			}
		}
		removed = append(removed, file)
	}

	for _, dir := range orphanedDirs {
		path := filepath.Join(halDir, dir)
		info, err := os.Stat(path)
		if os.IsNotExist(err) || (err == nil && !info.IsDir()) {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", dir, err)
		}
		if !dryRun {
			if err := os.RemoveAll(path); err != nil {
				return fmt.Errorf("failed to remove %s: %w", dir, err)
			}
		}
		removed = append(removed, dir+"/")
	}

	// Clean deprecated engine skill links (project-local)
	projectDir := filepath.Dir(halDir)
	for _, link := range deprecatedSkillLinks(projectDir) {
		if _, err := os.Lstat(link); os.IsNotExist(err) {
			continue
		}
		if !dryRun {
			if err := os.RemoveAll(link); err != nil {
				return fmt.Errorf("failed to remove %s: %w", link, err)
			}
		}
		removed = append(removed, link)
	}

	jr := CleanupResult{
		ContractVersion: 1,
		OK:              true,
		Removed:         removed,
		DryRun:          dryRun,
	}
	if len(removed) == 0 {
		jr.Summary = "No orphaned files found."
	} else if dryRun {
		jr.Summary = fmt.Sprintf("Would remove %d item(s).", len(removed))
	} else {
		jr.Summary = fmt.Sprintf("Removed %d item(s).", len(removed))
	}

	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cleanup result: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func runCleanupFn(halDir string, dryRun bool, w io.Writer) error {
	removed := 0

	for _, file := range orphanedFiles {
		path := filepath.Join(halDir, file)
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", file, err)
		}
		if info.IsDir() {
			continue
		}

		if dryRun {
			fmt.Fprintf(w, "Would remove: %s\n", path)
		} else {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("failed to remove %s: %w", file, err)
			}
			fmt.Fprintf(w, "Removed: %s\n", path)
		}
		removed++
	}

	for _, dir := range orphanedDirs {
		path := filepath.Join(halDir, dir)
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", dir, err)
		}
		if !info.IsDir() {
			continue
		}

		if dryRun {
			fmt.Fprintf(w, "Would remove: %s/\n", path)
		} else {
			if err := os.RemoveAll(path); err != nil {
				return fmt.Errorf("failed to remove %s: %w", dir, err)
			}
			fmt.Fprintf(w, "Removed: %s/\n", path)
		}
		removed++
	}

	// Clean deprecated engine skill links (project-local)
	projectDir := filepath.Dir(halDir) // halDir is .hal, parent is project root
	for _, link := range deprecatedSkillLinks(projectDir) {
		if _, err := os.Lstat(link); os.IsNotExist(err) {
			continue
		}
		if dryRun {
			fmt.Fprintf(w, "Would remove: %s\n", link)
		} else {
			if err := os.RemoveAll(link); err != nil {
				return fmt.Errorf("failed to remove %s: %w", link, err)
			}
			fmt.Fprintf(w, "Removed: %s\n", link)
		}
		removed++
	}

	if removed == 0 {
		fmt.Fprintln(w, "No orphaned files found.")
	} else if dryRun {
		fmt.Fprintf(w, "\nWould remove %d item(s). Run without --dry-run to remove.\n", removed)
	} else {
		fmt.Fprintf(w, "\nRemoved %d item(s).\n", removed)
	}

	return nil
}

// deprecatedSkillLinks returns paths to deprecated skill links that should be removed.
func deprecatedSkillLinks(projectDir string) []string {
	return []string{
		filepath.Join(projectDir, ".claude", "skills", "ralph"),
		filepath.Join(projectDir, ".pi", "skills", "ralph"),
	}
}
