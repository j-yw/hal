package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var cleanupDryRun bool

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Remove orphaned files from .hal/",
	Args:  noArgsValidation(),
	Long: `Remove orphaned files from .hal/ that are no longer used.

This command removes:
  - auto-progress.txt (replaced by unified progress.txt)
  - rules/ directory (replaced by standards/)

Use --dry-run to preview what would be removed without making changes.

This command is idempotent and safe to run multiple times.`,
	Example: `  hal cleanup --dry-run
  hal cleanup`,
	RunE: runCleanup,
}

func init() {
	cleanupCmd.Flags().BoolVar(&cleanupDryRun, "dry-run", false, "Preview changes without removing files")
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
	return runCleanupFn(template.HalDir, cleanupDryRun, os.Stdout)
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

	if removed == 0 {
		fmt.Fprintln(w, "No orphaned files found.")
	} else if dryRun {
		fmt.Fprintf(w, "\nWould remove %d item(s). Run without --dry-run to remove.\n", removed)
	} else {
		fmt.Fprintf(w, "\nRemoved %d item(s).\n", removed)
	}

	return nil
}
