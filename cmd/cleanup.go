package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var cleanupDryRun bool

var cleanupCmd = &cobra.Command{
	Use:   "cleanup",
	Short: "Remove orphaned files from .hal/",
	Long: `Remove orphaned files from .hal/ that are no longer used.

This command removes:
  - auto-progress.txt (replaced by unified progress.txt)

Use --dry-run to preview what would be removed without making changes.

This command is idempotent and safe to run multiple times.`,
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

func runCleanup(cmd *cobra.Command, args []string) error {
	halDir := template.HalDir
	removed := 0

	for _, file := range orphanedFiles {
		path := filepath.Join(halDir, file)
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			// File doesn't exist, nothing to do
			continue
		}
		if err != nil {
			return fmt.Errorf("failed to stat %s: %w", file, err)
		}
		if info.IsDir() {
			// Skip directories for safety
			continue
		}

		if cleanupDryRun {
			fmt.Printf("Would remove: %s\n", path)
		} else {
			if err := os.Remove(path); err != nil {
				return fmt.Errorf("failed to remove %s: %w", file, err)
			}
			fmt.Printf("Removed: %s\n", path)
		}
		removed++
	}

	if removed == 0 {
		fmt.Println("No orphaned files found.")
	} else if cleanupDryRun {
		fmt.Printf("\nWould remove %d file(s). Run without --dry-run to remove.\n", removed)
	} else {
		fmt.Printf("\nRemoved %d file(s).\n", removed)
	}

	return nil
}
