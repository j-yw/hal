package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jywlabs/goralph/internal/template"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize .goralph/ directory",
	Long: `Initialize the .goralph/ directory in the current project.

Creates:
  .goralph/
    prompt.md      # Agent instructions template
    progress.txt   # Progress log for learnings
    archive/       # Archived runs

After init, create a prd.json with your user stories and run 'goralph run'.`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	configDir := template.GoralphDir
	archiveDir := filepath.Join(configDir, "archive")

	// Check if already initialized
	if _, err := os.Stat(configDir); err == nil {
		return fmt.Errorf(".goralph/ already exists")
	}

	// Create directories
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}

	// Create default files from templates
	for filename, content := range template.DefaultFiles() {
		filePath := filepath.Join(configDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", filename, err)
		}
	}

	// Create .gitkeep in archive
	gitkeepPath := filepath.Join(archiveDir, ".gitkeep")
	if err := os.WriteFile(gitkeepPath, []byte(""), 0644); err != nil {
		return fmt.Errorf("failed to write .gitkeep: %w", err)
	}

	fmt.Println("Initialized .goralph/")
	fmt.Println()
	fmt.Println("Created:")
	fmt.Println("  .goralph/prompt.md      - Agent instructions (customize for your project)")
	fmt.Println("  .goralph/progress.txt   - Progress log for learnings")
	fmt.Println("  .goralph/archive/       - Archived previous runs")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Create .goralph/prd.json with your user stories")
	fmt.Println("  2. Run: goralph run")

	return nil
}
