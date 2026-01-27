package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jywlabs/goralph/internal/skills"
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
    skills/        # PRD and Ralph skills
      prd/         # PRD generation skill
      ralph/       # PRD-to-JSON conversion skill

Also creates .claude/skills/ with symlinks to .goralph/skills/ for Claude Code
skill discovery.

After init, create a prd.json with your user stories and run 'goralph run'.
Or use 'goralph plan' to interactively generate a PRD.`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	configDir := template.GoralphDir
	archiveDir := filepath.Join(configDir, "archive")
	projectDir := "."

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

	// Install embedded skills to .goralph/skills/
	if err := skills.InstallSkills(projectDir); err != nil {
		return fmt.Errorf("failed to install skills: %w", err)
	}

	// Create symlinks for engine skill discovery
	skills.LinkAllEngines(projectDir) // Errors are logged as warnings

	fmt.Println("Initialized .goralph/")
	fmt.Println()
	fmt.Println("Created:")
	fmt.Println("  .goralph/prompt.md       - Agent instructions (customize for your project)")
	fmt.Println("  .goralph/progress.txt    - Progress log for learnings")
	fmt.Println("  .goralph/archive/        - Archived previous runs")
	fmt.Println("  .goralph/skills/         - PRD and Ralph skills")
	fmt.Println("  .claude/skills/          - Symlinks for Claude Code discovery")
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Run: goralph plan \"feature description\" to generate a PRD")
	fmt.Println("  2. Or create .goralph/prd.json manually")
	fmt.Println("  3. Run: goralph run")

	return nil
}
