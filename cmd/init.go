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
    config.yaml    # Configuration settings
    prompt.md      # Agent instructions template
    progress.txt   # Progress log for learnings
    archive/       # Archived runs
    reports/       # Analysis reports for auto mode
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
	reportsDir := filepath.Join(configDir, "reports")
	projectDir := "."

	// Create directories (MkdirAll is idempotent - won't fail if exists)
	if err := os.MkdirAll(archiveDir, 0755); err != nil {
		return fmt.Errorf("failed to create directories: %w", err)
	}
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return fmt.Errorf("failed to create reports directory: %w", err)
	}

	// Create default files from templates only if they don't exist
	var created, skipped []string
	for filename, content := range template.DefaultFiles() {
		filePath := filepath.Join(configDir, filename)
		if _, err := os.Stat(filePath); err == nil {
			skipped = append(skipped, filename)
			continue
		}
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			return fmt.Errorf("failed to write %s: %w", filename, err)
		}
		created = append(created, filename)
	}

	// Create .gitkeep in archive only if it doesn't exist
	gitkeepPath := filepath.Join(archiveDir, ".gitkeep")
	if _, err := os.Stat(gitkeepPath); os.IsNotExist(err) {
		if err := os.WriteFile(gitkeepPath, []byte(""), 0644); err != nil {
			return fmt.Errorf("failed to write .gitkeep: %w", err)
		}
	}

	// Create .gitkeep in reports only if it doesn't exist
	reportsGitkeepPath := filepath.Join(reportsDir, ".gitkeep")
	if _, err := os.Stat(reportsGitkeepPath); os.IsNotExist(err) {
		if err := os.WriteFile(reportsGitkeepPath, []byte(""), 0644); err != nil {
			return fmt.Errorf("failed to write reports .gitkeep: %w", err)
		}
	}

	// Install embedded skills to .goralph/skills/
	if err := skills.InstallSkills(projectDir); err != nil {
		return fmt.Errorf("failed to install skills: %w", err)
	}

	// Create symlinks for engine skill discovery
	if err := skills.LinkAllEngines(projectDir); err != nil {
		_ = err // Errors are logged as warnings in LinkAllEngines.
	}

	fmt.Println("Initialized .goralph/")
	fmt.Println()

	if len(created) > 0 {
		fmt.Println("Created:")
		for _, f := range created {
			fmt.Printf("  .goralph/%s\n", f)
		}
	}

	if len(skipped) > 0 {
		fmt.Println("Already existed (preserved):")
		for _, f := range skipped {
			fmt.Printf("  .goralph/%s\n", f)
		}
	}

	if len(created) == 0 && len(skipped) > 0 {
		fmt.Println()
		fmt.Println("All files already exist. No changes made.")
	} else {
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Println("  1. Run: goralph plan \"feature description\" to generate a PRD")
		fmt.Println("  2. Or create .goralph/prd.json manually")
		fmt.Println("  3. Run: goralph run")
	}

	return nil
}
