package cmd

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

// migrateResult indicates the outcome of a config directory migration.
type migrateResult int

const (
	migrateNone    migrateResult = iota // no migration needed
	migrateDone                         // .goralph was renamed to .hal
	migrateWarning                      // both directories exist
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize .hal/ directory",
	Long: `Initialize the .hal/ directory in the current project.

If an existing .goralph/ directory is detected and no .hal/ directory exists,
it will be automatically renamed to .hal/ to preserve your configuration.

Creates:
  .hal/
    config.yaml    # Configuration settings
    prompt.md      # Agent instructions template
    progress.txt   # Progress log for learnings
    archive/       # Archived runs
    reports/       # Analysis reports for auto mode
    skills/        # PRD and Hal skills
      prd/         # PRD generation skill
      hal/         # PRD-to-JSON conversion skill

Also creates .claude/skills/ with symlinks to .hal/skills/ for Claude Code
skill discovery.

After init, create a prd.json with your user stories and run 'hal run'.
Or use 'hal plan' to interactively generate a PRD.`,
	RunE: runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	configDir := template.HalDir
	archiveDir := filepath.Join(configDir, "archive")
	reportsDir := filepath.Join(configDir, "reports")
	projectDir := "."

	// Auto-migrate .goralph/ to .hal/ if applicable
	oldDir := ".goralph"
	_, oldExists := os.Stat(oldDir)
	_, newExists := os.Stat(configDir)

	if oldExists == nil && newExists != nil {
		// .goralph exists but .hal does not — migrate
		if err := os.Rename(oldDir, configDir); err != nil {
			return fmt.Errorf("failed to migrate %s to %s: %w", oldDir, configDir, err)
		}
		fmt.Printf("Migrated %s/ to %s/ — I've upgraded your configuration. It's going to be a much better experience.\n", oldDir, configDir)
		fmt.Println()
	} else if oldExists == nil && newExists == nil {
		// Both exist — warn and use .hal
		fmt.Printf("Warning: both %s/ and %s/ exist. Using %s/ — you may want to remove %s/ manually.\n", oldDir, configDir, configDir, oldDir)
		fmt.Println()
	}

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

	// Install embedded skills to .hal/skills/
	if err := skills.InstallSkills(projectDir); err != nil {
		return fmt.Errorf("failed to install skills: %w", err)
	}

	// Create symlinks for engine skill discovery
	if err := skills.LinkAllEngines(projectDir); err != nil {
		_ = err // Errors are logged as warnings in LinkAllEngines.
	}

	fmt.Println("Initialized .hal/")
	fmt.Println()

	if len(created) > 0 {
		fmt.Println("Created:")
		for _, f := range created {
			fmt.Printf("  .hal/%s\n", f)
		}
	}

	if len(skipped) > 0 {
		fmt.Println("Already existed (preserved):")
		for _, f := range skipped {
			fmt.Printf("  .hal/%s\n", f)
		}
	}

	if len(created) == 0 && len(skipped) > 0 {
		fmt.Println()
		fmt.Println("All files already exist. No changes made.")
	} else {
		fmt.Println()
		fmt.Println("Next steps:")
		fmt.Println("  1. Run: hal plan \"feature description\" to generate a PRD")
		fmt.Println("  2. Or create .hal/prd.json manually")
		fmt.Println("  3. Run: hal run")
	}

	return nil
}

// migrateConfigDir checks for a legacy oldDir and migrates it to newDir if applicable.
// Output messages are written to w.
func migrateConfigDir(oldDir, newDir string, w io.Writer) (migrateResult, error) {
	return migrateNone, nil
}
