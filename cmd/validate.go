package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var validateEngineFlag string

var validateCmd = &cobra.Command{
	Use:   "validate [prd-path]",
	Short: "Validate a PRD using AI",
	Long: `Validate a PRD file against the hal skill rules using an AI engine.

Checks:
  - Each story is completable in one iteration (small scope)
  - Stories are ordered by dependency (schema → backend → UI)
  - Every story has "Typecheck passes" as a criterion
  - UI stories have browser verification criteria
  - Acceptance criteria are verifiable (not vague)

Examples:
  hal validate                    # Validate .hal/prd.json
  hal validate path/to/prd.json   # Validate specific file
  hal validate -e codex           # Use Codex engine`,
	Args: maxArgsValidation(1),
	RunE: runValidate,
}

func init() {
	validateCmd.Flags().StringVarP(&validateEngineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	// Determine PRD path
	prdPath := filepath.Join(template.HalDir, template.PRDFile)
	if len(args) > 0 {
		prdPath = args[0]
	}

	// Check PRD exists
	if _, err := os.Stat(prdPath); os.IsNotExist(err) {
		return fmt.Errorf("PRD not found: %s", prdPath)
	}

	engineName, err := resolveEngine(cmd, "engine", validateEngineFlag, ".")
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	// Create engine
	eng, err := newEngine(engineName)
	if err != nil {
		return err
	}

	// Create display for streaming feedback
	display := engine.NewDisplay(os.Stdout)

	// Show command header
	display.ShowCommandHeader("Validate", prdPath, buildHeaderCtx(engineName))

	// Validate
	ctx := context.Background()
	result, err := prd.ValidateWithEngine(ctx, eng, prdPath, display)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Display result using styled display
	if result.Valid {
		display.ShowCommandSuccess("PRD is valid", "All checks passed")
	} else {
		errors := make([]engine.ValidationIssue, len(result.Errors))
		for i, e := range result.Errors {
			errors[i] = engine.ValidationIssue{StoryID: e.StoryID, Field: e.Field, Message: e.Message}
		}
		warnings := make([]engine.ValidationIssue, len(result.Warnings))
		for i, w := range result.Warnings {
			warnings[i] = engine.ValidationIssue{StoryID: w.StoryID, Field: w.Field, Message: w.Message}
		}
		display.ShowCommandError("Validation failed", errors, warnings)
		return exitWithCode(cmd, ExitCodeValidation, fmt.Errorf("validation failed"))
	}

	return nil
}
