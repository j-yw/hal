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

	// Register available engines
	_ "github.com/jywlabs/hal/internal/engine/claude"
)

var (
	convertEngineFlag   string
	convertOutputFlag   string
	convertValidateFlag bool
)

var convertCmd = &cobra.Command{
	Use:   "convert [markdown-prd]",
	Short: "Convert markdown PRD to JSON",
	Long: `Convert a markdown PRD file to prd.json format using the hal skill.

Without arguments, automatically finds prd-*.md files in .hal/ directory.
With a path argument, uses that file directly.

The conversion uses an AI engine to parse the markdown and generate
properly-sized user stories with verifiable acceptance criteria.

If an existing prd.json exists with a different feature, it will be
archived to .hal/archive/ before the new one is written.

Examples:
  hal convert                                  # Auto-discover PRD in .hal/
  hal convert .hal/prd-auth.md            # Explicit path
  hal convert .hal/prd.md -o custom.json  # Custom output path
  hal convert .hal/prd.md --validate      # Also validate after conversion
  hal convert .hal/prd.md -e claude       # Use Claude engine`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConvert,
}

func init() {
	convertCmd.Flags().StringVarP(&convertEngineFlag, "engine", "e", "claude", "Engine to use (claude)")
	convertCmd.Flags().StringVarP(&convertOutputFlag, "output", "o", "", "Output path (default: .hal/prd.json)")
	convertCmd.Flags().BoolVar(&convertValidateFlag, "validate", false, "Validate PRD after conversion")
	rootCmd.AddCommand(convertCmd)
}

func runConvert(cmd *cobra.Command, args []string) error {
	var mdPath string
	if len(args) > 0 {
		mdPath = args[0]
		// Check markdown file exists when explicit path provided
		if _, err := os.Stat(mdPath); os.IsNotExist(err) {
			return fmt.Errorf("markdown PRD not found: %s", mdPath)
		}
	}
	// mdPath = "" means auto-discover via skill

	// Determine output path
	outPath := convertOutputFlag
	if outPath == "" {
		outPath = filepath.Join(template.HalDir, template.PRDFile)
	}

	// Create engine
	eng, err := engine.New(convertEngineFlag)
	if err != nil {
		return err
	}

	// Create display for streaming feedback
	display := engine.NewDisplay(os.Stdout)

	// Show command header
	if mdPath != "" {
		display.ShowCommandHeader("Convert", fmt.Sprintf("%s → prd.json", mdPath), eng.Name())
	} else {
		display.ShowCommandHeader("Convert", "auto-discover → prd.json", eng.Name())
	}

	// Convert
	ctx := context.Background()
	if err := prd.ConvertWithEngine(ctx, eng, mdPath, outPath, display); err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}

	// Show success
	display.ShowCommandSuccess("Conversion complete", fmt.Sprintf("Output: %s", outPath))

	// Optionally validate
	if convertValidateFlag {
		display.ShowPhase(2, 2, "Validate")
		result, err := prd.ValidateWithEngine(ctx, eng, outPath, display)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}

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
			os.Exit(1)
		}
	}

	return nil
}
