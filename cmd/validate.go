package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/jywlabs/goralph/internal/engine"
	"github.com/jywlabs/goralph/internal/prd"
	"github.com/jywlabs/goralph/internal/template"
	"github.com/spf13/cobra"

	// Register available engines
	_ "github.com/jywlabs/goralph/internal/engine/amp"
	_ "github.com/jywlabs/goralph/internal/engine/claude"
)

var validateEngineFlag string

var validateCmd = &cobra.Command{
	Use:   "validate [prd-path]",
	Short: "Validate a PRD using AI",
	Long: `Validate a PRD file against the ralph skill rules using an AI engine.

Checks:
  - Each story is completable in one iteration (small scope)
  - Stories are ordered by dependency (schema → backend → UI)
  - Every story has "Typecheck passes" as a criterion
  - UI stories have browser verification criteria
  - Acceptance criteria are verifiable (not vague)

Examples:
  goralph validate                    # Validate .goralph/prd.json
  goralph validate path/to/prd.json   # Validate specific file
  goralph validate -e amp             # Use Amp engine`,
	RunE: runValidate,
}

func init() {
	validateCmd.Flags().StringVarP(&validateEngineFlag, "engine", "e", "claude", "Engine to use (claude, amp)")
	rootCmd.AddCommand(validateCmd)
}

func runValidate(cmd *cobra.Command, args []string) error {
	// Determine PRD path
	prdPath := filepath.Join(template.GoralphDir, "prd.json")
	if len(args) > 0 {
		prdPath = args[0]
	}

	// Check PRD exists
	if _, err := os.Stat(prdPath); os.IsNotExist(err) {
		return fmt.Errorf("PRD not found: %s", prdPath)
	}

	// Create engine
	eng, err := engine.New(validateEngineFlag)
	if err != nil {
		return err
	}

	fmt.Printf("Validating %s using %s engine...\n\n", prdPath, eng.Name())

	// Create display for streaming feedback
	display := engine.NewDisplay(os.Stdout)

	// Validate
	ctx := context.Background()
	result, err := prd.ValidateWithEngine(ctx, eng, prdPath, display)
	if err != nil {
		return fmt.Errorf("validation failed: %w", err)
	}

	// Display result
	fmt.Print(prd.FormatValidationResult(result))

	if !result.Valid {
		os.Exit(1)
	}

	return nil
}
