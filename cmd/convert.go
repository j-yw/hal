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
	_ "github.com/jywlabs/goralph/internal/engine/claude"
)

var (
	convertEngineFlag   string
	convertOutputFlag   string
	convertValidateFlag bool
)

var convertCmd = &cobra.Command{
	Use:   "convert <markdown-prd>",
	Short: "Convert markdown PRD to JSON",
	Long: `Convert a markdown PRD file to prd.json format using the ralph skill.

The conversion uses an AI engine to parse the markdown and generate
properly-sized user stories with verifiable acceptance criteria.

If an existing prd.json exists with a different feature, it will be
archived to .goralph/archive/ before the new one is written.

Examples:
  goralph convert tasks/prd-auth.md              # Output to .goralph/prd.json
  goralph convert docs/feature.md -o custom.json # Custom output path
  goralph convert tasks/prd.md --validate        # Also validate after conversion
  goralph convert tasks/prd.md -e claude         # Use Claude engine`,
	Args: cobra.ExactArgs(1),
	RunE: runConvert,
}

func init() {
	convertCmd.Flags().StringVarP(&convertEngineFlag, "engine", "e", "claude", "Engine to use (claude)")
	convertCmd.Flags().StringVarP(&convertOutputFlag, "output", "o", "", "Output path (default: .goralph/prd.json)")
	convertCmd.Flags().BoolVar(&convertValidateFlag, "validate", false, "Validate PRD after conversion")
	rootCmd.AddCommand(convertCmd)
}

func runConvert(cmd *cobra.Command, args []string) error {
	mdPath := args[0]

	// Check markdown file exists
	if _, err := os.Stat(mdPath); os.IsNotExist(err) {
		return fmt.Errorf("markdown PRD not found: %s", mdPath)
	}

	// Determine output path
	outPath := convertOutputFlag
	if outPath == "" {
		outPath = filepath.Join(template.GoralphDir, "prd.json")
	}

	// Create engine
	eng, err := engine.New(convertEngineFlag)
	if err != nil {
		return err
	}

	fmt.Printf("Converting %s using %s engine...\n", mdPath, eng.Name())

	// Create display for streaming feedback
	display := engine.NewDisplay(os.Stdout)

	// Convert
	ctx := context.Background()
	if err := prd.ConvertWithEngine(ctx, eng, mdPath, outPath, display); err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}

	fmt.Printf("Wrote %s\n", outPath)

	// Optionally validate
	if convertValidateFlag {
		fmt.Println()
		fmt.Println("Validating...")
		result, err := prd.ValidateWithEngine(ctx, eng, outPath, display)
		if err != nil {
			return fmt.Errorf("validation failed: %w", err)
		}
		fmt.Print(prd.FormatValidationResult(result))
		if !result.Valid {
			os.Exit(1)
		}
	}

	return nil
}
