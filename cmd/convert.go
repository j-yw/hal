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

var (
	convertEngineFlag   string
	convertOutputFlag   string
	convertValidateFlag bool
	convertArchiveFlag  bool
	convertForceFlag    bool
)

var convertCmd = &cobra.Command{
	Use:   "convert [markdown-prd]",
	Short: "Convert markdown PRD to JSON",
	Long: `Convert a markdown PRD file to prd.json format using the hal skill.

Source selection:
- With no argument, scans .hal/prd-*.md and picks newest by modified time.
- If modified times tie, picks lexicographically ascending filename.
- With an explicit argument, uses that exact path.
- Prints "Using source: <path>" once the source is resolved.

Safety controls:
- Default convert does NOT archive existing state.
- --archive archives existing feature state before writing canonical .hal/prd.json.
- --archive is only supported when output is canonical .hal/prd.json.
- Canonical writes are protected from branchName switches; use --archive or --force to override.

Examples:
  hal convert                                # Auto-discover source (no archive)
  hal convert .hal/prd-auth.md              # Explicit source path
  hal convert --archive                      # Archive before writing .hal/prd.json
  hal convert .hal/prd.md --force           # Override branch mismatch guard
  hal convert .hal/prd.md -o custom.json    # Custom output path (no archive)
  hal convert .hal/prd.md --validate        # Also validate after conversion
  hal convert .hal/prd.md -e claude         # Use Claude engine`,
	Example: `  hal convert
  hal convert --archive
  hal convert .hal/prd-auth.md --validate
  hal convert .hal/prd-auth.md --force
  hal convert .hal/prd-auth.md --engine codex`,
	Args: cobra.MaximumNArgs(1),
	RunE: runConvert,
}

func init() {
	convertCmd.Flags().StringVarP(&convertEngineFlag, "engine", "e", "claude", "Engine to use (claude, codex, pi)")
	convertCmd.Flags().StringVarP(&convertOutputFlag, "output", "o", "", "Output path (default: .hal/prd.json)")
	convertCmd.Flags().BoolVar(&convertValidateFlag, "validate", false, "Validate PRD after conversion")
	convertCmd.Flags().BoolVar(&convertArchiveFlag, "archive", false, "Archive existing feature state before writing canonical .hal/prd.json")
	convertCmd.Flags().BoolVar(&convertForceFlag, "force", false, "Allow canonical overwrite without archive when branch mismatch protection would block")
	rootCmd.AddCommand(convertCmd)
}

type convertDeps struct {
	newEngine          func(string) (engine.Engine, error)
	convertWithEngine  func(context.Context, engine.Engine, string, string, prd.ConvertOptions, *engine.Display) error
	validateWithEngine func(context.Context, engine.Engine, string, *engine.Display) (*prd.ValidationResult, error)
}

var defaultConvertDeps = convertDeps{
	newEngine:          newEngine,
	convertWithEngine:  prd.ConvertWithEngine,
	validateWithEngine: prd.ValidateWithEngine,
}

func runConvert(cmd *cobra.Command, args []string) error {
	return runConvertWithDeps(cmd, args, defaultConvertDeps)
}

func runConvertWithDeps(cmd *cobra.Command, args []string, deps convertDeps) error {
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
	eng, err := deps.newEngine(convertEngineFlag)
	if err != nil {
		return err
	}

	// Create display for streaming feedback
	display := engine.NewDisplay(os.Stdout)

	// Show command header
	hctx := buildHeaderCtx(convertEngineFlag)
	if mdPath != "" {
		display.ShowCommandHeader("Convert", fmt.Sprintf("%s → prd.json", mdPath), hctx)
	} else {
		display.ShowCommandHeader("Convert", "auto-discover → prd.json", hctx)
	}

	opts := prd.ConvertOptions{
		Archive: convertArchiveFlag,
		Force:   convertForceFlag,
	}

	// Convert
	ctx := context.Background()
	if err := deps.convertWithEngine(ctx, eng, mdPath, outPath, opts, display); err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}

	// Show success
	display.ShowCommandSuccess("Conversion complete", fmt.Sprintf("Output: %s", outPath))

	// Optionally validate
	if convertValidateFlag {
		display.ShowPhase(2, 2, "Validate")
		result, err := deps.validateWithEngine(ctx, eng, outPath, display)
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
