package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

const explodeDeprecationWarning = "warning: 'hal explode' is deprecated; use 'hal convert --granular'."

var (
	explodeBranchFlag string
	explodeEngineFlag string
	explodeJSONFlag   bool
)

// ExplodeResult is the machine-readable output of hal explode --json.
type ExplodeResult struct {
	ContractVersion int    `json:"contractVersion"`
	OK              bool   `json:"ok"`
	OutputPath      string `json:"outputPath,omitempty"`
	TaskCount       int    `json:"taskCount"`
	Error           string `json:"error,omitempty"`
	Summary         string `json:"summary"`
}

var explodeCmd = &cobra.Command{
	Use:   "explode [prd-path]",
	Short: "Deprecated shim for 'hal convert --granular'",
	Long: `Deprecated: use 'hal convert --granular'.

This command is a one-release compatibility shim.
It delegates conversion to:
  hal convert --granular --output .hal/prd.json

Behavior:
- Prints a deprecation warning to stderr.
- Preserves the explode --json output contract.
- Passes through --branch and --engine.

Examples:
  hal explode .hal/prd-feature.md                    # Deprecated shim to convert --granular
  hal explode .hal/prd-feature.md --branch feature   # Pin branchName in generated prd.json
  hal explode .hal/prd-feature.md --engine claude    # Use specific engine
  hal explode .hal/prd-feature.md --json             # Machine-readable explode contract`,
	Example: `  hal explode .hal/prd-checkout.md
  hal explode .hal/prd-checkout.md --branch checkout
  hal explode .hal/prd-checkout.md --engine codex
  hal explode .hal/prd-checkout.md --json`,
	Args: exactArgsValidation(1),
	RunE: runExplode,
}

func init() {
	explodeCmd.Flags().StringVar(&explodeBranchFlag, "branch", "", "Branch name to pin in generated prd.json")
	explodeCmd.Flags().StringVarP(&explodeEngineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")
	explodeCmd.Flags().BoolVar(&explodeJSONFlag, "json", false, "Output machine-readable JSON result")
	rootCmd.AddCommand(explodeCmd)
}

type explodeDeps struct {
	newEngine         func(string) (engine.Engine, error)
	convertWithEngine func(context.Context, engine.Engine, string, string, prd.ConvertOptions, *engine.Display) error
	readFile          func(string) ([]byte, error)
}

var defaultExplodeDeps = explodeDeps{
	newEngine:         newEngine,
	convertWithEngine: prd.ConvertWithEngine,
	readFile:          os.ReadFile,
}

func runExplode(cmd *cobra.Command, args []string) error {
	return runExplodeWithDeps(cmd, args, defaultExplodeDeps)
}

func runExplodeWithDeps(cmd *cobra.Command, args []string, deps explodeDeps) error {
	ctx := context.Background()
	out := io.Writer(os.Stdout)
	errOut := io.Writer(os.Stderr)
	if cmd != nil {
		if cmd.Context() != nil {
			ctx = cmd.Context()
		}
		out = cmd.OutOrStdout()
		errOut = cmd.ErrOrStderr()
	}

	if deps.newEngine == nil {
		deps.newEngine = newEngine
	}
	if deps.convertWithEngine == nil {
		deps.convertWithEngine = prd.ConvertWithEngine
	}
	if deps.readFile == nil {
		deps.readFile = os.ReadFile
	}

	fmt.Fprintln(errOut, explodeDeprecationWarning)

	prdPath := args[0]
	if _, err := os.Stat(prdPath); os.IsNotExist(err) {
		return fmt.Errorf("PRD file not found: %s", prdPath)
	}

	engineName, err := resolveEngine(cmd, "engine", explodeEngineFlag, ".")
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	eng, err := deps.newEngine(engineName)
	if err != nil {
		return err
	}

	display := engine.NewDisplay(out)
	display.ShowCommandHeader("Explode", filepath.Base(prdPath), buildHeaderCtx(engineName))

	outPath := filepath.Join(template.HalDir, template.PRDFile)
	opts := prd.ConvertOptions{
		Granular:   true,
		BranchName: explodeBranchFlag,
	}

	if err := deps.convertWithEngine(ctx, eng, prdPath, outPath, opts, display); err != nil {
		return fmt.Errorf("conversion failed: %w", err)
	}

	taskCount, err := loadExplodeTaskCount(deps.readFile, outPath)
	if err != nil {
		return err
	}

	if explodeJSONFlag {
		return outputExplodeJSON(out, outPath, taskCount)
	}

	display.ShowCommandSuccess("Tasks generated", fmt.Sprintf("%d tasks • Path: %s", taskCount, outPath))
	return nil
}

func loadExplodeTaskCount(readFile func(string) ([]byte, error), path string) (int, error) {
	data, err := readFile(path)
	if err != nil {
		return 0, fmt.Errorf("failed to read generated prd.json: %w", err)
	}

	var p engine.PRD
	if err := json.Unmarshal(data, &p); err != nil {
		return 0, fmt.Errorf("generated prd.json is invalid: %w", err)
	}

	return countTasks(&p), nil
}

func outputExplodeJSON(out io.Writer, outPath string, taskCount int) error {
	jr := ExplodeResult{
		ContractVersion: 1,
		OK:              true,
		OutputPath:      outPath,
		TaskCount:       taskCount,
		Summary:         fmt.Sprintf("%d tasks generated at %s.", taskCount, outPath),
	}
	data, err := json.MarshalIndent(jr, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal explode result: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func countTasks(prd *engine.PRD) int {
	if len(prd.UserStories) > 0 {
		return len(prd.UserStories)
	}
	return len(prd.Tasks)
}
