package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/spf13/cobra"
)

const (
	PlanContractVersion = 1

	PlanInputSourceArgument = "argument"
	PlanInputSourceFile     = "file"
	PlanInputSourceStdin    = "stdin"
	PlanInputSourceEditor   = "editor"
)

var (
	planEngineFlag      string
	planFormatFlag      string
	planInputFlag       string
	planNoQuestionsFlag bool
	planJSONFlag        bool
)

// PlanResult is the machine-readable output of hal plan --json.
type PlanResult struct {
	ContractVersion int      `json:"contractVersion"`
	OK              bool     `json:"ok"`
	OutputPath      string   `json:"outputPath,omitempty"`
	Format          string   `json:"format"`
	InputSource     string   `json:"inputSource"`
	QuestionsAsked  bool     `json:"questionsAsked"`
	NextSteps       []string `json:"nextSteps,omitempty"`
	Error           string   `json:"error,omitempty"`
	Summary         string   `json:"summary"`
}

var planCmd = &cobra.Command{
	Use:   "plan [feature-description]",
	Short: "Generate a PRD interactively",
	Long: `Generate a Product Requirements Document through an interactive flow.

The plan command supports human-friendly interactive planning and agent-safe
non-interactive input.

Human flow:
1. Analyzes your feature description and generates clarifying questions
2. Collects your answers and generates a complete PRD

Agent-safe flow:
- Use --input <path> to read a longer feature brief from a file.
- Use --input - to read from stdin.
- Use --no-questions to skip interactive clarification and place ambiguity in
  Open Questions.
- Use --json with --no-questions and explicit input for machine-readable output.

If no description is provided, your $EDITOR will open for you to write the spec
when stdin is interactive. Editor mode is never used with --json.

By default, the PRD is written as markdown to .hal/prd-[feature-name].md.
Use --format json to output directly to .hal/prd.json for immediate use with 'hal run'.

Examples:
  hal plan                                             # Opens editor for full spec
  hal plan "user authentication"                       # Interactive PRD generation
  hal plan "add dark mode" -f json                     # Output directly to prd.json
  hal plan --input .hal/input/feature.md               # Read a longer brief from file
  hal plan --input .hal/input/feature.md --no-questions --format json --json
  hal plan --input - --no-questions --format json --json < feature.md
  hal plan "notifications" -e claude                   # Use Claude engine`,
	Example: `  hal plan
  hal plan "user authentication"
  hal plan "add dark mode" --format json
  hal plan --input .hal/input/feature.md
  hal plan --input .hal/input/feature.md --no-questions --format json --json
  hal plan --input - --no-questions --format json --json < feature.md
  hal plan "notifications" --engine codex`,
	Args: cobra.ArbitraryArgs,
	RunE: runPlan,
}

func init() {
	planCmd.Flags().StringVarP(&planEngineFlag, "engine", "e", "codex", "Engine to use (claude, codex, pi)")
	planCmd.Flags().StringVarP(&planFormatFlag, "format", "f", "markdown", "Output format: markdown, json")
	planCmd.Flags().StringVar(&planInputFlag, "input", "", "Read feature description/spec from file; '-' means stdin")
	planCmd.Flags().BoolVar(&planNoQuestionsFlag, "no-questions", false, "Generate directly without interactive clarifying questions")
	planCmd.Flags().BoolVar(&planJSONFlag, "json", false, "Output machine-readable JSON result")
	rootCmd.AddCommand(planCmd)
}

type planDeps struct {
	newEngine                 func(string) (engine.Engine, error)
	generateWithEngineOptions func(context.Context, engine.Engine, string, prd.GenerateOptions, *engine.Display) (string, error)
	openEditor                func(io.Reader, io.Writer, io.Writer) (string, error)
	isTTY                     func(io.Reader) bool
	readFile                  func(string) ([]byte, error)
}

var defaultPlanDeps = planDeps{
	newEngine:                 newEngine,
	generateWithEngineOptions: prd.GenerateWithEngineOptions,
	openEditor:                openEditorForInput,
	isTTY:                     isTTY,
	readFile:                  os.ReadFile,
}

func runPlan(cmd *cobra.Command, args []string) error {
	return runPlanWithDeps(cmd, args, defaultPlanDeps)
}

func runPlanWithDeps(cmd *cobra.Command, args []string, deps planDeps) error {
	out := io.Writer(os.Stdout)
	in := io.Reader(os.Stdin)
	errOut := io.Writer(os.Stderr)
	if cmd != nil {
		out = cmd.OutOrStdout()
		in = cmd.InOrStdin()
		errOut = cmd.ErrOrStderr()
	}
	deps = normalizePlanDeps(deps)

	formatValue, inputValue, noQuestions, jsonMode, err := readPlanFlags(cmd)
	if err != nil {
		return err
	}
	inputValue = strings.TrimSpace(inputValue)
	inputSource := inferPlanInputSource(args, inputValue)

	format, err := validateFormat(formatValue, "markdown", "json")
	if err != nil {
		return handlePlanValidationError(cmd, out, jsonMode, planFormatForFailure(formatValue), inputSource, err)
	}

	if err := validatePlanInputMode(args, inputValue, noQuestions, jsonMode); err != nil {
		return handlePlanValidationError(cmd, out, jsonMode, format, inputSource, err)
	}

	inputSource, description, explicitInput, err := resolvePlanDescription(args, inputValue, jsonMode, in, out, errOut, deps)
	if err != nil {
		return handlePlanValidationError(cmd, out, jsonMode, format, inputSource, err)
	}
	if jsonMode && !explicitInput {
		err := fmt.Errorf("--json requires explicit input via feature-description or --input")
		return handlePlanValidationError(cmd, out, jsonMode, format, inputSource, err)
	}

	engineName, err := resolveEngine(cmd, "engine", planEngineFlag, ".")
	if err != nil {
		return handlePlanValidationError(cmd, out, jsonMode, format, inputSource, err)
	}

	eng, err := deps.newEngine(engineName)
	if err != nil {
		if jsonMode {
			return outputPlanJSONFailure(cmd, out, planFailureResult(format, inputSource, fmt.Sprintf("failed to create engine: %v", err), "PRD generation failed"), ExitCodeExpectedNonZero, err)
		}
		return err
	}

	var display *engine.Display
	if !jsonMode {
		display = engine.NewDisplay(out)
		display.ShowCommandHeader("Plan", planHeaderTarget(inputSource, inputValue, description), buildHeaderCtx(engineName))
	}

	ctx := context.Background()
	outputPath, err := deps.generateWithEngineOptions(ctx, eng, description, prd.GenerateOptions{
		Format:       format,
		AskQuestions: !noQuestions,
	}, display)
	if err != nil {
		if jsonMode {
			wrapped := fmt.Errorf("PRD generation failed: %w", err)
			return outputPlanJSONFailure(cmd, out, planFailureResult(format, inputSource, wrapped.Error(), "PRD generation failed"), ExitCodeExpectedNonZero, wrapped)
		}
		return fmt.Errorf("PRD generation failed: %w", err)
	}

	if jsonMode {
		return outputPlanJSON(out, PlanResult{
			ContractVersion: PlanContractVersion,
			OK:              true,
			OutputPath:      outputPath,
			Format:          format,
			InputSource:     inputSource,
			QuestionsAsked:  !noQuestions,
			NextSteps:       planNextSteps(format, outputPath, true),
			Summary:         "PRD created",
		})
	}

	display.ShowCommandSuccess("PRD created", fmt.Sprintf("Path: %s", outputPath))
	display.ShowNextSteps(planNextSteps(format, outputPath, false))

	return nil
}

func normalizePlanDeps(deps planDeps) planDeps {
	if deps.newEngine == nil {
		deps.newEngine = newEngine
	}
	if deps.generateWithEngineOptions == nil {
		deps.generateWithEngineOptions = prd.GenerateWithEngineOptions
	}
	if deps.openEditor == nil {
		deps.openEditor = openEditorForInput
	}
	if deps.isTTY == nil {
		deps.isTTY = isTTY
	}
	if deps.readFile == nil {
		deps.readFile = os.ReadFile
	}
	return deps
}

func readPlanFlags(cmd *cobra.Command) (formatValue string, inputValue string, noQuestions bool, jsonMode bool, err error) {
	formatValue = planFormatFlag
	inputValue = planInputFlag
	noQuestions = planNoQuestionsFlag
	jsonMode = planJSONFlag

	if cmd == nil || cmd.Flags() == nil {
		return formatValue, inputValue, noQuestions, jsonMode, nil
	}

	if cmd.Flags().Lookup("format") != nil {
		formatValue, err = cmd.Flags().GetString("format")
		if err != nil {
			return "", "", false, false, err
		}
	}
	if cmd.Flags().Lookup("input") != nil {
		inputValue, err = cmd.Flags().GetString("input")
		if err != nil {
			return "", "", false, false, err
		}
	}
	if cmd.Flags().Lookup("no-questions") != nil {
		noQuestions, err = cmd.Flags().GetBool("no-questions")
		if err != nil {
			return "", "", false, false, err
		}
	}
	if cmd.Flags().Lookup("json") != nil {
		jsonMode, err = cmd.Flags().GetBool("json")
		if err != nil {
			return "", "", false, false, err
		}
	}

	return formatValue, inputValue, noQuestions, jsonMode, nil
}

func validatePlanInputMode(args []string, inputValue string, noQuestions bool, jsonMode bool) error {
	if inputValue != "" && len(args) > 0 {
		return fmt.Errorf("use either --input or positional feature-description, not both")
	}
	if inputValue == "-" && !noQuestions {
		return fmt.Errorf("--input - requires --no-questions")
	}
	if jsonMode && !noQuestions {
		return fmt.Errorf("--json requires --no-questions")
	}
	if jsonMode && inputValue == "" && len(args) == 0 {
		return fmt.Errorf("--json requires explicit input via feature-description or --input")
	}
	return nil
}

func resolvePlanDescription(args []string, inputValue string, jsonMode bool, in io.Reader, out io.Writer, errOut io.Writer, deps planDeps) (string, string, bool, error) {
	if inputValue == "-" {
		data, err := io.ReadAll(in)
		if err != nil {
			return PlanInputSourceStdin, "", true, fmt.Errorf("failed to read stdin: %w", err)
		}
		description := strings.TrimSpace(string(data))
		if description == "" {
			return PlanInputSourceStdin, "", true, fmt.Errorf("no description provided from stdin")
		}
		return PlanInputSourceStdin, description, true, nil
	}

	if inputValue != "" {
		data, err := deps.readFile(inputValue)
		if err != nil {
			return PlanInputSourceFile, "", true, fmt.Errorf("failed to read input file %s: %w", inputValue, err)
		}
		description := strings.TrimSpace(string(data))
		if description == "" {
			return PlanInputSourceFile, "", true, fmt.Errorf("no description provided in %s", inputValue)
		}
		return PlanInputSourceFile, description, true, nil
	}

	if len(args) > 0 {
		description := strings.TrimSpace(strings.Join(args, " "))
		if description == "" {
			return PlanInputSourceArgument, "", true, fmt.Errorf("no description provided")
		}
		return PlanInputSourceArgument, description, true, nil
	}

	if jsonMode {
		return PlanInputSourceEditor, "", false, fmt.Errorf("--json requires explicit input via feature-description or --input")
	}
	if !deps.isTTY(in) {
		return PlanInputSourceEditor, "", false, fmt.Errorf("no description provided; pass feature-description, --input <path>, or --input -")
	}

	content, err := deps.openEditor(in, out, errOut)
	if err != nil {
		return PlanInputSourceEditor, "", false, err
	}
	description := strings.TrimSpace(content)
	if description == "" {
		return PlanInputSourceEditor, "", false, fmt.Errorf("no description provided")
	}
	return PlanInputSourceEditor, description, false, nil
}

func inferPlanInputSource(args []string, inputValue string) string {
	switch {
	case inputValue == "-":
		return PlanInputSourceStdin
	case inputValue != "":
		return PlanInputSourceFile
	case len(args) > 0:
		return PlanInputSourceArgument
	default:
		return PlanInputSourceEditor
	}
}

func planFormatForFailure(formatValue string) string {
	format := strings.ToLower(strings.TrimSpace(formatValue))
	if format == "" {
		return "markdown"
	}
	return format
}

func handlePlanValidationError(cmd *cobra.Command, out io.Writer, jsonMode bool, format string, inputSource string, err error) error {
	if !jsonMode {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}
	return outputPlanJSONFailure(cmd, out, planFailureResult(format, inputSource, err.Error(), "Invalid plan input"), ExitCodeValidation, err)
}

func outputPlanJSONFailure(cmd *cobra.Command, out io.Writer, result PlanResult, code int, err error) error {
	if outputErr := outputPlanJSON(out, result); outputErr != nil {
		return outputErr
	}
	return exitWithCode(cmd, code, err)
}

func planHeaderTarget(inputSource string, inputValue string, description string) string {
	switch inputSource {
	case PlanInputSourceFile:
		return fmt.Sprintf("input: %s", inputValue)
	case PlanInputSourceStdin:
		return "stdin"
	case PlanInputSourceEditor:
		return "editor input"
	default:
		return truncateForHeader(description, 120)
	}
}

func truncateForHeader(value string, max int) string {
	trimmed := strings.TrimSpace(value)
	if max <= 0 || len(trimmed) <= max {
		return trimmed
	}
	if max <= 1 {
		return trimmed[:max]
	}
	return strings.TrimSpace(trimmed[:max-1]) + "…"
}

func planNextSteps(format string, outputPath string, machine bool) []string {
	if format == "json" {
		if machine {
			return []string{"hal validate --json", "hal run --json"}
		}
		return []string{"hal validate", "hal run"}
	}

	if machine {
		return []string{
			fmt.Sprintf("hal convert %s --json", outputPath),
			"hal validate --json",
			"hal run --json",
		}
	}
	return []string{
		fmt.Sprintf("hal convert %s", outputPath),
		"hal validate",
		"hal run",
	}
}

func planFailureResult(format string, inputSource string, errMsg string, summary string) PlanResult {
	return PlanResult{
		ContractVersion: PlanContractVersion,
		OK:              false,
		Format:          format,
		InputSource:     inputSource,
		QuestionsAsked:  false,
		Error:           errMsg,
		Summary:         summary,
	}
}

func outputPlanJSON(out io.Writer, result PlanResult) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal plan result: %w", err)
	}
	fmt.Fprintln(out, string(data))
	return nil
}

func openEditorForInput(in io.Reader, out io.Writer, errOut io.Writer) (string, error) {
	// Create temp file with template
	tmpfile, err := os.CreateTemp("", "hal-plan-*.md")
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpfile.Name())

	// Write template
	template := `# Feature Specification

<!-- Write your feature description below. Save and quit when done. -->
<!-- Lines starting with <!-- will be ignored. -->

`
	if _, err := tmpfile.WriteString(template); err != nil {
		return "", fmt.Errorf("failed to write template: %w", err)
	}
	tmpfile.Close()

	// Get editor
	editor := os.Getenv("EDITOR")
	if editor == "" {
		editor = os.Getenv("VISUAL")
	}
	if editor == "" {
		// Try common editors
		for _, e := range []string{"nvim", "nano", "vim", "vi"} {
			if _, err := exec.LookPath(e); err == nil {
				editor = e
				break
			}
		}
	}
	if editor == "" {
		return "", fmt.Errorf("no editor found - set $EDITOR environment variable")
	}

	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}
	fmt.Fprintf(out, "Opening %s... (save and quit when done)\n", editor)
	editorCmd := exec.Command(editor, tmpfile.Name())
	editorCmd.Stdin = in
	editorCmd.Stdout = out
	editorCmd.Stderr = errOut

	if err := editorCmd.Run(); err != nil {
		return "", fmt.Errorf("editor failed: %w", err)
	}

	// Read content
	content, err := os.ReadFile(tmpfile.Name())
	if err != nil {
		return "", fmt.Errorf("failed to read file: %w", err)
	}

	// Strip comment lines
	lines := strings.Split(string(content), "\n")
	var filtered []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "<!--") && strings.HasSuffix(trimmed, "-->") {
			continue
		}
		filtered = append(filtered, line)
	}

	return strings.Join(filtered, "\n"), nil
}
