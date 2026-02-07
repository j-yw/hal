package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/prd"
	"github.com/spf13/cobra"
)

var (
	planEngineFlag string
	planFormatFlag string
)

var planCmd = &cobra.Command{
	Use:   "plan [feature-description]",
	Short: "Generate a PRD interactively",
	Long: `Generate a Product Requirements Document through an interactive flow.

The plan command uses a two-phase approach:
1. Analyzes your feature description and generates clarifying questions
2. Collects your answers and generates a complete PRD

If no description is provided, your $EDITOR will open for you to write the spec.

By default, the PRD is written as markdown to .hal/prd-[feature-name].md.
Use --format json to output directly to .hal/prd.json for immediate use with 'hal run'.

Examples:
  hal plan                            # Opens editor for full spec
  hal plan "user authentication"      # Interactive PRD generation
  hal plan "add dark mode" -f json    # Output directly to prd.json
  hal plan "notifications" -e claude  # Use Claude engine`,
	Args: cobra.ArbitraryArgs,
	RunE: runPlan,
}

func init() {
	planCmd.Flags().StringVarP(&planEngineFlag, "engine", "e", "claude", "Engine to use (claude, codex, pi)")
	planCmd.Flags().StringVarP(&planFormatFlag, "format", "f", "markdown", "Output format: markdown, json")
	rootCmd.AddCommand(planCmd)
}

func runPlan(cmd *cobra.Command, args []string) error {
	var description string

	if len(args) == 0 {
		// No args - open editor
		content, err := openEditorForInput()
		if err != nil {
			return err
		}
		description = strings.TrimSpace(content)
		if description == "" {
			return fmt.Errorf("no description provided")
		}
	} else {
		description = strings.Join(args, " ")
	}

	// Create engine
	eng, err := newEngine(planEngineFlag)
	if err != nil {
		return err
	}

	// Create display for streaming feedback
	display := engine.NewDisplay(os.Stdout)

	// Show command header
	display.ShowCommandHeader("Plan", description, buildHeaderCtx(planEngineFlag))

	// Generate PRD
	ctx := context.Background()
	outputPath, err := prd.GenerateWithEngine(ctx, eng, description, planFormatFlag, display)
	if err != nil {
		return fmt.Errorf("PRD generation failed: %w", err)
	}

	// Show success
	display.ShowCommandSuccess("PRD created", fmt.Sprintf("Path: %s", outputPath))

	// Show next steps
	if planFormatFlag == "json" {
		display.ShowNextSteps([]string{"hal run    # Execute the stories"})
	} else {
		display.ShowNextSteps([]string{
			fmt.Sprintf("hal convert %s", outputPath),
			"hal run",
		})
	}

	return nil
}

func openEditorForInput() (string, error) {
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

	// Open editor
	fmt.Printf("Opening %s... (save and quit when done)\n", editor)
	editorCmd := exec.Command(editor, tmpfile.Name())
	editorCmd.Stdin = os.Stdin
	editorCmd.Stdout = os.Stdout
	editorCmd.Stderr = os.Stderr

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
