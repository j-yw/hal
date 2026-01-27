package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/jywlabs/goralph/internal/engine"
	"github.com/jywlabs/goralph/internal/prd"
	"github.com/spf13/cobra"

	// Register available engines
	_ "github.com/jywlabs/goralph/internal/engine/amp"
	_ "github.com/jywlabs/goralph/internal/engine/claude"
)

var (
	planEngineFlag string
	planJSONFlag   bool
)

var planCmd = &cobra.Command{
	Use:   "plan [feature-description]",
	Short: "Generate a PRD interactively",
	Long: `Generate a Product Requirements Document through an interactive flow.

The plan command uses a two-phase approach:
1. Analyzes your feature description and generates clarifying questions
2. Collects your answers and generates a complete PRD

If no description is provided, your $EDITOR will open for you to write the spec.

By default, the PRD is written as markdown to tasks/prd-[feature-name].md.
Use --json to output directly to .goralph/prd.json for immediate use with 'goralph run'.

Examples:
  goralph plan                            # Opens editor for full spec
  goralph plan "user authentication"      # Interactive PRD generation
  goralph plan "add dark mode" --json     # Output directly to prd.json
  goralph plan "notifications" -e amp     # Use Amp engine`,
	Args: cobra.ArbitraryArgs,
	RunE: runPlan,
}

func init() {
	planCmd.Flags().StringVarP(&planEngineFlag, "engine", "e", "claude", "Engine to use (claude, amp)")
	planCmd.Flags().BoolVar(&planJSONFlag, "json", false, "Output directly to .goralph/prd.json")
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
	eng, err := engine.New(planEngineFlag)
	if err != nil {
		return err
	}

	fmt.Printf("Planning feature: %s\n", description)
	fmt.Printf("Using %s engine\n\n", eng.Name())

	// Create display for streaming feedback
	display := engine.NewDisplay(os.Stdout)

	// Generate PRD
	ctx := context.Background()
	outputPath, err := prd.GenerateWithEngine(ctx, eng, description, planJSONFlag, display)
	if err != nil {
		return fmt.Errorf("PRD generation failed: %w", err)
	}

	fmt.Printf("\nPRD written to: %s\n", outputPath)

	if planJSONFlag {
		fmt.Println("\nNext steps:")
		fmt.Println("  goralph run    # Execute the stories")
	} else {
		fmt.Println("\nNext steps:")
		fmt.Println("  1. Review the PRD")
		fmt.Println("  2. Run: goralph convert " + outputPath)
		fmt.Println("  3. Run: goralph run")
	}

	return nil
}

func openEditorForInput() (string, error) {
	// Create temp file with template
	tmpfile, err := os.CreateTemp("", "goralph-plan-*.md")
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
		for _, e := range []string{"nano", "vim", "vi"} {
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
