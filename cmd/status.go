package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/jywlabs/hal/internal/compound"
	display "github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/status"
	"github.com/spf13/cobra"
)

var statusJSONFlag bool

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current workflow state",
	Args:  noArgsValidation(),
	Long: `Show the current Hal workflow state.

Inspects .hal/ artifacts to determine:
  - Which workflow track is active (manual, compound, unknown)
  - What state the workflow is in
  - What artifacts exist
  - What the next recommended action is

With --json, outputs a stable machine-readable contract (v1) suitable
for agent orchestration and tooling integration.

Workflow states:
  not_initialized         No .hal/ directory found
  hal_initialized_no_prd  .hal/ exists but no prd.json
  manual_in_progress      PRD has pending stories
  manual_complete         All PRD stories passed
  compound_active         Auto pipeline in progress
  compound_complete       Auto pipeline step is 'done'
  review_loop_complete    Review-loop reports exist (no active PRD)

Examples:
  hal status            # Human-readable summary
  hal status --json     # Machine-readable JSON contract`,
	Example: `  hal status
  hal status --json`,
	RunE: runStatus,
}

func init() {
	statusCmd.Flags().BoolVar(&statusJSONFlag, "json", false, "Output machine-readable JSON (v1 contract)")
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := statusJSONFlag

	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("json") != nil {
			v, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = v
		}
	}

	return runStatusFn(".", jsonMode, out)
}

// statusWithEngine wraps StatusResult with the configured engine for JSON output.
type statusWithEngine struct {
	status.StatusResult
	Engine string `json:"engine,omitempty"`
}

func runStatusFn(dir string, jsonMode bool, out io.Writer) error {
	result := status.Get(dir)

	if jsonMode {
		engine, _ := compound.LoadDefaultEngine(dir)
		wrapped := statusWithEngine{
			StatusResult: result,
			Engine:       engine,
		}
		data, err := json.MarshalIndent(wrapped, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal status: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	// Human-readable output
	engine, _ := compound.LoadDefaultEngine(dir)

	// Header section
	fmt.Fprintf(out, "%s  %s\n", display.StyleBold.Render("Workflow:"), result.WorkflowTrack)
	fmt.Fprintf(out, "%s     %s\n", display.StyleBold.Render("State:"), result.State)
	if engine != "" {
		fmt.Fprintf(out, "%s    %s\n", display.StyleBold.Render("Engine:"), engine)
	}
	fmt.Fprintln(out)

	// Show detail for manual workflows
	if result.Manual != nil {
		m := result.Manual
		if m.BranchName != "" {
			fmt.Fprintf(out, "%s    %s\n", display.StyleBold.Render("Branch:"), display.StyleInfo.Render(m.BranchName))
		}
		storyLabel := fmt.Sprintf("%d/%d complete", m.CompletedStories, m.TotalStories)
		if m.CompletedStories == m.TotalStories && m.TotalStories > 0 {
			storyLabel = display.StyleSuccess.Render(storyLabel)
		} else if m.CompletedStories > 0 {
			storyLabel = display.StyleWarning.Render(storyLabel)
		}
		fmt.Fprintf(out, "Stories:  %s\n", storyLabel)
		if m.NextStory != nil {
			label := display.StyleInfo.Render(m.NextStory.ID)
			if m.NextStory.Title != "" {
				label += " — " + m.NextStory.Title
			}
			fmt.Fprintf(out, "Next:     %s\n", label)
		}
		fmt.Fprintln(out)
	}

	// Show detail for compound workflows
	if result.Compound != nil {
		c := result.Compound
		if c.BranchName != "" {
			fmt.Fprintf(out, "%s    %s\n", display.StyleBold.Render("Branch:"), display.StyleInfo.Render(c.BranchName))
		}
		if c.Step != "" {
			fmt.Fprintf(out, "Step:     %s\n", c.Step)
		}
		fmt.Fprintln(out)
	}

	// Show review-loop detail
	if result.ReviewLoop != nil {
		if result.ReviewLoop.LatestReport != "" {
			fmt.Fprintf(out, "Review:   %s\n", display.StyleMuted.Render(result.ReviewLoop.LatestReport))
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintf(out, "%s\n", display.StyleBold.Render("Artifacts:"))
	printArtifact(out, "  .hal/ directory", result.Artifacts.HalDir)
	printArtifact(out, "  Markdown PRD", result.Artifacts.MarkdownPRD)
	printArtifact(out, "  JSON PRD", result.Artifacts.JSONPRD)
	printArtifact(out, "  Progress file", result.Artifacts.ProgressFile)
	printArtifact(out, "  Report", result.Artifacts.ReportAvailable)
	printArtifact(out, "  Auto state", result.Artifacts.AutoState)
	fmt.Fprintln(out)

	if result.NextAction.ID != "" {
		fmt.Fprintf(out, "%s    %s\n", display.StyleBold.Render("Action:"), display.StyleInfo.Render(result.NextAction.Command))
		fmt.Fprintf(out, "          %s\n", display.StyleMuted.Render(result.NextAction.Description))
	}

	return nil
}

func printArtifact(out io.Writer, label string, present bool) {
	if present {
		fmt.Fprintf(out, "  %s %s\n", display.StyleSuccess.Render("✓"), label)
	} else {
		fmt.Fprintf(out, "  %s %s\n", display.StyleMuted.Render("✗"), label)
	}
}
