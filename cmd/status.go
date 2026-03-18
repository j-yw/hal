package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

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

func runStatusFn(dir string, jsonMode bool, out io.Writer) error {
	result := status.Get(dir)

	if jsonMode {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal status: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	// Human-readable output
	fmt.Fprintf(out, "Workflow:  %s\n", result.WorkflowTrack)
	fmt.Fprintf(out, "State:    %s\n", result.State)
	fmt.Fprintln(out)

	// Show detail for manual workflows
	if result.Manual != nil {
		m := result.Manual
		if m.BranchName != "" {
			fmt.Fprintf(out, "Branch:   %s\n", m.BranchName)
		}
		fmt.Fprintf(out, "Stories:  %d/%d complete\n", m.CompletedStories, m.TotalStories)
		if m.NextStory != nil {
			label := m.NextStory.ID
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
			fmt.Fprintf(out, "Branch:   %s\n", c.BranchName)
		}
		if c.Step != "" {
			fmt.Fprintf(out, "Step:     %s\n", c.Step)
		}
		fmt.Fprintln(out)
	}

	// Show review-loop detail
	if result.ReviewLoop != nil {
		if result.ReviewLoop.LatestReport != "" {
			fmt.Fprintf(out, "Review:   %s\n", result.ReviewLoop.LatestReport)
		}
		fmt.Fprintln(out)
	}

	fmt.Fprintln(out, "Artifacts:")
	printArtifact(out, "  .hal/ directory", result.Artifacts.HalDir)
	printArtifact(out, "  Markdown PRD", result.Artifacts.MarkdownPRD)
	printArtifact(out, "  JSON PRD", result.Artifacts.JSONPRD)
	printArtifact(out, "  Progress file", result.Artifacts.ProgressFile)
	printArtifact(out, "  Report", result.Artifacts.ReportAvailable)
	printArtifact(out, "  Auto state", result.Artifacts.AutoState)
	fmt.Fprintln(out)

	if result.NextAction.ID != "" {
		fmt.Fprintf(out, "Action:   %s\n", result.NextAction.Command)
		fmt.Fprintf(out, "          %s\n", result.NextAction.Description)
	}

	return nil
}

func printArtifact(out io.Writer, label string, present bool) {
	mark := "✗"
	if present {
		mark = "✓"
	}
	fmt.Fprintf(out, "  %s %s\n", mark, label)
}
