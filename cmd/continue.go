package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/doctor"
	"github.com/jywlabs/hal/internal/status"
	"github.com/spf13/cobra"
)

var continueJSONFlag bool

// ContinueResult is the machine-readable output of hal continue --json.
type ContinueResult struct {
	ContractVersion int                `json:"contractVersion"`
	Ready           bool               `json:"ready"`
	Status          status.StatusResult `json:"status"`
	Doctor          doctor.DoctorResult `json:"doctor"`
	NextCommand     string              `json:"nextCommand"`
	NextDescription string              `json:"nextDescription"`
	Summary         string              `json:"summary"`
}

var continueCmd = &cobra.Command{
	Use:   "continue",
	Short: "Show what to do next",
	Args:  noArgsValidation(),
	Long: `Show the next recommended action by combining workflow state and health checks.

This command inspects both the workflow state (hal status) and environment
health (hal doctor) to determine the safest next step.

If the environment needs repair, the repair step is shown first.
Otherwise, the workflow-appropriate next action is shown.

With --json, outputs combined status and doctor results.

Examples:
  hal continue          # Human-readable next step
  hal continue --json   # Machine-readable combined status + doctor`,
	Example: `  hal continue
  hal continue --json`,
	RunE: runContinue,
}

func init() {
	continueCmd.Flags().BoolVar(&continueJSONFlag, "json", false, "Output machine-readable JSON")
	rootCmd.AddCommand(continueCmd)
}

func runContinue(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := continueJSONFlag

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

	return runContinueFn(".", jsonMode, out)
}

func runContinueFn(dir string, jsonMode bool, out io.Writer) error {
	statusResult := status.Get(dir)

	engine, _ := compound.LoadDefaultEngine(dir)
	doctorResult := doctor.Run(doctor.Options{
		Dir:    dir,
		Engine: engine,
	})

	// Determine what to do: doctor issues take priority over workflow actions
	ready := doctorResult.OverallStatus == doctor.StatusPass
	nextCmd := statusResult.NextAction.Command
	nextDesc := statusResult.NextAction.Description

	if !ready && doctorResult.PrimaryRemediation != nil {
		nextCmd = doctorResult.PrimaryRemediation.Command
		nextDesc = "Fix environment issues first: " + doctorResult.Summary
	}

	summary := statusResult.Summary
	if !ready {
		summary = doctorResult.Summary + " " + statusResult.Summary
	}

	if jsonMode {
		jr := ContinueResult{
			ContractVersion: 1,
			Ready:           ready,
			Status:          statusResult,
			Doctor:          doctorResult,
			NextCommand:     nextCmd,
			NextDescription: nextDesc,
			Summary:         summary,
		}
		data, err := json.MarshalIndent(jr, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal continue result: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	// Human-readable output
	if !ready {
		fmt.Fprintln(out, "⚠  Environment needs attention")
		fmt.Fprintln(out)
		for _, c := range doctorResult.Checks {
			if c.Status == doctor.StatusFail || c.Status == doctor.StatusWarn {
				fmt.Fprintf(out, "  %s\n", c.Message)
			}
		}
		fmt.Fprintln(out)
		fmt.Fprintf(out, "Fix:      %s\n", nextCmd)
		fmt.Fprintln(out)
		fmt.Fprintf(out, "Then:     %s\n", statusResult.NextAction.Command)
		fmt.Fprintf(out, "          %s\n", statusResult.NextAction.Description)
	} else {
		fmt.Fprintf(out, "Workflow: %s (%s)\n", statusResult.WorkflowTrack, statusResult.State)
		fmt.Fprintf(out, "Health:   %d/%d checks passed\n", doctorResult.PassedChecks, doctorResult.TotalChecks)
		if statusResult.Manual != nil {
			fmt.Fprintf(out, "Stories:  %d/%d complete\n", statusResult.Manual.CompletedStories, statusResult.Manual.TotalStories)
		}
		if statusResult.Compound != nil {
			if statusResult.Compound.Step != "" {
				fmt.Fprintf(out, "Step:     %s\n", statusResult.Compound.Step)
			}
			if statusResult.Compound.BranchName != "" {
				fmt.Fprintf(out, "Branch:   %s\n", statusResult.Compound.BranchName)
			}
		}
		fmt.Fprintln(out)
		fmt.Fprintf(out, "Next:     %s\n", nextCmd)
		fmt.Fprintf(out, "          %s\n", nextDesc)
	}

	return nil
}
