package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/doctor"
	"github.com/jywlabs/hal/internal/skills"
	"github.com/jywlabs/hal/internal/template"
	"github.com/spf13/cobra"
)

var (
	repairDryRunFlag bool
	repairJSONFlag   bool
)

// RepairResult is the machine-readable output of hal repair --json.
type RepairResult struct {
	ContractVersion int            `json:"contractVersion"`
	OK              bool           `json:"ok"`
	Applied         []RepairAction `json:"applied,omitempty"`
	Remaining       []string       `json:"remaining,omitempty"`
	Summary         string         `json:"summary"`
}

// RepairAction describes a single repair step that was applied.
type RepairAction struct {
	CheckID string `json:"checkId"`
	Command string `json:"command"`
	Status  string `json:"status"` // "applied", "skipped", "failed"
	Error   string `json:"error,omitempty"`
}

var repairCmd = &cobra.Command{
	Use:   "repair",
	Short: "Auto-fix environment issues detected by doctor",
	Args:  noArgsValidation(),
	Long: `Automatically fix environment issues detected by hal doctor.

Only applies safe remediations:
  - hal init (for missing .hal/ files, skills, commands)
  - hal cleanup (for legacy debris)
  - hal links refresh (for stale engine links)

Use --dry-run to preview what would be fixed.
Use --json for machine-readable output.

Examples:
  hal repair            # Fix all safe issues
  hal repair --dry-run  # Preview fixes
  hal repair --json     # Machine-readable result`,
	Example: `  hal repair
  hal repair --dry-run
  hal repair --json`,
	RunE: runRepair,
}

func init() {
	repairCmd.Flags().BoolVar(&repairDryRunFlag, "dry-run", false, "Preview repairs without applying")
	repairCmd.Flags().BoolVar(&repairJSONFlag, "json", false, "Output machine-readable JSON result")
	rootCmd.AddCommand(repairCmd)
}

func runRepair(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	dryRun := repairDryRunFlag
	jsonMode := repairJSONFlag

	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("dry-run") != nil {
			v, _ := cmd.Flags().GetBool("dry-run")
			dryRun = v
		}
		if cmd.Flags().Lookup("json") != nil {
			v, _ := cmd.Flags().GetBool("json")
			jsonMode = v
		}
	}

	return runRepairFn(".", dryRun, jsonMode, out)
}

func runRepairFn(dir string, dryRun bool, jsonMode bool, out io.Writer) error {
	engine, _ := compound.LoadDefaultEngine(dir)

	result := doctor.Run(doctor.Options{
		Dir:    dir,
		Engine: engine,
	})

	if result.OverallStatus == doctor.StatusPass {
		if jsonMode {
			jr := RepairResult{
				ContractVersion: 1,
				OK:              true,
				Summary:         "No repairs needed. Hal is healthy.",
			}
			data, _ := json.MarshalIndent(jr, "", "  ")
			fmt.Fprintln(out, string(data))
			return nil
		}
		fmt.Fprintln(out, "No repairs needed. Hal is healthy.")
		return nil
	}

	// Collect unique safe remediation commands
	type repairStep struct {
		checkID string
		command string
	}
	seen := map[string]bool{}
	var steps []repairStep

	for _, c := range result.Checks {
		if (c.Status == doctor.StatusFail || c.Status == doctor.StatusWarn) && c.Remediation != nil && c.Remediation.Safe {
			if !seen[c.Remediation.Command] {
				seen[c.Remediation.Command] = true
				steps = append(steps, repairStep{checkID: c.ID, command: c.Remediation.Command})
			}
		}
	}

	if len(steps) == 0 {
		remaining := append(result.Failures, result.Warnings...)
		if jsonMode {
			jr := RepairResult{
				ContractVersion: 1,
				OK:              false,
				Remaining:       remaining,
				Summary:         "Issues found but no safe auto-repairs available.",
			}
			data, _ := json.MarshalIndent(jr, "", "  ")
			fmt.Fprintln(out, string(data))
			return nil
		}
		fmt.Fprintln(out, "Issues found but no safe auto-repairs available.")
		for _, r := range remaining {
			fmt.Fprintf(out, "  - %s\n", r)
		}
		return nil
	}

	var applied []RepairAction

	for _, step := range steps {
		if dryRun {
			applied = append(applied, RepairAction{
				CheckID: step.checkID,
				Command: step.command,
				Status:  "skipped",
			})
			if !jsonMode {
				fmt.Fprintf(out, "[dry-run] Would run: %s\n", step.command)
			}
			continue
		}

		action := RepairAction{
			CheckID: step.checkID,
			Command: step.command,
		}

		err := executeRepairCommand(dir, step.command)
		if err != nil {
			action.Status = "failed"
			action.Error = err.Error()
			if !jsonMode {
				fmt.Fprintf(out, "✗ %s: %v\n", step.command, err)
			}
		} else {
			action.Status = "applied"
			if !jsonMode {
				fmt.Fprintf(out, "✓ %s\n", step.command)
			}
		}
		applied = append(applied, action)
	}

	// Re-check to find remaining issues
	recheck := doctor.Run(doctor.Options{Dir: dir, Engine: engine})
	var remaining []string
	remaining = append(remaining, recheck.Failures...)
	remaining = append(remaining, recheck.Warnings...)

	allOK := recheck.OverallStatus == doctor.StatusPass

	if jsonMode {
		jr := RepairResult{
			ContractVersion: 1,
			OK:              allOK,
			Applied:         applied,
			Remaining:       remaining,
		}
		if dryRun {
			jr.Summary = fmt.Sprintf("Would apply %d repair(s).", len(steps))
		} else if allOK {
			jr.Summary = fmt.Sprintf("Applied %d repair(s). Hal is now healthy.", len(steps))
		} else {
			jr.Summary = fmt.Sprintf("Applied %d repair(s). %d issue(s) remain.", len(steps), len(remaining))
		}
		data, _ := json.MarshalIndent(jr, "", "  ")
		fmt.Fprintln(out, string(data))
		return nil
	}

	fmt.Fprintln(out)
	if dryRun {
		fmt.Fprintf(out, "Would apply %d repair(s). Run without --dry-run to apply.\n", len(steps))
	} else if allOK {
		fmt.Fprintf(out, "Applied %d repair(s). Hal is now healthy.\n", len(steps))
	} else {
		fmt.Fprintf(out, "Applied %d repair(s). %d issue(s) remain. Run hal doctor for details.\n", len(steps), len(remaining))
	}

	return nil
}

// executeRepairCommand runs a repair command by name.
func executeRepairCommand(dir string, command string) error {
	switch command {
	case "hal init":
		return runInitWithWriters(nil, nil, io.Discard, io.Discard)
	case "hal cleanup":
		return runCleanupFn(filepath.Join(dir, template.HalDir), false, io.Discard)
	case "hal init --refresh-templates":
		return runInitWithWriters(nil, nil, io.Discard, io.Discard)
	case "hal links refresh":
		if err := skills.LinkAllEngines(dir); err != nil {
			_ = err
		}
		if err := skills.LinkAllCommands(dir); err != nil {
			_ = err
		}
		return nil
	case "hal links clean":
		return runLinksCleanFn(dir, io.Discard)
	default:
		return fmt.Errorf("unknown repair command: %s", command)
	}
}
