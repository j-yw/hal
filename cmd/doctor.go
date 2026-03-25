package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/jywlabs/hal/internal/compound"
	"github.com/jywlabs/hal/internal/doctor"
	display "github.com/jywlabs/hal/internal/engine"
	"github.com/spf13/cobra"
)

var (
	doctorJSONFlag bool
	doctorFixFlag  bool
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check Hal readiness and environment health",
	Args:  noArgsValidation(),
	Long: `Check that Hal is properly set up and ready to use.

Inspects:
  - Git repository presence
  - .hal/ directory and config
  - Default engine CLI availability
  - Installed skills and commands
  - Codex global links (only when engine is codex)

With --json, outputs a stable machine-readable contract (v1) suitable
for agent orchestration and tooling integration.

The doctor is engine-aware: Codex-specific checks are skipped when
the configured engine is not codex.

Use --fix to auto-apply safe remediations (equivalent to 'hal repair').

Examples:
  hal doctor            # Human-readable check results
  hal doctor --json     # Machine-readable JSON contract
  hal doctor --fix      # Check and auto-fix safe issues`,
	Example: `  hal doctor
  hal doctor --json
  hal doctor --fix`,
	RunE: runDoctor,
}

func init() {
	doctorCmd.Flags().BoolVar(&doctorJSONFlag, "json", false, "Output machine-readable JSON (v1 contract)")
	doctorCmd.Flags().BoolVar(&doctorFixFlag, "fix", false, "Auto-fix safe issues (equivalent to hal repair)")
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	jsonMode := doctorJSONFlag
	fix := doctorFixFlag

	if cmd != nil {
		out = cmd.OutOrStdout()
		if cmd.Flags().Lookup("json") != nil {
			v, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = v
		}
		if cmd.Flags().Lookup("fix") != nil {
			v, err := cmd.Flags().GetBool("fix")
			if err != nil {
				return err
			}
			fix = v
		}
	}

	if fix {
		return runRepairFn(".", false, jsonMode, out)
	}

	return runDoctorFn(".", jsonMode, out)
}

func runDoctorFn(dir string, jsonMode bool, out io.Writer) error {
	engine, _ := compound.LoadDefaultEngine(dir)

	result := doctor.Run(doctor.Options{
		Dir:    dir,
		Engine: engine,
	})

	if jsonMode {
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal doctor result: %w", err)
		}
		fmt.Fprintln(out, string(data))
		return nil
	}

	// Human-readable output
	fmt.Fprintf(out, "Engine:   %s\n", engine)
	checksLabel := fmt.Sprintf("%d/%d passed", result.PassedChecks, result.TotalChecks)
	if result.PassedChecks == result.TotalChecks {
		checksLabel = display.StyleSuccess.Render(checksLabel)
	} else {
		checksLabel = display.StyleWarning.Render(checksLabel)
	}
	fmt.Fprintf(out, "Checks:   %s\n\n", checksLabel)
	for _, c := range result.Checks {
		var icon string
		switch c.Status {
		case doctor.StatusFail:
			icon = display.StyleError.Render("✗")
		case doctor.StatusWarn:
			icon = display.StyleWarning.Render("⚠")
		case doctor.StatusSkip:
			icon = display.StyleMuted.Render("−")
		default:
			icon = display.StyleSuccess.Render("✓")
		}
		fmt.Fprintf(out, "  %s  %s\n", icon, c.Message)
	}

	fmt.Fprintln(out)
	if result.OverallStatus == doctor.StatusPass {
		fmt.Fprintln(out, display.StyleSuccess.Render(result.Summary))
	} else {
		fmt.Fprintln(out, display.StyleWarning.Render(result.Summary))
	}

	if result.PrimaryRemediation != nil {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "Fix:      %s\n", display.StyleInfo.Render(result.PrimaryRemediation.Command))
	}

	return nil
}
