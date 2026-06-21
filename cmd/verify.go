package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	display "github.com/jywlabs/hal/internal/engine"
	"github.com/jywlabs/hal/internal/verify"
	"github.com/spf13/cobra"
)

var verifyJSONFlag bool

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Run configured verification checks",
	Args:  noArgsValidation(),
	Long: `Run configured project verification checks from .hal/config.yaml.

Verification checks are defined under verify.checks and currently use shell
commands. The required field defaults to true and workDir defaults to the
project root when omitted.

Minimal shell-check configuration:
  verify:
    checks:
      - id: test
        name: Go tests
        command: go test ./...
        timeoutSeconds: 120
      - id: lint
        name: Lint
        command: golangci-lint run ./...
        required: false

Required checks fail the verification gate when they fail, time out, or are
missing. Optional checks produce warnings without failing the gate.

With --json, emits the verify-v1 machine-readable contract on stdout. The
command exits 0 for pass and warn results, and exits non-zero for fail results.

Examples:
  hal verify          # Human-readable verification summary
  hal verify --json   # Machine-readable verify-v1 JSON output`,
	Example: `  hal verify
  hal verify --json`,
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().BoolVar(&verifyJSONFlag, "json", false, "Output machine-readable verify-v1 JSON")
	rootCmd.AddCommand(verifyCmd)
}

type verifyDeps struct {
	loadConfig func(string) (*verify.Config, error)
	run        func(context.Context, *verify.Config) (*verify.Result, error)
}

func defaultVerifyDeps() verifyDeps {
	return verifyDeps{
		loadConfig: verify.LoadConfig,
		run:        verify.Run,
	}
}

func runVerify(cmd *cobra.Command, args []string) error {
	out := io.Writer(os.Stdout)
	errOut := io.Writer(os.Stderr)
	jsonMode := verifyJSONFlag
	ctx := context.Background()

	if cmd != nil {
		out = cmd.OutOrStdout()
		errOut = cmd.ErrOrStderr()
		ctx = cmd.Context()
		if cmd.Flags().Lookup("json") != nil {
			value, err := cmd.Flags().GetBool("json")
			if err != nil {
				return err
			}
			jsonMode = value
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}

	return runVerifyWithDeps(ctx, ".", jsonMode, out, errOut, defaultVerifyDeps(), cmd)
}

func runVerifyWithDeps(ctx context.Context, dir string, jsonMode bool, out, errOut io.Writer, deps verifyDeps, cmd *cobra.Command) error {
	if out == nil {
		out = io.Discard
	}
	if errOut == nil {
		errOut = io.Discard
	}
	if deps.loadConfig == nil {
		deps.loadConfig = verify.LoadConfig
	}
	if deps.run == nil {
		deps.run = verify.Run
	}
	if ctx == nil {
		ctx = context.Background()
	}

	cfg, err := deps.loadConfig(dir)
	if err != nil {
		return exitWithCode(cmd, ExitCodeValidation, err)
	}

	result, err := deps.run(ctx, cfg)
	if err != nil {
		return exitWithCode(cmd, ExitCodeExpectedNonZero, err)
	}

	if jsonMode {
		if err := writeVerifyJSON(out, result); err != nil {
			return err
		}
		if result.Status == verify.StatusFail {
			return exitWithCode(cmd, ExitCodeExpectedNonZero, nil)
		}
		return nil
	}

	renderVerifyHuman(out, result)
	if result.Status == verify.StatusFail {
		return exitWithCode(cmd, ExitCodeExpectedNonZero, fmt.Errorf("verification failed"))
	}
	return nil
}

func writeVerifyJSON(out io.Writer, result *verify.Result) error {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal verify result: %w", err)
	}
	_, err = fmt.Fprintln(out, string(data))
	return err
}

func renderVerifyHuman(out io.Writer, result *verify.Result) {
	if result == nil {
		return
	}

	fmt.Fprintf(out, "%s\n", display.StyleTitle.Render("Verify"))
	fmt.Fprintf(out, "%s     %s\n", display.StyleBold.Render("Status:"), renderVerifyStatus(result.Status))
	fmt.Fprintf(out, "%s     %d total, %d passed, %d failed, %d timed out, %d missing, %d warnings\n",
		display.StyleBold.Render("Checks:"),
		result.Summary.Total,
		result.Summary.Passed,
		result.Summary.Failed,
		result.Summary.TimedOut,
		result.Summary.Missing,
		result.Summary.Warnings,
	)
	fmt.Fprintln(out)

	for _, check := range result.Checks {
		fmt.Fprintf(out, "  %s  %s (%s)\n", renderVerifyCheckIcon(check.Status), check.Name, check.Status)
		if check.Message != "" {
			fmt.Fprintf(out, "     %s\n", display.StyleMuted.Render(check.Message))
		}
	}
}

func renderVerifyStatus(status string) string {
	switch status {
	case verify.StatusPass:
		return display.StyleSuccess.Render(status)
	case verify.StatusWarn:
		return display.StyleWarning.Render(status)
	case verify.StatusFail:
		return display.StyleError.Render(status)
	default:
		return status
	}
}

func renderVerifyCheckIcon(status string) string {
	switch status {
	case verify.CheckStatusPass:
		return display.StyleSuccess.Render("✓")
	case verify.CheckStatusFail, verify.CheckStatusTimeout, verify.CheckStatusMissing:
		return display.StyleError.Render("✗")
	default:
		return display.StyleWarning.Render("⚠")
	}
}
