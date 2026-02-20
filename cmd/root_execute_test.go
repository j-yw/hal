package cmd

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestExecuteWithDepsTypedErrorPrintsOnceWithoutUsage(t *testing.T) {
	root := &cobra.Command{Use: "hal"}
	typed := &cobra.Command{
		Use: "typed",
		RunE: func(cmd *cobra.Command, args []string) error {
			return exitWithCode(cmd, ExitCodeValidation, errors.New("invalid input"))
		},
	}
	root.AddCommand(typed)
	root.SetArgs([]string{"typed"})

	var cobraErr bytes.Buffer
	root.SetErr(&cobraErr)

	var helperErr bytes.Buffer
	var exitCode int
	executeWithDeps(root, &helperErr, func(code int) {
		exitCode = code
	})

	if exitCode != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitCode, ExitCodeValidation)
	}
	if helperErr.String() != "invalid input\n" {
		t.Fatalf("helper stderr = %q, want %q", helperErr.String(), "invalid input\\n")
	}
	if strings.Contains(cobraErr.String(), "Usage:") {
		t.Fatalf("cobra stderr should not include usage for typed error: %q", cobraErr.String())
	}
}

func TestExecuteWithDepsNonTypedErrorKeepsLegacyBehavior(t *testing.T) {
	root := &cobra.Command{Use: "hal"}
	broken := &cobra.Command{
		Use: "broken",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("boom")
		},
	}
	root.AddCommand(broken)
	root.SetArgs([]string{"broken"})

	var cobraErr bytes.Buffer
	root.SetErr(&cobraErr)

	var helperErr bytes.Buffer
	var exitCode int
	executeWithDeps(root, &helperErr, func(code int) {
		exitCode = code
	})

	if exitCode != 1 {
		t.Fatalf("exit code = %d, want %d", exitCode, 1)
	}
	if helperErr.Len() != 0 {
		t.Fatalf("helper stderr should be empty for non-typed errors, got %q", helperErr.String())
	}
	if !strings.Contains(cobraErr.String(), "boom") {
		t.Fatalf("cobra stderr = %q, want to contain %q", cobraErr.String(), "boom")
	}
}

func TestExecuteWithDepsFlagParseErrorUsesValidationExitCode(t *testing.T) {
	root := &cobra.Command{Use: "hal"}
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return exitWithCode(cmd, ExitCodeValidation, err)
	})
	root.Flags().Bool("known", false, "known flag")
	root.SetArgs([]string{"--unknown"})

	var helperErr bytes.Buffer
	var exitCode int
	executeWithDeps(root, &helperErr, func(code int) {
		exitCode = code
	})

	if exitCode != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitCode, ExitCodeValidation)
	}
	if !strings.Contains(helperErr.String(), "unknown flag") {
		t.Fatalf("stderr = %q, want unknown flag message", helperErr.String())
	}
	if strings.Contains(helperErr.String(), "Usage:") {
		t.Fatalf("stderr should not include usage: %q", helperErr.String())
	}
}

func TestExecuteWithDepsArgsValidationErrorDoesNotPrintUsage(t *testing.T) {
	root := &cobra.Command{Use: "hal"}
	report := &cobra.Command{
		Use:  "report",
		Args: noArgsValidation(),
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	root.AddCommand(report)
	root.SetArgs([]string{"report", "extra"})

	var cobraErr bytes.Buffer
	root.SetErr(&cobraErr)

	var helperErr bytes.Buffer
	var exitCode int
	executeWithDeps(root, &helperErr, func(code int) {
		exitCode = code
	})

	if exitCode != ExitCodeValidation {
		t.Fatalf("exit code = %d, want %d", exitCode, ExitCodeValidation)
	}
	if !strings.Contains(helperErr.String(), "accepts 0 arg(s), received 1") {
		t.Fatalf("stderr = %q, want positional arg validation message", helperErr.String())
	}
	if strings.Contains(helperErr.String(), "Usage:") {
		t.Fatalf("helper stderr should not include usage: %q", helperErr.String())
	}
	if strings.Contains(cobraErr.String(), "Usage:") {
		t.Fatalf("cobra stderr should not include usage: %q", cobraErr.String())
	}
}
