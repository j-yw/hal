package cmd

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestNoArgsCommandsRejectExtraArgsWithValidationCode(t *testing.T) {
	tests := []struct {
		name string
		cmd  *cobra.Command
	}{
		{name: "init", cmd: initCmd},
		{name: "auto", cmd: autoCmd},
		{name: "cleanup", cmd: cleanupCmd},
		{name: "version", cmd: versionCmd},
		{name: "report", cmd: reportCmd},
		{name: "archive create", cmd: archiveCreateCmd},
		{name: "archive list", cmd: archiveListCmd},
		{name: "standards list", cmd: standardsListCmd},
		{name: "standards discover", cmd: standardsDiscoverCmd},
		{name: "sandbox setup", cmd: sandboxSetupCmd},
		{name: "sandbox start", cmd: sandboxStartCmd},


	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.cmd.Args == nil {
				t.Fatalf("%s has no Args validator", tt.name)
			}

			err := tt.cmd.Args(tt.cmd, []string{"unexpected"})
			if err == nil {
				t.Fatalf("%s should reject extra args", tt.name)
			}

			var exitErr *ExitCodeError
			if !errors.As(err, &exitErr) {
				t.Fatalf("%s returned %T, want ExitCodeError", tt.name, err)
			}
			if exitErr.Code != ExitCodeValidation {
				t.Fatalf("%s exit code = %d, want %d", tt.name, exitErr.Code, ExitCodeValidation)
			}
			if !strings.Contains(err.Error(), "accepts 0 arg(s), received 1") {
				t.Fatalf("%s error = %q, want no-args validation message", tt.name, err.Error())
			}
		})
	}
}

func TestParentCommandRoutingHandlesHelpAndUnknownSubcommands(t *testing.T) {
	execRoot := func(t *testing.T, dir string, args ...string) (string, string, error) {
		t.Helper()

		origDir, err := os.Getwd()
		if err != nil {
			t.Fatalf("getwd: %v", err)
		}
		if err := os.Chdir(dir); err != nil {
			t.Fatalf("chdir: %v", err)
		}
		t.Cleanup(func() { _ = os.Chdir(origDir) })

		origOut := rootCmd.OutOrStdout()
		origErr := rootCmd.ErrOrStderr()
		origIn := rootCmd.InOrStdin()
		t.Cleanup(func() {
			rootCmd.SetOut(origOut)
			rootCmd.SetErr(origErr)
			rootCmd.SetIn(origIn)
			rootCmd.SetArgs(nil)
		})

		if flag := archiveCmd.PersistentFlags().Lookup("name"); flag != nil {
			_ = flag.Value.Set("")
			flag.Changed = false
		}
		archiveNameFlag = ""
		if flag := archiveListCmd.Flags().Lookup("verbose"); flag != nil {
			_ = flag.Value.Set("false")
			flag.Changed = false
		}
		archiveVerboseFlag = false

		var stdout, stderr bytes.Buffer
		rootCmd.SetOut(&stdout)
		rootCmd.SetErr(&stderr)
		rootCmd.SetArgs(args)

		err = rootCmd.Execute()
		return stdout.String(), stderr.String(), err
	}

	t.Run("archive help token shows help", func(t *testing.T) {
		stdout, _, err := execRoot(t, t.TempDir(), "archive", "help")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !strings.Contains(stdout, "Archive current feature state") {
			t.Fatalf("stdout %q does not include archive help text", stdout)
		}
	})

	t.Run("archive typo is unknown command", func(t *testing.T) {
		_, _, err := execRoot(t, t.TempDir(), "archive", "lst")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `unknown command "lst" for "hal archive"`) {
			t.Fatalf("error %q does not include unknown command guidance", err.Error())
		}
		if strings.Contains(err.Error(), "accepts 0 arg(s)") {
			t.Fatalf("error %q should not be positional-arg validation", err.Error())
		}
	})

	t.Run("config help token shows help", func(t *testing.T) {
		stdout, _, err := execRoot(t, t.TempDir(), "config", "help")
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if !strings.Contains(stdout, "Show the current Hal configuration") {
			t.Fatalf("stdout %q does not include config help text", stdout)
		}
	})

	t.Run("config typo is unknown command", func(t *testing.T) {
		_, _, err := execRoot(t, t.TempDir(), "config", "lst")
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if !strings.Contains(err.Error(), `unknown command "lst" for "hal config"`) {
			t.Fatalf("error %q does not include unknown command guidance", err.Error())
		}
		if strings.Contains(err.Error(), "accepts 0 arg(s)") {
			t.Fatalf("error %q should not be positional-arg validation", err.Error())
		}
	})
}
