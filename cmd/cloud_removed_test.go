package cmd

import (
	"bytes"
	"strings"
	"testing"
)

// TestCloudCommandTree_SnapshotSupportedCommands verifies that hal cloud --help
// lists exactly the supported commands and does not list any removed commands.
func TestCloudCommandTree_SnapshotSupportedCommands(t *testing.T) {
	supported := []string{"setup", "doctor", "list", "status", "logs", "cancel", "pull", "auth", "worker"}
	removed := []string{"submit", "run", "smoke", "env", "runs"}

	var subcommands []string
	for _, sub := range cloudCmd.Commands() {
		subcommands = append(subcommands, sub.Name())
	}

	// Verify all supported commands are present.
	for _, want := range supported {
		found := false
		for _, name := range subcommands {
			if name == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("supported command %q not found in cloud subcommands: %v", want, subcommands)
		}
	}

	// Verify all removed commands are absent.
	for _, unwanted := range removed {
		for _, name := range subcommands {
			if name == unwanted {
				t.Errorf("removed command %q should not appear in cloud subcommands: %v", unwanted, subcommands)
			}
		}
	}
}

// TestCloudCommandTree_HelpDoesNotListRemovedCommands verifies that the help
// output text does not mention removed commands as subcommand entries.
func TestCloudCommandTree_HelpDoesNotListRemovedCommands(t *testing.T) {
	removed := []string{"submit", "smoke", "env"}

	// Build the subcommand listing text (name + short description).
	var listing strings.Builder
	for _, sub := range cloudCmd.Commands() {
		listing.WriteString(" " + sub.Name() + " " + sub.Short)
	}
	subcommandText := listing.String()

	for _, unwanted := range removed {
		if strings.Contains(subcommandText, unwanted) {
			t.Errorf("removed command %q found in cloud subcommand listing:\n%s", unwanted, subcommandText)
		}
	}

	// Also verify the Long description does not reference removed command names
	// as subcommand entries (lines starting with two spaces followed by the name).
	longText := cloudCmd.Long
	for _, unwanted := range []string{"submit", "smoke", "env", "runs"} {
		entry := "  " + unwanted
		for _, line := range strings.Split(longText, "\n") {
			trimmed := strings.TrimRight(line, " ")
			if strings.HasPrefix(trimmed, entry) {
				t.Errorf("removed command %q found as entry in cloud Long description:\n%s", unwanted, longText)
			}
		}
	}

	// Verify "run" does not appear as a standalone subcommand entry.
	// (Must not match "run " as a subcommand while allowing words like "running".)
	for _, sub := range cloudCmd.Commands() {
		if sub.Name() == "run" {
			t.Errorf("removed command %q is registered as a cloud subcommand", "run")
		}
	}
}

// TestCloudRemovedCommands_UnknownCommandBehavior verifies that invoking
// each removed command returns unknown-command behavior with non-zero exit.
func TestCloudRemovedCommands_UnknownCommandBehavior(t *testing.T) {
	removed := []string{"submit", "run", "smoke", "env", "runs"}

	for _, name := range removed {
		t.Run(name, func(t *testing.T) {
			// Verify the command is not registered as a subcommand.
			for _, sub := range cloudCmd.Commands() {
				if sub.Name() == name {
					t.Fatalf("removed command %q is still registered as a cloud subcommand", name)
				}
			}

			// Verify that running `hal cloud <removed>` produces an error.
			// We use the root command to test the full command tree.
			root := rootCmd
			var stderr bytes.Buffer
			root.SetArgs([]string{"cloud", name})
			root.SetOut(&stderr)
			root.SetErr(&stderr)
			root.SilenceUsage = true
			root.SilenceErrors = true
			err := root.Execute()
			if err == nil {
				t.Errorf("hal cloud %s should return error, got nil", name)
			}
			// Reset for other tests.
			root.SetArgs(nil)
			root.SetOut(nil)
			root.SetErr(nil)
			root.SilenceUsage = false
			root.SilenceErrors = false
		})
	}
}
