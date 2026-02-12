package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestCloudHelp_ListsOnlySupportedCommands verifies that hal cloud --help
// lists exactly the 9 supported commands and no others.
func TestCloudHelp_ListsOnlySupportedCommands(t *testing.T) {
	supported := []string{"setup", "doctor", "list", "status", "logs", "cancel", "pull", "auth", "worker"}

	var subcommands []string
	for _, sub := range cloudCmd.Commands() {
		subcommands = append(subcommands, sub.Name())
	}

	// Verify exact count — catches both missing and extra commands.
	if len(subcommands) != len(supported) {
		t.Errorf("expected %d cloud subcommands, got %d: %v", len(supported), len(subcommands), subcommands)
	}

	// Verify each supported command is registered.
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
}

// TestCloudHelp_RemovedCommandsAbsentFromHelpText verifies that removed commands
// do not appear in the rendered help text output.
func TestCloudHelp_RemovedCommandsAbsentFromHelpText(t *testing.T) {
	removed := []string{"submit", "smoke", "env"}

	var buf bytes.Buffer
	cloudCmd.SetOut(&buf)
	cloudCmd.SetErr(&buf)
	_ = cloudCmd.Help()
	helpOutput := buf.String()
	cloudCmd.SetOut(nil)
	cloudCmd.SetErr(nil)

	for _, unwanted := range removed {
		// Check the "Available Commands:" section for removed names.
		inAvailable := false
		for _, line := range strings.Split(helpOutput, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "Available Commands:" {
				inAvailable = true
				continue
			}
			if inAvailable && trimmed == "" {
				inAvailable = false
				continue
			}
			if inAvailable && strings.HasPrefix(trimmed, unwanted+" ") {
				t.Errorf("removed command %q found in Available Commands section of hal cloud --help", unwanted)
			}
		}
	}

	// Additionally verify "run" is not in Available Commands.
	inAvailable := false
	for _, line := range strings.Split(helpOutput, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "Available Commands:" {
			inAvailable = true
			continue
		}
		if inAvailable && trimmed == "" {
			inAvailable = false
			continue
		}
		if inAvailable && strings.HasPrefix(trimmed, "run ") {
			t.Errorf("removed command %q found in Available Commands section of hal cloud --help", "run")
		}
	}
}

// TestCloudHelp_LongDescriptionListsSupportedCommands verifies that the Long
// description in cloudCmd lists the supported command entries.
func TestCloudHelp_LongDescriptionListsSupportedCommands(t *testing.T) {
	supported := []string{"setup", "doctor", "list", "status", "logs", "cancel", "pull", "auth", "worker"}
	longText := cloudCmd.Long

	for _, want := range supported {
		entry := "  " + want
		found := false
		for _, line := range strings.Split(longText, "\n") {
			if strings.HasPrefix(line, entry) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("supported command %q not listed in cloud Long description:\n%s", want, longText)
		}
	}
}

// TestWorkflowCommands_SharedCloudFlags verifies that hal run, hal auto, and
// hal review all register the same shared cloud flag set.
func TestWorkflowCommands_SharedCloudFlags(t *testing.T) {
	expectedFlags := CloudFlagNames()

	cmds := []struct {
		name string
		cmd  *cobra.Command
	}{
		{"run", runCmd},
		{"auto", autoCmd},
		{"review", reviewCmd},
	}

	for _, tc := range cmds {
		t.Run(tc.name, func(t *testing.T) {
			for _, flagName := range expectedFlags {
				f := tc.cmd.Flags().Lookup(flagName)
				if f == nil {
					t.Errorf("hal %s --help is missing cloud flag --%s", tc.name, flagName)
				}
			}
		})
	}
}

// TestWorkflowCommands_CloudFlagUsageInHelp verifies that hal run --help,
// hal auto --help, and hal review --help each include usage text for all
// shared cloud flags.
func TestWorkflowCommands_CloudFlagUsageInHelp(t *testing.T) {
	expectedFlags := CloudFlagNames()

	cmds := []struct {
		name string
		cmd  *cobra.Command
	}{
		{"run", runCmd},
		{"auto", autoCmd},
		{"review", reviewCmd},
	}

	for _, tc := range cmds {
		t.Run(tc.name, func(t *testing.T) {
			usage := tc.cmd.UsageString()
			for _, flagName := range expectedFlags {
				flagStr := "--" + flagName
				if !strings.Contains(usage, flagStr) {
					t.Errorf("hal %s --help does not document flag %s", tc.name, flagStr)
				}
			}
		})
	}
}

// TestWorkflowCommands_CloudFlagConsistency verifies that all three workflow
// commands have exactly the same cloud flag definitions (same defaults and
// usage descriptions).
func TestWorkflowCommands_CloudFlagConsistency(t *testing.T) {
	expectedFlags := CloudFlagNames()

	type flagSnapshot struct {
		defValue string
		usage    string
	}

	// Collect from run as reference.
	runSnap := make(map[string]flagSnapshot)
	for _, flagName := range expectedFlags {
		f := runCmd.Flags().Lookup(flagName)
		if f == nil {
			t.Fatalf("hal run missing cloud flag --%s", flagName)
		}
		runSnap[flagName] = flagSnapshot{defValue: f.DefValue, usage: f.Usage}
	}

	// Compare auto and review flags to run.
	otherCmds := []struct {
		name string
		cmd  *cobra.Command
	}{
		{"auto", autoCmd},
		{"review", reviewCmd},
	}

	for _, other := range otherCmds {
		t.Run("run_vs_"+other.name, func(t *testing.T) {
			for _, flagName := range expectedFlags {
				f := other.cmd.Flags().Lookup(flagName)
				if f == nil {
					t.Fatalf("hal %s missing cloud flag --%s", other.name, flagName)
				}
				ref := runSnap[flagName]
				if f.DefValue != ref.defValue {
					t.Errorf("flag --%s: hal run default %q != hal %s default %q",
						flagName, ref.defValue, other.name, f.DefValue)
				}
				if f.Usage != ref.usage {
					t.Errorf("flag --%s: hal run usage %q != hal %s usage %q",
						flagName, ref.usage, other.name, f.Usage)
				}
			}
		})
	}
}

// TestCloudHelp_CommandTreeSnapshot is a snapshot test that locks the exact
// set of cloud subcommands and their short descriptions.
func TestCloudHelp_CommandTreeSnapshot(t *testing.T) {
	wantTree := map[string]string{
		"setup":  "Guided cloud profile configuration",
		"doctor": "Diagnose cloud configuration and connectivity",
		"list":   "List cloud runs",
		"status": "Check run status",
		"logs":   "View run logs",
		"cancel": "Cancel a running run",
		"pull":   "Pull final state from a completed run",
		"auth":   "Manage auth profiles",
		"worker": "Run the cloud worker loop",
	}

	subs := cloudCmd.Commands()
	if len(subs) != len(wantTree) {
		var names []string
		for _, s := range subs {
			names = append(names, s.Name())
		}
		t.Fatalf("expected %d cloud subcommands, got %d: %v", len(wantTree), len(subs), names)
	}

	for _, sub := range subs {
		wantShort, ok := wantTree[sub.Name()]
		if !ok {
			t.Errorf("unexpected cloud subcommand %q", sub.Name())
			continue
		}
		if sub.Short != wantShort {
			t.Errorf("cloud %s Short = %q, want %q", sub.Name(), sub.Short, wantShort)
		}
	}
}

// TestCloudHelp_CloudFlagDocSnapshot locks the exact flag definitions used by
// all workflow commands. If a flag is added, removed, or renamed, this test
// will catch it.
func TestCloudHelp_CloudFlagDocSnapshot(t *testing.T) {
	wantFlags := []struct {
		name     string
		usage    string
		defValue string
	}{
		{"cloud", "Execute in the cloud", "false"},
		{"cloud-profile", "Cloud profile name from .hal/cloud.yaml", ""},
		{"detach", "Submit and return immediately without waiting", "false"},
		{"wait", "Wait for cloud run to complete", "false"},
		{"json", "Output in JSON format", "false"},
		{"cloud-mode", "Cloud execution mode", ""},
		{"cloud-endpoint", "Cloud endpoint URL", ""},
		{"cloud-repo", "Repository (owner/repo)", ""},
		{"cloud-base", "Base branch name", ""},
		{"cloud-auth-profile", "Auth profile ID", ""},
		{"cloud-auth-scope", "Auth scope reference", ""},
	}

	for _, wf := range wantFlags {
		t.Run(wf.name, func(t *testing.T) {
			// Verify against the run command as the reference.
			f := runCmd.Flags().Lookup(wf.name)
			if f == nil {
				t.Fatalf("hal run missing cloud flag --%s", wf.name)
			}
			if f.Usage != wf.usage {
				t.Errorf("flag --%s usage = %q, want %q", wf.name, f.Usage, wf.usage)
			}
			if f.DefValue != wf.defValue {
				t.Errorf("flag --%s default = %q, want %q", wf.name, f.DefValue, wf.defValue)
			}
		})
	}
}
