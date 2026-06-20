package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestTargetedCommandHelpPhrases(t *testing.T) {
	tests := []struct {
		name        string
		cmd         *cobra.Command
		text        func(*cobra.Command) string
		wantPhrases []string
		wantAbsent  []string
	}{
		{
			name:       "config help omits deprecated add-rule example",
			cmd:        configCmd,
			text:       commandHelpBody,
			wantAbsent: []string{"config add-rule"},
		},
		{
			name:       "run help omits stable contract wording",
			cmd:        runCmd,
			text:       commandHelpBody,
			wantAbsent: []string{"stable machine-readable result contract"},
		},
		{
			name: "auto help documents side effects",
			cmd:  autoCmd,
			text: commandLongHelp,
			wantPhrases: []string{
				"Side effects",
				"May create or switch git branches",
				"write .hal/prd.json and .hal/auto-state.json",
				"commit changes through run/review",
				"push/create pull requests during CI",
				"archive completed state",
				"--dry-run",
			},
		},
		{
			name: "archive create help advises agents to pass name",
			cmd:  archiveCreateCmd,
			text: commandLongHelp,
			wantPhrases: []string{
				"--name",
				"agent",
			},
		},
		{
			name:        "archive restore help documents side effects",
			cmd:         archiveRestoreCmd,
			text:        commandLongHelp,
			wantPhrases: []string{"Side effects"},
		},
		{
			name: "plan help documents non-interactive input flags",
			cmd:  planCmd,
			text: commandLongHelp,
			wantPhrases: []string{
				"--input",
				"--input -",
				"--no-questions",
				"--json",
			},
		},
		{
			name:        "ci fix help documents side effects",
			cmd:         ciFixCmd,
			text:        commandLongHelp,
			wantPhrases: []string{"Side effects"},
		},
		{
			name:        "review help documents side effects",
			cmd:         reviewCmd,
			text:        commandLongHelp,
			wantPhrases: []string{"Side effects"},
		},
		{
			name:        "report help documents side effects",
			cmd:         reportCmd,
			text:        commandLongHelp,
			wantPhrases: []string{"Side effects"},
		},
		{
			name:        "init help documents side effects",
			cmd:         initCmd,
			text:        commandLongHelp,
			wantPhrases: []string{"Side effects"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assertHelpPhrases(t, tt.cmd, tt.text(tt.cmd), tt.wantPhrases, tt.wantAbsent)
		})
	}
}

func TestOptionalParentCommandHelpSideEffectGuidance(t *testing.T) {
	tests := []struct {
		name string
		path []string
	}{
		{
			name: "sandbox parent help",
			path: []string{"sandbox"},
		},
		{
			name: "links parent help",
			path: []string{"links"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cmd := optionalCommandAtPath(t, Root(), tt.path...)
			if cmd == nil {
				t.Skipf("command %q is not present in this command tree", strings.Join(tt.path, " "))
			}

			assertHelpPhrases(t, cmd, commandLongHelp(cmd), []string{"Side effects"}, nil)
		})
	}
}

func commandHelpBody(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}

	return strings.Join([]string{cmd.Long, cmd.Example}, "\n")
}

func commandLongHelp(cmd *cobra.Command) string {
	if cmd == nil {
		return ""
	}

	return cmd.Long
}

func assertHelpPhrases(t *testing.T, cmd *cobra.Command, text string, wantPhrases, wantAbsent []string) {
	t.Helper()

	if cmd == nil {
		t.Fatal("command is nil")
	}

	for _, phrase := range wantPhrases {
		if !strings.Contains(text, phrase) {
			t.Fatalf("command %q help must include %q, got %q", commandPathLabel(cmd), phrase, text)
		}
	}

	for _, phrase := range wantAbsent {
		if strings.Contains(text, phrase) {
			t.Fatalf("command %q help must not include %q, got %q", commandPathLabel(cmd), phrase, text)
		}
	}
}

func optionalCommandAtPath(t *testing.T, root *cobra.Command, path ...string) *cobra.Command {
	t.Helper()

	cmd, err := commandAtPath(root, path...)
	if err != nil {
		return nil
	}

	return cmd
}
