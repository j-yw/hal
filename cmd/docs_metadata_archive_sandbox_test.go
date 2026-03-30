package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCommandFamiliesHaveCompleteMetadata(t *testing.T) {
	// Not parallel: walks shared global Root() command tree

	root := Root()
	if root == nil {
		t.Fatal("root command is nil")
	}

	tests := []struct {
		name     string
		family   string
		required bool
	}{
		{
			name:     "archive command family",
			family:   "archive",
			required: true,
		},
		{
			name:     "ci command family",
			family:   "ci",
			required: true,
		},
		{
			name:     "sandbox command family",
			family:   "sandbox",
			required: false,
		},
		{
			name:     "links command family",
			family:   "links",
			required: true,
		},
		{
			name:     "prd command family",
			family:   "prd",
			required: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			familyCmd := findDirectSubcommandByName(root, tt.family)
			if familyCmd == nil {
				if tt.required {
					t.Fatalf("required command family %q is missing from root command tree", tt.family)
				}
				t.Skipf("optional command family %q is not present in this command tree", tt.family)
			}

			for _, cmd := range collectInScopeFamilyCommands(familyCmd) {
				if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
					t.Fatalf("command %q is missing metadata fields: %s", commandPathLabel(cmd), strings.Join(missing, ", "))
				}

				commandPath := commandPathLabel(cmd)
				if !strings.Contains(cmd.Example, commandPath) {
					t.Fatalf("command %q example must include %q, got %q", commandPath, commandPath, cmd.Example)
				}
			}
		})
	}
}

func collectInScopeFamilyCommands(root *cobra.Command) []*cobra.Command {
	if root == nil {
		return nil
	}

	var inScope []*cobra.Command
	var walk func(*cobra.Command)

	walk = func(cmd *cobra.Command) {
		if cmd == nil {
			return
		}

		if isCommandInMetadataScope(cmd) {
			inScope = append(inScope, cmd)
		}

		for _, child := range cmd.Commands() {
			walk(child)
		}
	}

	walk(root)
	return inScope
}
