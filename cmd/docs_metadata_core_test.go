package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCoreCommandsHaveCompleteMetadata(t *testing.T) {
	// Not parallel: walks shared global Root() command tree

	root := Root()
	tests := []struct {
		name            string
		path            []string
		exampleContains string
	}{
		{
			name:            "root command",
			path:            nil,
			exampleContains: "hal init",
		},
		{
			name:            "run command",
			path:            []string{"run"},
			exampleContains: "hal run",
		},
		{
			name:            "auto command",
			path:            []string{"auto"},
			exampleContains: "hal auto",
		},
		{
			name:            "review command",
			path:            []string{"review"},
			exampleContains: "hal review",
		},
		{
			name:            "report command",
			path:            []string{"report"},
			exampleContains: "hal report",
		},
		{
			name:            "explode command",
			path:            []string{"explode"},
			exampleContains: "hal explode",
		},
		{
			name:            "analyze command",
			path:            []string{"analyze"},
			exampleContains: "hal analyze",
		},
		{
			name:            "plan command",
			path:            []string{"plan"},
			exampleContains: "hal plan",
		},
		{
			name:            "init command",
			path:            []string{"init"},
			exampleContains: "hal init",
		},
		{
			name:            "validate command",
			path:            []string{"validate"},
			exampleContains: "hal validate",
		},
		{
			name:            "status command",
			path:            []string{"status"},
			exampleContains: "hal status",
		},
		{
			name:            "doctor command",
			path:            []string{"doctor"},
			exampleContains: "hal doctor",
		},
		{
			name:            "cleanup command",
			path:            []string{"cleanup"},
			exampleContains: "hal cleanup",
		},
		{
			name:            "convert command",
			path:            []string{"convert"},
			exampleContains: "hal convert",
		},
		{
			name:            "continue command",
			path:            []string{"continue"},
			exampleContains: "hal continue",
		},
		{
			name:            "ci command",
			path:            []string{"ci"},
			exampleContains: "hal ci",
		},
		{
			name:            "version command",
			path:            []string{"version"},
			exampleContains: "hal version",
		},
		{
			name:            "repair command",
			path:            []string{"repair"},
			exampleContains: "hal repair",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := commandAtPath(root, tt.path...)
			if err != nil {
				t.Fatalf("failed to find command at path %v: %v", tt.path, err)
			}

			if !isCommandInMetadataScope(cmd) {
				t.Fatalf("command %q is unexpectedly out of metadata scope", commandPathLabel(cmd))
			}

			if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
				t.Fatalf("command %q is missing metadata fields: %s", commandPathLabel(cmd), strings.Join(missing, ", "))
			}

			if !strings.Contains(cmd.Example, tt.exampleContains) {
				t.Fatalf("command %q example must include %q, got %q", commandPathLabel(cmd), tt.exampleContains, cmd.Example)
			}
		})
	}
}

func commandAtPath(root *cobra.Command, path ...string) (*cobra.Command, error) {
	if root == nil {
		return nil, fmt.Errorf("root command is nil")
	}

	current := root
	for _, segment := range path {
		next := findDirectSubcommandByName(current, segment)
		if next == nil {
			return nil, fmt.Errorf("subcommand %q not found under %q", segment, commandPathLabel(current))
		}
		current = next
	}

	return current, nil
}

func findDirectSubcommandByName(parent *cobra.Command, name string) *cobra.Command {
	for _, child := range parent.Commands() {
		if child.Name() == name {
			return child
		}
	}

	return nil
}

func missingCommandMetadataFields(cmd *cobra.Command) []string {
	var missing []string

	if strings.TrimSpace(cmd.Use) == "" {
		missing = append(missing, "Use")
	}
	if strings.TrimSpace(cmd.Short) == "" {
		missing = append(missing, "Short")
	}
	if strings.TrimSpace(cmd.Long) == "" {
		missing = append(missing, "Long")
	}
	if strings.TrimSpace(cmd.Example) == "" {
		missing = append(missing, "Example")
	}

	return missing
}

func commandPathLabel(cmd *cobra.Command) string {
	if cmd == nil {
		return "<nil>"
	}

	path := strings.TrimSpace(cmd.CommandPath())
	if path == "" {
		return cmd.Name()
	}

	return path
}
