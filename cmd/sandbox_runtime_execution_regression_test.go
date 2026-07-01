package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestSandboxRuntimeInspectionDoesNotBleedIntoExecutionCommands(t *testing.T) {
	root := Root()
	tests := []struct {
		name          string
		path          []string
		requiredFlags []string
	}{
		{
			name: "sandbox daemon",
			path: []string{"sandboxd"},
			requiredFlags: []string{
				"driver",
				"json",
				"max-concurrent",
				"podman",
				"socket",
				"worker-id",
			},
		},
		{
			name: "run sandbox execution",
			path: []string{"run"},
			requiredFlags: []string{
				"base",
				"engine",
				"json",
				"sandbox",
				"sandbox-name",
			},
		},
		{
			name: "auto sandbox execution",
			path: []string{"auto"},
			requiredFlags: []string{
				"base",
				"engine",
				"json",
				"sandbox",
				"sandbox-name",
			},
		},
		{
			name: "factory run sandbox execution",
			path: []string{"factory", "run"},
			requiredFlags: []string{
				"base",
				"json",
				"sandbox",
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			cmd, err := commandAtPath(root, tt.path...)
			if err != nil {
				t.Fatalf("command path %q missing: %v", strings.Join(tt.path, " "), err)
			}
			if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
				t.Fatalf("command %q missing metadata fields: %v", commandPathLabel(cmd), missing)
			}

			for _, flagName := range tt.requiredFlags {
				if cmd.Flags().Lookup(flagName) == nil {
					t.Fatalf("command %q missing existing --%s flag", commandPathLabel(cmd), flagName)
				}
			}

			assertCommandHasNoRuntimeInspectionSurface(t, cmd)
		})
	}
}

func assertCommandHasNoRuntimeInspectionSurface(t *testing.T, cmd *cobra.Command) {
	t.Helper()

	for _, flagName := range []string{"live"} {
		if cmd.Flags().Lookup(flagName) != nil {
			t.Fatalf("command %q unexpectedly exposes runtime inspection --%s flag", commandPathLabel(cmd), flagName)
		}
	}

	for _, childName := range []string{"runtime", "list", "status"} {
		if child := findDirectSubcommandByName(cmd, childName); child != nil {
			t.Fatalf("command %q unexpectedly has runtime inspection child %q", commandPathLabel(cmd), childName)
		}
	}

	for _, field := range []struct {
		name  string
		value string
	}{
		{name: "Long", value: cmd.Long},
		{name: "Example", value: cmd.Example},
	} {
		if strings.Contains(field.value, "hal sandbox runtime") {
			t.Fatalf("command %q %s unexpectedly references runtime inspection: %q", commandPathLabel(cmd), field.name, field.value)
		}
	}
}
