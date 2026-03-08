package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestCommandTreeHasCompleteMetadata(t *testing.T) {
	t.Parallel()

	root := Root()
	if root == nil {
		t.Fatal("root command is nil")
	}

	for _, cmd := range collectInScopeCommands(root) {
		if missing := missingCommandMetadataFields(cmd); len(missing) > 0 {
			t.Errorf("command %q is missing metadata fields: %s", commandPathLabel(cmd), strings.Join(missing, ", "))
		}
	}
}

func collectInScopeCommands(root *cobra.Command) []*cobra.Command {
	if root == nil {
		return nil
	}

	var commands []*cobra.Command
	var walk func(cmd *cobra.Command)

	walk = func(cmd *cobra.Command) {
		if cmd == nil {
			return
		}

		if isCommandInMetadataScope(cmd) {
			commands = append(commands, cmd)
		}

		for _, child := range cmd.Commands() {
			walk(child)
		}
	}

	walk(root)
	return commands
}
