package main

import (
	"strings"

	"github.com/spf13/cobra"
)

// portableSandboxdDefaults changes documentation display metadata only. Runtime
// flag values and explicit selections remain intact, including after errors.
func portableSandboxdDefaults(root *cobra.Command) func() {
	for _, command := range root.Commands() {
		if command.Name() != "sandboxd" {
			continue
		}
		var restore []func()
		for _, display := range []struct{ name, value string }{
			{"socket", "RUNTIME_DIR/hal-sandboxd.sock"},
			{"job-state-dir", "RUNTIME_DIR/jobs"},
		} {
			if flag := command.Flags().Lookup(display.name); flag != nil {
				original := flag.DefValue
				flag.DefValue = display.value
				restore = append(restore, func() { flag.DefValue = original })
			}
		}
		originalLong := command.Long
		command.Long = strings.TrimRight(originalLong, "\n") + `

RUNTIME_DIR below is a documentation placeholder, not a literal path. On
supported Unix platforms, it is selected at runtime from a validated private
XDG_RUNTIME_DIR/hal-sd location, or a private per-user directory under the system
temporary directory. Other platforms do not support the private runtime directory.`
		return func() {
			command.Long = originalLong
			for _, reset := range restore {
				reset()
			}
		}
	}
	return func() {}
}
