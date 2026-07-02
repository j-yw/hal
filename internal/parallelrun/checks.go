package parallelrun

import (
	"runtime"
	"strings"

	"github.com/jywlabs/hal/internal/integrator"
)

// ShellCheckCommands converts configured shell checks into integrator commands
// that run against the canonical tree after each worker cherry-pick.
func ShellCheckCommands(commands []string) []integrator.CheckCommand {
	checks := make([]integrator.CheckCommand, 0, len(commands))
	for _, command := range commands {
		command = strings.TrimSpace(command)
		if command == "" {
			continue
		}
		name, args := shellCheckCommand(command)
		checks = append(checks, integrator.CheckCommand{
			Name: name,
			Args: args,
		})
	}
	return checks
}

func shellCheckCommand(command string) (string, []string) {
	if runtime.GOOS == "windows" {
		return "cmd", []string{"/C", command}
	}
	return "sh", []string{"-c", command}
}
