package sandbox

import "strings"

func sshRemoteCommand(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, sshShellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func appendSSHRemoteCommand(cmdArgs []string, args []string) []string {
	if len(args) == 0 {
		return cmdArgs
	}
	return append(cmdArgs, sshRemoteCommand(args))
}

func sshShellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
