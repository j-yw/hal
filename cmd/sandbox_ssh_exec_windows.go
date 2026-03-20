//go:build windows

package cmd

import "os/exec"

func execInteractiveSSH(cmd *exec.Cmd) error {
	return cmd.Run()
}
