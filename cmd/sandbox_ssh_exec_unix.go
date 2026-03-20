//go:build unix

package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func execInteractiveSSH(cmd *exec.Cmd) error {
	binary, err := exec.LookPath(cmd.Path)
	if err != nil {
		return fmt.Errorf("finding SSH binary: %w", err)
	}

	env := cmd.Env
	if len(env) == 0 {
		env = os.Environ()
	}

	return syscall.Exec(binary, cmd.Args, env)
}
