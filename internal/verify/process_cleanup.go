package verify

import (
	"errors"
	"os"
	"os/exec"
	"strconv"
)

func runProcessCleanupCommand(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

func killWindowsProcessTree(pid int, killParent func() error, run func(string, ...string) error) error {
	if run == nil {
		run = runProcessCleanupCommand
	}

	err := run("taskkill.exe", "/T", "/F", "/PID", strconv.Itoa(pid))
	if err == nil {
		return nil
	}
	if killParent == nil {
		return err
	}
	if killErr := killParent(); killErr != nil && !errors.Is(killErr, os.ErrProcessDone) {
		return errors.Join(err, killErr)
	}
	return err
}
