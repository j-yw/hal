//go:build windows

package verify

import (
	"os/exec"
	"syscall"
)

func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}

func setupProcessCleanup(cmd *exec.Cmd) {}
