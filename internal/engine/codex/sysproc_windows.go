//go:build windows

package codex

import (
	"os/exec"
	"syscall"
)

// newSysProcAttr returns SysProcAttr for Windows (no Setsid equivalent).
func newSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{}
}

// setupProcessCleanup is a no-op on Windows.
func setupProcessCleanup(cmd *exec.Cmd) {}
