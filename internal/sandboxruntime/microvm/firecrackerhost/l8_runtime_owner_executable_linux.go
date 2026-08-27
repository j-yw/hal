//go:build linux

package firecrackerhost

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

func runPrivateL8RuntimeOwnerExecutable(arguments []string, file func(uintptr, string) *os.File) int {
	_ = launchPrivateL8RuntimeOwnerLinuxChild
	return runPrivateL8RuntimeOwnerExecutableWithOps(arguments, l8RuntimeOwnerExecutableOps{
		OpenFD: func(fd uintptr, role string) (int, error) {
			if file == nil {
				return -1, errL8RuntimeOwnerInvalid
			}
			opened := file(fd, role)
			if opened == nil {
				return -1, errL8RuntimeOwnerInvalid
			}
			return int(opened.Fd()), nil
		},
		CloseFD: func(fd int) error {
			if fd < 0 {
				return nil
			}
			if err := unix.Close(fd); err != nil {
				return errL8RuntimeOwnerInvalid
			}
			return nil
		},
		RunSupervisor: func([6]int) error {
			return errL8RuntimeOwnerInvalid
		},
		RunChildGate: func([6]int) error {
			return errL8RuntimeOwnerInvalid
		},
	})
}

func launchPrivateL8RuntimeOwnerLinuxChild(command *exec.Cmd) error {
	if command == nil {
		return errL8RuntimeOwnerInvalid
	}
	runtime.LockOSThread()
	command.SysProcAttr = &syscall.SysProcAttr{
		Pdeathsig: syscall.SIGKILL,
	}
	startErr := command.Start()
	var waitErr error
	if startErr == nil {
		waitErr = command.Wait()
	}
	runtime.UnlockOSThread()
	if startErr != nil || waitErr != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}
