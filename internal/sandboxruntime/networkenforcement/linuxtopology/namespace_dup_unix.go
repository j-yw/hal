//go:build unix

package linuxtopology

import (
	"os"
	"syscall"
)

func duplicateNamespaceFile(file *os.File) (*os.File, error) {
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), uintptr(syscall.F_DUPFD_CLOEXEC), uintptr(3))
	if errno != 0 {
		return nil, errno
	}
	return os.NewFile(fd, file.Name()), nil
}
