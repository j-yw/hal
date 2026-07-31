//go:build unix

package linuxtopology

import (
	"os"
	"syscall"
)

func duplicateNamespaceFile(file *os.File) (*os.File, error) {
	fd, err := syscall.Dup(int(file.Fd()))
	if err != nil {
		return nil, err
	}
	syscall.CloseOnExec(fd)
	return os.NewFile(uintptr(fd), file.Name()), nil
}
