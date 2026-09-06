//go:build linux

package firecrackerhost

import (
	"os"
	"syscall"
)

func processTerminationSignal() (os.Signal, error) {
	return syscall.SIGTERM, nil
}
