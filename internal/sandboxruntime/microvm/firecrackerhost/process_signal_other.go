//go:build !linux

package firecrackerhost

import (
	"errors"
	"os"
)

func processTerminationSignal() (os.Signal, error) {
	return nil, errors.New("Firecracker termination signal unsupported")
}
