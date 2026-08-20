//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package sandboxworker

import (
	"errors"
	"net"
)

func validateWorkerPeerCredentials(net.Conn, bool) error {
	return errors.New("worker peer identity is unavailable")
}

func workerPeerCredentials(net.Conn) (uint32, uint32, error) {
	return 0, 0, errors.New("worker peer identity is unavailable")
}
