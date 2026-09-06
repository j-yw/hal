//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package sandboxworker

import (
	"errors"
	"net"
)

func validateWorkerPeerCredentials(net.Conn, bool) error {
	return errors.New("worker peer identity is unavailable")
}

func authenticateWorkerPeerCredentials(net.Conn, bool) (workerPeerIdentity, error) {
	return workerPeerIdentity{}, errors.New("worker peer identity is unavailable")
}
