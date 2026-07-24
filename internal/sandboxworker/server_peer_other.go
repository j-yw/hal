//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd

package sandboxworker

import (
	"errors"
	"net"
)

func validateWorkerPeerCredentials(net.Conn, bool) error {
	return errors.New("worker peer identity is unavailable")
}
