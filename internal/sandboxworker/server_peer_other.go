//go:build !linux

package sandboxworker

import (
	"errors"
	"net"
)

func validateWorkerPeerCredentials(net.Conn) error {
	return errors.New("worker peer identity is unavailable")
}
