//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package sandboxworker

import (
	"errors"
	"net"
)

// validateWorkerPeerCredentials fails closed on Unix platforms where this
// package has no peer-credential adapter. Filesystem metadata alone cannot
// prove a peer identity because ACLs may grant access beyond mode bits.
func validateWorkerPeerCredentials(_ net.Conn, filesystemBoundaryProven bool) error {
	return validateWorkerPeerFilesystemFallback(filesystemBoundaryProven)
}

func workerPeerCredentials(net.Conn) (uint32, uint32, error) {
	return 0, 0, errors.New("worker peer identity is unavailable")
}
