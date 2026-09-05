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

func authenticateWorkerPeerCredentials(net.Conn, bool) (workerPeerIdentity, error) {
	return workerPeerIdentity{}, errors.New("worker peer identity is unavailable")
}
