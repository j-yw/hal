//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package sandboxworker

import "net"

// validateWorkerPeerCredentials fails closed on Unix platforms where this
// package has no peer-credential adapter. Filesystem metadata alone cannot
// prove a peer identity because ACLs may grant access beyond mode bits.
func validateWorkerPeerCredentials(_ net.Conn, filesystemBoundaryProven bool) error {
	return validateWorkerPeerFilesystemFallback(filesystemBoundaryProven)
}
