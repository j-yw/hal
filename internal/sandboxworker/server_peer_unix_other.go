//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package sandboxworker

import "net"

// validateWorkerPeerCredentials uses the hardened filesystem boundary on Unix
// platforms where this package has no peer-credential adapter. The fallback is
// allowed only for ListenAndServe after it has proven a current-user-owned
// 0700 parent and created the 0600 socket itself. Direct Serve calls fail
// closed because they cannot provide that proof.
func validateWorkerPeerCredentials(_ net.Conn, filesystemBoundaryProven bool) error {
	return validateWorkerPeerFilesystemFallback(filesystemBoundaryProven)
}
