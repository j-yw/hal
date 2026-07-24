//go:build linux

package sandboxworker

import (
	"errors"
	"net"
	"os"
	"syscall"
)

func validateWorkerPeerCredentials(conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("worker peer identity is unavailable")
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return errors.New("worker peer identity is unavailable")
	}
	var credentialErr error
	var peerUID uint32
	if err := rawConn.Control(func(fd uintptr) {
		credentials, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil || credentials == nil {
			credentialErr = errors.New("worker peer identity is unavailable")
			return
		}
		peerUID = credentials.Uid
	}); err != nil {
		return errors.New("worker peer identity is unavailable")
	}
	if credentialErr != nil {
		return credentialErr
	}
	return validateWorkerPeerUID(peerUID, uint32(os.Geteuid()))
}
