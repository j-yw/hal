//go:build linux

package sandboxworker

import (
	"errors"
	"net"
	"os"
	"syscall"
)

func validateWorkerPeerCredentials(conn net.Conn, _ bool) error {
	_, err := authenticateWorkerPeerCredentials(conn, false)
	return err
}

func authenticateWorkerPeerCredentials(conn net.Conn, _ bool) (workerPeerIdentity, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return workerPeerIdentity{}, errors.New("worker peer identity is unavailable")
	}
	rawConn, err := unixConn.SyscallConn()
	if err != nil {
		return workerPeerIdentity{}, errors.New("worker peer identity is unavailable")
	}
	var credentialErr error
	var peer workerPeerIdentity
	if err := rawConn.Control(func(fd uintptr) {
		credentials, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil || credentials == nil {
			credentialErr = errors.New("worker peer identity is unavailable")
			return
		}
		peer.uid = credentials.Uid
		peer.gid = credentials.Gid
	}); err != nil {
		return workerPeerIdentity{}, errors.New("worker peer identity is unavailable")
	}
	if credentialErr != nil {
		return workerPeerIdentity{}, credentialErr
	}
	if err := validateWorkerPeerIdentity(peer, uint32(os.Geteuid()), uint32(os.Getegid())); err != nil {
		return workerPeerIdentity{}, err
	}
	return peer, nil
}
