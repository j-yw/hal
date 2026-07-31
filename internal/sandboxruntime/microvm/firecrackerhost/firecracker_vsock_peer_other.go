//go:build !linux

package firecrackerhost

import (
	"errors"
	"net"
	"os"
)

type vsockSocketIdentity struct {
	socketDevice uint64
	socketInode  uint64
	parentDevice uint64
	parentInode  uint64
}

type privateStateDirIdentity struct {
	device uint64
	inode  uint64
	uid    uint32
}

func statPrivateFirecrackerStateDir(string) (privateStateDirIdentity, error) {
	return privateStateDirIdentity{}, errors.New("Firecracker state directory validation is unavailable")
}

func validatePrivateFirecrackerStateDir(string) error {
	return errors.New("Firecracker state directory validation is unavailable")
}

func removePinnedFirecrackerStateDir(string, privateStateDirIdentity) error {
	return errors.New("Firecracker state directory removal is unavailable")
}

func removePinnedFirecrackerStateEntry(string, string, privateStateDirIdentity) error {
	return errors.New("Firecracker state entry removal is unavailable")
}

func validateVsockSocketOwnership(string, os.FileInfo) error {
	return errors.New("Firecracker socket ownership unsupported")
}

func statVsockSocket(string) (vsockSocketIdentity, error) {
	return vsockSocketIdentity{}, errors.New("Firecracker socket identity unsupported")
}

func verifyVsockPeer(*net.UnixConn, int) error {
	return errors.New("Firecracker peer credentials unsupported")
}
