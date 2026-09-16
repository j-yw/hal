//go:build linux

package firecrackerhost

import (
	"net"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

func validMinimalWorkEndpoint(file *os.File) bool {
	if file == nil {
		return false
	}
	fd := int(file.Fd())
	flags, flagErr := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	kind, kindErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	listening, listenErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	return flagErr == nil && flags&unix.FD_CLOEXEC != 0 && kindErr == nil && kind == unix.SOCK_STREAM &&
		listenErr == nil && listening == 0 && minimalWorkAnonymousAddress(fd, unix.SYS_GETSOCKNAME) && minimalWorkAnonymousAddress(fd, unix.SYS_GETPEERNAME)
}

// x/sys represents both an unnamed socket and an empty abstract address as
// "@". Require the actual kernel address extent (family only), not that lossy
// pathname projection. Both calls inspect only this already-owned endpoint.
func minimalWorkAnonymousAddress(fd int, operation uintptr) bool {
	var address unix.RawSockaddrUnix
	length := uint32(unix.SizeofSockaddrUnix)
	_, _, err := unix.Syscall(operation, uintptr(fd), uintptr(unsafe.Pointer(&address)), uintptr(unsafe.Pointer(&length)))
	return err == 0 && length == 2 && address.Family == unix.AF_UNIX
}

// File remains with its current owner. net.FileConn returns a separate owned
// pollable descriptor, and never transfers or closes this original alias.
func minimalWorkEndpointConn(file *os.File) (*net.UnixConn, error) {
	if !validMinimalWorkEndpoint(file) {
		return nil, errL8RuntimeOwnerInvalid
	}
	conn, err := net.FileConn(file)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, errL8RuntimeOwnerInvalid
	}
	return unixConn, nil
}

// Only the original producer's sole reader calls this after revision 2. All
// received rights belong here immediately, including malformed/error prefixes.
func receiveMinimalWorkReady(fd int) (minimalControlReadinessEventV1, *os.File, error) {
	var wire [minimalControlReadinessEventMax + 1]byte
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, flags, _, receiveErr := unix.Recvmsg(fd, wire[:], oob, unix.MSG_CMSG_CLOEXEC)
	if receiveErr != nil || n < 0 || n > len(wire) || oobn < 0 || oobn > len(oob) {
		closeMinimalJailerAncillary(oob)
		return minimalControlReadinessEventV1{}, nil, errL8RuntimeOwnerProtocol
	}
	if _, err := unix.ParseSocketControlMessage(oob[:oobn]); err != nil {
		closeMinimalJailerAncillary(oob)
		return minimalControlReadinessEventV1{}, nil, errL8RuntimeOwnerProtocol
	}
	files, filesErr := l8RuntimeOwnerFilesFromControl(oob[:oobn])
	event, err := decodeMinimalWorkReady(wire[:n])
	if filesErr != nil || err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(files) != 1 || !validMinimalWorkEndpoint(files[0]) {
		closeL8RuntimeOwnerFiles(files)
		return minimalControlReadinessEventV1{}, nil, errL8RuntimeOwnerProtocol
	}
	return event, files[0], nil
}
