//go:build linux

package credentialclient

import "syscall"

func revalidateVerifiedHelperStream(stream VerifiedHelperStream) error {
	conn, ok := stream.(syscall.Conn)
	if !ok || !configuredDependency(stream) {
		return ErrClientControlDependencyUnaccepted
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return ErrClientControlDependencyUnaccepted
	}
	if controlErr := raw.Control(func(uintptr) {}); controlErr != nil {
		return ErrClientControlDependencyUnaccepted
	}
	return nil
}
