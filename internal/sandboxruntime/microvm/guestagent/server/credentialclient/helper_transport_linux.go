//go:build linux

package credentialclient

import (
	"context"
	"errors"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

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

func sendHelperDatagramPlatform(ctx context.Context, stream VerifiedHelperStream, datagram []byte) error {
	conn, ok := stream.(syscall.Conn)
	if !ok || !configuredDependency(stream) {
		return sendHelperDatagramWrite(ctx, stream, datagram)
	}
	raw, err := conn.SyscallConn()
	if err != nil || raw == nil {
		return sendHelperDatagramWrite(ctx, stream, datagram)
	}
	var sendErr error
	var sent int
	controlErr := raw.Write(func(fd uintptr) bool {
		sendErr = unix.Sendmsg(int(fd), datagram, nil, nil, 0)
		if sendErr == unix.EINTR || errors.Is(sendErr, unix.EAGAIN) || errors.Is(sendErr, unix.EWOULDBLOCK) {
			return false
		}
		if sendErr == nil {
			sent = len(datagram)
		}
		return true
	})
	if controlErr != nil || sendErr != nil || sent != len(datagram) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errInvalidHelperSendPacket
	}
	return nil
}

func recvHelperDatagramPlatform(ctx context.Context, stream VerifiedHelperStream, dontWait bool) ([]byte, []int, bool, error) {
	conn, ok := stream.(syscall.Conn)
	if !ok || !configuredDependency(stream) {
		return recvHelperDatagramRead(ctx, stream, dontWait)
	}
	raw, err := conn.SyscallConn()
	if err != nil || raw == nil {
		return recvHelperDatagramRead(ctx, stream, dontWait)
	}

	flags := unix.MSG_CMSG_CLOEXEC
	if dontWait {
		flags |= unix.MSG_DONTWAIT
	}
	datagram := make([]byte, credentialprotocol.MaxHelperPacketDatagramBytes)
	oob := make([]byte, unix.CmsgSpace(4))
	var n, oobn, recvFlags int
	var recvErr error
	controlErr := raw.Read(func(fd uintptr) bool {
		n, oobn, recvFlags, _, recvErr = unix.Recvmsg(int(fd), datagram, oob, flags)
		if recvErr == unix.EINTR {
			return false
		}
		if !dontWait && (errors.Is(recvErr, unix.EAGAIN) || errors.Is(recvErr, unix.EWOULDBLOCK)) {
			return false
		}
		return true
	})
	if controlErr != nil {
		clear(datagram)
		clear(oob)
		if ctx.Err() != nil {
			return nil, nil, false, ctx.Err()
		}
		return nil, nil, false, errInvalidHelperPacket
	}
	if recvErr != nil {
		clear(datagram)
		clear(oob)
		if dontWait && (errors.Is(recvErr, unix.EAGAIN) || errors.Is(recvErr, unix.EWOULDBLOCK)) {
			return nil, nil, true, nil
		}
		if ctx.Err() != nil {
			return nil, nil, false, ctx.Err()
		}
		return nil, nil, false, errInvalidHelperPacket
	}

	rights, rightsErr := parseOneHelperRight(oob[:oobn])
	clear(oob)
	if rightsErr != nil || recvFlags&unix.MSG_TRUNC != 0 || recvFlags&unix.MSG_CTRUNC != 0 || n < credentialprotocol.HelperPacketHeaderSize {
		closeReceivedHelperRights(rights)
		clear(datagram)
		return nil, nil, false, errInvalidHelperPacket
	}
	received := append([]byte(nil), datagram[:n]...)
	clear(datagram)
	return received, rights, false, nil
}

func parseOneHelperRight(oob []byte) ([]int, error) {
	if len(oob) == 0 {
		return nil, nil
	}
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, errInvalidHelperPacket
	}
	all := make([]int, 0, 1)
	valid := len(messages) == 1
	for index := range messages {
		if messages[index].Header.Level != unix.SOL_SOCKET || messages[index].Header.Type != unix.SCM_RIGHTS {
			valid = false
			continue
		}
		parsed, parseErr := unix.ParseUnixRights(&messages[index])
		if parseErr != nil {
			valid = false
			continue
		}
		all = append(all, parsed...)
	}
	if !valid || len(all) > 1 {
		closeReceivedHelperRights(all)
		return nil, errInvalidHelperPacket
	}
	return all, nil
}

func closeReceivedHelperRights(descriptors []int) {
	for index, descriptor := range descriptors {
		if descriptor < 0 {
			continue
		}
		_ = unix.Close(descriptor)
		descriptors[index] = -1
	}
}

func newSSHAcceptedConnFromRight(conn int, digest [32]byte) SSHConnectionCapability {
	return newLinuxSSHAcceptedConn(conn, digest)
}

type linuxSSHAcceptedConn struct {
	liveValue
	mu     sync.Mutex
	conn   int
	digest [32]byte
	closed bool
}

func newLinuxSSHAcceptedConn(conn int, digest [32]byte) *linuxSSHAcceptedConn {
	return &linuxSSHAcceptedConn{conn: conn, digest: digest}
}

func (conn *linuxSSHAcceptedConn) SHA256() [32]byte {
	if conn == nil {
		return [32]byte{}
	}
	conn.mu.Lock()
	defer conn.mu.Unlock()
	return conn.digest
}

func (conn *linuxSSHAcceptedConn) Read(ctx context.Context, sink credentialmemory.CredentialSink) (SSHIOResult, error) {
	if conn == nil || ctx == nil || ctx.Err() != nil || !configuredDependency(sink) {
		return SSHIOResult{}, sshOwnershipError()
	}
	conn.mu.Lock()
	descriptor, digest, closed := conn.conn, conn.digest, conn.closed
	conn.mu.Unlock()
	if closed || descriptor < 0 || digest == ([32]byte{}) {
		return SSHIOResult{}, sshOwnershipError()
	}
	capacity := sink.MaxCredentialBytes()
	if capacity < 1 || capacity > credentialprotocol.SSHAgentMaxFrameBytes {
		return SSHIOResult{}, sshOwnershipError()
	}
	buf := make([]byte, capacity)
	n, err := unix.Read(descriptor, buf)
	if ctx.Err() != nil {
		clear(buf)
		return SSHIOResult{}, sshOwnershipError()
	}
	if err != nil {
		clear(buf)
		return SSHIOResult{}, sshOwnershipError()
	}
	if n == 0 {
		clear(buf)
		return NewSSHIOResult(0, true, false)
	}
	if writeErr := sink.WriteCredential(buf[:n]); writeErr != nil {
		clear(buf)
		return SSHIOResult{}, sshOwnershipError()
	}
	clear(buf)
	return NewSSHIOResult(uint64(n), false, n == capacity)
}

func (conn *linuxSSHAcceptedConn) Write(ctx context.Context, source credentialmemory.BorrowedView) (SSHIOResult, error) {
	if conn == nil || ctx == nil || ctx.Err() != nil || !configuredDependency(source) {
		return SSHIOResult{}, sshOwnershipError()
	}
	conn.mu.Lock()
	descriptor, closed := conn.conn, conn.closed
	conn.mu.Unlock()
	if closed || descriptor < 0 {
		return SSHIOResult{}, sshOwnershipError()
	}
	length := source.Len()
	if length < 1 || length > credentialprotocol.SSHAgentMaxFrameBytes {
		return SSHIOResult{}, sshOwnershipError()
	}
	sink := &linuxSSHAcceptedWriteSink{ctx: ctx, conn: descriptor, remaining: length}
	if err := source.WriteTo(ctx, sink); err != nil || sink.failed || sink.written != length || ctx.Err() != nil {
		return SSHIOResult{}, sshOwnershipError()
	}
	return NewSSHIOResult(uint64(length), false, false)
}

func (conn *linuxSSHAcceptedConn) Shutdown(ctx context.Context, direction SSHShutdownDirection) error {
	if conn == nil || ctx == nil || ctx.Err() != nil {
		return sshOwnershipError()
	}
	if err := ValidateSSHShutdownDirection(direction); err != nil {
		return err
	}
	how := unix.SHUT_RDWR
	switch direction {
	case SSHShutdownRead:
		how = unix.SHUT_RD
	case SSHShutdownWrite:
		how = unix.SHUT_WR
	}
	conn.mu.Lock()
	descriptor, closed := conn.conn, conn.closed
	conn.mu.Unlock()
	if closed || descriptor < 0 {
		return sshOwnershipError()
	}
	if err := unix.Shutdown(descriptor, how); err != nil {
		return sshOwnershipError()
	}
	return nil
}

func (conn *linuxSSHAcceptedConn) Close(context.Context) error {
	if conn == nil {
		return sshOwnershipError()
	}
	conn.mu.Lock()
	if conn.closed {
		conn.mu.Unlock()
		return nil
	}
	descriptor := conn.conn
	conn.conn = -1
	conn.closed = true
	conn.mu.Unlock()
	if descriptor < 0 {
		return nil
	}
	if err := unix.Close(descriptor); err != nil {
		return sshCleanupError()
	}
	return nil
}

type linuxSSHAcceptedWriteSink struct {
	ctx       context.Context
	conn      int
	remaining int
	written   int
	failed    bool
}

func (sink *linuxSSHAcceptedWriteSink) MaxCredentialBytes() int {
	if sink == nil || sink.failed {
		return 0
	}
	return sink.remaining
}

func (sink *linuxSSHAcceptedWriteSink) WriteCredential(value []byte) error {
	if sink == nil || sink.failed || sink.ctx.Err() != nil || len(value) > sink.remaining {
		if sink != nil {
			sink.failed = true
		}
		return sshOwnershipError()
	}
	wrote, err := unix.Write(sink.conn, value)
	if err != nil || wrote != len(value) {
		sink.failed = true
		return sshOwnershipError()
	}
	sink.remaining -= wrote
	sink.written += wrote
	return nil
}

var _ SSHConnectionCapability = (*linuxSSHAcceptedConn)(nil)
