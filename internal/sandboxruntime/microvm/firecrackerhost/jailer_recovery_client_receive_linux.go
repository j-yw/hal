//go:build linux

package firecrackerhost

import (
	"context"

	"golang.org/x/sys/unix"
)

// The production client hardwires unix.Recvmsg. The private syscall-shaped
// argument permits observation of real interruption and bounded fault tests,
// without storing a hook or changing the shared receiver's policy.
func receiveJailerRecoveryClientReply(ctx context.Context, fd int, receive func(int, []byte, []byte, int) (int, int, int, unix.Sockaddr, error)) (l8RuntimeOwnerReceivedPacketV1, error) {
	buf := make([]byte, l8RuntimeOwnerPacketLimit)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, flags, _, err := receive(fd, buf, oob, unix.MSG_CMSG_CLOEXEC)
	return decodeL8RuntimeOwnerReceive(buf, oob[:oobn], n, flags, err)
}
