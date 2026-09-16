//go:build linux

package firecrackerhost

import (
	"context"
	"time"

	"golang.org/x/sys/unix"
)

// The production client hardwires unix.Recvmsg. The private syscall-shaped
// argument permits observation of real interruption and bounded fault tests,
// without storing a hook or changing the shared receiver's policy.
func receiveJailerRecoveryClientReply(ctx context.Context, fd int, receive func(int, []byte, []byte, int) (int, int, int, unix.Sockaddr, error)) (result l8RuntimeOwnerReceivedPacketV1, resultErr error) {
	started := time.Now()
	if ctx == nil || ctx.Err() != nil || receive == nil {
		return result, errL8RuntimeOwnerProtocol
	}
	original, err := unix.GetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO)
	if err != nil || original.Sec < 0 || original.Usec < 0 || original.Usec >= 1_000_000 {
		return result, errL8RuntimeOwnerProtocol
	}
	budget := time.Duration(original.Sec)*time.Second + time.Duration(original.Usec)*time.Microsecond
	// The legacy client installs a finite budget before authentication. Reject
	// unset or overflowing options rather than inventing an unbounded policy.
	if budget <= 0 || int64(budget/time.Second) != int64(original.Sec) {
		return result, errL8RuntimeOwnerProtocol
	}
	deadline := started.Add(budget)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(deadline) {
		deadline = callerDeadline
	}
	defer func() {
		// Never change the send budget. Every later exchange gets the exact
		// original receive option, not this operation's remaining interval.
		if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, original) != nil ||
			ctx.Err() != nil || !time.Now().Before(deadline) {
			closeL8RuntimeOwnerFiles(result.Files)
			result = l8RuntimeOwnerReceivedPacketV1{}
			resultErr = errL8RuntimeOwnerProtocol
		}
	}()
	buf := make([]byte, l8RuntimeOwnerPacketLimit)
	oob := make([]byte, unix.CmsgSpace(4*4))
	for {
		remaining := time.Until(deadline)
		if ctx.Err() != nil || remaining < time.Microsecond {
			return l8RuntimeOwnerReceivedPacketV1{}, errL8RuntimeOwnerProtocol
		}
		value := unix.NsecToTimeval(remaining.Nanoseconds())
		if unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &value) != nil ||
			ctx.Err() != nil || !time.Now().Before(deadline) {
			return l8RuntimeOwnerReceivedPacketV1{}, errL8RuntimeOwnerProtocol
		}
		clear(buf)
		clear(oob)
		n, oobn, flags, _, receiveErr := receive(fd, buf, oob, unix.MSG_CMSG_CLOEXEC)
		ancillary := false
		for _, value := range oob {
			ancillary = ancillary || value != 0
		}
		if receiveErr != nil || n < 0 || n > len(buf) || oobn < 0 || oobn > len(oob) ||
			oobn > 0 && oobn < unix.CmsgLen(0) || oobn == 0 && ancillary {
			// Reuse the existing complete-prefix disposal routine, including
			// error-plus-rights and impossible stale-buffer observations.
			closeMinimalJailerAncillary(oob)
			if receiveErr == unix.EINTR && (n == -1 || n == 0) && oobn == 0 && !ancillary && flags == 0 {
				continue // The loop retains the original deadline and caller.
			}
			return l8RuntimeOwnerReceivedPacketV1{}, errL8RuntimeOwnerProtocol
		}
		if _, err := unix.ParseSocketControlMessage(oob[:oobn]); err != nil {
			closeMinimalJailerAncillary(oob)
			return l8RuntimeOwnerReceivedPacketV1{}, errL8RuntimeOwnerProtocol
		}
		return decodeL8RuntimeOwnerReceive(buf, oob[:oobn], n, flags, nil)
	}
}
