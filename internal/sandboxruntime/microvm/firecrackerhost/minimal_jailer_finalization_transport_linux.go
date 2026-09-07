//go:build linux

package firecrackerhost

import (
	"time"

	"golang.org/x/sys/unix"
)

// Per-selected-stream syscall operations, copied at attachment. Production uses
// the fixed unix operations; this seam does not supply decoded replies or proof.
type minimalJailerSocketOps struct {
	sendmsg func(int, []byte, []byte, unix.Sockaddr, int) error
	recvmsg func(int, []byte, []byte, int) (int, int, int, unix.Sockaddr, error)
}

// A successful send is never repeated. Both directions share the one original
// exchange deadline; only EINTR with no receive data/rights can retry.
func (stream *minimalJailerIO) exchangeSelected(packet l8RuntimeOwnerPacketV1, deadline time.Time) (l8RuntimeOwnerPacketV1, error) {
	wire, err := encodeL8RuntimeOwnerPacket(packet)
	if err != nil {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
	}
	for {
		if stream.prepareSyscall(deadline) != nil {
			return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
		}
		err = stream.ops.sendmsg(int(stream.file.Fd()), wire, nil, nil, 0)
		if err == nil {
			break
		}
		if err != unix.EINTR {
			return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
		}
	}
	buf := make([]byte, l8RuntimeOwnerPacketLimit)
	oob := make([]byte, unix.CmsgSpace(4*4))
	for {
		if stream.prepareSyscall(deadline) != nil {
			return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
		}
		clear(oob) // No stale rights numbers can survive an interrupted attempt.
		n, oobn, flags, _, receiveErr := stream.ops.recvmsg(int(stream.file.Fd()), buf, oob, unix.MSG_CMSG_CLOEXEC)
		if oobn < 0 || oobn > len(oob) || oobn > 0 && oobn < unix.CmsgLen(0) {
			closeMinimalJailerAncillary(oob)
			return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
		}
		if oobn == 0 {
			for _, value := range oob {
				if value != 0 {
					closeMinimalJailerAncillary(oob)
					return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
				}
			}
		}
		if n < 0 || n > len(buf) || receiveErr != nil {
			closeMinimalJailerAncillary(oob)
			if receiveErr == unix.EINTR && n <= 0 && oobn == 0 && flags == 0 {
				continue
			}
			return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
		}
		if _, err := unix.ParseSocketControlMessage(oob[:oobn]); err != nil {
			closeMinimalJailerAncillary(oob)
			return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
		}
		response, err := decodeL8RuntimeOwnerReceive(buf, oob[:oobn], n, flags, nil)
		defer closeL8RuntimeOwnerFiles(response.Files)
		if err != nil || validateJailerRecoveryClientReply(packet, response) != nil {
			return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
		}
		// A canonical reply remains an internal observation even if its caller
		// is now unavailable. Only the Commit consumer can retain its exact ACK.
		if !minimalJailerCallerCurrent(stream.ctx) || !time.Now().Before(deadline) {
			return response.Packet, errL8RuntimeOwnerInvalid
		}
		return response.Packet, nil
	}
}

func (stream *minimalJailerIO) prepareSyscall(deadline time.Time) error {
	if !minimalJailerCallerCurrent(stream.ctx) {
		return errL8RuntimeOwnerInvalid
	}
	remaining := time.Until(deadline)
	if remaining < time.Microsecond || setL8RuntimeOwnerSocketTimeout(int(stream.file.Fd()), remaining) != nil ||
		!minimalJailerCallerCurrent(stream.ctx) || !time.Now().Before(deadline) {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

// Rejected syscall observations cannot authorize a packet. Dispose every
// complete ancillary prefix even if an injected size is invalid or trailing
// buffer padding is not a control message; never guess an FD from malformed data.
func closeMinimalJailerAncillary(oob []byte) {
	for len(oob) >= unix.CmsgLen(0) {
		_, _, rest, err := unix.ParseOneSocketControlMessage(oob)
		if err != nil {
			return
		}
		files, _ := l8RuntimeOwnerFilesFromControl(oob[:len(oob)-len(rest)])
		closeL8RuntimeOwnerFiles(files)
		oob = rest
	}
}
