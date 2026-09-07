//go:build linux

package firecrackerhost

import "golang.org/x/sys/unix"

// Per-selected-stream syscall operations, copied at attachment. Production uses
// the fixed unix operations; this seam does not supply decoded replies or proof.
type minimalJailerSocketOps struct {
	sendmsg func(int, []byte, []byte, unix.Sockaddr, int) error
	recvmsg func(int, []byte, []byte, int) (int, int, int, unix.Sockaddr, error)
}

// Compiling RED preserves the existing single-syscall behavior and cancellation
// order. Retry and retention of received Commit acknowledgments are not fixed.
func (stream *minimalJailerIO) exchangeOnce(packet l8RuntimeOwnerPacketV1) (l8RuntimeOwnerPacketV1, error) {
	if stream.ctx.Err() != nil {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
	}
	wire, err := encodeL8RuntimeOwnerPacket(packet)
	if err != nil || stream.ops.sendmsg(int(stream.file.Fd()), wire, nil, nil, 0) != nil {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
	}
	buf := make([]byte, l8RuntimeOwnerPacketLimit)
	oob := make([]byte, unix.CmsgSpace(4*4))
	n, oobn, flags, _, err := stream.ops.recvmsg(int(stream.file.Fd()), buf, oob, unix.MSG_CMSG_CLOEXEC)
	response, err := decodeL8RuntimeOwnerReceive(buf, oob[:oobn], n, flags, err)
	defer closeL8RuntimeOwnerFiles(response.Files)
	if err != nil || stream.ctx.Err() != nil || validateJailerRecoveryClientReply(packet, response) != nil {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerInvalid
	}
	return response.Packet, nil
}
