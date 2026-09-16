//go:build linux

package firecrackerhost

import "context"

// Caller holds starter.mu on entry and return. This first selected extraction
// deliberately retains the old lock-held receive and five-second timeout so
// behavioral RED reaches the real I/O before interruption changes are made.
func (starter *jailerRecoveryStarter) awaitMinimalGateArmedLocked(ctx context.Context) error {
	gate := starter.minimalGate
	if ctx == nil || ctx.Err() != nil || gate == nil || !gate.matches(starter, gate.prep) ||
		!starter.started || starter.closed || starter.released || starter.gate == nil || !starter.observation.pidfdOwned {
		return errStrictJailerNamespaceStartFailed
	}
	if setL8RuntimeOwnerSocketTimeout(int(starter.gate.Fd()), l8RuntimeOwnerHandshakeTimeout) != nil {
		return errStrictJailerNamespaceStartFailed
	}
	armed, err := receiveL8RuntimeOwnerSeqpacket(int(starter.gate.Fd()))
	defer closeL8RuntimeOwnerFiles(armed.Files)
	if err != nil || ctx.Err() != nil || validateL8RuntimeOwnerPacketRole(armed.Packet, false, len(armed.Files)) != nil || armed.Packet.Opcode != l8RuntimeOwnerOpcodeChildArmed {
		return errStrictJailerNamespaceStartFailed
	}
	return nil
}
