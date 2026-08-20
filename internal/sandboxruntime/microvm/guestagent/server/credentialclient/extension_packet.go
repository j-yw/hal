package credentialclient

import (
	"context"
	"crypto/subtle"
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var (
	ErrExtensionPacketType      = errors.New("credential client extension packet type is invalid")
	ErrExtensionPacketMetadata  = errors.New("credential client extension packet metadata is invalid")
	ErrExtensionRightRequired   = errors.New("credential client extension right capability is required")
	ErrExtensionPacketOwnership = errors.New("credential client extension packet ownership is invalid")
)

const (
	maxExtensionPacketBindings uint16 = 16
	maxSSHConnectionOrdinal    uint8  = 64
)

type extensionPacketMetadata struct {
	identityDigest   [32]byte
	revision         uint64
	bindingIndex     uint16
	ordinal          uint8
	capabilitySHA256 [32]byte
}

// ExtensionPacket is the authenticated, client-owned extension union. D2
// permits only the SSH accepted-connection packet and an opaque inspected
// rights capability; it never stores a numeric descriptor or generic body.
type ExtensionPacket struct {
	liveValue
	packetType credentialprotocol.PacketType
	metadata   extensionPacketMetadata
	ownership  *sshConnectionOwnership
}

// Type returns the already-authenticated closed packet type.
func (packet ExtensionPacket) Type() credentialprotocol.PacketType {
	return packet.packetType
}

// SSHAccepted returns the sole typed extension arm. The connection is a
// parent-owned transfer view and never the Transport-issued capability.
func (packet ExtensionPacket) SSHAccepted() (SSHAcceptedPacket, bool) {
	if packet.packetType != credentialprotocol.PacketTypeSSHAcceptedFD || packet.ownership == nil {
		return SSHAcceptedPacket{}, false
	}
	view := sshConnectionView{ownership: packet.ownership}
	return SSHAcceptedPacket{
		revision:         packet.metadata.revision,
		bindingIndex:     packet.metadata.bindingIndex,
		ordinal:          packet.metadata.ordinal,
		capabilitySHA256: packet.metadata.capabilitySHA256,
		connection:       view,
		ownership:        packet.ownership,
	}, true
}

func newExtensionPacket(
	packetType credentialprotocol.PacketType,
	metadata extensionPacketMetadata,
	capability SSHConnectionCapability,
) (ExtensionPacket, error) {
	capabilitySupplied := configuredDependency(capability)
	capabilityRetained := false
	if capabilitySupplied {
		defer func() {
			if !capabilityRetained {
				closeRejectedSSHCapability(capability)
			}
		}()
	}
	if err := credentialprotocol.ValidatePacketType(packetType); err != nil {
		return ExtensionPacket{}, err
	}
	if packetType != credentialprotocol.PacketTypeSSHAcceptedFD {
		return ExtensionPacket{}, ErrExtensionPacketType
	}
	if metadata.identityDigest == ([32]byte{}) ||
		metadata.revision == 0 ||
		metadata.bindingIndex >= maxExtensionPacketBindings ||
		metadata.ordinal == 0 || metadata.ordinal > maxSSHConnectionOrdinal ||
		metadata.capabilitySHA256 == ([32]byte{}) {
		return ExtensionPacket{}, ErrExtensionPacketMetadata
	}
	if !capabilitySupplied {
		return ExtensionPacket{}, ErrExtensionRightRequired
	}
	capabilityDigest, valid := safeSSHIssuerDigest(capability)
	if !valid || capabilityDigest == ([32]byte{}) || subtle.ConstantTimeCompare(capabilityDigest[:], metadata.capabilitySHA256[:]) != 1 {
		return ExtensionPacket{}, ErrExtensionPacketMetadata
	}
	packet := ExtensionPacket{
		packetType: packetType,
		metadata:   metadata,
		ownership:  newSSHConnectionOwnership(capabilityDigest, capability),
	}
	capabilityRetained = true
	return packet, nil
}

// commitExtensionPacketOwnership records the post-Handle(nil) transfer. It
// deliberately exposes neither the capability nor a public transfer API.
func commitExtensionPacketOwnership(packet ExtensionPacket) error {
	if packet.ownership == nil {
		return ErrExtensionPacketOwnership
	}
	packet.ownership.mu.Lock()
	defer packet.ownership.mu.Unlock()
	if packet.ownership.phase != sshConnectionClientOwned {
		return ErrExtensionPacketOwnership
	}
	packet.ownership.phase = sshConnectionTransferred
	packet.ownership.cond.Broadcast()
	return nil
}

// closeOwnedExtensionPacket closes a still-client-owned right exactly once and
// latches only a sanitized result for every alias.
func closeOwnedExtensionPacket(ctx context.Context, packet ExtensionPacket) error {
	if packet.ownership == nil {
		return ErrExtensionPacketOwnership
	}
	packet.ownership.mu.Lock()
	switch packet.ownership.phase {
	case sshConnectionClosed:
		err := packet.ownership.closeErr
		packet.ownership.mu.Unlock()
		return err
	case sshConnectionTransferred:
		packet.ownership.mu.Unlock()
		return ErrExtensionPacketOwnership
	case sshConnectionClosing:
		if !validSSHContext(ctx) || !waitSSHConnectionLocked(ctx, packet.ownership, func() bool {
			return packet.ownership.phase == sshConnectionClosed
		}) {
			packet.ownership.mu.Unlock()
			return ErrExtensionPacketOwnership
		}
		err := packet.ownership.closeErr
		packet.ownership.mu.Unlock()
		return err
	case sshConnectionClientOwned:
		if !validSSHContext(ctx) {
			packet.ownership.mu.Unlock()
			return ErrExtensionPacketOwnership
		}
		packet.ownership.phase = sshConnectionClosing
		packet.ownership.closeStarted = true
		packet.ownership.cond.Broadcast()
		capability := packet.ownership.issuer
		packet.ownership.mu.Unlock()
		closeErr := safeSSHIssuerClose(ctx, capability)
		if closeErr != nil {
			closeErr = ErrExtensionPacketOwnership
		}
		packet.ownership.mu.Lock()
		packet.ownership.issuer = nil
		packet.ownership.closeErr = closeErr
		packet.ownership.phase = sshConnectionClosed
		packet.ownership.cond.Broadcast()
		packet.ownership.mu.Unlock()
		return closeErr
	default:
		packet.ownership.mu.Unlock()
		return ErrExtensionPacketOwnership
	}
}

func closeRejectedSSHCapability(capability SSHConnectionCapability) {
	if !configuredDependency(capability) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), sshConnectionCleanupTimeout)
	defer cancel()
	_ = safeSSHIssuerClose(ctx, capability)
}
