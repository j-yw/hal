package credentialclient

import (
	"context"
	"errors"
	"sync"

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

type extensionRightCapability interface {
	Close(context.Context) error
}

type extensionPacketMetadata struct {
	identityDigest   [32]byte
	revision         uint64
	bindingIndex     uint16
	ordinal          uint8
	capabilitySHA256 [32]byte
}

type extensionRightOwnership struct {
	mu         sync.Mutex
	state      extensionRightState
	capability extensionRightCapability
}

type extensionRightState uint8

const (
	extensionRightClientOwned extensionRightState = iota
	extensionRightTransferred
	extensionRightClosed
)

// ExtensionPacket is the authenticated, client-owned extension union. D2
// permits only the SSH accepted-connection packet and an opaque inspected
// rights capability; it never stores a numeric descriptor or generic body.
type ExtensionPacket struct {
	liveValue
	packetType credentialprotocol.PacketType
	metadata   extensionPacketMetadata
	ownership  *extensionRightOwnership
}

func newExtensionPacket(
	packetType credentialprotocol.PacketType,
	metadata extensionPacketMetadata,
	capability extensionRightCapability,
) (ExtensionPacket, error) {
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
	if !configuredDependency(capability) {
		return ExtensionPacket{}, ErrExtensionRightRequired
	}
	return ExtensionPacket{
		packetType: packetType,
		metadata:   metadata,
		ownership: &extensionRightOwnership{
			state:      extensionRightClientOwned,
			capability: capability,
		},
	}, nil
}

// commitExtensionPacketOwnership records the post-Handle(nil) transfer. It
// deliberately exposes neither the capability nor a public transfer API.
func commitExtensionPacketOwnership(packet ExtensionPacket) error {
	if packet.ownership == nil {
		return ErrExtensionPacketOwnership
	}
	packet.ownership.mu.Lock()
	defer packet.ownership.mu.Unlock()
	if packet.ownership.state != extensionRightClientOwned {
		return ErrExtensionPacketOwnership
	}
	packet.ownership.state = extensionRightTransferred
	return nil
}

// closeOwnedExtensionPacket closes a still-client-owned right exactly once.
// A close failure retains client ownership so bounded cleanup can retry.
func closeOwnedExtensionPacket(ctx context.Context, packet ExtensionPacket) error {
	if packet.ownership == nil {
		return ErrExtensionPacketOwnership
	}
	packet.ownership.mu.Lock()
	defer packet.ownership.mu.Unlock()
	switch packet.ownership.state {
	case extensionRightClosed:
		return nil
	case extensionRightTransferred:
		return ErrExtensionPacketOwnership
	case extensionRightClientOwned:
		if err := packet.ownership.capability.Close(ctx); err != nil {
			return err
		}
		packet.ownership.state = extensionRightClosed
		return nil
	default:
		return ErrExtensionPacketOwnership
	}
}
