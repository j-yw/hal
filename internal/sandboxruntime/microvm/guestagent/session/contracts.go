// Package session implements the data-only L8 guest-agent authenticated
// session wire contract. It deliberately owns no socket, listener, process,
// filesystem, command, or protocol-dispatch behavior.
package session

import (
	"crypto/ed25519"
	"io"
	"time"
)

const (
	HandshakeSuite1 uint16 = 0x0001
	WireVersion     byte   = 1

	GuestCID     uint32 = 3
	ControlPort  uint32 = 1025
	SSHRelayPort uint32 = 1026

	HandshakeDeadline                 = 5 * time.Second
	MaxGuestCredentialSessionLifetime = 35 * time.Minute
	MaxHandshakeInnerBytes            = 4096
	MaxControlPlaintextBytes          = 2 * 1024 * 1024
	MaxRelayPlaintextBytes            = 256 * 1024
	MaxPrivateBindingBytes            = 64 * 1024
	MaxPrivateAggregateBytes          = 1024 * 1024
	SecureRecordHeaderBytes           = 52
	GCMTagBytes                       = 16
	MaxControlWireBytes               = SecureRecordHeaderBytes + MaxControlPlaintextBytes + GCMTagBytes
	MaxRelayWireBytes                 = SecureRecordHeaderBytes + MaxRelayPlaintextBytes + GCMTagBytes
	MaxPreAuthConnections             = 3
	MaxEncryptedRecordsPerDirection   = uint64(1) << 32
)

type Channel uint8

const (
	ChannelControl  Channel = 1
	ChannelSSHRelay Channel = 2
)

func (c Channel) label() string {
	switch c {
	case ChannelControl:
		return "control"
	case ChannelSSHRelay:
		return "ssh-relay"
	default:
		return ""
	}
}

type Role uint8

const (
	RoleGuest Role = iota + 1
	RoleController
)

type Direction uint8

const (
	DirectionGuestToController Direction = iota + 1
	DirectionControllerToGuest
)

type FrameType byte

const (
	FrameTypeGuestFinished       FrameType = 0x01
	FrameTypeControllerFinished  FrameType = 0x02
	FrameTypeControlRequest      FrameType = 0x10
	FrameTypeControlResponse     FrameType = 0x11
	FrameTypeControlEvent        FrameType = 0x12
	FrameTypeControlPrivate      FrameType = 0x13
	FrameTypeControlStream       FrameType = 0x14
	FrameTypeControlStreamCredit FrameType = 0x15
	FrameTypeRelayRequest        FrameType = 0x20
	FrameTypeRelayResponse       FrameType = 0x21
	FrameTypeCloseNotify         FrameType = 0x7f
)

// Identity is the exact authenticated runtime/session identity carried by a
// GuestHello. Relay-only generation fields are present only on channel 2.
type Identity struct {
	Channel                      Channel
	GuestBootNonce               [32]byte
	GuestCID                     uint32
	GuestPort                    uint32
	ControllerKeyGeneration      string
	RuntimeID                    string
	RuntimeGeneration            string
	FirecrackerProcessGeneration string
	VsockGeneration              string
	BootGeneration               string
	ImageGeneration              string
	ImageSHA256                  [32]byte
	JobGeneration                string
	ActivationGeneration         string
	RelayGeneration              string
}

type GuestHello struct {
	Suite             uint16
	Identity          Identity
	GuestX25519Public [32]byte
}

type ControllerAuth struct {
	Suite                  uint16
	Channel                Channel
	ControllerX25519Public [32]byte
	Signature              [ed25519.SignatureSize]byte
}

type Dependencies struct {
	Random io.Reader
	Now    func() time.Time
}

type GuestHandshakeConfig struct {
	Identity                  Identity
	PinnedControllerPublicKey ed25519.PublicKey
	Dependencies              Dependencies
}

type ControllerHandshakeConfig struct {
	ExpectedIdentity Identity
	SigningKey       ed25519.PrivateKey
	Dependencies     Dependencies
}

type RecordHeader struct {
	Type             FrameType
	Sequence         uint64
	CiphertextLength uint32
	SessionID        [32]byte
}

// PlaintextValidator performs the concrete payload semantic validation owned
// by a later codec before a receive counter is committed.
type PlaintextValidator func(FrameType, []byte) error

type LossReason uint8

const (
	LossReasonEOF LossReason = iota + 1
	LossReasonTimeout
	LossReasonProcessReplacement
	LossReasonSocketReplacement
	LossReasonGenerationDrift
	LossReasonAuthenticationFailure
	LossReasonPreAuthExhausted
)

type LossEvent struct {
	Reason         LossReason
	JobGenerations []string
}

type GateHooks struct {
	NotifyLoss func(LossEvent)
	RevokeJob  func(string)
}
