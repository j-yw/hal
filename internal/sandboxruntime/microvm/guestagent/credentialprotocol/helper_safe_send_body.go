package credentialprotocol

import (
	"encoding/binary"
	"errors"
)

const (
	helperReadyBodyBytes         = 0
	helperDigestAckBodyBytes     = 32
	helperSSHAcceptedFDBodyBytes = 43
)

var (
	ErrHelperSafeSendBodyLength = errors.New("credential protocol safe send body length is invalid")
	ErrHelperSafeSendBodyValue  = errors.New("credential protocol safe send body value is invalid")
)

func HelperReadyBodyEncodedLength() uint32         { return helperReadyBodyBytes }
func HelperBootstrapAckBodyEncodedLength() uint32  { return helperDigestAckBodyBytes }
func HelperAgentHelloAckBodyEncodedLength() uint32 { return helperDigestAckBodyBytes }
func HelperSSHAcceptedFDBodyEncodedLength() uint32 { return helperSSHAcceptedFDBodyBytes }

func EncodeHelperReadyBodyTo(dst []byte) error {
	if len(dst) != helperReadyBodyBytes {
		return ErrHelperSafeSendBodyLength
	}
	return nil
}

func EncodeHelperBootstrapAckBodyTo(dst []byte, bootstrapSHA256 [32]byte) error {
	return encodeHelperDigestAckBodyTo(dst, bootstrapSHA256)
}

func EncodeHelperAgentHelloAckBodyTo(dst []byte, bootstrapSHA256 [32]byte) error {
	return encodeHelperDigestAckBodyTo(dst, bootstrapSHA256)
}

func encodeHelperDigestAckBodyTo(dst []byte, digest [32]byte) error {
	if digest == ([32]byte{}) {
		return ErrHelperSafeSendBodyValue
	}
	if len(dst) != helperDigestAckBodyBytes {
		return ErrHelperSafeSendBodyLength
	}
	copy(dst, digest[:])
	return nil
}

func EncodeHelperSSHAcceptedFDBodyTo(dst []byte, revision uint64, bindingIndex uint16, connectionOrdinal uint8, relayCapabilitySHA256 [32]byte) error {
	if revision == 0 || bindingIndex >= MaxHelperBindings || connectionOrdinal == 0 || connectionOrdinal > SSHAgentRelayMaxLifetimeConnections || relayCapabilitySHA256 == ([32]byte{}) {
		return ErrHelperSafeSendBodyValue
	}
	if len(dst) != helperSSHAcceptedFDBodyBytes {
		return ErrHelperSafeSendBodyLength
	}
	binary.BigEndian.PutUint64(dst[:8], revision)
	binary.BigEndian.PutUint16(dst[8:10], bindingIndex)
	dst[10] = connectionOrdinal
	copy(dst[11:], relayCapabilitySHA256[:])
	return nil
}
