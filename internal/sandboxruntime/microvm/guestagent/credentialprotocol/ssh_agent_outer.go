package credentialprotocol

import (
	"encoding/binary"
	"errors"
)

const (
	// SSHAgentFrameHeaderBytes is the exact outer payload-length prefix size.
	SSHAgentFrameHeaderBytes = 4
	// SSHAgentMinPayloadBytes is the minimum outer payload size, including type.
	SSHAgentMinPayloadBytes = 1
	// SSHAgentMaxPayloadBytes is the fixed 256-KiB outer payload limit.
	SSHAgentMaxPayloadBytes = 256 * 1024
	// SSHAgentMaxFrameBytes includes the header and maximum payload.
	SSHAgentMaxFrameBytes = SSHAgentFrameHeaderBytes + SSHAgentMaxPayloadBytes
)

var (
	ErrSSHAgentFrameHeader        = errors.New("credential protocol SSH-agent frame header is invalid")
	ErrSSHAgentPayloadLength      = errors.New("credential protocol SSH-agent payload length is invalid")
	ErrSSHAgentFrameTruncated     = errors.New("credential protocol SSH-agent frame is truncated")
	ErrSSHAgentFrameTrailingData  = errors.New("credential protocol SSH-agent frame has trailing data")
	ErrSSHAgentMessageType        = errors.New("credential protocol SSH-agent message type is unknown")
	ErrSSHAgentMessageBody        = errors.New("credential protocol SSH-agent message body is invalid")
	ErrSSHAgentKeyAlgorithm       = errors.New("credential protocol SSH-agent key algorithm is unknown")
	ErrSSHAgentSignatureAlgorithm = errors.New("credential protocol SSH-agent signature algorithm is unknown")
	ErrSSHAgentFlags              = errors.New("credential protocol SSH-agent flags are invalid")
	ErrSSHAgentSignaturePolicy    = errors.New("credential protocol SSH-agent signature policy does not match")
)

// SSHAgentMessageType is the closed one-byte request and response catalog.
type SSHAgentMessageType uint8

const (
	SSHAgentMessageFailure           SSHAgentMessageType = 5
	SSHAgentMessageRequestIdentities SSHAgentMessageType = 11
	SSHAgentMessageIdentitiesAnswer  SSHAgentMessageType = 12
	SSHAgentMessageSignRequest       SSHAgentMessageType = 13
	SSHAgentMessageSignResponse      SSHAgentMessageType = 14
)

// ValidateSSHAgentMessageType rejects protocol-v1, mutation, extension, and
// every other operation outside the L8 request/response catalog.
func ValidateSSHAgentMessageType(messageType SSHAgentMessageType) error {
	switch messageType {
	case SSHAgentMessageFailure,
		SSHAgentMessageRequestIdentities,
		SSHAgentMessageIdentitiesAnswer,
		SSHAgentMessageSignRequest,
		SSHAgentMessageSignResponse:
		return nil
	default:
		return ErrSSHAgentMessageType
	}
}

// String returns a safe catalog name and never renders an unknown wire value.
func (messageType SSHAgentMessageType) String() string {
	switch messageType {
	case SSHAgentMessageFailure:
		return "failure"
	case SSHAgentMessageRequestIdentities:
		return "request_identities"
	case SSHAgentMessageIdentitiesAnswer:
		return "identities_answer"
	case SSHAgentMessageSignRequest:
		return "sign_request"
	case SSHAgentMessageSignResponse:
		return "sign_response"
	default:
		return "unknown"
	}
}

// SSHAgentMessageClass distinguishes client requests from relay responses.
// It is string-backed because only message-type bytes are protocol numbers.
type SSHAgentMessageClass string

const (
	SSHAgentMessageClassUnknown       SSHAgentMessageClass = ""
	SSHAgentMessageClassClientRequest SSHAgentMessageClass = "client_request"
	SSHAgentMessageClassResponse      SSHAgentMessageClass = "response"
)

// String returns a safe class name and never renders a noncatalog value.
func (class SSHAgentMessageClass) String() string {
	switch class {
	case SSHAgentMessageClassClientRequest:
		return "client_request"
	case SSHAgentMessageClassResponse:
		return "response"
	default:
		return "unknown"
	}
}

// GoString keeps Go-syntax formatting on the same closed safe catalog.
func (class SSHAgentMessageClass) GoString() string {
	return class.String()
}

// ClassifySSHAgentMessageType validates and classifies one closed type.
func ClassifySSHAgentMessageType(messageType SSHAgentMessageType) (SSHAgentMessageClass, error) {
	switch messageType {
	case SSHAgentMessageRequestIdentities, SSHAgentMessageSignRequest:
		return SSHAgentMessageClassClientRequest, nil
	case SSHAgentMessageFailure, SSHAgentMessageIdentitiesAnswer, SSHAgentMessageSignResponse:
		return SSHAgentMessageClassResponse, nil
	default:
		return SSHAgentMessageClassUnknown, ErrSSHAgentMessageType
	}
}

// SSHAgentOuterFrameMetadata is safe structural metadata. It does not retain
// or expose the source frame or any message body.
type SSHAgentOuterFrameMetadata struct {
	PayloadLength uint32
	MessageType   SSHAgentMessageType
	Class         SSHAgentMessageClass
}

// ValidateSSHAgentOuterFrame validates one complete outer frame without
// allocating or copying its body. Nested message parsing remains a later codec
// responsibility. Bodyless failure and identities-request messages must have
// exactly their one-byte type payload.
func ValidateSSHAgentOuterFrame(frame []byte) (SSHAgentOuterFrameMetadata, error) {
	if len(frame) < SSHAgentFrameHeaderBytes {
		return SSHAgentOuterFrameMetadata{}, ErrSSHAgentFrameHeader
	}
	payloadLength := binary.BigEndian.Uint32(frame[:SSHAgentFrameHeaderBytes])
	if payloadLength < SSHAgentMinPayloadBytes || payloadLength > SSHAgentMaxPayloadBytes {
		return SSHAgentOuterFrameMetadata{}, ErrSSHAgentPayloadLength
	}
	completeLength := SSHAgentFrameHeaderBytes + int(payloadLength)
	if len(frame) < completeLength {
		return SSHAgentOuterFrameMetadata{}, ErrSSHAgentFrameTruncated
	}
	if len(frame) > completeLength {
		return SSHAgentOuterFrameMetadata{}, ErrSSHAgentFrameTrailingData
	}

	messageType := SSHAgentMessageType(frame[SSHAgentFrameHeaderBytes])
	class, err := ClassifySSHAgentMessageType(messageType)
	if err != nil {
		return SSHAgentOuterFrameMetadata{}, err
	}
	if payloadLength != 1 && (messageType == SSHAgentMessageRequestIdentities || messageType == SSHAgentMessageFailure) {
		return SSHAgentOuterFrameMetadata{}, ErrSSHAgentMessageBody
	}
	return SSHAgentOuterFrameMetadata{
		PayloadLength: payloadLength,
		MessageType:   messageType,
		Class:         class,
	}, nil
}

// EncodeSSHAgentFrameHeader encodes only the canonical four-byte outer header.
// It deliberately has no payload/body encoding counterpart.
func EncodeSSHAgentFrameHeader(payloadLength uint32) ([SSHAgentFrameHeaderBytes]byte, error) {
	if payloadLength < SSHAgentMinPayloadBytes || payloadLength > SSHAgentMaxPayloadBytes {
		return [SSHAgentFrameHeaderBytes]byte{}, ErrSSHAgentPayloadLength
	}
	var header [SSHAgentFrameHeaderBytes]byte
	binary.BigEndian.PutUint32(header[:], payloadLength)
	return header, nil
}

// SSHAgentKeyAlgorithm is the closed L8 public-key algorithm catalog.
type SSHAgentKeyAlgorithm string

const (
	SSHAgentKeyAlgorithmED25519       SSHAgentKeyAlgorithm = "ssh-ed25519"
	SSHAgentKeyAlgorithmECDSANISTP256 SSHAgentKeyAlgorithm = "ecdsa-sha2-nistp256"
	SSHAgentKeyAlgorithmECDSANISTP384 SSHAgentKeyAlgorithm = "ecdsa-sha2-nistp384"
	SSHAgentKeyAlgorithmECDSANISTP521 SSHAgentKeyAlgorithm = "ecdsa-sha2-nistp521"
	SSHAgentKeyAlgorithmRSA           SSHAgentKeyAlgorithm = "ssh-rsa"
)

// ValidateSSHAgentKeyAlgorithm accepts only the exact L8 key catalog.
func ValidateSSHAgentKeyAlgorithm(algorithm SSHAgentKeyAlgorithm) error {
	switch algorithm {
	case SSHAgentKeyAlgorithmED25519,
		SSHAgentKeyAlgorithmECDSANISTP256,
		SSHAgentKeyAlgorithmECDSANISTP384,
		SSHAgentKeyAlgorithmECDSANISTP521,
		SSHAgentKeyAlgorithmRSA:
		return nil
	default:
		return ErrSSHAgentKeyAlgorithm
	}
}

// String returns the exact safe catalog value or "unknown".
func (algorithm SSHAgentKeyAlgorithm) String() string {
	if ValidateSSHAgentKeyAlgorithm(algorithm) != nil {
		return "unknown"
	}
	return string(algorithm)
}

// GoString keeps Go-syntax formatting on the same closed safe catalog.
func (algorithm SSHAgentKeyAlgorithm) GoString() string {
	return algorithm.String()
}

// SSHAgentSignatureAlgorithm is the closed L8 signature algorithm catalog.
type SSHAgentSignatureAlgorithm string

const (
	SSHAgentSignatureAlgorithmED25519       SSHAgentSignatureAlgorithm = "ssh-ed25519"
	SSHAgentSignatureAlgorithmECDSANISTP256 SSHAgentSignatureAlgorithm = "ecdsa-sha2-nistp256"
	SSHAgentSignatureAlgorithmECDSANISTP384 SSHAgentSignatureAlgorithm = "ecdsa-sha2-nistp384"
	SSHAgentSignatureAlgorithmECDSANISTP521 SSHAgentSignatureAlgorithm = "ecdsa-sha2-nistp521"
	SSHAgentSignatureAlgorithmRSASHA256     SSHAgentSignatureAlgorithm = "rsa-sha2-256"
	SSHAgentSignatureAlgorithmRSASHA512     SSHAgentSignatureAlgorithm = "rsa-sha2-512"
)

// ValidateSSHAgentSignatureAlgorithm accepts only the exact L8 signature
// catalog. Legacy SHA-1 ssh-rsa is intentionally absent.
func ValidateSSHAgentSignatureAlgorithm(algorithm SSHAgentSignatureAlgorithm) error {
	switch algorithm {
	case SSHAgentSignatureAlgorithmED25519,
		SSHAgentSignatureAlgorithmECDSANISTP256,
		SSHAgentSignatureAlgorithmECDSANISTP384,
		SSHAgentSignatureAlgorithmECDSANISTP521,
		SSHAgentSignatureAlgorithmRSASHA256,
		SSHAgentSignatureAlgorithmRSASHA512:
		return nil
	default:
		return ErrSSHAgentSignatureAlgorithm
	}
}

// String returns the exact safe catalog value or "unknown".
func (algorithm SSHAgentSignatureAlgorithm) String() string {
	if ValidateSSHAgentSignatureAlgorithm(algorithm) != nil {
		return "unknown"
	}
	return string(algorithm)
}

// GoString keeps Go-syntax formatting on the same closed safe catalog.
func (algorithm SSHAgentSignatureAlgorithm) GoString() string {
	return algorithm.String()
}

// SSHAgentRSAFlags is the exact uint32 sign-request flags field.
type SSHAgentRSAFlags uint32

const (
	SSHAgentRSAFlagSHA256 SSHAgentRSAFlags = 2
	SSHAgentRSAFlagSHA512 SSHAgentRSAFlags = 4
)

// ValidateSSHAgentRequestFlags enforces zero flags for non-RSA keys and one
// exact SHA-2 flag for RSA. Zero, combined, SHA-1, and unknown RSA flags fail.
func ValidateSSHAgentRequestFlags(key SSHAgentKeyAlgorithm, flags SSHAgentRSAFlags) error {
	if err := ValidateSSHAgentKeyAlgorithm(key); err != nil {
		return err
	}
	if key == SSHAgentKeyAlgorithmRSA {
		if flags == SSHAgentRSAFlagSHA256 || flags == SSHAgentRSAFlagSHA512 {
			return nil
		}
		return ErrSSHAgentFlags
	}
	if flags != 0 {
		return ErrSSHAgentFlags
	}
	return nil
}

// ValidateSSHAgentSignPolicy requires the response signature algorithm to
// match the admitted key algorithm and exact request flags.
func ValidateSSHAgentSignPolicy(key SSHAgentKeyAlgorithm, flags SSHAgentRSAFlags, signature SSHAgentSignatureAlgorithm) error {
	if err := ValidateSSHAgentKeyAlgorithm(key); err != nil {
		return err
	}
	if err := ValidateSSHAgentSignatureAlgorithm(signature); err != nil {
		return err
	}
	if err := ValidateSSHAgentRequestFlags(key, flags); err != nil {
		return err
	}

	matches := key == SSHAgentKeyAlgorithmED25519 && signature == SSHAgentSignatureAlgorithmED25519 ||
		key == SSHAgentKeyAlgorithmECDSANISTP256 && signature == SSHAgentSignatureAlgorithmECDSANISTP256 ||
		key == SSHAgentKeyAlgorithmECDSANISTP384 && signature == SSHAgentSignatureAlgorithmECDSANISTP384 ||
		key == SSHAgentKeyAlgorithmECDSANISTP521 && signature == SSHAgentSignatureAlgorithmECDSANISTP521 ||
		key == SSHAgentKeyAlgorithmRSA && flags == SSHAgentRSAFlagSHA256 && signature == SSHAgentSignatureAlgorithmRSASHA256 ||
		key == SSHAgentKeyAlgorithmRSA && flags == SSHAgentRSAFlagSHA512 && signature == SSHAgentSignatureAlgorithmRSASHA512
	if !matches {
		return ErrSSHAgentSignaturePolicy
	}
	return nil
}
