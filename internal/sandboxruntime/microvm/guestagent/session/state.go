package session

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"sync"
	"time"
)

const frameAADLabel = "hal/l8/guest-session/frame-aad/v1\x00"

type State struct {
	mu               sync.Mutex
	role             Role
	channel          Channel
	material         sessionMaterial
	localFinished    [32]byte
	peerFinished     [32]byte
	nextSend         uint64
	nextReceive      uint64
	sentFinished     bool
	receivedFinished bool
	established      bool
	revoked          bool
	now              func() time.Time
	deadline         time.Time
	hardExpiry       time.Time
}

func newState(role Role, channel Channel, material sessionMaterial, transcriptHash [32]byte, now func() time.Time, deadline time.Time) *State {
	state := &State{
		role:       role,
		channel:    channel,
		material:   material,
		now:        now,
		deadline:   deadline,
		hardExpiry: deadline.Add(MaxGuestCredentialSessionLifetime - HandshakeDeadline),
	}
	state.setFinishedValues(transcriptHash)
	material.destroy()
	zero(transcriptHash[:])
	return state
}

func (s *State) setFinishedValues(transcriptHash [32]byte) {
	guestFinished := finishedValue(s.material.guestToController.finishedKey[:], s.channel, "guest", transcriptHash, s.material.sessionID)
	controllerFinished := finishedValue(s.material.controllerToGuest.finishedKey[:], s.channel, "controller", transcriptHash, s.material.sessionID)
	if s.role == RoleGuest {
		s.localFinished = guestFinished
		s.peerFinished = controllerFinished
	} else {
		s.localFinished = controllerFinished
		s.peerFinished = guestFinished
	}
	zero(guestFinished[:])
	zero(controllerFinished[:])
}

func (s *State) SealFinished() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableForHandshakeLocked(); err != nil {
		return nil, err
	}
	if s.sentFinished || s.established || s.role == RoleController && !s.receivedFinished {
		return nil, s.failLocked(ErrInvalidState)
	}
	frameType := FrameTypeGuestFinished
	if s.role == RoleController {
		frameType = FrameTypeControllerFinished
	}
	wire, err := s.sealLocked(frameType, s.localFinished[:])
	if err != nil {
		return nil, err
	}
	s.sentFinished = true
	s.updateEstablishedLocked()
	return wire, nil
}

func (s *State) OpenFinished(wire []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableForHandshakeLocked(); err != nil {
		return err
	}
	if s.receivedFinished || s.established || s.role == RoleGuest && !s.sentFinished {
		return s.failLocked(ErrInvalidState)
	}
	expectedType := FrameTypeControllerFinished
	if s.role == RoleController {
		expectedType = FrameTypeGuestFinished
	}
	plaintext, err := s.openLocked(wire, expectedType, func(_ FrameType, plaintext []byte) error {
		if !constantTimeEqual(plaintext, s.peerFinished[:]) {
			return ErrAuthentication
		}
		return nil
	})
	zero(plaintext)
	if err != nil {
		return err
	}
	s.receivedFinished = true
	s.updateEstablishedLocked()
	return nil
}

func (s *State) SealApplication(frameType FrameType, plaintext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sealApplicationLocked(frameType, plaintext)
}

func (s *State) WriteApplication(writer io.Writer, frameType FrameType, plaintext []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableForApplicationLocked(); err != nil {
		return err
	}
	if writer == nil {
		return s.failLocked(ErrPartialWrite)
	}
	wire, err := s.sealAdmittedApplicationLocked(frameType, plaintext)
	if err != nil {
		return err
	}
	written, writeErr := writer.Write(wire)
	zero(wire)
	if writeErr != nil || written != len(wire) {
		return s.failLocked(ErrPartialWrite)
	}
	return nil
}

func (s *State) OpenApplication(wire []byte, validate PlaintextValidator) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableForApplicationLocked(); err != nil {
		return nil, err
	}
	header, err := parseRecordHeader(wire, s.channel)
	if err != nil {
		return nil, s.failLocked(err)
	}
	if !allowedApplicationType(s.channel, s.inboundDirection(), header.Type) {
		return nil, s.failLocked(ErrUnexpectedFrame)
	}
	return s.openLocked(wire, header.Type, validate)
}

func (s *State) Established() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.established && !s.revoked
}

func (s *State) Revoked() bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.revoked
}

func (s *State) SessionID() [32]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.material.sessionID
}

func (s *State) Deadline() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline
}

func (s *State) HardExpiry() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hardExpiry
}

func (s *State) ValidateCredentialExpiry(expiry time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.revoked {
		return ErrSessionRevoked
	}
	now := s.now()
	if sessionHardExpiryReached(now, s.hardExpiry) {
		return s.failLocked(ErrCredentialLifetime)
	}
	if expiry.Before(now) || expiry.After(s.hardExpiry) {
		return ErrCredentialLifetime
	}
	return nil
}

func (s *State) Revoke() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revokeLocked()
}

func DestroyBytes(value []byte) {
	zero(value)
}

func (s *State) sealApplicationLocked(frameType FrameType, plaintext []byte) ([]byte, error) {
	if err := s.usableForApplicationLocked(); err != nil {
		return nil, err
	}
	return s.sealAdmittedApplicationLocked(frameType, plaintext)
}

func (s *State) sealAdmittedApplicationLocked(frameType FrameType, plaintext []byte) ([]byte, error) {
	if !allowedApplicationType(s.channel, s.outboundDirection(), frameType) {
		return nil, s.failLocked(ErrUnexpectedFrame)
	}
	if len(plaintext) > maximumPlaintext(s.channel) {
		return nil, s.failLocked(ErrRecordTooLarge)
	}
	return s.sealLocked(frameType, plaintext)
}

func (s *State) usableForApplicationLocked() error {
	if s.revoked {
		return ErrSessionRevoked
	}
	// The application lifetime is half-open: [establishment, hardExpiry).
	// Reaching the boundary revokes the session before any record processing.
	if sessionHardExpiryReached(s.now(), s.hardExpiry) {
		return s.failLocked(ErrCredentialLifetime)
	}
	if !s.established {
		return s.failLocked(ErrInvalidState)
	}
	return nil
}

func sessionHardExpiryReached(now, hardExpiry time.Time) bool {
	return !now.Before(hardExpiry)
}

func (s *State) sealLocked(frameType FrameType, plaintext []byte) ([]byte, error) {
	if s.nextSend >= MaxEncryptedRecordsPerDirection {
		return nil, s.failLocked(ErrSequenceExhausted)
	}
	direction := s.outboundDirection()
	directional := s.directionMaterial(direction)
	aead, err := newGCM(directional.key[:])
	if err != nil {
		return nil, s.failLocked(ErrAuthentication)
	}
	header := makeRecordHeader(frameType, s.nextSend, uint32(len(plaintext)+aead.Overhead()), s.material.sessionID)
	aad := makeAAD(header)
	nonce := makeNonce(directional.noncePrefix[:], s.nextSend)
	wire := make([]byte, SecureRecordHeaderBytes, SecureRecordHeaderBytes+len(plaintext)+aead.Overhead())
	copy(wire, header[:])
	wire = aead.Seal(wire, nonce[:], plaintext, aad)
	zero(aad)
	zero(nonce[:])
	s.nextSend++
	return wire, nil
}

func (s *State) openLocked(wire []byte, expectedType FrameType, validate PlaintextValidator) ([]byte, error) {
	if s.nextReceive >= MaxEncryptedRecordsPerDirection {
		return nil, s.failLocked(ErrSequenceExhausted)
	}
	header, err := parseRecordHeader(wire, s.channel)
	if err != nil {
		return nil, s.failLocked(err)
	}
	if header.Type != expectedType {
		return nil, s.failLocked(ErrUnexpectedFrame)
	}
	if !constantTimeEqual(header.SessionID[:], s.material.sessionID[:]) {
		return nil, s.failLocked(ErrInvalidFrame)
	}
	if header.Sequence < s.nextReceive {
		return nil, s.failLocked(ErrReplay)
	}
	if header.Sequence > s.nextReceive {
		return nil, s.failLocked(ErrSequenceGap)
	}
	directional := s.directionMaterial(s.inboundDirection())
	aead, err := newGCM(directional.key[:])
	if err != nil {
		return nil, s.failLocked(ErrAuthentication)
	}
	headerBytes := wire[:SecureRecordHeaderBytes]
	aad := makeAADArray(headerBytes)
	nonce := makeNonce(directional.noncePrefix[:], header.Sequence)
	plaintext, err := aead.Open(nil, nonce[:], wire[SecureRecordHeaderBytes:], aad)
	zero(aad)
	zero(nonce[:])
	if err != nil {
		zero(plaintext)
		return nil, s.failLocked(ErrAuthentication)
	}
	if validate != nil {
		if validationErr := validate(header.Type, plaintext); validationErr != nil {
			zero(plaintext)
			return nil, s.failLocked(ErrSemanticValidation)
		}
	}
	s.nextReceive++
	return plaintext, nil
}

func (s *State) usableForHandshakeLocked() error {
	if s.revoked {
		return ErrSessionRevoked
	}
	if handshakeDeadlineExpired(s.now(), s.deadline) {
		return s.failLocked(ErrHandshakeTimeout)
	}
	return nil
}

func (s *State) updateEstablishedLocked() {
	s.established = s.sentFinished && s.receivedFinished
	if s.established {
		zero(s.localFinished[:])
		zero(s.peerFinished[:])
		zero(s.material.controllerToGuest.finishedKey[:])
		zero(s.material.guestToController.finishedKey[:])
	}
}

func (s *State) failLocked(err error) error {
	s.revokeLocked()
	return err
}

func (s *State) revokeLocked() {
	if s.revoked {
		return
	}
	s.revoked = true
	s.established = false
	s.material.destroy()
	zero(s.localFinished[:])
	zero(s.peerFinished[:])
}

func (s *State) outboundDirection() Direction {
	if s.role == RoleGuest {
		return DirectionGuestToController
	}
	return DirectionControllerToGuest
}

func (s *State) inboundDirection() Direction {
	if s.role == RoleGuest {
		return DirectionControllerToGuest
	}
	return DirectionGuestToController
}

func (s *State) directionMaterial(direction Direction) *directionalMaterial {
	if direction == DirectionGuestToController {
		return &s.material.guestToController
	}
	return &s.material.controllerToGuest
}

func ParseRecordHeader(wire []byte, channel Channel) (RecordHeader, error) {
	return parseRecordHeader(wire, channel)
}

func parseRecordHeader(wire []byte, channel Channel) (RecordHeader, error) {
	if len(wire) < SecureRecordHeaderBytes {
		return RecordHeader{}, ErrInvalidFrame
	}
	header, err := ParseRecordHeaderPrefix(wire[:SecureRecordHeaderBytes], channel)
	if err != nil || uint64(SecureRecordHeaderBytes)+uint64(header.CiphertextLength) != uint64(len(wire)) {
		return RecordHeader{}, ErrInvalidFrame
	}
	return header, nil
}

// ParseRecordHeaderPrefix validates exactly one fixed header, including its
// channel-specific declaration bound, before ciphertext allocation.
func ParseRecordHeaderPrefix(prefix []byte, channel Channel) (RecordHeader, error) {
	if len(prefix) != SecureRecordHeaderBytes || prefix[0] != recordMagic[0] || prefix[1] != recordMagic[1] || prefix[2] != recordMagic[2] || prefix[3] != recordMagic[3] || prefix[4] != WireVersion || prefix[6] != 0 || prefix[7] != 0 {
		return RecordHeader{}, ErrInvalidFrame
	}
	ciphertextLength := binary.BigEndian.Uint32(prefix[16:20])
	maximum := maximumPlaintext(channel)
	if maximum == 0 || ciphertextLength < GCMTagBytes || uint64(ciphertextLength) > uint64(maximum+GCMTagBytes) {
		return RecordHeader{}, ErrInvalidFrame
	}
	header := RecordHeader{
		Type:             FrameType(prefix[5]),
		Sequence:         binary.BigEndian.Uint64(prefix[8:16]),
		CiphertextLength: ciphertextLength,
	}
	copy(header.SessionID[:], prefix[20:52])
	return header, nil
}

func makeRecordHeader(frameType FrameType, sequence uint64, ciphertextLength uint32, sessionID [32]byte) [SecureRecordHeaderBytes]byte {
	var header [SecureRecordHeaderBytes]byte
	copy(header[:4], recordMagic[:])
	header[4] = WireVersion
	header[5] = byte(frameType)
	binary.BigEndian.PutUint64(header[8:16], sequence)
	binary.BigEndian.PutUint32(header[16:20], ciphertextLength)
	copy(header[20:52], sessionID[:])
	return header
}

func makeAAD(header [SecureRecordHeaderBytes]byte) []byte {
	return makeAADArray(header[:])
}

func makeAADArray(header []byte) []byte {
	aad := make([]byte, 0, len(frameAADLabel)+SecureRecordHeaderBytes)
	aad = append(aad, frameAADLabel...)
	aad = append(aad, header...)
	return aad
}

func makeNonce(prefix []byte, sequence uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[:4], prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func maximumPlaintext(channel Channel) int {
	switch channel {
	case ChannelControl:
		return MaxControlPlaintextBytes
	case ChannelSSHRelay:
		return MaxRelayPlaintextBytes
	default:
		return 0
	}
}

func allowedApplicationType(channel Channel, direction Direction, frameType FrameType) bool {
	if frameType == FrameTypeCloseNotify {
		return true
	}
	switch channel {
	case ChannelControl:
		switch direction {
		case DirectionControllerToGuest:
			return frameType == FrameTypeControlRequest || frameType == FrameTypeControlPrivate || frameType == FrameTypeControlStream || frameType == FrameTypeControlStreamCredit
		case DirectionGuestToController:
			return frameType == FrameTypeControlResponse || frameType == FrameTypeControlEvent || frameType == FrameTypeControlStream || frameType == FrameTypeControlStreamCredit
		}
	case ChannelSSHRelay:
		if direction == DirectionGuestToController {
			return frameType == FrameTypeRelayRequest
		}
		if direction == DirectionControllerToGuest {
			return frameType == FrameTypeRelayResponse
		}
	}
	return false
}
