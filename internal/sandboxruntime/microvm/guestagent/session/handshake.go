package session

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"io"
	"time"
)

const (
	transcriptLabel          = "hal/l8/guest-session/transcript/v1"
	controllerSignatureLabel = "hal/l8/guest-session/controller-signature/v1"
	sessionIDLabel           = "hal/l8/guest-session/id/v1"
)

type GuestHandshake struct {
	identity      Identity
	controllerKey ed25519.PublicKey
	privateKey    *ecdh.PrivateKey
	guestInner    []byte
	now           func() time.Time
	deadline      time.Time
	consumed      bool
}

type ControllerHandshake struct {
	expectedIdentity Identity
	signingKey       ed25519.PrivateKey
	random           io.Reader
	now              func() time.Time
	deadline         time.Time
	consumed         bool
}

func (h *GuestHandshake) Deadline() time.Time {
	if h == nil {
		return time.Time{}
	}
	return h.deadline
}

func (h *ControllerHandshake) Deadline() time.Time {
	if h == nil {
		return time.Time{}
	}
	return h.deadline
}

func NewGuestHandshake(config GuestHandshakeConfig) (*GuestHandshake, []byte, error) {
	if validateIdentity(config.Identity) != nil || len(config.PinnedControllerPublicKey) != ed25519.PublicKeySize {
		return nil, nil, ErrMalformedHandshake
	}
	randomSource, now := normalizeDependencies(config.Dependencies)
	startedAt := now()
	privateKey, err := generateX25519PrivateKey(randomSource)
	if err != nil {
		return nil, nil, ErrAuthentication
	}
	var public [32]byte
	copy(public[:], privateKey.PublicKey().Bytes())
	hello := GuestHello{Suite: HandshakeSuite1, Identity: config.Identity, GuestX25519Public: public}
	inner, err := marshalGuestHelloInner(hello)
	if err != nil {
		return nil, nil, err
	}
	wire, err := marshalHandshakeOuter(inner)
	if err != nil {
		return nil, nil, err
	}
	return &GuestHandshake{
		identity:      config.Identity,
		controllerKey: append(ed25519.PublicKey(nil), config.PinnedControllerPublicKey...),
		privateKey:    privateKey,
		guestInner:    append([]byte(nil), inner...),
		now:           now,
		deadline:      startedAt.Add(HandshakeDeadline),
	}, wire, nil
}

func NewControllerHandshake(config ControllerHandshakeConfig) (*ControllerHandshake, error) {
	if validateIdentity(config.ExpectedIdentity) != nil || len(config.SigningKey) != ed25519.PrivateKeySize {
		return nil, ErrMalformedHandshake
	}
	randomSource, now := normalizeDependencies(config.Dependencies)
	startedAt := now()
	return &ControllerHandshake{
		expectedIdentity: config.ExpectedIdentity,
		signingKey:       append(ed25519.PrivateKey(nil), config.SigningKey...),
		random:           randomSource,
		now:              now,
		deadline:         startedAt.Add(HandshakeDeadline),
	}, nil
}

func (h *GuestHandshake) AcceptControllerAuth(wire []byte) (*State, error) {
	if h == nil || h.consumed || h.privateKey == nil {
		return nil, ErrInvalidState
	}
	h.consumed = true
	defer h.destroy()
	if handshakeDeadlineExpired(h.now(), h.deadline) {
		return nil, ErrHandshakeTimeout
	}
	auth, err := ParseControllerAuth(wire)
	if err != nil || auth.Channel != h.identity.Channel || auth.Suite != HandshakeSuite1 {
		return nil, ErrMalformedHandshake
	}
	unsigned, err := marshalControllerUnsignedInner(auth)
	if err != nil {
		return nil, ErrMalformedHandshake
	}
	transcriptHash := hashTranscript(h.guestInner, unsigned)
	signatureInput := opaqueHashInput(controllerSignatureLabel, transcriptHash)
	if !ed25519.Verify(h.controllerKey, signatureInput, auth.Signature[:]) {
		zero(signatureInput)
		return nil, ErrAuthentication
	}
	zero(signatureInput)
	material, err := deriveMaterial(h.identity.Channel, h.privateKey, auth.ControllerX25519Public[:], transcriptHash)
	if err != nil {
		return nil, err
	}
	state := newState(RoleGuest, h.identity.Channel, material, transcriptHash, h.now, h.deadline)
	material.destroy()
	zero(transcriptHash[:])
	return state, nil
}

func (h *ControllerHandshake) AcceptGuestHello(wire []byte) (*State, []byte, error) {
	if h == nil || h.consumed {
		return nil, nil, ErrInvalidState
	}
	h.consumed = true
	defer h.destroy()
	if handshakeDeadlineExpired(h.now(), h.deadline) {
		return nil, nil, ErrHandshakeTimeout
	}
	hello, err := ParseGuestHello(wire)
	if err != nil {
		return nil, nil, err
	}
	if !identitiesEqual(hello.Identity, h.expectedIdentity) {
		return nil, nil, ErrIdentityMismatch
	}
	guestInner, err := marshalGuestHelloInner(hello)
	if err != nil {
		return nil, nil, ErrMalformedHandshake
	}
	privateKey, err := generateX25519PrivateKey(h.random)
	if err != nil {
		return nil, nil, ErrAuthentication
	}
	var public [32]byte
	copy(public[:], privateKey.PublicKey().Bytes())
	auth := ControllerAuth{Suite: HandshakeSuite1, Channel: hello.Identity.Channel, ControllerX25519Public: public}
	unsigned, err := marshalControllerUnsignedInner(auth)
	if err != nil {
		return nil, nil, ErrMalformedHandshake
	}
	transcriptHash := hashTranscript(guestInner, unsigned)
	signatureInput := opaqueHashInput(controllerSignatureLabel, transcriptHash)
	signature := ed25519.Sign(h.signingKey, signatureInput)
	zero(signatureInput)
	copy(auth.Signature[:], signature)
	zero(signature)
	authWire, err := MarshalControllerAuth(auth)
	if err != nil {
		return nil, nil, err
	}
	material, err := deriveMaterial(hello.Identity.Channel, privateKey, hello.GuestX25519Public[:], transcriptHash)
	if err != nil {
		return nil, nil, err
	}
	state := newState(RoleController, hello.Identity.Channel, material, transcriptHash, h.now, h.deadline)
	material.destroy()
	zero(transcriptHash[:])
	return state, authWire, nil
}

func normalizeDependencies(dependencies Dependencies) (io.Reader, func() time.Time) {
	randomSource := dependencies.Random
	if randomSource == nil {
		randomSource = rand.Reader
	}
	now := dependencies.Now
	if now == nil {
		now = time.Now
	}
	return randomSource, now
}

// handshakeDeadlineExpired uses the conservative half-open interval
// [startedAt, deadline): reaching the exact five-second deadline is terminal.
func handshakeDeadlineExpired(now, deadline time.Time) bool {
	return !now.Before(deadline)
}

func generateX25519PrivateKey(randomSource io.Reader) (*ecdh.PrivateKey, error) {
	privateBytes := make([]byte, 32)
	if _, err := io.ReadFull(randomSource, privateBytes); err != nil {
		zero(privateBytes)
		return nil, ErrAuthentication
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	zero(privateBytes)
	if err != nil {
		return nil, ErrAuthentication
	}
	return privateKey, nil
}

func (h *GuestHandshake) destroy() {
	h.privateKey = nil
	zero(h.guestInner)
	h.guestInner = nil
	zero(h.controllerKey)
	h.controllerKey = nil
}

func (h *ControllerHandshake) destroy() {
	zero(h.signingKey)
	h.signingKey = nil
	h.random = nil
}

func identitiesEqual(left, right Identity) bool {
	return left == right
}

func hashTranscript(guestInner, controllerUnsigned []byte) [32]byte {
	input := make([]byte, 0, 2+len(transcriptLabel)+4+len(guestInner)+4+len(controllerUnsigned))
	input = appendOpaque16(input, transcriptLabel)
	input = appendUint32(input, uint32(len(guestInner)))
	input = append(input, guestInner...)
	input = appendUint32(input, uint32(len(controllerUnsigned)))
	input = append(input, controllerUnsigned...)
	digest := sha256.Sum256(input)
	zero(input)
	return digest
}

func opaqueHashInput(label string, digest [32]byte) []byte {
	input := make([]byte, 0, 2+len(label)+32)
	input = appendOpaque16(input, label)
	input = append(input, digest[:]...)
	return input
}

type directionalMaterial struct {
	key         [32]byte
	noncePrefix [4]byte
	finishedKey [32]byte
}

type sessionMaterial struct {
	sessionID         [32]byte
	controllerToGuest directionalMaterial
	guestToController directionalMaterial
}

func deriveMaterial(channel Channel, localPrivate *ecdh.PrivateKey, peerPublicBytes []byte, transcriptHash [32]byte) (sessionMaterial, error) {
	peerPublic, err := ecdh.X25519().NewPublicKey(peerPublicBytes)
	if err != nil {
		return sessionMaterial{}, ErrAuthentication
	}
	sharedSecret, err := localPrivate.ECDH(peerPublic)
	if err != nil || len(sharedSecret) != 32 {
		zero(sharedSecret)
		return sessionMaterial{}, ErrAuthentication
	}
	var material sessionMaterial
	sessionInput := opaqueHashInput(sessionIDLabel, transcriptHash)
	material.sessionID = sha256.Sum256(sessionInput)
	zero(sessionInput)
	prk := hkdfExtract(transcriptHash[:], sharedSecret)
	zero(sharedSecret)
	label := channel.label()
	if label == "" {
		zero(prk[:])
		material.destroy()
		return sessionMaterial{}, ErrMalformedHandshake
	}
	expandDirectional := func(direction string, destination *directionalMaterial) {
		hkdfExpandInto(destination.key[:], prk[:], "hal/l8/guest-session/"+label+"/"+direction+"/key/v1")
		hkdfExpandInto(destination.noncePrefix[:], prk[:], "hal/l8/guest-session/"+label+"/"+direction+"/nonce-prefix/v1")
		hkdfExpandInto(destination.finishedKey[:], prk[:], "hal/l8/guest-session/"+label+"/"+direction+"/finished-key/v1")
	}
	expandDirectional("controller-to-guest", &material.controllerToGuest)
	expandDirectional("guest-to-controller", &material.guestToController)
	zero(prk[:])
	return material, nil
}

func hkdfExtract(salt, secret []byte) [32]byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(secret)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func hkdfExpandInto(destination, prk []byte, label string) {
	mac := hmac.New(sha256.New, prk)
	mac.Write([]byte(label))
	mac.Write([]byte{1})
	block := mac.Sum(nil)
	copy(destination, block[:len(destination)])
	zero(block)
}

func finishedValue(key []byte, channel Channel, side string, transcriptHash, sessionID [32]byte) [32]byte {
	label := "hal/l8/guest-session/" + channel.label() + "/" + side + "-finished/v1"
	input := make([]byte, 0, 2+len(label)+64)
	input = appendOpaque16(input, label)
	input = append(input, transcriptHash[:]...)
	input = append(input, sessionID[:]...)
	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	zero(input)
	return result
}

func appendOpaque16(destination []byte, value string) []byte {
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(value)))
	destination = append(destination, length[:]...)
	return append(destination, value...)
}

func appendUint32(destination []byte, value uint32) []byte {
	var encoded [4]byte
	binary.BigEndian.PutUint32(encoded[:], value)
	return append(destination, encoded[:]...)
}

func constantTimeEqual(left, right []byte) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare(left, right) == 1
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func (m *sessionMaterial) destroy() {
	zero(m.sessionID[:])
	zero(m.controllerToGuest.key[:])
	zero(m.controllerToGuest.noncePrefix[:])
	zero(m.controllerToGuest.finishedKey[:])
	zero(m.guestToController.key[:])
	zero(m.guestToController.noncePrefix[:])
	zero(m.guestToController.finishedKey[:])
}
