package credentialprotocol

import (
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
)

const (
	// SSHAgentMaxIdentities is the maximum decoded host identity count.
	SSHAgentMaxIdentities = 256
	// SSHAgentMaxKeyBlobBytes bounds one complete public-key blob.
	SSHAgentMaxKeyBlobBytes = 16 * 1024
	// SSHAgentMaxCommentBytes bounds one discarded source comment.
	SSHAgentMaxCommentBytes = 4 * 1024
	// SSHAgentMaxChallengeBytes bounds one signing challenge.
	SSHAgentMaxChallengeBytes = 192 * 1024
	// SSHAgentMaxSignatureBytes bounds one complete nested signature blob.
	SSHAgentMaxSignatureBytes = 16 * 1024
)

var (
	ErrSSHAgentMessageDirection    = errors.New("credential protocol SSH-agent message direction is invalid")
	ErrSSHAgentNestedTruncated     = errors.New("credential protocol SSH-agent nested message is truncated")
	ErrSSHAgentNestedTrailingData  = errors.New("credential protocol SSH-agent nested message has trailing data")
	ErrSSHAgentIdentityCount       = errors.New("credential protocol SSH-agent identity count is invalid")
	ErrSSHAgentKeyBlobLength       = errors.New("credential protocol SSH-agent key blob length is invalid")
	ErrSSHAgentCommentLength       = errors.New("credential protocol SSH-agent comment length is invalid")
	ErrSSHAgentChallengeLength     = errors.New("credential protocol SSH-agent challenge length is invalid")
	ErrSSHAgentSignatureLength     = errors.New("credential protocol SSH-agent signature length is invalid")
	ErrSSHAgentKeyBlob             = errors.New("credential protocol SSH-agent key blob is invalid")
	ErrSSHAgentSignatureBlob       = errors.New("credential protocol SSH-agent signature blob is invalid")
	ErrSSHAgentFingerprint         = errors.New("credential protocol SSH-agent fingerprint is invalid")
	ErrSSHAgentNestedSerialization = errors.New("credential protocol SSH-agent nested value serialization is denied")
)

// SSHAgentSignRequest owns the decoded public-key blob and challenge. Accessors
// return copies; callers wipe both those copies and the request after use.
type SSHAgentSignRequest struct {
	keyAlgorithm SSHAgentKeyAlgorithm
	flags        SSHAgentRSAFlags
	keyBlob      []byte
	challenge    []byte
}

// SSHAgentIdentity owns one validated public-key blob and no source comment.
type SSHAgentIdentity struct {
	keyAlgorithm SSHAgentKeyAlgorithm
	keyBlob      []byte
}

// SSHAgentSignature owns one validated algorithm-specific signature value.
type SSHAgentSignature struct {
	algorithm SSHAgentSignatureAlgorithm
	signature []byte
}

// SSHAgentKeyFingerprint is an opaque registry-private SHA-256 selector.
type SSHAgentKeyFingerprint struct {
	digest [sha256.Size]byte
	valid  bool
}

// ValidateSSHAgentIdentitiesRequest accepts exactly one complete, bodyless
// SSH_AGENTC_REQUEST_IDENTITIES frame.
func ValidateSSHAgentIdentitiesRequest(frame []byte) error {
	_, err := sshAgentNestedPayload(frame, SSHAgentMessageRequestIdentities)
	return err
}

// DecodeSSHAgentSignRequest consumes one complete SSH_AGENTC_SIGN_REQUEST
// frame and returns an independently owned request.
func DecodeSSHAgentSignRequest(frame []byte) (*SSHAgentSignRequest, error) {
	body, err := sshAgentNestedPayload(frame, SSHAgentMessageSignRequest)
	if err != nil {
		return nil, err
	}
	reader := sshAgentNestedReader{data: body}
	keyBlob, err := reader.readString(SSHAgentMaxKeyBlobBytes, ErrSSHAgentKeyBlobLength)
	if err != nil {
		return nil, err
	}
	algorithm, err := validateSSHAgentKeyBlob(keyBlob)
	if err != nil {
		return nil, err
	}
	challenge, err := reader.readString(SSHAgentMaxChallengeBytes, ErrSSHAgentChallengeLength)
	if err != nil {
		return nil, err
	}
	flagsValue, err := reader.readUint32()
	if err != nil {
		return nil, err
	}
	if err := reader.done(); err != nil {
		return nil, err
	}
	flags := SSHAgentRSAFlags(flagsValue)
	if err := ValidateSSHAgentRequestFlags(algorithm, flags); err != nil {
		return nil, err
	}
	return &SSHAgentSignRequest{
		keyAlgorithm: algorithm,
		flags:        flags,
		keyBlob:      cloneSSHAgentBytes(keyBlob),
		challenge:    cloneSSHAgentBytes(challenge),
	}, nil
}

// DecodeSSHAgentIdentitiesAnswer consumes one complete host-agent identities
// answer. It preserves identity order and validates, then discards, comments.
func DecodeSSHAgentIdentitiesAnswer(frame []byte) ([]SSHAgentIdentity, error) {
	body, err := sshAgentNestedPayload(frame, SSHAgentMessageIdentitiesAnswer)
	if err != nil {
		return nil, err
	}
	reader := sshAgentNestedReader{data: body}
	count, err := reader.readUint32()
	if err != nil {
		return nil, err
	}
	if count > SSHAgentMaxIdentities {
		return nil, ErrSSHAgentIdentityCount
	}
	identities := make([]SSHAgentIdentity, 0, int(count))
	for index := uint32(0); index < count; index++ {
		keyBlob, readErr := reader.readString(SSHAgentMaxKeyBlobBytes, ErrSSHAgentKeyBlobLength)
		if readErr != nil {
			WipeSSHAgentIdentities(identities)
			return nil, readErr
		}
		algorithm, validationErr := validateSSHAgentKeyBlob(keyBlob)
		if validationErr != nil {
			WipeSSHAgentIdentities(identities)
			return nil, validationErr
		}
		if _, readErr = reader.readString(SSHAgentMaxCommentBytes, ErrSSHAgentCommentLength); readErr != nil {
			WipeSSHAgentIdentities(identities)
			return nil, readErr
		}
		identities = append(identities, SSHAgentIdentity{
			keyAlgorithm: algorithm,
			keyBlob:      cloneSSHAgentBytes(keyBlob),
		})
	}
	if err := reader.done(); err != nil {
		WipeSSHAgentIdentities(identities)
		return nil, err
	}
	return identities, nil
}

// DecodeSSHAgentSignResponse consumes one complete host-agent sign response
// and returns an independently owned, canonical nested signature.
func DecodeSSHAgentSignResponse(frame []byte) (*SSHAgentSignature, error) {
	body, err := sshAgentNestedPayload(frame, SSHAgentMessageSignResponse)
	if err != nil {
		return nil, err
	}
	reader := sshAgentNestedReader{data: body}
	signatureBlob, err := reader.readString(SSHAgentMaxSignatureBytes, ErrSSHAgentSignatureLength)
	if err != nil {
		return nil, err
	}
	if err := reader.done(); err != nil {
		return nil, err
	}
	algorithm, signature, err := parseSSHAgentSignatureBlob(signatureBlob)
	if err != nil {
		return nil, err
	}
	return &SSHAgentSignature{algorithm: algorithm, signature: cloneSSHAgentBytes(signature)}, nil
}

// NewSSHAgentIdentity validates and defensively copies one key blob.
func NewSSHAgentIdentity(keyBlob []byte) (SSHAgentIdentity, error) {
	if len(keyBlob) > SSHAgentMaxKeyBlobBytes {
		return SSHAgentIdentity{}, ErrSSHAgentKeyBlobLength
	}
	algorithm, err := validateSSHAgentKeyBlob(keyBlob)
	if err != nil {
		return SSHAgentIdentity{}, err
	}
	return SSHAgentIdentity{keyAlgorithm: algorithm, keyBlob: cloneSSHAgentBytes(keyBlob)}, nil
}

// NewSSHAgentSignature validates and defensively copies one signature value.
func NewSSHAgentSignature(algorithm SSHAgentSignatureAlgorithm, signature []byte) (SSHAgentSignature, error) {
	if err := ValidateSSHAgentSignatureAlgorithm(algorithm); err != nil {
		return SSHAgentSignature{}, err
	}
	if err := validateSSHAgentSignatureValue(algorithm, signature); err != nil {
		return SSHAgentSignature{}, err
	}
	if sshAgentNestedStringSize(len(algorithm))+sshAgentNestedStringSize(len(signature)) > SSHAgentMaxSignatureBytes {
		return SSHAgentSignature{}, ErrSSHAgentSignatureLength
	}
	return SSHAgentSignature{algorithm: algorithm, signature: cloneSSHAgentBytes(signature)}, nil
}

// EncodeSSHAgentIdentitiesAnswer emits one complete identities answer in the
// given order and always writes an empty comment for every identity.
func EncodeSSHAgentIdentitiesAnswer(identities []SSHAgentIdentity) ([]byte, error) {
	if len(identities) > SSHAgentMaxIdentities {
		return nil, ErrSSHAgentIdentityCount
	}
	payloadLength := 1 + 4
	for index := range identities {
		identity := &identities[index]
		if len(identity.keyBlob) > SSHAgentMaxKeyBlobBytes {
			return nil, ErrSSHAgentKeyBlobLength
		}
		algorithm, err := validateSSHAgentKeyBlob(identity.keyBlob)
		if err != nil {
			return nil, err
		}
		if identity.keyAlgorithm != algorithm {
			return nil, ErrSSHAgentKeyBlob
		}
		payloadLength += sshAgentNestedStringSize(len(identity.keyBlob)) + 4
		if payloadLength > SSHAgentMaxPayloadBytes {
			return nil, ErrSSHAgentPayloadLength
		}
	}
	payload := make([]byte, 1, payloadLength)
	payload[0] = byte(SSHAgentMessageIdentitiesAnswer)
	payload = appendSSHAgentUint32(payload, uint32(len(identities)))
	for index := range identities {
		payload = appendSSHAgentString(payload, identities[index].keyBlob)
		payload = appendSSHAgentString(payload, nil)
	}
	frame, err := frameSSHAgentPayload(payload)
	WipeSSHAgentBytes(payload)
	return frame, err
}

// EncodeSSHAgentSignResponse emits one complete canonical sign response.
func EncodeSSHAgentSignResponse(signature SSHAgentSignature) ([]byte, error) {
	if err := ValidateSSHAgentSignatureAlgorithm(signature.algorithm); err != nil {
		return nil, err
	}
	if err := validateSSHAgentSignatureValue(signature.algorithm, signature.signature); err != nil {
		return nil, err
	}
	signatureBlobLength := sshAgentNestedStringSize(len(signature.algorithm)) + sshAgentNestedStringSize(len(signature.signature))
	if signatureBlobLength > SSHAgentMaxSignatureBytes {
		return nil, ErrSSHAgentSignatureLength
	}
	signatureBlob := make([]byte, 0, signatureBlobLength)
	signatureBlob = appendSSHAgentString(signatureBlob, []byte(signature.algorithm))
	signatureBlob = appendSSHAgentString(signatureBlob, signature.signature)
	payload := []byte{byte(SSHAgentMessageSignResponse)}
	payload = appendSSHAgentString(payload, signatureBlob)
	WipeSSHAgentBytes(signatureBlob)
	frame, err := frameSSHAgentPayload(payload)
	WipeSSHAgentBytes(payload)
	return frame, err
}

// EncodeSSHAgentFailure emits the one canonical complete failure frame.
func EncodeSSHAgentFailure() []byte {
	return []byte{0, 0, 0, 1, byte(SSHAgentMessageFailure)}
}

// ValidateSSHAgentSignatureForRequest enforces the decoded request's exact
// key, flags, and signature-algorithm policy.
func ValidateSSHAgentSignatureForRequest(request *SSHAgentSignRequest, signature SSHAgentSignature) error {
	if request == nil {
		return ErrSSHAgentSignaturePolicy
	}
	if err := validateSSHAgentSignatureValue(signature.algorithm, signature.signature); err != nil {
		return err
	}
	return ValidateSSHAgentSignPolicy(request.keyAlgorithm, request.flags, signature.algorithm)
}

// DeriveSSHAgentKeyFingerprint validates a key blob and derives its exact
// OpenSSH-style registry-private SHA-256 selector.
func DeriveSSHAgentKeyFingerprint(keyBlob []byte) (SSHAgentKeyFingerprint, error) {
	if len(keyBlob) > SSHAgentMaxKeyBlobBytes {
		return SSHAgentKeyFingerprint{}, ErrSSHAgentKeyBlobLength
	}
	if _, err := validateSSHAgentKeyBlob(keyBlob); err != nil {
		return SSHAgentKeyFingerprint{}, err
	}
	return SSHAgentKeyFingerprint{digest: sha256.Sum256(keyBlob), valid: true}, nil
}

// ParseSSHAgentKeyFingerprint accepts only SHA256: plus 43 characters of
// canonical, unpadded standard base64.
func ParseSSHAgentKeyFingerprint(value string) (SSHAgentKeyFingerprint, error) {
	const prefix = "SHA256:"
	const encodedDigestLength = 43
	if len(value) != len(prefix)+encodedDigestLength || value[:len(prefix)] != prefix {
		return SSHAgentKeyFingerprint{}, ErrSSHAgentFingerprint
	}
	decoded, err := base64.RawStdEncoding.DecodeString(value[len(prefix):])
	if err != nil || len(decoded) != sha256.Size || base64.RawStdEncoding.EncodeToString(decoded) != value[len(prefix):] {
		WipeSSHAgentBytes(decoded)
		return SSHAgentKeyFingerprint{}, ErrSSHAgentFingerprint
	}
	var fingerprint SSHAgentKeyFingerprint
	copy(fingerprint.digest[:], decoded)
	fingerprint.valid = true
	WipeSSHAgentBytes(decoded)
	return fingerprint, nil
}

// Equal compares two valid fingerprints without data-dependent digest timing.
func (fingerprint SSHAgentKeyFingerprint) Equal(other SSHAgentKeyFingerprint) bool {
	valid := subtle.ConstantTimeByteEq(boolByte(fingerprint.valid), 1) &
		subtle.ConstantTimeByteEq(boolByte(other.valid), 1)
	equal := subtle.ConstantTimeCompare(fingerprint.digest[:], other.digest[:])
	return valid&equal == 1
}

// KeyAlgorithm returns safe catalog metadata.
func (request *SSHAgentSignRequest) KeyAlgorithm() SSHAgentKeyAlgorithm {
	if request == nil {
		return ""
	}
	return request.keyAlgorithm
}

// Flags returns the exact request flags.
func (request *SSHAgentSignRequest) Flags() SSHAgentRSAFlags {
	if request == nil {
		return 0
	}
	return request.flags
}

// PublicKeyBlob returns an independently owned copy.
func (request *SSHAgentSignRequest) PublicKeyBlob() []byte {
	if request == nil {
		return nil
	}
	return cloneSSHAgentBytes(request.keyBlob)
}

// Challenge returns an independently owned copy.
func (request *SSHAgentSignRequest) Challenge() []byte {
	if request == nil {
		return nil
	}
	return cloneSSHAgentBytes(request.challenge)
}

// Wipe destroys all buffers owned by the request.
func (request *SSHAgentSignRequest) Wipe() {
	if request == nil {
		return
	}
	WipeSSHAgentBytes(request.keyBlob)
	WipeSSHAgentBytes(request.challenge)
	request.keyBlob = nil
	request.challenge = nil
	request.keyAlgorithm = ""
	request.flags = 0
}

// KeyAlgorithm returns safe catalog metadata.
func (identity SSHAgentIdentity) KeyAlgorithm() SSHAgentKeyAlgorithm { return identity.keyAlgorithm }

// PublicKeyBlob returns an independently owned copy.
func (identity SSHAgentIdentity) PublicKeyBlob() []byte { return cloneSSHAgentBytes(identity.keyBlob) }

// Wipe destroys the buffer owned by the identity.
func (identity *SSHAgentIdentity) Wipe() {
	if identity == nil {
		return
	}
	WipeSSHAgentBytes(identity.keyBlob)
	identity.keyBlob = nil
	identity.keyAlgorithm = ""
}

// Algorithm returns safe catalog metadata.
func (signature SSHAgentSignature) Algorithm() SSHAgentSignatureAlgorithm { return signature.algorithm }

// Signature returns an independently owned copy.
func (signature SSHAgentSignature) Signature() []byte { return cloneSSHAgentBytes(signature.signature) }

// Wipe destroys the buffer owned by the signature.
func (signature *SSHAgentSignature) Wipe() {
	if signature == nil {
		return
	}
	WipeSSHAgentBytes(signature.signature)
	signature.signature = nil
	signature.algorithm = ""
}

// Wipe destroys the opaque fingerprint digest.
func (fingerprint *SSHAgentKeyFingerprint) Wipe() {
	if fingerprint == nil {
		return
	}
	WipeSSHAgentBytes(fingerprint.digest[:])
	fingerprint.valid = false
}

// WipeSSHAgentIdentities destroys every owned identity buffer and clears the
// supplied slice elements.
func WipeSSHAgentIdentities(identities []SSHAgentIdentity) {
	for index := range identities {
		identities[index].Wipe()
	}
}

// WipeSSHAgentBytes overwrites one caller-owned mutable ephemeral buffer.
func WipeSSHAgentBytes(buffer []byte) {
	clear(buffer)
	runtime.KeepAlive(buffer)
}

func validateSSHAgentKeyBlob(keyBlob []byte) (SSHAgentKeyAlgorithm, error) {
	if len(keyBlob) == 0 || len(keyBlob) > SSHAgentMaxKeyBlobBytes {
		if len(keyBlob) > SSHAgentMaxKeyBlobBytes {
			return "", ErrSSHAgentKeyBlobLength
		}
		return "", ErrSSHAgentKeyBlob
	}
	reader := sshAgentNestedReader{data: keyBlob}
	algorithmBytes, err := reader.readString(64, ErrSSHAgentKeyBlob)
	if err != nil {
		return "", err
	}
	algorithm := SSHAgentKeyAlgorithm(string(algorithmBytes))
	if err := ValidateSSHAgentKeyAlgorithm(algorithm); err != nil {
		return "", err
	}
	switch algorithm {
	case SSHAgentKeyAlgorithmED25519:
		public, readErr := reader.readString(32, ErrSSHAgentKeyBlob)
		if readErr != nil {
			return "", readErr
		}
		if len(public) != 32 {
			return "", ErrSSHAgentKeyBlob
		}
	case SSHAgentKeyAlgorithmECDSANISTP256,
		SSHAgentKeyAlgorithmECDSANISTP384,
		SSHAgentKeyAlgorithmECDSANISTP521:
		if err := validateSSHAgentECDSAKey(&reader, algorithm); err != nil {
			return "", err
		}
	case SSHAgentKeyAlgorithmRSA:
		exponent, readErr := reader.readString(SSHAgentMaxKeyBlobBytes, ErrSSHAgentKeyBlob)
		if readErr != nil {
			return "", readErr
		}
		if !validSSHAgentPositiveMPInt(exponent) {
			return "", ErrSSHAgentKeyBlob
		}
		modulus, readErr := reader.readString(SSHAgentMaxKeyBlobBytes, ErrSSHAgentKeyBlob)
		if readErr != nil {
			return "", readErr
		}
		if !validSSHAgentPositiveMPInt(modulus) {
			return "", ErrSSHAgentKeyBlob
		}
	}
	if err := reader.done(); err != nil {
		return "", err
	}
	return algorithm, nil
}

func validateSSHAgentECDSAKey(reader *sshAgentNestedReader, algorithm SSHAgentKeyAlgorithm) error {
	var curve string
	var pointLength int
	var ellipticCurve elliptic.Curve
	switch algorithm {
	case SSHAgentKeyAlgorithmECDSANISTP256:
		curve, pointLength, ellipticCurve = "nistp256", 65, elliptic.P256()
	case SSHAgentKeyAlgorithmECDSANISTP384:
		curve, pointLength, ellipticCurve = "nistp384", 97, elliptic.P384()
	case SSHAgentKeyAlgorithmECDSANISTP521:
		curve, pointLength, ellipticCurve = "nistp521", 133, elliptic.P521()
	default:
		return ErrSSHAgentKeyBlob
	}
	curveBytes, err := reader.readString(len(curve), ErrSSHAgentKeyBlob)
	if err != nil {
		return err
	}
	if string(curveBytes) != curve {
		return ErrSSHAgentKeyBlob
	}
	point, err := reader.readString(pointLength, ErrSSHAgentKeyBlob)
	if err != nil {
		return err
	}
	if len(point) != pointLength || point[0] != 4 {
		return ErrSSHAgentKeyBlob
	}
	// SSH ECDSA keys use SEC1 points for signature verification, not ECDH.
	//nolint:staticcheck // crypto/ecdh is not a replacement for this ECDSA SEC1 validation.
	if x, y := elliptic.Unmarshal(ellipticCurve, point); x == nil || y == nil {
		return ErrSSHAgentKeyBlob
	}
	return nil
}

func parseSSHAgentSignatureBlob(blob []byte) (SSHAgentSignatureAlgorithm, []byte, error) {
	reader := sshAgentNestedReader{data: blob}
	algorithmBytes, err := reader.readString(64, ErrSSHAgentSignatureBlob)
	if err != nil {
		return "", nil, err
	}
	algorithm := SSHAgentSignatureAlgorithm(string(algorithmBytes))
	if err := ValidateSSHAgentSignatureAlgorithm(algorithm); err != nil {
		return "", nil, err
	}
	signature, err := reader.readString(SSHAgentMaxSignatureBytes, ErrSSHAgentSignatureLength)
	if err != nil {
		return "", nil, err
	}
	if err := reader.done(); err != nil {
		return "", nil, err
	}
	if err := validateSSHAgentSignatureValue(algorithm, signature); err != nil {
		return "", nil, err
	}
	return algorithm, signature, nil
}

func validateSSHAgentSignatureValue(algorithm SSHAgentSignatureAlgorithm, signature []byte) error {
	if err := ValidateSSHAgentSignatureAlgorithm(algorithm); err != nil {
		return err
	}
	switch algorithm {
	case SSHAgentSignatureAlgorithmED25519:
		if len(signature) != 64 {
			return ErrSSHAgentSignatureBlob
		}
	case SSHAgentSignatureAlgorithmECDSANISTP256,
		SSHAgentSignatureAlgorithmECDSANISTP384,
		SSHAgentSignatureAlgorithmECDSANISTP521:
		reader := sshAgentNestedReader{data: signature}
		r, err := reader.readString(SSHAgentMaxSignatureBytes, ErrSSHAgentSignatureBlob)
		if err != nil {
			return err
		}
		if !validSSHAgentPositiveMPInt(r) {
			return ErrSSHAgentSignatureBlob
		}
		s, err := reader.readString(SSHAgentMaxSignatureBytes, ErrSSHAgentSignatureBlob)
		if err != nil {
			return err
		}
		if !validSSHAgentPositiveMPInt(s) {
			return ErrSSHAgentSignatureBlob
		}
		if err := reader.done(); err != nil {
			return err
		}
	case SSHAgentSignatureAlgorithmRSASHA256, SSHAgentSignatureAlgorithmRSASHA512:
		if len(signature) == 0 {
			return ErrSSHAgentSignatureBlob
		}
	}
	return nil
}

func validSSHAgentPositiveMPInt(value []byte) bool {
	if len(value) == 0 {
		return false
	}
	if value[0]&0x80 != 0 {
		return false
	}
	if value[0] == 0 {
		return len(value) > 1 && value[1]&0x80 != 0
	}
	return true
}

func sshAgentNestedPayload(frame []byte, expected SSHAgentMessageType) ([]byte, error) {
	metadata, err := ValidateSSHAgentOuterFrame(frame)
	if err != nil {
		return nil, err
	}
	if metadata.MessageType != expected {
		return nil, ErrSSHAgentMessageDirection
	}
	return frame[SSHAgentFrameHeaderBytes+1:], nil
}

type sshAgentNestedReader struct {
	data   []byte
	offset int
}

func (reader *sshAgentNestedReader) readUint32() (uint32, error) {
	if len(reader.data)-reader.offset < 4 {
		return 0, ErrSSHAgentNestedTruncated
	}
	value := binary.BigEndian.Uint32(reader.data[reader.offset : reader.offset+4])
	reader.offset += 4
	return value, nil
}

func (reader *sshAgentNestedReader) readString(maximum int, boundError error) ([]byte, error) {
	length, err := reader.readUint32()
	if err != nil {
		return nil, err
	}
	if uint64(length) > uint64(maximum) {
		return nil, boundError
	}
	if uint64(length) > uint64(len(reader.data)-reader.offset) {
		return nil, ErrSSHAgentNestedTruncated
	}
	value := reader.data[reader.offset : reader.offset+int(length)]
	reader.offset += int(length)
	return value, nil
}

func (reader *sshAgentNestedReader) done() error {
	if reader.offset != len(reader.data) {
		return ErrSSHAgentNestedTrailingData
	}
	return nil
}

func appendSSHAgentString(dst, value []byte) []byte {
	dst = appendSSHAgentUint32(dst, uint32(len(value)))
	return append(dst, value...)
}

func appendSSHAgentUint32(dst []byte, value uint32) []byte {
	return append(dst, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func sshAgentNestedStringSize(length int) int { return 4 + length }

func frameSSHAgentPayload(payload []byte) ([]byte, error) {
	if len(payload) < SSHAgentMinPayloadBytes || len(payload) > SSHAgentMaxPayloadBytes {
		return nil, ErrSSHAgentPayloadLength
	}
	header, err := EncodeSSHAgentFrameHeader(uint32(len(payload)))
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 0, SSHAgentFrameHeaderBytes+len(payload))
	frame = append(frame, header[:]...)
	frame = append(frame, payload...)
	return frame, nil
}

func cloneSSHAgentBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte(nil), value...)
}

func boolByte(value bool) byte {
	if value {
		return 1
	}
	return 0
}

func (SSHAgentSignRequest) String() string   { return "SSHAgentSignRequest" }
func (SSHAgentSignRequest) GoString() string { return "SSHAgentSignRequest" }
func (SSHAgentIdentity) String() string      { return "SSHAgentIdentity" }
func (SSHAgentIdentity) GoString() string    { return "SSHAgentIdentity" }
func (SSHAgentSignature) String() string     { return "SSHAgentSignature" }
func (SSHAgentSignature) GoString() string   { return "SSHAgentSignature" }
func (SSHAgentKeyFingerprint) String() string {
	return "SSHAgentKeyFingerprint"
}
func (SSHAgentKeyFingerprint) GoString() string { return "SSHAgentKeyFingerprint" }

func (SSHAgentSignRequest) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("SSHAgentSignRequest"))
}
func (SSHAgentIdentity) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("SSHAgentIdentity"))
}
func (SSHAgentSignature) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("SSHAgentSignature"))
}
func (SSHAgentKeyFingerprint) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("SSHAgentKeyFingerprint"))
}

func (SSHAgentSignRequest) MarshalJSON() ([]byte, error) { return nil, ErrSSHAgentNestedSerialization }
func (SSHAgentSignRequest) MarshalText() ([]byte, error) { return nil, ErrSSHAgentNestedSerialization }
func (SSHAgentSignRequest) MarshalBinary() ([]byte, error) {
	return nil, ErrSSHAgentNestedSerialization
}
func (*SSHAgentSignRequest) UnmarshalJSON([]byte) error   { return ErrSSHAgentNestedSerialization }
func (*SSHAgentSignRequest) UnmarshalText([]byte) error   { return ErrSSHAgentNestedSerialization }
func (*SSHAgentSignRequest) UnmarshalBinary([]byte) error { return ErrSSHAgentNestedSerialization }

func (SSHAgentIdentity) MarshalJSON() ([]byte, error)   { return nil, ErrSSHAgentNestedSerialization }
func (SSHAgentIdentity) MarshalText() ([]byte, error)   { return nil, ErrSSHAgentNestedSerialization }
func (SSHAgentIdentity) MarshalBinary() ([]byte, error) { return nil, ErrSSHAgentNestedSerialization }
func (*SSHAgentIdentity) UnmarshalJSON([]byte) error    { return ErrSSHAgentNestedSerialization }
func (*SSHAgentIdentity) UnmarshalText([]byte) error    { return ErrSSHAgentNestedSerialization }
func (*SSHAgentIdentity) UnmarshalBinary([]byte) error  { return ErrSSHAgentNestedSerialization }

func (SSHAgentSignature) MarshalJSON() ([]byte, error)   { return nil, ErrSSHAgentNestedSerialization }
func (SSHAgentSignature) MarshalText() ([]byte, error)   { return nil, ErrSSHAgentNestedSerialization }
func (SSHAgentSignature) MarshalBinary() ([]byte, error) { return nil, ErrSSHAgentNestedSerialization }
func (*SSHAgentSignature) UnmarshalJSON([]byte) error    { return ErrSSHAgentNestedSerialization }
func (*SSHAgentSignature) UnmarshalText([]byte) error    { return ErrSSHAgentNestedSerialization }
func (*SSHAgentSignature) UnmarshalBinary([]byte) error  { return ErrSSHAgentNestedSerialization }

func (SSHAgentKeyFingerprint) MarshalJSON() ([]byte, error) {
	return nil, ErrSSHAgentNestedSerialization
}
func (SSHAgentKeyFingerprint) MarshalText() ([]byte, error) {
	return nil, ErrSSHAgentNestedSerialization
}
func (SSHAgentKeyFingerprint) MarshalBinary() ([]byte, error) {
	return nil, ErrSSHAgentNestedSerialization
}
func (*SSHAgentKeyFingerprint) UnmarshalJSON([]byte) error   { return ErrSSHAgentNestedSerialization }
func (*SSHAgentKeyFingerprint) UnmarshalText([]byte) error   { return ErrSSHAgentNestedSerialization }
func (*SSHAgentKeyFingerprint) UnmarshalBinary([]byte) error { return ErrSSHAgentNestedSerialization }
