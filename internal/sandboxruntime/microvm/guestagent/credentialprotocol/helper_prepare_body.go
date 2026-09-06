package credentialprotocol

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
)

const (
	// MaxHelperFileBytes is the exact private-file bound for one HL8P binding.
	MaxHelperFileBytes = 64 * 1024
	// MaxHelperFileAggregateBytes is the exact aggregate bound for one prepare.
	MaxHelperFileAggregateBytes = 1024 * 1024

	helperPrepareBeginFixedBytes = 18
	helperPrepareFileFixedBytes  = 46
	helperPrepareCommitBytes     = 40
	helperManifestDomain         = "hal/l8/guest-helper/manifest/v1"
)

var (
	ErrHelperPrepareRevision           = errors.New("credential protocol helper prepare revision is invalid")
	ErrHelperPrepareBindingCount       = errors.New("credential protocol helper prepare binding count is invalid")
	ErrHelperPrepareBindingDuplicate   = errors.New("credential protocol helper prepare binding ID is duplicated")
	ErrHelperPrepareHTTPBindingCount   = errors.New("credential protocol helper prepare HTTP binding count is invalid")
	ErrHelperPrepareBindingModeFields  = errors.New("credential protocol helper prepare binding mode fields are invalid")
	ErrHelperPrepareBindingIndex       = errors.New("credential protocol helper prepare binding index is invalid")
	ErrHelperPrepareFileLength         = errors.New("credential protocol helper prepare file length is invalid")
	ErrHelperPrepareFileDigest         = errors.New("credential protocol helper prepare file digest is invalid")
	ErrHelperPrepareBeginBodyLength    = errors.New("credential protocol helper prepare-begin body length is invalid")
	ErrHelperPrepareBeginTrailingData  = errors.New("credential protocol helper prepare-begin body has trailing data")
	ErrHelperPrepareFileBodyLength     = errors.New("credential protocol helper prepare-file body length is invalid")
	ErrHelperPrepareFileTrailingData   = errors.New("credential protocol helper prepare-file body has trailing data")
	ErrHelperPrepareCommitBodyLength   = errors.New("credential protocol helper prepare-commit body length is invalid")
	ErrHelperPrepareCommitTrailingData = errors.New("credential protocol helper prepare-commit body has trailing data")
	ErrHelperPreparePrivateDestination = errors.New("credential protocol helper prepare private destination is too small")
	ErrHelperPreparePrivateWiped       = errors.New("credential protocol helper prepare private bytes are wiped")
	ErrHelperPrepareBodySerialization  = errors.New("credential protocol helper prepare body serialization is denied")
)

// HelperBindingManifestRecord is one exact ordered HL8P binding declaration.
// Only file-tmpfs records carry target, size, and digest fields.
type HelperBindingManifestRecord struct {
	BindingID         string
	Mode              DeliveryMode
	TargetPath        string
	DeclaredFileBytes uint32
	FileSHA256        [32]byte
}

// HelperPrepareBeginBody is the exact safe body for PacketTypePrepareBegin.
type HelperPrepareBeginBody struct {
	Revision       uint64
	ExpiryUnixNano int64
	Bindings       []HelperBindingManifestRecord
}

// HelperPrepareFileBody is a copy-safe opaque handle that owns the mutable
// private bytes for one exact PacketTypePrepareFile body. Value copies share
// wipe state. Call Wipe once the encoded or decoded bytes are no longer needed.
type HelperPrepareFileBody struct {
	state *helperPrepareFileState
}

type helperPrepareFileState struct {
	revision     uint64
	bindingIndex uint16
	fileLength   uint32
	fileSHA256   [32]byte
	privateBytes []byte
	wiped        bool
}

// HelperPrepareCommitBody is the exact safe body for PacketTypePrepareCommit.
// ManifestSHA256 is a fixed-width representation; zero is not reserved by the
// codec and comparison with the computed digest belongs to transaction state.
type HelperPrepareCommitBody struct {
	Revision       uint64
	ManifestSHA256 [32]byte
}

// ValidateHelperBindingManifestRecord validates one record without changing
// or normalizing its caller-selected manifest position.
func ValidateHelperBindingManifestRecord(record HelperBindingManifestRecord) error {
	if err := ValidateBodyToken(record.BindingID); err != nil {
		return err
	}
	if err := ValidateDeliveryMode(record.Mode); err != nil {
		return err
	}
	switch record.Mode {
	case DeliveryModeHTTPProxy, DeliveryModeSSHAgent:
		if record.TargetPath != "" || record.DeclaredFileBytes != 0 || record.FileSHA256 != [32]byte{} {
			return ErrHelperPrepareBindingModeFields
		}
	case DeliveryModeFileTmpfs:
		if record.TargetPath == "" {
			return ErrHelperPrepareBindingModeFields
		}
		if err := ValidateOptionalRelativePath(record.TargetPath); err != nil {
			return err
		}
		if record.DeclaredFileBytes == 0 || record.DeclaredFileBytes > MaxHelperFileBytes {
			return ErrHelperPrepareFileLength
		}
		if record.FileSHA256 == [32]byte{} {
			return ErrHelperPrepareFileDigest
		}
	}
	return nil
}

// EncodeHelperPrepareBeginBody returns revision, signed expiry, binding count,
// and the exact caller-ordered canonical binding records.
func EncodeHelperPrepareBeginBody(body HelperPrepareBeginBody) ([]byte, error) {
	manifest, err := encodeHelperBindingManifest(body.Bindings)
	if err != nil {
		return nil, err
	}
	if err := validateHelperPrepareRevision(body.Revision); err != nil {
		return nil, err
	}
	encoded := make([]byte, helperPrepareBeginFixedBytes+len(manifest))
	binary.BigEndian.PutUint64(encoded[0:8], body.Revision)
	binary.BigEndian.PutUint64(encoded[8:16], uint64(body.ExpiryUnixNano))
	binary.BigEndian.PutUint16(encoded[16:18], uint16(len(body.Bindings)))
	copy(encoded[18:], manifest)
	return encoded, nil
}

// DecodeHelperPrepareBeginBody strictly decodes one complete prepare-begin
// body and returns an independently owned ordered manifest.
func DecodeHelperPrepareBeginBody(encoded []byte) (HelperPrepareBeginBody, error) {
	if len(encoded) < helperPrepareBeginFixedBytes {
		return HelperPrepareBeginBody{}, ErrHelperPrepareBeginBodyLength
	}
	body := HelperPrepareBeginBody{
		Revision:       binary.BigEndian.Uint64(encoded[0:8]),
		ExpiryUnixNano: int64(binary.BigEndian.Uint64(encoded[8:16])),
	}
	if err := validateHelperPrepareRevision(body.Revision); err != nil {
		return HelperPrepareBeginBody{}, err
	}
	count := int(binary.BigEndian.Uint16(encoded[16:18]))
	if count < 1 || count > MaxHelperBindings {
		return HelperPrepareBeginBody{}, ErrHelperPrepareBindingCount
	}
	body.Bindings = make([]HelperBindingManifestRecord, count)
	offset := helperPrepareBeginFixedBytes
	for index := range body.Bindings {
		record, consumed, err := decodeHelperBindingManifestRecord(encoded[offset:])
		if err != nil {
			return HelperPrepareBeginBody{}, err
		}
		body.Bindings[index] = record
		offset += consumed
	}
	if offset != len(encoded) {
		return HelperPrepareBeginBody{}, ErrHelperPrepareBeginTrailingData
	}
	if err := validateHelperBindingManifest(body.Bindings); err != nil {
		return HelperPrepareBeginBody{}, err
	}
	return body, nil
}

// ComputeHelperManifestSHA256 hashes the exact ordered manifest encoding with
// the locked opaque16 domain and uint16 binding count.
func ComputeHelperManifestSHA256(bindings []HelperBindingManifestRecord) ([32]byte, error) {
	var digest [32]byte
	manifest, err := encodeHelperBindingManifest(bindings)
	if err != nil {
		return digest, err
	}
	domain := make([]byte, 2+len(helperManifestDomain))
	binary.BigEndian.PutUint16(domain[:2], uint16(len(helperManifestDomain)))
	copy(domain[2:], helperManifestDomain)
	hash := sha256.New()
	_, _ = hash.Write(domain)
	var count [2]byte
	binary.BigEndian.PutUint16(count[:], uint16(len(bindings)))
	_, _ = hash.Write(count[:])
	_, _ = hash.Write(manifest)
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}

// NewHelperPrepareFileBody validates and defensively copies exact private file
// bytes into an allocation whose capacity equals its length.
func NewHelperPrepareFileBody(revision uint64, bindingIndex uint16, fileSHA256 [32]byte, privateBytes []byte) (*HelperPrepareFileBody, error) {
	if err := validateHelperPrepareRevision(revision); err != nil {
		return nil, err
	}
	if bindingIndex >= MaxHelperBindings {
		return nil, ErrHelperPrepareBindingIndex
	}
	if len(privateBytes) < 1 || len(privateBytes) > MaxHelperFileBytes {
		return nil, ErrHelperPrepareFileLength
	}
	if fileSHA256 == [32]byte{} || sha256.Sum256(privateBytes) != fileSHA256 {
		return nil, ErrHelperPrepareFileDigest
	}
	owned := make([]byte, len(privateBytes))
	copy(owned, privateBytes)
	return &HelperPrepareFileBody{
		state: &helperPrepareFileState{
			revision: revision, bindingIndex: bindingIndex, fileLength: uint32(len(owned)),
			fileSHA256: fileSHA256, privateBytes: owned,
		},
	}, nil
}

// EncodeHelperPrepareFileBody returns exact metadata followed by a defensive
// wire copy of the private bytes.
func EncodeHelperPrepareFileBody(body *HelperPrepareFileBody) ([]byte, error) {
	if body == nil || body.state == nil || body.state.wiped || body.state.privateBytes == nil {
		return nil, ErrHelperPreparePrivateWiped
	}
	state := body.state
	if err := validateHelperPrepareRevision(state.revision); err != nil {
		return nil, err
	}
	if state.bindingIndex >= MaxHelperBindings {
		return nil, ErrHelperPrepareBindingIndex
	}
	if state.fileLength == 0 || state.fileLength > MaxHelperFileBytes || int(state.fileLength) != len(state.privateBytes) || cap(state.privateBytes) != len(state.privateBytes) {
		return nil, ErrHelperPrepareFileLength
	}
	if state.fileSHA256 == [32]byte{} || sha256.Sum256(state.privateBytes) != state.fileSHA256 {
		return nil, ErrHelperPrepareFileDigest
	}
	encoded := make([]byte, helperPrepareFileFixedBytes+len(state.privateBytes))
	binary.BigEndian.PutUint64(encoded[0:8], state.revision)
	binary.BigEndian.PutUint16(encoded[8:10], state.bindingIndex)
	binary.BigEndian.PutUint32(encoded[10:14], state.fileLength)
	copy(encoded[14:46], state.fileSHA256[:])
	copy(encoded[46:], state.privateBytes)
	return encoded, nil
}

// DecodeHelperPrepareFileBody strictly decodes and defensively owns one
// complete prepare-file body. The caller must Wipe the returned value.
func DecodeHelperPrepareFileBody(encoded []byte) (*HelperPrepareFileBody, error) {
	if len(encoded) < helperPrepareFileFixedBytes {
		return nil, ErrHelperPrepareFileBodyLength
	}
	revision := binary.BigEndian.Uint64(encoded[0:8])
	if err := validateHelperPrepareRevision(revision); err != nil {
		return nil, err
	}
	bindingIndex := binary.BigEndian.Uint16(encoded[8:10])
	if bindingIndex >= MaxHelperBindings {
		return nil, ErrHelperPrepareBindingIndex
	}
	fileLength := binary.BigEndian.Uint32(encoded[10:14])
	if fileLength == 0 || fileLength > MaxHelperFileBytes {
		return nil, ErrHelperPrepareFileLength
	}
	expectedLength := helperPrepareFileFixedBytes + int(fileLength)
	if len(encoded) < expectedLength {
		return nil, ErrHelperPrepareFileBodyLength
	}
	if len(encoded) > expectedLength {
		return nil, ErrHelperPrepareFileTrailingData
	}
	var fileSHA256 [32]byte
	copy(fileSHA256[:], encoded[14:46])
	return NewHelperPrepareFileBody(revision, bindingIndex, fileSHA256, encoded[46:])
}

// CopyPrivateBytes copies the complete private value or leaves destination
// untouched. It never returns a slice that aliases the owned bytes.
func (body *HelperPrepareFileBody) CopyPrivateBytes(destination []byte) (int, error) {
	if body == nil || body.state == nil || body.state.wiped || body.state.privateBytes == nil {
		return 0, ErrHelperPreparePrivateWiped
	}
	if len(destination) < len(body.state.privateBytes) {
		return 0, ErrHelperPreparePrivateDestination
	}
	return copy(destination, body.state.privateBytes), nil
}

// Revision returns the exact safe wire revision, or zero after wipe.
func (body HelperPrepareFileBody) Revision() uint64 {
	if body.state == nil || body.state.wiped {
		return 0
	}
	return body.state.revision
}

// BindingIndex returns the exact safe manifest index, or zero after wipe.
func (body HelperPrepareFileBody) BindingIndex() uint16 {
	if body.state == nil || body.state.wiped {
		return 0
	}
	return body.state.bindingIndex
}

// FileLength returns the exact private byte count, or zero after wipe.
func (body HelperPrepareFileBody) FileLength() uint32 {
	if body.state == nil || body.state.wiped {
		return 0
	}
	return body.state.fileLength
}

// FileSHA256 returns the exact private digest, or zero after wipe.
func (body HelperPrepareFileBody) FileSHA256() [32]byte {
	if body.state == nil || body.state.wiped {
		return [32]byte{}
	}
	return body.state.fileSHA256
}

// Wipe overwrites the private allocation through its full capacity, releases
// the slice, and permanently prevents copying or encoding this owner.
func (body *HelperPrepareFileBody) Wipe() {
	if body == nil || body.state == nil || body.state.wiped {
		return
	}
	state := body.state
	if state.privateBytes != nil {
		private := state.privateBytes[:cap(state.privateBytes)]
		clear(private)
		runtime.KeepAlive(private)
	}
	state.privateBytes = nil
	state.revision = 0
	state.bindingIndex = 0
	state.fileLength = 0
	state.fileSHA256 = [32]byte{}
	state.wiped = true
}

// EncodeHelperPrepareCommitBody returns revision and the fixed-width digest.
func EncodeHelperPrepareCommitBody(body HelperPrepareCommitBody) ([]byte, error) {
	if err := validateHelperPrepareRevision(body.Revision); err != nil {
		return nil, err
	}
	encoded := make([]byte, helperPrepareCommitBytes)
	binary.BigEndian.PutUint64(encoded[0:8], body.Revision)
	copy(encoded[8:40], body.ManifestSHA256[:])
	return encoded, nil
}

// DecodeHelperPrepareCommitBody strictly decodes one complete commit body.
func DecodeHelperPrepareCommitBody(encoded []byte) (HelperPrepareCommitBody, error) {
	if len(encoded) < helperPrepareCommitBytes {
		return HelperPrepareCommitBody{}, ErrHelperPrepareCommitBodyLength
	}
	if len(encoded) > helperPrepareCommitBytes {
		return HelperPrepareCommitBody{}, ErrHelperPrepareCommitTrailingData
	}
	body := HelperPrepareCommitBody{Revision: binary.BigEndian.Uint64(encoded[0:8])}
	if err := validateHelperPrepareRevision(body.Revision); err != nil {
		return HelperPrepareCommitBody{}, err
	}
	copy(body.ManifestSHA256[:], encoded[8:40])
	return body, nil
}

func validateHelperPrepareRevision(revision uint64) error {
	if revision != 1 {
		return ErrHelperPrepareRevision
	}
	return nil
}

func validateHelperBindingManifest(bindings []HelperBindingManifestRecord) error {
	if len(bindings) < 1 || len(bindings) > MaxHelperBindings {
		return ErrHelperPrepareBindingCount
	}
	httpBindings := 0
	var aggregate uint64
	for index, record := range bindings {
		if err := ValidateHelperBindingManifestRecord(record); err != nil {
			return err
		}
		if record.Mode == DeliveryModeHTTPProxy {
			httpBindings++
			if httpBindings > 1 {
				return ErrHelperPrepareHTTPBindingCount
			}
		}
		aggregate += uint64(record.DeclaredFileBytes)
		if aggregate > MaxHelperFileAggregateBytes {
			return ErrHelperPrepareFileLength
		}
		for prior := 0; prior < index; prior++ {
			if bindings[prior].BindingID == record.BindingID {
				return ErrHelperPrepareBindingDuplicate
			}
		}
	}
	return nil
}

func encodeHelperBindingManifest(bindings []HelperBindingManifestRecord) ([]byte, error) {
	if err := validateHelperBindingManifest(bindings); err != nil {
		return nil, err
	}
	encoded := make([]byte, 0, len(bindings)*48)
	for _, record := range bindings {
		bindingID, err := EncodeBodyToken(record.BindingID)
		if err != nil {
			return nil, err
		}
		targetPath, err := EncodeOptionalRelativePath(record.TargetPath)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, bindingID...)
		encoded = append(encoded, byte(record.Mode))
		encoded = append(encoded, targetPath...)
		var declared [4]byte
		binary.BigEndian.PutUint32(declared[:], record.DeclaredFileBytes)
		encoded = append(encoded, declared[:]...)
		encoded = append(encoded, record.FileSHA256[:]...)
	}
	return encoded, nil
}

func decodeHelperBindingManifestRecord(encoded []byte) (HelperBindingManifestRecord, int, error) {
	var record HelperBindingManifestRecord
	bindingID, tokenBytes, err := DecodeBodyTokenPrefix(encoded)
	if err != nil {
		return record, 0, err
	}
	offset := tokenBytes
	if len(encoded) < offset+1 {
		return record, 0, ErrHelperPrepareBeginBodyLength
	}
	record.BindingID = bindingID
	record.Mode = DeliveryMode(encoded[offset])
	offset++
	targetPath, pathBytes, err := DecodeOptionalRelativePathPrefix(encoded[offset:])
	if err != nil {
		return record, 0, err
	}
	record.TargetPath = targetPath
	offset += pathBytes
	if len(encoded) < offset+4+sha256.Size {
		return record, 0, ErrHelperPrepareBeginBodyLength
	}
	record.DeclaredFileBytes = binary.BigEndian.Uint32(encoded[offset : offset+4])
	offset += 4
	copy(record.FileSHA256[:], encoded[offset:offset+sha256.Size])
	offset += sha256.Size
	if err := ValidateHelperBindingManifestRecord(record); err != nil {
		return HelperBindingManifestRecord{}, 0, err
	}
	return record, offset, nil
}

func (HelperBindingManifestRecord) String() string   { return "HelperBindingManifestRecord" }
func (HelperBindingManifestRecord) GoString() string { return "HelperBindingManifestRecord" }
func (HelperPrepareBeginBody) String() string        { return "HelperPrepareBeginBody" }
func (HelperPrepareBeginBody) GoString() string      { return "HelperPrepareBeginBody" }
func (HelperPrepareFileBody) String() string         { return "HelperPrepareFileBody" }
func (HelperPrepareFileBody) GoString() string       { return "HelperPrepareFileBody" }
func (HelperPrepareCommitBody) String() string       { return "HelperPrepareCommitBody" }
func (HelperPrepareCommitBody) GoString() string     { return "HelperPrepareCommitBody" }

func (HelperBindingManifestRecord) Format(state fmt.State, _ rune) {
	writeHelperPrepareTypeName(state, "HelperBindingManifestRecord")
}
func (HelperPrepareBeginBody) Format(state fmt.State, _ rune) {
	writeHelperPrepareTypeName(state, "HelperPrepareBeginBody")
}
func (HelperPrepareFileBody) Format(state fmt.State, _ rune) {
	writeHelperPrepareTypeName(state, "HelperPrepareFileBody")
}
func (HelperPrepareCommitBody) Format(state fmt.State, _ rune) {
	writeHelperPrepareTypeName(state, "HelperPrepareCommitBody")
}

func writeHelperPrepareTypeName(state fmt.State, name string) { _, _ = state.Write([]byte(name)) }

func (HelperBindingManifestRecord) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (HelperBindingManifestRecord) MarshalText() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (HelperBindingManifestRecord) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (*HelperBindingManifestRecord) UnmarshalJSON([]byte) error {
	return ErrHelperPrepareBodySerialization
}
func (*HelperBindingManifestRecord) UnmarshalText([]byte) error {
	return ErrHelperPrepareBodySerialization
}
func (*HelperBindingManifestRecord) UnmarshalBinary([]byte) error {
	return ErrHelperPrepareBodySerialization
}

func (HelperPrepareBeginBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (HelperPrepareBeginBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (HelperPrepareBeginBody) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (*HelperPrepareBeginBody) UnmarshalJSON([]byte) error {
	return ErrHelperPrepareBodySerialization
}
func (*HelperPrepareBeginBody) UnmarshalText([]byte) error {
	return ErrHelperPrepareBodySerialization
}
func (*HelperPrepareBeginBody) UnmarshalBinary([]byte) error {
	return ErrHelperPrepareBodySerialization
}

func (HelperPrepareFileBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (HelperPrepareFileBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (HelperPrepareFileBody) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (body *HelperPrepareFileBody) UnmarshalJSON([]byte) error {
	return ErrHelperPrepareBodySerialization
}
func (body *HelperPrepareFileBody) UnmarshalText([]byte) error {
	return ErrHelperPrepareBodySerialization
}
func (body *HelperPrepareFileBody) UnmarshalBinary([]byte) error {
	return ErrHelperPrepareBodySerialization
}

func (HelperPrepareCommitBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (HelperPrepareCommitBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (HelperPrepareCommitBody) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperPrepareBodySerialization
}
func (*HelperPrepareCommitBody) UnmarshalJSON([]byte) error {
	return ErrHelperPrepareBodySerialization
}
func (*HelperPrepareCommitBody) UnmarshalText([]byte) error {
	return ErrHelperPrepareBodySerialization
}
func (*HelperPrepareCommitBody) UnmarshalBinary([]byte) error {
	return ErrHelperPrepareBodySerialization
}
