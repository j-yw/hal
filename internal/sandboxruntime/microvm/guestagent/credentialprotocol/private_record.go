package credentialprotocol

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"runtime"
)

const (
	// PrivateRecordFixedHeaderBytes is the exact HL8B fixed plaintext header.
	PrivateRecordFixedHeaderBytes = 100
	// MaxPrivateRecordPayloadBytes is the exact bound for one mutable payload.
	MaxPrivateRecordPayloadBytes = 64 * 1024
	// MaxPreparePrivateRecordCount is the exact file-record count bound.
	MaxPreparePrivateRecordCount = 16
	// MaxPreparePrivateAggregateBytes is the exact prepare aggregate bound.
	MaxPreparePrivateAggregateBytes = 1024 * 1024

	privateRecordMagic   = "HL8B"
	privateRecordVersion = 1
)

// PrivateRecordKind is the closed HL8B private plaintext kind catalog.
type PrivateRecordKind uint8

const (
	PrivateRecordKindFileBytes         PrivateRecordKind = 1
	PrivateRecordKindOpaqueExecBinding PrivateRecordKind = 2
)

type privateRecordError string

func (err privateRecordError) Error() string { return string(err) }

const (
	ErrPrivateRecordMagic          privateRecordError = "credential protocol private-record magic is invalid"
	ErrPrivateRecordVersion        privateRecordError = "credential protocol private-record version is invalid"
	ErrPrivateRecordKind           privateRecordError = "credential protocol private-record kind is invalid"
	ErrPrivateRecordFlags          privateRecordError = "credential protocol private-record flags are invalid"
	ErrPrivateRecordRequestID      privateRecordError = "credential protocol private-record request ID is invalid"
	ErrPrivateRecordIdentityDigest privateRecordError = "credential protocol private-record identity digest is invalid"
	ErrPrivateRecordBindingIndex   privateRecordError = "credential protocol private-record binding index is invalid"
	ErrPrivateRecordChunk          privateRecordError = "credential protocol private-record chunk fields are invalid"
	ErrPrivateRecordReserved       privateRecordError = "credential protocol private-record reserved field is invalid"
	ErrPrivateRecordPayloadLength  privateRecordError = "credential protocol private-record payload length is invalid"
	ErrPrivateRecordPayloadDigest  privateRecordError = "credential protocol private-record payload digest is invalid"
	ErrPrivateRecordLength         privateRecordError = "credential protocol private-record length is invalid"
	ErrPrivateRecordTrailingData   privateRecordError = "credential protocol private-record has trailing data"
	ErrPrivateRecordDestination    privateRecordError = "credential protocol private-record destination is too small"
	ErrPrivateRecordWiped          privateRecordError = "credential protocol private-record is wiped"
	ErrPrivateRecordSerialization  privateRecordError = "credential protocol private-record serialization is denied"

	ErrPrivateRecordSetCount           privateRecordError = "credential protocol private-record set count is invalid"
	ErrPrivateRecordSetRequestID       privateRecordError = "credential protocol private-record set request ID does not match"
	ErrPrivateRecordSetIdentityDigest  privateRecordError = "credential protocol private-record set identity digest does not match"
	ErrPrivateRecordSetKind            privateRecordError = "credential protocol private-record set kind does not match"
	ErrPrivateRecordSetBindingOrder    privateRecordError = "credential protocol private-record set binding order does not match"
	ErrPrivateRecordSetPayload         privateRecordError = "credential protocol private-record set payload metadata does not match"
	ErrPrivateRecordSetAggregateBytes  privateRecordError = "credential protocol private-record set aggregate bytes do not match"
	ErrPrivateRecordSetAggregateDigest privateRecordError = "credential protocol private-record set aggregate digest does not match"
)

// PrivateRecord is an opaque owner for one authenticated HL8B plaintext.
// Value copies deliberately share one wipe state.
type PrivateRecord struct {
	state *privateRecordState
}

type privateRecordState struct {
	kind           PrivateRecordKind
	requestID      [16]byte
	identityDigest [32]byte
	bindingIndex   uint16
	chunkIndex     uint16
	chunkCount     uint16
	payloadLength  uint32
	payloadSHA256  [32]byte
	payload        []byte
	wiped          bool
}

// PrivateRecordSetExpectation is the exact control-plane correlation for one
// consecutive private-record set. AggregateSHA256 hashes payload bytes in
// record order; the empty set uses SHA-256 of empty bytes.
type PrivateRecordSetExpectation struct {
	RequestID       [16]byte
	IdentityDigest  [32]byte
	RecordCount     uint32
	AggregateBytes  uint64
	AggregateSHA256 [32]byte
}

// PrivateFileRecordExpectation is one exact file manifest entry selected by
// its original ordered binding index.
type PrivateFileRecordExpectation struct {
	BindingIndex  uint16
	PayloadLength uint32
	PayloadSHA256 [32]byte
}

// NewPrivateRecord validates scalar correlation and defensively owns payload.
func NewPrivateRecord(kind PrivateRecordKind, requestID [16]byte, identityDigest [32]byte, bindingIndex uint16, payload []byte) (*PrivateRecord, error) {
	if err := validatePrivateRecordMetadata(kind, requestID, identityDigest, bindingIndex, 0, 1, len(payload)); err != nil {
		return nil, err
	}
	owned := make([]byte, len(payload))
	copy(owned, payload)
	return &PrivateRecord{state: &privateRecordState{
		kind:           kind,
		requestID:      requestID,
		identityDigest: identityDigest,
		bindingIndex:   bindingIndex,
		chunkCount:     1,
		payloadLength:  uint32(len(owned)),
		payloadSHA256:  sha256.Sum256(owned),
		payload:        owned,
	}}, nil
}

// EncodePrivateRecord returns a defensive exact HL8B wire copy.
func EncodePrivateRecord(record *PrivateRecord) ([]byte, error) {
	state, err := privateRecordLiveState(record)
	if err != nil {
		return nil, err
	}
	wire := make([]byte, PrivateRecordFixedHeaderBytes+len(state.payload))
	copy(wire[0:4], privateRecordMagic)
	wire[4] = privateRecordVersion
	wire[5] = byte(state.kind)
	copy(wire[8:24], state.requestID[:])
	copy(wire[24:56], state.identityDigest[:])
	binary.BigEndian.PutUint16(wire[56:58], state.bindingIndex)
	binary.BigEndian.PutUint16(wire[58:60], state.chunkIndex)
	binary.BigEndian.PutUint16(wire[60:62], state.chunkCount)
	binary.BigEndian.PutUint32(wire[64:68], state.payloadLength)
	copy(wire[68:100], state.payloadSHA256[:])
	copy(wire[PrivateRecordFixedHeaderBytes:], state.payload)
	return wire, nil
}

// DecodePrivateRecord strictly validates one complete HL8B plaintext before
// publishing an independently owned record.
func DecodePrivateRecord(wire []byte) (*PrivateRecord, error) {
	if len(wire) < PrivateRecordFixedHeaderBytes {
		return nil, ErrPrivateRecordLength
	}
	if string(wire[0:4]) != privateRecordMagic {
		return nil, ErrPrivateRecordMagic
	}
	if wire[4] != privateRecordVersion {
		return nil, ErrPrivateRecordVersion
	}
	kind := PrivateRecordKind(wire[5])
	if kind != PrivateRecordKindFileBytes && kind != PrivateRecordKindOpaqueExecBinding {
		return nil, ErrPrivateRecordKind
	}
	if binary.BigEndian.Uint16(wire[6:8]) != 0 {
		return nil, ErrPrivateRecordFlags
	}
	var requestID [16]byte
	copy(requestID[:], wire[8:24])
	if requestID == [16]byte{} {
		return nil, ErrPrivateRecordRequestID
	}
	var identityDigest [32]byte
	copy(identityDigest[:], wire[24:56])
	if identityDigest == [32]byte{} {
		return nil, ErrPrivateRecordIdentityDigest
	}
	bindingIndex := binary.BigEndian.Uint16(wire[56:58])
	chunkIndex := binary.BigEndian.Uint16(wire[58:60])
	chunkCount := binary.BigEndian.Uint16(wire[60:62])
	if chunkIndex != 0 || chunkCount != 1 {
		return nil, ErrPrivateRecordChunk
	}
	if binary.BigEndian.Uint16(wire[62:64]) != 0 {
		return nil, ErrPrivateRecordReserved
	}
	payloadLength := binary.BigEndian.Uint32(wire[64:68])
	if payloadLength == 0 || payloadLength > MaxPrivateRecordPayloadBytes {
		return nil, ErrPrivateRecordPayloadLength
	}
	expectedLength := PrivateRecordFixedHeaderBytes + int(payloadLength)
	if len(wire) < expectedLength {
		return nil, ErrPrivateRecordLength
	}
	if len(wire) > expectedLength {
		return nil, ErrPrivateRecordTrailingData
	}
	if kind == PrivateRecordKindOpaqueExecBinding && bindingIndex != 0 {
		return nil, ErrPrivateRecordBindingIndex
	}
	var payloadDigest [32]byte
	copy(payloadDigest[:], wire[68:100])
	if payloadDigest == [32]byte{} || sha256.Sum256(wire[PrivateRecordFixedHeaderBytes:]) != payloadDigest {
		return nil, ErrPrivateRecordPayloadDigest
	}

	record, err := NewPrivateRecord(kind, requestID, identityDigest, bindingIndex, wire[PrivateRecordFixedHeaderBytes:])
	if err != nil {
		return nil, err
	}
	if record.state.payloadSHA256 != payloadDigest {
		record.Wipe()
		return nil, ErrPrivateRecordPayloadDigest
	}
	return record, nil
}

// ValidatePreparePrivateRecords correlates one complete prepare transaction.
// Records must be one-per-file in strictly ascending original manifest index.
func ValidatePreparePrivateRecords(records []*PrivateRecord, files []PrivateFileRecordExpectation, expected PrivateRecordSetExpectation) error {
	if expected.RecordCount != uint32(len(records)) || len(records) != len(files) || len(records) > MaxPreparePrivateRecordCount {
		return ErrPrivateRecordSetCount
	}
	if expected.AggregateBytes > MaxPreparePrivateAggregateBytes {
		return ErrPrivateRecordSetAggregateBytes
	}
	for index, file := range files {
		if file.BindingIndex >= MaxPreparePrivateRecordCount || (index != 0 && file.BindingIndex <= files[index-1].BindingIndex) {
			return ErrPrivateRecordSetBindingOrder
		}
		if file.PayloadLength == 0 || file.PayloadLength > MaxPrivateRecordPayloadBytes || file.PayloadSHA256 == [32]byte{} {
			return ErrPrivateRecordSetPayload
		}
	}
	return validatePrivateRecordSet(records, PrivateRecordKindFileBytes, files, expected, MaxPreparePrivateAggregateBytes)
}

// ValidateExecPrivateRecords correlates the exact optional HTTP exec binding.
// HTTP requires exactly one kind-2 record; its absence forbids all records.
func ValidateExecPrivateRecords(records []*PrivateRecord, httpPrepared bool, expected PrivateRecordSetExpectation) error {
	requiredCount := uint32(0)
	if httpPrepared {
		requiredCount = 1
	}
	if expected.RecordCount != requiredCount || uint32(len(records)) != requiredCount {
		return ErrPrivateRecordSetCount
	}
	return validatePrivateRecordSet(records, PrivateRecordKindOpaqueExecBinding, nil, expected, MaxPrivateRecordPayloadBytes)
}

func validatePrivateRecordSet(records []*PrivateRecord, kind PrivateRecordKind, files []PrivateFileRecordExpectation, expected PrivateRecordSetExpectation, maximumAggregate uint64) error {
	if expected.RequestID == [16]byte{} {
		return ErrPrivateRecordSetRequestID
	}
	if expected.IdentityDigest == [32]byte{} {
		return ErrPrivateRecordSetIdentityDigest
	}
	if expected.AggregateBytes > maximumAggregate {
		return ErrPrivateRecordSetAggregateBytes
	}
	hash := sha256.New()
	var aggregate uint64
	for index, record := range records {
		state, err := privateRecordLiveState(record)
		if err != nil {
			return ErrPrivateRecordSetPayload
		}
		if state.requestID != expected.RequestID {
			return ErrPrivateRecordSetRequestID
		}
		if state.identityDigest != expected.IdentityDigest {
			return ErrPrivateRecordSetIdentityDigest
		}
		if state.kind != kind {
			return ErrPrivateRecordSetKind
		}
		if kind == PrivateRecordKindFileBytes {
			file := files[index]
			if state.bindingIndex != file.BindingIndex {
				return ErrPrivateRecordSetBindingOrder
			}
			if state.payloadLength != file.PayloadLength || state.payloadSHA256 != file.PayloadSHA256 {
				return ErrPrivateRecordSetPayload
			}
		} else if state.bindingIndex != 0 {
			return ErrPrivateRecordSetBindingOrder
		}
		aggregate += uint64(state.payloadLength)
		if aggregate > maximumAggregate {
			return ErrPrivateRecordSetAggregateBytes
		}
		_, _ = hash.Write(state.payload)
	}
	if aggregate != expected.AggregateBytes {
		return ErrPrivateRecordSetAggregateBytes
	}
	var aggregateDigest [32]byte
	copy(aggregateDigest[:], hash.Sum(nil))
	if aggregateDigest != expected.AggregateSHA256 {
		return ErrPrivateRecordSetAggregateDigest
	}
	return nil
}

func privateRecordLiveState(record *PrivateRecord) (*privateRecordState, error) {
	if record == nil || record.state == nil || record.state.wiped || record.state.payload == nil {
		return nil, ErrPrivateRecordWiped
	}
	state := record.state
	if err := validatePrivateRecordMetadata(state.kind, state.requestID, state.identityDigest, state.bindingIndex, state.chunkIndex, state.chunkCount, len(state.payload)); err != nil {
		return nil, err
	}
	if state.payloadLength != uint32(len(state.payload)) || cap(state.payload) != len(state.payload) {
		return nil, ErrPrivateRecordPayloadLength
	}
	if state.payloadSHA256 == [32]byte{} || sha256.Sum256(state.payload) != state.payloadSHA256 {
		return nil, ErrPrivateRecordPayloadDigest
	}
	return state, nil
}

func validatePrivateRecordMetadata(kind PrivateRecordKind, requestID [16]byte, identityDigest [32]byte, bindingIndex uint16, chunkIndex uint16, chunkCount uint16, payloadLength int) error {
	if kind != PrivateRecordKindFileBytes && kind != PrivateRecordKindOpaqueExecBinding {
		return ErrPrivateRecordKind
	}
	if requestID == [16]byte{} {
		return ErrPrivateRecordRequestID
	}
	if identityDigest == [32]byte{} {
		return ErrPrivateRecordIdentityDigest
	}
	if kind == PrivateRecordKindFileBytes && bindingIndex >= MaxPreparePrivateRecordCount {
		return ErrPrivateRecordBindingIndex
	}
	if kind == PrivateRecordKindOpaqueExecBinding && bindingIndex != 0 {
		return ErrPrivateRecordBindingIndex
	}
	if chunkIndex != 0 || chunkCount != 1 {
		return ErrPrivateRecordChunk
	}
	if payloadLength < 1 || payloadLength > MaxPrivateRecordPayloadBytes {
		return ErrPrivateRecordPayloadLength
	}
	return nil
}

// CopyPayload copies the complete payload or leaves destination untouched.
func (record *PrivateRecord) CopyPayload(destination []byte) (int, error) {
	state, err := privateRecordLiveState(record)
	if err != nil {
		return 0, err
	}
	if len(destination) < len(state.payload) {
		return 0, ErrPrivateRecordDestination
	}
	return copy(destination, state.payload), nil
}

func (record PrivateRecord) Kind() PrivateRecordKind {
	if record.state == nil || record.state.wiped {
		return 0
	}
	return record.state.kind
}
func (record PrivateRecord) RequestID() [16]byte {
	if record.state == nil || record.state.wiped {
		return [16]byte{}
	}
	return record.state.requestID
}
func (record PrivateRecord) IdentityDigest() [32]byte {
	if record.state == nil || record.state.wiped {
		return [32]byte{}
	}
	return record.state.identityDigest
}
func (record PrivateRecord) BindingIndex() uint16 {
	if record.state == nil || record.state.wiped {
		return 0
	}
	return record.state.bindingIndex
}
func (record PrivateRecord) ChunkIndex() uint16 {
	if record.state == nil || record.state.wiped {
		return 0
	}
	return record.state.chunkIndex
}
func (record PrivateRecord) ChunkCount() uint16 {
	if record.state == nil || record.state.wiped {
		return 0
	}
	return record.state.chunkCount
}
func (record PrivateRecord) PayloadLength() uint32 {
	if record.state == nil || record.state.wiped {
		return 0
	}
	return record.state.payloadLength
}
func (record PrivateRecord) PayloadSHA256() [32]byte {
	if record.state == nil || record.state.wiped {
		return [32]byte{}
	}
	return record.state.payloadSHA256
}

// Wipe overwrites the full private capacity and invalidates every value alias.
func (record *PrivateRecord) Wipe() {
	if record == nil || record.state == nil || record.state.wiped {
		return
	}
	state := record.state
	if state.payload != nil {
		payload := state.payload[:cap(state.payload)]
		clear(payload)
		runtime.KeepAlive(payload)
	}
	state.payload = nil
	state.kind = 0
	state.requestID = [16]byte{}
	state.identityDigest = [32]byte{}
	state.bindingIndex = 0
	state.chunkIndex = 0
	state.chunkCount = 0
	state.payloadLength = 0
	state.payloadSHA256 = [32]byte{}
	state.wiped = true
}

func (PrivateRecord) String() string   { return "PrivateRecord" }
func (PrivateRecord) GoString() string { return "PrivateRecord" }
func (PrivateRecord) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("PrivateRecord"))
}

func (PrivateRecord) MarshalJSON() ([]byte, error)   { return nil, ErrPrivateRecordSerialization }
func (PrivateRecord) MarshalText() ([]byte, error)   { return nil, ErrPrivateRecordSerialization }
func (PrivateRecord) MarshalBinary() ([]byte, error) { return nil, ErrPrivateRecordSerialization }
func (*PrivateRecord) UnmarshalJSON([]byte) error    { return ErrPrivateRecordSerialization }
func (*PrivateRecord) UnmarshalText([]byte) error    { return ErrPrivateRecordSerialization }
func (*PrivateRecord) UnmarshalBinary([]byte) error  { return ErrPrivateRecordSerialization }
