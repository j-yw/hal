package l8composition

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	controllerMonitorPrepareFileBodyPrefixBytes = 46
	ControllerMonitorPrepareFilePrefixBytes     = ControllerMonitorHeaderBytes + controllerMonitorPrepareFileBodyPrefixBytes
	ControllerMonitorPrepareFileSlotBytes       = ControllerMonitorHeaderBytes + controllerMonitorPrepareFileMaxBytes
)

var (
	ErrControllerMonitorPrepareFileSlot            = errors.New("L8 controller-monitor prepare file slot is invalid")
	ErrControllerMonitorPrepareFileSlotLength      = errors.New("L8 controller-monitor prepare file slot length is invalid")
	ErrControllerMonitorPrepareFileSlotRequired    = errors.New("L8 controller-monitor prepare file requires the fixed slot path")
	ErrControllerMonitorPrepareFileObservation     = errors.New("L8 controller-monitor prepare file observation is invalid")
	ErrControllerMonitorPrepareFileObservationUsed = errors.New("L8 controller-monitor prepare file observation is already used")
)

// ControllerMonitorPrepareFileSlot is the maximum complete 0x11 datagram.
// D4 owns locking, receive/send, wiping, unlocking, and unmapping it.
type ControllerMonitorPrepareFileSlot [ControllerMonitorPrepareFileSlotBytes]byte

func (ControllerMonitorPrepareFileSlot) String() string {
	return "ControllerMonitorPrepareFileSlot"
}
func (ControllerMonitorPrepareFileSlot) GoString() string {
	return "ControllerMonitorPrepareFileSlot"
}
func (ControllerMonitorPrepareFileSlot) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorPrepareFileSlot")
}
func (ControllerMonitorPrepareFileSlot) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPrepareFileSlot) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPrepareFileSlot) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPrepareFileSlot) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (ControllerMonitorPrepareFileSlot) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (ControllerMonitorPrepareFileSlot) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}

// ControllerMonitorPrepareFileObservation is a one-use, copy-safe handle to
// canonical safe metadata. It retains no slot pointer or private payload.
type ControllerMonitorPrepareFileObservation struct {
	owner *controllerMonitorPrepareFileObservationOwner
}

type controllerMonitorPrepareFileObservationOwner struct {
	mu     sync.Mutex
	header ControllerMonitorHeader
	helper credentialprotocol.HelperPrepareFileObservation
	used   bool
}

// EncodeControllerMonitorPrepareFilePrefix writes only the safe complete
// header and fixed helper prefix. D4 appends the separately filled and hashed
// payload in its already-locked transmit slot.
func EncodeControllerMonitorPrepareFilePrefix(header ControllerMonitorHeader, revision uint64, bindingIndex uint16, fileLength uint32, fileSHA256 [32]byte) ([ControllerMonitorPrepareFilePrefixBytes]byte, error) {
	var encoded [ControllerMonitorPrepareFilePrefixBytes]byte
	if header.Type != ControllerMonitorPacketTypePrepareFile || header.BodyLength != controllerMonitorPrepareFileBodyPrefixBytes+fileLength || revision != 1 || bindingIndex >= credentialprotocol.MaxHelperBindings || fileLength == 0 || fileLength > credentialprotocol.MaxHelperFileBytes || fileSHA256 == [32]byte{} {
		return encoded, ErrControllerMonitorPrepareFileSlot
	}
	wireHeader, err := EncodeControllerMonitorHeader(header)
	if err != nil {
		return encoded, err
	}
	copy(encoded[:ControllerMonitorHeaderBytes], wireHeader[:])
	binary.BigEndian.PutUint64(encoded[ControllerMonitorHeaderBytes:ControllerMonitorHeaderBytes+8], revision)
	binary.BigEndian.PutUint16(encoded[ControllerMonitorHeaderBytes+8:ControllerMonitorHeaderBytes+10], bindingIndex)
	binary.BigEndian.PutUint32(encoded[ControllerMonitorHeaderBytes+10:ControllerMonitorHeaderBytes+14], fileLength)
	copy(encoded[ControllerMonitorHeaderBytes+14:], fileSHA256[:])
	return encoded, nil
}

// InspectControllerMonitorPrepareFileSlot validates one complete 0x11
// datagram in place. It hashes the payload directly in the caller-owned slot
// and retains only safe canonical correlation metadata.
func InspectControllerMonitorPrepareFileSlot(slot *ControllerMonitorPrepareFileSlot, receivedBytes uint32) (ControllerMonitorPrepareFileObservation, error) {
	if slot == nil {
		return ControllerMonitorPrepareFileObservation{}, ErrControllerMonitorPrepareFileSlot
	}
	if receivedBytes < ControllerMonitorPrepareFilePrefixBytes+1 || receivedBytes > ControllerMonitorPrepareFileSlotBytes {
		return ControllerMonitorPrepareFileObservation{}, ErrControllerMonitorPrepareFileSlotLength
	}
	header, err := DecodeControllerMonitorHeader(slot[:ControllerMonitorHeaderBytes])
	if err != nil {
		return ControllerMonitorPrepareFileObservation{}, err
	}
	if header.Type != ControllerMonitorPacketTypePrepareFile || header.BodyLength < controllerMonitorPrepareFileMinBytes || header.BodyLength > controllerMonitorPrepareFileMaxBytes || uint32(ControllerMonitorHeaderBytes)+header.BodyLength != receivedBytes {
		return ControllerMonitorPrepareFileObservation{}, ErrControllerMonitorPrepareFileSlotLength
	}
	offset := ControllerMonitorHeaderBytes
	revision := binary.BigEndian.Uint64(slot[offset : offset+8])
	bindingIndex := binary.BigEndian.Uint16(slot[offset+8 : offset+10])
	fileLength := binary.BigEndian.Uint32(slot[offset+10 : offset+14])
	var declared [32]byte
	copy(declared[:], slot[offset+14:offset+controllerMonitorPrepareFileBodyPrefixBytes])
	if revision != 1 || bindingIndex >= credentialprotocol.MaxHelperBindings || fileLength == 0 || fileLength > credentialprotocol.MaxHelperFileBytes || declared == [32]byte{} || header.BodyLength != controllerMonitorPrepareFileBodyPrefixBytes+fileLength || receivedBytes != ControllerMonitorPrepareFilePrefixBytes+fileLength {
		return ControllerMonitorPrepareFileObservation{}, ErrControllerMonitorPrepareFileSlot
	}
	observed := sha256.Sum256(slot[ControllerMonitorPrepareFilePrefixBytes:receivedBytes])
	helper, err := credentialprotocol.NewHelperPrepareFileObservation(revision, bindingIndex, fileLength, declared, observed)
	if err != nil {
		return ControllerMonitorPrepareFileObservation{}, ErrControllerMonitorPrepareFileSlot
	}
	return ControllerMonitorPrepareFileObservation{owner: &controllerMonitorPrepareFileObservationOwner{header: header, helper: helper}}, nil
}

func (ControllerMonitorPrepareFileObservation) String() string {
	return "ControllerMonitorPrepareFileObservation"
}
func (ControllerMonitorPrepareFileObservation) GoString() string {
	return "ControllerMonitorPrepareFileObservation"
}
func (ControllerMonitorPrepareFileObservation) Format(state fmt.State, _ rune) {
	controllerMonitorFormat(state, "ControllerMonitorPrepareFileObservation")
}
func (ControllerMonitorPrepareFileObservation) MarshalJSON() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPrepareFileObservation) MarshalText() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPrepareFileObservation) MarshalBinary() ([]byte, error) {
	return controllerMonitorMarshalDenied()
}
func (ControllerMonitorPrepareFileObservation) UnmarshalJSON(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (ControllerMonitorPrepareFileObservation) UnmarshalText(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
func (ControllerMonitorPrepareFileObservation) UnmarshalBinary(value []byte) error {
	return controllerMonitorUnmarshalDenied(value)
}
