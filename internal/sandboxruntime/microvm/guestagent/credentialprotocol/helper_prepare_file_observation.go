package credentialprotocol

import (
	"errors"
	"fmt"
	"sync"
)

var (
	ErrHelperPrepareFileObservation      = errors.New("credential protocol helper prepare file observation is invalid")
	ErrHelperPrepareFileObservationUsed  = errors.New("credential protocol helper prepare file observation is already used")
	ErrHelperPrepareObservationSerialize = errors.New("credential protocol helper prepare file observation serialization is denied")
)

// HelperPrepareFileObservation is a copy-safe, one-use handle to canonical
// safe file metadata. It owns and exposes no private payload bytes and makes no
// claim about storage, locking, staging, publication, or live inspection.
type HelperPrepareFileObservation struct {
	owner *helperPrepareFileObservationOwner
}

type helperPrepareFileObservationOwner struct {
	mu           sync.Mutex
	revision     uint64
	bindingIndex uint16
	fileLength   uint32
	fileSHA256   [32]byte
	used         bool
}

// NewHelperPrepareFileObservation binds canonical declared metadata to the
// independently observed payload digest without retaining the payload.
func NewHelperPrepareFileObservation(revision uint64, bindingIndex uint16, fileLength uint32, fileSHA256, observedSHA256 [32]byte) (HelperPrepareFileObservation, error) {
	if revision != 1 || bindingIndex >= MaxHelperBindings || fileLength == 0 || fileLength > MaxHelperFileBytes || fileSHA256 == [32]byte{} || fileSHA256 != observedSHA256 {
		return HelperPrepareFileObservation{}, ErrHelperPrepareFileObservation
	}
	return HelperPrepareFileObservation{owner: &helperPrepareFileObservationOwner{revision: revision, bindingIndex: bindingIndex, fileLength: fileLength, fileSHA256: fileSHA256}}, nil
}

func (HelperPrepareFileObservation) String() string   { return "HelperPrepareFileObservation" }
func (HelperPrepareFileObservation) GoString() string { return "HelperPrepareFileObservation" }
func (HelperPrepareFileObservation) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("HelperPrepareFileObservation"))
}
func (HelperPrepareFileObservation) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperPrepareObservationSerialize
}
func (HelperPrepareFileObservation) MarshalText() ([]byte, error) {
	return nil, ErrHelperPrepareObservationSerialize
}
func (HelperPrepareFileObservation) MarshalBinary() ([]byte, error) {
	return nil, ErrHelperPrepareObservationSerialize
}
func (HelperPrepareFileObservation) UnmarshalJSON([]byte) error {
	return ErrHelperPrepareObservationSerialize
}
func (HelperPrepareFileObservation) UnmarshalText([]byte) error {
	return ErrHelperPrepareObservationSerialize
}
func (HelperPrepareFileObservation) UnmarshalBinary([]byte) error {
	return ErrHelperPrepareObservationSerialize
}
