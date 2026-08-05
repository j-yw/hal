package credentialprotocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	helperRenewBodyFixedBytes  = 16
	helperRevokeBodyBytes      = 9
	helperEventBodyFixedBytes  = 9
	helperCloseNotifyBodyBytes = 1
)

var (
	ErrHelperLifecycleRevision           = errors.New("credential protocol helper lifecycle revision is invalid")
	ErrHelperRenewBodyLength             = errors.New("credential protocol helper renew body length is invalid")
	ErrHelperRenewBodyTrailingData       = errors.New("credential protocol helper renew body has trailing data")
	ErrHelperRevokeBodyLength            = errors.New("credential protocol helper revoke body length is invalid")
	ErrHelperRevokeBodyTrailingData      = errors.New("credential protocol helper revoke body has trailing data")
	ErrHelperEventBodyLength             = errors.New("credential protocol helper event body length is invalid")
	ErrHelperEventBodyTrailingData       = errors.New("credential protocol helper event body has trailing data")
	ErrHelperCloseNotifyBodyLength       = errors.New("credential protocol helper close-notify body length is invalid")
	ErrHelperCloseNotifyBodyTrailingData = errors.New("credential protocol helper close-notify body has trailing data")
	ErrHelperLifecycleBodySerialization  = errors.New("credential protocol helper lifecycle body serialization is denied")
)

// HelperRenewBody is the exact safe body for PacketTypeRenew. ExpiryUnixNano
// is a signed wire timestamp; lifecycle state, not this codec, owns expiry
// policy.
type HelperRenewBody struct {
	Revision       uint64
	ExpiryUnixNano int64
	PriorProofID   string
}

// HelperRevokeBody is the exact safe body for PacketTypeRevoke.
type HelperRevokeBody struct {
	Revision uint64
	Reason   RevokeReason
}

// HelperEventBody is the exact safe body for PacketTypeEvent.
type HelperEventBody struct {
	Code     EventCode
	Revision uint64
	EventID  string
}

// HelperCloseNotifyBody is the exact safe body for PacketTypeCloseNotify.
type HelperCloseNotifyBody struct {
	Reason CloseReason
}

// EncodeHelperRenewBody returns revision:u64, expiryUnixNano:i64, then the
// canonical body-token encoding of priorProofID.
func EncodeHelperRenewBody(body HelperRenewBody) ([]byte, error) {
	if err := validateHelperLifecycleRevision(body.Revision); err != nil {
		return nil, err
	}
	proofID, err := EncodeBodyToken(body.PriorProofID)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, helperRenewBodyFixedBytes+len(proofID))
	binary.BigEndian.PutUint64(encoded[0:8], body.Revision)
	binary.BigEndian.PutUint64(encoded[8:16], uint64(body.ExpiryUnixNano))
	copy(encoded[16:], proofID)
	return encoded, nil
}

// DecodeHelperRenewBody strictly decodes one complete renew body.
func DecodeHelperRenewBody(encoded []byte) (HelperRenewBody, error) {
	if len(encoded) < helperRenewBodyFixedBytes+2 {
		return HelperRenewBody{}, ErrHelperRenewBodyLength
	}
	proofID, consumed, err := DecodeBodyTokenPrefix(encoded[helperRenewBodyFixedBytes:])
	if err != nil {
		return HelperRenewBody{}, helperLifecycleTokenDecodeError(ErrHelperRenewBodyLength, err)
	}
	if helperRenewBodyFixedBytes+consumed != len(encoded) {
		return HelperRenewBody{}, ErrHelperRenewBodyTrailingData
	}
	body := HelperRenewBody{
		Revision:       binary.BigEndian.Uint64(encoded[0:8]),
		ExpiryUnixNano: int64(binary.BigEndian.Uint64(encoded[8:16])),
		PriorProofID:   proofID,
	}
	if err := validateHelperLifecycleRevision(body.Revision); err != nil {
		return HelperRenewBody{}, err
	}
	return body, nil
}

// EncodeHelperRevokeBody returns revision:u64 followed by the closed reason.
func EncodeHelperRevokeBody(body HelperRevokeBody) ([]byte, error) {
	if err := validateHelperLifecycleRevision(body.Revision); err != nil {
		return nil, err
	}
	if err := ValidateRevokeReason(body.Reason); err != nil {
		return nil, err
	}
	encoded := make([]byte, helperRevokeBodyBytes)
	binary.BigEndian.PutUint64(encoded[0:8], body.Revision)
	encoded[8] = byte(body.Reason)
	return encoded, nil
}

// DecodeHelperRevokeBody strictly decodes one complete revoke body.
func DecodeHelperRevokeBody(encoded []byte) (HelperRevokeBody, error) {
	if len(encoded) < helperRevokeBodyBytes {
		return HelperRevokeBody{}, ErrHelperRevokeBodyLength
	}
	if len(encoded) > helperRevokeBodyBytes {
		return HelperRevokeBody{}, ErrHelperRevokeBodyTrailingData
	}
	body := HelperRevokeBody{
		Revision: binary.BigEndian.Uint64(encoded[0:8]),
		Reason:   RevokeReason(encoded[8]),
	}
	if err := validateHelperLifecycleRevision(body.Revision); err != nil {
		return HelperRevokeBody{}, err
	}
	if err := ValidateRevokeReason(body.Reason); err != nil {
		return HelperRevokeBody{}, err
	}
	return body, nil
}

// EncodeHelperEventBody returns eventCode:u8, revision:u64, then the canonical
// body-token encoding of eventID.
func EncodeHelperEventBody(body HelperEventBody) ([]byte, error) {
	if err := ValidateEventCode(body.Code); err != nil {
		return nil, err
	}
	if err := validateHelperLifecycleRevision(body.Revision); err != nil {
		return nil, err
	}
	eventID, err := EncodeBodyToken(body.EventID)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, helperEventBodyFixedBytes+len(eventID))
	encoded[0] = byte(body.Code)
	binary.BigEndian.PutUint64(encoded[1:9], body.Revision)
	copy(encoded[9:], eventID)
	return encoded, nil
}

// DecodeHelperEventBody strictly decodes one complete event body.
func DecodeHelperEventBody(encoded []byte) (HelperEventBody, error) {
	if len(encoded) < helperEventBodyFixedBytes+2 {
		return HelperEventBody{}, ErrHelperEventBodyLength
	}
	eventID, consumed, err := DecodeBodyTokenPrefix(encoded[helperEventBodyFixedBytes:])
	if err != nil {
		return HelperEventBody{}, helperLifecycleTokenDecodeError(ErrHelperEventBodyLength, err)
	}
	if helperEventBodyFixedBytes+consumed != len(encoded) {
		return HelperEventBody{}, ErrHelperEventBodyTrailingData
	}
	body := HelperEventBody{
		Code:     EventCode(encoded[0]),
		Revision: binary.BigEndian.Uint64(encoded[1:9]),
		EventID:  eventID,
	}
	if err := ValidateEventCode(body.Code); err != nil {
		return HelperEventBody{}, err
	}
	if err := validateHelperLifecycleRevision(body.Revision); err != nil {
		return HelperEventBody{}, err
	}
	return body, nil
}

// EncodeHelperCloseNotifyBody returns the sole closed reason byte.
func EncodeHelperCloseNotifyBody(body HelperCloseNotifyBody) ([]byte, error) {
	if err := ValidateCloseReason(body.Reason); err != nil {
		return nil, err
	}
	return []byte{byte(body.Reason)}, nil
}

// DecodeHelperCloseNotifyBody strictly decodes one complete close-notify body.
func DecodeHelperCloseNotifyBody(encoded []byte) (HelperCloseNotifyBody, error) {
	if len(encoded) < helperCloseNotifyBodyBytes {
		return HelperCloseNotifyBody{}, ErrHelperCloseNotifyBodyLength
	}
	if len(encoded) > helperCloseNotifyBodyBytes {
		return HelperCloseNotifyBody{}, ErrHelperCloseNotifyBodyTrailingData
	}
	body := HelperCloseNotifyBody{Reason: CloseReason(encoded[0])}
	if err := ValidateCloseReason(body.Reason); err != nil {
		return HelperCloseNotifyBody{}, err
	}
	return body, nil
}

func validateHelperLifecycleRevision(revision uint64) error {
	if revision == 0 {
		return ErrHelperLifecycleRevision
	}
	return nil
}

func helperLifecycleTokenDecodeError(bodyLengthError, tokenError error) error {
	if errors.Is(tokenError, ErrBodyTokenEncoding) {
		return fmt.Errorf("%w: %w", bodyLengthError, tokenError)
	}
	return tokenError
}

func (HelperRenewBody) String() string         { return "HelperRenewBody" }
func (HelperRenewBody) GoString() string       { return "HelperRenewBody" }
func (HelperRevokeBody) String() string        { return "HelperRevokeBody" }
func (HelperRevokeBody) GoString() string      { return "HelperRevokeBody" }
func (HelperEventBody) String() string         { return "HelperEventBody" }
func (HelperEventBody) GoString() string       { return "HelperEventBody" }
func (HelperCloseNotifyBody) String() string   { return "HelperCloseNotifyBody" }
func (HelperCloseNotifyBody) GoString() string { return "HelperCloseNotifyBody" }

func (HelperRenewBody) Format(state fmt.State, _ rune) {
	writeHelperLifecycleBodyName(state, "HelperRenewBody")
}

func (HelperRevokeBody) Format(state fmt.State, _ rune) {
	writeHelperLifecycleBodyName(state, "HelperRevokeBody")
}

func (HelperEventBody) Format(state fmt.State, _ rune) {
	writeHelperLifecycleBodyName(state, "HelperEventBody")
}

func (HelperCloseNotifyBody) Format(state fmt.State, _ rune) {
	writeHelperLifecycleBodyName(state, "HelperCloseNotifyBody")
}

func writeHelperLifecycleBodyName(state fmt.State, name string) {
	_, _ = state.Write([]byte(name))
}

func (HelperRenewBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperLifecycleBodySerialization
}

func (HelperRenewBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperLifecycleBodySerialization
}

func (*HelperRenewBody) UnmarshalJSON([]byte) error {
	return ErrHelperLifecycleBodySerialization
}

func (*HelperRenewBody) UnmarshalText([]byte) error {
	return ErrHelperLifecycleBodySerialization
}

func (HelperRevokeBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperLifecycleBodySerialization
}

func (HelperRevokeBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperLifecycleBodySerialization
}

func (*HelperRevokeBody) UnmarshalJSON([]byte) error {
	return ErrHelperLifecycleBodySerialization
}

func (*HelperRevokeBody) UnmarshalText([]byte) error {
	return ErrHelperLifecycleBodySerialization
}

func (HelperEventBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperLifecycleBodySerialization
}

func (HelperEventBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperLifecycleBodySerialization
}

func (*HelperEventBody) UnmarshalJSON([]byte) error {
	return ErrHelperLifecycleBodySerialization
}

func (*HelperEventBody) UnmarshalText([]byte) error {
	return ErrHelperLifecycleBodySerialization
}

func (HelperCloseNotifyBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperLifecycleBodySerialization
}

func (HelperCloseNotifyBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperLifecycleBodySerialization
}

func (*HelperCloseNotifyBody) UnmarshalJSON([]byte) error {
	return ErrHelperLifecycleBodySerialization
}

func (*HelperCloseNotifyBody) UnmarshalText([]byte) error {
	return ErrHelperLifecycleBodySerialization
}
