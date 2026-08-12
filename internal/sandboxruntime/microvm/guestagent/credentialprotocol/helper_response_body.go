package credentialprotocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	helperResponseCommonBytes     = 11
	helperExecResponseResultBytes = 158

	// MaxHelperBindings is the exact HL8P prepare binding/proof-count bound.
	MaxHelperBindings = 16
)

var (
	ErrHelperResponseRevision          = errors.New("credential protocol helper response revision is invalid")
	ErrHelperResponseBodyLength        = errors.New("credential protocol helper response body length is invalid")
	ErrHelperResponseBodyTrailingData  = errors.New("credential protocol helper response body has trailing data")
	ErrHelperResponseMatrix            = errors.New("credential protocol helper response matrix is invalid")
	ErrHelperResponseResult            = errors.New("credential protocol helper response result is invalid")
	ErrHelperResponseBoolean           = errors.New("credential protocol helper response boolean is invalid")
	ErrHelperResponseBindingCount      = errors.New("credential protocol helper response binding count is invalid")
	ErrHelperResponseBindingProof      = errors.New("credential protocol helper response binding proof is invalid")
	ErrHelperResponseExitCode          = errors.New("credential protocol helper response exit code is invalid")
	ErrUnknownHelperCleanupDisposition = errors.New("credential protocol helper cleanup disposition is unknown")
	ErrHelperResponseBodySerialization = errors.New("credential protocol helper response body serialization is denied")
)

// HelperResponseBody is the closed PacketTypeResponse body union. Exactly one
// typed result is present on success; every failure has no result arm.
type HelperResponseBody struct {
	RequestType PacketType
	Disposition ResponseDisposition
	Revision    uint64
	FailureCode FailureCode
	Prepare     *HelperPrepareResponseResult
	Renew       *HelperRenewResponseResult
	Revoke      *HelperRevokeResponseResult
	Exec        *HelperExecResponseResult
}

// HelperBindingProof is one manifest-ordered prepare proof.
type HelperBindingProof struct {
	BindingID string
	Mode      DeliveryMode
	ProofID   string
}

// HelperPrepareResponseResult is the exact accepted prepare result.
type HelperPrepareResponseResult struct {
	ExpiresAtUnixNano int64
	ActiveProofID     string
	ExecBindingID     string
	BindingProofs     []HelperBindingProof
}

// HelperRenewResponseResult is the exact accepted renew result.
type HelperRenewResponseResult struct {
	ExpiresAtUnixNano        int64
	ReplacementActiveProofID string
}

// HelperRevokeResponseResult is the exact cleanup-complete revoke result.
type HelperRevokeResponseResult struct {
	CleanupProofID  string
	AuthorityAbsent bool
	ResourcesAbsent bool
}

// HelperExecResponseResult is the exact accepted exec result.
type HelperExecResponseResult struct {
	ExitCode              int32
	StdinBytes            uint64
	StdinSHA256           [32]byte
	StdoutBytes           uint64
	StdoutSHA256          [32]byte
	StdoutTruncated       bool
	StderrBytes           uint64
	StderrSHA256          [32]byte
	StderrTruncated       bool
	ExecTransactionSHA256 [32]byte
}

// HelperCleanupDisposition is the neutral cleanup result mapped from the
// closed numeric wire disposition.
type HelperCleanupDisposition string

const (
	HelperCleanupComplete       HelperCleanupDisposition = "cleanup_complete"
	HelperCleanupRetryRequired  HelperCleanupDisposition = "retry_required"
	HelperCleanupStopVMRequired HelperCleanupDisposition = "stop_vm_required"
)

func (value HelperCleanupDisposition) String() string {
	if ValidateHelperCleanupDisposition(value) != nil {
		return "unknown"
	}
	return string(value)
}

// ValidateHelperCleanupDisposition rejects empty and unknown neutral values.
func ValidateHelperCleanupDisposition(value HelperCleanupDisposition) error {
	switch value {
	case HelperCleanupComplete, HelperCleanupRetryRequired, HelperCleanupStopVMRequired:
		return nil
	default:
		return ErrUnknownHelperCleanupDisposition
	}
}

// MapHelperCleanupDisposition maps only the three cleanup wire dispositions.
func MapHelperCleanupDisposition(value ResponseDisposition) (HelperCleanupDisposition, error) {
	switch value {
	case ResponseDispositionCleanupComplete:
		return HelperCleanupComplete, nil
	case ResponseDispositionCleanupRetry:
		return HelperCleanupRetryRequired, nil
	case ResponseDispositionStopVMRequired:
		return HelperCleanupStopVMRequired, nil
	default:
		return "", ErrUnknownHelperCleanupDisposition
	}
}

// ValidateHelperResponseBody validates the closed request, disposition,
// operation-specific failure, and exact typed-result matrix without encoding.
func ValidateHelperResponseBody(body HelperResponseBody) error {
	if err := validateHelperResponseCommon(body); err != nil {
		return err
	}

	armCount := helperResponseArmCount(body)
	switch body.Disposition {
	case ResponseDispositionAccepted:
		if armCount != 1 || !helperResponseHasExpectedArm(body) {
			return ErrHelperResponseResult
		}
	case ResponseDispositionCleanupComplete:
		if armCount != 1 || body.Revoke == nil {
			return ErrHelperResponseResult
		}
	case ResponseDispositionRejected, ResponseDispositionCleanupRetry, ResponseDispositionStopVMRequired:
		if armCount != 0 {
			return ErrHelperResponseResult
		}
	}

	switch {
	case body.Prepare != nil:
		return validateHelperPrepareResponseResult(*body.Prepare)
	case body.Renew != nil:
		return validateHelperRenewResponseResult(*body.Renew)
	case body.Revoke != nil:
		return validateHelperRevokeResponseResult(*body.Revoke)
	case body.Exec != nil:
		return validateHelperExecResponseResult(*body.Exec)
	default:
		return nil
	}
}

func validateHelperResponseCommon(body HelperResponseBody) error {
	if !isHelperResponseRequestType(body.RequestType) {
		return ErrHelperResponseMatrix
	}
	if err := ValidateResponseDisposition(body.Disposition); err != nil {
		return err
	}
	if body.Revision == 0 {
		return ErrHelperResponseRevision
	}
	if err := ValidateFailureCode(body.FailureCode); err != nil {
		return err
	}

	switch body.Disposition {
	case ResponseDispositionAccepted:
		if body.RequestType == PacketTypeRevoke || body.FailureCode != FailureCodeNone {
			return ErrHelperResponseMatrix
		}
	case ResponseDispositionCleanupComplete:
		if body.RequestType != PacketTypeRevoke || body.FailureCode != FailureCodeNone {
			return ErrHelperResponseMatrix
		}
	case ResponseDispositionRejected:
		if body.FailureCode == FailureCodeNone || !helperResponseFailureAllowed(body.RequestType, body.FailureCode) {
			return ErrHelperResponseMatrix
		}
	case ResponseDispositionCleanupRetry, ResponseDispositionStopVMRequired:
		if body.RequestType != PacketTypeRevoke || body.FailureCode == FailureCodeNone ||
			!helperResponseFailureAllowed(body.RequestType, body.FailureCode) {
			return ErrHelperResponseMatrix
		}
	default:
		return ErrHelperResponseMatrix
	}
	return nil
}

// EncodeHelperResponseBody returns the exact canonical response-body encoding.
func EncodeHelperResponseBody(body HelperResponseBody) ([]byte, error) {
	length, err := HelperResponseBodyEncodedLength(body)
	if err != nil {
		return nil, err
	}
	encoded := make([]byte, length)
	if err := EncodeHelperResponseBodyTo(encoded, body); err != nil {
		clear(encoded)
		return nil, err
	}
	return encoded, nil
}

// HelperResponseBodyEncodedLength returns the exact canonical response length.
func HelperResponseBodyEncodedLength(body HelperResponseBody) (uint32, error) {
	if err := ValidateHelperResponseBody(body); err != nil {
		return 0, err
	}
	length := helperResponseCommonBytes
	switch {
	case body.Prepare != nil:
		result := body.Prepare
		length += 8 + 2 + len(result.ActiveProofID) + 2 + len(result.ExecBindingID) + 2
		for _, proof := range result.BindingProofs {
			length += 2 + len(proof.BindingID) + 1 + 2 + len(proof.ProofID)
		}
	case body.Renew != nil:
		length += 8 + 2 + len(body.Renew.ReplacementActiveProofID)
	case body.Revoke != nil:
		length += 2 + len(body.Revoke.CleanupProofID) + 2
	case body.Exec != nil:
		length += helperExecResponseResultBytes
	}
	return uint32(length), nil
}

// EncodeHelperResponseBodyTo writes a response into an exact destination.
func EncodeHelperResponseBodyTo(dst []byte, body HelperResponseBody) error {
	length, err := HelperResponseBodyEncodedLength(body)
	if err != nil {
		return err
	}
	if len(dst) != int(length) {
		return ErrHelperResponseBodyLength
	}
	dst[0] = byte(body.RequestType)
	dst[1] = byte(body.Disposition)
	binary.BigEndian.PutUint64(dst[2:10], body.Revision)
	dst[10] = byte(body.FailureCode)
	offset := helperResponseCommonBytes
	switch {
	case body.Prepare != nil:
		result := body.Prepare
		binary.BigEndian.PutUint64(dst[offset:offset+8], uint64(result.ExpiresAtUnixNano))
		offset += 8
		offset += putBodyToken(dst[offset:], result.ActiveProofID)
		offset += putBodyToken(dst[offset:], result.ExecBindingID)
		binary.BigEndian.PutUint16(dst[offset:offset+2], uint16(len(result.BindingProofs)))
		offset += 2
		for _, proof := range result.BindingProofs {
			offset += putBodyToken(dst[offset:], proof.BindingID)
			dst[offset] = byte(proof.Mode)
			offset++
			offset += putBodyToken(dst[offset:], proof.ProofID)
		}
	case body.Renew != nil:
		binary.BigEndian.PutUint64(dst[offset:offset+8], uint64(body.Renew.ExpiresAtUnixNano))
		offset += 8
		offset += putBodyToken(dst[offset:], body.Renew.ReplacementActiveProofID)
	case body.Revoke != nil:
		offset += putBodyToken(dst[offset:], body.Revoke.CleanupProofID)
		dst[offset] = encodeHelperResponseBoolean(body.Revoke.AuthorityAbsent)
		dst[offset+1] = encodeHelperResponseBoolean(body.Revoke.ResourcesAbsent)
		offset += 2
	case body.Exec != nil:
		result := body.Exec
		binary.BigEndian.PutUint32(dst[offset:offset+4], uint32(result.ExitCode))
		binary.BigEndian.PutUint64(dst[offset+4:offset+12], result.StdinBytes)
		copy(dst[offset+12:offset+44], result.StdinSHA256[:])
		binary.BigEndian.PutUint64(dst[offset+44:offset+52], result.StdoutBytes)
		copy(dst[offset+52:offset+84], result.StdoutSHA256[:])
		dst[offset+84] = encodeHelperResponseBoolean(result.StdoutTruncated)
		binary.BigEndian.PutUint64(dst[offset+85:offset+93], result.StderrBytes)
		copy(dst[offset+93:offset+125], result.StderrSHA256[:])
		dst[offset+125] = encodeHelperResponseBoolean(result.StderrTruncated)
		copy(dst[offset+126:offset+158], result.ExecTransactionSHA256[:])
		offset += helperExecResponseResultBytes
	}
	if offset != len(dst) {
		return ErrHelperResponseBodyLength
	}
	return nil
}

// DecodeHelperResponseBody strictly decodes one complete response body.
func DecodeHelperResponseBody(encoded []byte) (HelperResponseBody, error) {
	if len(encoded) < helperResponseCommonBytes {
		return HelperResponseBody{}, ErrHelperResponseBodyLength
	}
	body := HelperResponseBody{
		RequestType: PacketType(encoded[0]),
		Disposition: ResponseDisposition(encoded[1]),
		Revision:    binary.BigEndian.Uint64(encoded[2:10]),
		FailureCode: FailureCode(encoded[10]),
	}
	if !isHelperResponseRequestType(body.RequestType) {
		return HelperResponseBody{}, ErrHelperResponseMatrix
	}
	if err := ValidateResponseDisposition(body.Disposition); err != nil {
		return HelperResponseBody{}, err
	}
	if body.Revision == 0 {
		return HelperResponseBody{}, ErrHelperResponseRevision
	}
	if err := ValidateFailureCode(body.FailureCode); err != nil {
		return HelperResponseBody{}, err
	}
	if err := validateHelperResponseCommon(body); err != nil {
		return HelperResponseBody{}, err
	}

	if body.Disposition == ResponseDispositionRejected ||
		body.Disposition == ResponseDispositionCleanupRetry ||
		body.Disposition == ResponseDispositionStopVMRequired {
		if err := ValidateHelperResponseBody(body); err != nil {
			return HelperResponseBody{}, err
		}
		if len(encoded) != helperResponseCommonBytes {
			return HelperResponseBody{}, ErrHelperResponseBodyTrailingData
		}
		return body, nil
	}

	decoder := helperResponseDecoder{encoded: encoded, offset: helperResponseCommonBytes}
	var err error
	switch body.RequestType {
	case PacketTypePrepareCommit:
		body.Prepare, err = decoder.decodePrepare()
	case PacketTypeRenew:
		body.Renew, err = decoder.decodeRenew()
	case PacketTypeRevoke:
		body.Revoke, err = decoder.decodeRevoke()
	case PacketTypeExec:
		body.Exec, err = decoder.decodeExec()
	}
	if err != nil {
		return HelperResponseBody{}, err
	}
	if decoder.offset != len(encoded) {
		return HelperResponseBody{}, ErrHelperResponseBodyTrailingData
	}
	if err := ValidateHelperResponseBody(body); err != nil {
		return HelperResponseBody{}, err
	}
	return body, nil
}

func isHelperResponseRequestType(value PacketType) bool {
	switch value {
	case PacketTypePrepareCommit, PacketTypeRenew, PacketTypeRevoke, PacketTypeExec:
		return true
	default:
		return false
	}
}

func helperResponseArmCount(body HelperResponseBody) int {
	count := 0
	if body.Prepare != nil {
		count++
	}
	if body.Renew != nil {
		count++
	}
	if body.Revoke != nil {
		count++
	}
	if body.Exec != nil {
		count++
	}
	return count
}

func helperResponseHasExpectedArm(body HelperResponseBody) bool {
	switch body.RequestType {
	case PacketTypePrepareCommit:
		return body.Prepare != nil
	case PacketTypeRenew:
		return body.Renew != nil
	case PacketTypeExec:
		return body.Exec != nil
	default:
		return false
	}
}

func helperResponseFailureAllowed(requestType PacketType, failure FailureCode) bool {
	switch requestType {
	case PacketTypePrepareCommit:
		switch failure {
		case FailureCodeMalformed, FailureCodeIdentityMismatch, FailureCodeRevisionStale,
			FailureCodeExpired, FailureCodeResourceLimit, FailureCodePrepareFailed,
			FailureCodeHelperUnavailable, FailureCodeCleanupIncomplete:
			return true
		}
	case PacketTypeRenew:
		switch failure {
		case FailureCodeMalformed, FailureCodeIdentityMismatch, FailureCodeRevisionStale,
			FailureCodeExpired, FailureCodeRenewFailed, FailureCodeHelperUnavailable:
			return true
		}
	case PacketTypeRevoke:
		switch failure {
		case FailureCodeMalformed, FailureCodeIdentityMismatch, FailureCodeRevisionStale,
			FailureCodeRevokeFailed, FailureCodeHelperUnavailable, FailureCodeCleanupIncomplete:
			return true
		}
	case PacketTypeExec:
		switch failure {
		case FailureCodeMalformed, FailureCodeIdentityMismatch, FailureCodeRevisionStale,
			FailureCodeExpired, FailureCodeResourceLimit, FailureCodeExecFailed,
			FailureCodeHelperUnavailable:
			return true
		}
	}
	return false
}

func validateHelperPrepareResponseResult(result HelperPrepareResponseResult) error {
	if err := ValidateBodyToken(result.ActiveProofID); err != nil {
		return err
	}
	if err := ValidateBodyToken(result.ExecBindingID); err != nil {
		return err
	}
	if len(result.BindingProofs) == 0 || len(result.BindingProofs) > MaxHelperBindings {
		return ErrHelperResponseBindingCount
	}
	for index, proof := range result.BindingProofs {
		if err := ValidateBodyToken(proof.BindingID); err != nil {
			return err
		}
		if err := ValidateDeliveryMode(proof.Mode); err != nil {
			return err
		}
		if err := ValidateBodyToken(proof.ProofID); err != nil {
			return err
		}
		for prior := 0; prior < index; prior++ {
			if result.BindingProofs[prior].BindingID == proof.BindingID {
				return ErrHelperResponseBindingProof
			}
		}
	}
	return nil
}

func validateHelperRenewResponseResult(result HelperRenewResponseResult) error {
	return ValidateBodyToken(result.ReplacementActiveProofID)
}

func validateHelperRevokeResponseResult(result HelperRevokeResponseResult) error {
	if err := ValidateBodyToken(result.CleanupProofID); err != nil {
		return err
	}
	if !result.AuthorityAbsent || !result.ResourcesAbsent {
		return ErrHelperResponseResult
	}
	return nil
}

func validateHelperExecResponseResult(result HelperExecResponseResult) error {
	if result.ExitCode < 0 {
		return ErrHelperResponseExitCode
	}
	return nil
}

func encodeHelperResponseBoolean(value bool) byte {
	if value {
		return 1
	}
	return 0
}

type helperResponseDecoder struct {
	encoded []byte
	offset  int
}

func (decoder *helperResponseDecoder) decodePrepare() (*HelperPrepareResponseResult, error) {
	expires, err := decoder.readUint64()
	if err != nil {
		return nil, err
	}
	activeProofID, err := decoder.readToken()
	if err != nil {
		return nil, err
	}
	execBindingID, err := decoder.readToken()
	if err != nil {
		return nil, err
	}
	count, err := decoder.readUint16()
	if err != nil {
		return nil, err
	}
	if count == 0 || count > MaxHelperBindings {
		return nil, ErrHelperResponseBindingCount
	}
	proofs := make([]HelperBindingProof, int(count))
	for index := range proofs {
		proofs[index].BindingID, err = decoder.readToken()
		if err != nil {
			return nil, err
		}
		mode, modeErr := decoder.readByte()
		if modeErr != nil {
			return nil, modeErr
		}
		proofs[index].Mode = DeliveryMode(mode)
		proofs[index].ProofID, err = decoder.readToken()
		if err != nil {
			return nil, err
		}
	}
	return &HelperPrepareResponseResult{
		ExpiresAtUnixNano: int64(expires), ActiveProofID: activeProofID,
		ExecBindingID: execBindingID, BindingProofs: proofs,
	}, nil
}

func (decoder *helperResponseDecoder) decodeRenew() (*HelperRenewResponseResult, error) {
	expires, err := decoder.readUint64()
	if err != nil {
		return nil, err
	}
	proofID, err := decoder.readToken()
	if err != nil {
		return nil, err
	}
	return &HelperRenewResponseResult{ExpiresAtUnixNano: int64(expires), ReplacementActiveProofID: proofID}, nil
}

func (decoder *helperResponseDecoder) decodeRevoke() (*HelperRevokeResponseResult, error) {
	proofID, err := decoder.readToken()
	if err != nil {
		return nil, err
	}
	authorityAbsent, err := decoder.readBoolean()
	if err != nil {
		return nil, err
	}
	resourcesAbsent, err := decoder.readBoolean()
	if err != nil {
		return nil, err
	}
	return &HelperRevokeResponseResult{
		CleanupProofID: proofID, AuthorityAbsent: authorityAbsent, ResourcesAbsent: resourcesAbsent,
	}, nil
}

func (decoder *helperResponseDecoder) decodeExec() (*HelperExecResponseResult, error) {
	if len(decoder.encoded)-decoder.offset < helperExecResponseResultBytes {
		return nil, ErrHelperResponseBodyLength
	}
	start := decoder.offset
	result := &HelperExecResponseResult{
		ExitCode:    int32(binary.BigEndian.Uint32(decoder.encoded[start : start+4])),
		StdinBytes:  binary.BigEndian.Uint64(decoder.encoded[start+4 : start+12]),
		StdoutBytes: binary.BigEndian.Uint64(decoder.encoded[start+44 : start+52]),
		StderrBytes: binary.BigEndian.Uint64(decoder.encoded[start+85 : start+93]),
	}
	copy(result.StdinSHA256[:], decoder.encoded[start+12:start+44])
	copy(result.StdoutSHA256[:], decoder.encoded[start+52:start+84])
	copy(result.StderrSHA256[:], decoder.encoded[start+93:start+125])
	copy(result.ExecTransactionSHA256[:], decoder.encoded[start+126:start+158])
	var err error
	result.StdoutTruncated, err = decodeHelperResponseBoolean(decoder.encoded[start+84])
	if err != nil {
		return nil, err
	}
	result.StderrTruncated, err = decodeHelperResponseBoolean(decoder.encoded[start+125])
	if err != nil {
		return nil, err
	}
	decoder.offset += helperExecResponseResultBytes
	return result, nil
}

func (decoder *helperResponseDecoder) readByte() (byte, error) {
	if decoder.offset >= len(decoder.encoded) {
		return 0, ErrHelperResponseBodyLength
	}
	value := decoder.encoded[decoder.offset]
	decoder.offset++
	return value, nil
}

func (decoder *helperResponseDecoder) readUint16() (uint16, error) {
	if len(decoder.encoded)-decoder.offset < 2 {
		return 0, ErrHelperResponseBodyLength
	}
	value := binary.BigEndian.Uint16(decoder.encoded[decoder.offset : decoder.offset+2])
	decoder.offset += 2
	return value, nil
}

func (decoder *helperResponseDecoder) readUint64() (uint64, error) {
	if len(decoder.encoded)-decoder.offset < 8 {
		return 0, ErrHelperResponseBodyLength
	}
	value := binary.BigEndian.Uint64(decoder.encoded[decoder.offset : decoder.offset+8])
	decoder.offset += 8
	return value, nil
}

func (decoder *helperResponseDecoder) readToken() (string, error) {
	value, consumed, err := DecodeBodyTokenPrefix(decoder.encoded[decoder.offset:])
	if err != nil {
		if errors.Is(err, ErrBodyTokenEncoding) {
			return "", fmt.Errorf("%w: %w", ErrHelperResponseBodyLength, err)
		}
		return "", err
	}
	decoder.offset += consumed
	return value, nil
}

func (decoder *helperResponseDecoder) readBoolean() (bool, error) {
	value, err := decoder.readByte()
	if err != nil {
		return false, err
	}
	return decodeHelperResponseBoolean(value)
}

func decodeHelperResponseBoolean(value byte) (bool, error) {
	switch value {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, ErrHelperResponseBoolean
	}
}

func (HelperResponseBody) String() string            { return "HelperResponseBody" }
func (HelperResponseBody) GoString() string          { return "HelperResponseBody" }
func (HelperBindingProof) String() string            { return "HelperBindingProof" }
func (HelperBindingProof) GoString() string          { return "HelperBindingProof" }
func (HelperPrepareResponseResult) String() string   { return "HelperPrepareResponseResult" }
func (HelperPrepareResponseResult) GoString() string { return "HelperPrepareResponseResult" }
func (HelperRenewResponseResult) String() string     { return "HelperRenewResponseResult" }
func (HelperRenewResponseResult) GoString() string   { return "HelperRenewResponseResult" }
func (HelperRevokeResponseResult) String() string    { return "HelperRevokeResponseResult" }
func (HelperRevokeResponseResult) GoString() string  { return "HelperRevokeResponseResult" }
func (HelperExecResponseResult) String() string      { return "HelperExecResponseResult" }
func (HelperExecResponseResult) GoString() string    { return "HelperExecResponseResult" }

func (HelperResponseBody) Format(state fmt.State, _ rune) {
	writeHelperResponseTypeName(state, "HelperResponseBody")
}
func (HelperBindingProof) Format(state fmt.State, _ rune) {
	writeHelperResponseTypeName(state, "HelperBindingProof")
}
func (HelperPrepareResponseResult) Format(state fmt.State, _ rune) {
	writeHelperResponseTypeName(state, "HelperPrepareResponseResult")
}
func (HelperRenewResponseResult) Format(state fmt.State, _ rune) {
	writeHelperResponseTypeName(state, "HelperRenewResponseResult")
}
func (HelperRevokeResponseResult) Format(state fmt.State, _ rune) {
	writeHelperResponseTypeName(state, "HelperRevokeResponseResult")
}
func (HelperExecResponseResult) Format(state fmt.State, _ rune) {
	writeHelperResponseTypeName(state, "HelperExecResponseResult")
}

func writeHelperResponseTypeName(state fmt.State, name string) {
	_, _ = state.Write([]byte(name))
}

func (HelperResponseBody) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (HelperResponseBody) MarshalText() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (*HelperResponseBody) UnmarshalJSON([]byte) error { return ErrHelperResponseBodySerialization }
func (*HelperResponseBody) UnmarshalText([]byte) error { return ErrHelperResponseBodySerialization }
func (HelperBindingProof) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (HelperBindingProof) MarshalText() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (*HelperBindingProof) UnmarshalJSON([]byte) error { return ErrHelperResponseBodySerialization }
func (*HelperBindingProof) UnmarshalText([]byte) error { return ErrHelperResponseBodySerialization }
func (HelperPrepareResponseResult) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (HelperPrepareResponseResult) MarshalText() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (*HelperPrepareResponseResult) UnmarshalJSON([]byte) error {
	return ErrHelperResponseBodySerialization
}
func (*HelperPrepareResponseResult) UnmarshalText([]byte) error {
	return ErrHelperResponseBodySerialization
}
func (HelperRenewResponseResult) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (HelperRenewResponseResult) MarshalText() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (*HelperRenewResponseResult) UnmarshalJSON([]byte) error {
	return ErrHelperResponseBodySerialization
}
func (*HelperRenewResponseResult) UnmarshalText([]byte) error {
	return ErrHelperResponseBodySerialization
}
func (HelperRevokeResponseResult) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (HelperRevokeResponseResult) MarshalText() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (*HelperRevokeResponseResult) UnmarshalJSON([]byte) error {
	return ErrHelperResponseBodySerialization
}
func (*HelperRevokeResponseResult) UnmarshalText([]byte) error {
	return ErrHelperResponseBodySerialization
}
func (HelperExecResponseResult) MarshalJSON() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (HelperExecResponseResult) MarshalText() ([]byte, error) {
	return nil, ErrHelperResponseBodySerialization
}
func (*HelperExecResponseResult) UnmarshalJSON([]byte) error {
	return ErrHelperResponseBodySerialization
}
func (*HelperExecResponseResult) UnmarshalText([]byte) error {
	return ErrHelperResponseBodySerialization
}
