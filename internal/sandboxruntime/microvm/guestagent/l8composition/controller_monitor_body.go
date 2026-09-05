package l8composition

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	controllerMonitorReadyMinBytes        = 87
	controllerMonitorReadyMaxBytes        = 722
	controllerMonitorPrepareBeginMinBytes = 60
	controllerMonitorPrepareBeginMaxBytes = 68258
	controllerMonitorPrepareFileMinBytes  = 47
	controllerMonitorPrepareFileMaxBytes  = 65582
	controllerMonitorPrepareCommitBytes   = 40
	controllerMonitorSSHCreateMinBytes    = 80
	controllerMonitorSSHCreateMaxBytes    = 334
	controllerMonitorRevokeBytes          = 9
	controllerMonitorResponsePrefixBytes  = 11
	controllerMonitorEventMinBytes        = 71
	controllerMonitorEventMaxBytes        = 198
	controllerMonitorCloseBytes           = 1
)

type ControllerMonitorReadyBody struct {
	Revision           uint64
	JobGeneration      string
	MonitorGeneration  string
	MountGeneration    string
	CgroupGeneration   string
	LimitSetID         string
	CreateJobSHA256    [sha256.Size]byte
	MonitorReadySHA256 [sha256.Size]byte
}

type ControllerMonitorCreateSSHEndpointBody struct {
	Revision             uint64
	BindingIndex         uint16
	BindingID            string
	EndpointGeneration   string
	ManifestSHA256       [sha256.Size]byte
	EndpointConfigSHA256 [sha256.Size]byte
}

type ControllerMonitorPrepareResult struct {
	MountGeneration             string
	ManifestSHA256              [sha256.Size]byte
	PrepareTransactionSHA256    [sha256.Size]byte
	FileCount                   uint16
	AggregateFileBytes          uint64
	PreparePostinspectionSHA256 [sha256.Size]byte
}

type ControllerMonitorSSHEndpointResult struct {
	BindingIndex       uint16
	BindingID          string
	EndpointGeneration string
	EndpointSHA256     [sha256.Size]byte
}

type ControllerMonitorRevokeResult struct {
	CleanupSHA256 [sha256.Size]byte
	EntriesAbsent bool
	SocketAbsent  bool
	MountAbsent   bool
}

type ControllerMonitorResponseBody struct {
	requestType ControllerMonitorPacketType
	disposition credentialprotocol.ResponseDisposition
	revision    uint64
	failure     ControllerMonitorFailureCode
	prepare     *ControllerMonitorPrepareResult
	ssh         *ControllerMonitorSSHEndpointResult
	revoke      *ControllerMonitorRevokeResult
}

type ControllerMonitorEventBody struct {
	EventCode            ControllerMonitorEventCode
	FailureCode          ControllerMonitorFailureCode
	CleanupCategory      ControllerMonitorCleanupCategory
	Revision             uint64
	EventID              string
	MountGeneration      string
	PostinspectionSHA256 [sha256.Size]byte
}

type ControllerMonitorCloseNotifyBody struct {
	Reason credentialprotocol.CloseReason
}

func EncodeControllerMonitorReadyBody(body ControllerMonitorReadyBody) ([]byte, error) {
	if err := validateControllerMonitorReadyBody(body); err != nil {
		return nil, err
	}
	encoded := make([]byte, 8)
	binary.BigEndian.PutUint64(encoded, body.Revision)
	for _, value := range []string{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration, body.LimitSetID} {
		token, _ := credentialprotocol.EncodeBodyToken(value)
		encoded = append(encoded, token...)
	}
	encoded = append(encoded, body.CreateJobSHA256[:]...)
	encoded = append(encoded, body.MonitorReadySHA256[:]...)
	return encoded, nil
}

func DecodeControllerMonitorReadyBody(encoded []byte) (ControllerMonitorReadyBody, error) {
	if len(encoded) < controllerMonitorReadyMinBytes || len(encoded) > controllerMonitorReadyMaxBytes {
		return ControllerMonitorReadyBody{}, ErrControllerMonitorBodyLength
	}
	body := ControllerMonitorReadyBody{Revision: binary.BigEndian.Uint64(encoded[:8])}
	offset := 8
	values := []*string{&body.JobGeneration, &body.MonitorGeneration, &body.MountGeneration, &body.CgroupGeneration, &body.LimitSetID}
	for _, target := range values {
		value, consumed, err := credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
		if err != nil {
			return ControllerMonitorReadyBody{}, err
		}
		*target = value
		offset += consumed
	}
	if len(encoded)-offset != 2*sha256.Size {
		return ControllerMonitorReadyBody{}, ErrControllerMonitorBodyLength
	}
	copy(body.CreateJobSHA256[:], encoded[offset:offset+sha256.Size])
	copy(body.MonitorReadySHA256[:], encoded[offset+sha256.Size:])
	if err := validateControllerMonitorReadyBody(body); err != nil {
		return ControllerMonitorReadyBody{}, err
	}
	return body, nil
}

func validateControllerMonitorReadyBody(body ControllerMonitorReadyBody) error {
	if body.Revision != 1 {
		return ErrControllerMonitorRevision
	}
	for _, value := range []string{body.JobGeneration, body.MonitorGeneration, body.MountGeneration, body.CgroupGeneration, body.LimitSetID} {
		if !validControllerMonitorSafeID(value) {
			return ErrControllerMonitorGeneration
		}
	}
	if body.LimitSetID != ControllerMonitorLimitSetID {
		return ErrControllerMonitorLimitSet
	}
	if controllerMonitorZero32(body.CreateJobSHA256) || controllerMonitorZero32(body.MonitorReadySHA256) {
		return ErrControllerMonitorDigest
	}
	return nil
}

func EncodeControllerMonitorCreateSSHEndpointBody(body ControllerMonitorCreateSSHEndpointBody) ([]byte, error) {
	if err := validateControllerMonitorCreateSSHEndpointBody(body); err != nil {
		return nil, err
	}
	encoded := make([]byte, 10)
	binary.BigEndian.PutUint64(encoded[:8], body.Revision)
	binary.BigEndian.PutUint16(encoded[8:10], body.BindingIndex)
	binding, _ := credentialprotocol.EncodeBodyToken(body.BindingID)
	generation, _ := credentialprotocol.EncodeBodyToken(body.EndpointGeneration)
	encoded = append(encoded, binding...)
	encoded = append(encoded, generation...)
	encoded = append(encoded, body.ManifestSHA256[:]...)
	encoded = append(encoded, body.EndpointConfigSHA256[:]...)
	return encoded, nil
}

func DecodeControllerMonitorCreateSSHEndpointBody(encoded []byte) (ControllerMonitorCreateSSHEndpointBody, error) {
	if len(encoded) < controllerMonitorSSHCreateMinBytes || len(encoded) > controllerMonitorSSHCreateMaxBytes {
		return ControllerMonitorCreateSSHEndpointBody{}, ErrControllerMonitorBodyLength
	}
	body := ControllerMonitorCreateSSHEndpointBody{Revision: binary.BigEndian.Uint64(encoded[:8]), BindingIndex: binary.BigEndian.Uint16(encoded[8:10])}
	offset := 10
	var consumed int
	var err error
	body.BindingID, consumed, err = credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
	if err != nil {
		return ControllerMonitorCreateSSHEndpointBody{}, err
	}
	offset += consumed
	body.EndpointGeneration, consumed, err = credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
	if err != nil {
		return ControllerMonitorCreateSSHEndpointBody{}, err
	}
	offset += consumed
	if len(encoded)-offset != 2*sha256.Size {
		return ControllerMonitorCreateSSHEndpointBody{}, ErrControllerMonitorBodyLength
	}
	copy(body.ManifestSHA256[:], encoded[offset:offset+sha256.Size])
	copy(body.EndpointConfigSHA256[:], encoded[offset+sha256.Size:])
	if err := validateControllerMonitorCreateSSHEndpointBody(body); err != nil {
		return ControllerMonitorCreateSSHEndpointBody{}, err
	}
	return body, nil
}

func validateControllerMonitorCreateSSHEndpointBody(body ControllerMonitorCreateSSHEndpointBody) error {
	if body.Revision != 1 {
		return ErrControllerMonitorRevision
	}
	if body.BindingIndex >= credentialprotocol.MaxHelperBindings || !validControllerMonitorSafeID(body.BindingID) || !validControllerMonitorSafeID(body.EndpointGeneration) {
		return ErrControllerMonitorGeneration
	}
	if controllerMonitorZero32(body.ManifestSHA256) || controllerMonitorZero32(body.EndpointConfigSHA256) {
		return ErrControllerMonitorDigest
	}
	return nil
}

func NewControllerMonitorRejectedResponse(requestType ControllerMonitorPacketType, revision uint64, failure ControllerMonitorFailureCode) (ControllerMonitorResponseBody, error) {
	body := ControllerMonitorResponseBody{requestType: requestType, disposition: credentialprotocol.ResponseDispositionRejected, revision: revision, failure: failure}
	return body, validateControllerMonitorResponseBody(body)
}

func NewControllerMonitorStopVMResponse(requestType ControllerMonitorPacketType, revision uint64, failure ControllerMonitorFailureCode) (ControllerMonitorResponseBody, error) {
	body := ControllerMonitorResponseBody{requestType: requestType, disposition: credentialprotocol.ResponseDispositionStopVMRequired, revision: revision, failure: failure}
	return body, validateControllerMonitorResponseBody(body)
}

func NewControllerMonitorCleanupRetryResponse(revision uint64, failure ControllerMonitorFailureCode) (ControllerMonitorResponseBody, error) {
	body := ControllerMonitorResponseBody{requestType: ControllerMonitorPacketTypeRevoke, disposition: credentialprotocol.ResponseDispositionCleanupRetry, revision: revision, failure: failure}
	return body, validateControllerMonitorResponseBody(body)
}

func NewControllerMonitorPrepareAcceptedResponse(revision uint64, result ControllerMonitorPrepareResult) (ControllerMonitorResponseBody, error) {
	body := ControllerMonitorResponseBody{requestType: ControllerMonitorPacketTypePrepareCommit, disposition: credentialprotocol.ResponseDispositionAccepted, revision: revision, failure: ControllerMonitorFailureNone, prepare: &result}
	return body, validateControllerMonitorResponseBody(body)
}

func NewControllerMonitorSSHEndpointAcceptedResponse(revision uint64, result ControllerMonitorSSHEndpointResult) (ControllerMonitorResponseBody, error) {
	body := ControllerMonitorResponseBody{requestType: ControllerMonitorPacketTypeCreateSSHEndpoint, disposition: credentialprotocol.ResponseDispositionAccepted, revision: revision, failure: ControllerMonitorFailureNone, ssh: &result}
	return body, validateControllerMonitorResponseBody(body)
}

func NewControllerMonitorCleanupCompleteResponse(revision uint64, result ControllerMonitorRevokeResult) (ControllerMonitorResponseBody, error) {
	body := ControllerMonitorResponseBody{requestType: ControllerMonitorPacketTypeRevoke, disposition: credentialprotocol.ResponseDispositionCleanupComplete, revision: revision, failure: ControllerMonitorFailureNone, revoke: &result}
	return body, validateControllerMonitorResponseBody(body)
}

func (body ControllerMonitorResponseBody) RequestType() ControllerMonitorPacketType {
	return body.requestType
}
func (body ControllerMonitorResponseBody) Disposition() credentialprotocol.ResponseDisposition {
	return body.disposition
}
func (body ControllerMonitorResponseBody) Revision() uint64 { return body.revision }
func (body ControllerMonitorResponseBody) FailureCode() ControllerMonitorFailureCode {
	return body.failure
}
func (body ControllerMonitorResponseBody) PrepareResult() (ControllerMonitorPrepareResult, bool) {
	if body.prepare == nil {
		return ControllerMonitorPrepareResult{}, false
	}
	return *body.prepare, true
}
func (body ControllerMonitorResponseBody) SSHEndpointResult() (ControllerMonitorSSHEndpointResult, bool) {
	if body.ssh == nil {
		return ControllerMonitorSSHEndpointResult{}, false
	}
	return *body.ssh, true
}
func (body ControllerMonitorResponseBody) RevokeResult() (ControllerMonitorRevokeResult, bool) {
	if body.revoke == nil {
		return ControllerMonitorRevokeResult{}, false
	}
	return *body.revoke, true
}

func EncodeControllerMonitorResponseBody(body ControllerMonitorResponseBody) ([]byte, error) {
	if err := validateControllerMonitorResponseBody(body); err != nil {
		return nil, err
	}
	encoded := make([]byte, controllerMonitorResponsePrefixBytes)
	encoded[0] = byte(body.requestType)
	encoded[1] = byte(body.disposition)
	binary.BigEndian.PutUint64(encoded[2:10], body.revision)
	encoded[10] = byte(body.failure)
	if body.prepare != nil {
		token, _ := credentialprotocol.EncodeBodyToken(body.prepare.MountGeneration)
		encoded = append(encoded, token...)
		encoded = append(encoded, body.prepare.ManifestSHA256[:]...)
		encoded = append(encoded, body.prepare.PrepareTransactionSHA256[:]...)
		encoded = appendUint16CM(encoded, body.prepare.FileCount)
		encoded = appendUint64CM(encoded, body.prepare.AggregateFileBytes)
		encoded = append(encoded, body.prepare.PreparePostinspectionSHA256[:]...)
	} else if body.ssh != nil {
		encoded = appendUint16CM(encoded, body.ssh.BindingIndex)
		binding, _ := credentialprotocol.EncodeBodyToken(body.ssh.BindingID)
		generation, _ := credentialprotocol.EncodeBodyToken(body.ssh.EndpointGeneration)
		encoded = append(encoded, binding...)
		encoded = append(encoded, generation...)
		encoded = append(encoded, body.ssh.EndpointSHA256[:]...)
	} else if body.revoke != nil {
		encoded = append(encoded, body.revoke.CleanupSHA256[:]...)
		encoded = append(encoded, boolByteCM(body.revoke.EntriesAbsent), boolByteCM(body.revoke.SocketAbsent), boolByteCM(body.revoke.MountAbsent))
	}
	return encoded, nil
}

func DecodeControllerMonitorResponseBody(encoded []byte) (ControllerMonitorResponseBody, error) {
	if len(encoded) < controllerMonitorResponsePrefixBytes {
		return ControllerMonitorResponseBody{}, ErrControllerMonitorBodyLength
	}
	body := ControllerMonitorResponseBody{requestType: ControllerMonitorPacketType(encoded[0]), disposition: credentialprotocol.ResponseDisposition(encoded[1]), revision: binary.BigEndian.Uint64(encoded[2:10]), failure: ControllerMonitorFailureCode(encoded[10])}
	offset := controllerMonitorResponsePrefixBytes
	switch body.disposition {
	case credentialprotocol.ResponseDispositionAccepted:
		switch body.requestType {
		case ControllerMonitorPacketTypePrepareCommit:
			result := ControllerMonitorPrepareResult{}
			value, consumed, err := credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
			if err != nil {
				return ControllerMonitorResponseBody{}, err
			}
			result.MountGeneration = value
			offset += consumed
			if len(encoded)-offset != 32+32+2+8+32 {
				return ControllerMonitorResponseBody{}, ErrControllerMonitorBodyLength
			}
			copy(result.ManifestSHA256[:], encoded[offset:offset+32])
			offset += 32
			copy(result.PrepareTransactionSHA256[:], encoded[offset:offset+32])
			offset += 32
			result.FileCount = binary.BigEndian.Uint16(encoded[offset : offset+2])
			offset += 2
			result.AggregateFileBytes = binary.BigEndian.Uint64(encoded[offset : offset+8])
			offset += 8
			copy(result.PreparePostinspectionSHA256[:], encoded[offset:offset+32])
			offset += 32
			body.prepare = &result
		case ControllerMonitorPacketTypeCreateSSHEndpoint:
			if len(encoded)-offset < 2 {
				return ControllerMonitorResponseBody{}, ErrControllerMonitorBodyLength
			}
			result := ControllerMonitorSSHEndpointResult{BindingIndex: binary.BigEndian.Uint16(encoded[offset : offset+2])}
			offset += 2
			var consumed int
			var err error
			result.BindingID, consumed, err = credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
			if err != nil {
				return ControllerMonitorResponseBody{}, err
			}
			offset += consumed
			result.EndpointGeneration, consumed, err = credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
			if err != nil {
				return ControllerMonitorResponseBody{}, err
			}
			offset += consumed
			if len(encoded)-offset != 32 {
				return ControllerMonitorResponseBody{}, ErrControllerMonitorBodyLength
			}
			copy(result.EndpointSHA256[:], encoded[offset:])
			offset += 32
			body.ssh = &result
		default:
			return ControllerMonitorResponseBody{}, ErrControllerMonitorResponse
		}
	case credentialprotocol.ResponseDispositionCleanupComplete:
		if body.requestType != ControllerMonitorPacketTypeRevoke || len(encoded)-offset != 35 {
			return ControllerMonitorResponseBody{}, ErrControllerMonitorBodyLength
		}
		result := ControllerMonitorRevokeResult{}
		copy(result.CleanupSHA256[:], encoded[offset:offset+32])
		offset += 32
		var err error
		result.EntriesAbsent, err = decodeBoolCM(encoded[offset])
		if err != nil {
			return ControllerMonitorResponseBody{}, err
		}
		offset++
		result.SocketAbsent, err = decodeBoolCM(encoded[offset])
		if err != nil {
			return ControllerMonitorResponseBody{}, err
		}
		offset++
		result.MountAbsent, err = decodeBoolCM(encoded[offset])
		if err != nil {
			return ControllerMonitorResponseBody{}, err
		}
		offset++
		body.revoke = &result
	case credentialprotocol.ResponseDispositionRejected, credentialprotocol.ResponseDispositionCleanupRetry, credentialprotocol.ResponseDispositionStopVMRequired:
		if offset != len(encoded) {
			return ControllerMonitorResponseBody{}, ErrControllerMonitorBodyLength
		}
	default:
		return ControllerMonitorResponseBody{}, ErrControllerMonitorResponse
	}
	if offset != len(encoded) {
		return ControllerMonitorResponseBody{}, ErrControllerMonitorBodyLength
	}
	if err := validateControllerMonitorResponseBody(body); err != nil {
		return ControllerMonitorResponseBody{}, err
	}
	return body, nil
}

func validateControllerMonitorResponseBody(body ControllerMonitorResponseBody) error {
	if body.revision != 1 || ValidateControllerMonitorFailureCode(body.failure) != nil || credentialprotocol.ValidateResponseDisposition(body.disposition) != nil {
		return ErrControllerMonitorResponse
	}
	arms := 0
	if body.prepare != nil {
		arms++
	}
	if body.ssh != nil {
		arms++
	}
	if body.revoke != nil {
		arms++
	}
	switch body.disposition {
	case credentialprotocol.ResponseDispositionAccepted:
		if body.failure != ControllerMonitorFailureNone || arms != 1 {
			return ErrControllerMonitorResponse
		}
		if body.requestType == ControllerMonitorPacketTypePrepareCommit && body.prepare != nil {
			return validateControllerMonitorPrepareResult(*body.prepare)
		}
		if body.requestType == ControllerMonitorPacketTypeCreateSSHEndpoint && body.ssh != nil {
			return validateControllerMonitorSSHResult(*body.ssh)
		}
		return ErrControllerMonitorResponse
	case credentialprotocol.ResponseDispositionCleanupComplete:
		if body.requestType != ControllerMonitorPacketTypeRevoke || body.failure != ControllerMonitorFailureNone || arms != 1 || body.revoke == nil {
			return ErrControllerMonitorResponse
		}
		if controllerMonitorZero32(body.revoke.CleanupSHA256) || !body.revoke.EntriesAbsent || !body.revoke.SocketAbsent || !body.revoke.MountAbsent {
			return ErrControllerMonitorResponseResult
		}
	case credentialprotocol.ResponseDispositionRejected:
		if arms != 0 || body.requestType == ControllerMonitorPacketTypeRevoke {
			return ErrControllerMonitorResponse
		}
		if body.failure != ControllerMonitorFailureResourceLimit && body.failure != ControllerMonitorFailureOperationDenied && body.failure != ControllerMonitorFailurePrepareFailed && body.failure != ControllerMonitorFailureSSHEndpointFailed {
			return ErrControllerMonitorResponse
		}
		if body.requestType != ControllerMonitorPacketTypePrepareCommit && body.requestType != ControllerMonitorPacketTypeCreateSSHEndpoint {
			return ErrControllerMonitorResponse
		}
		if body.failure == ControllerMonitorFailurePrepareFailed && body.requestType != ControllerMonitorPacketTypePrepareCommit || body.failure == ControllerMonitorFailureSSHEndpointFailed && body.requestType != ControllerMonitorPacketTypeCreateSSHEndpoint {
			return ErrControllerMonitorResponse
		}
	case credentialprotocol.ResponseDispositionCleanupRetry:
		if arms != 0 || body.requestType != ControllerMonitorPacketTypeRevoke || !validControllerMonitorCleanupFailure(body.failure) {
			return ErrControllerMonitorResponse
		}
	case credentialprotocol.ResponseDispositionStopVMRequired:
		if arms != 0 || !validControllerMonitorStopFailure(body.requestType, body.failure) {
			return ErrControllerMonitorResponse
		}
	default:
		return ErrControllerMonitorResponse
	}
	return nil
}

func validControllerMonitorCleanupFailure(value ControllerMonitorFailureCode) bool {
	return value == ControllerMonitorFailureRevokeFailed || value == ControllerMonitorFailureInspectionFailed || value == ControllerMonitorFailureCleanupIncomplete
}
func validControllerMonitorStopFailure(requestType ControllerMonitorPacketType, value ControllerMonitorFailureCode) bool {
	switch requestType {
	case ControllerMonitorPacketTypePrepareCommit:
		return value == ControllerMonitorFailurePrepareFailed || value == ControllerMonitorFailureInspectionFailed || value == ControllerMonitorFailureCleanupIncomplete
	case ControllerMonitorPacketTypeCreateSSHEndpoint:
		return value == ControllerMonitorFailureSSHEndpointFailed || value == ControllerMonitorFailureInspectionFailed || value == ControllerMonitorFailureCleanupIncomplete
	case ControllerMonitorPacketTypeRevoke:
		return validControllerMonitorCleanupFailure(value)
	default:
		return false
	}
}
func validateControllerMonitorPrepareResult(result ControllerMonitorPrepareResult) error {
	if !validControllerMonitorSafeID(result.MountGeneration) || controllerMonitorZero32(result.ManifestSHA256) || controllerMonitorZero32(result.PrepareTransactionSHA256) || controllerMonitorZero32(result.PreparePostinspectionSHA256) || result.FileCount > credentialprotocol.MaxHelperBindings || result.AggregateFileBytes > credentialprotocol.MaxHelperFileAggregateBytes {
		return ErrControllerMonitorResponseResult
	}
	return nil
}
func validateControllerMonitorSSHResult(result ControllerMonitorSSHEndpointResult) error {
	if result.BindingIndex >= credentialprotocol.MaxHelperBindings || !validControllerMonitorSafeID(result.BindingID) || !validControllerMonitorSafeID(result.EndpointGeneration) || controllerMonitorZero32(result.EndpointSHA256) {
		return ErrControllerMonitorResponseResult
	}
	return nil
}

func EncodeControllerMonitorEventBody(body ControllerMonitorEventBody) ([]byte, error) {
	if err := ValidateControllerMonitorEventBody(body); err != nil {
		return nil, err
	}
	encoded := make([]byte, 12)
	encoded[0], encoded[1], encoded[2] = byte(body.EventCode), byte(body.FailureCode), byte(body.CleanupCategory)
	binary.BigEndian.PutUint64(encoded[4:12], body.Revision)
	event, _ := credentialprotocol.EncodeBodyToken(body.EventID)
	mount, _ := credentialprotocol.EncodeBodyToken(body.MountGeneration)
	encoded = append(encoded, event...)
	encoded = append(encoded, mount...)
	encoded = append(encoded, body.PostinspectionSHA256[:]...)
	return encoded, nil
}
func DecodeControllerMonitorEventBody(encoded []byte) (ControllerMonitorEventBody, error) {
	if len(encoded) < controllerMonitorEventMinBytes || len(encoded) > controllerMonitorEventMaxBytes {
		return ControllerMonitorEventBody{}, ErrControllerMonitorBodyLength
	}
	if encoded[3] != 0 {
		return ControllerMonitorEventBody{}, ErrControllerMonitorEvent
	}
	body := ControllerMonitorEventBody{EventCode: ControllerMonitorEventCode(encoded[0]), FailureCode: ControllerMonitorFailureCode(encoded[1]), CleanupCategory: ControllerMonitorCleanupCategory(encoded[2]), Revision: binary.BigEndian.Uint64(encoded[4:12])}
	offset := 12
	var consumed int
	var err error
	body.EventID, consumed, err = credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
	if err != nil {
		return ControllerMonitorEventBody{}, err
	}
	offset += consumed
	body.MountGeneration, consumed, err = credentialprotocol.DecodeBodyTokenPrefix(encoded[offset:])
	if err != nil {
		return ControllerMonitorEventBody{}, err
	}
	offset += consumed
	if len(encoded)-offset != 32 {
		return ControllerMonitorEventBody{}, ErrControllerMonitorBodyLength
	}
	copy(body.PostinspectionSHA256[:], encoded[offset:])
	if err := ValidateControllerMonitorEventBody(body); err != nil {
		return ControllerMonitorEventBody{}, err
	}
	return body, nil
}
func ValidateControllerMonitorEventBody(body ControllerMonitorEventBody) error {
	if body.Revision != 1 || ValidateControllerMonitorEventCode(body.EventCode) != nil || ValidateControllerMonitorFailureCode(body.FailureCode) != nil || ValidateControllerMonitorCleanupCategory(body.CleanupCategory) != nil || len(body.EventID) != 22 || !validControllerMonitorSafeID(body.EventID) || !validControllerMonitorSafeID(body.MountGeneration) || controllerMonitorZero32(body.PostinspectionSHA256) {
		return ErrControllerMonitorEvent
	}
	switch body.EventCode {
	case ControllerMonitorEventExpired:
		if body.FailureCode != ControllerMonitorFailureOperationDenied || body.CleanupCategory != ControllerMonitorCleanupRetryRequired {
			return ErrControllerMonitorEvent
		}
	case ControllerMonitorEventMountDrift, ControllerMonitorEventEndpointDrift:
		if body.FailureCode != ControllerMonitorFailureInspectionFailed || body.CleanupCategory != ControllerMonitorCleanupStopVMRequired {
			return ErrControllerMonitorEvent
		}
	case ControllerMonitorEventCleanupRequired:
		if body.FailureCode != ControllerMonitorFailureCleanupIncomplete || body.CleanupCategory != ControllerMonitorCleanupRetryRequired && body.CleanupCategory != ControllerMonitorCleanupStopVMRequired {
			return ErrControllerMonitorEvent
		}
	}
	return nil
}

func EncodeControllerMonitorCloseNotifyBody(body ControllerMonitorCloseNotifyBody) ([]byte, error) {
	return credentialprotocol.EncodeHelperCloseNotifyBody(credentialprotocol.HelperCloseNotifyBody{Reason: body.Reason})
}
func DecodeControllerMonitorCloseNotifyBody(encoded []byte) (ControllerMonitorCloseNotifyBody, error) {
	body, err := credentialprotocol.DecodeHelperCloseNotifyBody(encoded)
	if err != nil {
		return ControllerMonitorCloseNotifyBody{}, err
	}
	return ControllerMonitorCloseNotifyBody{Reason: body.Reason}, nil
}

func controllerMonitorEventID(requestID [16]byte) string {
	return base64.RawURLEncoding.EncodeToString(requestID[:])
}
func appendUint16CM(encoded []byte, value uint16) []byte {
	var item [2]byte
	binary.BigEndian.PutUint16(item[:], value)
	return append(encoded, item[:]...)
}
func appendUint64CM(encoded []byte, value uint64) []byte {
	var item [8]byte
	binary.BigEndian.PutUint64(item[:], value)
	return append(encoded, item[:]...)
}
func boolByteCM(value bool) byte {
	if value {
		return 1
	}
	return 0
}
func decodeBoolCM(value byte) (bool, error) {
	if value == 0 {
		return false, nil
	}
	if value == 1 {
		return true, nil
	}
	return false, ErrControllerMonitorBoolean
}
