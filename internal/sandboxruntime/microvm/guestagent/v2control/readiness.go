package v2control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var (
	ErrInvalidReadinessRequest      = errors.New("guest agent v2 readiness request is invalid")
	ErrInvalidReadinessRequestJSON  = errors.New("guest agent v2 readiness request JSON is invalid")
	ErrInvalidReadinessSuccess      = errors.New("guest agent v2 readiness success response is invalid")
	ErrInvalidReadinessSuccessJSON  = errors.New("guest agent v2 readiness success response JSON is invalid")
	ErrReadinessCorrelationMismatch = errors.New("guest agent v2 readiness response correlation does not match")
	ErrReadinessSerialization       = errors.New("guest agent v2 readiness serialization is denied")
)

const (
	// ReadinessServiceUID is the fixed guest-agent service identity.
	ReadinessServiceUID uint32 = 998
	// ReadinessServiceGID is the fixed guest-agent service group.
	ReadinessServiceGID uint32 = 998
	// ReadinessWorkloadUID is the fixed credential-aware workload identity.
	ReadinessWorkloadUID uint32 = 1000
	// ReadinessWorkloadGID is the fixed credential-aware workload group.
	ReadinessWorkloadGID uint32 = 1000
	// ReadinessHelperProtocol is the sole accepted helper protocol.
	ReadinessHelperProtocol = "guest-helper-v1"

	// ReadinessCapabilityCredentialLifecycle is the lifecycle capability token.
	ReadinessCapabilityCredentialLifecycle = "credential_lifecycle"
	// ReadinessCapabilityCredentialExecBinding is the exec-binding capability token.
	ReadinessCapabilityCredentialExecBinding = "credential_exec_binding"
	// ReadinessCapabilityHelperExactPID is the exact-helper-PID capability token.
	ReadinessCapabilityHelperExactPID = "helper_exact_pid"
	// ReadinessCapabilityFileTmpfs is the tmpfs-file capability token.
	ReadinessCapabilityFileTmpfs = "file_tmpfs"
	// ReadinessCapabilitySSHAgent is the SSH-agent capability token.
	ReadinessCapabilitySSHAgent = "ssh_agent"

	maxReadinessJSONBytes        = 2 * 1024 * 1024
	maxReadinessJSONDepth        = 3
	maxReadinessJSONObjectFields = 16
)

// ReadinessRequest owns one complete canonical readiness request envelope.
// Its fixed protocol, operation, capabilities, identities, and helper protocol
// are not caller-selectable.
type ReadinessRequest struct {
	state *readinessRequestState
}

type readinessRequestState struct {
	protocolVersion string
	operation       Operation
	requestID       RequestID
	identityDigest  IdentityDigest
	body            readinessRequestBodyState
}

type readinessRequestBodyState struct {
	requiredCapabilities []string
	expectedServiceUID   uint32
	expectedServiceGID   uint32
	expectedWorkloadUID  uint32
	expectedWorkloadGID  uint32
	helperProtocol       string
}

// ReadinessSuccessResponse owns one complete canonical readiness success
// envelope correlated to the request from which it was constructed.
type ReadinessSuccessResponse struct {
	state *readinessSuccessState
}

type readinessSuccessState struct {
	protocolVersion string
	operation       Operation
	requestID       RequestID
	identityDigest  IdentityDigest
	ok              bool
	body            readinessSuccessBodyState
}

type readinessSuccessBodyState struct {
	capabilities           []string
	serviceUID             uint32
	serviceGID             uint32
	workloadUID            uint32
	workloadGID            uint32
	helperProtocol         string
	guestSessionGeneration string
	helperGeneration       string
}

type readinessRequestJSON struct {
	ProtocolVersion string                   `json:"protocolVersion"`
	Operation       string                   `json:"operation"`
	RequestID       string                   `json:"requestId"`
	IdentityDigest  string                   `json:"identityDigest"`
	Body            readinessRequestBodyJSON `json:"body"`
}

type readinessRequestBodyJSON struct {
	RequiredCapabilities []string `json:"requiredCapabilities"`
	ExpectedServiceUID   uint32   `json:"expectedServiceUID"`
	ExpectedServiceGID   uint32   `json:"expectedServiceGID"`
	ExpectedWorkloadUID  uint32   `json:"expectedWorkloadUID"`
	ExpectedWorkloadGID  uint32   `json:"expectedWorkloadGID"`
	HelperProtocol       string   `json:"helperProtocol"`
}

type readinessSuccessJSON struct {
	ProtocolVersion string                   `json:"protocolVersion"`
	Operation       string                   `json:"operation"`
	RequestID       string                   `json:"requestId"`
	IdentityDigest  string                   `json:"identityDigest"`
	OK              bool                     `json:"ok"`
	Body            readinessSuccessBodyJSON `json:"body"`
}

type readinessSuccessBodyJSON struct {
	Capabilities           []string `json:"capabilities"`
	ServiceUID             uint32   `json:"serviceUID"`
	ServiceGID             uint32   `json:"serviceGID"`
	WorkloadUID            uint32   `json:"workloadUID"`
	WorkloadGID            uint32   `json:"workloadGID"`
	HelperProtocol         string   `json:"helperProtocol"`
	GuestSessionGeneration string   `json:"guestSessionGeneration"`
	HelperGeneration       string   `json:"helperGeneration"`
}

// NewReadinessRequest constructs the only valid readiness request body around
// the existing request-ID and base-session-ID representation authorities.
func NewReadinessRequest(requestID RequestID, sessionID IdentityDigest) (ReadinessRequest, error) {
	if _, err := EncodeRequestID(requestID); err != nil {
		return ReadinessRequest{}, ErrInvalidReadinessRequest
	}
	request := ReadinessRequest{state: &readinessRequestState{
		protocolVersion: ProtocolVersion,
		operation:       OperationReadiness,
		requestID:       requestID,
		identityDigest:  sessionID,
		body: readinessRequestBodyState{
			requiredCapabilities: canonicalReadinessCapabilities(),
			expectedServiceUID:   ReadinessServiceUID,
			expectedServiceGID:   ReadinessServiceGID,
			expectedWorkloadUID:  ReadinessWorkloadUID,
			expectedWorkloadGID:  ReadinessWorkloadGID,
			helperProtocol:       ReadinessHelperProtocol,
		},
	}}
	if err := ValidateReadinessRequest(request); err != nil {
		return ReadinessRequest{}, err
	}
	return request, nil
}

// ValidateReadinessRequest validates the complete opaque request envelope.
func ValidateReadinessRequest(request ReadinessRequest) error {
	if request.state == nil || request.state.protocolVersion != ProtocolVersion ||
		request.state.operation != OperationReadiness {
		return ErrInvalidReadinessRequest
	}
	if _, err := EncodeRequestID(request.state.requestID); err != nil {
		return ErrInvalidReadinessRequest
	}
	if !validReadinessRequestBody(request.state.body) {
		return ErrInvalidReadinessRequest
	}
	return nil
}

// EncodeReadinessRequest returns the sole canonical compact JSON encoding.
func EncodeReadinessRequest(request ReadinessRequest) ([]byte, error) {
	if err := ValidateReadinessRequest(request); err != nil {
		return nil, err
	}
	requestID, err := EncodeRequestID(request.state.requestID)
	if err != nil {
		return nil, ErrInvalidReadinessRequest
	}
	wire, err := json.Marshal(readinessRequestJSON{
		ProtocolVersion: request.state.protocolVersion,
		Operation:       string(request.state.operation),
		RequestID:       requestID,
		IdentityDigest:  EncodeIdentityDigest(request.state.identityDigest),
		Body: readinessRequestBodyJSON{
			RequiredCapabilities: append([]string(nil), request.state.body.requiredCapabilities...),
			ExpectedServiceUID:   request.state.body.expectedServiceUID,
			ExpectedServiceGID:   request.state.body.expectedServiceGID,
			ExpectedWorkloadUID:  request.state.body.expectedWorkloadUID,
			ExpectedWorkloadGID:  request.state.body.expectedWorkloadGID,
			HelperProtocol:       request.state.body.helperProtocol,
		},
	})
	if err != nil {
		return nil, ErrInvalidReadinessRequest
	}
	return wire, nil
}

// DecodeReadinessRequest accepts only the canonical request encoding and
// returns an opaque value with copy-safe accessors.
func DecodeReadinessRequest(wire []byte) (ReadinessRequest, error) {
	if !validReadinessJSONInput(wire) {
		return ReadinessRequest{}, ErrInvalidReadinessRequestJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var decoded readinessRequestJSON
	if err := decoder.Decode(&decoded); err != nil || requireReadinessJSONEOF(decoder) != nil {
		return ReadinessRequest{}, ErrInvalidReadinessRequestJSON
	}
	if decoded.ProtocolVersion != ProtocolVersion || decoded.Operation != string(OperationReadiness) ||
		!validReadinessRequestBodyJSON(decoded.Body) {
		return ReadinessRequest{}, ErrInvalidReadinessRequestJSON
	}
	requestID, err := ParseRequestID(decoded.RequestID)
	if err != nil {
		return ReadinessRequest{}, ErrInvalidReadinessRequestJSON
	}
	digest, err := ParseIdentityDigest(decoded.IdentityDigest)
	if err != nil {
		return ReadinessRequest{}, ErrInvalidReadinessRequestJSON
	}
	request, err := NewReadinessRequest(requestID, digest)
	if err != nil {
		return ReadinessRequest{}, ErrInvalidReadinessRequestJSON
	}
	canonical, err := EncodeReadinessRequest(request)
	if err != nil || !bytes.Equal(canonical, wire) {
		return ReadinessRequest{}, ErrInvalidReadinessRequestJSON
	}
	return request, nil
}

// NewReadinessSuccessResponse derives a response from a validated request and
// one authenticated helper safe ID. Callers cannot supply correlation fields.
func NewReadinessSuccessResponse(request ReadinessRequest, helperGeneration string) (ReadinessSuccessResponse, error) {
	if ValidateReadinessRequest(request) != nil || !validHelperGeneration(helperGeneration) {
		return ReadinessSuccessResponse{}, ErrInvalidReadinessSuccess
	}
	response := ReadinessSuccessResponse{state: &readinessSuccessState{
		protocolVersion: request.state.protocolVersion,
		operation:       request.state.operation,
		requestID:       request.state.requestID,
		identityDigest:  request.state.identityDigest,
		ok:              true,
		body: readinessSuccessBodyState{
			capabilities:           append([]string(nil), request.state.body.requiredCapabilities...),
			serviceUID:             request.state.body.expectedServiceUID,
			serviceGID:             request.state.body.expectedServiceGID,
			workloadUID:            request.state.body.expectedWorkloadUID,
			workloadGID:            request.state.body.expectedWorkloadGID,
			helperProtocol:         request.state.body.helperProtocol,
			guestSessionGeneration: EncodeIdentityDigest(request.state.identityDigest),
			helperGeneration:       helperGeneration,
		},
	}}
	if err := ValidateReadinessSuccessResponse(response); err != nil {
		return ReadinessSuccessResponse{}, err
	}
	return response, nil
}

// ValidateReadinessSuccessResponse validates the complete opaque success
// envelope and its internal session-generation derivation.
func ValidateReadinessSuccessResponse(response ReadinessSuccessResponse) error {
	if response.state == nil || response.state.protocolVersion != ProtocolVersion ||
		response.state.operation != OperationReadiness || !response.state.ok {
		return ErrInvalidReadinessSuccess
	}
	if _, err := EncodeRequestID(response.state.requestID); err != nil {
		return ErrInvalidReadinessSuccess
	}
	if !validReadinessSuccessBody(response.state.body, response.state.identityDigest) {
		return ErrInvalidReadinessSuccess
	}
	return nil
}

// EncodeReadinessSuccessResponse returns the sole canonical compact success
// JSON encoding.
func EncodeReadinessSuccessResponse(response ReadinessSuccessResponse) ([]byte, error) {
	if err := ValidateReadinessSuccessResponse(response); err != nil {
		return nil, err
	}
	requestID, err := EncodeRequestID(response.state.requestID)
	if err != nil {
		return nil, ErrInvalidReadinessSuccess
	}
	wire, err := json.Marshal(readinessSuccessJSON{
		ProtocolVersion: response.state.protocolVersion,
		Operation:       string(response.state.operation),
		RequestID:       requestID,
		IdentityDigest:  EncodeIdentityDigest(response.state.identityDigest),
		OK:              response.state.ok,
		Body: readinessSuccessBodyJSON{
			Capabilities:           append([]string(nil), response.state.body.capabilities...),
			ServiceUID:             response.state.body.serviceUID,
			ServiceGID:             response.state.body.serviceGID,
			WorkloadUID:            response.state.body.workloadUID,
			WorkloadGID:            response.state.body.workloadGID,
			HelperProtocol:         response.state.body.helperProtocol,
			GuestSessionGeneration: response.state.body.guestSessionGeneration,
			HelperGeneration:       response.state.body.helperGeneration,
		},
	})
	if err != nil {
		return nil, ErrInvalidReadinessSuccess
	}
	return wire, nil
}

// DecodeReadinessSuccessResponse accepts only a canonical response whose
// request ID and base session ID exactly match expected.
func DecodeReadinessSuccessResponse(expected ReadinessRequest, wire []byte) (ReadinessSuccessResponse, error) {
	if ValidateReadinessRequest(expected) != nil {
		return ReadinessSuccessResponse{}, ErrInvalidReadinessSuccess
	}
	if !validReadinessJSONInput(wire) {
		return ReadinessSuccessResponse{}, ErrInvalidReadinessSuccessJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	var decoded readinessSuccessJSON
	if err := decoder.Decode(&decoded); err != nil || requireReadinessJSONEOF(decoder) != nil {
		return ReadinessSuccessResponse{}, ErrInvalidReadinessSuccessJSON
	}
	if decoded.ProtocolVersion != ProtocolVersion || decoded.Operation != string(OperationReadiness) ||
		!decoded.OK || !validReadinessSuccessBodyJSON(decoded.Body) {
		return ReadinessSuccessResponse{}, ErrInvalidReadinessSuccessJSON
	}
	requestID, err := ParseRequestID(decoded.RequestID)
	if err != nil {
		return ReadinessSuccessResponse{}, ErrInvalidReadinessSuccessJSON
	}
	digest, err := ParseIdentityDigest(decoded.IdentityDigest)
	if err != nil {
		return ReadinessSuccessResponse{}, ErrInvalidReadinessSuccessJSON
	}
	if requestID != expected.state.requestID || digest != expected.state.identityDigest {
		return ReadinessSuccessResponse{}, ErrReadinessCorrelationMismatch
	}
	response, err := NewReadinessSuccessResponse(expected, decoded.Body.HelperGeneration)
	if err != nil {
		return ReadinessSuccessResponse{}, ErrInvalidReadinessSuccessJSON
	}
	canonical, err := EncodeReadinessSuccessResponse(response)
	if err != nil || !bytes.Equal(canonical, wire) {
		return ReadinessSuccessResponse{}, ErrInvalidReadinessSuccessJSON
	}
	return response, nil
}

func (request ReadinessRequest) RequestID() RequestID {
	if request.state == nil {
		return RequestID{}
	}
	return request.state.requestID
}

func (request ReadinessRequest) IdentityDigest() IdentityDigest {
	if request.state == nil {
		return IdentityDigest{}
	}
	return request.state.identityDigest
}

func (request ReadinessRequest) RequiredCapabilities() []string {
	if request.state == nil {
		return nil
	}
	return append([]string(nil), request.state.body.requiredCapabilities...)
}

func (request ReadinessRequest) ExpectedServiceUID() uint32 {
	if request.state == nil {
		return 0
	}
	return request.state.body.expectedServiceUID
}

func (request ReadinessRequest) ExpectedServiceGID() uint32 {
	if request.state == nil {
		return 0
	}
	return request.state.body.expectedServiceGID
}

func (request ReadinessRequest) ExpectedWorkloadUID() uint32 {
	if request.state == nil {
		return 0
	}
	return request.state.body.expectedWorkloadUID
}

func (request ReadinessRequest) ExpectedWorkloadGID() uint32 {
	if request.state == nil {
		return 0
	}
	return request.state.body.expectedWorkloadGID
}

func (request ReadinessRequest) HelperProtocol() string {
	if request.state == nil {
		return ""
	}
	return request.state.body.helperProtocol
}

func (response ReadinessSuccessResponse) RequestID() RequestID {
	if response.state == nil {
		return RequestID{}
	}
	return response.state.requestID
}

func (response ReadinessSuccessResponse) IdentityDigest() IdentityDigest {
	if response.state == nil {
		return IdentityDigest{}
	}
	return response.state.identityDigest
}

func (response ReadinessSuccessResponse) Capabilities() []string {
	if response.state == nil {
		return nil
	}
	return append([]string(nil), response.state.body.capabilities...)
}

func (response ReadinessSuccessResponse) ServiceUID() uint32 {
	if response.state == nil {
		return 0
	}
	return response.state.body.serviceUID
}

func (response ReadinessSuccessResponse) ServiceGID() uint32 {
	if response.state == nil {
		return 0
	}
	return response.state.body.serviceGID
}

func (response ReadinessSuccessResponse) WorkloadUID() uint32 {
	if response.state == nil {
		return 0
	}
	return response.state.body.workloadUID
}

func (response ReadinessSuccessResponse) WorkloadGID() uint32 {
	if response.state == nil {
		return 0
	}
	return response.state.body.workloadGID
}

func (response ReadinessSuccessResponse) HelperProtocol() string {
	if response.state == nil {
		return ""
	}
	return response.state.body.helperProtocol
}

func (response ReadinessSuccessResponse) GuestSessionGeneration() string {
	if response.state == nil {
		return ""
	}
	return response.state.body.guestSessionGeneration
}

func (response ReadinessSuccessResponse) HelperGeneration() string {
	if response.state == nil {
		return ""
	}
	return response.state.body.helperGeneration
}

func canonicalReadinessCapabilities() []string {
	return []string{
		ReadinessCapabilityCredentialLifecycle,
		ReadinessCapabilityCredentialExecBinding,
		ReadinessCapabilityHelperExactPID,
		ReadinessCapabilityFileTmpfs,
		ReadinessCapabilitySSHAgent,
	}
}

func validReadinessCapabilities(capabilities []string) bool {
	canonical := canonicalReadinessCapabilities()
	if len(capabilities) != len(canonical) {
		return false
	}
	for index := range canonical {
		if capabilities[index] != canonical[index] {
			return false
		}
	}
	return true
}

func validReadinessRequestBody(body readinessRequestBodyState) bool {
	return validReadinessCapabilities(body.requiredCapabilities) &&
		body.expectedServiceUID == ReadinessServiceUID && body.expectedServiceGID == ReadinessServiceGID &&
		body.expectedWorkloadUID == ReadinessWorkloadUID && body.expectedWorkloadGID == ReadinessWorkloadGID &&
		body.helperProtocol == ReadinessHelperProtocol
}

func validReadinessRequestBodyJSON(body readinessRequestBodyJSON) bool {
	return validReadinessCapabilities(body.RequiredCapabilities) &&
		body.ExpectedServiceUID == ReadinessServiceUID && body.ExpectedServiceGID == ReadinessServiceGID &&
		body.ExpectedWorkloadUID == ReadinessWorkloadUID && body.ExpectedWorkloadGID == ReadinessWorkloadGID &&
		body.HelperProtocol == ReadinessHelperProtocol
}

func validReadinessSuccessBody(body readinessSuccessBodyState, digest IdentityDigest) bool {
	return validReadinessCapabilities(body.capabilities) &&
		body.serviceUID == ReadinessServiceUID && body.serviceGID == ReadinessServiceGID &&
		body.workloadUID == ReadinessWorkloadUID && body.workloadGID == ReadinessWorkloadGID &&
		body.helperProtocol == ReadinessHelperProtocol &&
		body.guestSessionGeneration == EncodeIdentityDigest(digest) &&
		validHelperGeneration(body.helperGeneration)
}

func validReadinessSuccessBodyJSON(body readinessSuccessBodyJSON) bool {
	return validReadinessCapabilities(body.Capabilities) &&
		body.ServiceUID == ReadinessServiceUID && body.ServiceGID == ReadinessServiceGID &&
		body.WorkloadUID == ReadinessWorkloadUID && body.WorkloadGID == ReadinessWorkloadGID &&
		body.HelperProtocol == ReadinessHelperProtocol &&
		len(body.GuestSessionGeneration) == identityDigestEncodedLength &&
		validHelperGeneration(body.HelperGeneration)
}

func validHelperGeneration(value string) bool {
	return credentialprotocol.ValidateSafeID(credentialprotocol.SafeID(value)) == nil
}

func validReadinessJSONInput(wire []byte) bool {
	if len(wire) == 0 || len(wire) > maxReadinessJSONBytes || !utf8.Valid(wire) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	if !scanReadinessJSONValue(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func scanReadinessJSONValue(decoder *json.Decoder, depth int) bool {
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	nestedDepth := depth + 1
	if nestedDepth > maxReadinessJSONDepth {
		return false
	}
	switch delimiter {
	case '{':
		var keys [maxReadinessJSONObjectFields]string
		keyCount := 0
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, isString := keyToken.(string)
			if keyErr != nil || !isString || keyCount == len(keys) {
				return false
			}
			for index := 0; index < keyCount; index++ {
				if keys[index] == key {
					return false
				}
			}
			keys[keyCount] = key
			keyCount++
			if !scanReadinessJSONValue(decoder, nestedDepth) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		return closeErr == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !scanReadinessJSONValue(decoder, nestedDepth) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		return closeErr == nil && closing == json.Delim(']')
	default:
		return false
	}
}

func requireReadinessJSONEOF(decoder *json.Decoder) error {
	var trailing struct{}
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	}
	return ErrInvalidReadinessRequestJSON
}
