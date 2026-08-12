package v2control

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"unicode/utf8"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	maxCredentialLifecycleJSONBytes       = 2 * 1024 * 1024
	maxCredentialLifecycleJSONDepth       = 5
	maxCredentialLifecycleJSONTokens      = 512
	maxCredentialLifecycleJSONStringBytes = credentialprotocol.MaxSafeIDBytes
)

var (
	ErrInvalidCredentialRenewRequest       = errors.New("guest agent v2 credential renew request is invalid")
	ErrInvalidCredentialRenewRequestJSON   = errors.New("guest agent v2 credential renew request JSON is invalid")
	ErrInvalidCredentialRenewSuccess       = errors.New("guest agent v2 credential renew success response is invalid")
	ErrInvalidCredentialRenewSuccessJSON   = errors.New("guest agent v2 credential renew success response JSON is invalid")
	ErrCredentialRenewCorrelationMismatch  = errors.New("guest agent v2 credential renew response correlation does not match")
	ErrInvalidCredentialRevokeRequest      = errors.New("guest agent v2 credential revoke request is invalid")
	ErrInvalidCredentialRevokeRequestJSON  = errors.New("guest agent v2 credential revoke request JSON is invalid")
	ErrInvalidCredentialRevokeSuccess      = errors.New("guest agent v2 credential revoke success response is invalid")
	ErrInvalidCredentialRevokeSuccessJSON  = errors.New("guest agent v2 credential revoke success response JSON is invalid")
	ErrCredentialRevokeCorrelationMismatch = errors.New("guest agent v2 credential revoke response correlation does not match")
	ErrCredentialLifecycleSerialization    = errors.New("guest agent v2 credential lifecycle serialization is denied")
)

// CredentialRevokeReason is the closed reason catalog for credential_revoke.
type CredentialRevokeReason string

const (
	CredentialRevokeReasonRequested      CredentialRevokeReason = "requested"
	CredentialRevokeReasonExpired        CredentialRevokeReason = "expired"
	CredentialRevokeReasonSessionLoss    CredentialRevokeReason = "session_loss"
	CredentialRevokeReasonSourceRevoked  CredentialRevokeReason = "source_revoked"
	CredentialRevokeReasonWorkerCancel   CredentialRevokeReason = "worker_cancel"
	CredentialRevokeReasonDaemonShutdown CredentialRevokeReason = "daemon_shutdown"
)

// CredentialCleanupDisposition is the closed successful cleanup catalog.
type CredentialCleanupDisposition string

const CredentialCleanupDispositionComplete CredentialCleanupDisposition = "cleanup_complete"

// CredentialRenewRequest owns one canonical renew envelope together with the
// caller-supplied state needed to prove an exact monotonic bounded renewal.
type CredentialRenewRequest struct {
	state *credentialRenewRequestState
}

type credentialRenewRequestState struct {
	protocolVersion                     string
	operation                           Operation
	requestID                           RequestID
	identity                            GuestCredentialSessionIdentity
	identityDigest                      IdentityDigest
	priorRevision                       uint64
	revision                            uint64
	expiresAtUnixNano                   int64
	authenticatedSessionExpiresUnixNano int64
	rootExpiresAtUnixNano               int64
	priorProofID                        string
}

// CredentialRenewSuccessResponse owns one request-correlated canonical renew
// success envelope.
type CredentialRenewSuccessResponse struct {
	state *credentialRenewSuccessState
}

type credentialRenewSuccessState struct {
	protocolVersion          string
	operation                Operation
	requestID                RequestID
	identityDigest           IdentityDigest
	ok                       bool
	revision                 uint64
	expiresAtUnixNano        int64
	replacementActiveProofID string
}

// CredentialRevokeRequest owns one canonical revoke envelope and the caller's
// exact current revision.
type CredentialRevokeRequest struct {
	state *credentialRevokeRequestState
}

type credentialRevokeRequestState struct {
	protocolVersion string
	operation       Operation
	requestID       RequestID
	identity        GuestCredentialSessionIdentity
	identityDigest  IdentityDigest
	currentRevision uint64
	revision        uint64
	reason          CredentialRevokeReason
}

// CredentialRevokeSuccessResponse owns one request-correlated canonical
// cleanup-complete response.
type CredentialRevokeSuccessResponse struct {
	state *credentialRevokeSuccessState
}

type credentialRevokeSuccessState struct {
	protocolVersion    string
	operation          Operation
	requestID          RequestID
	identityDigest     IdentityDigest
	ok                 bool
	revision           uint64
	cleanupProofID     string
	authorityAbsent    bool
	resourcesAbsent    bool
	cleanupDisposition CredentialCleanupDisposition
}

type credentialRenewRequestJSON struct {
	ProtocolVersion string                         `json:"protocolVersion"`
	Operation       string                         `json:"operation"`
	RequestID       string                         `json:"requestId"`
	IdentityDigest  string                         `json:"identityDigest"`
	Body            credentialRenewRequestBodyJSON `json:"body"`
}

type credentialRenewRequestBodyJSON struct {
	Identity          JobIdentity `json:"identity"`
	Revision          uint64      `json:"revision"`
	ExpiresAtUnixNano int64       `json:"expiresAtUnixNano"`
	PriorProofID      string      `json:"priorProofId"`
}

type credentialRenewSuccessJSON struct {
	ProtocolVersion string                         `json:"protocolVersion"`
	Operation       string                         `json:"operation"`
	RequestID       string                         `json:"requestId"`
	IdentityDigest  string                         `json:"identityDigest"`
	OK              bool                           `json:"ok"`
	Body            credentialRenewSuccessBodyJSON `json:"body"`
}

type credentialRenewSuccessBodyJSON struct {
	Revision                 uint64 `json:"revision"`
	ExpiresAtUnixNano        int64  `json:"expiresAtUnixNano"`
	ReplacementActiveProofID string `json:"replacementActiveProofId"`
}

type credentialRevokeRequestJSON struct {
	ProtocolVersion string                          `json:"protocolVersion"`
	Operation       string                          `json:"operation"`
	RequestID       string                          `json:"requestId"`
	IdentityDigest  string                          `json:"identityDigest"`
	Body            credentialRevokeRequestBodyJSON `json:"body"`
}

type credentialRevokeRequestBodyJSON struct {
	Identity JobIdentity            `json:"identity"`
	Revision uint64                 `json:"revision"`
	Reason   CredentialRevokeReason `json:"reason"`
}

type credentialRevokeSuccessJSON struct {
	ProtocolVersion string                          `json:"protocolVersion"`
	Operation       string                          `json:"operation"`
	RequestID       string                          `json:"requestId"`
	IdentityDigest  string                          `json:"identityDigest"`
	OK              bool                            `json:"ok"`
	Body            credentialRevokeSuccessBodyJSON `json:"body"`
}

type credentialRevokeSuccessBodyJSON struct {
	Revision           uint64                       `json:"revision"`
	CleanupProofID     string                       `json:"cleanupProofId"`
	AuthorityAbsent    bool                         `json:"authorityAbsent"`
	ResourcesAbsent    bool                         `json:"resourcesAbsent"`
	CleanupDisposition CredentialCleanupDisposition `json:"cleanupDisposition"`
}

// NewCredentialRenewRequest constructs revision priorRevision+1 and validates
// its expiry against both authenticated caller-supplied horizons. It performs
// no clock read.
func NewCredentialRenewRequest(requestID RequestID, identity GuestCredentialSessionIdentity, priorRevision uint64, expiresAtUnixNano, authenticatedSessionExpiresUnixNano, rootExpiresAtUnixNano int64, priorProofID string) (CredentialRenewRequest, error) {
	digest, err := credentialLifecycleIdentityDigest(identity)
	if err != nil || priorRevision == 0 || priorRevision == ^uint64(0) {
		return CredentialRenewRequest{}, ErrInvalidCredentialRenewRequest
	}
	request := CredentialRenewRequest{state: &credentialRenewRequestState{
		protocolVersion: ProtocolVersion, operation: OperationCredentialRenew,
		requestID: requestID, identity: identity, identityDigest: digest,
		priorRevision: priorRevision, revision: priorRevision + 1,
		expiresAtUnixNano:                   expiresAtUnixNano,
		authenticatedSessionExpiresUnixNano: authenticatedSessionExpiresUnixNano,
		rootExpiresAtUnixNano:               rootExpiresAtUnixNano, priorProofID: priorProofID,
	}}
	if err := ValidateCredentialRenewRequest(request); err != nil {
		return CredentialRenewRequest{}, err
	}
	return request, nil
}

// ValidateCredentialRenewRequest revalidates exact revision arithmetic,
// authenticated horizons, identity digest, and safe proof identity.
func ValidateCredentialRenewRequest(request CredentialRenewRequest) error {
	if request.state == nil || request.state.protocolVersion != ProtocolVersion ||
		request.state.operation != OperationCredentialRenew || request.state.priorRevision == 0 ||
		request.state.priorRevision == ^uint64(0) || request.state.revision != request.state.priorRevision+1 ||
		request.state.expiresAtUnixNano <= 0 || request.state.authenticatedSessionExpiresUnixNano <= 0 ||
		request.state.rootExpiresAtUnixNano <= 0 ||
		!validCredentialRenewRootExpiry(request.state.identity.JobIdentity().IssuedAtUnixNano, request.state.expiresAtUnixNano) ||
		request.state.expiresAtUnixNano > request.state.authenticatedSessionExpiresUnixNano ||
		request.state.expiresAtUnixNano > request.state.rootExpiresAtUnixNano ||
		!validCredentialLifecycleSafeID(request.state.priorProofID) {
		return ErrInvalidCredentialRenewRequest
	}
	if _, err := EncodeRequestID(request.state.requestID); err != nil {
		return ErrInvalidCredentialRenewRequest
	}
	digest, err := credentialLifecycleIdentityDigest(request.state.identity)
	if err != nil || digest != request.state.identityDigest {
		return ErrInvalidCredentialRenewRequest
	}
	return nil
}

// EncodeCredentialRenewRequest returns the sole canonical compact encoding.
func EncodeCredentialRenewRequest(request CredentialRenewRequest) ([]byte, error) {
	if ValidateCredentialRenewRequest(request) != nil {
		return nil, ErrInvalidCredentialRenewRequest
	}
	requestID, _ := EncodeRequestID(request.state.requestID)
	wire, err := json.Marshal(credentialRenewRequestJSON{
		ProtocolVersion: request.state.protocolVersion, Operation: string(request.state.operation),
		RequestID: requestID, IdentityDigest: EncodeIdentityDigest(request.state.identityDigest),
		Body: credentialRenewRequestBodyJSON{
			Identity: request.state.identity.JobIdentity(), Revision: request.state.revision,
			ExpiresAtUnixNano: request.state.expiresAtUnixNano, PriorProofID: request.state.priorProofID,
		},
	})
	if err != nil {
		return nil, ErrInvalidCredentialRenewRequest
	}
	return wire, nil
}

// DecodeCredentialRenewRequest accepts only canonical bytes matching the
// authenticated identity, current proof, prior revision, and expiry horizons.
func DecodeCredentialRenewRequest(expectedIdentity GuestCredentialSessionIdentity, priorRevision uint64, expectedPriorProofID string, authenticatedSessionExpiresUnixNano, rootExpiresAtUnixNano int64, wire []byte) (CredentialRenewRequest, error) {
	if ValidateGuestCredentialSessionIdentity(expectedIdentity) != nil ||
		!validCredentialLifecycleSafeID(expectedPriorProofID) || !validCredentialLifecycleJSONInput(wire) {
		return CredentialRenewRequest{}, ErrInvalidCredentialRenewRequestJSON
	}
	var decoded credentialRenewRequestJSON
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || requireCredentialLifecycleJSONEOF(decoder) != nil || decoded.ProtocolVersion != ProtocolVersion || decoded.Operation != string(OperationCredentialRenew) {
		return CredentialRenewRequest{}, ErrInvalidCredentialRenewRequestJSON
	}
	requestID, err := ParseRequestID(decoded.RequestID)
	if err != nil {
		return CredentialRenewRequest{}, ErrInvalidCredentialRenewRequestJSON
	}
	digest, err := ParseIdentityDigest(decoded.IdentityDigest)
	if err != nil || !sameCredentialLifecycleIdentity(decoded.Body.Identity, expectedIdentity.JobIdentity()) {
		return CredentialRenewRequest{}, ErrInvalidCredentialRenewRequestJSON
	}
	expectedDigest, err := credentialLifecycleIdentityDigest(expectedIdentity)
	if err != nil || digest != expectedDigest || priorRevision == 0 || priorRevision == ^uint64(0) ||
		decoded.Body.Revision != priorRevision+1 || decoded.Body.PriorProofID != expectedPriorProofID {
		return CredentialRenewRequest{}, ErrInvalidCredentialRenewRequestJSON
	}
	request, err := NewCredentialRenewRequest(requestID, expectedIdentity, priorRevision, decoded.Body.ExpiresAtUnixNano, authenticatedSessionExpiresUnixNano, rootExpiresAtUnixNano, decoded.Body.PriorProofID)
	if err != nil {
		return CredentialRenewRequest{}, ErrInvalidCredentialRenewRequestJSON
	}
	canonical, err := EncodeCredentialRenewRequest(request)
	if err != nil || !bytes.Equal(canonical, wire) {
		return CredentialRenewRequest{}, ErrInvalidCredentialRenewRequestJSON
	}
	return request, nil
}

// NewCredentialRenewSuccessResponse derives every correlation and lifecycle
// scalar from the expected request.
func NewCredentialRenewSuccessResponse(request CredentialRenewRequest, replacementActiveProofID string) (CredentialRenewSuccessResponse, error) {
	if ValidateCredentialRenewRequest(request) != nil || !validCredentialLifecycleSafeID(replacementActiveProofID) {
		return CredentialRenewSuccessResponse{}, ErrInvalidCredentialRenewSuccess
	}
	response := CredentialRenewSuccessResponse{state: &credentialRenewSuccessState{
		protocolVersion: request.state.protocolVersion, operation: request.state.operation,
		requestID: request.state.requestID, identityDigest: request.state.identityDigest, ok: true,
		revision: request.state.revision, expiresAtUnixNano: request.state.expiresAtUnixNano,
		replacementActiveProofID: replacementActiveProofID,
	}}
	if ValidateCredentialRenewSuccessResponse(response) != nil {
		return CredentialRenewSuccessResponse{}, ErrInvalidCredentialRenewSuccess
	}
	return response, nil
}

// ValidateCredentialRenewSuccessResponse validates the opaque success owner.
func ValidateCredentialRenewSuccessResponse(response CredentialRenewSuccessResponse) error {
	if response.state == nil || response.state.protocolVersion != ProtocolVersion ||
		response.state.operation != OperationCredentialRenew || !response.state.ok ||
		response.state.revision == 0 || response.state.expiresAtUnixNano <= 0 ||
		!validCredentialLifecycleSafeID(response.state.replacementActiveProofID) {
		return ErrInvalidCredentialRenewSuccess
	}
	if _, err := EncodeRequestID(response.state.requestID); err != nil {
		return ErrInvalidCredentialRenewSuccess
	}
	return nil
}

// EncodeCredentialRenewSuccessResponse returns canonical compact JSON.
func EncodeCredentialRenewSuccessResponse(response CredentialRenewSuccessResponse) ([]byte, error) {
	if ValidateCredentialRenewSuccessResponse(response) != nil {
		return nil, ErrInvalidCredentialRenewSuccess
	}
	requestID, _ := EncodeRequestID(response.state.requestID)
	wire, err := json.Marshal(credentialRenewSuccessJSON{
		ProtocolVersion: response.state.protocolVersion, Operation: string(response.state.operation),
		RequestID: requestID, IdentityDigest: EncodeIdentityDigest(response.state.identityDigest), OK: true,
		Body: credentialRenewSuccessBodyJSON{
			Revision: response.state.revision, ExpiresAtUnixNano: response.state.expiresAtUnixNano,
			ReplacementActiveProofID: response.state.replacementActiveProofID,
		},
	})
	if err != nil {
		return nil, ErrInvalidCredentialRenewSuccess
	}
	return wire, nil
}

// DecodeCredentialRenewSuccessResponse requires the originating request and
// exposes no uncorrelated generic success path.
func DecodeCredentialRenewSuccessResponse(expected CredentialRenewRequest, wire []byte) (CredentialRenewSuccessResponse, error) {
	if ValidateCredentialRenewRequest(expected) != nil {
		return CredentialRenewSuccessResponse{}, ErrInvalidCredentialRenewSuccess
	}
	if !validCredentialLifecycleJSONInput(wire) {
		return CredentialRenewSuccessResponse{}, ErrInvalidCredentialRenewSuccessJSON
	}
	var decoded credentialRenewSuccessJSON
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || requireCredentialLifecycleJSONEOF(decoder) != nil || decoded.ProtocolVersion != ProtocolVersion ||
		decoded.Operation != string(OperationCredentialRenew) || !decoded.OK ||
		decoded.Body.Revision == 0 || decoded.Body.ExpiresAtUnixNano <= 0 ||
		!validCredentialLifecycleSafeID(decoded.Body.ReplacementActiveProofID) {
		return CredentialRenewSuccessResponse{}, ErrInvalidCredentialRenewSuccessJSON
	}
	requestID, err := ParseRequestID(decoded.RequestID)
	if err != nil {
		return CredentialRenewSuccessResponse{}, ErrInvalidCredentialRenewSuccessJSON
	}
	digest, err := ParseIdentityDigest(decoded.IdentityDigest)
	if err != nil {
		return CredentialRenewSuccessResponse{}, ErrInvalidCredentialRenewSuccessJSON
	}
	if requestID != expected.state.requestID || digest != expected.state.identityDigest ||
		decoded.Body.Revision != expected.state.revision || decoded.Body.ExpiresAtUnixNano != expected.state.expiresAtUnixNano {
		return CredentialRenewSuccessResponse{}, ErrCredentialRenewCorrelationMismatch
	}
	response, err := NewCredentialRenewSuccessResponse(expected, decoded.Body.ReplacementActiveProofID)
	if err != nil {
		return CredentialRenewSuccessResponse{}, ErrInvalidCredentialRenewSuccessJSON
	}
	canonical, err := EncodeCredentialRenewSuccessResponse(response)
	if err != nil || !bytes.Equal(canonical, wire) {
		return CredentialRenewSuccessResponse{}, ErrInvalidCredentialRenewSuccessJSON
	}
	return response, nil
}

// NewCredentialRevokeRequest constructs a revoke at exactly currentRevision.
func NewCredentialRevokeRequest(requestID RequestID, identity GuestCredentialSessionIdentity, currentRevision uint64, reason CredentialRevokeReason) (CredentialRevokeRequest, error) {
	digest, err := credentialLifecycleIdentityDigest(identity)
	if err != nil {
		return CredentialRevokeRequest{}, ErrInvalidCredentialRevokeRequest
	}
	request := CredentialRevokeRequest{state: &credentialRevokeRequestState{
		protocolVersion: ProtocolVersion, operation: OperationCredentialRevoke,
		requestID: requestID, identity: identity, identityDigest: digest,
		currentRevision: currentRevision, revision: currentRevision, reason: reason,
	}}
	if ValidateCredentialRevokeRequest(request) != nil {
		return CredentialRevokeRequest{}, ErrInvalidCredentialRevokeRequest
	}
	return request, nil
}

// ValidateCredentialRevokeRequest validates current revision, identity, and
// the exact reason catalog.
func ValidateCredentialRevokeRequest(request CredentialRevokeRequest) error {
	if request.state == nil || request.state.protocolVersion != ProtocolVersion ||
		request.state.operation != OperationCredentialRevoke || request.state.currentRevision == 0 ||
		request.state.revision != request.state.currentRevision || !validCredentialRevokeReason(request.state.reason) {
		return ErrInvalidCredentialRevokeRequest
	}
	if _, err := EncodeRequestID(request.state.requestID); err != nil {
		return ErrInvalidCredentialRevokeRequest
	}
	digest, err := credentialLifecycleIdentityDigest(request.state.identity)
	if err != nil || digest != request.state.identityDigest {
		return ErrInvalidCredentialRevokeRequest
	}
	return nil
}

// EncodeCredentialRevokeRequest returns the sole canonical compact encoding.
func EncodeCredentialRevokeRequest(request CredentialRevokeRequest) ([]byte, error) {
	if ValidateCredentialRevokeRequest(request) != nil {
		return nil, ErrInvalidCredentialRevokeRequest
	}
	requestID, _ := EncodeRequestID(request.state.requestID)
	wire, err := json.Marshal(credentialRevokeRequestJSON{
		ProtocolVersion: request.state.protocolVersion, Operation: string(request.state.operation),
		RequestID: requestID, IdentityDigest: EncodeIdentityDigest(request.state.identityDigest),
		Body: credentialRevokeRequestBodyJSON{
			Identity: request.state.identity.JobIdentity(), Revision: request.state.revision, Reason: request.state.reason,
		},
	})
	if err != nil {
		return nil, ErrInvalidCredentialRevokeRequest
	}
	return wire, nil
}

// DecodeCredentialRevokeRequest accepts only canonical bytes matching the
// authenticated identity and caller's exact current revision.
func DecodeCredentialRevokeRequest(expectedIdentity GuestCredentialSessionIdentity, currentRevision uint64, wire []byte) (CredentialRevokeRequest, error) {
	if ValidateGuestCredentialSessionIdentity(expectedIdentity) != nil || !validCredentialLifecycleJSONInput(wire) {
		return CredentialRevokeRequest{}, ErrInvalidCredentialRevokeRequestJSON
	}
	var decoded credentialRevokeRequestJSON
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || requireCredentialLifecycleJSONEOF(decoder) != nil || decoded.ProtocolVersion != ProtocolVersion || decoded.Operation != string(OperationCredentialRevoke) ||
		decoded.Body.Revision != currentRevision || !sameCredentialLifecycleIdentity(decoded.Body.Identity, expectedIdentity.JobIdentity()) {
		return CredentialRevokeRequest{}, ErrInvalidCredentialRevokeRequestJSON
	}
	requestID, err := ParseRequestID(decoded.RequestID)
	if err != nil {
		return CredentialRevokeRequest{}, ErrInvalidCredentialRevokeRequestJSON
	}
	digest, err := ParseIdentityDigest(decoded.IdentityDigest)
	expectedDigest, digestErr := credentialLifecycleIdentityDigest(expectedIdentity)
	if err != nil || digestErr != nil || digest != expectedDigest {
		return CredentialRevokeRequest{}, ErrInvalidCredentialRevokeRequestJSON
	}
	request, err := NewCredentialRevokeRequest(requestID, expectedIdentity, currentRevision, decoded.Body.Reason)
	if err != nil {
		return CredentialRevokeRequest{}, ErrInvalidCredentialRevokeRequestJSON
	}
	canonical, err := EncodeCredentialRevokeRequest(request)
	if err != nil || !bytes.Equal(canonical, wire) {
		return CredentialRevokeRequest{}, ErrInvalidCredentialRevokeRequestJSON
	}
	return request, nil
}

// NewCredentialRevokeSuccessResponse derives all correlation, revision, and
// fixed absence/disposition fields from one expected revoke request.
func NewCredentialRevokeSuccessResponse(request CredentialRevokeRequest, cleanupProofID string) (CredentialRevokeSuccessResponse, error) {
	if ValidateCredentialRevokeRequest(request) != nil || !validCredentialLifecycleSafeID(cleanupProofID) {
		return CredentialRevokeSuccessResponse{}, ErrInvalidCredentialRevokeSuccess
	}
	response := CredentialRevokeSuccessResponse{state: &credentialRevokeSuccessState{
		protocolVersion: request.state.protocolVersion, operation: request.state.operation,
		requestID: request.state.requestID, identityDigest: request.state.identityDigest, ok: true,
		revision: request.state.revision, cleanupProofID: cleanupProofID,
		authorityAbsent: true, resourcesAbsent: true,
		cleanupDisposition: CredentialCleanupDispositionComplete,
	}}
	if ValidateCredentialRevokeSuccessResponse(response) != nil {
		return CredentialRevokeSuccessResponse{}, ErrInvalidCredentialRevokeSuccess
	}
	return response, nil
}

// ValidateCredentialRevokeSuccessResponse requires proved authority and
// resource absence with the sole successful disposition.
func ValidateCredentialRevokeSuccessResponse(response CredentialRevokeSuccessResponse) error {
	if response.state == nil || response.state.protocolVersion != ProtocolVersion ||
		response.state.operation != OperationCredentialRevoke || !response.state.ok ||
		response.state.revision == 0 || !validCredentialLifecycleSafeID(response.state.cleanupProofID) ||
		!response.state.authorityAbsent || !response.state.resourcesAbsent ||
		response.state.cleanupDisposition != CredentialCleanupDispositionComplete {
		return ErrInvalidCredentialRevokeSuccess
	}
	if _, err := EncodeRequestID(response.state.requestID); err != nil {
		return ErrInvalidCredentialRevokeSuccess
	}
	return nil
}

// EncodeCredentialRevokeSuccessResponse returns canonical compact JSON.
func EncodeCredentialRevokeSuccessResponse(response CredentialRevokeSuccessResponse) ([]byte, error) {
	if ValidateCredentialRevokeSuccessResponse(response) != nil {
		return nil, ErrInvalidCredentialRevokeSuccess
	}
	requestID, _ := EncodeRequestID(response.state.requestID)
	wire, err := json.Marshal(credentialRevokeSuccessJSON{
		ProtocolVersion: response.state.protocolVersion, Operation: string(response.state.operation),
		RequestID: requestID, IdentityDigest: EncodeIdentityDigest(response.state.identityDigest), OK: true,
		Body: credentialRevokeSuccessBodyJSON{
			Revision: response.state.revision, CleanupProofID: response.state.cleanupProofID,
			AuthorityAbsent: true, ResourcesAbsent: true,
			CleanupDisposition: CredentialCleanupDispositionComplete,
		},
	})
	if err != nil {
		return nil, ErrInvalidCredentialRevokeSuccess
	}
	return wire, nil
}

// DecodeCredentialRevokeSuccessResponse requires the originating request and
// exposes no uncorrelated generic success path.
func DecodeCredentialRevokeSuccessResponse(expected CredentialRevokeRequest, wire []byte) (CredentialRevokeSuccessResponse, error) {
	if ValidateCredentialRevokeRequest(expected) != nil {
		return CredentialRevokeSuccessResponse{}, ErrInvalidCredentialRevokeSuccess
	}
	if !validCredentialLifecycleJSONInput(wire) {
		return CredentialRevokeSuccessResponse{}, ErrInvalidCredentialRevokeSuccessJSON
	}
	var decoded credentialRevokeSuccessJSON
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&decoded) != nil || requireCredentialLifecycleJSONEOF(decoder) != nil || decoded.ProtocolVersion != ProtocolVersion ||
		decoded.Operation != string(OperationCredentialRevoke) || !decoded.OK || decoded.Body.Revision == 0 ||
		!validCredentialLifecycleSafeID(decoded.Body.CleanupProofID) || !decoded.Body.AuthorityAbsent ||
		!decoded.Body.ResourcesAbsent || decoded.Body.CleanupDisposition != CredentialCleanupDispositionComplete {
		return CredentialRevokeSuccessResponse{}, ErrInvalidCredentialRevokeSuccessJSON
	}
	requestID, err := ParseRequestID(decoded.RequestID)
	if err != nil {
		return CredentialRevokeSuccessResponse{}, ErrInvalidCredentialRevokeSuccessJSON
	}
	digest, err := ParseIdentityDigest(decoded.IdentityDigest)
	if err != nil {
		return CredentialRevokeSuccessResponse{}, ErrInvalidCredentialRevokeSuccessJSON
	}
	if requestID != expected.state.requestID || digest != expected.state.identityDigest || decoded.Body.Revision != expected.state.revision {
		return CredentialRevokeSuccessResponse{}, ErrCredentialRevokeCorrelationMismatch
	}
	response, err := NewCredentialRevokeSuccessResponse(expected, decoded.Body.CleanupProofID)
	if err != nil {
		return CredentialRevokeSuccessResponse{}, ErrInvalidCredentialRevokeSuccessJSON
	}
	canonical, err := EncodeCredentialRevokeSuccessResponse(response)
	if err != nil || !bytes.Equal(canonical, wire) {
		return CredentialRevokeSuccessResponse{}, ErrInvalidCredentialRevokeSuccessJSON
	}
	return response, nil
}

func (request CredentialRenewRequest) RequestID() RequestID {
	if request.state == nil {
		return RequestID{}
	}
	return request.state.requestID
}
func (request CredentialRenewRequest) IdentityDigest() IdentityDigest {
	if request.state == nil {
		return IdentityDigest{}
	}
	return request.state.identityDigest
}
func (request CredentialRenewRequest) Identity() JobIdentity {
	if request.state == nil {
		return JobIdentity{}
	}
	return request.state.identity.JobIdentity()
}
func (request CredentialRenewRequest) Revision() uint64 {
	if request.state == nil {
		return 0
	}
	return request.state.revision
}
func (request CredentialRenewRequest) ExpiresAtUnixNano() int64 {
	if request.state == nil {
		return 0
	}
	return request.state.expiresAtUnixNano
}
func (request CredentialRenewRequest) PriorProofID() string {
	if request.state == nil {
		return ""
	}
	return request.state.priorProofID
}
func (response CredentialRenewSuccessResponse) Revision() uint64 {
	if response.state == nil {
		return 0
	}
	return response.state.revision
}
func (response CredentialRenewSuccessResponse) RequestID() RequestID {
	if response.state == nil {
		return RequestID{}
	}
	return response.state.requestID
}
func (response CredentialRenewSuccessResponse) IdentityDigest() IdentityDigest {
	if response.state == nil {
		return IdentityDigest{}
	}
	return response.state.identityDigest
}
func (response CredentialRenewSuccessResponse) ExpiresAtUnixNano() int64 {
	if response.state == nil {
		return 0
	}
	return response.state.expiresAtUnixNano
}
func (response CredentialRenewSuccessResponse) ReplacementActiveProofID() string {
	if response.state == nil {
		return ""
	}
	return response.state.replacementActiveProofID
}
func (request CredentialRevokeRequest) RequestID() RequestID {
	if request.state == nil {
		return RequestID{}
	}
	return request.state.requestID
}
func (request CredentialRevokeRequest) IdentityDigest() IdentityDigest {
	if request.state == nil {
		return IdentityDigest{}
	}
	return request.state.identityDigest
}
func (request CredentialRevokeRequest) Identity() JobIdentity {
	if request.state == nil {
		return JobIdentity{}
	}
	return request.state.identity.JobIdentity()
}
func (request CredentialRevokeRequest) Revision() uint64 {
	if request.state == nil {
		return 0
	}
	return request.state.revision
}
func (request CredentialRevokeRequest) Reason() CredentialRevokeReason {
	if request.state == nil {
		return ""
	}
	return request.state.reason
}
func (response CredentialRevokeSuccessResponse) Revision() uint64 {
	if response.state == nil {
		return 0
	}
	return response.state.revision
}
func (response CredentialRevokeSuccessResponse) RequestID() RequestID {
	if response.state == nil {
		return RequestID{}
	}
	return response.state.requestID
}
func (response CredentialRevokeSuccessResponse) IdentityDigest() IdentityDigest {
	if response.state == nil {
		return IdentityDigest{}
	}
	return response.state.identityDigest
}
func (response CredentialRevokeSuccessResponse) CleanupProofID() string {
	if response.state == nil {
		return ""
	}
	return response.state.cleanupProofID
}
func (response CredentialRevokeSuccessResponse) AuthorityAbsent() bool {
	return response.state != nil && response.state.authorityAbsent
}
func (response CredentialRevokeSuccessResponse) ResourcesAbsent() bool {
	return response.state != nil && response.state.resourcesAbsent
}
func (response CredentialRevokeSuccessResponse) CleanupDisposition() CredentialCleanupDisposition {
	if response.state == nil {
		return ""
	}
	return response.state.cleanupDisposition
}

func credentialLifecycleIdentityDigest(identity GuestCredentialSessionIdentity) (IdentityDigest, error) {
	digest, err := GuestCredentialSessionIdentityDigest(identity)
	if err != nil {
		return IdentityDigest{}, err
	}
	return NewIdentityDigest(digest), nil
}

func validCredentialLifecycleSafeID(value string) bool {
	return credentialprotocol.ValidateSafeID(credentialprotocol.SafeID(value)) == nil
}

func validCredentialRenewRootExpiry(issuedAtUnixNano, expiresAtUnixNano int64) bool {
	maximumLifetime := int64(sandboxruntime.MaxJobCredentialLifetime)
	return issuedAtUnixNano > 0 && maximumLifetime > 0 &&
		issuedAtUnixNano <= math.MaxInt64-maximumLifetime &&
		expiresAtUnixNano > issuedAtUnixNano &&
		expiresAtUnixNano <= issuedAtUnixNano+maximumLifetime
}

func validCredentialRevokeReason(reason CredentialRevokeReason) bool {
	switch reason {
	case CredentialRevokeReasonRequested, CredentialRevokeReasonExpired,
		CredentialRevokeReasonSessionLoss, CredentialRevokeReasonSourceRevoked,
		CredentialRevokeReasonWorkerCancel, CredentialRevokeReasonDaemonShutdown:
		return true
	default:
		return false
	}
}

func sameCredentialLifecycleIdentity(left, right JobIdentity) bool {
	leftWire, leftErr := MarshalJobIdentity(left)
	rightWire, rightErr := MarshalJobIdentity(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftWire, rightWire)
}

func requireCredentialLifecycleJSONEOF(decoder *json.Decoder) error {
	var trailing struct{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrInvalidCredentialRenewRequestJSON
	}
	return nil
}

func validCredentialLifecycleJSONInput(wire []byte) bool {
	if len(wire) == 0 || len(wire) > maxCredentialLifecycleJSONBytes || !utf8.Valid(wire) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	tokens := 0
	if !scanCredentialLifecycleJSONValue(decoder, 0, &tokens) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func scanCredentialLifecycleJSONValue(decoder *json.Decoder, depth int, tokens *int) bool {
	token, err := decoder.Token()
	if err != nil || !countCredentialLifecycleToken(tokens) {
		return false
	}
	if value, ok := token.(string); ok && len(value) > maxCredentialLifecycleJSONStringBytes {
		return false
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return true
	}
	nestedDepth := depth + 1
	if nestedDepth > maxCredentialLifecycleJSONDepth {
		return false
	}
	switch delimiter {
	case '{':
		var keys [40]string
		keyCount := 0
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, isString := keyToken.(string)
			if keyErr != nil || !isString || len(key) > maxCredentialLifecycleJSONStringBytes ||
				!countCredentialLifecycleToken(tokens) || keyCount == len(keys) {
				return false
			}
			for index := 0; index < keyCount; index++ {
				if keys[index] == key {
					return false
				}
			}
			keys[keyCount] = key
			keyCount++
			if !scanCredentialLifecycleJSONValue(decoder, nestedDepth, tokens) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim('}') && countCredentialLifecycleToken(tokens)
	case '[':
		for decoder.More() {
			if !scanCredentialLifecycleJSONValue(decoder, nestedDepth, tokens) {
				return false
			}
		}
		end, endErr := decoder.Token()
		return endErr == nil && end == json.Delim(']') && countCredentialLifecycleToken(tokens)
	default:
		return false
	}
}

func countCredentialLifecycleToken(tokens *int) bool {
	*tokens++
	return *tokens <= maxCredentialLifecycleJSONTokens
}
