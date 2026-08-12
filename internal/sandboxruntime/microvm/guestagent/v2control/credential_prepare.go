package v2control

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const (
	maxCredentialPrepareJSONBytes        = 2 * 1024 * 1024
	maxCredentialPrepareJSONDepth        = 5
	maxCredentialPrepareJSONTokens       = 512
	maxCredentialPrepareJSONObjectFields = 64
	maxCredentialPrepareJSONStringBytes  = credentialprotocol.MaxRelativePathBytes
	maxCredentialPrepareBindings         = credentialprotocol.MaxHelperBindings
	maxCredentialPrepareFileBytes        = credentialprotocol.MaxHelperFileBytes
	maxCredentialPrepareAggregateBytes   = credentialprotocol.MaxHelperFileAggregateBytes
)

var (
	ErrInvalidBindingManifest               = errors.New("guest agent v2 credential prepare binding manifest is invalid")
	ErrInvalidBindingProof                  = errors.New("guest agent v2 credential prepare binding proof is invalid")
	ErrInvalidCredentialPrepareRequest      = errors.New("guest agent v2 credential prepare request is invalid")
	ErrInvalidCredentialPrepareRequestJSON  = errors.New("guest agent v2 credential prepare request JSON is invalid")
	ErrInvalidCredentialPrepareSuccess      = errors.New("guest agent v2 credential prepare success response is invalid")
	ErrInvalidCredentialPrepareSuccessJSON  = errors.New("guest agent v2 credential prepare success response JSON is invalid")
	ErrCredentialPrepareCorrelationMismatch = errors.New("guest agent v2 credential prepare response correlation does not match")
	ErrCredentialPrepareSerialization       = errors.New("guest agent v2 credential prepare serialization is denied")
)

// BindingManifest is one opaque member of the closed HTTP, file, and SSH
// credential-prepare manifest union.
type BindingManifest struct {
	state bindingManifestState
}

type bindingManifestState struct {
	bindingID         string
	mode              DeliveryMode
	serviceID         string
	targetPath        string
	declaredFileBytes uint32
	fileSHA256        string
	sshPolicyID       string
	sshPolicyRevision uint64
}

// BindingProof is one opaque manifest-correlated success proof.
type BindingProof struct {
	state bindingProofState
}

type bindingProofState struct {
	bindingID string
	mode      DeliveryMode
	proofID   string
}

// CredentialPrepareRequest owns one complete canonical request envelope.
type CredentialPrepareRequest struct {
	state *credentialPrepareRequestState
}

type credentialPrepareRequestState struct {
	protocolVersion       string
	operation             Operation
	requestID             RequestID
	identityDigest        IdentityDigest
	identity              JobIdentity
	revision              uint64
	expiresAtUnixNano     int64
	bindings              []BindingManifest
	privateRecordCount    uint32
	privateAggregateBytes uint64
}

// CredentialPrepareSuccessResponse owns one complete canonical success
// envelope whose correlation and proof layout are derived from a request.
type CredentialPrepareSuccessResponse struct {
	state *credentialPrepareSuccessState
}

type credentialPrepareSuccessState struct {
	protocolVersion   string
	operation         Operation
	requestID         RequestID
	identityDigest    IdentityDigest
	ok                bool
	revision          uint64
	expiresAtUnixNano int64
	activeProofID     string
	execBindingID     string
	bindingProofs     []BindingProof
}

// NewHTTPBindingManifest constructs the exact HTTP manifest union member.
func NewHTTPBindingManifest(bindingID, serviceID string) (BindingManifest, error) {
	return newBindingManifest(bindingManifestState{
		bindingID: bindingID, mode: DeliveryMode("http_proxy"), serviceID: serviceID,
	})
}

// NewFileBindingManifest constructs the exact tmpfs-file manifest union member.
func NewFileBindingManifest(bindingID, targetPath string, declaredFileBytes uint32, fileSHA256 string) (BindingManifest, error) {
	return newBindingManifest(bindingManifestState{
		bindingID: bindingID, mode: DeliveryMode("file_tmpfs"), targetPath: targetPath,
		declaredFileBytes: declaredFileBytes, fileSHA256: fileSHA256,
	})
}

// NewSSHBindingManifest constructs the exact SSH-agent manifest union member.
func NewSSHBindingManifest(bindingID, sshPolicyID string, sshPolicyRevision uint64) (BindingManifest, error) {
	return newBindingManifest(bindingManifestState{
		bindingID: bindingID, mode: DeliveryMode("ssh_agent"),
		sshPolicyID: sshPolicyID, sshPolicyRevision: sshPolicyRevision,
	})
}

func newBindingManifest(state bindingManifestState) (BindingManifest, error) {
	manifest := BindingManifest{state: state}
	if ValidateBindingManifest(manifest) != nil {
		return BindingManifest{}, ErrInvalidBindingManifest
	}
	return manifest, nil
}

// ValidateBindingManifest validates the sole state for its closed union mode.
func ValidateBindingManifest(manifest BindingManifest) error {
	state := manifest.state
	if !validPrepareSafeID(state.bindingID) {
		return ErrInvalidBindingManifest
	}
	switch state.mode {
	case DeliveryMode("http_proxy"):
		if !validPrepareSafeID(state.serviceID) || state.targetPath != "" ||
			state.declaredFileBytes != 0 || state.fileSHA256 != "" ||
			state.sshPolicyID != "" || state.sshPolicyRevision != 0 {
			return ErrInvalidBindingManifest
		}
	case DeliveryMode("file_tmpfs"):
		if state.serviceID != "" || state.targetPath == "" ||
			credentialprotocol.ValidateOptionalRelativePath(state.targetPath) != nil ||
			state.declaredFileBytes == 0 || state.declaredFileBytes > maxCredentialPrepareFileBytes ||
			!validLowerSHA256(state.fileSHA256) || state.sshPolicyID != "" || state.sshPolicyRevision != 0 {
			return ErrInvalidBindingManifest
		}
	case DeliveryMode("ssh_agent"):
		if state.serviceID != "" || state.targetPath != "" || state.declaredFileBytes != 0 ||
			state.fileSHA256 != "" || !validPrepareSafeID(state.sshPolicyID) || state.sshPolicyRevision == 0 {
			return ErrInvalidBindingManifest
		}
	default:
		return ErrInvalidBindingManifest
	}
	return nil
}

// NewBindingProof constructs one safe proof for a concrete manifest identity.
func NewBindingProof(bindingID string, mode DeliveryMode, proofID string) (BindingProof, error) {
	proof := BindingProof{state: bindingProofState{bindingID: bindingID, mode: mode, proofID: proofID}}
	if ValidateBindingProof(proof) != nil {
		return BindingProof{}, ErrInvalidBindingProof
	}
	return proof, nil
}

// ValidateBindingProof validates only the closed safe proof object.
func ValidateBindingProof(proof BindingProof) error {
	if !validPrepareSafeID(proof.state.bindingID) || !validPrepareSafeID(proof.state.proofID) ||
		!validPrepareMode(proof.state.mode) {
		return ErrInvalidBindingProof
	}
	return nil
}

// NewCredentialPrepareRequest constructs a request and derives its envelope
// identity digest from the validated concrete JobIdentity.
func NewCredentialPrepareRequest(requestID RequestID, identity JobIdentity, revision uint64, expiresAtUnixNano int64, bindings []BindingManifest, privateRecordCount uint32, privateAggregateBytes uint64) (CredentialPrepareRequest, error) {
	digestBytes, err := JobIdentityDigest(identity)
	if err != nil {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequest
	}
	request := CredentialPrepareRequest{state: &credentialPrepareRequestState{
		protocolVersion: ProtocolVersion, operation: OperationCredentialPrepare,
		requestID: requestID, identityDigest: NewIdentityDigest(digestBytes),
		identity: cloneJobIdentity(identity), revision: revision, expiresAtUnixNano: expiresAtUnixNano,
		bindings: cloneBindingManifests(bindings), privateRecordCount: privateRecordCount,
		privateAggregateBytes: privateAggregateBytes,
	}}
	if ValidateCredentialPrepareRequest(request) != nil {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequest
	}
	return request, nil
}

// ValidateCredentialPrepareRequest validates all envelope, identity, union,
// private-record accounting, and fixed-limit invariants.
func ValidateCredentialPrepareRequest(request CredentialPrepareRequest) error {
	if request.state == nil || request.state.protocolVersion != ProtocolVersion ||
		request.state.operation != OperationCredentialPrepare || request.state.revision != 1 ||
		!validCredentialPrepareRootExpiry(request.state.identity, request.state.expiresAtUnixNano) {
		return ErrInvalidCredentialPrepareRequest
	}
	if _, err := EncodeRequestID(request.state.requestID); err != nil {
		return ErrInvalidCredentialPrepareRequest
	}
	digest, err := JobIdentityDigest(request.state.identity)
	if err != nil || request.state.identityDigest != NewIdentityDigest(digest) {
		return ErrInvalidCredentialPrepareRequest
	}
	if !validPrepareManifestList(request.state.identity, request.state.bindings,
		request.state.privateRecordCount, request.state.privateAggregateBytes) {
		return ErrInvalidCredentialPrepareRequest
	}
	return nil
}

// ValidateCredentialPrepareRequestExpiry applies the authenticated session's
// caller-owned hard-expiry boundary. The codec has no clock or session state.
func ValidateCredentialPrepareRequestExpiry(request CredentialPrepareRequest, sessionHardExpiryUnixNano int64) error {
	if ValidateCredentialPrepareRequest(request) != nil || sessionHardExpiryUnixNano <= request.state.identity.IssuedAtUnixNano ||
		request.state.expiresAtUnixNano > sessionHardExpiryUnixNano {
		return ErrInvalidCredentialPrepareRequest
	}
	return nil
}

// EncodeCredentialPrepareRequest returns the sole canonical compact JSON wire.
func EncodeCredentialPrepareRequest(request CredentialPrepareRequest) ([]byte, error) {
	if ValidateCredentialPrepareRequest(request) != nil {
		return nil, ErrInvalidCredentialPrepareRequest
	}
	identityWire, err := MarshalJobIdentity(request.state.identity)
	if err != nil {
		return nil, ErrInvalidCredentialPrepareRequest
	}
	requestID, err := EncodeRequestID(request.state.requestID)
	if err != nil {
		return nil, ErrInvalidCredentialPrepareRequest
	}
	var wire bytes.Buffer
	wire.WriteString(`{"protocolVersion":"guest-agent-v2","operation":"credential_prepare","requestId":`)
	writePrepareJSONString(&wire, requestID)
	wire.WriteString(`,"identityDigest":`)
	writePrepareJSONString(&wire, EncodeIdentityDigest(request.state.identityDigest))
	wire.WriteString(`,"body":{"identity":`)
	wire.Write(identityWire)
	wire.WriteString(`,"revision":1,"expiresAtUnixNano":`)
	wire.WriteString(strconv.FormatInt(request.state.expiresAtUnixNano, 10))
	wire.WriteString(`,"bindings":[`)
	for index, manifest := range request.state.bindings {
		if index != 0 {
			wire.WriteByte(',')
		}
		encodeBindingManifest(&wire, manifest)
	}
	wire.WriteString(`],"privateRecordCount":`)
	wire.WriteString(strconv.FormatUint(uint64(request.state.privateRecordCount), 10))
	wire.WriteString(`,"privateAggregateBytes":`)
	wire.WriteString(strconv.FormatUint(request.state.privateAggregateBytes, 10))
	wire.WriteString(`}}`)
	return wire.Bytes(), nil
}

// DecodeCredentialPrepareRequest accepts exactly one complete canonical wire.
func DecodeCredentialPrepareRequest(wire []byte) (CredentialPrepareRequest, error) {
	if !validCredentialPrepareJSONInput(wire) {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if !expectPrepareDelimiter(decoder, '{') || !expectPrepareKey(decoder, "protocolVersion") {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	protocolVersion, ok := readPrepareString(decoder)
	if !ok || protocolVersion != ProtocolVersion || !expectPrepareKey(decoder, "operation") {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	operation, ok := readPrepareString(decoder)
	if !ok || operation != string(OperationCredentialPrepare) || !expectPrepareKey(decoder, "requestId") {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	requestIDText, ok := readPrepareString(decoder)
	if !ok || !expectPrepareKey(decoder, "identityDigest") {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	digestText, ok := readPrepareString(decoder)
	if !ok || !expectPrepareKey(decoder, "body") || !expectPrepareDelimiter(decoder, '{') ||
		!expectPrepareKey(decoder, "identity") {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	var identity JobIdentity
	if decoder.Decode(&identity) != nil || ValidateJobIdentity(identity) != nil ||
		!expectPrepareKey(decoder, "revision") {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	revision, ok := readPrepareUint64(decoder)
	if !ok || !expectPrepareKey(decoder, "expiresAtUnixNano") {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	expiresAtUnixNano, ok := readPrepareInt64(decoder)
	if !ok || !expectPrepareKey(decoder, "bindings") {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	bindings, ok := decodeBindingManifests(decoder)
	if !ok || !expectPrepareKey(decoder, "privateRecordCount") {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	privateRecordCount64, ok := readPrepareUint64(decoder)
	if !ok || privateRecordCount64 > uint64(^uint32(0)) || !expectPrepareKey(decoder, "privateAggregateBytes") {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	privateAggregateBytes, ok := readPrepareUint64(decoder)
	if !ok || !expectPrepareDelimiter(decoder, '}') || !expectPrepareDelimiter(decoder, '}') || requirePrepareJSONEOF(decoder) != nil {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	requestID, err := ParseRequestID(requestIDText)
	if err != nil {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	identityDigest, err := ParseIdentityDigest(digestText)
	if err != nil {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	request, err := NewCredentialPrepareRequest(requestID, identity, revision, expiresAtUnixNano,
		bindings, uint32(privateRecordCount64), privateAggregateBytes)
	if err != nil || request.state.identityDigest != identityDigest {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	canonical, err := EncodeCredentialPrepareRequest(request)
	if err != nil || !bytes.Equal(canonical, wire) {
		return CredentialPrepareRequest{}, ErrInvalidCredentialPrepareRequestJSON
	}
	return request, nil
}

// NewCredentialPrepareSuccessResponse constructs a request-correlated success.
func NewCredentialPrepareSuccessResponse(request CredentialPrepareRequest, revision uint64, expiresAtUnixNano int64, activeProofID, execBindingID string, bindingProofs []BindingProof) (CredentialPrepareSuccessResponse, error) {
	if ValidateCredentialPrepareRequest(request) != nil {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccess
	}
	response := CredentialPrepareSuccessResponse{state: &credentialPrepareSuccessState{
		protocolVersion: request.state.protocolVersion, operation: request.state.operation,
		requestID: request.state.requestID, identityDigest: request.state.identityDigest, ok: true,
		revision: revision, expiresAtUnixNano: expiresAtUnixNano, activeProofID: activeProofID,
		execBindingID: execBindingID, bindingProofs: cloneBindingProofs(bindingProofs),
	}}
	if !validCredentialPrepareSuccessForRequest(request, response) {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccess
	}
	return response, nil
}

// ValidateCredentialPrepareSuccessResponse validates an internally complete
// success envelope. Request-specific proof correlation is additionally applied
// by construction and decoding.
func ValidateCredentialPrepareSuccessResponse(response CredentialPrepareSuccessResponse) error {
	if response.state == nil || response.state.protocolVersion != ProtocolVersion ||
		response.state.operation != OperationCredentialPrepare || !response.state.ok ||
		response.state.revision != 1 || response.state.expiresAtUnixNano <= 0 ||
		!validPrepareSafeID(response.state.activeProofID) || !validPrepareSafeID(response.state.execBindingID) ||
		len(response.state.bindingProofs) < 1 || len(response.state.bindingProofs) > maxCredentialPrepareBindings {
		return ErrInvalidCredentialPrepareSuccess
	}
	if _, err := EncodeRequestID(response.state.requestID); err != nil {
		return ErrInvalidCredentialPrepareSuccess
	}
	for _, proof := range response.state.bindingProofs {
		if ValidateBindingProof(proof) != nil {
			return ErrInvalidCredentialPrepareSuccess
		}
	}
	return nil
}

// EncodeCredentialPrepareSuccessResponse returns the sole canonical compact
// success JSON wire. No private-record fields exist on this representation.
func EncodeCredentialPrepareSuccessResponse(response CredentialPrepareSuccessResponse) ([]byte, error) {
	if ValidateCredentialPrepareSuccessResponse(response) != nil {
		return nil, ErrInvalidCredentialPrepareSuccess
	}
	requestID, err := EncodeRequestID(response.state.requestID)
	if err != nil {
		return nil, ErrInvalidCredentialPrepareSuccess
	}
	var wire bytes.Buffer
	wire.WriteString(`{"protocolVersion":"guest-agent-v2","operation":"credential_prepare","requestId":`)
	writePrepareJSONString(&wire, requestID)
	wire.WriteString(`,"identityDigest":`)
	writePrepareJSONString(&wire, EncodeIdentityDigest(response.state.identityDigest))
	wire.WriteString(`,"ok":true,"body":{"revision":`)
	wire.WriteString(strconv.FormatUint(response.state.revision, 10))
	wire.WriteString(`,"expiresAtUnixNano":`)
	wire.WriteString(strconv.FormatInt(response.state.expiresAtUnixNano, 10))
	wire.WriteString(`,"activeProofId":`)
	writePrepareJSONString(&wire, response.state.activeProofID)
	wire.WriteString(`,"execBindingId":`)
	writePrepareJSONString(&wire, response.state.execBindingID)
	wire.WriteString(`,"bindingProofs":[`)
	for index, proof := range response.state.bindingProofs {
		if index != 0 {
			wire.WriteByte(',')
		}
		wire.WriteString(`{"bindingId":`)
		writePrepareJSONString(&wire, proof.state.bindingID)
		wire.WriteString(`,"mode":`)
		writePrepareJSONString(&wire, string(proof.state.mode))
		wire.WriteString(`,"proofId":`)
		writePrepareJSONString(&wire, proof.state.proofID)
		wire.WriteByte('}')
	}
	wire.WriteString(`]}}`)
	return wire.Bytes(), nil
}

// DecodeCredentialPrepareSuccessResponse requires the expected request and
// accepts only exact envelope correlation and manifest-correlated proofs.
func DecodeCredentialPrepareSuccessResponse(expected CredentialPrepareRequest, wire []byte) (CredentialPrepareSuccessResponse, error) {
	if ValidateCredentialPrepareRequest(expected) != nil {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccess
	}
	if !validCredentialPrepareJSONInput(wire) {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(wire))
	decoder.UseNumber()
	if !expectPrepareDelimiter(decoder, '{') || !expectPrepareKey(decoder, "protocolVersion") {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	protocolVersion, ok := readPrepareString(decoder)
	if !ok || protocolVersion != ProtocolVersion || !expectPrepareKey(decoder, "operation") {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	operation, ok := readPrepareString(decoder)
	if !ok || operation != string(OperationCredentialPrepare) || !expectPrepareKey(decoder, "requestId") {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	requestIDText, ok := readPrepareString(decoder)
	if !ok || !expectPrepareKey(decoder, "identityDigest") {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	digestText, ok := readPrepareString(decoder)
	if !ok || !expectPrepareKey(decoder, "ok") || !readPrepareTrue(decoder) ||
		!expectPrepareKey(decoder, "body") || !expectPrepareDelimiter(decoder, '{') ||
		!expectPrepareKey(decoder, "revision") {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	revision, ok := readPrepareUint64(decoder)
	if !ok || !expectPrepareKey(decoder, "expiresAtUnixNano") {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	expiresAtUnixNano, ok := readPrepareInt64(decoder)
	if !ok || !expectPrepareKey(decoder, "activeProofId") {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	activeProofID, ok := readPrepareString(decoder)
	if !ok || !expectPrepareKey(decoder, "execBindingId") {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	execBindingID, ok := readPrepareString(decoder)
	if !ok || !expectPrepareKey(decoder, "bindingProofs") {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	bindingProofs, ok := decodeBindingProofs(decoder)
	if !ok || !expectPrepareDelimiter(decoder, '}') || !expectPrepareDelimiter(decoder, '}') || requirePrepareJSONEOF(decoder) != nil {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	requestID, err := ParseRequestID(requestIDText)
	if err != nil {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	identityDigest, err := ParseIdentityDigest(digestText)
	if err != nil {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	if requestID != expected.state.requestID || identityDigest != expected.state.identityDigest {
		return CredentialPrepareSuccessResponse{}, ErrCredentialPrepareCorrelationMismatch
	}
	response, err := NewCredentialPrepareSuccessResponse(expected, revision, expiresAtUnixNano,
		activeProofID, execBindingID, bindingProofs)
	if err != nil {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	canonical, err := EncodeCredentialPrepareSuccessResponse(response)
	if err != nil || !bytes.Equal(canonical, wire) {
		return CredentialPrepareSuccessResponse{}, ErrInvalidCredentialPrepareSuccessJSON
	}
	return response, nil
}

func validPrepareManifestList(identity JobIdentity, manifests []BindingManifest, privateRecordCount uint32, privateAggregateBytes uint64) bool {
	if len(manifests) < 1 || len(manifests) > maxCredentialPrepareBindings || len(identity.Bindings) != len(manifests) {
		return false
	}
	var fileCount uint32
	var aggregate uint64
	httpCount := 0
	for index, manifest := range manifests {
		if ValidateBindingManifest(manifest) != nil || identity.Bindings[index].BindingID != manifest.state.bindingID ||
			identity.Bindings[index].Mode != manifest.state.mode {
			return false
		}
		for prior := 0; prior < index; prior++ {
			if manifests[prior].state.bindingID == manifest.state.bindingID {
				return false
			}
		}
		switch manifest.state.mode {
		case DeliveryMode("http_proxy"):
			httpCount++
		case DeliveryMode("file_tmpfs"):
			fileCount++
			aggregate += uint64(manifest.state.declaredFileBytes)
		}
	}
	return httpCount <= 1 && fileCount == privateRecordCount && aggregate == privateAggregateBytes &&
		aggregate <= maxCredentialPrepareAggregateBytes
}

func validCredentialPrepareRootExpiry(identity JobIdentity, expiresAtUnixNano int64) bool {
	if expiresAtUnixNano <= 0 || expiresAtUnixNano <= identity.IssuedAtUnixNano {
		return false
	}
	issuedAt := time.Unix(0, identity.IssuedAtUnixNano)
	expiresAt := time.Unix(0, expiresAtUnixNano)
	return expiresAt.Sub(issuedAt) <= sandboxruntime.MaxJobCredentialLifetime
}

func validCredentialPrepareSuccessForRequest(request CredentialPrepareRequest, response CredentialPrepareSuccessResponse) bool {
	if ValidateCredentialPrepareRequest(request) != nil || ValidateCredentialPrepareSuccessResponse(response) != nil ||
		response.state.requestID != request.state.requestID || response.state.identityDigest != request.state.identityDigest ||
		response.state.revision != request.state.revision || response.state.expiresAtUnixNano != request.state.expiresAtUnixNano ||
		len(response.state.bindingProofs) != len(request.state.bindings) {
		return false
	}
	for index, manifest := range request.state.bindings {
		proof := response.state.bindingProofs[index]
		if proof.state.bindingID != manifest.state.bindingID || proof.state.mode != manifest.state.mode {
			return false
		}
	}
	return true
}

func validPrepareSafeID(value string) bool {
	return credentialprotocol.ValidateSafeID(credentialprotocol.SafeID(value)) == nil
}

func validPrepareMode(mode DeliveryMode) bool {
	return mode == DeliveryMode("http_proxy") || mode == DeliveryMode("file_tmpfs") || mode == DeliveryMode("ssh_agent")
}

func validLowerSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return false
	}
	for _, item := range decoded {
		if item != 0 {
			return true
		}
	}
	return false
}

func encodeBindingManifest(wire *bytes.Buffer, manifest BindingManifest) {
	wire.WriteString(`{"bindingId":`)
	writePrepareJSONString(wire, manifest.state.bindingID)
	wire.WriteString(`,"mode":`)
	writePrepareJSONString(wire, string(manifest.state.mode))
	switch manifest.state.mode {
	case DeliveryMode("http_proxy"):
		wire.WriteString(`,"serviceId":`)
		writePrepareJSONString(wire, manifest.state.serviceID)
	case DeliveryMode("file_tmpfs"):
		wire.WriteString(`,"targetPath":`)
		writePrepareJSONString(wire, manifest.state.targetPath)
		wire.WriteString(`,"declaredFileBytes":`)
		wire.WriteString(strconv.FormatUint(uint64(manifest.state.declaredFileBytes), 10))
		wire.WriteString(`,"fileSha256":`)
		writePrepareJSONString(wire, manifest.state.fileSHA256)
	case DeliveryMode("ssh_agent"):
		wire.WriteString(`,"sshPolicyId":`)
		writePrepareJSONString(wire, manifest.state.sshPolicyID)
		wire.WriteString(`,"sshPolicyRevision":`)
		wire.WriteString(strconv.FormatUint(manifest.state.sshPolicyRevision, 10))
	}
	wire.WriteByte('}')
}

func decodeBindingManifests(decoder *json.Decoder) ([]BindingManifest, bool) {
	if !expectPrepareDelimiter(decoder, '[') {
		return nil, false
	}
	manifests := make([]BindingManifest, 0, maxCredentialPrepareBindings)
	for decoder.More() {
		if len(manifests) == maxCredentialPrepareBindings || !expectPrepareDelimiter(decoder, '{') ||
			!expectPrepareKey(decoder, "bindingId") {
			return nil, false
		}
		bindingID, ok := readPrepareString(decoder)
		if !ok || !expectPrepareKey(decoder, "mode") {
			return nil, false
		}
		mode, ok := readPrepareString(decoder)
		if !ok {
			return nil, false
		}
		var manifest BindingManifest
		var err error
		switch DeliveryMode(mode) {
		case DeliveryMode("http_proxy"):
			if !expectPrepareKey(decoder, "serviceId") {
				return nil, false
			}
			serviceID, present := readPrepareString(decoder)
			if !present {
				return nil, false
			}
			manifest, err = NewHTTPBindingManifest(bindingID, serviceID)
		case DeliveryMode("file_tmpfs"):
			if !expectPrepareKey(decoder, "targetPath") {
				return nil, false
			}
			targetPath, present := readPrepareString(decoder)
			if !present || !expectPrepareKey(decoder, "declaredFileBytes") {
				return nil, false
			}
			declared, present := readPrepareUint64(decoder)
			if !present || declared > uint64(^uint32(0)) || !expectPrepareKey(decoder, "fileSha256") {
				return nil, false
			}
			digest, present := readPrepareString(decoder)
			if !present {
				return nil, false
			}
			manifest, err = NewFileBindingManifest(bindingID, targetPath, uint32(declared), digest)
		case DeliveryMode("ssh_agent"):
			if !expectPrepareKey(decoder, "sshPolicyId") {
				return nil, false
			}
			policyID, present := readPrepareString(decoder)
			if !present || !expectPrepareKey(decoder, "sshPolicyRevision") {
				return nil, false
			}
			policyRevision, present := readPrepareUint64(decoder)
			if !present {
				return nil, false
			}
			manifest, err = NewSSHBindingManifest(bindingID, policyID, policyRevision)
		default:
			return nil, false
		}
		if err != nil || !expectPrepareDelimiter(decoder, '}') {
			return nil, false
		}
		manifests = append(manifests, manifest)
	}
	if !expectPrepareDelimiter(decoder, ']') {
		return nil, false
	}
	return manifests, true
}

func decodeBindingProofs(decoder *json.Decoder) ([]BindingProof, bool) {
	if !expectPrepareDelimiter(decoder, '[') {
		return nil, false
	}
	proofs := make([]BindingProof, 0, maxCredentialPrepareBindings)
	for decoder.More() {
		if len(proofs) == maxCredentialPrepareBindings || !expectPrepareDelimiter(decoder, '{') ||
			!expectPrepareKey(decoder, "bindingId") {
			return nil, false
		}
		bindingID, ok := readPrepareString(decoder)
		if !ok || !expectPrepareKey(decoder, "mode") {
			return nil, false
		}
		mode, ok := readPrepareString(decoder)
		if !ok || !expectPrepareKey(decoder, "proofId") {
			return nil, false
		}
		proofID, ok := readPrepareString(decoder)
		if !ok || !expectPrepareDelimiter(decoder, '}') {
			return nil, false
		}
		proof, err := NewBindingProof(bindingID, DeliveryMode(mode), proofID)
		if err != nil {
			return nil, false
		}
		proofs = append(proofs, proof)
	}
	if !expectPrepareDelimiter(decoder, ']') {
		return nil, false
	}
	return proofs, true
}

func writePrepareJSONString(wire *bytes.Buffer, value string) {
	encoded, _ := json.Marshal(value)
	wire.Write(encoded)
}
