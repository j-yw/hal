package credentialclient

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

var (
	ErrClientControlDependencyUnaccepted = errors.New("credential client control dependency is unaccepted")
	errInvalidControlAcceptExpectation   = errors.New("credential client control accept expectation is invalid")
	errInvalidTransportIdentity          = errors.New("credential client transport identity is invalid")
	errInvalidControlReceiveRequest      = errors.New("credential client control receive request is invalid")
	errInvalidControllerPacket           = errors.New("credential client controller packet is invalid")
	errInvalidControllerSendPacket       = errors.New("credential client controller send packet is invalid")
	errInvalidHelperReceiveRequest       = errors.New("credential client helper receive request is invalid")
	errInvalidHelperPacket               = errors.New("credential client helper packet is invalid")
	errInvalidHelperSendPacket           = errors.New("credential client helper send packet is invalid")
)

const helperExecStreamCanonicalPrefixBytes = 56

// ControlAcceptExpectation is the private-snapshot expectation presented only
// to the inherited, preopened control listener owner. It carries no FD.
type ControlAcceptExpectation struct {
	liveValue
	identity session.Identity
}

func newControlAcceptExpectation(identity session.Identity) (ControlAcceptExpectation, error) {
	if !validControlSessionIdentity(identity) {
		return ControlAcceptExpectation{}, errInvalidControlAcceptExpectation
	}
	return ControlAcceptExpectation{identity: identity}, nil
}

func (expectation ControlAcceptExpectation) Identity() session.Identity { return expectation.identity }

// VerifiedControlStream is the exact already-accepted and same-object
// revalidated stream. It can neither bind nor listen.
type VerifiedControlStream interface {
	io.Reader
	io.Writer
	SetDeadline(time.Time) error
	Close() error
}

// ControlConnectionOwner owns the inherited fixed-port listener and returns
// only a connection revalidated against the supplied immutable expectation.
type ControlConnectionOwner interface {
	AcceptVerified(context.Context, ControlAcceptExpectation) (VerifiedControlStream, error)
	Close(context.Context) error
}

// transportIdentity binds the authenticated control session to the exact
// helper generation retained by the same operational Transport.
type transportIdentity struct {
	liveValue
	sessionID        [32]byte
	identity         session.Identity
	hardExpiry       time.Time
	helperGeneration credentialprotocol.SafeID
}

// authenticatedTransport is the exact D6 control/helper transport admitted by
// future operational Client construction. The legacy Transport interface is
// left source-compatible while the RED contract is reviewed.
type authenticatedTransport interface {
	Transport
	Identity() transportIdentity
}

func newTransportIdentity(sessionID [32]byte, identity session.Identity, hardExpiry time.Time, helperGeneration credentialprotocol.SafeID) (transportIdentity, error) {
	if sessionID == ([32]byte{}) || !validControlSessionIdentity(identity) || hardExpiry.IsZero() ||
		credentialprotocol.ValidateSafeID(helperGeneration) != nil {
		return transportIdentity{}, errInvalidTransportIdentity
	}
	return transportIdentity{
		sessionID:        sessionID,
		identity:         identity,
		hardExpiry:       hardExpiry.UTC(),
		helperGeneration: helperGeneration,
	}, nil
}

func validControlSessionIdentity(identity session.Identity) bool {
	if identity.Channel != session.ChannelControl || identity.GuestCID != session.GuestCID ||
		identity.GuestPort != session.ControlPort || identity.JobGeneration != "" ||
		identity.ActivationGeneration != "" || identity.RelayGeneration != "" ||
		identity.GuestBootNonce == ([32]byte{}) || identity.ImageSHA256 == ([32]byte{}) {
		return false
	}
	for _, token := range []string{
		identity.ControllerKeyGeneration,
		identity.RuntimeID,
		identity.RuntimeGeneration,
		identity.FirecrackerProcessGeneration,
		identity.VsockGeneration,
		identity.BootGeneration,
		identity.ImageGeneration,
	} {
		if credentialprotocol.ValidateSafeID(credentialprotocol.SafeID(token)) != nil {
			return false
		}
	}
	return true
}

func (identity transportIdentity) sessionIDValue() [32]byte          { return identity.sessionID }
func (identity transportIdentity) sessionIdentity() session.Identity { return identity.identity }
func (identity transportIdentity) hardExpiryValue() time.Time        { return identity.hardExpiry }
func (identity transportIdentity) helperGenerationValue() credentialprotocol.SafeID {
	return identity.helperGeneration
}

// controllerBodyCapability owns one fixed-capacity locked controller body.
type controllerBodyCapability interface {
	Len() uint32
	SHA256() [32]byte
	Borrow(context.Context, func(credentialmemory.BorrowedView) error) error
	Destroy(context.Context) error
}

// helperBodyCapability owns one fixed-capacity locked helper body.
type helperBodyCapability interface {
	Len() uint32
	SHA256() [32]byte
	Borrow(context.Context, func(credentialmemory.BorrowedView) error) error
	Destroy(context.Context) error
}

// bodySegmentSink accepts only the future exact contiguous canonical fill.
type bodySegmentSink interface {
	Capacity() uint32
	WriteSegment(offset uint32, source []byte) error
}

type controllerUnknownOperation struct {
	liveValue
	inspected v2control.InspectedRequest
}

type controllerMalformedKnown struct {
	liveValue
	inspected v2control.InspectedRequest
}

type controllerPrivateRecord struct {
	liveValue
	kind           credentialprotocol.PrivateRecordKind
	requestID      v2control.RequestID
	identityDigest v2control.IdentityDigest
	bindingIndex   uint16
	chunkIndex     uint16
	chunkCount     uint16
	payloadLength  uint32
	payloadSHA256  [32]byte
}

type controllerStreamRecord struct {
	liveValue
	kind           credentialprotocol.HelperExecStreamKind
	flags          credentialprotocol.HelperExecStreamFlags
	requestID      v2control.RequestID
	identityDigest v2control.IdentityDigest
	offset         uint64
	payloadLength  uint32
	payloadSHA256  [32]byte
}

type controllerCreditRecord struct {
	liveValue
	kind           credentialprotocol.HelperExecStreamKind
	requestID      v2control.RequestID
	identityDigest v2control.IdentityDigest
	nextOffset     uint64
}

type controllerPacketArmKind uint8

const (
	controllerPacketArmReadiness controllerPacketArmKind = iota + 1
	controllerPacketArmPrepare
	controllerPacketArmRenew
	controllerPacketArmRevoke
	controllerPacketArmExec
	controllerPacketArmUnknown
	controllerPacketArmMalformed
	controllerPacketArmPrivate
	controllerPacketArmStream
	controllerPacketArmCredit
	controllerPacketArmClose
)

type controllerPacketArm struct {
	kind      controllerPacketArmKind
	readiness v2control.ReadinessRequest
	prepare   v2control.CredentialPrepareRequest
	renew     v2control.CredentialRenewRequest
	revoke    v2control.CredentialRevokeRequest
	exec      v2control.CredentialExecRequest
	unknown   controllerUnknownOperation
	malformed controllerMalformedKnown
	private   controllerPrivateRecord
	stream    controllerStreamRecord
	credit    controllerCreditRecord
	close     credentialprotocol.CloseReason
}

type controllerSendArmKind uint8

const (
	controllerSendArmReadiness controllerSendArmKind = iota + 1
	controllerSendArmPrepare
	controllerSendArmRenew
	controllerSendArmRevoke
	controllerSendArmExec
	controllerSendArmFailure
	controllerSendArmStream
	controllerSendArmCredit
	controllerSendArmClose
)

type controllerSendArm struct {
	readiness v2control.ReadinessSuccessResponse
	prepare   v2control.CredentialPrepareSuccessResponse
	renew     v2control.CredentialRenewSuccessResponse
	revoke    v2control.CredentialRevokeSuccessResponse
	exec      v2control.CredentialExecSuccessResponse
	failure   v2control.FailureResponse
	stream    controllerStreamRecord
	credit    controllerCreditRecord
	close     credentialprotocol.CloseReason
}

type controllerSendPacketState struct {
	mu       sync.Mutex
	consumed bool
	owner    *controllerSendPacketOwner
}

type controllerSendPacketOwner struct {
	arm  controllerSendArm
	body controllerBodyCapability
}

type helperExecStreamRecord struct {
	liveValue
	revision      uint64
	kind          credentialprotocol.HelperExecStreamKind
	flags         credentialprotocol.HelperExecStreamFlags
	offset        uint64
	payloadLength uint32
	payloadSHA256 [32]byte
}

type helperPacketArmKind uint8

const (
	helperPacketArmResponse helperPacketArmKind = iota + 1
	helperPacketArmEvent
	helperPacketArmExecStream
	helperPacketArmExecCredit
	helperPacketArmSSHAccepted
	helperPacketArmClose
)

type helperPacketArm struct {
	kind        helperPacketArmKind
	response    credentialprotocol.HelperResponseBody
	event       credentialprotocol.HelperEventBody
	execStream  helperExecStreamRecord
	execCredit  credentialprotocol.HelperExecCreditBody
	sshAccepted SSHAcceptedPacket
	close       credentialprotocol.HelperCloseNotifyBody
}

type helperSendArmKind uint8

const (
	helperSendArmPrepareBegin helperSendArmKind = iota + 1
	helperSendArmPrepareFile
	helperSendArmPrepareCommit
	helperSendArmRenew
	helperSendArmRevoke
	helperSendArmExec
	helperSendArmExecPrivate
	helperSendArmExecStream
	helperSendArmExecCredit
	helperSendArmClose
)

type helperPrepareFileArm struct {
	revision     uint64
	bindingIndex uint16
	fileLength   uint32
	fileSHA256   [32]byte
	owner        *helperPrepareFileOwner
}

// helperPrepareFileOwner is the opaque wipeable owner for one admitted
// prepare-file payload. Value copies share wipe state. Private bytes are
// defensively copied into cap==len storage, never logged or serialized.
type helperPrepareFileOwner struct {
	liveValue
	body *credentialprotocol.HelperPrepareFileBody
}

func newHelperPrepareFileOwner(revision uint64, bindingIndex uint16, fileSHA256 [32]byte, privateBytes []byte) (*helperPrepareFileOwner, error) {
	body, err := credentialprotocol.NewHelperPrepareFileBody(revision, bindingIndex, fileSHA256, privateBytes)
	if err != nil {
		return nil, err
	}
	return &helperPrepareFileOwner{body: body}, nil
}

func (owner *helperPrepareFileOwner) Wipe() {
	if owner == nil || owner.body == nil {
		return
	}
	owner.body.Wipe()
	owner.body = nil
}

func wipeHelperPrepareFileOwner(owner *helperPrepareFileOwner) {
	if owner != nil {
		owner.Wipe()
	}
}

// helperExecPrivateOwner is the opaque wipeable owner for one admitted
// exec-private payload. Value copies share wipe state. Private bytes are
// defensively copied into cap==len storage, never logged or serialized.
type helperExecPrivateOwner struct {
	liveValue
	body *credentialprotocol.HelperExecPrivateBody
}

func newHelperExecPrivateOwner(revision uint64, privateBindingSHA256 [32]byte, privateBytes []byte) (*helperExecPrivateOwner, error) {
	body, err := credentialprotocol.NewHelperExecPrivateBody(revision, privateBindingSHA256, privateBytes)
	if err != nil {
		return nil, err
	}
	return &helperExecPrivateOwner{body: body}, nil
}

func (owner *helperExecPrivateOwner) Wipe() {
	if owner == nil || owner.body == nil {
		return
	}
	owner.body.Wipe()
	owner.body = nil
}

func wipeHelperExecPrivateOwner(owner *helperExecPrivateOwner) {
	if owner != nil {
		owner.Wipe()
	}
}

type helperExecPrivateArm struct {
	revision             uint64
	privateBindingLength uint32
	privateBindingSHA256 [32]byte
	owner                *helperExecPrivateOwner
}

type helperSendArm struct {
	kind          helperSendArmKind
	prepareBegin  credentialprotocol.HelperPrepareBeginBody
	prepareFile   helperPrepareFileArm
	prepareCommit credentialprotocol.HelperPrepareCommitBody
	renew         credentialprotocol.HelperRenewBody
	revoke        credentialprotocol.HelperRevokeBody
	exec          credentialprotocol.HelperExecBody
	execPrivate   helperExecPrivateArm
	execStream    helperExecStreamRecord
	execCredit    credentialprotocol.HelperExecCreditBody
	close         credentialprotocol.HelperCloseNotifyBody
}

type helperSendPacketState struct {
	mu       sync.Mutex
	consumed bool
	owner    *helperSendPacketOwner
}

type helperSendPacketOwner struct {
	arm  helperSendArm
	body helperBodyCapability
}

func newControlReceiveRequest(sequence uint64, identity v2control.IdentityDigest, identitySet bool, maximumPlaintextBytes uint32) (ControllerReceiveRequest, error) {
	if sequence == 0 || sequence > uint64(^uint32(0)) || maximumPlaintextBytes < 1 || maximumPlaintextBytes > session.MaxControlPlaintextBytes {
		return ControllerReceiveRequest{}, errInvalidControlReceiveRequest
	}
	if identitySet && identity == (v2control.IdentityDigest{}) {
		return ControllerReceiveRequest{}, errInvalidControlReceiveRequest
	}
	return ControllerReceiveRequest{
		nextSequence:          sequence,
		expectedIdentity:      identity,
		expectedIdentitySet:   identitySet,
		maximumPlaintextBytes: maximumPlaintextBytes,
		state:                 &controllerReceiveRequestState{},
	}, nil
}

func consumeControllerReceiveRequest(request ControllerReceiveRequest) error {
	if request.state == nil {
		return errInvalidControlReceiveRequest
	}
	request.state.mu.Lock()
	defer request.state.mu.Unlock()
	if request.state.consumed {
		return errInvalidControlReceiveRequest
	}
	request.state.consumed = true
	return nil
}

func newHelperControlReceiveRequest(sequence uint64, maximumBodyBytes, maximumRights uint32, expectedRequestID [16]byte, expectedRequestIDSet bool, expectedIdentity [32]byte) (HelperReceiveRequest, error) {
	if sequence == 0 || sequence > uint64(^uint32(0)) || maximumBodyBytes > credentialprotocol.MaxHelperPacketBodyBytes || maximumRights > 1 {
		return HelperReceiveRequest{}, errInvalidHelperReceiveRequest
	}
	if expectedIdentity == ([32]byte{}) {
		return HelperReceiveRequest{}, errInvalidHelperReceiveRequest
	}
	if expectedRequestIDSet != (expectedRequestID != ([16]byte{})) {
		return HelperReceiveRequest{}, errInvalidHelperReceiveRequest
	}
	return HelperReceiveRequest{
		nextSequence:         sequence,
		maximumBodyBytes:     maximumBodyBytes,
		maximumRights:        maximumRights,
		expectedRequestID:    expectedRequestID,
		expectedRequestIDSet: expectedRequestIDSet,
		expectedIdentity:     expectedIdentity,
		state:                &helperReceiveRequestState{},
	}, nil
}

func consumeHelperReceiveRequest(request HelperReceiveRequest) error {
	if request.state == nil {
		return errInvalidHelperReceiveRequest
	}
	request.state.mu.Lock()
	defer request.state.mu.Unlock()
	if request.state.consumed {
		return errInvalidHelperReceiveRequest
	}
	request.state.consumed = true
	return nil
}

func (request ControllerReceiveRequest) nextSequenceValue() uint64 { return request.nextSequence }
func (request ControllerReceiveRequest) expectedIdentityValue() (v2control.IdentityDigest, bool) {
	return request.expectedIdentity, request.expectedIdentitySet
}
func (request ControllerReceiveRequest) maximumPlaintextBytesValue() uint32 {
	return request.maximumPlaintextBytes
}

func (request HelperReceiveRequest) nextSequenceValue() uint64     { return request.nextSequence }
func (request HelperReceiveRequest) maximumBodyBytesValue() uint32 { return request.maximumBodyBytes }
func (request HelperReceiveRequest) maximumRightsValue() uint32    { return request.maximumRights }
func (request HelperReceiveRequest) expectedRequestIDValue() ([16]byte, bool) {
	return request.expectedRequestID, request.expectedRequestIDSet
}
func (request HelperReceiveRequest) expectedIdentityDigestValue() [32]byte {
	return request.expectedIdentity
}

func newControllerUnknownOperationPacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, inspected v2control.InspectedRequest) (ControllerPacket, error) {
	return newControllerInspectedPacket(request, sequence, sessionID, inspected, false, controllerPacketArmUnknown)
}

func newControllerMalformedKnownPacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, inspected v2control.InspectedRequest) (ControllerPacket, error) {
	return newControllerInspectedPacket(request, sequence, sessionID, inspected, true, controllerPacketArmMalformed)
}

func newControllerInspectedPacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, inspected v2control.InspectedRequest, requireKnown bool, kind controllerPacketArmKind) (ControllerPacket, error) {
	if err := consumeControllerReceiveRequest(request); err != nil {
		return ControllerPacket{}, err
	}
	if sequence == 0 || sequence != request.nextSequence || sessionID == ([32]byte{}) {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if _, err := v2control.EncodeOperationToken(inspected.OperationToken()); err != nil {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if _, err := v2control.EncodeRequestID(inspected.RequestID()); err != nil {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	_, known := inspected.KnownOperation()
	if known != requireKnown {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if request.expectedIdentitySet && request.expectedIdentity != inspected.IdentityDigest() {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	packet := ControllerPacket{sequence: sequence, sessionID: sessionID}
	if requireKnown {
		packet.arm = controllerPacketArm{kind: kind, malformed: controllerMalformedKnown{inspected: inspected}}
	} else {
		packet.arm = controllerPacketArm{kind: kind, unknown: controllerUnknownOperation{inspected: inspected}}
	}
	return packet, nil
}

func newControllerReadinessPacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, readiness v2control.ReadinessRequest) (ControllerPacket, error) {
	if err := consumeControllerReceiveRequest(request); err != nil {
		return ControllerPacket{}, err
	}
	if sequence == 0 || sequence != request.nextSequence || sessionID == ([32]byte{}) ||
		v2control.ValidateReadinessRequest(readiness) != nil ||
		readiness.IdentityDigest() != v2control.NewIdentityDigest(sessionID) {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if request.expectedIdentitySet && request.expectedIdentity != readiness.IdentityDigest() {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	return ControllerPacket{
		sequence:  sequence,
		sessionID: sessionID,
		arm:       controllerPacketArm{kind: controllerPacketArmReadiness, readiness: readiness},
	}, nil
}

func newControllerReadinessSendPacket(packet ControllerPacket, response v2control.ReadinessSuccessResponse) (ControllerSendPacket, error) {
	request, ok := packet.readinessValue()
	if !ok || packet.sequence == 0 || packet.sessionID == ([32]byte{}) ||
		v2control.ValidateReadinessSuccessResponse(response) != nil ||
		response.RequestID() != request.RequestID() || response.IdentityDigest() != request.IdentityDigest() ||
		response.IdentityDigest() != v2control.NewIdentityDigest(packet.sessionID) {
		return ControllerSendPacket{}, errInvalidControllerSendPacket
	}
	return finishControllerJSONSendPacket(packet.sequence, packet.sessionID, controllerSendArmReadiness, controllerSendArm{readiness: response})
}

func newControllerPreparePacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, prepare v2control.CredentialPrepareRequest) (ControllerPacket, error) {
	if err := consumeControllerReceiveRequest(request); err != nil {
		return ControllerPacket{}, err
	}
	if sequence == 0 || sequence != request.nextSequence || sessionID == ([32]byte{}) ||
		v2control.ValidateCredentialPrepareRequest(prepare) != nil ||
		!controllerIdentityMatchesSession(sessionID, prepare.Identity(), prepare.IdentityDigest()) {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if request.expectedIdentitySet && request.expectedIdentity != prepare.IdentityDigest() {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	return ControllerPacket{
		sequence:  sequence,
		sessionID: sessionID,
		arm:       controllerPacketArm{kind: controllerPacketArmPrepare, prepare: prepare},
	}, nil
}

func newControllerPrepareSendPacket(packet ControllerPacket, response v2control.CredentialPrepareSuccessResponse) (ControllerSendPacket, error) {
	request, ok := packet.prepareValue()
	if !ok || packet.sequence == 0 || packet.sessionID == ([32]byte{}) ||
		v2control.ValidateCredentialPrepareSuccessResponse(response) != nil ||
		!controllerPrepareResponseMatchesRequest(request, response) {
		return ControllerSendPacket{}, errInvalidControllerSendPacket
	}
	return finishControllerJSONSendPacket(packet.sequence, packet.sessionID, controllerSendArmPrepare, controllerSendArm{prepare: response})
}

func newControllerRenewPacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, renew v2control.CredentialRenewRequest) (ControllerPacket, error) {
	if err := consumeControllerReceiveRequest(request); err != nil {
		return ControllerPacket{}, err
	}
	if sequence == 0 || sequence != request.nextSequence || sessionID == ([32]byte{}) ||
		v2control.ValidateCredentialRenewRequest(renew) != nil ||
		!controllerIdentityMatchesSession(sessionID, renew.Identity(), renew.IdentityDigest()) {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if request.expectedIdentitySet && request.expectedIdentity != renew.IdentityDigest() {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	return ControllerPacket{
		sequence:  sequence,
		sessionID: sessionID,
		arm:       controllerPacketArm{kind: controllerPacketArmRenew, renew: renew},
	}, nil
}

func newControllerRenewSendPacket(packet ControllerPacket, response v2control.CredentialRenewSuccessResponse) (ControllerSendPacket, error) {
	request, ok := packet.renewValue()
	if !ok || packet.sequence == 0 || packet.sessionID == ([32]byte{}) ||
		v2control.ValidateCredentialRenewSuccessResponse(response) != nil ||
		response.RequestID() != request.RequestID() || response.IdentityDigest() != request.IdentityDigest() ||
		response.Revision() != request.Revision() || response.ExpiresAtUnixNano() != request.ExpiresAtUnixNano() {
		return ControllerSendPacket{}, errInvalidControllerSendPacket
	}
	return finishControllerJSONSendPacket(packet.sequence, packet.sessionID, controllerSendArmRenew, controllerSendArm{renew: response})
}

func newControllerRevokePacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, revoke v2control.CredentialRevokeRequest) (ControllerPacket, error) {
	if err := consumeControllerReceiveRequest(request); err != nil {
		return ControllerPacket{}, err
	}
	if sequence == 0 || sequence != request.nextSequence || sessionID == ([32]byte{}) ||
		v2control.ValidateCredentialRevokeRequest(revoke) != nil ||
		!controllerIdentityMatchesSession(sessionID, revoke.Identity(), revoke.IdentityDigest()) {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if request.expectedIdentitySet && request.expectedIdentity != revoke.IdentityDigest() {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	return ControllerPacket{
		sequence:  sequence,
		sessionID: sessionID,
		arm:       controllerPacketArm{kind: controllerPacketArmRevoke, revoke: revoke},
	}, nil
}

func newControllerRevokeSendPacket(packet ControllerPacket, response v2control.CredentialRevokeSuccessResponse) (ControllerSendPacket, error) {
	request, ok := packet.revokeValue()
	if !ok || packet.sequence == 0 || packet.sessionID == ([32]byte{}) ||
		v2control.ValidateCredentialRevokeSuccessResponse(response) != nil ||
		response.RequestID() != request.RequestID() || response.IdentityDigest() != request.IdentityDigest() ||
		response.Revision() != request.Revision() {
		return ControllerSendPacket{}, errInvalidControllerSendPacket
	}
	return finishControllerJSONSendPacket(packet.sequence, packet.sessionID, controllerSendArmRevoke, controllerSendArm{revoke: response})
}

func newControllerExecPacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, exec v2control.CredentialExecRequest) (ControllerPacket, error) {
	if err := consumeControllerReceiveRequest(request); err != nil {
		return ControllerPacket{}, err
	}
	if sequence == 0 || sequence != request.nextSequence || sessionID == ([32]byte{}) ||
		v2control.ValidateCredentialExecRequest(exec) != nil ||
		!controllerIdentityMatchesSession(sessionID, exec.Identity(), exec.IdentityDigest()) {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if request.expectedIdentitySet && request.expectedIdentity != exec.IdentityDigest() {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	return ControllerPacket{
		sequence:  sequence,
		sessionID: sessionID,
		arm:       controllerPacketArm{kind: controllerPacketArmExec, exec: exec},
	}, nil
}

func newControllerExecSendPacket(packet ControllerPacket, response v2control.CredentialExecSuccessResponse) (ControllerSendPacket, error) {
	request, ok := packet.execValue()
	if !ok || packet.sequence == 0 || packet.sessionID == ([32]byte{}) ||
		v2control.ValidateCredentialExecSuccessResponse(response) != nil ||
		response.RequestID() != request.RequestID() || response.IdentityDigest() != request.IdentityDigest() ||
		response.Revision() != request.Revision() {
		return ControllerSendPacket{}, errInvalidControllerSendPacket
	}
	return finishControllerJSONSendPacket(packet.sequence, packet.sessionID, controllerSendArmExec, controllerSendArm{exec: response})
}

func controllerPrepareResponseMatchesRequest(request v2control.CredentialPrepareRequest, response v2control.CredentialPrepareSuccessResponse) bool {
	if response.RequestID() != request.RequestID() || response.IdentityDigest() != request.IdentityDigest() ||
		response.Revision() != request.Revision() || response.ExpiresAtUnixNano() != request.ExpiresAtUnixNano() {
		return false
	}
	bindings := request.Bindings()
	proofs := response.BindingProofs()
	if len(bindings) != len(proofs) {
		return false
	}
	for index := range bindings {
		if bindings[index].BindingID() != proofs[index].BindingID() || bindings[index].Mode() != proofs[index].Mode() {
			return false
		}
	}
	return true
}

func controllerIdentityMatchesSession(sessionID [32]byte, jobIdentity v2control.JobIdentity, digest v2control.IdentityDigest) bool {
	// Credential envelopes bind identityDigest to sessionID through GuestCredentialSessionIdentity, not the raw session bytes.
	identity, err := v2control.NewGuestCredentialSessionIdentity(sessionID, jobIdentity)
	if err != nil {
		return false
	}
	computed, err := v2control.GuestCredentialSessionIdentityDigest(identity)
	if err != nil {
		return false
	}
	return digest == v2control.NewIdentityDigest(computed)
}

func finishControllerJSONSendPacket(sequence uint64, sessionID [32]byte, kind controllerSendArmKind, arm controllerSendArm) (ControllerSendPacket, error) {
	body, err := encodeControllerSendCanonicalBody(kind, arm)
	if err != nil || len(body) == 0 {
		return ControllerSendPacket{}, errInvalidControllerSendPacket
	}
	return ControllerSendPacket{
		sequence:          sequence,
		sessionID:         sessionID,
		arm:               kind,
		encodedBodyLength: uint32(len(body)),
		bodySHA256:        sha256.Sum256(body),
		state: &controllerSendPacketState{
			owner: &controllerSendPacketOwner{arm: arm},
		},
	}, nil
}

func encodeControllerSendCanonicalBody(kind controllerSendArmKind, arm controllerSendArm) ([]byte, error) {
	switch kind {
	case controllerSendArmReadiness:
		return v2control.EncodeReadinessSuccessResponse(arm.readiness)
	case controllerSendArmPrepare:
		return v2control.EncodeCredentialPrepareSuccessResponse(arm.prepare)
	case controllerSendArmRenew:
		return v2control.EncodeCredentialRenewSuccessResponse(arm.renew)
	case controllerSendArmRevoke:
		return v2control.EncodeCredentialRevokeSuccessResponse(arm.revoke)
	case controllerSendArmExec:
		return v2control.EncodeCredentialExecSuccessResponse(arm.exec)
	default:
		return nil, ErrClientControlDependencyUnaccepted
	}
}

func newControllerPrivatePacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, kind credentialprotocol.PrivateRecordKind, requestID v2control.RequestID, identityDigest v2control.IdentityDigest, bindingIndex, chunkIndex, chunkCount uint16, payloadLength uint32, payloadSHA256 [32]byte, body controllerBodyCapability) (packet ControllerPacket, err error) {
	retainedBody := false
	defer func() {
		if err != nil && !retainedBody {
			_ = destroyControllerBody(body)
		}
	}()
	if consumeErr := consumeControllerReceiveRequest(request); consumeErr != nil {
		return ControllerPacket{}, consumeErr
	}
	if sequence == 0 || sequence != request.nextSequence || sessionID == ([32]byte{}) ||
		!validControllerPrivateMetadata(kind, requestID, identityDigest, bindingIndex, chunkIndex, chunkCount, payloadLength, payloadSHA256) ||
		!configuredDependency(body) {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	length, digest, ok := controllerBodyMetadata(body)
	if !ok || length != payloadLength || digest != payloadSHA256 {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if request.expectedIdentitySet && request.expectedIdentity != identityDigest {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	retainedBody = true
	return ControllerPacket{
		sequence:  sequence,
		sessionID: sessionID,
		arm: controllerPacketArm{
			kind: controllerPacketArmPrivate,
			private: controllerPrivateRecord{
				kind:           kind,
				requestID:      requestID,
				identityDigest: identityDigest,
				bindingIndex:   bindingIndex,
				chunkIndex:     chunkIndex,
				chunkCount:     chunkCount,
				payloadLength:  payloadLength,
				payloadSHA256:  payloadSHA256,
			},
		},
		body: body,
	}, nil
}

func newControllerStreamPacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, kind credentialprotocol.HelperExecStreamKind, flags credentialprotocol.HelperExecStreamFlags, requestID v2control.RequestID, identityDigest v2control.IdentityDigest, offset uint64, payloadLength uint32, payloadSHA256 [32]byte, body controllerBodyCapability) (packet ControllerPacket, err error) {
	retainedBody := false
	defer func() {
		if err != nil && !retainedBody {
			_ = destroyControllerBody(body)
		}
	}()
	if consumeErr := consumeControllerReceiveRequest(request); consumeErr != nil {
		return ControllerPacket{}, consumeErr
	}
	if sequence == 0 || sequence != request.nextSequence || sessionID == ([32]byte{}) ||
		!validControllerReceiveExecStream(kind, flags, payloadLength, payloadSHA256) {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if _, err := v2control.EncodeRequestID(requestID); err != nil {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if identityDigest == (v2control.IdentityDigest{}) {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if payloadLength == 0 {
		if configuredDependency(body) {
			return ControllerPacket{}, errInvalidControllerPacket
		}
	} else if !configuredDependency(body) {
		return ControllerPacket{}, errInvalidControllerPacket
	} else {
		length, digest, ok := controllerBodyMetadata(body)
		if !ok || length != payloadLength || digest != payloadSHA256 {
			return ControllerPacket{}, errInvalidControllerPacket
		}
	}
	if request.expectedIdentitySet && request.expectedIdentity != identityDigest {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	retainedBody = configuredDependency(body)
	return ControllerPacket{
		sequence:  sequence,
		sessionID: sessionID,
		arm: controllerPacketArm{
			kind: controllerPacketArmStream,
			stream: controllerStreamRecord{
				kind:           kind,
				flags:          flags,
				requestID:      requestID,
				identityDigest: identityDigest,
				offset:         offset,
				payloadLength:  payloadLength,
				payloadSHA256:  payloadSHA256,
			},
		},
		body: body,
	}, nil
}

func newControllerCreditPacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, kind credentialprotocol.HelperExecStreamKind, requestID v2control.RequestID, identityDigest v2control.IdentityDigest, nextOffset uint64) (ControllerPacket, error) {
	if err := consumeControllerReceiveRequest(request); err != nil {
		return ControllerPacket{}, err
	}
	if sequence == 0 || sequence != request.nextSequence || sessionID == ([32]byte{}) ||
		!validControllerReceiveCredit(kind) {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if _, err := v2control.EncodeRequestID(requestID); err != nil {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if identityDigest == (v2control.IdentityDigest{}) {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	if request.expectedIdentitySet && request.expectedIdentity != identityDigest {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	return ControllerPacket{
		sequence:  sequence,
		sessionID: sessionID,
		arm: controllerPacketArm{
			kind: controllerPacketArmCredit,
			credit: controllerCreditRecord{
				kind:           kind,
				requestID:      requestID,
				identityDigest: identityDigest,
				nextOffset:     nextOffset,
			},
		},
	}, nil
}

func newControllerCloseNotifyPacket(request ControllerReceiveRequest, sequence uint64, sessionID [32]byte, reason credentialprotocol.CloseReason) (ControllerPacket, error) {
	if err := consumeControllerReceiveRequest(request); err != nil {
		return ControllerPacket{}, err
	}
	if sequence == 0 || sequence != request.nextSequence || sessionID == ([32]byte{}) ||
		credentialprotocol.ValidateCloseReason(reason) != nil {
		return ControllerPacket{}, errInvalidControllerPacket
	}
	return ControllerPacket{
		sequence:  sequence,
		sessionID: sessionID,
		arm:       controllerPacketArm{kind: controllerPacketArmClose, close: reason},
	}, nil
}

func (packet ControllerPacket) sequenceValue() uint64    { return packet.sequence }
func (packet ControllerPacket) sessionIDValue() [32]byte { return packet.sessionID }
func (packet ControllerPacket) readinessValue() (v2control.ReadinessRequest, bool) {
	return packet.arm.readiness, packet.arm.kind == controllerPacketArmReadiness
}
func (packet ControllerPacket) prepareValue() (v2control.CredentialPrepareRequest, bool) {
	return packet.arm.prepare, packet.arm.kind == controllerPacketArmPrepare
}
func (packet ControllerPacket) renewValue() (v2control.CredentialRenewRequest, bool) {
	return packet.arm.renew, packet.arm.kind == controllerPacketArmRenew
}
func (packet ControllerPacket) revokeValue() (v2control.CredentialRevokeRequest, bool) {
	return packet.arm.revoke, packet.arm.kind == controllerPacketArmRevoke
}
func (packet ControllerPacket) execValue() (v2control.CredentialExecRequest, bool) {
	return packet.arm.exec, packet.arm.kind == controllerPacketArmExec
}
func (packet ControllerPacket) unknownOperationValue() (controllerUnknownOperation, bool) {
	return packet.arm.unknown, packet.arm.kind == controllerPacketArmUnknown
}
func (packet ControllerPacket) malformedKnownValue() (controllerMalformedKnown, bool) {
	return packet.arm.malformed, packet.arm.kind == controllerPacketArmMalformed
}
func (packet ControllerPacket) privateValue() (controllerPrivateRecord, bool) {
	return packet.arm.private, packet.arm.kind == controllerPacketArmPrivate
}
func (packet ControllerPacket) streamValue() (controllerStreamRecord, bool) {
	return packet.arm.stream, packet.arm.kind == controllerPacketArmStream
}
func (packet ControllerPacket) creditValue() (controllerCreditRecord, bool) {
	return packet.arm.credit, packet.arm.kind == controllerPacketArmCredit
}
func (packet ControllerPacket) closeNotifyValue() (credentialprotocol.CloseReason, bool) {
	return packet.arm.close, packet.arm.kind == controllerPacketArmClose
}

func (packet ControllerSendPacket) sequenceValue() uint64          { return packet.sequence }
func (packet ControllerSendPacket) sessionIDValue() [32]byte       { return packet.sessionID }
func (packet ControllerSendPacket) encodedBodyLengthValue() uint32 { return packet.encodedBodyLength }
func (packet ControllerSendPacket) bodySHA256Value() [32]byte      { return packet.bodySHA256 }
func (packet ControllerSendPacket) writeCanonicalBody(sink bodySegmentSink) (err error) {
	defer func() {
		if recover() != nil {
			err = errInvalidControllerSendPacket
		}
	}()
	switch packet.arm {
	case controllerSendArmReadiness, controllerSendArmPrepare, controllerSendArmRenew, controllerSendArmRevoke, controllerSendArmExec:
	default:
		return ErrClientControlDependencyUnaccepted
	}
	if packet.state == nil {
		return errInvalidControllerSendPacket
	}
	packet.state.mu.Lock()
	if packet.state.consumed || packet.state.owner == nil {
		packet.state.mu.Unlock()
		return errInvalidControllerSendPacket
	}
	owner := packet.state.owner
	packet.state.consumed = true
	packet.state.owner = nil
	packet.state.mu.Unlock()
	body, encodeErr := encodeControllerSendCanonicalBody(packet.arm, owner.arm)
	if encodeErr != nil || uint64(len(body)) != uint64(packet.encodedBodyLength) || sha256.Sum256(body) != packet.bodySHA256 {
		return errInvalidControllerSendPacket
	}
	if sink == nil || sink.Capacity() != packet.encodedBodyLength {
		return errInvalidControllerSendPacket
	}
	if writeErr := sink.WriteSegment(0, body); writeErr != nil {
		return errInvalidControllerSendPacket
	}
	return nil
}
func (packet ControllerSendPacket) readinessResponseValue() (v2control.ReadinessSuccessResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmReadiness, func(arm controllerSendArm) v2control.ReadinessSuccessResponse { return arm.readiness })
}
func (packet ControllerSendPacket) prepareResponseValue() (v2control.CredentialPrepareSuccessResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmPrepare, func(arm controllerSendArm) v2control.CredentialPrepareSuccessResponse { return arm.prepare })
}
func (packet ControllerSendPacket) renewResponseValue() (v2control.CredentialRenewSuccessResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmRenew, func(arm controllerSendArm) v2control.CredentialRenewSuccessResponse { return arm.renew })
}
func (packet ControllerSendPacket) revokeResponseValue() (v2control.CredentialRevokeSuccessResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmRevoke, func(arm controllerSendArm) v2control.CredentialRevokeSuccessResponse { return arm.revoke })
}
func (packet ControllerSendPacket) execResponseValue() (v2control.CredentialExecSuccessResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmExec, func(arm controllerSendArm) v2control.CredentialExecSuccessResponse { return arm.exec })
}
func (packet ControllerSendPacket) failureResponseValue() (v2control.FailureResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmFailure, func(arm controllerSendArm) v2control.FailureResponse { return arm.failure })
}
func (packet ControllerSendPacket) streamValue() (controllerStreamRecord, bool) {
	return controllerSendArmValue(packet, controllerSendArmStream, func(arm controllerSendArm) controllerStreamRecord { return arm.stream })
}
func (packet ControllerSendPacket) creditValue() (controllerCreditRecord, bool) {
	return controllerSendArmValue(packet, controllerSendArmCredit, func(arm controllerSendArm) controllerCreditRecord { return arm.credit })
}
func (packet ControllerSendPacket) closeNotifyValue() (credentialprotocol.CloseReason, bool) {
	return controllerSendArmValue(packet, controllerSendArmClose, func(arm controllerSendArm) credentialprotocol.CloseReason { return arm.close })
}

func controllerSendArmValue[T any](packet ControllerSendPacket, expected controllerSendArmKind, selectValue func(controllerSendArm) T) (T, bool) {
	var zero T
	if packet.state == nil {
		return zero, false
	}
	packet.state.mu.Lock()
	defer packet.state.mu.Unlock()
	if packet.state.consumed || packet.state.owner == nil || packet.arm != expected {
		return zero, false
	}
	return selectValue(packet.state.owner.arm), true
}

func newHelperResponsePacket(request HelperReceiveRequest, header credentialprotocol.HelperPacketHeader, body helperBodyCapability, response credentialprotocol.HelperResponseBody) (packet HelperPacket, err error) {
	released := false
	defer func() {
		if err != nil && !released {
			_ = destroyHelperBody(body)
		}
	}()
	encoded, encodeErr := credentialprotocol.EncodeHelperResponseBody(response)
	if consumeErr := consumeHelperReceiveRequest(request); consumeErr != nil {
		return HelperPacket{}, consumeErr
	}
	if encodeErr != nil || validateHelperReceiveHeader(request, header, credentialprotocol.PacketTypeResponse, true, false, uint32(len(encoded))) != nil ||
		validateOptionalHelperBody(body, encoded) != nil {
		clear(encoded)
		return HelperPacket{}, errInvalidHelperPacket
	}
	clear(encoded)
	released = true
	if destroyErr := destroyHelperBody(body); destroyErr != nil {
		return HelperPacket{}, errInvalidHelperPacket
	}
	return HelperPacket{
		header: header,
		arm:    helperPacketArm{kind: helperPacketArmResponse, response: cloneHelperResponseBody(response)},
	}, nil
}

func newHelperEventPacket(request HelperReceiveRequest, header credentialprotocol.HelperPacketHeader, body helperBodyCapability, event credentialprotocol.HelperEventBody) (packet HelperPacket, err error) {
	released := false
	defer func() {
		if err != nil && !released {
			_ = destroyHelperBody(body)
		}
	}()
	encoded, encodeErr := credentialprotocol.EncodeHelperEventBody(event)
	if consumeErr := consumeHelperReceiveRequest(request); consumeErr != nil {
		return HelperPacket{}, consumeErr
	}
	if encodeErr != nil || validateHelperReceiveHeader(request, header, credentialprotocol.PacketTypeEvent, false, false, uint32(len(encoded))) != nil ||
		validateOptionalHelperBody(body, encoded) != nil {
		clear(encoded)
		return HelperPacket{}, errInvalidHelperPacket
	}
	clear(encoded)
	released = true
	if destroyErr := destroyHelperBody(body); destroyErr != nil {
		return HelperPacket{}, errInvalidHelperPacket
	}
	return HelperPacket{
		header: header,
		arm:    helperPacketArm{kind: helperPacketArmEvent, event: event},
	}, nil
}

func newHelperExecStreamPacket(request HelperReceiveRequest, header credentialprotocol.HelperPacketHeader, body helperBodyCapability, revision uint64, kind credentialprotocol.HelperExecStreamKind, flags credentialprotocol.HelperExecStreamFlags, offset uint64, payloadLength uint32, payloadSHA256 [32]byte) (packet HelperPacket, err error) {
	retainedBody := false
	defer func() {
		if err != nil && !retainedBody {
			_ = destroyHelperBody(body)
		}
	}()
	if consumeErr := consumeHelperReceiveRequest(request); consumeErr != nil {
		return HelperPacket{}, consumeErr
	}
	if !validHelperReceiveExecStream(kind, flags, payloadLength, payloadSHA256) || revision == 0 {
		return HelperPacket{}, errInvalidHelperPacket
	}
	bodyLength := helperExecStreamCanonicalPrefixBytes + payloadLength
	if validateHelperReceiveHeader(request, header, credentialprotocol.PacketTypeExecStream, true, false, bodyLength) != nil ||
		(payloadLength > 0 && !configuredDependency(body)) ||
		validateOptionalHelperBodyLength(body, bodyLength) != nil {
		return HelperPacket{}, errInvalidHelperPacket
	}
	retainedBody = configuredDependency(body)
	return HelperPacket{
		header: header,
		arm: helperPacketArm{
			kind: helperPacketArmExecStream,
			execStream: helperExecStreamRecord{
				revision:      revision,
				kind:          kind,
				flags:         flags,
				offset:        offset,
				payloadLength: payloadLength,
				payloadSHA256: payloadSHA256,
			},
		},
		body: body,
	}, nil
}

func newHelperExecCreditPacket(request HelperReceiveRequest, header credentialprotocol.HelperPacketHeader, body helperBodyCapability, credit credentialprotocol.HelperExecCreditBody) (packet HelperPacket, err error) {
	released := false
	defer func() {
		if err != nil && !released {
			_ = destroyHelperBody(body)
		}
	}()
	encoded, encodeErr := credentialprotocol.EncodeHelperExecCreditBody(credit)
	if consumeErr := consumeHelperReceiveRequest(request); consumeErr != nil {
		return HelperPacket{}, consumeErr
	}
	if encodeErr != nil || credit.StreamKind != credentialprotocol.HelperExecStreamStdin ||
		validateHelperReceiveHeader(request, header, credentialprotocol.PacketTypeExecCredit, true, false, uint32(len(encoded))) != nil ||
		validateOptionalHelperBody(body, encoded) != nil {
		clear(encoded)
		return HelperPacket{}, errInvalidHelperPacket
	}
	clear(encoded)
	released = true
	if destroyErr := destroyHelperBody(body); destroyErr != nil {
		return HelperPacket{}, errInvalidHelperPacket
	}
	return HelperPacket{
		header: header,
		arm:    helperPacketArm{kind: helperPacketArmExecCredit, execCredit: credit},
	}, nil
}

func newHelperSSHAcceptedPacket(request HelperReceiveRequest, header credentialprotocol.HelperPacketHeader, body helperBodyCapability, revision uint64, bindingIndex uint16, ordinal uint8, digest [32]byte, capability SSHConnectionCapability) (packet HelperPacket, err error) {
	releasedBody := false
	retainedRight := false
	defer func() {
		if err != nil && !releasedBody {
			_ = destroyHelperBody(body)
		}
		if err != nil && !retainedRight && configuredDependency(capability) {
			_ = closeRejectedSSHCapability(capability)
		}
	}()
	encodedLength := credentialprotocol.HelperSSHAcceptedFDBodyEncodedLength()
	encoded := make([]byte, encodedLength)
	encodeErr := credentialprotocol.EncodeHelperSSHAcceptedFDBodyTo(encoded, revision, bindingIndex, ordinal, digest)
	if consumeErr := consumeHelperReceiveRequest(request); consumeErr != nil {
		clear(encoded)
		return HelperPacket{}, consumeErr
	}
	if encodeErr != nil || request.maximumRights != 1 ||
		validateHelperReceiveHeader(request, header, credentialprotocol.PacketTypeSSHAcceptedFD, false, false, encodedLength) != nil ||
		validateOptionalHelperBody(body, encoded) != nil || !configuredDependency(capability) {
		clear(encoded)
		return HelperPacket{}, errInvalidHelperPacket
	}
	clear(encoded)
	capabilityDigest, valid := safeSSHIssuerDigest(capability)
	if !valid || capabilityDigest == ([32]byte{}) || subtle.ConstantTimeCompare(capabilityDigest[:], digest[:]) != 1 {
		return HelperPacket{}, errInvalidHelperPacket
	}
	releasedBody = true
	if destroyErr := destroyHelperBody(body); destroyErr != nil {
		return HelperPacket{}, errInvalidHelperPacket
	}
	ownership := newSSHConnectionOwnership(capabilityDigest, capability)
	view := sshConnectionView{ownership: ownership}
	retainedRight = true
	return HelperPacket{
		header: header,
		arm: helperPacketArm{
			kind: helperPacketArmSSHAccepted,
			sshAccepted: SSHAcceptedPacket{
				revision:         revision,
				bindingIndex:     bindingIndex,
				ordinal:          ordinal,
				capabilitySHA256: digest,
				connection:       view,
				ownership:        ownership,
			},
		},
		right: view,
	}, nil
}

func newHelperCloseNotifyPacket(request HelperReceiveRequest, header credentialprotocol.HelperPacketHeader, body helperBodyCapability, closeBody credentialprotocol.HelperCloseNotifyBody) (packet HelperPacket, err error) {
	released := false
	defer func() {
		if err != nil && !released {
			_ = destroyHelperBody(body)
		}
	}()
	encoded, encodeErr := credentialprotocol.EncodeHelperCloseNotifyBody(closeBody)
	if consumeErr := consumeHelperReceiveRequest(request); consumeErr != nil {
		return HelperPacket{}, consumeErr
	}
	if encodeErr != nil || validateHelperReceiveHeader(request, header, credentialprotocol.PacketTypeCloseNotify, false, true, uint32(len(encoded))) != nil ||
		validateOptionalHelperBody(body, encoded) != nil {
		clear(encoded)
		return HelperPacket{}, errInvalidHelperPacket
	}
	clear(encoded)
	released = true
	if destroyErr := destroyHelperBody(body); destroyErr != nil {
		return HelperPacket{}, errInvalidHelperPacket
	}
	return HelperPacket{
		header: header,
		arm:    helperPacketArm{kind: helperPacketArmClose, close: closeBody},
	}, nil
}

func validateHelperReceiveHeader(request HelperReceiveRequest, header credentialprotocol.HelperPacketHeader, wantType credentialprotocol.PacketType, requireExpectedID, requireZeroRequestID bool, encodedLength uint32) error {
	if header.Type != wantType || header.Sequence == 0 || header.Sequence != request.nextSequence ||
		credentialprotocol.ValidateHelperPacketHeaderSemantics(header) != nil ||
		header.BodyLength != encodedLength || header.BodyLength > request.maximumBodyBytes ||
		header.GuestCredentialIdentityDigest != request.expectedIdentity {
		return errInvalidHelperPacket
	}
	if requireExpectedID && !request.expectedRequestIDSet {
		return errInvalidHelperPacket
	}
	if requireZeroRequestID {
		if request.expectedRequestIDSet || header.RequestID != ([16]byte{}) {
			return errInvalidHelperPacket
		}
		return nil
	}
	if request.expectedRequestIDSet && header.RequestID != request.expectedRequestID {
		return errInvalidHelperPacket
	}
	return nil
}

func validHelperReceiveExecStream(kind credentialprotocol.HelperExecStreamKind, flags credentialprotocol.HelperExecStreamFlags, payloadLength uint32, payloadSHA256 [32]byte) bool {
	if kind != credentialprotocol.HelperExecStreamStdout && kind != credentialprotocol.HelperExecStreamStderr {
		return false
	}
	return validHelperExecStreamShape(flags, payloadLength, payloadSHA256)
}

func validControllerReceiveExecStream(kind credentialprotocol.HelperExecStreamKind, flags credentialprotocol.HelperExecStreamFlags, payloadLength uint32, payloadSHA256 [32]byte) bool {
	if kind != credentialprotocol.HelperExecStreamStdin {
		return false
	}
	return validHelperExecStreamShape(flags, payloadLength, payloadSHA256)
}

func validControllerReceiveCredit(kind credentialprotocol.HelperExecStreamKind) bool {
	return kind == credentialprotocol.HelperExecStreamStdout || kind == credentialprotocol.HelperExecStreamStderr
}

func validHelperExecStreamShape(flags credentialprotocol.HelperExecStreamFlags, payloadLength uint32, payloadSHA256 [32]byte) bool {
	if flags != credentialprotocol.HelperExecStreamFlagsNone && flags != credentialprotocol.HelperExecStreamFlagEOF {
		return false
	}
	if payloadLength > credentialprotocol.MaxHelperExecStreamPayloadBytes {
		return false
	}
	if flags == credentialprotocol.HelperExecStreamFlagsNone && payloadLength == 0 {
		return false
	}
	if flags == credentialprotocol.HelperExecStreamFlagEOF && payloadLength != 0 {
		return false
	}
	if payloadLength == 0 {
		return payloadSHA256 == sha256.Sum256(nil)
	}
	return payloadSHA256 != ([32]byte{})
}

func validControllerPrivateMetadata(kind credentialprotocol.PrivateRecordKind, requestID v2control.RequestID, identityDigest v2control.IdentityDigest, bindingIndex, chunkIndex, chunkCount uint16, payloadLength uint32, payloadSHA256 [32]byte) bool {
	if kind != credentialprotocol.PrivateRecordKindFileBytes && kind != credentialprotocol.PrivateRecordKindOpaqueExecBinding {
		return false
	}
	if _, err := v2control.EncodeRequestID(requestID); err != nil {
		return false
	}
	if identityDigest == (v2control.IdentityDigest{}) {
		return false
	}
	if chunkIndex != 0 || chunkCount != 1 {
		return false
	}
	if payloadLength < 1 || payloadLength > credentialprotocol.MaxPrivateRecordPayloadBytes {
		return false
	}
	if payloadSHA256 == ([32]byte{}) {
		return false
	}
	if kind == credentialprotocol.PrivateRecordKindFileBytes && bindingIndex >= credentialprotocol.MaxPreparePrivateRecordCount {
		return false
	}
	if kind == credentialprotocol.PrivateRecordKindOpaqueExecBinding && bindingIndex != 0 {
		return false
	}
	return true
}

func validateOptionalHelperBody(body helperBodyCapability, encoded []byte) error {
	if body == nil {
		return nil
	}
	if !configuredDependency(body) {
		return errInvalidHelperPacket
	}
	length, digest, ok := helperBodyMetadata(body)
	if !ok || uint64(length) != uint64(len(encoded)) || digest != sha256.Sum256(encoded) {
		return errInvalidHelperPacket
	}
	return nil
}

func validateOptionalHelperBodyLength(body helperBodyCapability, length uint32) error {
	if body == nil {
		return nil
	}
	if !configuredDependency(body) {
		return errInvalidHelperPacket
	}
	got, _, ok := helperBodyMetadata(body)
	if !ok || got != length {
		return errInvalidHelperPacket
	}
	return nil
}

func helperBodyMetadata(body helperBodyCapability) (length uint32, digest [32]byte, ok bool) {
	return bodyCapabilityMetadata(body)
}

func controllerBodyMetadata(body controllerBodyCapability) (length uint32, digest [32]byte, ok bool) {
	return bodyCapabilityMetadata(body)
}

func bodyCapabilityMetadata(body interface {
	Len() uint32
	SHA256() [32]byte
}) (length uint32, digest [32]byte, ok bool) {
	defer func() {
		if recover() != nil {
			length = 0
			digest = [32]byte{}
			ok = false
		}
	}()
	return body.Len(), body.SHA256(), true
}

func destroyHelperBody(body helperBodyCapability) error {
	return destroyOwnedBody(body, errInvalidHelperPacket)
}

func destroyControllerBody(body controllerBodyCapability) error {
	return destroyOwnedBody(body, errInvalidControllerPacket)
}

type exactPrivateByteSink struct {
	target []byte
	offset int
	failed bool
}

func (sink *exactPrivateByteSink) MaxCredentialBytes() int {
	if sink == nil || sink.failed {
		return 0
	}
	return len(sink.target) - sink.offset
}

func (sink *exactPrivateByteSink) WriteCredential(source []byte) error {
	if sink == nil || sink.failed || sink.offset+len(source) > len(sink.target) {
		if sink != nil {
			sink.failed = true
		}
		return errInvalidControllerPacket
	}
	copy(sink.target[sink.offset:], source)
	sink.offset += len(source)
	return nil
}

func helperSendPrivateOwnerUnaccepted(kind helperSendArmKind, err error) bool {
	return err != nil && errors.Is(err, ErrClientControlDependencyUnaccepted) &&
		(kind == helperSendArmPrepareFile || kind == helperSendArmExecPrivate)
}

func copyControllerPrepareFileOwner(
	ctx context.Context,
	body controllerBodyCapability,
	revision uint64,
	bindingIndex uint16,
	fileSHA256 [32]byte,
	expectedLength uint32,
) (*helperPrepareFileOwner, error) {
	if ctx == nil || ctx.Err() != nil || !configuredDependency(body) ||
		expectedLength == 0 || expectedLength > credentialprotocol.MaxHelperFileBytes {
		return nil, ErrClientControlDependencyUnaccepted
	}
	length, digest, ok := controllerBodyMetadata(body)
	if !ok || length != expectedLength || digest != fileSHA256 {
		return nil, ErrClientControlDependencyUnaccepted
	}
	var owner *helperPrepareFileOwner
	borrowErr := body.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		if view == nil || view.Len() != int(expectedLength) {
			return ErrClientControlDependencyUnaccepted
		}
		buf := make([]byte, expectedLength)
		sink := &exactPrivateByteSink{target: buf}
		if writeErr := view.WriteTo(ctx, sink); writeErr != nil {
			clear(buf)
			return writeErr
		}
		if sink.failed || sink.offset != len(buf) {
			clear(buf)
			return ErrClientControlDependencyUnaccepted
		}
		created, err := newHelperPrepareFileOwner(revision, bindingIndex, fileSHA256, buf)
		clear(buf)
		if err != nil {
			return ErrClientControlDependencyUnaccepted
		}
		owner = created
		return nil
	})
	if borrowErr != nil {
		wipeHelperPrepareFileOwner(owner)
		return nil, ErrClientControlDependencyUnaccepted
	}
	if owner == nil {
		return nil, ErrClientControlDependencyUnaccepted
	}
	return owner, nil
}

func copyControllerExecPrivateOwner(
	ctx context.Context,
	body controllerBodyCapability,
	revision uint64,
	privateBindingSHA256 [32]byte,
	expectedLength uint32,
) (*helperExecPrivateOwner, error) {
	if ctx == nil || ctx.Err() != nil || !configuredDependency(body) ||
		expectedLength == 0 || expectedLength > credentialprotocol.MaxHelperExecPrivateBytes {
		return nil, ErrClientControlDependencyUnaccepted
	}
	length, digest, ok := controllerBodyMetadata(body)
	if !ok || length != expectedLength || digest != privateBindingSHA256 {
		return nil, ErrClientControlDependencyUnaccepted
	}
	var owner *helperExecPrivateOwner
	borrowErr := body.Borrow(ctx, func(view credentialmemory.BorrowedView) error {
		if view == nil || view.Len() != int(expectedLength) {
			return ErrClientControlDependencyUnaccepted
		}
		buf := make([]byte, expectedLength)
		sink := &exactPrivateByteSink{target: buf}
		if writeErr := view.WriteTo(ctx, sink); writeErr != nil {
			clear(buf)
			return writeErr
		}
		if sink.failed || sink.offset != len(buf) {
			clear(buf)
			return ErrClientControlDependencyUnaccepted
		}
		created, err := newHelperExecPrivateOwner(revision, privateBindingSHA256, buf)
		clear(buf)
		if err != nil {
			return ErrClientControlDependencyUnaccepted
		}
		owner = created
		return nil
	})
	if borrowErr != nil {
		wipeHelperExecPrivateOwner(owner)
		return nil, ErrClientControlDependencyUnaccepted
	}
	if owner == nil {
		return nil, ErrClientControlDependencyUnaccepted
	}
	return owner, nil
}

func destroyOwnedBody(body interface {
	Destroy(context.Context) error
}, invalid error) (err error) {
	if !configuredDependency(body) {
		return nil
	}
	defer func() {
		if recover() != nil {
			err = invalid
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), sshConnectionCleanupTimeout)
	defer cancel()
	if destroyErr := body.Destroy(ctx); destroyErr != nil {
		return invalid
	}
	return nil
}

func cloneHelperResponseBody(body credentialprotocol.HelperResponseBody) credentialprotocol.HelperResponseBody {
	clone := body
	if body.Prepare != nil {
		prepare := *body.Prepare
		prepare.BindingProofs = cloneValues(body.Prepare.BindingProofs)
		clone.Prepare = &prepare
	}
	if body.Renew != nil {
		renew := *body.Renew
		clone.Renew = &renew
	}
	if body.Revoke != nil {
		revoke := *body.Revoke
		clone.Revoke = &revoke
	}
	if body.Exec != nil {
		exec := *body.Exec
		clone.Exec = &exec
	}
	return clone
}

func (packet HelperPacket) packetTypeValue() credentialprotocol.PacketType { return packet.header.Type }
func (packet HelperPacket) headerValue() credentialprotocol.HelperPacketHeader {
	return packet.header
}
func (packet HelperPacket) responseValue() (credentialprotocol.HelperResponseBody, bool) {
	return packet.arm.response, packet.arm.kind == helperPacketArmResponse
}
func (packet HelperPacket) eventValue() (credentialprotocol.HelperEventBody, bool) {
	return packet.arm.event, packet.arm.kind == helperPacketArmEvent
}
func (packet HelperPacket) execStreamValue() (helperExecStreamRecord, bool) {
	return packet.arm.execStream, packet.arm.kind == helperPacketArmExecStream
}
func (packet HelperPacket) execCreditValue() (credentialprotocol.HelperExecCreditBody, bool) {
	return packet.arm.execCredit, packet.arm.kind == helperPacketArmExecCredit
}
func (packet HelperPacket) sshAcceptedValue() (SSHAcceptedPacket, bool) {
	return packet.arm.sshAccepted, packet.arm.kind == helperPacketArmSSHAccepted
}
func (packet HelperPacket) closeNotifyValue() (credentialprotocol.HelperCloseNotifyBody, bool) {
	return packet.arm.close, packet.arm.kind == helperPacketArmClose
}

func (packet HelperSendPacket) packetTypeValue() credentialprotocol.PacketType {
	return packet.header.Type
}
func (packet HelperSendPacket) headerValue() credentialprotocol.HelperPacketHeader {
	return packet.header
}
func (packet HelperSendPacket) encodedBodyLengthValue() uint32 { return packet.encodedBodyLength }
func (packet HelperSendPacket) bodySHA256Value() [32]byte      { return packet.bodySHA256 }
func (packet HelperSendPacket) writeCanonicalBody(sink bodySegmentSink) (err error) {
	defer func() {
		if recover() != nil {
			err = errInvalidHelperSendPacket
		}
	}()
	switch packet.arm {
	case helperSendArmPrepareBegin, helperSendArmPrepareCommit, helperSendArmRenew, helperSendArmRevoke, helperSendArmExec, helperSendArmExecCredit, helperSendArmClose:
	case helperSendArmPrepareFile, helperSendArmExecPrivate:
		if packet.state == nil {
			return ErrClientControlDependencyUnaccepted
		}
	default:
		return ErrClientControlDependencyUnaccepted
	}
	if packet.state == nil {
		return errInvalidHelperSendPacket
	}
	packet.state.mu.Lock()
	if packet.state.consumed || packet.state.owner == nil {
		packet.state.mu.Unlock()
		return errInvalidHelperSendPacket
	}
	owner := packet.state.owner
	packet.state.consumed = true
	packet.state.owner = nil
	packet.state.mu.Unlock()
	defer func() { _ = destroyHelperBody(owner.body) }()
	switch packet.arm {
	case helperSendArmPrepareFile:
		defer wipeHelperPrepareFileOwner(owner.arm.prepareFile.owner)
		if owner.arm.prepareFile.owner == nil || owner.arm.prepareFile.owner.body == nil {
			return ErrClientControlDependencyUnaccepted
		}
	case helperSendArmExecPrivate:
		defer wipeHelperExecPrivateOwner(owner.arm.execPrivate.owner)
		if owner.arm.execPrivate.owner == nil || owner.arm.execPrivate.owner.body == nil {
			return ErrClientControlDependencyUnaccepted
		}
	}
	body, encodeErr := encodeHelperSendCanonicalBody(packet.arm, owner.arm)
	defer clear(body)
	if encodeErr != nil || uint64(len(body)) != uint64(packet.encodedBodyLength) || packet.header.BodyLength != packet.encodedBodyLength || sha256.Sum256(body) != packet.bodySHA256 {
		if helperSendPrivateOwnerUnaccepted(packet.arm, encodeErr) {
			return ErrClientControlDependencyUnaccepted
		}
		return errInvalidHelperSendPacket
	}
	if sink == nil || sink.Capacity() != packet.encodedBodyLength {
		return errInvalidHelperSendPacket
	}
	if writeErr := sink.WriteSegment(0, body); writeErr != nil {
		return errInvalidHelperSendPacket
	}
	return nil
}

func finishHelperSendPacket(header credentialprotocol.HelperPacketHeader, kind helperSendArmKind, arm helperSendArm) (HelperSendPacket, error) {
	body, err := encodeHelperSendCanonicalBody(kind, arm)
	defer clear(body)
	if err != nil || len(body) == 0 || header.Sequence == 0 || header.Sequence > uint64(^uint32(0)) ||
		(kind == helperSendArmClose && header.RequestID != ([16]byte{})) || header.BodyLength != uint32(len(body)) ||
		credentialprotocol.ValidateHelperPacketHeaderSemantics(header) != nil || header.Type != helperSendArmPacketType(kind) {
		return HelperSendPacket{}, errInvalidHelperSendPacket
	}
	return HelperSendPacket{
		header:            header,
		arm:               kind,
		encodedBodyLength: uint32(len(body)),
		bodySHA256:        sha256.Sum256(body),
		state: &helperSendPacketState{
			owner: &helperSendPacketOwner{arm: arm},
		},
	}, nil
}

func encodeHelperSendCanonicalBody(kind helperSendArmKind, arm helperSendArm) ([]byte, error) {
	switch kind {
	case helperSendArmPrepareBegin:
		return credentialprotocol.EncodeHelperPrepareBeginBody(arm.prepareBegin)
	case helperSendArmPrepareFile:
		if arm.prepareFile.owner == nil || arm.prepareFile.owner.body == nil {
			return nil, ErrClientControlDependencyUnaccepted
		}
		return credentialprotocol.EncodeHelperPrepareFileBody(arm.prepareFile.owner.body)
	case helperSendArmPrepareCommit:
		return credentialprotocol.EncodeHelperPrepareCommitBody(arm.prepareCommit)
	case helperSendArmRenew:
		return credentialprotocol.EncodeHelperRenewBody(arm.renew)
	case helperSendArmRevoke:
		return credentialprotocol.EncodeHelperRevokeBody(arm.revoke)
	case helperSendArmExec:
		return credentialprotocol.EncodeHelperExecBody(arm.exec)
	case helperSendArmExecPrivate:
		if arm.execPrivate.owner == nil || arm.execPrivate.owner.body == nil {
			return nil, ErrClientControlDependencyUnaccepted
		}
		return credentialprotocol.EncodeHelperExecPrivateBody(arm.execPrivate.owner.body)
	case helperSendArmExecCredit:
		if arm.execCredit.StreamKind != credentialprotocol.HelperExecStreamStdout &&
			arm.execCredit.StreamKind != credentialprotocol.HelperExecStreamStderr {
			return nil, errInvalidHelperSendPacket
		}
		return credentialprotocol.EncodeHelperExecCreditBody(arm.execCredit)
	case helperSendArmClose:
		return credentialprotocol.EncodeHelperCloseNotifyBody(arm.close)
	default:
		return nil, ErrClientControlDependencyUnaccepted
	}
}

func newHelperPrepareBeginSendPacket(header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperPrepareBeginBody) (HelperSendPacket, error) {
	cloned := body
	cloned.Bindings = cloneValues(body.Bindings)
	return newHelperMetadataSendPacket(header, helperSendArmPrepareBegin, helperSendArm{kind: helperSendArmPrepareBegin, prepareBegin: cloned})
}

func newHelperPrepareFileSendPacket(header credentialprotocol.HelperPacketHeader, owner *helperPrepareFileOwner) (HelperSendPacket, error) {
	if owner == nil || owner.body == nil {
		return HelperSendPacket{}, ErrClientControlDependencyUnaccepted
	}
	body := owner.body
	return newHelperMetadataSendPacket(header, helperSendArmPrepareFile, helperSendArm{
		kind: helperSendArmPrepareFile,
		prepareFile: helperPrepareFileArm{
			revision:     body.Revision(),
			bindingIndex: body.BindingIndex(),
			fileLength:   body.FileLength(),
			fileSHA256:   body.FileSHA256(),
			owner:        owner,
		},
	})
}

func newHelperPrepareCommitSendPacket(header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperPrepareCommitBody) (HelperSendPacket, error) {
	return newHelperMetadataSendPacket(header, helperSendArmPrepareCommit, helperSendArm{kind: helperSendArmPrepareCommit, prepareCommit: body})
}

func newHelperRenewSendPacket(header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperRenewBody) (HelperSendPacket, error) {
	return newHelperMetadataSendPacket(header, helperSendArmRenew, helperSendArm{kind: helperSendArmRenew, renew: body})
}

func newHelperRevokeSendPacket(header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperRevokeBody) (HelperSendPacket, error) {
	return newHelperMetadataSendPacket(header, helperSendArmRevoke, helperSendArm{kind: helperSendArmRevoke, revoke: body})
}

func newHelperExecSendPacket(header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperExecBody) (HelperSendPacket, error) {
	cloned := body
	cloned.Plan.Arguments = cloneValues(body.Plan.Arguments)
	cloned.Plan.Environment = cloneValues(body.Plan.Environment)
	return newHelperMetadataSendPacket(header, helperSendArmExec, helperSendArm{kind: helperSendArmExec, exec: cloned})
}

func newHelperExecPrivateSendPacket(header credentialprotocol.HelperPacketHeader, owner *helperExecPrivateOwner) (HelperSendPacket, error) {
	if owner == nil || owner.body == nil {
		return HelperSendPacket{}, ErrClientControlDependencyUnaccepted
	}
	body := owner.body
	return newHelperMetadataSendPacket(header, helperSendArmExecPrivate, helperSendArm{
		kind: helperSendArmExecPrivate,
		execPrivate: helperExecPrivateArm{
			revision:             body.Revision(),
			privateBindingLength: body.PrivateBindingLength(),
			privateBindingSHA256: body.PrivateBindingSHA256(),
			owner:                owner,
		},
	})
}

func newHelperExecCreditSendPacket(header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperExecCreditBody) (HelperSendPacket, error) {
	if body.StreamKind != credentialprotocol.HelperExecStreamStdout &&
		body.StreamKind != credentialprotocol.HelperExecStreamStderr {
		return HelperSendPacket{}, errInvalidHelperSendPacket
	}
	return newHelperMetadataSendPacket(header, helperSendArmExecCredit, helperSendArm{kind: helperSendArmExecCredit, execCredit: body})
}

func newHelperCloseNotifySendPacket(header credentialprotocol.HelperPacketHeader, body credentialprotocol.HelperCloseNotifyBody) (HelperSendPacket, error) {
	return newHelperMetadataSendPacket(header, helperSendArmClose, helperSendArm{kind: helperSendArmClose, close: body})
}

func newHelperMetadataSendPacket(header credentialprotocol.HelperPacketHeader, kind helperSendArmKind, arm helperSendArm) (HelperSendPacket, error) {
	if header.Sequence == 0 {
		return HelperSendPacket{}, errInvalidHelperSendPacket
	}
	header.Type = helperSendArmPacketType(kind)
	encoded, err := encodeHelperSendCanonicalBody(kind, arm)
	if err != nil || len(encoded) == 0 {
		clear(encoded)
		if helperSendPrivateOwnerUnaccepted(kind, err) {
			return HelperSendPacket{}, ErrClientControlDependencyUnaccepted
		}
		return HelperSendPacket{}, errInvalidHelperSendPacket
	}
	header.BodyLength = uint32(len(encoded))
	packet, finishErr := finishHelperSendPacket(header, kind, arm)
	clear(encoded)
	return packet, finishErr
}

func helperSendArmPacketType(kind helperSendArmKind) credentialprotocol.PacketType {
	switch kind {
	case helperSendArmPrepareBegin:
		return credentialprotocol.PacketTypePrepareBegin
	case helperSendArmPrepareFile:
		return credentialprotocol.PacketTypePrepareFile
	case helperSendArmPrepareCommit:
		return credentialprotocol.PacketTypePrepareCommit
	case helperSendArmRenew:
		return credentialprotocol.PacketTypeRenew
	case helperSendArmRevoke:
		return credentialprotocol.PacketTypeRevoke
	case helperSendArmExec:
		return credentialprotocol.PacketTypeExec
	case helperSendArmExecPrivate:
		return credentialprotocol.PacketTypeExecPrivate
	case helperSendArmExecStream:
		return credentialprotocol.PacketTypeExecStream
	case helperSendArmExecCredit:
		return credentialprotocol.PacketTypeExecCredit
	case helperSendArmClose:
		return credentialprotocol.PacketTypeCloseNotify
	default:
		return 0
	}
}

var _ io.Reader = VerifiedControlStream(nil)
