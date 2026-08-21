package credentialclient

import (
	"context"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/v2control"
)

var ErrClientControlDependencyUnaccepted = errors.New("credential client control dependency is unaccepted")

// ControlAcceptExpectation is the private-snapshot expectation presented only
// to the inherited, preopened control listener owner. It carries no FD.
type ControlAcceptExpectation struct {
	liveValue
	identity session.Identity
}

// NewControlAcceptExpectation is frozen by D6 RED tests. Production issuance
// remains dependency_unaccepted until the runtime-owned boot identity lands.
func NewControlAcceptExpectation(session.Identity) (ControlAcceptExpectation, error) {
	return ControlAcceptExpectation{}, ErrClientControlDependencyUnaccepted
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

// TransportIdentity binds the authenticated control session to the exact
// helper generation retained by the same operational Transport.
type TransportIdentity struct {
	liveValue
	sessionID        [32]byte
	identity         session.Identity
	hardExpiry       time.Time
	helperGeneration credentialprotocol.SafeID
}

// AuthenticatedTransport is the exact D6 control/helper transport admitted by
// future operational Client construction. The legacy Transport interface is
// left source-compatible while the RED contract is reviewed.
type AuthenticatedTransport interface {
	Transport
	Identity() TransportIdentity
}

// NewTransportIdentity is a RED contract stub. The future implementation must
// validate all base identity fields and helper/session correlation.
func NewTransportIdentity([32]byte, session.Identity, time.Time, credentialprotocol.SafeID) (TransportIdentity, error) {
	return TransportIdentity{}, ErrClientControlDependencyUnaccepted
}

func (identity TransportIdentity) SessionID() [32]byte               { return identity.sessionID }
func (identity TransportIdentity) SessionIdentity() session.Identity { return identity.identity }
func (identity TransportIdentity) HardExpiry() time.Time             { return identity.hardExpiry }
func (identity TransportIdentity) HelperGeneration() credentialprotocol.SafeID {
	return identity.helperGeneration
}

// ControllerBodyCapability owns one fixed-capacity locked controller body.
type ControllerBodyCapability interface {
	Len() uint32
	SHA256() [32]byte
	Borrow(context.Context, func(credentialmemory.BorrowedView) error) error
	Destroy(context.Context) error
}

// HelperBodyCapability owns one fixed-capacity locked helper body.
type HelperBodyCapability interface {
	Len() uint32
	SHA256() [32]byte
	Borrow(context.Context, func(credentialmemory.BorrowedView) error) error
	Destroy(context.Context) error
}

// BodySegmentSink accepts only the future exact contiguous canonical fill.
type BodySegmentSink interface {
	Capacity() uint32
	WriteSegment(offset uint32, source []byte) error
}

type ControllerUnknownOperation struct {
	liveValue
	inspected v2control.InspectedRequest
}

type ControllerMalformedKnown struct {
	liveValue
	inspected v2control.InspectedRequest
}

type ControllerPrivateRecord struct {
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

type ControllerStreamRecord struct {
	liveValue
	kind           credentialprotocol.HelperExecStreamKind
	flags          credentialprotocol.HelperExecStreamFlags
	requestID      v2control.RequestID
	identityDigest v2control.IdentityDigest
	offset         uint64
	payloadLength  uint32
	payloadSHA256  [32]byte
}

type ControllerCreditRecord struct {
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
	unknown   ControllerUnknownOperation
	malformed ControllerMalformedKnown
	private   ControllerPrivateRecord
	stream    ControllerStreamRecord
	credit    ControllerCreditRecord
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
	stream    ControllerStreamRecord
	credit    ControllerCreditRecord
	close     credentialprotocol.CloseReason
}

type controllerSendPacketState struct {
	mu       sync.Mutex
	consumed bool
	owner    *controllerSendPacketOwner
}

type controllerSendPacketOwner struct {
	arm  controllerSendArm
	body ControllerBodyCapability
}

type HelperExecStreamRecord struct {
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
	execStream  HelperExecStreamRecord
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
}

type helperExecPrivateArm struct {
	revision             uint64
	privateBindingLength uint32
	privateBindingSHA256 [32]byte
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
	execStream    HelperExecStreamRecord
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
	body HelperBodyCapability
}

func NewControllerReceiveRequest(uint64, v2control.IdentityDigest, bool, uint32) (ControllerReceiveRequest, error) {
	return ControllerReceiveRequest{}, ErrClientControlDependencyUnaccepted
}

func NewHelperReceiveRequest(uint64, uint32, uint32, [16]byte, bool, [32]byte) (HelperReceiveRequest, error) {
	return HelperReceiveRequest{}, ErrClientControlDependencyUnaccepted
}

func (request ControllerReceiveRequest) NextSequence() uint64 { return request.nextSequence }
func (request ControllerReceiveRequest) ExpectedIdentity() (v2control.IdentityDigest, bool) {
	return request.expectedIdentity, request.expectedIdentitySet
}
func (request ControllerReceiveRequest) MaximumPlaintextBytes() uint32 {
	return request.maximumPlaintextBytes
}

func (request HelperReceiveRequest) NextSequence() uint64     { return request.nextSequence }
func (request HelperReceiveRequest) MaximumBodyBytes() uint32 { return request.maximumBodyBytes }
func (request HelperReceiveRequest) MaximumRights() uint32    { return request.maximumRights }
func (request HelperReceiveRequest) ExpectedRequestID() ([16]byte, bool) {
	return request.expectedRequestID, request.expectedRequestIDSet
}
func (request HelperReceiveRequest) ExpectedIdentityDigest() [32]byte {
	return request.expectedIdentity
}

func NewControllerUnknownOperationPacket(ControllerReceiveRequest, uint64, [32]byte, v2control.InspectedRequest) (ControllerPacket, error) {
	return ControllerPacket{}, ErrClientControlDependencyUnaccepted
}

func NewControllerMalformedKnownPacket(ControllerReceiveRequest, uint64, [32]byte, v2control.InspectedRequest) (ControllerPacket, error) {
	return ControllerPacket{}, ErrClientControlDependencyUnaccepted
}

func NewControllerReadinessPacket(ControllerReceiveRequest, uint64, [32]byte, v2control.ReadinessRequest) (ControllerPacket, error) {
	return ControllerPacket{}, ErrClientControlDependencyUnaccepted
}

func NewControllerPreparePacket(ControllerReceiveRequest, uint64, [32]byte, v2control.CredentialPrepareRequest) (ControllerPacket, error) {
	return ControllerPacket{}, ErrClientControlDependencyUnaccepted
}

func NewControllerRenewPacket(ControllerReceiveRequest, uint64, [32]byte, v2control.CredentialRenewRequest) (ControllerPacket, error) {
	return ControllerPacket{}, ErrClientControlDependencyUnaccepted
}

func NewControllerRevokePacket(ControllerReceiveRequest, uint64, [32]byte, v2control.CredentialRevokeRequest) (ControllerPacket, error) {
	return ControllerPacket{}, ErrClientControlDependencyUnaccepted
}

func NewControllerExecPacket(ControllerReceiveRequest, uint64, [32]byte, v2control.CredentialExecRequest) (ControllerPacket, error) {
	return ControllerPacket{}, ErrClientControlDependencyUnaccepted
}

func NewControllerPrivatePacket(ControllerReceiveRequest, uint64, [32]byte, credentialprotocol.PrivateRecordKind, v2control.RequestID, v2control.IdentityDigest, uint16, uint16, uint16, uint32, [32]byte, ControllerBodyCapability) (ControllerPacket, error) {
	return ControllerPacket{}, ErrClientControlDependencyUnaccepted
}

func NewControllerStreamPacket(ControllerReceiveRequest, uint64, [32]byte, credentialprotocol.HelperExecStreamKind, credentialprotocol.HelperExecStreamFlags, v2control.RequestID, v2control.IdentityDigest, uint64, uint32, [32]byte, ControllerBodyCapability) (ControllerPacket, error) {
	return ControllerPacket{}, ErrClientControlDependencyUnaccepted
}

func NewControllerCreditPacket(ControllerReceiveRequest, uint64, [32]byte, credentialprotocol.HelperExecStreamKind, v2control.RequestID, v2control.IdentityDigest, uint64) (ControllerPacket, error) {
	return ControllerPacket{}, ErrClientControlDependencyUnaccepted
}

func NewControllerCloseNotifyPacket(ControllerReceiveRequest, uint64, [32]byte, credentialprotocol.CloseReason) (ControllerPacket, error) {
	return ControllerPacket{}, ErrClientControlDependencyUnaccepted
}

func (packet ControllerPacket) Sequence() uint64    { return packet.sequence }
func (packet ControllerPacket) SessionID() [32]byte { return packet.sessionID }
func (packet ControllerPacket) Readiness() (v2control.ReadinessRequest, bool) {
	return packet.arm.readiness, packet.arm.kind == controllerPacketArmReadiness
}
func (packet ControllerPacket) Prepare() (v2control.CredentialPrepareRequest, bool) {
	return packet.arm.prepare, packet.arm.kind == controllerPacketArmPrepare
}
func (packet ControllerPacket) Renew() (v2control.CredentialRenewRequest, bool) {
	return packet.arm.renew, packet.arm.kind == controllerPacketArmRenew
}
func (packet ControllerPacket) Revoke() (v2control.CredentialRevokeRequest, bool) {
	return packet.arm.revoke, packet.arm.kind == controllerPacketArmRevoke
}
func (packet ControllerPacket) Exec() (v2control.CredentialExecRequest, bool) {
	return packet.arm.exec, packet.arm.kind == controllerPacketArmExec
}
func (packet ControllerPacket) UnknownOperation() (ControllerUnknownOperation, bool) {
	return packet.arm.unknown, packet.arm.kind == controllerPacketArmUnknown
}
func (packet ControllerPacket) MalformedKnown() (ControllerMalformedKnown, bool) {
	return packet.arm.malformed, packet.arm.kind == controllerPacketArmMalformed
}
func (packet ControllerPacket) Private() (ControllerPrivateRecord, bool) {
	return packet.arm.private, packet.arm.kind == controllerPacketArmPrivate
}
func (packet ControllerPacket) Stream() (ControllerStreamRecord, bool) {
	return packet.arm.stream, packet.arm.kind == controllerPacketArmStream
}
func (packet ControllerPacket) Credit() (ControllerCreditRecord, bool) {
	return packet.arm.credit, packet.arm.kind == controllerPacketArmCredit
}
func (packet ControllerPacket) CloseNotify() (credentialprotocol.CloseReason, bool) {
	return packet.arm.close, packet.arm.kind == controllerPacketArmClose
}

func (packet ControllerSendPacket) Sequence() uint64          { return packet.sequence }
func (packet ControllerSendPacket) SessionID() [32]byte       { return packet.sessionID }
func (packet ControllerSendPacket) EncodedBodyLength() uint32 { return packet.encodedBodyLength }
func (packet ControllerSendPacket) BodySHA256() [32]byte      { return packet.bodySHA256 }
func (packet ControllerSendPacket) WriteCanonicalBody(BodySegmentSink) error {
	return ErrClientControlDependencyUnaccepted
}
func (packet ControllerSendPacket) ReadinessResponse() (v2control.ReadinessSuccessResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmReadiness, func(arm controllerSendArm) v2control.ReadinessSuccessResponse { return arm.readiness })
}
func (packet ControllerSendPacket) PrepareResponse() (v2control.CredentialPrepareSuccessResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmPrepare, func(arm controllerSendArm) v2control.CredentialPrepareSuccessResponse { return arm.prepare })
}
func (packet ControllerSendPacket) RenewResponse() (v2control.CredentialRenewSuccessResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmRenew, func(arm controllerSendArm) v2control.CredentialRenewSuccessResponse { return arm.renew })
}
func (packet ControllerSendPacket) RevokeResponse() (v2control.CredentialRevokeSuccessResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmRevoke, func(arm controllerSendArm) v2control.CredentialRevokeSuccessResponse { return arm.revoke })
}
func (packet ControllerSendPacket) ExecResponse() (v2control.CredentialExecSuccessResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmExec, func(arm controllerSendArm) v2control.CredentialExecSuccessResponse { return arm.exec })
}
func (packet ControllerSendPacket) FailureResponse() (v2control.FailureResponse, bool) {
	return controllerSendArmValue(packet, controllerSendArmFailure, func(arm controllerSendArm) v2control.FailureResponse { return arm.failure })
}
func (packet ControllerSendPacket) Stream() (ControllerStreamRecord, bool) {
	return controllerSendArmValue(packet, controllerSendArmStream, func(arm controllerSendArm) ControllerStreamRecord { return arm.stream })
}
func (packet ControllerSendPacket) Credit() (ControllerCreditRecord, bool) {
	return controllerSendArmValue(packet, controllerSendArmCredit, func(arm controllerSendArm) ControllerCreditRecord { return arm.credit })
}
func (packet ControllerSendPacket) CloseNotify() (credentialprotocol.CloseReason, bool) {
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

func NewHelperResponsePacket(HelperReceiveRequest, credentialprotocol.HelperPacketHeader, HelperBodyCapability, credentialprotocol.HelperResponseBody) (HelperPacket, error) {
	return HelperPacket{}, ErrClientControlDependencyUnaccepted
}
func NewHelperEventPacket(HelperReceiveRequest, credentialprotocol.HelperPacketHeader, HelperBodyCapability, credentialprotocol.HelperEventBody) (HelperPacket, error) {
	return HelperPacket{}, ErrClientControlDependencyUnaccepted
}
func NewHelperExecStreamPacket(HelperReceiveRequest, credentialprotocol.HelperPacketHeader, HelperBodyCapability, uint64, credentialprotocol.HelperExecStreamKind, credentialprotocol.HelperExecStreamFlags, uint64, uint32, [32]byte) (HelperPacket, error) {
	return HelperPacket{}, ErrClientControlDependencyUnaccepted
}
func NewHelperExecCreditPacket(HelperReceiveRequest, credentialprotocol.HelperPacketHeader, HelperBodyCapability, credentialprotocol.HelperExecCreditBody) (HelperPacket, error) {
	return HelperPacket{}, ErrClientControlDependencyUnaccepted
}
func NewHelperSSHAcceptedPacket(HelperReceiveRequest, credentialprotocol.HelperPacketHeader, HelperBodyCapability, uint64, uint16, uint8, [32]byte, SSHConnectionCapability) (HelperPacket, error) {
	return HelperPacket{}, ErrClientControlDependencyUnaccepted
}
func NewHelperCloseNotifyPacket(HelperReceiveRequest, credentialprotocol.HelperPacketHeader, HelperBodyCapability, credentialprotocol.HelperCloseNotifyBody) (HelperPacket, error) {
	return HelperPacket{}, ErrClientControlDependencyUnaccepted
}

func (packet HelperPacket) Type() credentialprotocol.PacketType { return packet.header.Type }
func (packet HelperPacket) Header() credentialprotocol.HelperPacketHeader {
	return packet.header
}
func (packet HelperPacket) Response() (credentialprotocol.HelperResponseBody, bool) {
	return packet.arm.response, packet.arm.kind == helperPacketArmResponse
}
func (packet HelperPacket) Event() (credentialprotocol.HelperEventBody, bool) {
	return packet.arm.event, packet.arm.kind == helperPacketArmEvent
}
func (packet HelperPacket) ExecStream() (HelperExecStreamRecord, bool) {
	return packet.arm.execStream, packet.arm.kind == helperPacketArmExecStream
}
func (packet HelperPacket) ExecCredit() (credentialprotocol.HelperExecCreditBody, bool) {
	return packet.arm.execCredit, packet.arm.kind == helperPacketArmExecCredit
}
func (packet HelperPacket) SSHAccepted() (SSHAcceptedPacket, bool) {
	return packet.arm.sshAccepted, packet.arm.kind == helperPacketArmSSHAccepted
}
func (packet HelperPacket) CloseNotify() (credentialprotocol.HelperCloseNotifyBody, bool) {
	return packet.arm.close, packet.arm.kind == helperPacketArmClose
}

func (packet HelperSendPacket) Type() credentialprotocol.PacketType { return packet.header.Type }
func (packet HelperSendPacket) Header() credentialprotocol.HelperPacketHeader {
	return packet.header
}
func (packet HelperSendPacket) EncodedBodyLength() uint32 { return packet.encodedBodyLength }
func (packet HelperSendPacket) BodySHA256() [32]byte      { return packet.bodySHA256 }
func (packet HelperSendPacket) WriteCanonicalBody(BodySegmentSink) error {
	return ErrClientControlDependencyUnaccepted
}

var _ io.Reader = VerifiedControlStream(nil)
