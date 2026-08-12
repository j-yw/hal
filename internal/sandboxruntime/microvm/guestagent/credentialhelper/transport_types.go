package credentialhelper

import (
	"context"
	"math"
	"sync/atomic"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

// Transport is the configured D4 packet capability boundary.
type Transport interface {
	Receive(context.Context, ReceiveRequest) (ReceivedPacket, error)
	Send(context.Context, SendPacket) error
	Close(context.Context) error
}

// ReceivedCapabilityKind is the closed set of live rights crossing HL8P.
type ReceivedCapabilityKind uint8

const (
	ReceivedCapabilityAgentPIDFD    ReceivedCapabilityKind = 1
	ReceivedCapabilitySSHConnection ReceivedCapabilityKind = 2
)

// ReceivedCapability is issued only by the configured Transport boundary.
type ReceivedCapability interface {
	Kind() ReceivedCapabilityKind
	SHA256() [32]byte
	Close(context.Context) error
}

// ReceivedBodyCapability is the configured Transport's locked receive body.
type ReceivedBodyCapability interface {
	Len() uint32
	SHA256() [32]byte
	Borrow(context.Context, func(credentialmemory.BorrowedView) error) error
	Destroy(context.Context) error
}

// ReceivedKernelCredential is one opaque kernel credential observation.
type ReceivedKernelCredential struct {
	liveValue
	pid uint32
	uid uint32
	gid uint32
}

// NewReceivedKernelCredential validates the positive Linux pid_t range.
func NewReceivedKernelCredential(pid, uid, gid uint32) (ReceivedKernelCredential, error) {
	if pid == 0 || pid > math.MaxInt32 {
		return ReceivedKernelCredential{}, ErrContractInvalidArgument
	}
	return ReceivedKernelCredential{pid: pid, uid: uid, gid: gid}, nil
}

type receiveRequestState struct{ consumed atomic.Bool }

// ReceiveRequest supplies one exact receive sequence and fixed budgets.
type ReceiveRequest struct {
	liveValue
	nextSequence     uint64
	maximumBodyBytes uint32
	expectedRights   uint32
	state            *receiveRequestState
}

func NewReceiveRequest(nextSequence uint64, maximumBodyBytes, expectedRights uint32) (ReceiveRequest, error) {
	if nextSequence > math.MaxUint32 || maximumBodyBytes > credentialprotocol.MaxHelperPacketBodyBytes || expectedRights > 1 {
		return ReceiveRequest{}, ErrContractInvalidArgument
	}
	return ReceiveRequest{nextSequence: nextSequence, maximumBodyBytes: maximumBodyBytes, expectedRights: expectedRights, state: &receiveRequestState{}}, nil
}

func (request ReceiveRequest) NextSequence() uint64     { return request.nextSequence }
func (request ReceiveRequest) MaximumBodyBytes() uint32 { return request.maximumBodyBytes }
func (request ReceiveRequest) ExpectedRights() uint32   { return request.expectedRights }

type receivedPacketArm interface{ receivedPacketArm() }

// ReceivedPacket is the closed inbound union. Its body, credential, and right
// remain package-private service-owned capabilities.
type ReceivedPacket struct {
	liveValue
	header     credentialprotocol.HelperPacketHeader
	arm        receivedPacketArm
	credential ReceivedKernelCredential
	body       ReceivedBodyCapability
	right      ReceivedCapability
}

func (packet ReceivedPacket) Type() credentialprotocol.PacketType           { return packet.header.Type }
func (packet ReceivedPacket) Header() credentialprotocol.HelperPacketHeader { return packet.header }

type ReceivedBootstrap struct {
	liveValue
	agentIdentitySHA256 [32]byte
	bootGeneration      credentialprotocol.SafeID
	helperGeneration    credentialprotocol.SafeID
}

type ReceivedAgentHello struct {
	liveValue
	bootstrapSHA256         [32]byte
	bootGeneration          credentialprotocol.SafeID
	helperGeneration        credentialprotocol.SafeID
	processDescriptorSHA256 [32]byte
}

type ReceivedPrepareBegin struct {
	liveValue
	revision       uint64
	expiryUnixNano int64
	manifest       ManifestCapability
}

type ReceivedPrepareFile struct {
	liveValue
	revision     uint64
	bindingIndex uint16
	fileLength   uint32
	fileSHA256   [32]byte
}

type ReceivedPrepareCommit struct {
	liveValue
	revision       uint64
	manifestSHA256 [32]byte
}

type ReceivedRenew struct {
	liveValue
	revision         uint64
	expiryUnixNano   int64
	priorProofSHA256 [32]byte
}

type ReceivedRevoke struct {
	liveValue
	revision uint64
	reason   credentialprotocol.RevokeReason
}

type ReceivedExec struct {
	liveValue
	revision             uint64
	execBindingID        credentialprotocol.SafeID
	privateBindingLength uint32
	privateBindingSHA256 [32]byte
	plan                 ExecPlanCapability
}

type ReceivedExecPrivate struct {
	liveValue
	revision             uint64
	privateBindingLength uint32
	privateBindingSHA256 [32]byte
}

type ReceivedExecStream struct {
	liveValue
	revision      uint64
	streamKind    credentialprotocol.HelperExecStreamKind
	flags         credentialprotocol.HelperExecStreamFlags
	offset        uint64
	payloadLength uint32
	payloadSHA256 [32]byte
}

type ReceivedExecCredit struct {
	liveValue
	revision   uint64
	streamKind credentialprotocol.HelperExecStreamKind
	nextOffset uint64
}

type ReceivedCloseNotify struct {
	liveValue
	reason credentialprotocol.CloseReason
}

func (ReceivedBootstrap) receivedPacketArm()     {}
func (ReceivedAgentHello) receivedPacketArm()    {}
func (ReceivedPrepareBegin) receivedPacketArm()  {}
func (ReceivedPrepareFile) receivedPacketArm()   {}
func (ReceivedPrepareCommit) receivedPacketArm() {}
func (ReceivedRenew) receivedPacketArm()         {}
func (ReceivedRevoke) receivedPacketArm()        {}
func (ReceivedExec) receivedPacketArm()          {}
func (ReceivedExecPrivate) receivedPacketArm()   {}
func (ReceivedExecStream) receivedPacketArm()    {}
func (ReceivedExecCredit) receivedPacketArm()    {}
func (ReceivedCloseNotify) receivedPacketArm()   {}
