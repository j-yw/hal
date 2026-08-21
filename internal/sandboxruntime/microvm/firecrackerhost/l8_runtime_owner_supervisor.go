package firecrackerhost

import (
	"context"
	"errors"
	"sync"
	"time"
)

const (
	l8RuntimeOwnerProtocolMagic           = "HL8OWNR1"
	l8RuntimeOwnerProtocolVersion  uint16 = 1
	l8RuntimeOwnerPacketHeaderSize        = 24
	l8RuntimeOwnerPacketLimit             = 512
	l8RuntimeOwnerHandshakeTimeout        = 5 * time.Second

	l8RuntimeOwnerOpcodeBootstrapStart     uint16 = 1
	l8RuntimeOwnerOpcodeBootstrapPublished uint16 = 2
	l8RuntimeOwnerOpcodeChildArmed         uint16 = 3
	l8RuntimeOwnerOpcodeChildRelease       uint16 = 4
	l8RuntimeOwnerOpcodeHandshake          uint16 = 5
	l8RuntimeOwnerOpcodeAbortStart         uint16 = 6
	l8RuntimeOwnerOpcodeInspect            uint16 = 7
	l8RuntimeOwnerOpcodeStopReap           uint16 = 8
	l8RuntimeOwnerOpcodeAcquireNamespaces  uint16 = 9
	l8RuntimeOwnerOpcodeFinalize           uint16 = 10
	l8RuntimeOwnerOpcodeCommit             uint16 = 11
	l8RuntimeOwnerOpcodeClose              uint16 = 12

	l8RuntimeOwnerStatusOK           uint16 = 0
	l8RuntimeOwnerStatusRejected     uint16 = 1
	l8RuntimeOwnerStatusInvalidState uint16 = 2
	l8RuntimeOwnerStatusUncertain    uint16 = 3
	l8RuntimeOwnerStatusUnsupported  uint16 = 4
)

var errL8RuntimeOwnerProtocol = errors.New("firecracker runtime owner protocol rejected")

type l8RuntimeOwnerPacketHeaderV1 struct {
	Magic      [8]byte
	Version    uint16
	Opcode     uint16
	Status     uint16
	BodyLength uint16
	Sequence   uint64
}

type l8RuntimeOwnerPacketV1 struct {
	Opcode   uint16
	Status   uint16
	Sequence uint64
	Body     []byte
}

type l8RuntimeOwnerHandshakeV1 struct {
	SupervisorGeneration string
	RuntimeGeneration    string
	RecordRevision       uint64
	ReconnectSecret      string
}

type l8RuntimeOwnerHandshakeAckV1 struct {
	ControllerSessionGeneration string
	RecordRevision              uint64
}

type l8RuntimeOwnerResponseV1 struct {
	State              byte
	AbsenceKind        byte
	RecordRevision     uint64
	ObservedAtUnixNano int64
}

type l8RuntimeOwnerAbsenceObservation struct {
	Kind       byte
	Revision   uint64
	ObservedAt time.Time
}

type l8RuntimeOwnerContainmentOps struct {
	RecordStopping  func() error
	Terminate       func() error
	Wait            func(context.Context) (bool, error)
	Kill            func() error
	RecordAbsent    func(l8RuntimeOwnerAbsenceObservation) error
	RecordUncertain func() error
	Now             func() time.Time
}

type l8RuntimeOwnerContainmentController struct {
	mu          sync.Mutex
	completed   bool
	observation l8RuntimeOwnerAbsenceObservation
	result      error
}

type l8RuntimeOwnerReplacementOps struct {
	CurrentBootID      func() (string, error)
	InspectSupervisor  func(uint32) (l8RuntimeOwnerProcessObservation, bool, error)
	InspectChild       func(uint32) (l8RuntimeOwnerProcessObservation, bool, error)
	SignalKill         func(l8RuntimeOwnerProcessObservation) error
	WaitTerminal       func(context.Context, l8RuntimeOwnerProcessObservation) error
	ProcessAbsent      func(uint32) (bool, error)
	AcquisitionBarrier func() error
	RecordAbsent       func(l8RuntimeOwnerAbsenceObservation) error
	RecordUncertain    func() error
	Now                func() time.Time
}

func encodeL8RuntimeOwnerPacket(l8RuntimeOwnerPacketV1) ([]byte, error) {
	return nil, errL8RuntimeOwnerProtocol
}

func decodeL8RuntimeOwnerPacket([]byte) (l8RuntimeOwnerPacketV1, error) {
	return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerProtocol
}

func encodeL8RuntimeOwnerHandshake(l8RuntimeOwnerHandshakeV1) ([]byte, error) {
	return nil, errL8RuntimeOwnerProtocol
}

func decodeL8RuntimeOwnerHandshake([]byte) (l8RuntimeOwnerHandshakeV1, error) {
	return l8RuntimeOwnerHandshakeV1{}, errL8RuntimeOwnerProtocol
}

func encodeL8RuntimeOwnerHandshakeAck(l8RuntimeOwnerHandshakeAckV1) ([]byte, error) {
	return nil, errL8RuntimeOwnerProtocol
}

func decodeL8RuntimeOwnerHandshakeAck([]byte) (l8RuntimeOwnerHandshakeAckV1, error) {
	return l8RuntimeOwnerHandshakeAckV1{}, errL8RuntimeOwnerProtocol
}

func encodeL8RuntimeOwnerResponse(l8RuntimeOwnerResponseV1) ([]byte, error) {
	return nil, errL8RuntimeOwnerProtocol
}

func decodeL8RuntimeOwnerResponse([]byte) (l8RuntimeOwnerResponseV1, error) {
	return l8RuntimeOwnerResponseV1{}, errL8RuntimeOwnerProtocol
}

func validL8RuntimeOwnerTransition(firecrackerRuntimeOwnerRecordV1, firecrackerRuntimeOwnerRecordV1) bool {
	return false
}

func reconcileL8RuntimeOwnerCommitUncertain(firecrackerRuntimeOwnerRecordV1, firecrackerRuntimeOwnerRecordV1, firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, bool, error) {
	return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
}

func containL8RuntimeOwnerChild(l8RuntimeOwnerContainmentOps) (l8RuntimeOwnerAbsenceObservation, error) {
	return l8RuntimeOwnerAbsenceObservation{}, errL8RuntimeOwnerInvalid
}

func (controller *l8RuntimeOwnerContainmentController) Stop(ops l8RuntimeOwnerContainmentOps) (l8RuntimeOwnerAbsenceObservation, error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.completed {
		return controller.observation, controller.result
	}
	controller.observation, controller.result = containL8RuntimeOwnerChild(ops)
	controller.completed = true
	return controller.observation, controller.result
}

func containL8RuntimeOwnerReplacement(firecrackerRuntimeOwnerRecordV1, l8RuntimeOwnerReplacementOps) (l8RuntimeOwnerAbsenceObservation, error) {
	return l8RuntimeOwnerAbsenceObservation{}, errL8RuntimeOwnerInvalid
}
