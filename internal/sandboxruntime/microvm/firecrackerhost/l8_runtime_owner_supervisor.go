package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
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

	l8RuntimeOwnerOpcodeReject             uint16 = 0
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

	l8RuntimeOwnerTokenSize                      = 43
	l8RuntimeOwnerHandshakeGenerationMin         = 1
	l8RuntimeOwnerHandshakeGenerationMax         = 128
	l8RuntimeOwnerContainmentBudget              = 30 * time.Second
	l8RuntimeOwnerContainmentTermWaitBudget      = 5 * time.Second
	l8RuntimeOwnerAbsenceKindNone           byte = 0
	l8RuntimeOwnerAbsenceKindWait           byte = 1
	l8RuntimeOwnerAbsenceKindProc           byte = 2
	l8RuntimeOwnerStateStarting             byte = 1
	l8RuntimeOwnerStateRunning              byte = 2
	l8RuntimeOwnerStateStopping             byte = 3
	l8RuntimeOwnerStateAbsent               byte = 4
	l8RuntimeOwnerStateFinalizing           byte = 5
	l8RuntimeOwnerStateFinalized            byte = 6
	l8RuntimeOwnerStateUncertain            byte = 7
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

type l8RuntimeOwnerControllerRequestV1 struct {
	ControllerSessionGeneration string
}

type l8RuntimeOwnerFinalizeRequestV1 struct {
	ControllerSessionGeneration string
	AbsenceRevision             uint64
	ObservedAtUnixNano          int64
}

type l8RuntimeOwnerFinalizeAckV1 struct {
	CommitID          string
	FinalizedRevision uint64
}

type l8RuntimeOwnerCommitRequestV1 struct {
	ControllerSessionGeneration string
	CommitID                    string
	FinalizedRevision           uint64
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

type l8RuntimeOwnerRecordStore interface {
	Load(context.Context) (firecrackerRuntimeOwnerRecordV1, error)
	CreateGenesis(context.Context, firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error)
	Transition(context.Context, uint64, firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error)
	RetireStartingZero(context.Context, uint64) error
	RetireFinalized(context.Context, uint64, string) error
}

type l8RuntimeOwnerTransactionOps struct {
	Lock           func(context.Context) error
	Unlock         func() error
	Read           func() (firecrackerRuntimeOwnerRecordV1, bool, error)
	WriteAndRename func(firecrackerRuntimeOwnerRecordV1) error
	SyncDirectory  func() error
}

type l8RuntimeOwnerControlResult struct {
	Packet l8RuntimeOwnerPacketV1
	Files  []int
	Exit   bool
}

type l8RuntimeOwnerStartedChild struct {
	Observation l8RuntimeOwnerProcessObservation
	Release     func() error
	Abort       func() error
}

type l8RuntimeOwnerSupervisorOptions struct {
	Store               l8RuntimeOwnerRecordStore
	GenesisRecord       firecrackerRuntimeOwnerRecordV1
	ExpectedUID         uint32
	RandomToken         func() (string, error)
	StartChild          func() (l8RuntimeOwnerStartedChild, error)
	ContainChild        func() (l8RuntimeOwnerAbsenceObservation, error)
	ReinspectAbsence    func() (l8RuntimeOwnerAbsenceObservation, error)
	DuplicateNamespaces func() ([]int, error)
	CloseNamespaces     func() error
	AbortStartingZero   func() error
	CommitKey           []byte
}

type l8RuntimeOwnerSupervisor struct {
	mu                sync.Mutex
	opts              l8RuntimeOwnerSupervisorOptions
	sessionGeneration string
	lastSequence      uint64
	lastOpcode        uint16
	lastPacket        l8RuntimeOwnerPacketV1
	lastRequestBody   []byte
	hasLast           bool
}

type l8RuntimeOwnerContainmentOps struct {
	RecordStopping  func() (uint64, error)
	Terminate       func() error
	Wait            func(context.Context) (bool, error)
	Kill            func() error
	RecordAbsent    func(l8RuntimeOwnerAbsenceObservation) (uint64, error)
	RecordUncertain func() (uint64, error)
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
	RecordAbsent       func(l8RuntimeOwnerAbsenceObservation) (uint64, error)
	RecordUncertain    func() (uint64, error)
	Now                func() time.Time
}

func encodeL8RuntimeOwnerPacket(packet l8RuntimeOwnerPacketV1) ([]byte, error) {
	if len(packet.Body) > l8RuntimeOwnerPacketLimit-l8RuntimeOwnerPacketHeaderSize {
		return nil, errL8RuntimeOwnerProtocol
	}
	if validateL8RuntimeOwnerPacketShape(packet) != nil {
		return nil, errL8RuntimeOwnerProtocol
	}
	wire := make([]byte, l8RuntimeOwnerPacketHeaderSize+len(packet.Body))
	copy(wire[:8], l8RuntimeOwnerProtocolMagic)
	binary.BigEndian.PutUint16(wire[8:10], l8RuntimeOwnerProtocolVersion)
	binary.BigEndian.PutUint16(wire[10:12], packet.Opcode)
	binary.BigEndian.PutUint16(wire[12:14], packet.Status)
	binary.BigEndian.PutUint16(wire[14:16], uint16(len(packet.Body)))
	binary.BigEndian.PutUint64(wire[16:24], packet.Sequence)
	copy(wire[l8RuntimeOwnerPacketHeaderSize:], packet.Body)
	return wire, nil
}

func decodeL8RuntimeOwnerPacket(wire []byte) (l8RuntimeOwnerPacketV1, error) {
	if len(wire) < l8RuntimeOwnerPacketHeaderSize || len(wire) > l8RuntimeOwnerPacketLimit {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerProtocol
	}
	if string(wire[:8]) != l8RuntimeOwnerProtocolMagic {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerProtocol
	}
	version := binary.BigEndian.Uint16(wire[8:10])
	opcode := binary.BigEndian.Uint16(wire[10:12])
	status := binary.BigEndian.Uint16(wire[12:14])
	bodyLength := binary.BigEndian.Uint16(wire[14:16])
	sequence := binary.BigEndian.Uint64(wire[16:24])
	if version != l8RuntimeOwnerProtocolVersion || int(bodyLength) != len(wire)-l8RuntimeOwnerPacketHeaderSize {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerProtocol
	}
	packet := l8RuntimeOwnerPacketV1{
		Opcode:   opcode,
		Status:   status,
		Sequence: sequence,
		Body:     append([]byte(nil), wire[l8RuntimeOwnerPacketHeaderSize:]...),
	}
	if validateL8RuntimeOwnerPacketShape(packet) != nil {
		return l8RuntimeOwnerPacketV1{}, errL8RuntimeOwnerProtocol
	}
	return packet, nil
}

func encodeL8RuntimeOwnerHandshake(value l8RuntimeOwnerHandshakeV1) ([]byte, error) {
	if !validL8RuntimeOwnerToken(value.SupervisorGeneration) || !validL8RuntimeOwnerToken(value.ReconnectSecret) ||
		!validL8RuntimeOwnerSafeID(value.RuntimeGeneration) {
		return nil, errL8RuntimeOwnerProtocol
	}
	generation := []byte(value.RuntimeGeneration)
	body := make([]byte, l8RuntimeOwnerTokenSize+2+len(generation)+8+l8RuntimeOwnerTokenSize)
	copy(body[:l8RuntimeOwnerTokenSize], value.SupervisorGeneration)
	binary.BigEndian.PutUint16(body[l8RuntimeOwnerTokenSize:l8RuntimeOwnerTokenSize+2], uint16(len(generation)))
	copy(body[l8RuntimeOwnerTokenSize+2:l8RuntimeOwnerTokenSize+2+len(generation)], generation)
	binary.BigEndian.PutUint64(body[l8RuntimeOwnerTokenSize+2+len(generation):l8RuntimeOwnerTokenSize+2+len(generation)+8], value.RecordRevision)
	copy(body[l8RuntimeOwnerTokenSize+2+len(generation)+8:], value.ReconnectSecret)
	return body, nil
}

func decodeL8RuntimeOwnerHandshake(body []byte) (l8RuntimeOwnerHandshakeV1, error) {
	if len(body) < 97 || len(body) > 224 {
		return l8RuntimeOwnerHandshakeV1{}, errL8RuntimeOwnerProtocol
	}
	generationLength := int(binary.BigEndian.Uint16(body[l8RuntimeOwnerTokenSize : l8RuntimeOwnerTokenSize+2]))
	if generationLength < l8RuntimeOwnerHandshakeGenerationMin || generationLength > l8RuntimeOwnerHandshakeGenerationMax ||
		len(body) != l8RuntimeOwnerTokenSize+2+generationLength+8+l8RuntimeOwnerTokenSize {
		return l8RuntimeOwnerHandshakeV1{}, errL8RuntimeOwnerProtocol
	}
	value := l8RuntimeOwnerHandshakeV1{
		SupervisorGeneration: string(body[:l8RuntimeOwnerTokenSize]),
		RuntimeGeneration:    string(body[l8RuntimeOwnerTokenSize+2 : l8RuntimeOwnerTokenSize+2+generationLength]),
		RecordRevision:       binary.BigEndian.Uint64(body[l8RuntimeOwnerTokenSize+2+generationLength : l8RuntimeOwnerTokenSize+2+generationLength+8]),
		ReconnectSecret:      string(body[l8RuntimeOwnerTokenSize+2+generationLength+8:]),
	}
	if !validL8RuntimeOwnerToken(value.SupervisorGeneration) || !validL8RuntimeOwnerToken(value.ReconnectSecret) ||
		!validL8RuntimeOwnerSafeID(value.RuntimeGeneration) {
		return l8RuntimeOwnerHandshakeV1{}, errL8RuntimeOwnerProtocol
	}
	return value, nil
}

func encodeL8RuntimeOwnerHandshakeAck(value l8RuntimeOwnerHandshakeAckV1) ([]byte, error) {
	if !validL8RuntimeOwnerToken(value.ControllerSessionGeneration) {
		return nil, errL8RuntimeOwnerProtocol
	}
	body := make([]byte, l8RuntimeOwnerTokenSize+8)
	copy(body[:l8RuntimeOwnerTokenSize], value.ControllerSessionGeneration)
	binary.BigEndian.PutUint64(body[l8RuntimeOwnerTokenSize:], value.RecordRevision)
	return body, nil
}

func decodeL8RuntimeOwnerHandshakeAck(body []byte) (l8RuntimeOwnerHandshakeAckV1, error) {
	if len(body) != l8RuntimeOwnerTokenSize+8 {
		return l8RuntimeOwnerHandshakeAckV1{}, errL8RuntimeOwnerProtocol
	}
	value := l8RuntimeOwnerHandshakeAckV1{
		ControllerSessionGeneration: string(body[:l8RuntimeOwnerTokenSize]),
		RecordRevision:              binary.BigEndian.Uint64(body[l8RuntimeOwnerTokenSize:]),
	}
	if !validL8RuntimeOwnerToken(value.ControllerSessionGeneration) {
		return l8RuntimeOwnerHandshakeAckV1{}, errL8RuntimeOwnerProtocol
	}
	return value, nil
}

func encodeL8RuntimeOwnerResponse(value l8RuntimeOwnerResponseV1) ([]byte, error) {
	if value.State == 0 && value.AbsenceKind == 0 && value.RecordRevision == 0 && value.ObservedAtUnixNano == 0 {
		// zero value is still a legal 24-byte encoding
	}
	body := make([]byte, 24)
	body[0] = value.State
	body[1] = value.AbsenceKind
	binary.BigEndian.PutUint64(body[8:16], value.RecordRevision)
	binary.BigEndian.PutUint64(body[16:24], uint64(value.ObservedAtUnixNano))
	return body, nil
}

func decodeL8RuntimeOwnerResponse(body []byte) (l8RuntimeOwnerResponseV1, error) {
	if len(body) != 24 {
		return l8RuntimeOwnerResponseV1{}, errL8RuntimeOwnerProtocol
	}
	for _, reserved := range body[2:8] {
		if reserved != 0 {
			return l8RuntimeOwnerResponseV1{}, errL8RuntimeOwnerProtocol
		}
	}
	return l8RuntimeOwnerResponseV1{
		State:              body[0],
		AbsenceKind:        body[1],
		RecordRevision:     binary.BigEndian.Uint64(body[8:16]),
		ObservedAtUnixNano: int64(binary.BigEndian.Uint64(body[16:24])),
	}, nil
}

func encodeL8RuntimeOwnerControllerRequest(value l8RuntimeOwnerControllerRequestV1) ([]byte, error) {
	if !validL8RuntimeOwnerToken(value.ControllerSessionGeneration) {
		return nil, errL8RuntimeOwnerProtocol
	}
	return []byte(value.ControllerSessionGeneration), nil
}

func decodeL8RuntimeOwnerControllerRequest(body []byte) (l8RuntimeOwnerControllerRequestV1, error) {
	if len(body) != l8RuntimeOwnerTokenSize || !validL8RuntimeOwnerToken(string(body)) {
		return l8RuntimeOwnerControllerRequestV1{}, errL8RuntimeOwnerProtocol
	}
	return l8RuntimeOwnerControllerRequestV1{ControllerSessionGeneration: string(body)}, nil
}

func encodeL8RuntimeOwnerFinalizeRequest(value l8RuntimeOwnerFinalizeRequestV1) ([]byte, error) {
	if !validL8RuntimeOwnerToken(value.ControllerSessionGeneration) {
		return nil, errL8RuntimeOwnerProtocol
	}
	body := make([]byte, l8RuntimeOwnerTokenSize+16)
	copy(body[:l8RuntimeOwnerTokenSize], value.ControllerSessionGeneration)
	binary.BigEndian.PutUint64(body[l8RuntimeOwnerTokenSize:l8RuntimeOwnerTokenSize+8], value.AbsenceRevision)
	binary.BigEndian.PutUint64(body[l8RuntimeOwnerTokenSize+8:], uint64(value.ObservedAtUnixNano))
	return body, nil
}

func decodeL8RuntimeOwnerFinalizeRequest(body []byte) (l8RuntimeOwnerFinalizeRequestV1, error) {
	if len(body) != l8RuntimeOwnerTokenSize+16 {
		return l8RuntimeOwnerFinalizeRequestV1{}, errL8RuntimeOwnerProtocol
	}
	value := l8RuntimeOwnerFinalizeRequestV1{
		ControllerSessionGeneration: string(body[:l8RuntimeOwnerTokenSize]),
		AbsenceRevision:             binary.BigEndian.Uint64(body[l8RuntimeOwnerTokenSize : l8RuntimeOwnerTokenSize+8]),
		ObservedAtUnixNano:          int64(binary.BigEndian.Uint64(body[l8RuntimeOwnerTokenSize+8:])),
	}
	if !validL8RuntimeOwnerToken(value.ControllerSessionGeneration) {
		return l8RuntimeOwnerFinalizeRequestV1{}, errL8RuntimeOwnerProtocol
	}
	return value, nil
}

func encodeL8RuntimeOwnerFinalizeAck(value l8RuntimeOwnerFinalizeAckV1) ([]byte, error) {
	commitID, err := l8RuntimeOwnerExportedStringField(value, "CommitID")
	if err != nil || !validL8RuntimeOwnerToken(commitID) {
		return nil, errL8RuntimeOwnerProtocol
	}
	body := make([]byte, l8RuntimeOwnerTokenSize+8)
	copy(body[:l8RuntimeOwnerTokenSize], commitID)
	binary.BigEndian.PutUint64(body[l8RuntimeOwnerTokenSize:], value.FinalizedRevision)
	return body, nil
}

func decodeL8RuntimeOwnerFinalizeAck(body []byte) (l8RuntimeOwnerFinalizeAckV1, error) {
	if len(body) != l8RuntimeOwnerTokenSize+8 {
		return l8RuntimeOwnerFinalizeAckV1{}, errL8RuntimeOwnerProtocol
	}
	commitID := string(body[:l8RuntimeOwnerTokenSize])
	if !validL8RuntimeOwnerToken(commitID) {
		return l8RuntimeOwnerFinalizeAckV1{}, errL8RuntimeOwnerProtocol
	}
	return l8RuntimeOwnerFinalizeAckV1{
		CommitID:          commitID,
		FinalizedRevision: binary.BigEndian.Uint64(body[l8RuntimeOwnerTokenSize:]),
	}, nil
}

func encodeL8RuntimeOwnerCommitRequest(value l8RuntimeOwnerCommitRequestV1) ([]byte, error) {
	commitID, err := l8RuntimeOwnerExportedStringField(value, "CommitID")
	if err != nil || !validL8RuntimeOwnerToken(value.ControllerSessionGeneration) || !validL8RuntimeOwnerToken(commitID) {
		return nil, errL8RuntimeOwnerProtocol
	}
	body := make([]byte, l8RuntimeOwnerTokenSize+l8RuntimeOwnerTokenSize+8)
	copy(body[:l8RuntimeOwnerTokenSize], value.ControllerSessionGeneration)
	copy(body[l8RuntimeOwnerTokenSize:l8RuntimeOwnerTokenSize*2], commitID)
	binary.BigEndian.PutUint64(body[l8RuntimeOwnerTokenSize*2:], value.FinalizedRevision)
	return body, nil
}

func decodeL8RuntimeOwnerCommitRequest(body []byte) (l8RuntimeOwnerCommitRequestV1, error) {
	if len(body) != l8RuntimeOwnerTokenSize+l8RuntimeOwnerTokenSize+8 {
		return l8RuntimeOwnerCommitRequestV1{}, errL8RuntimeOwnerProtocol
	}
	session := string(body[:l8RuntimeOwnerTokenSize])
	commitID := string(body[l8RuntimeOwnerTokenSize : l8RuntimeOwnerTokenSize*2])
	if !validL8RuntimeOwnerToken(session) || !validL8RuntimeOwnerToken(commitID) {
		return l8RuntimeOwnerCommitRequestV1{}, errL8RuntimeOwnerProtocol
	}
	return l8RuntimeOwnerCommitRequestV1{
		ControllerSessionGeneration: session,
		CommitID:                    commitID,
		FinalizedRevision:           binary.BigEndian.Uint64(body[l8RuntimeOwnerTokenSize*2:]),
	}, nil
}

func l8RuntimeOwnerExportedStringField(value any, name string) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", errL8RuntimeOwnerProtocol
	}
	var object map[string]any
	if json.Unmarshal(payload, &object) != nil {
		return "", errL8RuntimeOwnerProtocol
	}
	field, _ := object[name].(string)
	return field, nil
}

func validateL8RuntimeOwnerPacketRole(packet l8RuntimeOwnerPacketV1, response bool, rights int) error {
	if validateL8RuntimeOwnerPacketShapeForRole(packet, response) != nil {
		return errL8RuntimeOwnerProtocol
	}
	wantRights := 0
	if !response && packet.Opcode == l8RuntimeOwnerOpcodeBootstrapStart {
		wantRights = 2
	}
	if response && packet.Status == l8RuntimeOwnerStatusOK && packet.Opcode == l8RuntimeOwnerOpcodeAcquireNamespaces {
		wantRights = 2
	}
	if rights != wantRights {
		return errL8RuntimeOwnerProtocol
	}
	return nil
}

func validateL8RuntimeOwnerPacketShape(packet l8RuntimeOwnerPacketV1) error {
	if validateL8RuntimeOwnerPacketShapeForRole(packet, false) == nil || validateL8RuntimeOwnerPacketShapeForRole(packet, true) == nil {
		return nil
	}
	return errL8RuntimeOwnerProtocol
}

func validateL8RuntimeOwnerPacketShapeForRole(packet l8RuntimeOwnerPacketV1, response bool) error {
	bodyLen := len(packet.Body)
	if packet.Opcode == l8RuntimeOwnerOpcodeReject {
		if !response || packet.Status != l8RuntimeOwnerStatusRejected || packet.Sequence != 0 || bodyLen != 0 {
			return errL8RuntimeOwnerProtocol
		}
		return nil
	}
	if packet.Opcode > l8RuntimeOwnerOpcodeClose {
		return errL8RuntimeOwnerProtocol
	}
	if !response {
		if packet.Status != l8RuntimeOwnerStatusOK {
			return errL8RuntimeOwnerProtocol
		}
		switch packet.Opcode {
		case l8RuntimeOwnerOpcodeBootstrapStart:
			if packet.Sequence != 0 || bodyLen != 32 {
				return errL8RuntimeOwnerProtocol
			}
		case l8RuntimeOwnerOpcodeChildArmed:
			if packet.Sequence != 0 || bodyLen != 0 {
				return errL8RuntimeOwnerProtocol
			}
		case l8RuntimeOwnerOpcodeHandshake:
			if packet.Sequence != 0 || bodyLen < 97 || bodyLen > 224 {
				return errL8RuntimeOwnerProtocol
			}
		case l8RuntimeOwnerOpcodeAbortStart, l8RuntimeOwnerOpcodeInspect, l8RuntimeOwnerOpcodeStopReap, l8RuntimeOwnerOpcodeAcquireNamespaces, l8RuntimeOwnerOpcodeClose:
			if packet.Sequence < 1 || bodyLen != l8RuntimeOwnerTokenSize {
				return errL8RuntimeOwnerProtocol
			}
		case l8RuntimeOwnerOpcodeFinalize:
			if packet.Sequence < 1 || bodyLen != 59 {
				return errL8RuntimeOwnerProtocol
			}
		case l8RuntimeOwnerOpcodeCommit:
			if packet.Sequence < 1 || bodyLen != 94 {
				return errL8RuntimeOwnerProtocol
			}
		default:
			return errL8RuntimeOwnerProtocol
		}
		return nil
	}
	if packet.Status == l8RuntimeOwnerStatusInvalidState || packet.Status == l8RuntimeOwnerStatusUncertain || packet.Status == l8RuntimeOwnerStatusUnsupported {
		if packet.Sequence < 1 || bodyLen != 0 {
			return errL8RuntimeOwnerProtocol
		}
		switch packet.Opcode {
		case l8RuntimeOwnerOpcodeAbortStart, l8RuntimeOwnerOpcodeInspect, l8RuntimeOwnerOpcodeStopReap, l8RuntimeOwnerOpcodeAcquireNamespaces, l8RuntimeOwnerOpcodeFinalize, l8RuntimeOwnerOpcodeCommit, l8RuntimeOwnerOpcodeClose:
			return nil
		default:
			return errL8RuntimeOwnerProtocol
		}
	}
	if packet.Status != l8RuntimeOwnerStatusOK {
		return errL8RuntimeOwnerProtocol
	}
	switch packet.Opcode {
	case l8RuntimeOwnerOpcodeBootstrapPublished:
		if packet.Sequence != 0 || bodyLen != 8 {
			return errL8RuntimeOwnerProtocol
		}
	case l8RuntimeOwnerOpcodeChildRelease:
		if packet.Sequence != 0 || bodyLen != 0 {
			return errL8RuntimeOwnerProtocol
		}
	case l8RuntimeOwnerOpcodeHandshake:
		if packet.Sequence != 0 || bodyLen != 51 {
			return errL8RuntimeOwnerProtocol
		}
	case l8RuntimeOwnerOpcodeAbortStart, l8RuntimeOwnerOpcodeInspect, l8RuntimeOwnerOpcodeStopReap, l8RuntimeOwnerOpcodeClose, l8RuntimeOwnerOpcodeAcquireNamespaces:
		if packet.Sequence < 1 || bodyLen != 24 {
			return errL8RuntimeOwnerProtocol
		}
	case l8RuntimeOwnerOpcodeFinalize:
		if packet.Sequence < 1 || bodyLen != 51 {
			return errL8RuntimeOwnerProtocol
		}
	case l8RuntimeOwnerOpcodeCommit:
		if packet.Sequence < 1 || bodyLen != 8 {
			return errL8RuntimeOwnerProtocol
		}
	default:
		return errL8RuntimeOwnerProtocol
	}
	return nil
}

func validL8RuntimeOwnerTransition(from, to firecrackerRuntimeOwnerRecordV1) bool {
	if to.Revision != from.Revision+1 {
		return false
	}
	if from.State == "starting" && from.ControllerState == "none" && from.Revision == 0 {
		return to.State == "starting" && to.ControllerState == "none" && to.FirecrackerPID != 0 && to.FirecrackerStartTime != 0
	}
	if from.State == "starting" && from.ControllerState == "none" && from.Revision == 1 {
		if to.State == "running" && to.ControllerState == "unclaimed" {
			return true
		}
		if to.State == "stopping" && to.ControllerState == "none" {
			return true
		}
		return false
	}
	if from.State == to.State && from.State != "starting" {
		if from.ControllerState == "unclaimed" && to.ControllerState == "controlled" {
			return true
		}
		if from.ControllerState == "controlled" && to.ControllerState == "unclaimed" {
			return true
		}
		if from.State == "absent" && from.ControllerState == "controlled" && to.ControllerState == "controlled" {
			return true
		}
	}
	if from.ControllerState == "controlled" && to.ControllerState == "controlled" {
		switch from.State + "->" + to.State {
		case "running->stopping", "running->uncertain", "stopping->absent", "stopping->uncertain",
			"uncertain->absent", "absent->finalizing", "finalizing->finalized":
			return true
		}
	}
	if from.State == "stopping" && from.ControllerState == "none" && to.State == "absent" && to.ControllerState == "none" {
		return true
	}
	return false
}

func reconcileL8RuntimeOwnerCommitUncertain(prior, intended, observed firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, bool, error) {
	if observed == prior {
		return prior, false, nil
	}
	if observed == intended {
		return intended, true, nil
	}
	return firecrackerRuntimeOwnerRecordV1{}, false, errL8RuntimeOwnerInvalid
}

func transitionL8RuntimeOwnerRecordLocked(ctx context.Context, ops l8RuntimeOwnerTransactionOps, expected uint64, intended firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error) {
	if ops.Lock == nil || ops.Unlock == nil || ops.Read == nil || ops.WriteAndRename == nil || ops.SyncDirectory == nil {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	if err := ops.Lock(ctx); err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	unlocked := false
	defer func() {
		if !unlocked {
			_ = ops.Unlock()
		}
	}()
	current, present, err := ops.Read()
	if err != nil || !present || current.Revision != expected {
		_ = ops.Unlock()
		unlocked = true
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	writeErr := ops.WriteAndRename(intended)
	if writeErr == nil {
		if syncErr := ops.SyncDirectory(); syncErr == nil {
			_ = ops.Unlock()
			unlocked = true
			return intended, nil
		}
	}
	reread, present, readErr := ops.Read()
	_ = ops.Unlock()
	unlocked = true
	if readErr != nil || !present {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	got, committed, err := reconcileL8RuntimeOwnerCommitUncertain(current, intended, reread)
	if err != nil || !committed {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	return got, nil
}

func containL8RuntimeOwnerChild(ops l8RuntimeOwnerContainmentOps) (observation l8RuntimeOwnerAbsenceObservation, err error) {
	defer func() {
		if recover() != nil {
			observation = l8RuntimeOwnerAbsenceObservation{}
			err = errL8RuntimeOwnerInvalid
		}
	}()
	fail := func() (l8RuntimeOwnerAbsenceObservation, error) {
		if ops.RecordUncertain != nil {
			_, _ = l8RuntimeOwnerCallUint64(ops.RecordUncertain)
		}
		return l8RuntimeOwnerAbsenceObservation{}, errL8RuntimeOwnerInvalid
	}
	if _, err := l8RuntimeOwnerCallUint64(ops.RecordStopping); err != nil {
		return fail()
	}
	started := time.Now()
	overall := started.Add(l8RuntimeOwnerContainmentBudget)
	_ = l8RuntimeOwnerCall(ops.Terminate)
	firstCtx, cancelFirst := context.WithDeadline(context.Background(), started.Add(l8RuntimeOwnerContainmentTermWaitBudget))
	reaped, waitErr := l8RuntimeOwnerCallWait(ops.Wait, firstCtx)
	cancelFirst()
	if waitErr != nil {
		return fail()
	}
	if !reaped {
		_ = l8RuntimeOwnerCall(ops.Kill)
		finalCtx, cancelFinal := context.WithDeadline(context.Background(), overall)
		reaped, waitErr = l8RuntimeOwnerCallWait(ops.Wait, finalCtx)
		cancelFinal()
		if waitErr != nil {
			return fail()
		}
	}
	if !reaped {
		return fail()
	}
	observedAt := time.Now()
	if ops.Now != nil {
		observedAt = ops.Now()
	}
	candidate := l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindWait, ObservedAt: observedAt}
	revision, recordErr := l8RuntimeOwnerCallRecordAbsent(ops.RecordAbsent, candidate)
	if recordErr != nil {
		return fail()
	}
	candidate.Revision = revision
	return candidate, nil
}

func (controller *l8RuntimeOwnerContainmentController) Stop(ops l8RuntimeOwnerContainmentOps) (l8RuntimeOwnerAbsenceObservation, error) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if controller.completed {
		return controller.observation, controller.result
	}
	controller.observation, controller.result = containL8RuntimeOwnerChild(ops)
	if controller.result == nil {
		controller.completed = true
	}
	return controller.observation, controller.result
}

func containL8RuntimeOwnerReplacement(record firecrackerRuntimeOwnerRecordV1, ops l8RuntimeOwnerReplacementOps) (observation l8RuntimeOwnerAbsenceObservation, err error) {
	defer func() {
		if recover() != nil {
			observation = l8RuntimeOwnerAbsenceObservation{}
			err = errL8RuntimeOwnerInvalid
		}
	}()
	fail := func() (l8RuntimeOwnerAbsenceObservation, error) {
		if ops.RecordUncertain != nil {
			_, _ = l8RuntimeOwnerCallUint64(ops.RecordUncertain)
		}
		return l8RuntimeOwnerAbsenceObservation{}, errL8RuntimeOwnerInvalid
	}
	if ops.CurrentBootID == nil || ops.InspectSupervisor == nil || ops.InspectChild == nil || ops.ProcessAbsent == nil {
		return fail()
	}
	bootID, err := ops.CurrentBootID()
	if err != nil || bootID != record.HostBootID {
		return fail()
	}
	supervisor, supervisorExists, err := ops.InspectSupervisor(record.SupervisorPID)
	if err != nil {
		_ = supervisor.Close()
		return fail()
	}
	if supervisorExists {
		_ = supervisor.Close()
		return fail()
	}
	_ = supervisor.Close()
	child, childExists, err := ops.InspectChild(record.FirecrackerPID)
	if err != nil {
		_ = child.Close()
		return fail()
	}
	if childExists {
		defer child.Close()
		if child.PID != record.FirecrackerPID || child.StartTime != record.FirecrackerStartTime || child.ParentPID != 1 || child.state == 'Z' {
			return fail()
		}
		if ops.SignalKill == nil || l8RuntimeOwnerCall(func() error { return ops.SignalKill(child) }) != nil {
			return fail()
		}
		if ops.WaitTerminal != nil {
			_ = l8RuntimeOwnerCall(func() error { return ops.WaitTerminal(context.Background(), child) })
		}
	} else {
		_ = child.Close()
	}
	firstAbsent, err := ops.ProcessAbsent(record.FirecrackerPID)
	if err != nil || !firstAbsent {
		return fail()
	}
	if ops.AcquisitionBarrier == nil || l8RuntimeOwnerCall(ops.AcquisitionBarrier) != nil {
		return fail()
	}
	secondAbsent, err := ops.ProcessAbsent(record.FirecrackerPID)
	if err != nil || !secondAbsent {
		return fail()
	}
	observedAt := time.Now()
	if ops.Now != nil {
		observedAt = ops.Now()
	}
	candidate := l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindProc, ObservedAt: observedAt}
	revision, recordErr := l8RuntimeOwnerCallRecordAbsent(ops.RecordAbsent, candidate)
	if recordErr != nil {
		return fail()
	}
	candidate.Revision = revision
	return candidate, nil
}

func newL8RuntimeOwnerSupervisor(opts l8RuntimeOwnerSupervisorOptions) (*l8RuntimeOwnerSupervisor, error) {
	if opts.Store == nil || len(opts.CommitKey) != 32 {
		return nil, errL8RuntimeOwnerInvalid
	}
	opts.CommitKey = append([]byte(nil), opts.CommitKey...)
	return &l8RuntimeOwnerSupervisor{opts: opts}, nil
}

func (owner *l8RuntimeOwnerSupervisor) HandleBootstrap(ctx context.Context, uid uint32, received l8RuntimeOwnerReceivedPacketV1) (l8RuntimeOwnerControlResult, error) {
	if owner == nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if uid != owner.opts.ExpectedUID || received.Packet.Opcode != l8RuntimeOwnerOpcodeBootstrapStart || owner.opts.StartChild == nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	if _, err := decodeL8RuntimeOwnerNamespaceCorrelation(received.Packet.Body); err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	if len(received.Files) != 2 {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	if _, err := owner.opts.Store.CreateGenesis(ctx, owner.opts.GenesisRecord); err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	child, err := owner.opts.StartChild()
	if err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	failed := true
	defer func() {
		if failed && child.Abort != nil {
			_ = child.Abort()
		}
	}()
	rev1 := owner.opts.GenesisRecord
	rev1.Revision = 1
	rev1.State = "starting"
	rev1.ControllerState = "none"
	rev1.FirecrackerPID = child.Observation.PID
	rev1.FirecrackerStartTime = child.Observation.StartTime
	if _, err := owner.opts.Store.Transition(ctx, 0, rev1); err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	if child.Release == nil || child.Release() != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	rev2 := rev1
	rev2.Revision = 2
	rev2.State = "running"
	rev2.ControllerState = "unclaimed"
	if _, err := owner.opts.Store.Transition(ctx, 1, rev2); err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	body := make([]byte, 8)
	binary.BigEndian.PutUint64(body, 2)
	failed = false
	return l8RuntimeOwnerControlResult{Packet: l8RuntimeOwnerPacketV1{
		Opcode: l8RuntimeOwnerOpcodeBootstrapPublished,
		Status: l8RuntimeOwnerStatusOK,
		Body:   body,
	}}, nil
}

func (owner *l8RuntimeOwnerSupervisor) AbortStart(ctx context.Context, uid uint32, received l8RuntimeOwnerReceivedPacketV1) (l8RuntimeOwnerControlResult, error) {
	if owner == nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if uid != owner.opts.ExpectedUID || received.Packet.Opcode != l8RuntimeOwnerOpcodeAbortStart {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	record, err := owner.opts.Store.Load(ctx)
	if err != nil || record.State != "starting" {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	if record.Revision == 0 {
		if owner.opts.AbortStartingZero == nil || owner.opts.AbortStartingZero() != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
		}
		if err := owner.opts.Store.RetireStartingZero(ctx, 0); err != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
		}
		return l8RuntimeOwnerControlResult{Exit: true}, nil
	}
	if record.Revision != 1 || owner.opts.ContainChild == nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	stopping := record
	stopping.Revision = 2
	stopping.State = "stopping"
	if _, err := owner.opts.Store.Transition(ctx, 1, stopping); err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	observation, err := owner.opts.ContainChild()
	if err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	absent := stopping
	absent.Revision = 3
	absent.State = "absent"
	absent.AbsenceKind = l8RuntimeOwnerAbsenceKindName(observation.Kind)
	absent.AbsenceRevision = observation.Revision
	if observation.Revision == 0 {
		absent.AbsenceRevision = 3
	}
	absent.AbsenceObservedAtUnixNano = observation.ObservedAt.UnixNano()
	if _, err := owner.opts.Store.Transition(ctx, 2, absent); err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
	}
	return l8RuntimeOwnerControlResult{Exit: true}, nil
}

func (owner *l8RuntimeOwnerSupervisor) AdmitController(ctx context.Context, uid uint32, received l8RuntimeOwnerReceivedPacketV1) (l8RuntimeOwnerControlResult, error) {
	if owner == nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if uid != owner.opts.ExpectedUID || received.Packet.Opcode != l8RuntimeOwnerOpcodeHandshake {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	handshake, err := decodeL8RuntimeOwnerHandshake(received.Packet.Body)
	if err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	record, err := owner.opts.Store.Load(ctx)
	if err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	if handshake.SupervisorGeneration != record.SupervisorGeneration || handshake.RuntimeGeneration != record.RuntimeGeneration ||
		handshake.RecordRevision != record.Revision ||
		subtle.ConstantTimeCompare([]byte(handshake.ReconnectSecret), []byte(record.ReconnectSecret)) != 1 {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	if record.ControllerState != "unclaimed" || owner.opts.RandomToken == nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	session, err := owner.opts.RandomToken()
	if err != nil || !validL8RuntimeOwnerToken(session) {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	secret, err := owner.opts.RandomToken()
	if err != nil || !validL8RuntimeOwnerToken(secret) {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	next := record
	next.Revision = record.Revision + 1
	next.ControllerState = "controlled"
	next.ReconnectSecret = secret
	if err := owner.refreshFinalizingIntent(&next); err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	if _, err := owner.opts.Store.Transition(ctx, record.Revision, next); err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	ack, err := encodeL8RuntimeOwnerHandshakeAck(l8RuntimeOwnerHandshakeAckV1{
		ControllerSessionGeneration: session,
		RecordRevision:              next.Revision,
	})
	if err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	owner.sessionGeneration = session
	owner.hasLast = false
	owner.lastSequence = 0
	owner.lastRequestBody = nil
	return l8RuntimeOwnerControlResult{Packet: l8RuntimeOwnerPacketV1{
		Opcode: l8RuntimeOwnerOpcodeHandshake,
		Status: l8RuntimeOwnerStatusOK,
		Body:   ack,
	}}, nil
}

func (owner *l8RuntimeOwnerSupervisor) HandleController(ctx context.Context, received l8RuntimeOwnerReceivedPacketV1) (l8RuntimeOwnerControlResult, error) {
	if owner == nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.hasLast && received.Packet.Sequence == owner.lastSequence && received.Packet.Opcode == owner.lastOpcode {
		if received.Packet.Status != l8RuntimeOwnerStatusOK || !bytes.Equal(received.Packet.Body, owner.lastRequestBody) {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		result := l8RuntimeOwnerControlResult{Packet: owner.lastPacket}
		if received.Packet.Opcode == l8RuntimeOwnerOpcodeAcquireNamespaces {
			files, err := owner.duplicateNamespaces()
			if err != nil {
				return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
			}
			result.Files = files
		}
		return result, nil
	}
	if owner.hasLast && received.Packet.Sequence != owner.lastSequence+1 {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	if !owner.hasLast && received.Packet.Sequence != 1 {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	session, err := l8RuntimeOwnerControllerSession(received.Packet)
	if err != nil {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	if owner.sessionGeneration != "" && session != owner.sessionGeneration {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	if owner.sessionGeneration == "" {
		owner.sessionGeneration = session
	}
	result, err := owner.dispatchController(ctx, received)
	if err != nil {
		return l8RuntimeOwnerControlResult{}, err
	}
	owner.lastSequence = received.Packet.Sequence
	owner.lastOpcode = received.Packet.Opcode
	owner.lastPacket = result.Packet
	owner.lastRequestBody = append(owner.lastRequestBody[:0], received.Packet.Body...)
	owner.hasLast = true
	return result, nil
}

func (owner *l8RuntimeOwnerSupervisor) ControllerLost(ctx context.Context) error {
	if owner == nil {
		return errL8RuntimeOwnerInvalid
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	record, err := owner.opts.Store.Load(ctx)
	if err != nil || record.ControllerState != "controlled" {
		return errL8RuntimeOwnerInvalid
	}
	if _, err := owner.unclaim(ctx, record); err != nil {
		return err
	}
	owner.sessionGeneration = ""
	owner.hasLast = false
	owner.lastSequence = 0
	owner.lastRequestBody = nil
	return nil
}

func (owner *l8RuntimeOwnerSupervisor) dispatchController(ctx context.Context, received l8RuntimeOwnerReceivedPacketV1) (l8RuntimeOwnerControlResult, error) {
	record, err := owner.opts.Store.Load(ctx)
	if err != nil || record.ControllerState != "controlled" {
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
	switch received.Packet.Opcode {
	case l8RuntimeOwnerOpcodeInspect:
		body, err := encodeL8RuntimeOwnerResponse(l8RuntimeOwnerResponseFromRecord(record, false))
		if err != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		return owner.controllerOK(received.Packet, body, nil, false), nil
	case l8RuntimeOwnerOpcodeStopReap:
		next, err := owner.reinspectAbsence(ctx, record)
		if err != nil {
			return l8RuntimeOwnerControlResult{}, err
		}
		body, err := encodeL8RuntimeOwnerResponse(l8RuntimeOwnerResponseFromRecord(next, true))
		if err != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		return owner.controllerOK(received.Packet, body, nil, false), nil
	case l8RuntimeOwnerOpcodeAcquireNamespaces:
		files, err := owner.duplicateNamespaces()
		if err != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		body, err := encodeL8RuntimeOwnerResponse(l8RuntimeOwnerResponseFromRecord(record, false))
		if err != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		return owner.controllerOK(received.Packet, body, files, false), nil
	case l8RuntimeOwnerOpcodeClose:
		next, err := owner.unclaim(ctx, record)
		if err != nil {
			return l8RuntimeOwnerControlResult{}, err
		}
		body, err := encodeL8RuntimeOwnerResponse(l8RuntimeOwnerResponseFromRecord(next, false))
		if err != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		owner.sessionGeneration = ""
		return owner.controllerOK(received.Packet, body, nil, false), nil
	case l8RuntimeOwnerOpcodeFinalize:
		request, err := decodeL8RuntimeOwnerFinalizeRequest(received.Packet.Body)
		if err != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		ack, err := owner.finalize(ctx, record, request)
		if err != nil {
			return l8RuntimeOwnerControlResult{}, err
		}
		body, err := encodeL8RuntimeOwnerFinalizeAck(ack)
		if err != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		return owner.controllerOK(received.Packet, body, nil, false), nil
	case l8RuntimeOwnerOpcodeCommit:
		request, err := decodeL8RuntimeOwnerCommitRequest(received.Packet.Body)
		if err != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		expected := l8RuntimeOwnerCommitRequestV1{
			ControllerSessionGeneration: owner.sessionGeneration,
			CommitID:                    record.FinalizedCommitID,
			FinalizedRevision:           record.FinalizeTargetRevision,
		}
		if record.State != "finalized" || request != expected {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
		}
		if err := owner.opts.Store.RetireFinalized(ctx, record.Revision, record.FinalizedCommitID); err != nil {
			return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerInvalid
		}
		body := make([]byte, 8)
		binary.BigEndian.PutUint64(body, record.FinalizeTargetRevision)
		return owner.controllerOK(received.Packet, body, nil, true), nil
	case l8RuntimeOwnerOpcodeAbortStart:
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	default:
		return l8RuntimeOwnerControlResult{}, errL8RuntimeOwnerProtocol
	}
}

func (owner *l8RuntimeOwnerSupervisor) controllerOK(request l8RuntimeOwnerPacketV1, body []byte, files []int, exit bool) l8RuntimeOwnerControlResult {
	return l8RuntimeOwnerControlResult{
		Packet: l8RuntimeOwnerPacketV1{
			Opcode:   request.Opcode,
			Status:   l8RuntimeOwnerStatusOK,
			Sequence: request.Sequence,
			Body:     body,
		},
		Files: files,
		Exit:  exit,
	}
}

func (owner *l8RuntimeOwnerSupervisor) duplicateNamespaces() ([]int, error) {
	if owner.opts.DuplicateNamespaces == nil {
		return nil, errL8RuntimeOwnerProtocol
	}
	files, err := owner.opts.DuplicateNamespaces()
	if err != nil || len(files) != 2 {
		return nil, errL8RuntimeOwnerProtocol
	}
	return append([]int(nil), files...), nil
}

func (owner *l8RuntimeOwnerSupervisor) unclaim(ctx context.Context, record firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error) {
	next := record
	next.Revision = record.Revision + 1
	next.ControllerState = "unclaimed"
	if owner.opts.RandomToken != nil {
		secret, err := owner.opts.RandomToken()
		if err != nil || !validL8RuntimeOwnerToken(secret) {
			return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
		}
		next.ReconnectSecret = secret
	}
	if err := owner.refreshFinalizingIntent(&next); err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	updated, err := owner.opts.Store.Transition(ctx, record.Revision, next)
	if err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	return updated, nil
}

func (owner *l8RuntimeOwnerSupervisor) reinspectAbsence(ctx context.Context, record firecrackerRuntimeOwnerRecordV1) (firecrackerRuntimeOwnerRecordV1, error) {
	var observation l8RuntimeOwnerAbsenceObservation
	var err error
	prior := record
	switch record.State {
	case "running":
		if owner.opts.ContainChild == nil {
			return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
		}
		stopping := record
		stopping.Revision++
		stopping.State = "stopping"
		stopping.AbsenceKind = ""
		stopping.AbsenceRevision = 0
		stopping.AbsenceObservedAtUnixNano = 0
		prior, err = owner.opts.Store.Transition(ctx, record.Revision, stopping)
		if err != nil {
			return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
		}
		observation, err = owner.opts.ContainChild()
	case "stopping", "uncertain":
		if owner.opts.ContainChild == nil {
			return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
		}
		observation, err = owner.opts.ContainChild()
	case "absent":
		if owner.opts.ReinspectAbsence == nil {
			return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
		}
		observation, err = owner.opts.ReinspectAbsence()
	default:
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	if err != nil {
		if prior.State == "stopping" {
			uncertain := prior
			uncertain.Revision++
			uncertain.State = "uncertain"
			uncertain.AbsenceKind = ""
			uncertain.AbsenceRevision = 0
			uncertain.AbsenceObservedAtUnixNano = 0
			_, _ = owner.opts.Store.Transition(ctx, prior.Revision, uncertain)
		}
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	next := prior
	next.Revision = prior.Revision + 1
	next.State = "absent"
	next.AbsenceKind = l8RuntimeOwnerAbsenceKindName(observation.Kind)
	next.AbsenceRevision = next.Revision
	next.AbsenceObservedAtUnixNano = observation.ObservedAt.UnixNano()
	updated, err := owner.opts.Store.Transition(ctx, prior.Revision, next)
	if err != nil {
		return firecrackerRuntimeOwnerRecordV1{}, errL8RuntimeOwnerInvalid
	}
	return updated, nil
}

func (owner *l8RuntimeOwnerSupervisor) finalize(ctx context.Context, record firecrackerRuntimeOwnerRecordV1, request l8RuntimeOwnerFinalizeRequestV1) (l8RuntimeOwnerFinalizeAckV1, error) {
	if (record.State != "absent" && record.State != "finalizing" && record.State != "finalized") ||
		request.AbsenceRevision != record.AbsenceRevision || request.ObservedAtUnixNano != record.AbsenceObservedAtUnixNano {
		return l8RuntimeOwnerFinalizeAckV1{}, errL8RuntimeOwnerInvalid
	}
	digestBytes, err := hex.DecodeString(record.SeedCorrelationDigest)
	if err != nil || len(digestBytes) != 32 {
		return l8RuntimeOwnerFinalizeAckV1{}, errL8RuntimeOwnerInvalid
	}
	var seedDigest [32]byte
	copy(seedDigest[:], digestBytes)
	if record.State == "finalized" {
		expected, err := l8RuntimeOwnerCommitID(owner.opts.CommitKey, seedDigest, record.FinalizeTargetRevision)
		if err != nil || subtle.ConstantTimeCompare([]byte(expected), []byte(record.FinalizedCommitID)) != 1 {
			return l8RuntimeOwnerFinalizeAckV1{}, errL8RuntimeOwnerInvalid
		}
		return l8RuntimeOwnerFinalizeAckV1{CommitID: record.FinalizedCommitID, FinalizedRevision: record.FinalizeTargetRevision}, nil
	}

	finalizing := record
	if record.State == "absent" {
		if record.Revision > ^uint64(0)-2 {
			return l8RuntimeOwnerFinalizeAckV1{}, errL8RuntimeOwnerInvalid
		}
		finalizing.Revision = record.Revision + 1
		finalizing.State = "finalizing"
		finalizing.FinalizeTargetRevision = record.Revision + 2
		finalizing.FinalizedCommitID, err = l8RuntimeOwnerCommitID(owner.opts.CommitKey, seedDigest, finalizing.FinalizeTargetRevision)
		if err != nil {
			return l8RuntimeOwnerFinalizeAckV1{}, errL8RuntimeOwnerInvalid
		}
		if _, err := owner.opts.Store.Transition(ctx, record.Revision, finalizing); err != nil {
			return l8RuntimeOwnerFinalizeAckV1{}, errL8RuntimeOwnerInvalid
		}
	} else {
		expected, err := l8RuntimeOwnerCommitID(owner.opts.CommitKey, seedDigest, record.FinalizeTargetRevision)
		if err != nil || record.Revision == ^uint64(0) || record.FinalizeTargetRevision != record.Revision+1 ||
			subtle.ConstantTimeCompare([]byte(expected), []byte(record.FinalizedCommitID)) != 1 {
			return l8RuntimeOwnerFinalizeAckV1{}, errL8RuntimeOwnerInvalid
		}
	}
	if owner.opts.CloseNamespaces == nil || owner.opts.CloseNamespaces() != nil {
		return l8RuntimeOwnerFinalizeAckV1{}, errL8RuntimeOwnerInvalid
	}
	finalized := finalizing
	finalized.Revision = finalizing.FinalizeTargetRevision
	finalized.State = "finalized"
	if _, err := owner.opts.Store.Transition(ctx, finalizing.Revision, finalized); err != nil {
		return l8RuntimeOwnerFinalizeAckV1{}, errL8RuntimeOwnerInvalid
	}
	return l8RuntimeOwnerFinalizeAckV1{CommitID: finalized.FinalizedCommitID, FinalizedRevision: finalized.FinalizeTargetRevision}, nil
}

func (owner *l8RuntimeOwnerSupervisor) refreshFinalizingIntent(record *firecrackerRuntimeOwnerRecordV1) error {
	if record == nil || record.State != "finalizing" {
		return nil
	}
	if record.Revision == ^uint64(0) {
		return errL8RuntimeOwnerInvalid
	}
	digestBytes, err := hex.DecodeString(record.SeedCorrelationDigest)
	if err != nil || len(digestBytes) != 32 {
		return errL8RuntimeOwnerInvalid
	}
	var seedDigest [32]byte
	copy(seedDigest[:], digestBytes)
	record.FinalizeTargetRevision = record.Revision + 1
	record.FinalizedCommitID, err = l8RuntimeOwnerCommitID(owner.opts.CommitKey, seedDigest, record.FinalizeTargetRevision)
	if err != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func l8RuntimeOwnerControllerSession(packet l8RuntimeOwnerPacketV1) (string, error) {
	switch packet.Opcode {
	case l8RuntimeOwnerOpcodeInspect, l8RuntimeOwnerOpcodeStopReap, l8RuntimeOwnerOpcodeAcquireNamespaces, l8RuntimeOwnerOpcodeClose, l8RuntimeOwnerOpcodeAbortStart:
		request, err := decodeL8RuntimeOwnerControllerRequest(packet.Body)
		if err != nil {
			return "", err
		}
		return request.ControllerSessionGeneration, nil
	case l8RuntimeOwnerOpcodeFinalize:
		request, err := decodeL8RuntimeOwnerFinalizeRequest(packet.Body)
		if err != nil {
			return "", err
		}
		return request.ControllerSessionGeneration, nil
	case l8RuntimeOwnerOpcodeCommit:
		request, err := decodeL8RuntimeOwnerCommitRequest(packet.Body)
		if err != nil {
			return "", err
		}
		return request.ControllerSessionGeneration, nil
	default:
		return "", errL8RuntimeOwnerProtocol
	}
}

func l8RuntimeOwnerResponseFromRecord(record firecrackerRuntimeOwnerRecordV1, includeAbsence bool) l8RuntimeOwnerResponseV1 {
	response := l8RuntimeOwnerResponseV1{
		State:          l8RuntimeOwnerStateByte(record.State),
		RecordRevision: record.Revision,
	}
	if includeAbsence && record.State == "absent" {
		response.AbsenceKind = l8RuntimeOwnerAbsenceKindByte(record.AbsenceKind)
		response.ObservedAtUnixNano = record.AbsenceObservedAtUnixNano
	}
	return response
}

func l8RuntimeOwnerStateByte(state string) byte {
	switch state {
	case "starting":
		return l8RuntimeOwnerStateStarting
	case "running":
		return l8RuntimeOwnerStateRunning
	case "stopping":
		return l8RuntimeOwnerStateStopping
	case "absent":
		return l8RuntimeOwnerStateAbsent
	case "finalizing":
		return l8RuntimeOwnerStateFinalizing
	case "finalized":
		return l8RuntimeOwnerStateFinalized
	case "uncertain":
		return l8RuntimeOwnerStateUncertain
	default:
		return 0
	}
}

func l8RuntimeOwnerAbsenceKindByte(kind string) byte {
	switch kind {
	case "direct_wait":
		return l8RuntimeOwnerAbsenceKindWait
	case "replacement_proc":
		return l8RuntimeOwnerAbsenceKindProc
	default:
		return l8RuntimeOwnerAbsenceKindNone
	}
}

func l8RuntimeOwnerAbsenceKindName(kind byte) string {
	switch kind {
	case l8RuntimeOwnerAbsenceKindWait:
		return "direct_wait"
	case l8RuntimeOwnerAbsenceKindProc:
		return "replacement_proc"
	default:
		return ""
	}
}

func validL8RuntimeOwnerSafeID(value string) bool {
	if value == "" || len(value) > l8RuntimeOwnerHandshakeGenerationMax {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' {
			continue
		}
		return false
	}
	return true
}

func l8RuntimeOwnerCall(fn func() error) (err error) {
	defer func() {
		if recover() != nil {
			err = errL8RuntimeOwnerInvalid
		}
	}()
	if fn == nil {
		return errL8RuntimeOwnerInvalid
	}
	if err := fn(); err != nil {
		return errL8RuntimeOwnerInvalid
	}
	return nil
}

func l8RuntimeOwnerCallUint64(fn func() (uint64, error)) (value uint64, err error) {
	defer func() {
		if recover() != nil {
			value = 0
			err = errL8RuntimeOwnerInvalid
		}
	}()
	if fn == nil {
		return 0, errL8RuntimeOwnerInvalid
	}
	value, callErr := fn()
	if callErr != nil {
		return 0, errL8RuntimeOwnerInvalid
	}
	return value, nil
}

func l8RuntimeOwnerCallWait(fn func(context.Context) (bool, error), ctx context.Context) (reaped bool, err error) {
	defer func() {
		if recover() != nil {
			reaped = false
			err = errL8RuntimeOwnerInvalid
		}
	}()
	if fn == nil {
		return false, errL8RuntimeOwnerInvalid
	}
	reaped, callErr := fn(ctx)
	if callErr != nil {
		return false, errL8RuntimeOwnerInvalid
	}
	return reaped, nil
}

func l8RuntimeOwnerCallRecordAbsent(fn func(l8RuntimeOwnerAbsenceObservation) (uint64, error), observation l8RuntimeOwnerAbsenceObservation) (revision uint64, err error) {
	defer func() {
		if recover() != nil {
			revision = 0
			err = errL8RuntimeOwnerInvalid
		}
	}()
	if fn == nil {
		return 0, errL8RuntimeOwnerInvalid
	}
	revision, callErr := fn(observation)
	if callErr != nil {
		return 0, errL8RuntimeOwnerInvalid
	}
	return revision, nil
}
