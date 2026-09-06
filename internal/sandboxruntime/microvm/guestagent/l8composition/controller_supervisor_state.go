package l8composition

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var (
	ErrControllerSupervisorTerminal            = errors.New("L8 controller-supervisor state is terminal")
	ErrControllerSupervisorTransition          = errors.New("L8 controller-supervisor transition is invalid")
	ErrControllerSupervisorCorrelation         = errors.New("L8 controller-supervisor correlation is invalid")
	ErrControllerSupervisorRequestReuse        = errors.New("L8 controller-supervisor request ID was reused")
	ErrControllerSupervisorOutstandingRequest  = errors.New("L8 controller-supervisor request is already outstanding")
	ErrControllerSupervisorLaunchLimit         = errors.New("L8 controller-supervisor launch limit is exhausted")
	ErrControllerSupervisorPendingEvent        = errors.New("L8 controller-supervisor pending event is invalid")
	ErrControllerSupervisorReadyMismatch       = errors.New("L8 controller-supervisor readiness does not match")
	ErrControllerSupervisorDescriptorMismatch  = errors.New("L8 controller-supervisor descriptor does not match")
	ErrControllerSupervisorCompositionMismatch = errors.New("L8 controller-supervisor composition does not match")
	ErrControllerSupervisorObservation         = errors.New("L8 controller-supervisor observation is invalid")
)

type ControllerSupervisorTransitionDecision uint8

const (
	ControllerSupervisorTransitionContinue ControllerSupervisorTransitionDecision = iota + 1
	ControllerSupervisorTransitionSendOutstandingResultBeforePendingEvent
	ControllerSupervisorTransitionPendingEventSendable
	ControllerSupervisorTransitionClosedClean
	ControllerSupervisorTransitionStopVMRequired
)

// ControllerSupervisorExpected is immutable constructor input. It contains
// only sealed correlation metadata; no field represents a live resource.
type ControllerSupervisorExpected struct {
	PID1Credential             ControllerSupervisorKernelCredential
	ControllerCredential       ControllerSupervisorKernelCredential
	AgentPID                   uint32
	SupervisorReady            ControllerSupervisorSupervisorReadyBody
	ControllerDescriptor       ProcessDescriptor
	ControllerDescriptorSHA256 [sha256.Size]byte
	CompositionSHA256          [sha256.Size]byte
	JobIdentityDigest          [sha256.Size]byte
}

// ControllerSupervisorShimExitObservation is untrusted pure metadata until a
// state correlates it with its active completed-launch entry. It is never live
// process, zero-population, cleanup, or resource proof.
type ControllerSupervisorShimExitObservation struct {
	exitCategory   ControllerSupervisorExitCategory
	exitCode       int32
	zeroPopulation bool
	monitorState   ControllerSupervisorMonitorState
	valid          bool
}

func NewControllerSupervisorShimExitObservation(exit ControllerSupervisorExitCategory, code int32, zeroPopulation bool, monitor ControllerSupervisorMonitorState) (ControllerSupervisorShimExitObservation, error) {
	test := ControllerSupervisorEventBody{EventCode: ControllerSupervisorEventShimExited, RequestType: ControllerSupervisorPacketTypeLaunchShim, FailureCode: ControllerSupervisorFailureNone, Revision: 1, JobGeneration: "x", MonitorGeneration: "x", MountGeneration: "x", CgroupGeneration: "x", LaunchID: "x", ExitCategory: exit, ExitCode: code, ZeroPopulation: zeroPopulation, MonitorState: monitor, CleanupCategory: ControllerSupervisorCleanupNotApplicable}
	if err := ValidateControllerSupervisorEventBody(test); err != nil {
		return ControllerSupervisorShimExitObservation{}, ErrControllerSupervisorObservation
	}
	return ControllerSupervisorShimExitObservation{exitCategory: exit, exitCode: code, zeroPopulation: zeroPopulation, monitorState: monitor, valid: true}, nil
}

type controllerSupervisorPhase uint8

const (
	controllerSupervisorPhaseReady controllerSupervisorPhase = iota + 1
	controllerSupervisorPhaseAttestation
	controllerSupervisorPhaseComposition
	controllerSupervisorPhaseIdle
	controllerSupervisorPhaseJob
	controllerSupervisorPhaseTerminated
	controllerSupervisorPhaseDestroyRetry
	controllerSupervisorPhaseDestroyed
	controllerSupervisorPhaseClosed
	controllerSupervisorPhaseStopped
)

type controllerSupervisorOutstanding struct {
	packetType   ControllerSupervisorPacketType
	requestID    [16]byte
	revision     uint64
	launchID     string
	launchDigest [32]byte
}
type controllerSupervisorCompletedLaunch struct {
	requestID                   [16]byte
	launchID                    string
	revision                    uint64
	job, monitor, mount, cgroup string
	launchDigest                [32]byte
	exitPending                 bool
}
type controllerSupervisorRequestLedger struct {
	create       [16]byte
	launches     [MaxControllerSupervisorLaunches][16]byte
	launchCount  uint16
	cleanup      [3][16]byte
	cleanupCount uint8
}
type controllerSupervisorJob struct {
	revision                           uint64
	job, monitor, mount, cgroup, limit string
	createDigest, monitorReady         [32]byte
}

// ControllerSupervisorState is a copy-safe one-pointer handle to a synchronized
// pure transcript verifier. Value copies share one owner. It owns no endpoint,
// right, descriptor, process, pidfd, namespace, or cleanup.
type ControllerSupervisorState struct {
	owner *controllerSupervisorStateOwner
}

type controllerSupervisorStateOwner struct {
	mu              sync.Mutex
	phase           controllerSupervisorPhase
	expected        ControllerSupervisorExpected
	descriptorWire  []byte
	nextPID1        uint64
	nextController  uint64
	requests        controllerSupervisorRequestLedger
	job             controllerSupervisorJob
	outstanding     controllerSupervisorOutstanding
	completed       controllerSupervisorCompletedLaunch
	pending         ControllerSupervisorShimExitObservation
	launchesDenied  bool
	closePID1       bool
	closeController bool
}

func NewControllerSupervisorState(expected ControllerSupervisorExpected) (*ControllerSupervisorState, error) {
	if !validControllerSupervisorPID1(expected.PID1Credential) || !validControllerSupervisorController(expected.ControllerCredential) || !validControllerSupervisorPID(expected.AgentPID) {
		return nil, ErrControllerSupervisorKernelCredential
	}
	if expected.PID1Credential.PID == expected.ControllerCredential.PID || expected.PID1Credential.PID == expected.AgentPID || expected.ControllerCredential.PID == expected.AgentPID {
		return nil, ErrControllerSupervisorRoleIdentityAlias
	}
	readyDigest, err := ControllerSupervisorReadySHA256(expected.SupervisorReady.BootGeneration, expected.SupervisorReady.HelperGeneration, expected.SupervisorReady.SupervisorGeneration, expected.SupervisorReady.LimitSetID)
	if err != nil || readyDigest != expected.SupervisorReady.SupervisorReadySHA256 {
		return nil, ErrControllerSupervisorReadyMismatch
	}
	if expected.ControllerDescriptor.Role != ProcessRoleHelper {
		return nil, ErrControllerSupervisorDescriptorRole
	}
	wire, err := EncodeProcessDescriptor(expected.ControllerDescriptor)
	if err != nil {
		return nil, err
	}
	if controllerSupervisorZero32(expected.ControllerDescriptorSHA256) || sha256.Sum256(wire) != expected.ControllerDescriptorSHA256 {
		return nil, ErrControllerSupervisorDescriptorDigest
	}
	if controllerSupervisorZero32(expected.CompositionSHA256) || controllerSupervisorZero32(expected.JobIdentityDigest) {
		return nil, ErrControllerSupervisorDigestZero
	}
	expected.ControllerDescriptor = cloneAgentSupervisorDescriptor(expected.ControllerDescriptor)
	return &ControllerSupervisorState{owner: &controllerSupervisorStateOwner{phase: controllerSupervisorPhaseReady, expected: expected, descriptorWire: append([]byte(nil), wire...)}}, nil
}

// Accept is the sole packet validation and transition-commit seam for both
// receive and send paths. D4 calls it before an atomic send; after a successful
// return the packet is committed and send failure must call Lost. This ordering
// lets ObserveActiveShimExit queue an exit after shim_started commits but before
// its send completes without weakening packet correlation.
func (state *ControllerSupervisorState) Accept(metadata ControllerSupervisorReceiveMetadata, encoded []byte) (ControllerSupervisorTransitionDecision, error) {
	s, err := state.stateOwner()
	if err != nil {
		return ControllerSupervisorTransitionStopVMRequired, ErrControllerSupervisorTerminal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == controllerSupervisorPhaseStopped {
		return ControllerSupervisorTransitionStopVMRequired, ErrControllerSupervisorTerminal
	}
	if s.phase == controllerSupervisorPhaseClosed {
		return s.stopLocked(ErrControllerSupervisorTerminal)
	}
	packet, err := DecodeControllerSupervisorPacket(encoded)
	if err != nil {
		return s.stopLocked(err)
	}
	if err := ValidateControllerSupervisorReceiveMetadata(packet, metadata, s.expected.PID1Credential, s.expected.ControllerCredential, s.expected.AgentPID); err != nil {
		return s.stopLocked(err)
	}
	if s.pending.valid && metadata.Direction == ControllerSupervisorDirectionControllerToPID1 {
		return s.stopLocked(ErrControllerSupervisorPendingEvent)
	}
	want := s.nextSequenceLocked(metadata.Direction)
	if want >= MaxControllerSupervisorPacketsPerDirection || packet.header.Sequence != want {
		return s.stopLocked(ErrControllerSupervisorSequence)
	}
	decision, err := s.transitionLocked(packet, metadata.Direction)
	if err != nil {
		return s.stopLocked(err)
	}
	s.advanceLocked(metadata.Direction)
	return decision, nil
}

func (s *controllerSupervisorStateOwner) transitionLocked(packet ControllerSupervisorPacket, direction ControllerSupervisorDirection) (ControllerSupervisorTransitionDecision, error) {
	if packet.header.Type == ControllerSupervisorPacketTypeCloseNotify {
		return s.closeLocked(packet, direction)
	}
	switch s.phase {
	case controllerSupervisorPhaseReady:
		if packet.header.Type != ControllerSupervisorPacketTypeSupervisorReady || packet.ready != s.expected.SupervisorReady {
			return 0, ErrControllerSupervisorReadyMismatch
		}
		digest, err := ControllerSupervisorReadySHA256(packet.ready.BootGeneration, packet.ready.HelperGeneration, packet.ready.SupervisorGeneration, packet.ready.LimitSetID)
		if err != nil || digest != packet.ready.SupervisorReadySHA256 {
			return 0, ErrControllerSupervisorReadyMismatch
		}
		s.phase = controllerSupervisorPhaseAttestation
		return ControllerSupervisorTransitionContinue, nil
	case controllerSupervisorPhaseAttestation:
		if packet.header.Type != ControllerSupervisorPacketTypeControllerAttestation {
			return 0, ErrControllerSupervisorTransition
		}
		wire, err := EncodeProcessDescriptor(packet.attestation.Descriptor)
		if err != nil || !bytes.Equal(wire, s.descriptorWire) || sha256.Sum256(wire) != s.expected.ControllerDescriptorSHA256 {
			return 0, ErrControllerSupervisorDescriptorMismatch
		}
		s.phase = controllerSupervisorPhaseComposition
		return ControllerSupervisorTransitionContinue, nil
	case controllerSupervisorPhaseComposition:
		if packet.header.Type != ControllerSupervisorPacketTypeCompositionAccepted || packet.accepted.CompositionSHA256 != s.expected.CompositionSHA256 {
			return 0, ErrControllerSupervisorCompositionMismatch
		}
		s.phase = controllerSupervisorPhaseIdle
		return ControllerSupervisorTransitionContinue, nil
	case controllerSupervisorPhaseIdle:
		if packet.header.Type != ControllerSupervisorPacketTypeCreateJob {
			return 0, ErrControllerSupervisorTransition
		}
		return s.acceptCreateLocked(packet)
	case controllerSupervisorPhaseJob:
		return s.acceptJobLocked(packet)
	case controllerSupervisorPhaseTerminated:
		return s.acceptTerminatedLocked(packet)
	case controllerSupervisorPhaseDestroyRetry:
		return s.acceptDestroyRetryLocked(packet)
	case controllerSupervisorPhaseDestroyed:
		return 0, ErrControllerSupervisorTransition
	default:
		return 0, ErrControllerSupervisorTerminal
	}
}

func (s *controllerSupervisorStateOwner) acceptCreateLocked(packet ControllerSupervisorPacket) (ControllerSupervisorTransitionDecision, error) {
	if s.hasOutstandingLocked() {
		return 0, ErrControllerSupervisorOutstandingRequest
	}
	if packet.header.JobIdentityDigest != s.expected.JobIdentityDigest || packet.create.Revision != 1 {
		return 0, ErrControllerSupervisorCorrelation
	}
	if err := s.chargeRequestLocked(packet.header.Type, packet.header.RequestID); err != nil {
		return 0, err
	}
	monitor, err := ControllerSupervisorMonitorConfigSHA256(packet.header.JobIdentityDigest, packet.create.JobGeneration, packet.create.MonitorGeneration, packet.create.MountGeneration, packet.create.LimitSetID)
	if err != nil || monitor != packet.create.MonitorConfigSHA256 {
		return 0, ErrControllerSupervisorCorrelation
	}
	cgroup, err := ControllerSupervisorCgroupConfigSHA256(packet.header.JobIdentityDigest, packet.create.JobGeneration, packet.create.CgroupGeneration, packet.create.LimitSetID)
	if err != nil || cgroup != packet.create.CgroupConfigSHA256 {
		return 0, ErrControllerSupervisorCorrelation
	}
	digest, err := ControllerSupervisorCreateJobSHA256(packet.header.JobIdentityDigest, packet.create)
	if err != nil {
		return 0, err
	}
	s.job = controllerSupervisorJob{revision: 1, job: string(packet.create.JobGeneration), monitor: string(packet.create.MonitorGeneration), mount: string(packet.create.MountGeneration), cgroup: string(packet.create.CgroupGeneration), limit: string(packet.create.LimitSetID), createDigest: digest}
	s.outstanding = controllerSupervisorOutstanding{packetType: packet.header.Type, requestID: packet.header.RequestID, revision: 1}
	s.phase = controllerSupervisorPhaseJob
	return ControllerSupervisorTransitionContinue, nil
}

func (s *controllerSupervisorStateOwner) acceptJobLocked(packet ControllerSupervisorPacket) (ControllerSupervisorTransitionDecision, error) {
	if packet.header.JobIdentityDigest != s.expected.JobIdentityDigest {
		return 0, ErrControllerSupervisorCorrelation
	}
	switch packet.header.Type {
	case ControllerSupervisorPacketTypeJobCreated:
		if !s.outstandingMatchesLocked(ControllerSupervisorPacketTypeCreateJob, packet.header.RequestID) || packet.created.Revision != s.outstanding.revision || !s.jobTupleLocked(packet.created.Revision, packet.created.JobGeneration, packet.created.MonitorGeneration, packet.created.MountGeneration, packet.created.CgroupGeneration, packet.created.LimitSetID) || packet.created.CreateJobSHA256 != s.job.createDigest {
			return 0, ErrControllerSupervisorCorrelation
		}
		ready, err := ControllerSupervisorMonitorReadySHA256(packet.header.JobIdentityDigest, packet.created)
		if err != nil || ready != packet.created.MonitorReadySHA256 {
			return 0, ErrControllerSupervisorCorrelation
		}
		s.job.monitorReady = ready
		s.outstanding = controllerSupervisorOutstanding{}
		return s.afterResultLocked(), nil
	case ControllerSupervisorPacketTypeLaunchShim:
		if s.hasOutstandingLocked() {
			return 0, ErrControllerSupervisorOutstandingRequest
		}
		if s.launchesDenied || s.completed.requestID != [16]byte{} || s.requests.launchCount >= MaxControllerSupervisorLaunches {
			return 0, ErrControllerSupervisorLaunchLimit
		}
		if !s.jobTupleLocked(packet.launch.Revision, packet.launch.JobGeneration, packet.launch.MonitorGeneration, packet.launch.MountGeneration, packet.launch.CgroupGeneration, packet.launch.LimitSetID) {
			return 0, ErrControllerSupervisorCorrelation
		}
		if err := s.chargeRequestLocked(packet.header.Type, packet.header.RequestID); err != nil {
			return 0, err
		}
		digest, err := ControllerSupervisorLaunchShimSHA256(packet.header.JobIdentityDigest, packet.launch)
		if err != nil {
			return 0, err
		}
		s.job.revision = packet.launch.Revision
		s.outstanding = controllerSupervisorOutstanding{packetType: packet.header.Type, requestID: packet.header.RequestID, revision: packet.launch.Revision, launchID: string(packet.launch.LaunchID), launchDigest: digest}
		return ControllerSupervisorTransitionContinue, nil
	case ControllerSupervisorPacketTypeShimStarted:
		if !s.outstandingMatchesLocked(ControllerSupervisorPacketTypeLaunchShim, packet.header.RequestID) || packet.started.Revision != s.outstanding.revision || string(packet.started.LaunchID) != s.outstanding.launchID || packet.started.LaunchShimSHA256 != s.outstanding.launchDigest || !s.jobTupleNoLimitLocked(packet.started.Revision, packet.started.JobGeneration, packet.started.MonitorGeneration, packet.started.MountGeneration, packet.started.CgroupGeneration) {
			return 0, ErrControllerSupervisorCorrelation
		}
		s.completed = controllerSupervisorCompletedLaunch{requestID: packet.header.RequestID, launchID: s.outstanding.launchID, revision: s.outstanding.revision, job: s.job.job, monitor: s.job.monitor, mount: s.job.mount, cgroup: s.job.cgroup, launchDigest: s.outstanding.launchDigest, exitPending: true}
		s.outstanding = controllerSupervisorOutstanding{}
		return s.afterResultLocked(), nil
	case ControllerSupervisorPacketTypeTerminateJob:
		if s.hasOutstandingLocked() {
			return 0, ErrControllerSupervisorOutstandingRequest
		}
		if !s.jobTupleNoLimitLocked(packet.terminate.Revision, packet.terminate.JobGeneration, packet.terminate.MonitorGeneration, packet.terminate.MountGeneration, packet.terminate.CgroupGeneration) {
			return 0, ErrControllerSupervisorCorrelation
		}
		if err := s.chargeRequestLocked(packet.header.Type, packet.header.RequestID); err != nil {
			return 0, err
		}
		s.launchesDenied = true
		s.job.revision = packet.terminate.Revision
		s.outstanding = controllerSupervisorOutstanding{packetType: packet.header.Type, requestID: packet.header.RequestID, revision: packet.terminate.Revision}
		return ControllerSupervisorTransitionContinue, nil
	case ControllerSupervisorPacketTypeSupervisorEvent:
		return s.acceptEventLocked(packet)
	default:
		return 0, ErrControllerSupervisorTransition
	}
}

func (s *controllerSupervisorStateOwner) acceptTerminatedLocked(packet ControllerSupervisorPacket) (ControllerSupervisorTransitionDecision, error) {
	if packet.header.JobIdentityDigest != s.expected.JobIdentityDigest {
		return 0, ErrControllerSupervisorCorrelation
	}
	switch packet.header.Type {
	case ControllerSupervisorPacketTypeDestroyJob:
		if s.hasOutstandingLocked() || s.completed.requestID != [16]byte{} || s.pending.valid {
			return 0, ErrControllerSupervisorTransition
		}
		if !s.jobTupleNoLimitLocked(packet.destroy.Revision, packet.destroy.JobGeneration, packet.destroy.MonitorGeneration, packet.destroy.MountGeneration, packet.destroy.CgroupGeneration) {
			return 0, ErrControllerSupervisorCorrelation
		}
		if err := s.chargeRequestLocked(packet.header.Type, packet.header.RequestID); err != nil {
			return 0, err
		}
		s.job.revision = packet.destroy.Revision
		s.outstanding = controllerSupervisorOutstanding{packetType: packet.header.Type, requestID: packet.header.RequestID, revision: packet.destroy.Revision}
		return ControllerSupervisorTransitionContinue, nil
	case ControllerSupervisorPacketTypeSupervisorEvent:
		return s.acceptEventLocked(packet)
	default:
		return 0, ErrControllerSupervisorTransition
	}
}

func (s *controllerSupervisorStateOwner) acceptDestroyRetryLocked(packet ControllerSupervisorPacket) (ControllerSupervisorTransitionDecision, error) {
	if packet.header.JobIdentityDigest != s.expected.JobIdentityDigest {
		return 0, ErrControllerSupervisorCorrelation
	}
	switch packet.header.Type {
	case ControllerSupervisorPacketTypeDestroyJob:
		if s.hasOutstandingLocked() || !s.jobTupleNoLimitLocked(packet.destroy.Revision, packet.destroy.JobGeneration, packet.destroy.MonitorGeneration, packet.destroy.MountGeneration, packet.destroy.CgroupGeneration) {
			return 0, ErrControllerSupervisorCorrelation
		}
		if err := s.chargeRequestLocked(packet.header.Type, packet.header.RequestID); err != nil {
			return 0, err
		}
		s.job.revision = packet.destroy.Revision
		s.outstanding = controllerSupervisorOutstanding{packetType: packet.header.Type, requestID: packet.header.RequestID, revision: packet.destroy.Revision}
		return ControllerSupervisorTransitionContinue, nil
	case ControllerSupervisorPacketTypeSupervisorEvent:
		return s.acceptEventLocked(packet)
	default:
		return 0, ErrControllerSupervisorTransition
	}
}

func (s *controllerSupervisorStateOwner) acceptEventLocked(packet ControllerSupervisorPacket) (ControllerSupervisorTransitionDecision, error) {
	e := packet.event
	if e.EventCode == ControllerSupervisorEventShimExited {
		if s.hasOutstandingLocked() {
			return 0, ErrControllerSupervisorPendingEvent
		}
		if s.completed.requestID == [16]byte{} || packet.header.RequestID != s.completed.requestID || string(e.LaunchID) != s.completed.launchID || e.Revision != s.completed.revision || string(e.JobGeneration) != s.completed.job || string(e.MonitorGeneration) != s.completed.monitor || string(e.MountGeneration) != s.completed.mount || string(e.CgroupGeneration) != s.completed.cgroup {
			return 0, ErrControllerSupervisorCorrelation
		}
		if s.pending.valid && (e.ExitCategory != s.pending.exitCategory || e.ExitCode != s.pending.exitCode || e.ZeroPopulation != s.pending.zeroPopulation || e.MonitorState != s.pending.monitorState) {
			return 0, ErrControllerSupervisorCorrelation
		}
		s.completed = controllerSupervisorCompletedLaunch{}
		s.pending = ControllerSupervisorShimExitObservation{}
		return ControllerSupervisorTransitionContinue, nil
	}
	if !s.jobTupleNoLimitLocked(e.Revision, e.JobGeneration, e.MonitorGeneration, e.MountGeneration, e.CgroupGeneration) {
		return 0, ErrControllerSupervisorCorrelation
	}
	if !s.hasOutstandingLocked() || packet.header.RequestID != s.outstanding.requestID || e.RequestType != s.outstanding.packetType || e.Revision != s.outstanding.revision {
		return 0, ErrControllerSupervisorCorrelation
	}
	switch e.EventCode {
	case ControllerSupervisorEventOperationFailed, ControllerSupervisorEventCleanupObserved:
		requestType := s.outstanding.packetType
		s.outstanding = controllerSupervisorOutstanding{}
		if e.CleanupCategory == ControllerSupervisorCleanupStopVMRequired {
			s.phase = controllerSupervisorPhaseStopped
			return ControllerSupervisorTransitionStopVMRequired, nil
		}
		switch requestType {
		case ControllerSupervisorPacketTypeCreateJob:
			// A committed create failure is the final HL8L packet even after a
			// proved rollback or pre-mutation resource-limit rejection.
			s.phase = controllerSupervisorPhaseStopped
			return ControllerSupervisorTransitionStopVMRequired, nil
		case ControllerSupervisorPacketTypeLaunchShim:
			if e.CleanupCategory == ControllerSupervisorCleanupRetryRequired {
				s.launchesDenied = true
			}
			s.phase = controllerSupervisorPhaseJob
		case ControllerSupervisorPacketTypeTerminateJob:
			s.launchesDenied = true
			s.phase = controllerSupervisorPhaseJob
		case ControllerSupervisorPacketTypeDestroyJob:
			s.launchesDenied = true
			s.phase = controllerSupervisorPhaseDestroyRetry
		default:
			return 0, ErrControllerSupervisorCorrelation
		}
		return s.afterResultLocked(), nil
	case ControllerSupervisorEventJobTerminated:
		if s.outstanding.packetType != ControllerSupervisorPacketTypeTerminateJob {
			return 0, ErrControllerSupervisorCorrelation
		}
		s.outstanding = controllerSupervisorOutstanding{}
		s.phase = controllerSupervisorPhaseTerminated
		return s.afterResultLocked(), nil
	case ControllerSupervisorEventJobDestroyed:
		if s.outstanding.packetType != ControllerSupervisorPacketTypeDestroyJob {
			return 0, ErrControllerSupervisorCorrelation
		}
		s.outstanding = controllerSupervisorOutstanding{}
		s.phase = controllerSupervisorPhaseDestroyed
		return s.afterResultLocked(), nil
	default:
		return 0, ErrControllerSupervisorCorrelation
	}
}

func (state *ControllerSupervisorState) ObserveActiveShimExit(observation ControllerSupervisorShimExitObservation) (ControllerSupervisorTransitionDecision, error) {
	s, err := state.stateOwner()
	if err != nil {
		return ControllerSupervisorTransitionStopVMRequired, ErrControllerSupervisorTerminal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == controllerSupervisorPhaseStopped || s.phase == controllerSupervisorPhaseClosed {
		return ControllerSupervisorTransitionStopVMRequired, ErrControllerSupervisorTerminal
	}
	if !observation.valid || s.completed.requestID == [16]byte{} || !s.completed.exitPending || s.pending.valid {
		return s.stopLocked(ErrControllerSupervisorObservation)
	}
	if observation.monitorState != ControllerSupervisorMonitorReady && observation.monitorState != ControllerSupervisorMonitorCleanupPending {
		return s.stopLocked(ErrControllerSupervisorObservation)
	}
	s.pending = observation
	if s.hasOutstandingLocked() {
		return ControllerSupervisorTransitionSendOutstandingResultBeforePendingEvent, nil
	}
	return ControllerSupervisorTransitionPendingEventSendable, nil
}

// PendingShimExitedPacket returns a defensive canonical wire copy only when
// the state-owned one-slot event is next sendable. D4 must pass the returned
// packet back through Accept to commit it before performing the atomic send.
func (state *ControllerSupervisorState) PendingShimExitedPacket() ([]byte, error) {
	s, err := state.stateOwner()
	if err != nil {
		return nil, ErrControllerSupervisorTerminal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == controllerSupervisorPhaseStopped || s.phase == controllerSupervisorPhaseClosed {
		return nil, ErrControllerSupervisorTerminal
	}
	if !s.pending.valid || s.hasOutstandingLocked() || s.completed.requestID == [16]byte{} || s.nextPID1 >= MaxControllerSupervisorPacketsPerDirection {
		return nil, ErrControllerSupervisorPendingEvent
	}
	body := ControllerSupervisorEventBody{EventCode: ControllerSupervisorEventShimExited, RequestType: ControllerSupervisorPacketTypeLaunchShim, FailureCode: ControllerSupervisorFailureNone, Revision: s.completed.revision, JobGeneration: credentialprotocol.SafeID(s.completed.job), MonitorGeneration: credentialprotocol.SafeID(s.completed.monitor), MountGeneration: credentialprotocol.SafeID(s.completed.mount), CgroupGeneration: credentialprotocol.SafeID(s.completed.cgroup), LaunchID: credentialprotocol.SafeID(s.completed.launchID), ExitCategory: s.pending.exitCategory, ExitCode: s.pending.exitCode, ZeroPopulation: s.pending.zeroPopulation, MonitorState: s.pending.monitorState, CleanupCategory: ControllerSupervisorCleanupNotApplicable}
	return EncodeControllerSupervisorEventPacket(s.nextPID1, s.completed.requestID, s.expected.JobIdentityDigest, body)
}

func (s *controllerSupervisorStateOwner) closeLocked(packet ControllerSupervisorPacket, direction ControllerSupervisorDirection) (ControllerSupervisorTransitionDecision, error) {
	if s.phase != controllerSupervisorPhaseDestroyed || packet.closeBody.Reason != 1 || s.hasOutstandingLocked() || s.pending.valid {
		return 0, ErrControllerSupervisorTransition
	}
	if direction == ControllerSupervisorDirectionPID1ToController {
		if s.closePID1 {
			return 0, ErrControllerSupervisorTransition
		}
		s.closePID1 = true
	} else {
		if s.closeController {
			return 0, ErrControllerSupervisorTransition
		}
		s.closeController = true
	}
	if s.closePID1 && s.closeController {
		s.phase = controllerSupervisorPhaseClosed
		return ControllerSupervisorTransitionClosedClean, nil
	}
	return ControllerSupervisorTransitionContinue, nil
}
func (s *controllerSupervisorStateOwner) afterResultLocked() ControllerSupervisorTransitionDecision {
	if s.pending.valid {
		return ControllerSupervisorTransitionPendingEventSendable
	}
	return ControllerSupervisorTransitionContinue
}
func (s *controllerSupervisorStateOwner) requestUsedLocked(id [16]byte) bool {
	if id == [16]byte{} || s.requests.create == id {
		return true
	}
	for index := uint16(0); index < s.requests.launchCount; index++ {
		if s.requests.launches[index] == id {
			return true
		}
	}
	for index := uint8(0); index < s.requests.cleanupCount; index++ {
		if s.requests.cleanup[index] == id {
			return true
		}
	}
	return false
}

// chargeRequestLocked applies bounds before every fixed-ledger write. The one
// shared cleanup counter is the D2 count authority for terminate and destroy;
// D4 separately owns the one shared 30-second deadline observation.
func (s *controllerSupervisorStateOwner) chargeRequestLocked(kind ControllerSupervisorPacketType, id [16]byte) error {
	if s.requestUsedLocked(id) {
		return ErrControllerSupervisorRequestReuse
	}
	switch kind {
	case ControllerSupervisorPacketTypeCreateJob:
		if s.requests.create != [16]byte{} {
			return ErrControllerSupervisorRequestReuse
		}
		s.requests.create = id
	case ControllerSupervisorPacketTypeLaunchShim:
		if s.requests.launchCount >= MaxControllerSupervisorLaunches {
			return ErrControllerSupervisorLaunchLimit
		}
		s.requests.launches[s.requests.launchCount] = id
		s.requests.launchCount++
	case ControllerSupervisorPacketTypeTerminateJob, ControllerSupervisorPacketTypeDestroyJob:
		if s.requests.cleanupCount >= 3 {
			return ErrControllerSupervisorTransition
		}
		s.requests.cleanup[s.requests.cleanupCount] = id
		s.requests.cleanupCount++
	default:
		return ErrControllerSupervisorTransition
	}
	return nil
}
func (s *controllerSupervisorStateOwner) hasOutstandingLocked() bool {
	return s.outstanding.requestID != [16]byte{}
}
func (s *controllerSupervisorStateOwner) outstandingMatchesLocked(kind ControllerSupervisorPacketType, id [16]byte) bool {
	return s.outstanding.packetType == kind && s.outstanding.requestID == id
}
func (s *controllerSupervisorStateOwner) jobTupleLocked(revision uint64, job, monitor, mount, cgroup, limit credentialprotocol.SafeID) bool {
	return revision >= s.job.revision && string(job) == s.job.job && string(monitor) == s.job.monitor && string(mount) == s.job.mount && string(cgroup) == s.job.cgroup && string(limit) == s.job.limit
}
func (s *controllerSupervisorStateOwner) jobTupleNoLimitLocked(revision uint64, job, monitor, mount, cgroup credentialprotocol.SafeID) bool {
	return revision >= s.job.revision && string(job) == s.job.job && string(monitor) == s.job.monitor && string(mount) == s.job.mount && string(cgroup) == s.job.cgroup
}
func (s *controllerSupervisorStateOwner) nextSequenceLocked(direction ControllerSupervisorDirection) uint64 {
	if direction == ControllerSupervisorDirectionPID1ToController {
		return s.nextPID1
	}
	return s.nextController
}
func (s *controllerSupervisorStateOwner) advanceLocked(direction ControllerSupervisorDirection) {
	if direction == ControllerSupervisorDirectionPID1ToController {
		s.nextPID1++
	} else {
		s.nextController++
	}
}
func (s *controllerSupervisorStateOwner) stopLocked(err error) (ControllerSupervisorTransitionDecision, error) {
	s.phase = controllerSupervisorPhaseStopped
	return ControllerSupervisorTransitionStopVMRequired, err
}
func (state *ControllerSupervisorState) Lost() ControllerSupervisorTransitionDecision {
	s, err := state.stateOwner()
	if err != nil {
		return ControllerSupervisorTransitionStopVMRequired
	}
	s.mu.Lock()
	s.phase = controllerSupervisorPhaseStopped
	s.mu.Unlock()
	return ControllerSupervisorTransitionStopVMRequired
}
func (state *ControllerSupervisorState) Decision() ControllerSupervisorTransitionDecision {
	s, err := state.stateOwner()
	if err != nil {
		return ControllerSupervisorTransitionStopVMRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.phase {
	case controllerSupervisorPhaseStopped:
		return ControllerSupervisorTransitionStopVMRequired
	case controllerSupervisorPhaseClosed:
		return ControllerSupervisorTransitionClosedClean
	}
	if s.pending.valid {
		if s.hasOutstandingLocked() {
			return ControllerSupervisorTransitionSendOutstandingResultBeforePendingEvent
		}
		return ControllerSupervisorTransitionPendingEventSendable
	}
	return ControllerSupervisorTransitionContinue
}

func (state *ControllerSupervisorState) stateOwner() (*controllerSupervisorStateOwner, error) {
	if state == nil || state.owner == nil {
		return nil, ErrControllerSupervisorTerminal
	}
	return state.owner, nil
}
