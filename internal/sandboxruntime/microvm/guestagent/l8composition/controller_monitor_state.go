package l8composition

import (
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

const maxControllerMonitorTrackedIDs = 16

var (
	ErrControllerMonitorExpected           = errors.New("L8 controller-monitor expected state is invalid")
	ErrControllerMonitorTransition         = errors.New("L8 controller-monitor transition is invalid")
	ErrControllerMonitorTerminal           = errors.New("L8 controller-monitor state is terminal")
	ErrControllerMonitorSequence           = errors.New("L8 controller-monitor sequence is invalid")
	ErrControllerMonitorCorrelation        = errors.New("L8 controller-monitor correlation is invalid")
	ErrControllerMonitorRequestReuse       = errors.New("L8 controller-monitor request ID was reused")
	ErrControllerMonitorOutstandingRequest = errors.New("L8 controller-monitor request is already outstanding")
	ErrControllerMonitorTrustedObservation = errors.New("L8 controller-monitor trusted observation is invalid")
	ErrControllerMonitorExpiryWindow       = errors.New("L8 controller-monitor expiry is outside the authenticated horizon")
	ErrControllerMonitorPendingEvent       = errors.New("L8 controller-monitor pending event is invalid")
	ErrControllerMonitorObservation        = errors.New("L8 controller-monitor local observation is invalid")
	ErrControllerMonitorCleanupAttempts    = errors.New("L8 controller-monitor cleanup attempts are exhausted")
)

type ControllerMonitorTransitionDecision uint8

const (
	ControllerMonitorTransitionContinue ControllerMonitorTransitionDecision = iota + 1
	ControllerMonitorTransitionSendOperationDenied
	ControllerMonitorTransitionSendOutstandingResultBeforePendingEvent
	ControllerMonitorTransitionPendingEventSendable
	ControllerMonitorTransitionSendNormalClose
	ControllerMonitorTransitionClosedClean
	ControllerMonitorTransitionStopVMRequired
)

type ControllerMonitorProtocolPhase uint8

const (
	ControllerMonitorPhaseNativeBootstrap ControllerMonitorProtocolPhase = iota + 1
	ControllerMonitorPhaseReadyTransferred
	ControllerMonitorPhasePreparing
	ControllerMonitorPhasePrepared
	ControllerMonitorPhasePreparedWithEndpoint
	ControllerMonitorPhaseRevokeRequired
	ControllerMonitorPhaseRevoking
	ControllerMonitorPhaseStopPendingEvent
	ControllerMonitorPhaseCleanupReported
	ControllerMonitorPhaseCloseWait
	ControllerMonitorPhaseClosed
	ControllerMonitorPhaseTerminal
)

type ControllerMonitorExpected struct {
	MonitorCredential                      ControllerMonitorKernelCredential
	ControllerCredential                   ControllerMonitorKernelCredential
	AgentPID                               uint32
	JobIdentityDigest                      [sha256.Size]byte
	MonitorReady                           ControllerMonitorReadyBody
	AuthenticatedSessionHardExpiryUnixNano int64
}

type controllerMonitorObservationKind uint8

const (
	controllerMonitorObservationExpired controllerMonitorObservationKind = iota + 1
	controllerMonitorObservationMountDrift
	controllerMonitorObservationEndpointDrift
	controllerMonitorObservationCleanupRetry
	controllerMonitorObservationCleanupStop
)

type ControllerMonitorLocalObservation struct {
	kind      controllerMonitorObservationKind
	requestID [16]byte
}

func NewControllerMonitorExpiredObservation(requestID [16]byte) (ControllerMonitorLocalObservation, error) {
	return newControllerMonitorObservation(controllerMonitorObservationExpired, requestID)
}
func NewControllerMonitorMountDriftObservation(requestID [16]byte) (ControllerMonitorLocalObservation, error) {
	return newControllerMonitorObservation(controllerMonitorObservationMountDrift, requestID)
}
func NewControllerMonitorEndpointDriftObservation(requestID [16]byte) (ControllerMonitorLocalObservation, error) {
	return newControllerMonitorObservation(controllerMonitorObservationEndpointDrift, requestID)
}
func NewControllerMonitorRetryableCleanupObservation(requestID [16]byte) (ControllerMonitorLocalObservation, error) {
	return newControllerMonitorObservation(controllerMonitorObservationCleanupRetry, requestID)
}
func NewControllerMonitorNonretryableCleanupObservation(requestID [16]byte) (ControllerMonitorLocalObservation, error) {
	return newControllerMonitorObservation(controllerMonitorObservationCleanupStop, requestID)
}
func newControllerMonitorObservation(kind controllerMonitorObservationKind, requestID [16]byte) (ControllerMonitorLocalObservation, error) {
	if kind < controllerMonitorObservationExpired || kind > controllerMonitorObservationCleanupStop || controllerMonitorZero16(requestID) {
		return ControllerMonitorLocalObservation{}, ErrControllerMonitorObservation
	}
	return ControllerMonitorLocalObservation{kind: kind, requestID: requestID}, nil
}

type ControllerMonitorPendingEvent struct {
	RequestID [16]byte
	Body      ControllerMonitorEventBody
}

type ControllerMonitorSnapshot struct {
	Phase              ControllerMonitorProtocolPhase
	NextControllerSend uint64
	NextMonitorSend    uint64
	PrepareConsumed    bool
	EndpointConsumed   bool
	RequestOutstanding bool
	PendingEvent       bool
	CleanupAttempts    uint8
}

type controllerMonitorOutstanding struct {
	requestType      ControllerMonitorPacketType
	requestID        [16]byte
	awaitingResponse bool
	operationDenied  bool
	forceStop        bool
	endpoint         ControllerMonitorCreateSSHEndpointBody
	prepare          ControllerMonitorPrepareResult
	revokeReason     credentialprotocol.RevokeReason
}

type ControllerMonitorState struct {
	owner *controllerMonitorStateOwner
}

type controllerMonitorStateOwner struct {
	mu                 sync.Mutex
	phase              ControllerMonitorProtocolPhase
	expected           ControllerMonitorExpected
	nextController     uint64
	nextMonitor        uint64
	usedIDs            [maxControllerMonitorTrackedIDs][16]byte
	usedIDCount        uint8
	prepareConsumed    bool
	endpointConsumed   bool
	cleanupAttempts    uint8
	outstanding        controllerMonitorOutstanding
	prepareCorrelation credentialprotocol.HelperPrepareTransactionCorrelation
	prepareTransaction *credentialprotocol.HelperPrepareTransaction
	manifest           [credentialprotocol.MaxHelperBindings]credentialprotocol.HelperBindingManifestRecord
	manifestCount      uint16
	manifestSHA256     [32]byte
	endpointGeneration string
	pending            ControllerMonitorPendingEvent
	hasPending         bool
}

func NewControllerMonitorState(expected ControllerMonitorExpected) (*ControllerMonitorState, error) {
	if !validControllerMonitorRootCredential(expected.MonitorCredential) || !validControllerMonitorRootCredential(expected.ControllerCredential) || !validControllerMonitorPID(expected.AgentPID) || controllerMonitorZero32(expected.JobIdentityDigest) || expected.AuthenticatedSessionHardExpiryUnixNano <= 0 {
		return nil, ErrControllerMonitorExpected
	}
	if expected.MonitorCredential.PID == expected.ControllerCredential.PID || expected.MonitorCredential.PID == expected.AgentPID || expected.ControllerCredential.PID == expected.AgentPID {
		return nil, ErrControllerMonitorRoleIdentityAlias
	}
	digest, err := ControllerMonitorReadySHA256(expected.JobIdentityDigest, expected.MonitorReady)
	if err != nil || digest != expected.MonitorReady.MonitorReadySHA256 {
		return nil, ErrControllerMonitorExpected
	}
	return &ControllerMonitorState{owner: &controllerMonitorStateOwner{phase: ControllerMonitorPhaseNativeBootstrap, expected: expected}}, nil
}

func (state *ControllerMonitorState) Accept(metadata ControllerMonitorReceiveMetadata, encoded []byte, trustedObservationUnixNano int64) (ControllerMonitorTransitionDecision, error) {
	s, err := state.stateOwner()
	if err != nil {
		return ControllerMonitorTransitionStopVMRequired, ErrControllerMonitorTerminal
	}
	if len(encoded) >= ControllerMonitorHeaderBytes {
		header, headerErr := DecodeControllerMonitorHeader(encoded[:ControllerMonitorHeaderBytes])
		if headerErr == nil && header.Type == ControllerMonitorPacketTypePrepareFile {
			s.mu.Lock()
			defer s.mu.Unlock()
			return s.stopLocked(ErrControllerMonitorPrepareFileSlotRequired)
		}
	}
	packet, err := DecodeControllerMonitorPacket(encoded)
	if err != nil {
		s.mu.Lock()
		s.stopNoErrorLocked()
		s.mu.Unlock()
		return ControllerMonitorTransitionStopVMRequired, err
	}
	defer packet.Wipe()
	if packet.header.Type == ControllerMonitorPacketTypePrepareBegin {
		if trustedObservationUnixNano <= 0 {
			s.mu.Lock()
			s.stopNoErrorLocked()
			s.mu.Unlock()
			return ControllerMonitorTransitionStopVMRequired, ErrControllerMonitorTrustedObservation
		}
	} else if trustedObservationUnixNano != 0 {
		s.mu.Lock()
		s.stopNoErrorLocked()
		s.mu.Unlock()
		return ControllerMonitorTransitionStopVMRequired, ErrControllerMonitorTrustedObservation
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == ControllerMonitorPhaseTerminal {
		return ControllerMonitorTransitionStopVMRequired, ErrControllerMonitorTerminal
	}
	if s.phase == ControllerMonitorPhaseClosed {
		return s.stopLocked(ErrControllerMonitorTerminal)
	}
	if err := ValidateControllerMonitorReceiveMetadata(packet, metadata, s.expected.MonitorCredential, s.expected.ControllerCredential, s.expected.AgentPID); err != nil {
		return s.stopLocked(err)
	}
	if packet.header.JobIdentityDigest != s.expected.JobIdentityDigest {
		return s.stopLocked(ErrControllerMonitorCorrelation)
	}
	want := s.nextSequenceLocked(metadata.Direction)
	if want >= MaxControllerMonitorPacketsPerDirection || packet.header.Sequence != want {
		return s.stopLocked(ErrControllerMonitorSequence)
	}
	decision, transitionErr := s.transitionLocked(packet, metadata.Direction, trustedObservationUnixNano)
	if transitionErr != nil && decision != ControllerMonitorTransitionSendOperationDenied {
		return s.stopLocked(transitionErr)
	}
	s.advanceLocked(metadata.Direction)
	return decision, transitionErr
}

// AcceptPrepareFile authenticates and commits safe metadata previously minted
// by the in-place fixed-slot inspector. It never receives or retains payload
// bytes and advances the controller sequence exactly once.
func (state *ControllerMonitorState) AcceptPrepareFile(metadata ControllerMonitorReceiveMetadata, observation ControllerMonitorPrepareFileObservation) (ControllerMonitorTransitionDecision, error) {
	s, err := state.stateOwner()
	if err != nil {
		return ControllerMonitorTransitionStopVMRequired, ErrControllerMonitorTerminal
	}
	observed := observation.owner
	if observed == nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.stopLocked(ErrControllerMonitorPrepareFileObservation)
	}
	observed.mu.Lock()
	defer observed.mu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == ControllerMonitorPhaseTerminal || s.phase == ControllerMonitorPhaseClosed {
		return ControllerMonitorTransitionStopVMRequired, ErrControllerMonitorTerminal
	}
	if observed.used {
		return s.stopLocked(ErrControllerMonitorPrepareFileObservationUsed)
	}
	observed.used = true
	packet := ControllerMonitorPacket{header: observed.header}
	if err := ValidateControllerMonitorReceiveMetadata(packet, metadata, s.expected.MonitorCredential, s.expected.ControllerCredential, s.expected.AgentPID); err != nil {
		return s.stopLocked(err)
	}
	if observed.header.JobIdentityDigest != s.expected.JobIdentityDigest || s.phase != ControllerMonitorPhasePreparing || s.outstanding.requestID == [16]byte{} || s.outstanding.awaitingResponse || observed.header.RequestID != s.outstanding.requestID {
		return s.stopLocked(ErrControllerMonitorCorrelation)
	}
	want := s.nextSequenceLocked(metadata.Direction)
	if want >= MaxControllerMonitorPacketsPerDirection || observed.header.Sequence != want {
		return s.stopLocked(ErrControllerMonitorSequence)
	}
	if s.prepareTransaction == nil {
		return s.stopLocked(ErrControllerMonitorTransition)
	}
	if err := s.prepareTransaction.AcceptObservedFileObservation(s.prepareCorrelation, observed.helper); err != nil {
		return s.stopLocked(err)
	}
	s.advanceLocked(metadata.Direction)
	return ControllerMonitorTransitionContinue, nil
}

func (state *controllerMonitorStateOwner) transitionLocked(packet ControllerMonitorPacket, direction ControllerMonitorDirection, observation int64) (ControllerMonitorTransitionDecision, error) {
	if packet.header.Type == ControllerMonitorPacketTypeCloseNotify {
		return state.acceptCloseLocked(packet, direction)
	}
	if packet.header.Type == ControllerMonitorPacketTypeMonitorEvent {
		return state.acceptEventLocked(packet)
	}
	if packet.header.Type == ControllerMonitorPacketTypeResponse {
		return state.acceptResponseLocked(packet)
	}
	switch state.phase {
	case ControllerMonitorPhaseNativeBootstrap:
		if packet.header.Type != ControllerMonitorPacketTypeMonitorReady || packet.ready != state.expected.MonitorReady {
			return 0, ErrControllerMonitorTransition
		}
		state.phase = ControllerMonitorPhaseReadyTransferred
		return ControllerMonitorTransitionContinue, nil
	case ControllerMonitorPhaseReadyTransferred, ControllerMonitorPhaseRevokeRequired:
		if packet.header.Type == ControllerMonitorPacketTypeRevoke {
			return state.acceptRevokeLocked(packet)
		}
		if state.phase == ControllerMonitorPhaseReadyTransferred && !state.prepareConsumed && packet.header.Type == ControllerMonitorPacketTypePrepareBegin {
			return state.acceptPrepareBeginLocked(packet, observation)
		}
		return 0, ErrControllerMonitorTransition
	case ControllerMonitorPhasePreparing:
		return state.acceptPreparingLocked(packet)
	case ControllerMonitorPhasePrepared:
		if packet.header.Type == ControllerMonitorPacketTypeRevoke {
			return state.acceptRevokeLocked(packet)
		}
		if !state.endpointConsumed && packet.header.Type == ControllerMonitorPacketTypeCreateSSHEndpoint {
			return state.acceptEndpointLocked(packet)
		}
		return 0, ErrControllerMonitorTransition
	case ControllerMonitorPhasePreparedWithEndpoint:
		if packet.header.Type == ControllerMonitorPacketTypeRevoke {
			return state.acceptRevokeLocked(packet)
		}
		return 0, ErrControllerMonitorTransition
	case ControllerMonitorPhaseRevoking:
		if state.outstanding.requestID == [16]byte{} && packet.header.Type == ControllerMonitorPacketTypeRevoke {
			return state.acceptRevokeLocked(packet)
		}
		return 0, ErrControllerMonitorTransition
	default:
		return 0, ErrControllerMonitorTransition
	}
}

func (state *controllerMonitorStateOwner) acceptPrepareBeginLocked(packet ControllerMonitorPacket, observation int64) (ControllerMonitorTransitionDecision, error) {
	if state.outstanding.requestID != [16]byte{} {
		return 0, ErrControllerMonitorOutstandingRequest
	}
	if err := state.useIDLocked(packet.header.RequestID); err != nil {
		return 0, err
	}
	state.prepareConsumed = true
	state.outstanding = controllerMonitorOutstanding{requestType: ControllerMonitorPacketTypePrepareCommit, requestID: packet.header.RequestID}
	if packet.begin.ExpiryUnixNano <= observation || packet.begin.ExpiryUnixNano > state.expected.AuthenticatedSessionHardExpiryUnixNano {
		state.outstanding.awaitingResponse = true
		state.outstanding.operationDenied = true
		return ControllerMonitorTransitionSendOperationDenied, ErrControllerMonitorExpiryWindow
	}
	manifest, err := credentialprotocol.ComputeHelperManifestSHA256(packet.begin.Bindings)
	if err != nil {
		return 0, err
	}
	correlation, err := credentialprotocol.NewHelperPrepareTransactionCorrelation(packet.header.RequestID, packet.header.JobIdentityDigest, packet.begin.Revision, packet.begin.ExpiryUnixNano)
	if err != nil {
		return 0, err
	}
	transaction, err := credentialprotocol.NewHelperPrepareTransaction(correlation, packet.begin, manifest)
	if err != nil {
		return 0, err
	}
	state.prepareCorrelation, state.prepareTransaction, state.manifestSHA256 = correlation, transaction, manifest
	state.manifestCount = uint16(len(packet.begin.Bindings))
	for index := range packet.begin.Bindings {
		state.manifest[index] = packet.begin.Bindings[index]
	}
	state.phase = ControllerMonitorPhasePreparing
	return ControllerMonitorTransitionContinue, nil
}

func (state *controllerMonitorStateOwner) acceptPreparingLocked(packet ControllerMonitorPacket) (ControllerMonitorTransitionDecision, error) {
	if state.outstanding.requestID == [16]byte{} || packet.header.RequestID != state.outstanding.requestID || state.outstanding.awaitingResponse {
		return 0, ErrControllerMonitorCorrelation
	}
	switch packet.header.Type {
	case ControllerMonitorPacketTypePrepareCommit:
		result, err := state.prepareTransaction.Commit(state.prepareCorrelation, packet.commit)
		if err != nil {
			return 0, err
		}
		snapshot := state.prepareTransaction.Snapshot()
		post, err := ControllerMonitorPreparePostinspectionSHA256(state.expected.JobIdentityDigest, 1, state.expected.MonitorReady.MonitorGeneration, state.expected.MonitorReady.MountGeneration, result.ManifestSHA256(), result.TransactionSHA256(), result.FileCount(), snapshot.AcceptedFileBytes)
		if err != nil {
			return 0, err
		}
		state.outstanding.prepare = ControllerMonitorPrepareResult{MountGeneration: state.expected.MonitorReady.MountGeneration, ManifestSHA256: result.ManifestSHA256(), PrepareTransactionSHA256: result.TransactionSHA256(), FileCount: result.FileCount(), AggregateFileBytes: snapshot.AcceptedFileBytes, PreparePostinspectionSHA256: post}
		state.outstanding.awaitingResponse = true
		return ControllerMonitorTransitionContinue, nil
	default:
		return 0, ErrControllerMonitorTransition
	}
}

func (state *controllerMonitorStateOwner) acceptEndpointLocked(packet ControllerMonitorPacket) (ControllerMonitorTransitionDecision, error) {
	if state.outstanding.requestID != [16]byte{} {
		return 0, ErrControllerMonitorOutstandingRequest
	}
	if err := state.useIDLocked(packet.header.RequestID); err != nil {
		return 0, err
	}
	state.endpointConsumed = true
	if packet.ssh.ManifestSHA256 != state.manifestSHA256 || int(packet.ssh.BindingIndex) >= int(state.manifestCount) {
		return 0, ErrControllerMonitorCorrelation
	}
	binding := state.manifest[packet.ssh.BindingIndex]
	if binding.Mode != credentialprotocol.DeliveryModeSSHAgent || binding.BindingID != packet.ssh.BindingID {
		return 0, ErrControllerMonitorCorrelation
	}
	digest, err := ControllerMonitorEndpointConfigSHA256(state.expected.JobIdentityDigest, 1, packet.ssh.BindingIndex, packet.ssh.BindingID, packet.ssh.EndpointGeneration, state.expected.MonitorReady.MountGeneration, state.manifestSHA256)
	if err != nil || digest != packet.ssh.EndpointConfigSHA256 {
		return 0, ErrControllerMonitorCorrelation
	}
	state.outstanding = controllerMonitorOutstanding{requestType: ControllerMonitorPacketTypeCreateSSHEndpoint, requestID: packet.header.RequestID, awaitingResponse: true, endpoint: packet.ssh}
	return ControllerMonitorTransitionContinue, nil
}

func (state *controllerMonitorStateOwner) acceptRevokeLocked(packet ControllerMonitorPacket) (ControllerMonitorTransitionDecision, error) {
	if state.outstanding.requestID != [16]byte{} {
		return 0, ErrControllerMonitorOutstandingRequest
	}
	if state.cleanupAttempts >= 3 {
		return 0, ErrControllerMonitorCleanupAttempts
	}
	if err := state.useIDLocked(packet.header.RequestID); err != nil {
		return 0, err
	}
	state.cleanupAttempts++
	state.outstanding = controllerMonitorOutstanding{requestType: ControllerMonitorPacketTypeRevoke, requestID: packet.header.RequestID, awaitingResponse: true, revokeReason: packet.revoke.Reason}
	state.phase = ControllerMonitorPhaseRevoking
	return ControllerMonitorTransitionContinue, nil
}

func (state *controllerMonitorStateOwner) acceptResponseLocked(packet ControllerMonitorPacket) (ControllerMonitorTransitionDecision, error) {
	if state.outstanding.requestID == [16]byte{} || !state.outstanding.awaitingResponse || packet.header.RequestID != state.outstanding.requestID || packet.response.requestType != state.outstanding.requestType {
		return 0, ErrControllerMonitorCorrelation
	}
	response := packet.response
	disposition := response.disposition
	if state.outstanding.forceStop && disposition != credentialprotocol.ResponseDispositionStopVMRequired {
		return 0, ErrControllerMonitorResponse
	}
	if state.outstanding.operationDenied {
		if disposition != credentialprotocol.ResponseDispositionRejected || response.failure != ControllerMonitorFailureOperationDenied {
			return 0, ErrControllerMonitorResponse
		}
		requestType := state.outstanding.requestType
		hadIndependentExpiry := state.hasPending
		if requestType == ControllerMonitorPacketTypePrepareCommit {
			state.phase = ControllerMonitorPhaseReadyTransferred
		} else {
			state.phase = ControllerMonitorPhasePrepared
		}
		state.outstanding = controllerMonitorOutstanding{}
		state.pending = ControllerMonitorPendingEvent{}
		state.hasPending = false
		if requestType == ControllerMonitorPacketTypePrepareCommit {
			state.clearPrepareLocked()
		}
		if hadIndependentExpiry {
			state.phase = ControllerMonitorPhaseRevokeRequired
		}
		return ControllerMonitorTransitionContinue, nil
	}
	switch state.outstanding.requestType {
	case ControllerMonitorPacketTypePrepareCommit:
		if disposition == credentialprotocol.ResponseDispositionAccepted {
			result, ok := response.PrepareResult()
			if !ok || result != state.outstanding.prepare {
				return 0, ErrControllerMonitorCorrelation
			}
			state.phase = ControllerMonitorPhasePrepared
		} else if disposition == credentialprotocol.ResponseDispositionRejected {
			state.phase = ControllerMonitorPhaseReadyTransferred
		} else if disposition == credentialprotocol.ResponseDispositionStopVMRequired {
			state.phase = ControllerMonitorPhaseTerminal
		} else {
			return 0, ErrControllerMonitorResponse
		}
	case ControllerMonitorPacketTypeCreateSSHEndpoint:
		if disposition == credentialprotocol.ResponseDispositionAccepted {
			result, ok := response.SSHEndpointResult()
			if !ok || result.BindingIndex != state.outstanding.endpoint.BindingIndex || result.BindingID != state.outstanding.endpoint.BindingID || result.EndpointGeneration != state.outstanding.endpoint.EndpointGeneration {
				return 0, ErrControllerMonitorCorrelation
			}
			digest, err := ControllerMonitorEndpointSHA256(state.expected.JobIdentityDigest, state.outstanding.endpoint.EndpointConfigSHA256, result.EndpointGeneration, state.expected.MonitorReady.MonitorGeneration, state.expected.MonitorReady.MountGeneration)
			if err != nil || digest != result.EndpointSHA256 {
				return 0, ErrControllerMonitorCorrelation
			}
			state.endpointGeneration = result.EndpointGeneration
			state.phase = ControllerMonitorPhasePreparedWithEndpoint
		} else if disposition == credentialprotocol.ResponseDispositionRejected {
			state.phase = ControllerMonitorPhasePrepared
		} else if disposition == credentialprotocol.ResponseDispositionStopVMRequired {
			state.phase = ControllerMonitorPhaseTerminal
		} else {
			return 0, ErrControllerMonitorResponse
		}
	case ControllerMonitorPacketTypeRevoke:
		if disposition == credentialprotocol.ResponseDispositionCleanupComplete {
			result, ok := response.RevokeResult()
			if !ok {
				return 0, ErrControllerMonitorCorrelation
			}
			digest, err := ControllerMonitorCleanupSHA256(state.expected.JobIdentityDigest, 1, state.outstanding.revokeReason, state.expected.MonitorReady.MonitorGeneration, state.expected.MonitorReady.MountGeneration, state.endpointGeneration, true, true, true)
			if err != nil || digest != result.CleanupSHA256 {
				return 0, ErrControllerMonitorCorrelation
			}
			state.phase = ControllerMonitorPhaseCleanupReported
		} else if disposition == credentialprotocol.ResponseDispositionCleanupRetry {
			state.phase = ControllerMonitorPhaseRevoking
		} else if disposition == credentialprotocol.ResponseDispositionStopVMRequired {
			state.phase = ControllerMonitorPhaseTerminal
		} else {
			return 0, ErrControllerMonitorResponse
		}
	default:
		return 0, ErrControllerMonitorResponse
	}
	state.outstanding = controllerMonitorOutstanding{}
	if state.phase == ControllerMonitorPhaseTerminal {
		state.clearPrepareLocked()
		state.hasPending = false
		return ControllerMonitorTransitionStopVMRequired, nil
	}
	if state.hasPending {
		if response.failure == ControllerMonitorFailureOperationDenied {
			state.hasPending = false
			state.pending = ControllerMonitorPendingEvent{}
			state.phase = ControllerMonitorPhaseRevokeRequired
		} else {
			state.phase = ControllerMonitorPhaseRevokeRequired
			return ControllerMonitorTransitionSendOutstandingResultBeforePendingEvent, nil
		}
	}
	if state.prepareConsumed && state.phase == ControllerMonitorPhaseReadyTransferred {
		state.clearPrepareLocked()
	}
	return ControllerMonitorTransitionContinue, nil
}

func (state *ControllerMonitorState) Observe(observation ControllerMonitorLocalObservation) (ControllerMonitorTransitionDecision, error) {
	s, err := state.stateOwner()
	if err != nil {
		return ControllerMonitorTransitionStopVMRequired, ErrControllerMonitorTerminal
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == ControllerMonitorPhaseTerminal || s.phase == ControllerMonitorPhaseClosed {
		return ControllerMonitorTransitionStopVMRequired, ErrControllerMonitorTerminal
	}
	if observation.kind < controllerMonitorObservationExpired || observation.kind > controllerMonitorObservationCleanupStop || controllerMonitorZero16(observation.requestID) {
		return s.stopLocked(ErrControllerMonitorObservation)
	}
	if s.hasPending {
		return s.stopLocked(ErrControllerMonitorPendingEvent)
	}
	if !s.observationLegalLocked(observation.kind) {
		return s.stopLocked(ErrControllerMonitorObservation)
	}
	if s.phase == ControllerMonitorPhaseRevoking && s.outstanding.requestID != [16]byte{} {
		if observation.kind == controllerMonitorObservationExpired || observation.kind == controllerMonitorObservationCleanupRetry {
			return ControllerMonitorTransitionContinue, nil
		}
		s.outstanding.forceStop = true
		return ControllerMonitorTransitionContinue, nil
	}
	if s.phase == ControllerMonitorPhaseRevoking && (observation.kind == controllerMonitorObservationExpired || observation.kind == controllerMonitorObservationCleanupRetry) {
		return ControllerMonitorTransitionContinue, nil
	}
	if s.outstanding.requestID != [16]byte{} {
		switch observation.kind {
		case controllerMonitorObservationExpired:
			if s.phase == ControllerMonitorPhasePreparing && !s.outstanding.awaitingResponse {
				s.outstanding.operationDenied = true
				s.outstanding.awaitingResponse = true
				s.phase = ControllerMonitorPhaseReadyTransferred
				s.clearPrepareLocked()
				return ControllerMonitorTransitionSendOperationDenied, nil
			}
		case controllerMonitorObservationMountDrift, controllerMonitorObservationEndpointDrift, controllerMonitorObservationCleanupStop:
			s.outstanding.forceStop = true
			s.outstanding.awaitingResponse = true
			return ControllerMonitorTransitionContinue, nil
		default:
			return s.stopLocked(ErrControllerMonitorObservation)
		}
	}
	if err := s.useIDLocked(observation.requestID); err != nil {
		return s.stopLocked(err)
	}
	body, err := s.eventForObservationLocked(observation)
	if err != nil {
		return s.stopLocked(err)
	}
	s.pending = ControllerMonitorPendingEvent{RequestID: observation.requestID, Body: body}
	s.hasPending = true
	if s.outstanding.requestID != [16]byte{} {
		s.phase = ControllerMonitorPhaseRevokeRequired
		return ControllerMonitorTransitionContinue, nil
	}
	if observation.kind == controllerMonitorObservationMountDrift || observation.kind == controllerMonitorObservationEndpointDrift || observation.kind == controllerMonitorObservationCleanupStop {
		s.phase = ControllerMonitorPhaseStopPendingEvent
	} else {
		s.phase = ControllerMonitorPhaseRevokeRequired
	}
	return ControllerMonitorTransitionPendingEventSendable, nil
}

func (state *controllerMonitorStateOwner) observationLegalLocked(kind controllerMonitorObservationKind) bool {
	switch kind {
	case controllerMonitorObservationExpired:
		return state.phase == ControllerMonitorPhaseReadyTransferred || state.phase == ControllerMonitorPhasePreparing || state.phase == ControllerMonitorPhasePrepared || state.phase == ControllerMonitorPhasePreparedWithEndpoint || state.phase == ControllerMonitorPhaseRevoking
	case controllerMonitorObservationMountDrift:
		return state.phase == ControllerMonitorPhasePreparing || state.phase == ControllerMonitorPhasePrepared || state.phase == ControllerMonitorPhasePreparedWithEndpoint || state.phase == ControllerMonitorPhaseRevoking
	case controllerMonitorObservationEndpointDrift:
		return state.phase == ControllerMonitorPhasePreparedWithEndpoint || state.phase == ControllerMonitorPhaseRevoking
	case controllerMonitorObservationCleanupRetry:
		return state.outstanding.requestID == [16]byte{} && (state.phase == ControllerMonitorPhaseReadyTransferred || state.phase == ControllerMonitorPhasePrepared || state.phase == ControllerMonitorPhasePreparedWithEndpoint) || state.phase == ControllerMonitorPhaseRevoking
	case controllerMonitorObservationCleanupStop:
		return state.phase == ControllerMonitorPhaseReadyTransferred || state.phase == ControllerMonitorPhasePreparing || state.phase == ControllerMonitorPhasePrepared || state.phase == ControllerMonitorPhasePreparedWithEndpoint || state.phase == ControllerMonitorPhaseRevoking
	default:
		return false
	}
}

func (state *controllerMonitorStateOwner) eventForObservationLocked(observation ControllerMonitorLocalObservation) (ControllerMonitorEventBody, error) {
	var event ControllerMonitorEventCode
	var failure ControllerMonitorFailureCode
	var cleanup ControllerMonitorCleanupCategory
	switch observation.kind {
	case controllerMonitorObservationExpired:
		event, failure, cleanup = ControllerMonitorEventExpired, ControllerMonitorFailureOperationDenied, ControllerMonitorCleanupRetryRequired
	case controllerMonitorObservationMountDrift:
		event, failure, cleanup = ControllerMonitorEventMountDrift, ControllerMonitorFailureInspectionFailed, ControllerMonitorCleanupStopVMRequired
	case controllerMonitorObservationEndpointDrift:
		if state.endpointGeneration == "" || state.phase != ControllerMonitorPhasePreparedWithEndpoint && state.phase != ControllerMonitorPhaseRevoking {
			return ControllerMonitorEventBody{}, ErrControllerMonitorObservation
		}
		event, failure, cleanup = ControllerMonitorEventEndpointDrift, ControllerMonitorFailureInspectionFailed, ControllerMonitorCleanupStopVMRequired
	case controllerMonitorObservationCleanupRetry:
		event, failure, cleanup = ControllerMonitorEventCleanupRequired, ControllerMonitorFailureCleanupIncomplete, ControllerMonitorCleanupRetryRequired
	case controllerMonitorObservationCleanupStop:
		event, failure, cleanup = ControllerMonitorEventCleanupRequired, ControllerMonitorFailureCleanupIncomplete, ControllerMonitorCleanupStopVMRequired
	}
	digest, err := ControllerMonitorEventPostinspectionSHA256(state.expected.JobIdentityDigest, event, failure, cleanup, 1, observation.requestID, state.expected.MonitorReady.MonitorGeneration, state.expected.MonitorReady.MountGeneration)
	if err != nil {
		return ControllerMonitorEventBody{}, err
	}
	return ControllerMonitorEventBody{EventCode: event, FailureCode: failure, CleanupCategory: cleanup, Revision: 1, EventID: controllerMonitorEventID(observation.requestID), MountGeneration: state.expected.MonitorReady.MountGeneration, PostinspectionSHA256: digest}, nil
}

func (state *controllerMonitorStateOwner) acceptEventLocked(packet ControllerMonitorPacket) (ControllerMonitorTransitionDecision, error) {
	if !state.hasPending || packet.header.RequestID != state.pending.RequestID || packet.event != state.pending.Body || state.outstanding.requestID != [16]byte{} {
		return 0, ErrControllerMonitorPendingEvent
	}
	state.hasPending = false
	state.pending = ControllerMonitorPendingEvent{}
	if state.phase == ControllerMonitorPhaseStopPendingEvent {
		state.phase = ControllerMonitorPhaseTerminal
		return ControllerMonitorTransitionStopVMRequired, nil
	}
	return ControllerMonitorTransitionContinue, nil
}

func (state *controllerMonitorStateOwner) acceptCloseLocked(packet ControllerMonitorPacket, direction ControllerMonitorDirection) (ControllerMonitorTransitionDecision, error) {
	if packet.close.Reason != credentialprotocol.CloseReasonNormal {
		return 0, ErrControllerMonitorTransition
	}
	if state.phase == ControllerMonitorPhaseCleanupReported && direction == ControllerMonitorDirectionMonitorToController {
		state.phase = ControllerMonitorPhaseCloseWait
		return ControllerMonitorTransitionSendNormalClose, nil
	}
	if state.phase == ControllerMonitorPhaseCloseWait && direction == ControllerMonitorDirectionControllerToMonitor {
		state.phase = ControllerMonitorPhaseClosed
		state.clearPrepareLocked()
		return ControllerMonitorTransitionClosedClean, nil
	}
	return 0, ErrControllerMonitorTransition
}

func (state *ControllerMonitorState) PendingEvent() (ControllerMonitorPendingEvent, bool) {
	s, err := state.stateOwner()
	if err != nil {
		return ControllerMonitorPendingEvent{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pending, s.hasPending
}
func (state *ControllerMonitorState) Snapshot() ControllerMonitorSnapshot {
	s, err := state.stateOwner()
	if err != nil {
		return ControllerMonitorSnapshot{Phase: ControllerMonitorPhaseTerminal}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return ControllerMonitorSnapshot{Phase: s.phase, NextControllerSend: s.nextController, NextMonitorSend: s.nextMonitor, PrepareConsumed: s.prepareConsumed, EndpointConsumed: s.endpointConsumed, RequestOutstanding: s.outstanding.requestID != [16]byte{}, PendingEvent: s.hasPending, CleanupAttempts: s.cleanupAttempts}
}
func (state *ControllerMonitorState) Decision() ControllerMonitorTransitionDecision {
	s, err := state.stateOwner()
	if err != nil {
		return ControllerMonitorTransitionStopVMRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == ControllerMonitorPhaseTerminal {
		return ControllerMonitorTransitionStopVMRequired
	}
	if s.phase == ControllerMonitorPhaseClosed {
		return ControllerMonitorTransitionClosedClean
	}
	if s.hasPending {
		return ControllerMonitorTransitionPendingEventSendable
	}
	return ControllerMonitorTransitionContinue
}
func (state *ControllerMonitorState) SendFailed() {
	s, err := state.stateOwner()
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopNoErrorLocked()
}
func (state *ControllerMonitorState) Lost() ControllerMonitorTransitionDecision {
	s, err := state.stateOwner()
	if err != nil {
		return ControllerMonitorTransitionStopVMRequired
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.phase == ControllerMonitorPhaseClosed {
		return ControllerMonitorTransitionClosedClean
	}
	s.stopNoErrorLocked()
	return ControllerMonitorTransitionStopVMRequired
}

func (state *ControllerMonitorState) stateOwner() (*controllerMonitorStateOwner, error) {
	if state == nil || state.owner == nil {
		return nil, ErrControllerMonitorTerminal
	}
	return state.owner, nil
}

func (state *controllerMonitorStateOwner) useIDLocked(id [16]byte) error {
	if controllerMonitorZero16(id) {
		return ErrControllerMonitorRequestIdentity
	}
	for index := uint8(0); index < state.usedIDCount; index++ {
		if state.usedIDs[index] == id {
			return ErrControllerMonitorRequestReuse
		}
	}
	if state.usedIDCount >= maxControllerMonitorTrackedIDs {
		return ErrControllerMonitorRequestReuse
	}
	state.usedIDs[state.usedIDCount] = id
	state.usedIDCount++
	return nil
}
func (state *controllerMonitorStateOwner) nextSequenceLocked(direction ControllerMonitorDirection) uint64 {
	if direction == ControllerMonitorDirectionControllerToMonitor {
		return state.nextController
	}
	return state.nextMonitor
}
func (state *controllerMonitorStateOwner) advanceLocked(direction ControllerMonitorDirection) {
	if direction == ControllerMonitorDirectionControllerToMonitor {
		state.nextController++
	} else {
		state.nextMonitor++
	}
}
func (state *controllerMonitorStateOwner) clearPrepareLocked() {
	if state.prepareTransaction != nil {
		state.prepareTransaction.Close()
	}
	state.prepareTransaction = nil
	state.prepareCorrelation = credentialprotocol.HelperPrepareTransactionCorrelation{}
	clear(state.manifest[:])
	state.manifestCount = 0
	state.manifestSHA256 = [32]byte{}
}
func (state *controllerMonitorStateOwner) stopNoErrorLocked() {
	state.phase = ControllerMonitorPhaseTerminal
	state.outstanding = controllerMonitorOutstanding{}
	state.pending = ControllerMonitorPendingEvent{}
	state.hasPending = false
	state.clearPrepareLocked()
}
func (state *controllerMonitorStateOwner) stopLocked(err error) (ControllerMonitorTransitionDecision, error) {
	state.stopNoErrorLocked()
	return ControllerMonitorTransitionStopVMRequired, err
}
