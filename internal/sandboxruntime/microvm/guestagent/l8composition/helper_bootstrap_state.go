package l8composition

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialprotocol"
)

var (
	ErrHelperBootstrapStateSerialization    = errors.New("L8 helper bootstrap state serialization is denied")
	ErrHelperBootstrapPeerIdentity          = errors.New("L8 helper bootstrap peer identity is invalid")
	ErrHelperBootstrapRoleIdentityAlias     = errors.New("L8 helper bootstrap role identities alias")
	ErrHelperBootstrapDirection             = errors.New("L8 helper bootstrap direction is invalid")
	ErrHelperBootstrapPacketDirection       = errors.New("L8 helper bootstrap packet direction is invalid")
	ErrHelperBootstrapReceiveTruncated      = errors.New("L8 helper bootstrap receive metadata reports truncation")
	ErrHelperBootstrapCredentialCount       = errors.New("L8 helper bootstrap kernel credential count is invalid")
	ErrHelperBootstrapKernelCredential      = errors.New("L8 helper bootstrap kernel credential does not match")
	ErrHelperBootstrapRights                = errors.New("L8 helper bootstrap ancillary rights are invalid")
	ErrHelperBootstrapRightKind             = errors.New("L8 helper bootstrap ancillary right kind is invalid")
	ErrHelperBootstrapRightIdentity         = errors.New("L8 helper bootstrap ancillary right identity does not match")
	ErrHelperBootstrapStateSequence         = errors.New("L8 helper bootstrap state sequence is invalid")
	ErrHelperBootstrapStateSequenceWrap     = errors.New("L8 helper bootstrap state sequence would wrap")
	ErrHelperBootstrapTransition            = errors.New("L8 helper bootstrap pre-admission transition is invalid")
	ErrHelperBootstrapPacketAfterCompletion = errors.New("L8 helper bootstrap packet arrived after handshake completion")
	ErrHelperBootstrapStateTerminal         = errors.New("L8 helper bootstrap pre-admission state is terminal")
)

// HelperBootstrapDirection is authenticated sender-to-receiver metadata. PID1
// and agent directions share the helper receive counter; helper directions
// share the helper send counter across the PID1-to-agent handoff.
type HelperBootstrapDirection uint8

const (
	HelperBootstrapDirectionHelperToPID1  HelperBootstrapDirection = 1
	HelperBootstrapDirectionPID1ToHelper  HelperBootstrapDirection = 2
	HelperBootstrapDirectionAgentToHelper HelperBootstrapDirection = 3
	HelperBootstrapDirectionHelperToAgent HelperBootstrapDirection = 4
)

// HelperBootstrapDecision is the complete pre-admission disposition.
type HelperBootstrapDecision uint8

const (
	HelperBootstrapDecisionContinue HelperBootstrapDecision = 1
	HelperBootstrapDecisionComplete HelperBootstrapDecision = 2
	HelperBootstrapDecisionStopVM   HelperBootstrapDecision = 3
)

// HelperBootstrapRightKind is the closed pre-admission rights catalog.
type HelperBootstrapRightKind uint8

const (
	HelperBootstrapRightAgentPIDFD HelperBootstrapRightKind = 1
)

// HelperBootstrapKernelCredential is already-inspected kernel metadata. It is
// not a live credential or process-inspection authority.
type HelperBootstrapKernelCredential struct {
	PID uint32
	UID uint32
	GID uint32
}

// HelperBootstrapRight describes the sole already-inspected bootstrap right.
// AgentPID is correlation metadata and never a numeric descriptor value.
type HelperBootstrapRight struct {
	Kind     HelperBootstrapRightKind
	AgentPID uint32
}

// HelperBootstrapReceiveMetadata contains full-width ancillary cardinalities.
// Right is populated only when RightsCount is exactly one.
type HelperBootstrapReceiveMetadata struct {
	Direction        HelperBootstrapDirection
	Credential       HelperBootstrapKernelCredential
	CredentialCount  uint32
	RightsCount      uint32
	Right            HelperBootstrapRight
	MessageTruncated bool
	ControlTruncated bool
}

// HelperBootstrapPreAdmissionExpected is sealed caller-owned correlation.
type HelperBootstrapPreAdmissionExpected struct {
	PID1Credential   HelperBootstrapKernelCredential
	HelperCredential HelperBootstrapKernelCredential
	AgentCredential  HelperBootstrapKernelCredential
	Bootstrap        HelperBootstrapExpected
	ClientDescriptor ProcessDescriptor
}

type helperBootstrapStatePhase uint8

const (
	helperBootstrapStateReady helperBootstrapStatePhase = iota + 1
	helperBootstrapStateBootstrap
	helperBootstrapStateAck
	helperBootstrapStateHello
	helperBootstrapStateHelloAck
	helperBootstrapStateComplete
	helperBootstrapStateStopped
)

type helperBootstrapStateData struct {
	mu                   sync.Mutex
	phase                helperBootstrapStatePhase
	pid1Credential       HelperBootstrapKernelCredential
	helperCredential     HelperBootstrapKernelCredential
	agentCredential      HelperBootstrapKernelCredential
	bootstrap            HelperBootstrapExpected
	clientDescriptor     ProcessDescriptor
	clientDescriptorWire []byte
	bootstrapSHA256      [sha256.Size]byte
	nextReceive          uint64
	nextSend             uint64
}

// HelperBootstrapPreAdmissionState is a pure deterministic verifier. Copies
// share one synchronized terminal state rather than forking protocol authority.
type HelperBootstrapPreAdmissionState struct {
	state *helperBootstrapStateData
}

// NewHelperBootstrapPreAdmissionState validates and snapshots all expected
// identities, generations, nonce, and the canonical client descriptor.
func NewHelperBootstrapPreAdmissionState(expected HelperBootstrapPreAdmissionExpected) (*HelperBootstrapPreAdmissionState, error) {
	if !validHelperBootstrapPID1Credential(expected.PID1Credential) ||
		!validHelperBootstrapControllerCredential(expected.HelperCredential) ||
		!validHelperBootstrapAgentCredential(expected.AgentCredential) {
		return nil, ErrHelperBootstrapPeerIdentity
	}
	if err := validateHelperBootstrapExpected(expected.Bootstrap); err != nil {
		return nil, err
	}
	if expected.AgentCredential.PID != expected.Bootstrap.AgentPID ||
		expected.AgentCredential.UID != expected.Bootstrap.AgentUID ||
		expected.AgentCredential.GID != expected.Bootstrap.AgentGID {
		return nil, ErrHelperBootstrapAgentIdentityMismatch
	}
	if expected.HelperCredential.PID == expected.AgentCredential.PID {
		return nil, ErrHelperBootstrapRoleIdentityAlias
	}
	descriptorWire, err := canonicalClientDescriptor(expected.ClientDescriptor)
	if err != nil {
		return nil, err
	}
	return &HelperBootstrapPreAdmissionState{state: &helperBootstrapStateData{
		phase:                helperBootstrapStateReady,
		pid1Credential:       expected.PID1Credential,
		helperCredential:     expected.HelperCredential,
		agentCredential:      expected.AgentCredential,
		bootstrap:            expected.Bootstrap,
		clientDescriptor:     cloneAgentSupervisorDescriptor(expected.ClientDescriptor),
		clientDescriptorWire: append([]byte(nil), descriptorWire...),
	}}, nil
}

// ValidateHelperBootstrapDirection rejects unknown logical endpoints.
func ValidateHelperBootstrapDirection(direction HelperBootstrapDirection) error {
	switch direction {
	case HelperBootstrapDirectionHelperToPID1, HelperBootstrapDirectionPID1ToHelper,
		HelperBootstrapDirectionAgentToHelper, HelperBootstrapDirectionHelperToAgent:
		return nil
	default:
		return ErrHelperBootstrapDirection
	}
}

// ValidateHelperBootstrapRightKind accepts only the authenticated agent pidfd
// catalog entry used by bootstrap.
func ValidateHelperBootstrapRightKind(kind HelperBootstrapRightKind) error {
	if kind != HelperBootstrapRightAgentPIDFD {
		return ErrHelperBootstrapRightKind
	}
	return nil
}

// Accept authenticates one complete datagram and advances only the locked
// helper-ready/bootstrap/ack/hello/ack transition. Every failure is terminal.
// PID1StartGateState must release before agent_hello. That cross-protocol
// precondition is outside HL8P; completion here does not claim global
// composition or admission.
func (machine *HelperBootstrapPreAdmissionState) Accept(metadata HelperBootstrapReceiveMetadata, encoded []byte) (HelperBootstrapDecision, error) {
	if machine == nil || machine.state == nil {
		return HelperBootstrapDecisionStopVM, ErrHelperBootstrapStateTerminal
	}
	state := machine.state
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.phase == helperBootstrapStateComplete {
		state.phase = helperBootstrapStateStopped
		return HelperBootstrapDecisionStopVM, ErrHelperBootstrapPacketAfterCompletion
	}
	if state.phase == helperBootstrapStateStopped {
		return HelperBootstrapDecisionStopVM, ErrHelperBootstrapStateTerminal
	}
	if metadata.MessageTruncated || metadata.ControlTruncated {
		return state.stop(ErrHelperBootstrapReceiveTruncated)
	}
	if err := ValidateHelperBootstrapDirection(metadata.Direction); err != nil {
		return state.stop(err)
	}
	if metadata.CredentialCount != 1 {
		return state.stop(ErrHelperBootstrapCredentialCount)
	}
	if !state.credentialMatches(metadata.Direction, metadata.Credential) {
		return state.stop(ErrHelperBootstrapKernelCredential)
	}
	header, err := credentialprotocol.ValidateHelperPacketDatagram(encoded)
	if err != nil {
		return state.stop(err)
	}
	if err := validateHelperBootstrapPacketDirection(header.Type, metadata.Direction); err != nil {
		return state.stop(err)
	}
	if err := state.validateRights(header.Type, metadata); err != nil {
		return state.stop(err)
	}
	expectedSequence := state.nextSequence(metadata.Direction)
	if header.Sequence != expectedSequence {
		return state.stop(ErrHelperBootstrapStateSequence)
	}
	if header.Sequence == ^uint64(0) {
		return state.stop(ErrHelperBootstrapStateSequenceWrap)
	}
	body := encoded[credentialprotocol.HelperPacketHeaderSize:]
	if err := state.acceptTransition(header, body); err != nil {
		return state.stop(err)
	}
	state.advance(metadata.Direction)
	if state.phase == helperBootstrapStateComplete {
		return HelperBootstrapDecisionComplete, nil
	}
	return HelperBootstrapDecisionContinue, nil
}

func (state *helperBootstrapStateData) acceptTransition(header credentialprotocol.HelperPacketHeader, encoded []byte) error {
	switch state.phase {
	case helperBootstrapStateReady:
		if header.Type != credentialprotocol.PacketTypeHelperReady {
			return ErrHelperBootstrapTransition
		}
		if _, err := DecodeHelperReadyBody(encoded); err != nil {
			return err
		}
		if err := ValidateHelperReadyCorrelation(header); err != nil {
			return err
		}
		state.phase = helperBootstrapStateBootstrap
	case helperBootstrapStateBootstrap:
		if header.Type != credentialprotocol.PacketTypeBootstrap {
			return ErrHelperBootstrapTransition
		}
		body, err := DecodeHelperBootstrapBody(encoded)
		if err != nil {
			return err
		}
		digest, err := ComputeHelperBootstrapSHA256(header, body, state.bootstrap)
		if err != nil {
			return err
		}
		state.bootstrapSHA256 = digest
		state.phase = helperBootstrapStateAck
	case helperBootstrapStateAck:
		if header.Type != credentialprotocol.PacketTypeBootstrapAck {
			return ErrHelperBootstrapTransition
		}
		body, err := DecodeHelperBootstrapAckBody(encoded)
		if err != nil {
			return err
		}
		if err := ValidateHelperBootstrapAckCorrelation(header, body, state.bootstrap.BootNonce, state.bootstrapSHA256); err != nil {
			return err
		}
		state.phase = helperBootstrapStateHello
	case helperBootstrapStateHello:
		if header.Type != credentialprotocol.PacketTypeAgentHello {
			return ErrHelperBootstrapTransition
		}
		body, err := DecodeHelperAgentHelloBody(encoded)
		if err != nil {
			return err
		}
		actualWire, encodeErr := canonicalClientDescriptor(body.Descriptor)
		if encodeErr != nil || !bytes.Equal(actualWire, state.clientDescriptorWire) {
			return ErrHelperBootstrapDescriptorMismatch
		}
		if err := ValidateHelperAgentHelloCorrelation(header, body, state.bootstrap.BootNonce, state.bootstrapSHA256,
			state.bootstrap.BootGeneration, state.bootstrap.HelperGeneration, state.clientDescriptor); err != nil {
			return err
		}
		state.phase = helperBootstrapStateHelloAck
	case helperBootstrapStateHelloAck:
		if header.Type != credentialprotocol.PacketTypeAgentHelloAck {
			return ErrHelperBootstrapTransition
		}
		body, err := DecodeHelperAgentHelloAckBody(encoded)
		if err != nil {
			return err
		}
		if err := ValidateHelperAgentHelloAckCorrelation(header, body, state.bootstrap.BootNonce, state.bootstrapSHA256); err != nil {
			return err
		}
		state.phase = helperBootstrapStateComplete
	default:
		return ErrHelperBootstrapStateTerminal
	}
	return nil
}

func validateHelperBootstrapPacketDirection(packetType credentialprotocol.PacketType, direction HelperBootstrapDirection) error {
	valid := false
	switch packetType {
	case credentialprotocol.PacketTypeHelperReady, credentialprotocol.PacketTypeBootstrapAck:
		valid = direction == HelperBootstrapDirectionHelperToPID1
	case credentialprotocol.PacketTypeBootstrap:
		valid = direction == HelperBootstrapDirectionPID1ToHelper
	case credentialprotocol.PacketTypeAgentHello:
		valid = direction == HelperBootstrapDirectionAgentToHelper
	case credentialprotocol.PacketTypeAgentHelloAck:
		valid = direction == HelperBootstrapDirectionHelperToAgent
	}
	if !valid {
		return ErrHelperBootstrapPacketDirection
	}
	return nil
}

func (state *helperBootstrapStateData) validateRights(packetType credentialprotocol.PacketType, metadata HelperBootstrapReceiveMetadata) error {
	zeroRight := metadata.Right == (HelperBootstrapRight{})
	if packetType != credentialprotocol.PacketTypeBootstrap {
		if metadata.RightsCount != 0 || !zeroRight {
			return ErrHelperBootstrapRights
		}
		return nil
	}
	if metadata.RightsCount != 1 {
		return ErrHelperBootstrapRights
	}
	if err := ValidateHelperBootstrapRightKind(metadata.Right.Kind); err != nil {
		return err
	}
	if metadata.Right.AgentPID != state.agentCredential.PID {
		return ErrHelperBootstrapRightIdentity
	}
	return nil
}

func (state *helperBootstrapStateData) credentialMatches(direction HelperBootstrapDirection, actual HelperBootstrapKernelCredential) bool {
	switch direction {
	case HelperBootstrapDirectionPID1ToHelper:
		return actual == state.pid1Credential
	case HelperBootstrapDirectionAgentToHelper:
		return actual == state.agentCredential
	case HelperBootstrapDirectionHelperToPID1, HelperBootstrapDirectionHelperToAgent:
		return actual == state.helperCredential
	default:
		return false
	}
}

func (state *helperBootstrapStateData) nextSequence(direction HelperBootstrapDirection) uint64 {
	if direction == HelperBootstrapDirectionPID1ToHelper || direction == HelperBootstrapDirectionAgentToHelper {
		return state.nextReceive
	}
	return state.nextSend
}

func (state *helperBootstrapStateData) advance(direction HelperBootstrapDirection) {
	if direction == HelperBootstrapDirectionPID1ToHelper || direction == HelperBootstrapDirectionAgentToHelper {
		state.nextReceive++
	} else {
		state.nextSend++
	}
}

func (state *helperBootstrapStateData) stop(err error) (HelperBootstrapDecision, error) {
	state.phase = helperBootstrapStateStopped
	return HelperBootstrapDecisionStopVM, err
}

// Lost permanently requires whole-VM stop before admission.
func (machine *HelperBootstrapPreAdmissionState) Lost() HelperBootstrapDecision {
	if machine == nil || machine.state == nil {
		return HelperBootstrapDecisionStopVM
	}
	machine.state.mu.Lock()
	machine.state.phase = helperBootstrapStateStopped
	machine.state.mu.Unlock()
	return HelperBootstrapDecisionStopVM
}

// Decision returns the current fail-closed disposition.
func (machine *HelperBootstrapPreAdmissionState) Decision() HelperBootstrapDecision {
	if machine == nil || machine.state == nil {
		return HelperBootstrapDecisionStopVM
	}
	machine.state.mu.Lock()
	defer machine.state.mu.Unlock()
	switch machine.state.phase {
	case helperBootstrapStateComplete:
		return HelperBootstrapDecisionComplete
	case helperBootstrapStateStopped:
		return HelperBootstrapDecisionStopVM
	default:
		return HelperBootstrapDecisionContinue
	}
}

func validHelperBootstrapPID1Credential(value HelperBootstrapKernelCredential) bool {
	return value.PID == 1 && value.UID == 0 && value.GID == 0
}

func validHelperBootstrapControllerCredential(value HelperBootstrapKernelCredential) bool {
	return validHelperBootstrapPID(value.PID) && value.UID == 0 && value.GID == 0
}

func validHelperBootstrapAgentCredential(value HelperBootstrapKernelCredential) bool {
	return validHelperBootstrapPID(value.PID) && value.UID == HelperAgentServiceUID && value.GID == HelperAgentServiceGID
}

func helperBootstrapStateFormat(state fmt.State, name string) { _, _ = state.Write([]byte(name)) }

func (HelperBootstrapDirection) Format(state fmt.State, _ rune) {
	helperBootstrapStateFormat(state, "HelperBootstrapDirection")
}
func (HelperBootstrapDecision) Format(state fmt.State, _ rune) {
	helperBootstrapStateFormat(state, "HelperBootstrapDecision")
}
func (HelperBootstrapRightKind) Format(state fmt.State, _ rune) {
	helperBootstrapStateFormat(state, "HelperBootstrapRightKind")
}
func (HelperBootstrapKernelCredential) Format(state fmt.State, _ rune) {
	helperBootstrapStateFormat(state, "HelperBootstrapKernelCredential")
}
func (HelperBootstrapRight) Format(state fmt.State, _ rune) {
	helperBootstrapStateFormat(state, "HelperBootstrapRight")
}
func (HelperBootstrapReceiveMetadata) Format(state fmt.State, _ rune) {
	helperBootstrapStateFormat(state, "HelperBootstrapReceiveMetadata")
}
func (HelperBootstrapPreAdmissionExpected) Format(state fmt.State, _ rune) {
	helperBootstrapStateFormat(state, "HelperBootstrapPreAdmissionExpected")
}
func (HelperBootstrapPreAdmissionState) Format(state fmt.State, _ rune) {
	helperBootstrapStateFormat(state, "HelperBootstrapPreAdmissionState")
}

func helperBootstrapStateMarshalDenied() ([]byte, error) {
	return nil, ErrHelperBootstrapStateSerialization
}
func helperBootstrapStateUnmarshalDenied([]byte) error { return ErrHelperBootstrapStateSerialization }

func (HelperBootstrapDirection) MarshalJSON() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapDirection) MarshalText() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapDirection) MarshalBinary() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (*HelperBootstrapDirection) UnmarshalJSON(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapDirection) UnmarshalText(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapDirection) UnmarshalBinary(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (HelperBootstrapDecision) MarshalJSON() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapDecision) MarshalText() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapDecision) MarshalBinary() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (*HelperBootstrapDecision) UnmarshalJSON(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapDecision) UnmarshalText(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapDecision) UnmarshalBinary(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (HelperBootstrapRightKind) MarshalJSON() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapRightKind) MarshalText() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapRightKind) MarshalBinary() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (*HelperBootstrapRightKind) UnmarshalJSON(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapRightKind) UnmarshalText(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapRightKind) UnmarshalBinary(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}

func (HelperBootstrapKernelCredential) MarshalJSON() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapKernelCredential) MarshalText() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapKernelCredential) MarshalBinary() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (*HelperBootstrapKernelCredential) UnmarshalJSON(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapKernelCredential) UnmarshalText(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapKernelCredential) UnmarshalBinary(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (HelperBootstrapRight) MarshalJSON() ([]byte, error) { return helperBootstrapStateMarshalDenied() }
func (HelperBootstrapRight) MarshalText() ([]byte, error) { return helperBootstrapStateMarshalDenied() }
func (HelperBootstrapRight) MarshalBinary() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (*HelperBootstrapRight) UnmarshalJSON(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapRight) UnmarshalText(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapRight) UnmarshalBinary(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (HelperBootstrapReceiveMetadata) MarshalJSON() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapReceiveMetadata) MarshalText() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapReceiveMetadata) MarshalBinary() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (*HelperBootstrapReceiveMetadata) UnmarshalJSON(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapReceiveMetadata) UnmarshalText(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapReceiveMetadata) UnmarshalBinary(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (HelperBootstrapPreAdmissionExpected) MarshalJSON() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapPreAdmissionExpected) MarshalText() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapPreAdmissionExpected) MarshalBinary() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (*HelperBootstrapPreAdmissionExpected) UnmarshalJSON(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapPreAdmissionExpected) UnmarshalText(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapPreAdmissionExpected) UnmarshalBinary(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (HelperBootstrapPreAdmissionState) MarshalJSON() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapPreAdmissionState) MarshalText() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (HelperBootstrapPreAdmissionState) MarshalBinary() ([]byte, error) {
	return helperBootstrapStateMarshalDenied()
}
func (*HelperBootstrapPreAdmissionState) UnmarshalJSON(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapPreAdmissionState) UnmarshalText(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
func (*HelperBootstrapPreAdmissionState) UnmarshalBinary(value []byte) error {
	return helperBootstrapStateUnmarshalDenied(value)
}
