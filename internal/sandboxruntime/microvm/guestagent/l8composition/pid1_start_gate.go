package l8composition

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrPID1StartGateSerialization       = errors.New("L8 PID1 start-gate serialization is denied")
	ErrPID1StartGateDigestZero          = errors.New("L8 PID1 start-gate sealed digest is zero")
	ErrPID1StartGateDigestAlias         = errors.New("L8 PID1 start-gate sealed digests alias")
	ErrPID1StartGateDigestMismatch      = errors.New("L8 PID1 start-gate descriptor digest does not match")
	ErrPID1StartGateRole                = errors.New("L8 PID1 start-gate descriptor role is invalid")
	ErrPID1StartGateRoleOrder           = errors.New("L8 PID1 start-gate descriptors are not helper then client")
	ErrPID1StartGateTransition          = errors.New("L8 PID1 start-gate transition is invalid")
	ErrPID1StartGateReleased            = errors.New("L8 PID1 start-gate already released")
	ErrPID1StartGateTerminal            = errors.New("L8 PID1 start-gate state is terminal")
	ErrPID1StartGateRegistration        = errors.New("L8 PID1 start-gate registration is invalid")
	ErrPID1StartGateCompositionMismatch = errors.New("L8 PID1 start-gate composition digest does not match")
)

// PID1StartGateDecision is the complete fail-closed start-gate disposition.
type PID1StartGateDecision uint8

const (
	PID1StartGateDecisionContinue PID1StartGateDecision = 1
	PID1StartGateDecisionRelease  PID1StartGateDecision = 2
	PID1StartGateDecisionStopVM   PID1StartGateDecision = 3
)

// PID1StartGateExpected is sealed image-profile correlation owned by PID1.
// It contains no live handle, path, descriptor body, or secret.
type PID1StartGateExpected struct {
	HelperDescriptorSHA256 [32]byte
	ClientDescriptorSHA256 [32]byte
	CompositionSHA256      [32]byte
}

type pid1StartGatePhase uint8

const (
	pid1StartGatePhaseHelper pid1StartGatePhase = iota + 1
	pid1StartGatePhaseClient
	pid1StartGatePhaseReleased
	pid1StartGatePhaseStopped
)

type pid1StartGateOwner struct {
	mu          sync.Mutex
	phase       pid1StartGatePhase
	expected    PID1StartGateExpected
	helper      ProcessDescriptor
	helperWire  []byte
	client      ProcessDescriptor
	clientWire  []byte
	composition CompositionDescriptor
}

// PID1StartGateState is a copy-safe PID1 composition coordinator. Value copies
// share one owner. It constructs no helper or client object and owns no
// endpoint, right, or start-gate file descriptor.
type PID1StartGateState struct {
	owner *pid1StartGateOwner
}

// NewPID1StartGateState snapshots sealed helper, client, and composition
// digests. Zero or aliased descriptor digests fail closed before any accept.
func NewPID1StartGateState(expected PID1StartGateExpected) (*PID1StartGateState, error) {
	if expected.HelperDescriptorSHA256 == [32]byte{} ||
		expected.ClientDescriptorSHA256 == [32]byte{} ||
		expected.CompositionSHA256 == [32]byte{} {
		return nil, ErrPID1StartGateDigestZero
	}
	if expected.HelperDescriptorSHA256 == expected.ClientDescriptorSHA256 {
		return nil, ErrPID1StartGateDigestAlias
	}
	return &PID1StartGateState{owner: &pid1StartGateOwner{
		phase:    pid1StartGatePhaseHelper,
		expected: expected,
	}}, nil
}

// AcceptHelperDescriptor admits the authenticated helper-role descriptor first.
func (state *PID1StartGateState) AcceptHelperDescriptor(descriptor ProcessDescriptor) (PID1StartGateDecision, error) {
	owner, err := state.lockOwner()
	if err != nil {
		return PID1StartGateDecisionStopVM, err
	}
	defer owner.mu.Unlock()
	if decision, err := owner.guardAccept(); err != nil {
		return decision, err
	}
	if owner.phase != pid1StartGatePhaseHelper {
		return owner.stop(ErrPID1StartGateTransition)
	}
	canonical, wire, err := canonicalStartGateDescriptor(descriptor, ProcessRoleHelper, owner.expected.HelperDescriptorSHA256)
	if err != nil {
		return owner.stop(err)
	}
	owner.helper = canonical
	owner.helperWire = wire
	owner.phase = pid1StartGatePhaseClient
	return PID1StartGateDecisionContinue, nil
}

// AcceptClientDescriptor admits the authenticated client-role descriptor and
// releases the agent start gate only after ValidateProcessDescriptors agrees
// with the sealed image-profile composition digest.
func (state *PID1StartGateState) AcceptClientDescriptor(descriptor ProcessDescriptor) (PID1StartGateDecision, error) {
	owner, err := state.lockOwner()
	if err != nil {
		return PID1StartGateDecisionStopVM, err
	}
	defer owner.mu.Unlock()
	if decision, err := owner.guardAccept(); err != nil {
		return decision, err
	}
	if owner.phase != pid1StartGatePhaseClient {
		return owner.stop(ErrPID1StartGateRoleOrder)
	}
	canonical, wire, err := canonicalStartGateDescriptor(descriptor, ProcessRoleClient, owner.expected.ClientDescriptorSHA256)
	if err != nil {
		return owner.stop(err)
	}
	owner.client = canonical
	owner.clientWire = wire
	composition, err := ValidateProcessDescriptors(owner.helper, owner.client)
	if err != nil {
		return owner.stop(err)
	}
	if composition.HelperSHA256 != owner.expected.HelperDescriptorSHA256 ||
		composition.ClientSHA256 != owner.expected.ClientDescriptorSHA256 {
		return owner.stop(ErrPID1StartGateDigestMismatch)
	}
	if composition.CompositionSHA256 != owner.expected.CompositionSHA256 {
		return owner.stop(ErrPID1StartGateCompositionMismatch)
	}
	if !exactSSHCompositionExtensions(owner.helper.Extensions) || !exactSSHCompositionExtensions(owner.client.Extensions) {
		return owner.stop(ErrPID1StartGateRegistration)
	}
	owner.helper = ProcessDescriptor{}
	owner.helperWire = nil
	owner.client = ProcessDescriptor{}
	owner.clientWire = nil
	owner.composition = composition
	owner.phase = pid1StartGatePhaseReleased
	return PID1StartGateDecisionRelease, nil
}

// Composition returns the independently computed composition only after
// start-gate release. Failure and incomplete states expose nothing.
func (state *PID1StartGateState) Composition() (CompositionDescriptor, bool) {
	if state == nil || state.owner == nil {
		return CompositionDescriptor{}, false
	}
	state.owner.mu.Lock()
	defer state.owner.mu.Unlock()
	if state.owner.phase != pid1StartGatePhaseReleased {
		return CompositionDescriptor{}, false
	}
	return state.owner.composition, true
}

// Lost permanently requires whole-VM stop and forgets any attested descriptors.
func (state *PID1StartGateState) Lost() PID1StartGateDecision {
	if state == nil || state.owner == nil {
		return PID1StartGateDecisionStopVM
	}
	state.owner.mu.Lock()
	defer state.owner.mu.Unlock()
	_, _ = state.owner.stop(ErrPID1StartGateTerminal)
	return PID1StartGateDecisionStopVM
}

// Decision returns the current fail-closed disposition.
func (state *PID1StartGateState) Decision() PID1StartGateDecision {
	if state == nil || state.owner == nil {
		return PID1StartGateDecisionStopVM
	}
	state.owner.mu.Lock()
	defer state.owner.mu.Unlock()
	switch state.owner.phase {
	case pid1StartGatePhaseReleased:
		return PID1StartGateDecisionRelease
	case pid1StartGatePhaseStopped:
		return PID1StartGateDecisionStopVM
	default:
		return PID1StartGateDecisionContinue
	}
}

func (state *PID1StartGateState) lockOwner() (*pid1StartGateOwner, error) {
	if state == nil || state.owner == nil {
		return nil, ErrPID1StartGateTerminal
	}
	state.owner.mu.Lock()
	return state.owner, nil
}

func (owner *pid1StartGateOwner) guardAccept() (PID1StartGateDecision, error) {
	switch owner.phase {
	case pid1StartGatePhaseReleased:
		return owner.stop(ErrPID1StartGateReleased)
	case pid1StartGatePhaseStopped:
		return PID1StartGateDecisionStopVM, ErrPID1StartGateTerminal
	default:
		return 0, nil
	}
}

func (owner *pid1StartGateOwner) stop(err error) (PID1StartGateDecision, error) {
	owner.phase = pid1StartGatePhaseStopped
	owner.helper = ProcessDescriptor{}
	owner.helperWire = nil
	owner.client = ProcessDescriptor{}
	owner.clientWire = nil
	owner.composition = CompositionDescriptor{}
	return PID1StartGateDecisionStopVM, err
}

func canonicalStartGateDescriptor(descriptor ProcessDescriptor, role ProcessRole, digest [32]byte) (ProcessDescriptor, []byte, error) {
	if descriptor.Role != role {
		return ProcessDescriptor{}, nil, ErrPID1StartGateRole
	}
	encoded, err := EncodeProcessDescriptor(descriptor)
	if err != nil {
		return ProcessDescriptor{}, nil, err
	}
	decoded, err := DecodeProcessDescriptor(encoded)
	if err != nil {
		return ProcessDescriptor{}, nil, err
	}
	reencoded, err := EncodeProcessDescriptor(decoded)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return ProcessDescriptor{}, nil, ErrProcessDescriptorContract
	}
	if sha256.Sum256(encoded) != digest {
		return ProcessDescriptor{}, nil, ErrPID1StartGateDigestMismatch
	}
	return cloneAgentSupervisorDescriptor(decoded), append([]byte(nil), encoded...), nil
}

func pid1StartGateFormat(state fmt.State, name string) { _, _ = state.Write([]byte(name)) }

func (PID1StartGateDecision) Format(state fmt.State, _ rune) {
	pid1StartGateFormat(state, "PID1StartGateDecision")
}
func (PID1StartGateExpected) Format(state fmt.State, _ rune) {
	pid1StartGateFormat(state, "PID1StartGateExpected")
}
func (PID1StartGateState) Format(state fmt.State, _ rune) {
	pid1StartGateFormat(state, "PID1StartGateState")
}

func (PID1StartGateDecision) String() string   { return "PID1StartGateDecision" }
func (PID1StartGateDecision) GoString() string { return "PID1StartGateDecision" }
func (PID1StartGateExpected) String() string   { return "PID1StartGateExpected" }
func (PID1StartGateExpected) GoString() string { return "PID1StartGateExpected" }
func (PID1StartGateState) String() string      { return "PID1StartGateState" }
func (PID1StartGateState) GoString() string    { return "PID1StartGateState" }

func pid1StartGateMarshalDenied() ([]byte, error) { return nil, ErrPID1StartGateSerialization }
func pid1StartGateUnmarshalDenied([]byte) error   { return ErrPID1StartGateSerialization }

func (PID1StartGateDecision) MarshalJSON() ([]byte, error) { return pid1StartGateMarshalDenied() }
func (PID1StartGateDecision) MarshalText() ([]byte, error) { return pid1StartGateMarshalDenied() }
func (PID1StartGateDecision) MarshalBinary() ([]byte, error) {
	return pid1StartGateMarshalDenied()
}
func (*PID1StartGateDecision) UnmarshalJSON(value []byte) error {
	return pid1StartGateUnmarshalDenied(value)
}
func (*PID1StartGateDecision) UnmarshalText(value []byte) error {
	return pid1StartGateUnmarshalDenied(value)
}
func (*PID1StartGateDecision) UnmarshalBinary(value []byte) error {
	return pid1StartGateUnmarshalDenied(value)
}

func (PID1StartGateExpected) MarshalJSON() ([]byte, error) { return pid1StartGateMarshalDenied() }
func (PID1StartGateExpected) MarshalText() ([]byte, error) { return pid1StartGateMarshalDenied() }
func (PID1StartGateExpected) MarshalBinary() ([]byte, error) {
	return pid1StartGateMarshalDenied()
}
func (*PID1StartGateExpected) UnmarshalJSON(value []byte) error {
	return pid1StartGateUnmarshalDenied(value)
}
func (*PID1StartGateExpected) UnmarshalText(value []byte) error {
	return pid1StartGateUnmarshalDenied(value)
}
func (*PID1StartGateExpected) UnmarshalBinary(value []byte) error {
	return pid1StartGateUnmarshalDenied(value)
}

func (PID1StartGateState) MarshalJSON() ([]byte, error) { return pid1StartGateMarshalDenied() }
func (PID1StartGateState) MarshalText() ([]byte, error) { return pid1StartGateMarshalDenied() }
func (PID1StartGateState) MarshalBinary() ([]byte, error) {
	return pid1StartGateMarshalDenied()
}
func (*PID1StartGateState) UnmarshalJSON(value []byte) error {
	return pid1StartGateUnmarshalDenied(value)
}
func (*PID1StartGateState) UnmarshalText(value []byte) error {
	return pid1StartGateUnmarshalDenied(value)
}
func (*PID1StartGateState) UnmarshalBinary(value []byte) error {
	return pid1StartGateUnmarshalDenied(value)
}
