package syscallpolicy

import (
	"crypto/sha256"
	"encoding/binary"
)

const filterInputDigestDomain = "hal/l8/filter-input/linux-amd64/v1"

// State is a validated immutable role/stage/fact snapshot.
type State struct {
	role  Role
	stage Stage
	facts StateFact
	valid bool
}

// FilterInput is a complete immutable raw syscall decision input.
type FilterInput struct {
	state             State
	auditArchitecture uint32
	rawSyscallNumber  uint32
	arguments         [6]uint64
	valid             bool
}

func NewState(role Role, stage Stage, facts StateFact) (State, error) {
	if ValidateRole(role) != nil {
		return State{}, contractError(ErrorCodeCatalog)
	}
	if ValidateStage(stage) != nil {
		return State{}, contractError(ErrorCodeCatalog)
	}
	if ValidateStateFacts(facts) != nil {
		return State{}, contractError(ErrorCodeCatalog)
	}
	return State{role: role, stage: stage, facts: facts, valid: true}, nil
}

func NewFilterInput(state State, auditArchitecture uint32, rawSyscallNumber uint32, arguments [6]uint64) (FilterInput, error) {
	if !state.valid || ValidateRole(state.role) != nil || ValidateStage(state.stage) != nil || ValidateStateFacts(state.facts) != nil {
		return FilterInput{}, contractError(ErrorCodeInvalidArgument)
	}
	return FilterInput{
		state:             state,
		auditArchitecture: auditArchitecture,
		rawSyscallNumber:  rawSyscallNumber,
		arguments:         arguments,
		valid:             true,
	}, nil
}

func (state State) Role() Role       { return state.role }
func (state State) Stage() Stage     { return state.stage }
func (state State) Facts() StateFact { return state.facts }

func (input FilterInput) State() State              { return input.state }
func (input FilterInput) AuditArchitecture() uint32 { return input.auditArchitecture }
func (input FilterInput) RawSyscallNumber() uint32  { return input.rawSyscallNumber }
func (input FilterInput) Argument(index uint8) (uint64, error) {
	if !input.valid || index >= uint8(len(input.arguments)) {
		return 0, contractError(ErrorCodeBounds)
	}
	return input.arguments[index], nil
}

func (input FilterInput) SHA256() [32]byte {
	if !input.valid {
		return [32]byte{}
	}
	body := make([]byte, 68)
	body[0] = byte(input.state.role)
	body[1] = byte(input.state.stage)
	binary.BigEndian.PutUint64(body[4:12], uint64(input.state.facts))
	binary.BigEndian.PutUint32(body[12:16], input.auditArchitecture)
	binary.BigEndian.PutUint32(body[16:20], input.rawSyscallNumber)
	for index, argument := range input.arguments {
		binary.BigEndian.PutUint64(body[20+index*8:28+index*8], argument)
	}
	framed := make([]byte, 2+len(filterInputDigestDomain)+len(body))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(filterInputDigestDomain)))
	copy(framed[2:], filterInputDigestDomain)
	copy(framed[2+len(filterInputDigestDomain):], body)
	return sha256.Sum256(framed)
}
