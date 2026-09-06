package credentialhelper

import "fmt"

// ContractErrorCode is the closed helper contract failure catalog.
type ContractErrorCode uint8

const (
	ContractInvalidArgument ContractErrorCode = 1
	ContractTypedNil        ContractErrorCode = 2
	ContractCorrelation     ContractErrorCode = 3
	ContractTransition      ContractErrorCode = 4
	ContractCapability      ContractErrorCode = 5
	ContractOwnership       ContractErrorCode = 6
	ContractResultMatrix    ContractErrorCode = 7
	ContractDependency      ContractErrorCode = 8
	ContractDestroyed       ContractErrorCode = 9
)

var (
	ErrContractInvalidArgument = ContractError{code: ContractInvalidArgument}
	ErrContractTypedNil        = ContractError{code: ContractTypedNil}
	ErrContractCorrelation     = ContractError{code: ContractCorrelation}
	ErrContractTransition      = ContractError{code: ContractTransition}
	ErrContractCapability      = ContractError{code: ContractCapability}
	ErrContractOwnership       = ContractError{code: ContractOwnership}
	ErrContractResultMatrix    = ContractError{code: ContractResultMatrix}
	ErrContractDependency      = ContractError{code: ContractDependency}
	ErrContractDestroyed       = ContractError{code: ContractDestroyed}
)

type liveValue struct{}

func (liveValue) String() string   { return "credentialhelper.live[redacted]" }
func (liveValue) GoString() string { return "credentialhelper.live[redacted]" }
func (liveValue) Format(state fmt.State, _ rune) {
	_, _ = fmt.Fprint(state, "credentialhelper.live[redacted]")
}
func (liveValue) MarshalJSON() ([]byte, error)   { return nil, ErrContractInvalidArgument }
func (liveValue) MarshalText() ([]byte, error)   { return nil, ErrContractInvalidArgument }
func (liveValue) MarshalBinary() ([]byte, error) { return nil, ErrContractInvalidArgument }
func (*liveValue) UnmarshalJSON([]byte) error    { return ErrContractInvalidArgument }
func (*liveValue) UnmarshalText([]byte) error    { return ErrContractInvalidArgument }
func (*liveValue) UnmarshalBinary([]byte) error  { return ErrContractInvalidArgument }

// ContractError is a redaction-safe contract failure.
type ContractError struct {
	liveValue
	code ContractErrorCode
}

func (err ContractError) Code() ContractErrorCode { return err.code }

func (err ContractError) Error() string {
	return "credential helper contract " + contractErrorCodeName(err.code)
}

func (err ContractError) Is(target error) bool {
	other, ok := target.(ContractError)
	return ok && err.code != 0 && err.code == other.code
}

func contractErrorCodeName(code ContractErrorCode) string {
	switch code {
	case ContractInvalidArgument:
		return "invalid_argument"
	case ContractTypedNil:
		return "typed_nil"
	case ContractCorrelation:
		return "correlation"
	case ContractTransition:
		return "transition"
	case ContractCapability:
		return "capability"
	case ContractOwnership:
		return "ownership"
	case ContractResultMatrix:
		return "result_matrix"
	case ContractDependency:
		return "dependency"
	case ContractDestroyed:
		return "destroyed"
	default:
		return "invalid_argument"
	}
}
