package v2control

import "fmt"

const (
	execEnvironmentPlaceholder           = "<v2control.ExecEnvironment>"
	execTimingPlaceholder                = "<v2control.ExecTiming>"
	execPlanPlaceholder                  = "<v2control.ExecPlan>"
	credentialExecCorrelationPlaceholder = "<v2control.CredentialExecCorrelation>"
	credentialExecRequestPlaceholder     = "<v2control.CredentialExecRequest>"
	credentialExecSuccessPlaceholder     = "<v2control.CredentialExecSuccessResponse>"
)

func (ExecEnvironment) String() string                 { return execEnvironmentPlaceholder }
func (ExecEnvironment) GoString() string               { return execEnvironmentPlaceholder }
func (ExecEnvironment) Format(state fmt.State, _ rune) { fmt.Fprint(state, execEnvironmentPlaceholder) }
func (ExecEnvironment) MarshalJSON() ([]byte, error)   { return nil, ErrCredentialExecSerialization }
func (ExecEnvironment) MarshalText() ([]byte, error)   { return nil, ErrCredentialExecSerialization }
func (ExecEnvironment) MarshalBinary() ([]byte, error) { return nil, ErrCredentialExecSerialization }
func (*ExecEnvironment) UnmarshalJSON([]byte) error    { return ErrCredentialExecSerialization }
func (*ExecEnvironment) UnmarshalText([]byte) error    { return ErrCredentialExecSerialization }
func (*ExecEnvironment) UnmarshalBinary([]byte) error  { return ErrCredentialExecSerialization }

func (ExecTiming) String() string                 { return execTimingPlaceholder }
func (ExecTiming) GoString() string               { return execTimingPlaceholder }
func (ExecTiming) Format(state fmt.State, _ rune) { fmt.Fprint(state, execTimingPlaceholder) }
func (ExecTiming) MarshalJSON() ([]byte, error)   { return nil, ErrCredentialExecSerialization }
func (ExecTiming) MarshalText() ([]byte, error)   { return nil, ErrCredentialExecSerialization }
func (ExecTiming) MarshalBinary() ([]byte, error) { return nil, ErrCredentialExecSerialization }
func (*ExecTiming) UnmarshalJSON([]byte) error    { return ErrCredentialExecSerialization }
func (*ExecTiming) UnmarshalText([]byte) error    { return ErrCredentialExecSerialization }
func (*ExecTiming) UnmarshalBinary([]byte) error  { return ErrCredentialExecSerialization }

func (ExecPlan) String() string                 { return execPlanPlaceholder }
func (ExecPlan) GoString() string               { return execPlanPlaceholder }
func (ExecPlan) Format(state fmt.State, _ rune) { fmt.Fprint(state, execPlanPlaceholder) }
func (ExecPlan) MarshalJSON() ([]byte, error)   { return nil, ErrCredentialExecSerialization }
func (ExecPlan) MarshalText() ([]byte, error)   { return nil, ErrCredentialExecSerialization }
func (ExecPlan) MarshalBinary() ([]byte, error) { return nil, ErrCredentialExecSerialization }
func (*ExecPlan) UnmarshalJSON([]byte) error    { return ErrCredentialExecSerialization }
func (*ExecPlan) UnmarshalText([]byte) error    { return ErrCredentialExecSerialization }
func (*ExecPlan) UnmarshalBinary([]byte) error  { return ErrCredentialExecSerialization }

func (CredentialExecCorrelation) String() string   { return credentialExecCorrelationPlaceholder }
func (CredentialExecCorrelation) GoString() string { return credentialExecCorrelationPlaceholder }
func (CredentialExecCorrelation) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, credentialExecCorrelationPlaceholder)
}
func (CredentialExecCorrelation) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialExecSerialization
}
func (CredentialExecCorrelation) MarshalText() ([]byte, error) {
	return nil, ErrCredentialExecSerialization
}
func (CredentialExecCorrelation) MarshalBinary() ([]byte, error) {
	return nil, ErrCredentialExecSerialization
}
func (*CredentialExecCorrelation) UnmarshalJSON([]byte) error { return ErrCredentialExecSerialization }
func (*CredentialExecCorrelation) UnmarshalText([]byte) error { return ErrCredentialExecSerialization }
func (*CredentialExecCorrelation) UnmarshalBinary([]byte) error {
	return ErrCredentialExecSerialization
}

func (CredentialExecRequest) String() string   { return credentialExecRequestPlaceholder }
func (CredentialExecRequest) GoString() string { return credentialExecRequestPlaceholder }
func (CredentialExecRequest) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, credentialExecRequestPlaceholder)
}
func (CredentialExecRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialExecSerialization
}
func (CredentialExecRequest) MarshalText() ([]byte, error) {
	return nil, ErrCredentialExecSerialization
}
func (CredentialExecRequest) MarshalBinary() ([]byte, error) {
	return nil, ErrCredentialExecSerialization
}
func (*CredentialExecRequest) UnmarshalJSON([]byte) error   { return ErrCredentialExecSerialization }
func (*CredentialExecRequest) UnmarshalText([]byte) error   { return ErrCredentialExecSerialization }
func (*CredentialExecRequest) UnmarshalBinary([]byte) error { return ErrCredentialExecSerialization }

func (CredentialExecSuccessResponse) String() string   { return credentialExecSuccessPlaceholder }
func (CredentialExecSuccessResponse) GoString() string { return credentialExecSuccessPlaceholder }
func (CredentialExecSuccessResponse) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, credentialExecSuccessPlaceholder)
}
func (CredentialExecSuccessResponse) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialExecSerialization
}
func (CredentialExecSuccessResponse) MarshalText() ([]byte, error) {
	return nil, ErrCredentialExecSerialization
}
func (CredentialExecSuccessResponse) MarshalBinary() ([]byte, error) {
	return nil, ErrCredentialExecSerialization
}
func (*CredentialExecSuccessResponse) UnmarshalJSON([]byte) error {
	return ErrCredentialExecSerialization
}
func (*CredentialExecSuccessResponse) UnmarshalText([]byte) error {
	return ErrCredentialExecSerialization
}
func (*CredentialExecSuccessResponse) UnmarshalBinary([]byte) error {
	return ErrCredentialExecSerialization
}
