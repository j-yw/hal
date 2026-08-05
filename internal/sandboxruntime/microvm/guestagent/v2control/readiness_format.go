package v2control

import "fmt"

const (
	readinessRequestPlaceholder = "<v2control.ReadinessRequest>"
	readinessSuccessPlaceholder = "<v2control.ReadinessSuccessResponse>"
)

func (ReadinessRequest) String() string {
	return readinessRequestPlaceholder
}

func (ReadinessRequest) GoString() string {
	return readinessRequestPlaceholder
}

func (ReadinessRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrReadinessSerialization
}

func (ReadinessRequest) MarshalText() ([]byte, error) {
	return nil, ErrReadinessSerialization
}

func (*ReadinessRequest) UnmarshalJSON([]byte) error {
	return ErrReadinessSerialization
}

func (*ReadinessRequest) UnmarshalText([]byte) error {
	return ErrReadinessSerialization
}

func (ReadinessRequest) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, readinessRequestPlaceholder)
}

func (ReadinessSuccessResponse) String() string {
	return readinessSuccessPlaceholder
}

func (ReadinessSuccessResponse) GoString() string {
	return readinessSuccessPlaceholder
}

func (ReadinessSuccessResponse) MarshalJSON() ([]byte, error) {
	return nil, ErrReadinessSerialization
}

func (ReadinessSuccessResponse) MarshalText() ([]byte, error) {
	return nil, ErrReadinessSerialization
}

func (*ReadinessSuccessResponse) UnmarshalJSON([]byte) error {
	return ErrReadinessSerialization
}

func (*ReadinessSuccessResponse) UnmarshalText([]byte) error {
	return ErrReadinessSerialization
}

func (ReadinessSuccessResponse) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, readinessSuccessPlaceholder)
}
