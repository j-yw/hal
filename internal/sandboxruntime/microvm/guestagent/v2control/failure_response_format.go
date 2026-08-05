package v2control

import "fmt"

const failureResponsePlaceholder = "<v2control.FailureResponse>"

func (FailureResponse) String() string {
	return failureResponsePlaceholder
}

func (FailureResponse) GoString() string {
	return failureResponsePlaceholder
}

func (FailureResponse) MarshalJSON() ([]byte, error) {
	return nil, ErrFailureSerialization
}

func (FailureResponse) MarshalText() ([]byte, error) {
	return nil, ErrFailureSerialization
}

func (*FailureResponse) UnmarshalJSON([]byte) error {
	return ErrFailureSerialization
}

func (*FailureResponse) UnmarshalText([]byte) error {
	return ErrFailureSerialization
}

func (FailureResponse) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, failureResponsePlaceholder)
}
