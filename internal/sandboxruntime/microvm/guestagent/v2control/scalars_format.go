package v2control

import "fmt"

const (
	requestIDPlaceholder      = "<v2control.RequestID>"
	identityDigestPlaceholder = "<v2control.IdentityDigest>"
)

func (RequestID) String() string {
	return requestIDPlaceholder
}

func (RequestID) GoString() string {
	return requestIDPlaceholder
}

func (RequestID) MarshalJSON() ([]byte, error) {
	return nil, ErrControlScalarSerialization
}

func (RequestID) MarshalText() ([]byte, error) {
	return nil, ErrControlScalarSerialization
}

func (RequestID) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, requestIDPlaceholder)
}

func (IdentityDigest) String() string {
	return identityDigestPlaceholder
}

func (IdentityDigest) GoString() string {
	return identityDigestPlaceholder
}

func (IdentityDigest) MarshalJSON() ([]byte, error) {
	return nil, ErrControlScalarSerialization
}

func (IdentityDigest) MarshalText() ([]byte, error) {
	return nil, ErrControlScalarSerialization
}

func (IdentityDigest) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, identityDigestPlaceholder)
}
