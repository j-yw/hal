package v2control

import "fmt"

const (
	credentialRenewRequestPlaceholder  = "<v2control.CredentialRenewRequest>"
	credentialRenewSuccessPlaceholder  = "<v2control.CredentialRenewSuccessResponse>"
	credentialRevokeRequestPlaceholder = "<v2control.CredentialRevokeRequest>"
	credentialRevokeSuccessPlaceholder = "<v2control.CredentialRevokeSuccessResponse>"
)

func (CredentialRenewRequest) String() string   { return credentialRenewRequestPlaceholder }
func (CredentialRenewRequest) GoString() string { return credentialRenewRequestPlaceholder }
func (CredentialRenewRequest) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, credentialRenewRequestPlaceholder)
}
func (CredentialRenewRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (CredentialRenewRequest) MarshalText() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (CredentialRenewRequest) MarshalBinary() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (*CredentialRenewRequest) UnmarshalJSON([]byte) error {
	return ErrCredentialLifecycleSerialization
}
func (*CredentialRenewRequest) UnmarshalText([]byte) error {
	return ErrCredentialLifecycleSerialization
}
func (*CredentialRenewRequest) UnmarshalBinary([]byte) error {
	return ErrCredentialLifecycleSerialization
}

func (CredentialRenewSuccessResponse) String() string   { return credentialRenewSuccessPlaceholder }
func (CredentialRenewSuccessResponse) GoString() string { return credentialRenewSuccessPlaceholder }
func (CredentialRenewSuccessResponse) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, credentialRenewSuccessPlaceholder)
}
func (CredentialRenewSuccessResponse) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (CredentialRenewSuccessResponse) MarshalText() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (CredentialRenewSuccessResponse) MarshalBinary() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (*CredentialRenewSuccessResponse) UnmarshalJSON([]byte) error {
	return ErrCredentialLifecycleSerialization
}
func (*CredentialRenewSuccessResponse) UnmarshalText([]byte) error {
	return ErrCredentialLifecycleSerialization
}
func (*CredentialRenewSuccessResponse) UnmarshalBinary([]byte) error {
	return ErrCredentialLifecycleSerialization
}

func (CredentialRevokeRequest) String() string   { return credentialRevokeRequestPlaceholder }
func (CredentialRevokeRequest) GoString() string { return credentialRevokeRequestPlaceholder }
func (CredentialRevokeRequest) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, credentialRevokeRequestPlaceholder)
}
func (CredentialRevokeRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (CredentialRevokeRequest) MarshalText() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (CredentialRevokeRequest) MarshalBinary() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (*CredentialRevokeRequest) UnmarshalJSON([]byte) error {
	return ErrCredentialLifecycleSerialization
}
func (*CredentialRevokeRequest) UnmarshalText([]byte) error {
	return ErrCredentialLifecycleSerialization
}
func (*CredentialRevokeRequest) UnmarshalBinary([]byte) error {
	return ErrCredentialLifecycleSerialization
}

func (CredentialRevokeSuccessResponse) String() string   { return credentialRevokeSuccessPlaceholder }
func (CredentialRevokeSuccessResponse) GoString() string { return credentialRevokeSuccessPlaceholder }
func (CredentialRevokeSuccessResponse) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, credentialRevokeSuccessPlaceholder)
}
func (CredentialRevokeSuccessResponse) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (CredentialRevokeSuccessResponse) MarshalText() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (CredentialRevokeSuccessResponse) MarshalBinary() ([]byte, error) {
	return nil, ErrCredentialLifecycleSerialization
}
func (*CredentialRevokeSuccessResponse) UnmarshalJSON([]byte) error {
	return ErrCredentialLifecycleSerialization
}
func (*CredentialRevokeSuccessResponse) UnmarshalText([]byte) error {
	return ErrCredentialLifecycleSerialization
}
func (*CredentialRevokeSuccessResponse) UnmarshalBinary([]byte) error {
	return ErrCredentialLifecycleSerialization
}
