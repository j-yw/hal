package v2control

import "fmt"

const (
	bindingManifestPlaceholder          = "<v2control.BindingManifest>"
	bindingProofPlaceholder             = "<v2control.BindingProof>"
	credentialPrepareRequestPlaceholder = "<v2control.CredentialPrepareRequest>"
	credentialPrepareSuccessPlaceholder = "<v2control.CredentialPrepareSuccessResponse>"
)

func (BindingManifest) String() string   { return bindingManifestPlaceholder }
func (BindingManifest) GoString() string { return bindingManifestPlaceholder }
func (BindingManifest) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, bindingManifestPlaceholder)
}
func (BindingManifest) MarshalJSON() ([]byte, error)   { return nil, ErrCredentialPrepareSerialization }
func (BindingManifest) MarshalText() ([]byte, error)   { return nil, ErrCredentialPrepareSerialization }
func (BindingManifest) MarshalBinary() ([]byte, error) { return nil, ErrCredentialPrepareSerialization }
func (*BindingManifest) UnmarshalJSON([]byte) error    { return ErrCredentialPrepareSerialization }
func (*BindingManifest) UnmarshalText([]byte) error    { return ErrCredentialPrepareSerialization }
func (*BindingManifest) UnmarshalBinary([]byte) error  { return ErrCredentialPrepareSerialization }

func (BindingProof) String() string   { return bindingProofPlaceholder }
func (BindingProof) GoString() string { return bindingProofPlaceholder }
func (BindingProof) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, bindingProofPlaceholder)
}
func (BindingProof) MarshalJSON() ([]byte, error)   { return nil, ErrCredentialPrepareSerialization }
func (BindingProof) MarshalText() ([]byte, error)   { return nil, ErrCredentialPrepareSerialization }
func (BindingProof) MarshalBinary() ([]byte, error) { return nil, ErrCredentialPrepareSerialization }
func (*BindingProof) UnmarshalJSON([]byte) error    { return ErrCredentialPrepareSerialization }
func (*BindingProof) UnmarshalText([]byte) error    { return ErrCredentialPrepareSerialization }
func (*BindingProof) UnmarshalBinary([]byte) error  { return ErrCredentialPrepareSerialization }

func (CredentialPrepareRequest) String() string   { return credentialPrepareRequestPlaceholder }
func (CredentialPrepareRequest) GoString() string { return credentialPrepareRequestPlaceholder }
func (CredentialPrepareRequest) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, credentialPrepareRequestPlaceholder)
}
func (CredentialPrepareRequest) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialPrepareSerialization
}
func (CredentialPrepareRequest) MarshalText() ([]byte, error) {
	return nil, ErrCredentialPrepareSerialization
}
func (CredentialPrepareRequest) MarshalBinary() ([]byte, error) {
	return nil, ErrCredentialPrepareSerialization
}
func (*CredentialPrepareRequest) UnmarshalJSON([]byte) error {
	return ErrCredentialPrepareSerialization
}
func (*CredentialPrepareRequest) UnmarshalText([]byte) error {
	return ErrCredentialPrepareSerialization
}
func (*CredentialPrepareRequest) UnmarshalBinary([]byte) error {
	return ErrCredentialPrepareSerialization
}

func (CredentialPrepareSuccessResponse) String() string   { return credentialPrepareSuccessPlaceholder }
func (CredentialPrepareSuccessResponse) GoString() string { return credentialPrepareSuccessPlaceholder }
func (CredentialPrepareSuccessResponse) Format(state fmt.State, _ rune) {
	fmt.Fprint(state, credentialPrepareSuccessPlaceholder)
}
func (CredentialPrepareSuccessResponse) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialPrepareSerialization
}
func (CredentialPrepareSuccessResponse) MarshalText() ([]byte, error) {
	return nil, ErrCredentialPrepareSerialization
}
func (CredentialPrepareSuccessResponse) MarshalBinary() ([]byte, error) {
	return nil, ErrCredentialPrepareSerialization
}
func (*CredentialPrepareSuccessResponse) UnmarshalJSON([]byte) error {
	return ErrCredentialPrepareSerialization
}
func (*CredentialPrepareSuccessResponse) UnmarshalText([]byte) error {
	return ErrCredentialPrepareSerialization
}
func (*CredentialPrepareSuccessResponse) UnmarshalBinary([]byte) error {
	return ErrCredentialPrepareSerialization
}
