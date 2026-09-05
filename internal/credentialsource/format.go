package credentialsource

import "fmt"

func (*Registry) String() string { return "<credentialsource.Registry>" }

func (*Registry) GoString() string { return "<credentialsource.Registry>" }

func (RegistryConfig) String() string { return "<credentialsource.RegistryConfig>" }

func (RegistryConfig) GoString() string { return "<credentialsource.RegistryConfig>" }

func (SourceRegistration) String() string { return "<credentialsource.SourceRegistration>" }

func (SourceRegistration) GoString() string { return "<credentialsource.SourceRegistration>" }

func (AdmissionGrantRegistration) String() string {
	return "<credentialsource.AdmissionGrantRegistration>"
}

func (AdmissionGrantRegistration) GoString() string {
	return "<credentialsource.AdmissionGrantRegistration>"
}

func (KeyIdentity) String() string { return "<credentialsource.KeyIdentity>" }

func (KeyIdentity) GoString() string { return "<credentialsource.KeyIdentity>" }

func (KeyDescriptor) String() string { return "<credentialsource.KeyDescriptor>" }

func (KeyDescriptor) GoString() string { return "<credentialsource.KeyDescriptor>" }

func (*registryAuthorization) String() string {
	return "<credentialsource.registryAuthorization>"
}

func (*registryAuthorization) GoString() string {
	return "<credentialsource.registryAuthorization>"
}

func (*keyringLiveSecretSource) String() string {
	return "<credentialsource.keyringLiveSecretSource>"
}

func (*keyringLiveSecretSource) GoString() string {
	return "<credentialsource.keyringLiveSecretSource>"
}

func (*Registry) MarshalJSON() ([]byte, error) { return nil, ErrCredentialSourceSerialization }

func (*Registry) MarshalText() ([]byte, error) { return nil, ErrCredentialSourceSerialization }

func (RegistryConfig) MarshalJSON() ([]byte, error) { return nil, ErrCredentialSourceSerialization }

func (RegistryConfig) MarshalText() ([]byte, error) { return nil, ErrCredentialSourceSerialization }

func (SourceRegistration) MarshalJSON() ([]byte, error) { return nil, ErrCredentialSourceSerialization }

func (SourceRegistration) MarshalText() ([]byte, error) { return nil, ErrCredentialSourceSerialization }

func (AdmissionGrantRegistration) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialSourceSerialization
}

func (AdmissionGrantRegistration) MarshalText() ([]byte, error) {
	return nil, ErrCredentialSourceSerialization
}

func (KeyIdentity) MarshalJSON() ([]byte, error) { return nil, ErrCredentialSourceSerialization }

func (KeyIdentity) MarshalText() ([]byte, error) { return nil, ErrCredentialSourceSerialization }

func (KeyDescriptor) MarshalJSON() ([]byte, error) { return nil, ErrCredentialSourceSerialization }

func (KeyDescriptor) MarshalText() ([]byte, error) { return nil, ErrCredentialSourceSerialization }

func (*registryAuthorization) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialSourceSerialization
}

func (*registryAuthorization) MarshalText() ([]byte, error) {
	return nil, ErrCredentialSourceSerialization
}

func (*keyringLiveSecretSource) MarshalJSON() ([]byte, error) {
	return nil, ErrCredentialSourceSerialization
}

func (*keyringLiveSecretSource) MarshalText() ([]byte, error) {
	return nil, ErrCredentialSourceSerialization
}

func (*Registry) Format(state fmt.State, verb rune) { fmt.Fprint(state, "<credentialsource.Registry>") }

func (RegistryConfig) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<credentialsource.RegistryConfig>")
}

func (SourceRegistration) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<credentialsource.SourceRegistration>")
}

func (AdmissionGrantRegistration) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<credentialsource.AdmissionGrantRegistration>")
}

func (KeyIdentity) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<credentialsource.KeyIdentity>")
}

func (KeyDescriptor) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<credentialsource.KeyDescriptor>")
}

func (*registryAuthorization) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<credentialsource.registryAuthorization>")
}

func (*keyringLiveSecretSource) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, "<credentialsource.keyringLiveSecretSource>")
}
