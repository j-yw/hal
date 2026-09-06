package v2control

import "fmt"

const guestCredentialSessionIdentityPlaceholder = "<v2control.GuestCredentialSessionIdentity>"

func (GuestCredentialSessionIdentity) String() string {
	return guestCredentialSessionIdentityPlaceholder
}

func (GuestCredentialSessionIdentity) GoString() string {
	return guestCredentialSessionIdentityPlaceholder
}

func (GuestCredentialSessionIdentity) MarshalJSON() ([]byte, error) {
	return nil, ErrGuestCredentialSessionIdentitySerialization
}

func (GuestCredentialSessionIdentity) MarshalText() ([]byte, error) {
	return nil, ErrGuestCredentialSessionIdentitySerialization
}

func (GuestCredentialSessionIdentity) Format(state fmt.State, verb rune) {
	fmt.Fprint(state, guestCredentialSessionIdentityPlaceholder)
}
