package sshrelay

import (
	"fmt"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
)

type helperLiveValue struct{}

func (helperLiveValue) MarshalJSON() ([]byte, error) {
	return nil, credentialhelper.ErrExtensionSerialization
}

func (helperLiveValue) MarshalText() ([]byte, error) {
	return nil, credentialhelper.ErrExtensionSerialization
}

func (helperLiveValue) MarshalBinary() ([]byte, error) {
	return nil, credentialhelper.ErrExtensionSerialization
}

func (helperLiveValue) UnmarshalJSON([]byte) error {
	return credentialhelper.ErrExtensionSerialization
}

func (helperLiveValue) UnmarshalText([]byte) error {
	return credentialhelper.ErrExtensionSerialization
}

func (helperLiveValue) UnmarshalBinary([]byte) error {
	return credentialhelper.ErrExtensionSerialization
}

func (helperLiveValue) String() string   { return "sshrelay.live[redacted]" }
func (helperLiveValue) GoString() string { return "sshrelay.live[redacted]" }

func (helperLiveValue) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("sshrelay.live[redacted]"))
}
