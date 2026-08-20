// Package sshrelay owns the production guest helper SSH-agent extension.
package sshrelay

import (
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/credentialhelper"
)

var errHelperUnavailable = errors.New("guest helper SSH relay is unavailable")

// HelperOptions is intentionally empty: live host authority arrives only in
// credentialhelper.ExtensionOpenRequest.
type HelperOptions struct{}

// NewHelperExtension constructs the process-local SSH relay registration.
func NewHelperExtension(HelperOptions) (credentialhelper.ExtensionRegistration, error) {
	return credentialhelper.ExtensionRegistration{}, errHelperUnavailable
}
