//go:build !linux

package server

import (
	"errors"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent"
)

// NewLinuxBackend fails closed on platforms that cannot provide the required
// Linux descriptor-containment and process-supervision primitives.
func NewLinuxBackend(LinuxBackendOptions) (Backend, error) {
	const message = "Linux guest backend is unsupported on this platform"
	return nil, &guestagent.ProtocolError{
		Code:    guestagent.ErrorCode("unsupported_platform"),
		Field:   "backend",
		Message: message,
		Err:     errors.New(message),
	}
}
