//go:build !linux

package vsock

import (
	"errors"
)

// ListenLinux fails closed when Linux AF_VSOCK is unavailable.
func ListenLinux() (Listener, error) {
	return nil, errors.New("guest AF_VSOCK is unsupported on this platform")
}
