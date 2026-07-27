//go:build !linux

package vsock

import "errors"

func NewListener(uint32) (Listener, error) {
	return nil, errors.New("guest vsock is unsupported on this platform")
}
