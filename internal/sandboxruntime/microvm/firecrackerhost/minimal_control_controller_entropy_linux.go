//go:build linux

package firecrackerhost

import "golang.org/x/sys/unix"

// The shared handshake takes an io.Reader. This concrete implementation permits
// only its exact 32-byte draw, with one nonblocking syscall and no fallback.
type minimalControlControllerEntropy struct{}

func (minimalControlControllerEntropy) Read(buffer []byte) (int, error) {
	return readMinimalControllerEntropy(buffer, unix.Getrandom)
}

func readMinimalControllerEntropy(buffer []byte, getrandom func([]byte, int) (int, error)) (int, error) {
	complete := false
	defer func() {
		if !complete {
			clear(buffer)
		}
	}()
	if len(buffer) != 32 {
		return 0, errMinimalControlController
	}
	n, err := getrandom(buffer, unix.GRND_NONBLOCK)
	if err != nil || n != len(buffer) {
		return 0, errMinimalControlController
	}
	complete = true
	return n, nil
}
