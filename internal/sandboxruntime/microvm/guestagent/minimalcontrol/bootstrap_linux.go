//go:build linux

package minimalcontrol

import (
	"context"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ReadLinuxBootCommandLine has exactly one production source. It retains the
// bytes (including the terminal newline) for validation before construction.
func ReadLinuxBootCommandLine(ctx context.Context) (string, error) {
	return readLinuxBootCommandLinePath(ctx, "/proc/cmdline")
}

func readLinuxBootCommandLinePath(ctx context.Context, path string) (string, error) {
	if ctx == nil {
		return "", ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", ErrInvalid
	}
	file := os.NewFile(uintptr(fd), "minimal-boot-command-line")
	if file == nil {
		_ = unix.Close(fd)
		return "", ErrInvalid
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return "", ErrInvalid
	}
	payload, err := io.ReadAll(io.LimitReader(file, MaximumBootCommandLineBytes+1))
	if err != nil || len(payload) > MaximumBootCommandLineBytes {
		return "", ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	return string(payload), nil
}

// bootstrapEntropy deliberately makes one nonblocking syscall for the exact
// ephemeral-key read, with no retries, device fallback or partial output.
type bootstrapEntropy struct{}

func (bootstrapEntropy) Read(value []byte) (int, error) {
	return readBootstrapEntropy(value, func(out []byte, flags int) (int, error) {
		// Avoid unix.Getrandom's vDSO path: this boundary promises one syscall
		// with GRND_NONBLOCK, not an adaptive userspace random source.
		n, _, errno := unix.Syscall(unix.SYS_GETRANDOM, uintptr(unsafe.Pointer(&out[0])), uintptr(len(out)), uintptr(flags))
		if errno != 0 {
			return 0, errno
		}
		return int(n), nil
	})
}

func readBootstrapEntropy(value []byte, getrandom func([]byte, int) (int, error)) (int, error) {
	if len(value) != 32 || getrandom == nil {
		clear(value)
		return 0, ErrUnavailable
	}
	n, err := getrandom(value, unix.GRND_NONBLOCK)
	if err != nil || n != len(value) {
		clear(value)
		return 0, ErrUnavailable
	}
	return n, nil
}
