//go:build linux

package guestnetwork

import (
	"context"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

const linuxBootCommandLinePath = "/proc/cmdline"

// LoadLinuxBootConfig reads the immutable Linux boot handoff with symlink and
// size protections, then returns only the validated in-memory contract.
func LoadLinuxBootConfig(ctx context.Context) (BootConfig, bool, error) {
	return loadLinuxBootConfigPath(ctx, linuxBootCommandLinePath)
}

func loadLinuxBootConfigPath(ctx context.Context, path string) (BootConfig, bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return BootConfig{}, false, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return BootConfig{}, false, ErrInvalidBootConfig
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return BootConfig{}, false, ErrInvalidBootConfig
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return BootConfig{}, false, ErrInvalidBootConfig
	}
	payload, err := io.ReadAll(io.LimitReader(file, MaximumBootCommandLineBytes+1))
	if err != nil || int64(len(payload)) > MaximumBootCommandLineBytes {
		return BootConfig{}, false, ErrInvalidBootConfig
	}
	if err := ctx.Err(); err != nil {
		return BootConfig{}, false, err
	}
	return ParseBootCommandLine(string(payload))
}
