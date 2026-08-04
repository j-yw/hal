//go:build linux

package credentialsource

import (
	"context"

	"github.com/jywlabs/hal/internal/credentialmemory"
	"golang.org/x/sys/unix"
)

type linuxKeyctlReader struct{}

func NewRegistry(config RegistryConfig) (*Registry, error) {
	if !validRegistryConfig(config) {
		return nil, ErrCredentialSourceRegistration
	}
	if err := credentialmemory.HardenCredentialProcess(); err != nil {
		return nil, ErrCredentialSourceUnavailable
	}
	return newRegistry(config, registryDeps{keyctl: linuxKeyctlReader{}, newLockedMapping: newCredentialMemoryMapping})
}

func (linuxKeyctlReader) DescribeSize(_ context.Context, serial int32) (int, error) {
	return unix.KeyctlBuffer(unix.KEYCTL_DESCRIBE, int(serial), nil, 0)
}

func (linuxKeyctlReader) DescribeInto(_ context.Context, serial int32, destination []byte) (int, error) {
	return unix.KeyctlBuffer(unix.KEYCTL_DESCRIBE, int(serial), destination, 0)
}

func (linuxKeyctlReader) ReadSize(_ context.Context, serial int32) (int, error) {
	return unix.KeyctlBuffer(unix.KEYCTL_READ, int(serial), nil, 0)
}

func (linuxKeyctlReader) ReadInto(_ context.Context, serial int32, destination []byte) (int, error) {
	return unix.KeyctlBuffer(unix.KEYCTL_READ, int(serial), destination, 0)
}
