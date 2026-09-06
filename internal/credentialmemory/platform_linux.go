//go:build linux

package credentialmemory

import "golang.org/x/sys/unix"

type linuxMemoryOps struct{}

func (linuxMemoryOps) MapAnonymous(capacity int) ([]byte, error) {
	return unix.Mmap(-1, 0, capacity, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
}

func (linuxMemoryOps) Lock(region []byte) error {
	return unix.Mlock(region)
}

func (linuxMemoryOps) Unlock(region []byte) error {
	return unix.Munlock(region)
}

func (linuxMemoryOps) Unmap(region []byte) error {
	return unix.Munmap(region)
}

type linuxProcessSecurityOps struct{}

func (linuxProcessSecurityOps) SetCoreLimitZero() error {
	limit := unix.Rlimit{Cur: 0, Max: 0}
	return unix.Setrlimit(unix.RLIMIT_CORE, &limit)
}

func (linuxProcessSecurityOps) SetDumpableFalse() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

func (linuxProcessSecurityOps) IsDumpable() (bool, error) {
	value, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	return value != 0, err
}

func NewLockedMapping(capacity int) (*LockedMapping, error) {
	return newLockedMapping(capacity, linuxMemoryOps{})
}

func HardenCredentialProcess() error {
	return hardenCredentialProcess(linuxProcessSecurityOps{})
}
