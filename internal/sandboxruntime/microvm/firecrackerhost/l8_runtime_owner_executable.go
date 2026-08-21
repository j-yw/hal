package firecrackerhost

import (
	"os"

	"github.com/jywlabs/hal/internal/sandboxruntime"
)

const (
	l8RuntimeOwnerExecutableSupervise     = "supervise"
	l8RuntimeOwnerExecutableChildGate     = "child-gate"
	l8RuntimeOwnerSupervisorConfigVersion = "firecracker-runtime-owner-supervisor-config-v1"
	l8RuntimeOwnerSupervisorConfigLimit   = 32 << 10
)

type l8RuntimeOwnerDescriptorIdentityV1 struct {
	Kind   string `json:"kind"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Digest string `json:"digest"`
}

type l8RuntimeOwnerSupervisorConfigV1 struct {
	ContractVersion            string                                   `json:"contractVersion"`
	Seed                       sandboxruntime.JobCredentialIdentitySeed `json:"seed"`
	DaemonUID                  uint32                                   `json:"daemonUid"`
	NamespaceWrapperExecutable string                                   `json:"namespaceWrapperExecutable"`
	FirecrackerExecutable      string                                   `json:"firecrackerExecutable"`
	FirecrackerArguments       []string                                 `json:"firecrackerArguments"`
	Kernel                     l8RuntimeOwnerDescriptorIdentityV1       `json:"kernel"`
	Rootfs                     l8RuntimeOwnerDescriptorIdentityV1       `json:"rootfs"`
	InheritedDescriptorCount   uint16                                   `json:"inheritedDescriptorCount"`
}

func encodeL8RuntimeOwnerSupervisorConfig(l8RuntimeOwnerSupervisorConfigV1) ([]byte, error) {
	return nil, errL8RuntimeOwnerInvalid
}

func decodeL8RuntimeOwnerSupervisorConfig([]byte) (l8RuntimeOwnerSupervisorConfigV1, error) {
	return l8RuntimeOwnerSupervisorConfigV1{}, errL8RuntimeOwnerInvalid
}

// RunPrivateL8RuntimeOwnerExecutable is the single internal entry point for
// the isolated runtime-owner executable. It is not a default runtime factory.
func RunPrivateL8RuntimeOwnerExecutable(arguments []string, file func(uintptr, string) *os.File) int {
	return runPrivateL8RuntimeOwnerExecutable(arguments, file)
}
