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

type l8RuntimeOwnerExecutableOps struct {
	OpenFD        func(uintptr, string) (int, error)
	CloseFD       func(int) error
	RunSupervisor func([6]int) error
	RunChildGate  func([6]int) error
}

type l8RuntimeOwnerChildLaunchOps struct {
	LockOSThread   func()
	UnlockOSThread func()
	Start          func() error
	Wait           func() error
}

type l8RuntimeOwnerFDRemapOps struct {
	DuplicateAtLeast func(int, int) (int, error)
	Dup3             func(int, int, int) error
	Close            func(int) error
	CloseFrom        func(int) error
	Exec             func(string, []string, []string) error
}

type l8RuntimeOwnerChildGateOps struct {
	ArmPdeathsigAndVerifyParent func() error
	SendArmed                   func() error
	AwaitRelease                func() error
	RemapAndExec                func() error
}

type l8RuntimeOwnerKeyIdentity struct {
	Regular bool
	Mode    uint32
	UID     uint32
	Links   uint64
	Size    int64
	Device  uint64
	Inode   uint64
}

type l8RuntimeOwnerKeyFDOps struct {
	Stat  func(int) (l8RuntimeOwnerKeyIdentity, error)
	Pread func(int, []byte, int64) (int, error)
	Close func(int) error
}

func encodeL8RuntimeOwnerSupervisorConfig(l8RuntimeOwnerSupervisorConfigV1) ([]byte, error) {
	return nil, errL8RuntimeOwnerInvalid
}

func decodeL8RuntimeOwnerSupervisorConfig([]byte) (l8RuntimeOwnerSupervisorConfigV1, error) {
	return l8RuntimeOwnerSupervisorConfigV1{}, errL8RuntimeOwnerInvalid
}

func runPrivateL8RuntimeOwnerExecutableWithOps([]string, l8RuntimeOwnerExecutableOps) int {
	return 127
}

func launchL8RuntimeOwnerChildOnRetainedThread(l8RuntimeOwnerChildLaunchOps) error {
	return errL8RuntimeOwnerInvalid
}

func remapAndExecL8RuntimeOwnerChild(l8RuntimeOwnerSupervisorConfigV1, [4]int, l8RuntimeOwnerFDRemapOps) error {
	return errL8RuntimeOwnerInvalid
}

func runL8RuntimeOwnerChildGate(l8RuntimeOwnerChildGateOps) error {
	return errL8RuntimeOwnerInvalid
}

func loadL8RuntimeOwnerStableKeyFD(int, uint32, l8RuntimeOwnerKeyFDOps) ([]byte, error) {
	return nil, errL8RuntimeOwnerInvalid
}

// RunPrivateL8RuntimeOwnerExecutable is the single internal entry point for
// the isolated runtime-owner executable. It is not a default runtime factory.
func RunPrivateL8RuntimeOwnerExecutable(arguments []string, file func(uintptr, string) *os.File) int {
	return runPrivateL8RuntimeOwnerExecutable(arguments, file)
}
