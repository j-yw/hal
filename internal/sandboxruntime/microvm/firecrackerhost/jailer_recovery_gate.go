package firecrackerhost

import "context"

const jailerRecoveryGateRole = "jailer-child-gate-v1"
const jailerRecoveryGateConfigLimit = 32 << 10

type jailerRecoveryMountedExecutable struct {
	Path   string `json:"path"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type jailerRecoveryGateConfig struct {
	Version         string                          `json:"version"`
	ParentPID       uint32                          `json:"parentPid"`
	ParentStartTime uint64                          `json:"parentStartTime"`
	Jailer          jailerRecoveryMountedExecutable `json:"jailer"`
	Firecracker     jailerRecoveryMountedExecutable `json:"firecracker"`
	Args            []string                        `json:"args"`
}

// Fail-closed declarations for the committed config/barrier RED checkpoint.
func decodeJailerRecoveryGateConfig([]byte) (jailerRecoveryGateConfig, error) {
	return jailerRecoveryGateConfig{}, errL8RuntimeOwnerInvalid
}

type jailerRecoveryGateOps struct {
	verifyParent  func() error
	verifyMounted func(jailerRecoveryMountedExecutable) error
	sendArmed     func() error
	awaitRelease  func() error
	closeFiles    func() error
	exec          func(string, []string) error
}

func runJailerRecoveryGate(context.Context, jailerRecoveryGateConfig, jailerRecoveryGateOps) error {
	return errL8RuntimeOwnerInvalid
}
