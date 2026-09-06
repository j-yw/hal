package firecrackerhost

import "github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"

const jailerRecoveryConfigVersion = "jailer-runtime-owner-minimal-config-v1"
const jailerRecoveryRecordVersion = "jailer-runtime-owner-minimal-record-v1"

// This private config is emitted only from explicitly injected trusted host
// policy and an authenticated minimal distribution. It is not a worker request
// and carries no credential/helper identity or readiness assertion.
type jailerRecoveryHostPolicy struct {
	IdentityDirectory string `json:"identityDirectory"`
	UID               uint32 `json:"uid"`
	GID               uint32 `json:"gid"`
	TrustedAnchor     string `json:"trustedAnchor"`
	ChrootBase        string `json:"chrootBase"`
	JailerPath        string `json:"jailerPath"`
	FirecrackerPath   string `json:"firecrackerPath"`
	JailerSHA256      string `json:"jailerSha256"`
	FirecrackerSHA256 string `json:"firecrackerSha256"`
	CgroupAnchor      string `json:"cgroupAnchor"`
	CPUQuota          uint64 `json:"cpuQuota"`
	CPUPeriod         uint64 `json:"cpuPeriod"`
	MemoryMax         uint64 `json:"memoryMax"`
	SwapMax           uint64 `json:"swapMax"`
	PidsMax           uint64 `json:"pidsMax"`
}

type jailerRecoveryJob struct {
	SandboxID         string `json:"sandboxId"`
	ExecutionID       string `json:"executionId"`
	WorkerID          string `json:"workerId"`
	HostID            string `json:"hostId"`
	RuntimeID         string `json:"runtimeId"`
	RuntimeGeneration string `json:"runtimeGeneration"`
}

type jailerRecoveryAsset struct {
	Kind   string `json:"kind"`
	Device uint64 `json:"device"`
	Inode  uint64 `json:"inode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type jailerRecoverySupervisorConfig struct {
	Version   string                   `json:"version"`
	DaemonUID uint32                   `json:"daemonUid"`
	Job       jailerRecoveryJob        `json:"job"`
	Policy    jailerRecoveryHostPolicy `json:"policy"`
	Paths     firecracker.PathPlan     `json:"paths"`
	Kernel    jailerRecoveryAsset      `json:"kernel"`
	Rootfs    jailerRecoveryAsset      `json:"rootfs"`
	Config    jailerRecoveryAsset      `json:"config"`
	EnablePCI bool                     `json:"enablePci"`
	Roles     []string                 `json:"roles"`
}

func decodeJailerRecoverySupervisorConfig([]byte) (jailerRecoverySupervisorConfig, error) {
	return jailerRecoverySupervisorConfig{}, errL8RuntimeOwnerInvalid
}
