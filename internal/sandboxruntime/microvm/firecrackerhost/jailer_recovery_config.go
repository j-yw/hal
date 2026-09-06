package firecrackerhost

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

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

func jailerRecoverySupervisorRoles() []string {
	return []string{"control-socket", "owner-directory", "supervisor-config", "kernel-asset", "rootfs-asset", "owner-root-key", "firecracker-config"}
}

func decodeJailerRecoverySupervisorConfig(payload []byte) (jailerRecoverySupervisorConfig, error) {
	var config jailerRecoverySupervisorConfig
	if len(payload) == 0 || len(payload) > l8RuntimeOwnerSupervisorConfigLimit || json.Unmarshal(payload, &config) != nil {
		return config, errL8RuntimeOwnerInvalid
	}
	canonical, err := json.Marshal(config)
	if err != nil || !bytes.Equal(canonical, payload) || validateJailerRecoverySupervisorConfig(config) != nil {
		return jailerRecoverySupervisorConfig{}, errL8RuntimeOwnerInvalid
	}
	return config, nil
}

func validateJailerRecoverySupervisorConfig(config jailerRecoverySupervisorConfig) error {
	if config.Version != jailerRecoveryConfigVersion || config.DaemonUID != 0 || !slices.Equal(config.Roles, jailerRecoverySupervisorRoles()) {
		return errL8RuntimeOwnerInvalid
	}
	return validateJailerRecoveryCommonConfig(config)
}

// Both private schemas apply their own exact discriminator, roles and root
// daemon gate before reusing these job/policy/path/asset checks.
func validateJailerRecoveryCommonConfig(config jailerRecoverySupervisorConfig) error {
	j := config.Job
	for _, id := range []string{j.SandboxID, j.ExecutionID, j.WorkerID, j.HostID, j.RuntimeID, j.RuntimeGeneration} {
		if !validL8RuntimeOwnerSafeID(id) {
			return errL8RuntimeOwnerInvalid
		}
	}
	if !validStrictJailerRuntimeID(j.RuntimeID) {
		return errL8RuntimeOwnerInvalid
	}
	p := config.Policy
	for _, path := range []string{p.IdentityDirectory, p.TrustedAnchor, p.ChrootBase, p.JailerPath, p.FirecrackerPath, p.CgroupAnchor} {
		if !filepathIsCleanAbsolute(path) || cleanupFilesystemRoot(path) || strings.ContainsAny(path, "\x00\r\n") || strings.TrimSpace(path) != path {
			return errL8RuntimeOwnerInvalid
		}
	}
	for _, path := range []string{p.ChrootBase, p.JailerPath, p.FirecrackerPath} {
		rel, err := filepath.Rel(p.TrustedAnchor, path)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errL8RuntimeOwnerInvalid
		}
	}
	if p.UID == 0 || p.GID == 0 || p.JailerPath == p.FirecrackerPath || !validJailerStagingDigest(p.JailerSHA256) || !validJailerStagingDigest(p.FirecrackerSHA256) || p.JailerSHA256 == p.FirecrackerSHA256 {
		return errL8RuntimeOwnerInvalid
	}
	// Exact guest-memory and host-page correlation is checked again against the
	// authenticated Firecracker config before any host mutation.
	resources := strictJailerCgroupResources{anchor: p.CgroupAnchor, cpuQuota: p.CPUQuota, cpuPeriod: p.CPUPeriod, memoryMax: p.MemoryMax, swapMax: p.SwapMax, pidsMax: p.PidsMax}
	if validateJailerCgroupRequest(strictJailerCgroupRequest{resources: resources, runtimeID: j.RuntimeID, configSHA256: config.Config.SHA256, guestMemoryMiB: 1}, 4096) != nil {
		return errL8RuntimeOwnerInvalid
	}
	paths, present, err := validatedCleanupPathPlan(config.Paths)
	if err != nil || !present || !cleanupPathPlansEqual(paths, config.Paths) {
		return errL8RuntimeOwnerInvalid
	}
	assets := []jailerRecoveryAsset{config.Kernel, config.Rootfs, config.Config}
	for index, asset := range assets {
		limit := int64(4 << 30)
		if index == 0 {
			limit = 128 << 20
		}
		if index == 2 {
			limit = maxStrictJailerConfigBytes
		}
		if asset.Kind != []string{"kernel", "rootfs", "config"}[index] || asset.Device == 0 || asset.Inode == 0 || asset.Size <= 0 || asset.Size > limit || !validJailerStagingDigest(asset.SHA256) {
			return errL8RuntimeOwnerInvalid
		}
		for prior := 0; prior < index; prior++ {
			if assets[prior].Device == asset.Device && assets[prior].Inode == asset.Inode {
				return errL8RuntimeOwnerInvalid
			}
		}
	}
	return nil
}
