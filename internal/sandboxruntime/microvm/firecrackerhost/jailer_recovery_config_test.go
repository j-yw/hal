package firecrackerhost

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func jailerRecoveryTestSupervisorConfig(t *testing.T) jailerRecoverySupervisorConfig {
	t.Helper()
	request := validStrictJailerCoordinatorRequest(t)
	return jailerRecoverySupervisorConfig{
		Version: jailerRecoveryConfigVersion,
		Job:     jailerRecoveryJob{SandboxID: "sandbox-1", ExecutionID: "execution-1", WorkerID: "worker-1", HostID: "host-1", RuntimeID: request.runtimeID, RuntimeGeneration: "runtime-generation-1"},
		Policy:  jailerRecoveryHostPolicy{IdentityDirectory: "/prepared/identity", UID: request.inspection.runtimeUID, GID: request.inspection.runtimeGID, TrustedAnchor: "/prepared", ChrootBase: "/prepared/jails", JailerPath: "/prepared/jailer", FirecrackerPath: "/prepared/firecracker", JailerSHA256: strings.Repeat("a", 64), FirecrackerSHA256: strings.Repeat("b", 64), CgroupAnchor: "/sys/fs/cgroup/hal", CPUQuota: 100000, CPUPeriod: 100000, MemoryMax: 512 << 20, SwapMax: 0, PidsMax: 64},
		Paths:   request.jailPaths,
		Kernel:  jailerRecoveryAsset{Kind: "kernel", Device: 1, Inode: 2, Size: 128, SHA256: request.kernel.SHA256},
		Rootfs:  jailerRecoveryAsset{Kind: "rootfs", Device: 1, Inode: 3, Size: 1024, SHA256: request.rootfs.SHA256},
		Config:  jailerRecoveryAsset{Kind: "config", Device: 1, Inode: 4, Size: request.config.SizeBytes, SHA256: request.config.SHA256},
		Roles:   []string{"control-socket", "owner-directory", "supervisor-config", "kernel-asset", "rootfs-asset", "owner-root-key", "firecracker-config"},
	}
}

func TestJailerRecoverySelectedConfigIsDistinctCanonicalAndBounded(t *testing.T) {
	config := jailerRecoveryTestSupervisorConfig(t)
	payload, _ := json.Marshal(config)
	decoded, err := decodeJailerRecoverySupervisorConfig(payload)
	if err != nil || !reflect.DeepEqual(decoded, config) {
		t.Errorf("selected no-credential config rejected: %v", err)
	}
	if _, err := decodeL8RuntimeOwnerSupervisorConfig(payload); err == nil {
		t.Fatal("minimal config entered legacy credential decoder")
	}
	for name, mutate := range map[string]func(*jailerRecoverySupervisorConfig){
		"version":            func(c *jailerRecoverySupervisorConfig) { c.Version = l8RuntimeOwnerSupervisorConfigVersion },
		"root runtime":       func(c *jailerRecoverySupervisorConfig) { c.Policy.UID = 0 },
		"absent gid":         func(c *jailerRecoverySupervisorConfig) { c.Policy.GID = 0 },
		"unprivileged owner": func(c *jailerRecoverySupervisorConfig) { c.DaemonUID = 1000 },
		"runtime":            func(c *jailerRecoverySupervisorConfig) { c.Job.RuntimeID = "" },
		"generation":         func(c *jailerRecoverySupervisorConfig) { c.Job.RuntimeGeneration = "" },
		"mutable path":       func(c *jailerRecoverySupervisorConfig) { c.Policy.IdentityDirectory = "../identity" },
		"absent trust":       func(c *jailerRecoverySupervisorConfig) { c.Policy.JailerSHA256 = "" },
		"same binaries":      func(c *jailerRecoverySupervisorConfig) { c.Policy.JailerSHA256 = c.Policy.FirecrackerSHA256 },
		"unlimited cpu":      func(c *jailerRecoverySupervisorConfig) { c.Policy.CPUQuota = 0 },
		"unlimited memory":   func(c *jailerRecoverySupervisorConfig) { c.Policy.MemoryMax = 0 },
		"unlimited pids":     func(c *jailerRecoverySupervisorConfig) { c.Policy.PidsMax = 0 },
		"swapped role":       func(c *jailerRecoverySupervisorConfig) { c.Roles[3], c.Roles[4] = c.Roles[4], c.Roles[3] },
		"missing role":       func(c *jailerRecoverySupervisorConfig) { c.Roles = c.Roles[:6] },
		"oversized config":   func(c *jailerRecoverySupervisorConfig) { c.Config.Size = maxStrictJailerConfigBytes + 1 },
		"asset alias":        func(c *jailerRecoverySupervisorConfig) { c.Rootfs.Inode = c.Kernel.Inode },
		"asset kind":         func(c *jailerRecoverySupervisorConfig) { c.Rootfs.Kind = "kernel" },
		"asset digest":       func(c *jailerRecoverySupervisorConfig) { c.Kernel.SHA256 = "" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			candidate.Roles = append([]string(nil), config.Roles...)
			mutate(&candidate)
			data, _ := json.Marshal(candidate)
			if _, err := decodeJailerRecoverySupervisorConfig(data); err == nil {
				t.Fatal("invalid selected config accepted")
			}
		})
	}
	for name, data := range map[string][]byte{
		"legacy": func() []byte {
			p, _ := encodeL8RuntimeOwnerSupervisorConfig(l8RuntimeOwnerTestSupervisorConfig())
			return p
		}(),
		"unknown":   bytes.Replace(payload, []byte(`"daemonUid":0`), []byte(`"seed":{},"daemonUid":0`), 1),
		"duplicate": bytes.Replace(payload, []byte(`"daemonUid":0`), []byte(`"daemonUid":0,"daemonUid":0`), 1),
		"null":      []byte("null"), "oversized": bytes.Repeat([]byte("x"), l8RuntimeOwnerSupervisorConfigLimit+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeJailerRecoverySupervisorConfig(data); err == nil {
				t.Fatal("noncanonical selected config accepted")
			}
		})
	}
}
