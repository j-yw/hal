//go:build linux

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

type jailerRecoveryRuntime struct {
	mu                  sync.Mutex
	config              jailerRecoverySupervisorConfig
	files               [3]*os.File
	starter             *jailerRecoveryStarter
	lifecycle           *strictJailerLifecycle
	coordinator         *strictJailerCoordinator
	session             strictJailerSession
	attempted, terminal bool
	observation         l8RuntimeOwnerAbsenceObservation
}

// Only the existing supervise entrypoint selects this constructor, after its
// sealed config discriminator. The default and credential-v1 paths do not.
func newJailerRecoveryLinuxRuntime(fds [6]int, config jailerRecoverySupervisorConfig, configFD int) (*l8RuntimeOwnerLinuxRuntime, error) {
	if os.Geteuid() != 0 || validateJailerRecoverySupervisorConfig(config) != nil || validateL8RuntimeOwnerSeqpacketFD(fds[0]) != nil || validateL8RuntimeOwnerDirectoryFD(fds[1]) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	selected := &jailerRecoveryRuntime{config: config, starter: &jailerRecoveryStarter{}}
	keep := false
	defer func() {
		if !keep {
			for _, file := range selected.files {
				if file != nil {
					_ = file.Close()
				}
			}
		}
	}()
	for index, fd := range []int{fds[3], fds[4], configFD} {
		expected := []jailerRecoveryAsset{config.Kernel, config.Rootfs, config.Config}[index]
		identity, err := validateL8RuntimeOwnerSealedRegularFD(fd, expected.Size)
		if err != nil || identity.Size != expected.Size || validateL8RuntimeOwnerAssetFD(fd, l8RuntimeOwnerDescriptorIdentityV1{Kind: expected.Kind, Device: expected.Device, Inode: expected.Inode, Digest: expected.SHA256}) != nil {
			return nil, errL8RuntimeOwnerInvalid
		}
		duplicate, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 10)
		if err != nil {
			return nil, errL8RuntimeOwnerInvalid
		}
		selected.files[index] = os.NewFile(uintptr(duplicate), "jailer-owner-verified-input")
	}
	request, err := selected.request()
	if err != nil || validateStrictJailerCoordinatorConfig(request) != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	if _, err := strictJailerCoordinatorCgroupRequest(request); err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	keyFD, err := unix.FcntlInt(uintptr(fds[5]), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	key, err := loadL8RuntimeOwnerStableKeyFD(keyFD, config.DaemonUID, realL8RuntimeOwnerKeyFDOps())
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	defer func() {
		if !keep {
			clear(key)
		}
	}()
	bootID, err := readL8RuntimeOwnerHostBootID()
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	supervisor, err := inspectL8RuntimeOwnerProcess(uint32(os.Getpid()))
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	defer supervisor.Close()
	generation, err := randomL8RuntimeOwnerToken()
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	listenerIdentity, err := randomL8RuntimeOwnerToken()
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	secret, err := randomL8RuntimeOwnerToken()
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	listenerFD, listenerKey, err := openL8RuntimeOwnerReconnectListener(fds[1], listenerIdentity)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	owned := &l8RuntimeOwnerLinuxRuntime{selected: selected, config: l8RuntimeOwnerSupervisorConfigV1{DaemonUID: config.DaemonUID}, store: &l8RuntimeOwnerLinuxRecordStore{directoryFD: fds[1], bootID: bootID, selected: &jailerRecoveryStore{config: config}}, commitKey: key, listenerFD: listenerFD, listenerKey: listenerKey, configFD: fds[2], assetFDs: [2]int{fds[3], fds[4]}}
	j := config.Job
	owned.genesis = firecrackerRuntimeOwnerRecordV1{ContractVersion: jailerRecoveryRecordVersion, State: "starting", ControllerState: "none", HostBootID: bootID, SeedCorrelationDigest: jailerRecoveryConfigDigest(config), SupervisorGeneration: generation, SupervisorPID: supervisor.PID, SupervisorStartTime: supervisor.StartTime, ReconnectListenerIdentity: listenerIdentity, ReconnectSecret: secret, SandboxID: j.SandboxID, ExecutionID: j.ExecutionID, WorkerID: j.WorkerID, HostID: j.HostID, RuntimeID: j.RuntimeID, RuntimeGeneration: j.RuntimeGeneration}
	runner, err := newStrictJailerNamespaceRunner(strictJailerNamespaceRunnerOptions{namespace: owned, starter: selected.starter})
	if err == nil {
		selected.lifecycle, err = newStrictJailerLifecycle(runner)
	}
	if err != nil {
		_ = unix.Close(listenerFD)
		_ = unix.Unlinkat(fds[1], listenerKey, 0)
		return nil, errL8RuntimeOwnerInvalid
	}
	policy := config.Policy
	selected.coordinator = newStrictJailerCoordinator(selected.lifecycle, newStrictJailerIdentityAuthority(strictJailerIdentitySlot{directory: policy.IdentityDirectory, uid: policy.UID, gid: policy.GID}), owned.store.recoveryAuthority())
	keep = true
	return owned, nil
}

func (selected *jailerRecoveryRuntime) request() (strictJailerCoordinatorRequest, error) {
	c := selected.config
	p := c.Policy
	request := strictJailerCoordinatorRequest{runtimeID: c.Job.RuntimeID, jailPaths: c.Paths, enablePCI: c.EnablePCI, cgroup: &strictJailerCgroupResources{anchor: p.CgroupAnchor, cpuQuota: p.CPUQuota, cpuPeriod: p.CPUPeriod, memoryMax: p.MemoryMax, swapMax: p.SwapMax, pidsMax: p.PidsMax}, inspection: strictJailerHostInspectionRequest{jailerPath: p.JailerPath, firecrackerPath: p.FirecrackerPath, trustedFilesystemAnchor: p.TrustedAnchor, runtimeUID: p.UID, runtimeGID: p.GID, chrootBaseDir: p.ChrootBase}}
	for _, pair := range []struct {
		digest string
		target *[32]byte
	}{{p.JailerSHA256, &request.inspection.expectedJailerSHA256}, {p.FirecrackerSHA256, &request.inspection.expectedFirecrackerSHA256}} {
		digest, err := hex.DecodeString(pair.digest)
		if err != nil || len(digest) != 32 {
			return request, errL8RuntimeOwnerInvalid
		}
		copy(pair.target[:], digest)
	}
	request.config = jailerStagingResourceInput{ID: "config", JailPath: c.Paths.ConfigPath, Source: selected.files[2], SizeBytes: c.Config.Size, SHA256: c.Config.SHA256, Mode: 0o400}
	rendered, err := readStrictJailerConfig(request.config)
	if err != nil || len(rendered.Drives) != 1 {
		return request, errL8RuntimeOwnerInvalid
	}
	request.kernel = jailerStagingResourceInput{ID: "kernel", JailPath: rendered.BootSource.KernelImagePath, Source: selected.files[0], SizeBytes: c.Kernel.Size, SHA256: c.Kernel.SHA256, Mode: 0o400}
	request.rootfs = jailerStagingResourceInput{ID: "rootfs", JailPath: rendered.Drives[0].PathOnHost, Source: selected.files[1], SizeBytes: c.Rootfs.Size, SHA256: c.Rootfs.SHA256, Mode: 0o600}
	// The selected minimal image has no initrd. Log/metrics files are fresh,
	// measured empty output files required by the existing exact staging plan.
	if rendered.BootSource.InitrdPath != nil {
		return request, errL8RuntimeOwnerInvalid
	}
	empty := sha256.Sum256(nil)
	for _, item := range []struct{ id, path string }{{"log", c.Paths.LogPath}, {"metrics", c.Paths.MetricsPath}} {
		request.support = append(request.support, jailerStagingResourceInput{ID: item.id, JailPath: item.path, Source: bytes.NewReader(nil), SHA256: hex.EncodeToString(empty[:]), Mode: 0o600})
	}
	return request, nil
}

func (selected *jailerRecoveryRuntime) startChild() (l8RuntimeOwnerStartedChild, error) {
	selected.mu.Lock()
	defer selected.mu.Unlock()
	if selected.attempted || selected.coordinator == nil || selected.starter == nil {
		return l8RuntimeOwnerStartedChild{}, errL8RuntimeOwnerInvalid
	}
	selected.attempted = true
	request, err := selected.request()
	if err != nil {
		return l8RuntimeOwnerStartedChild{}, errL8RuntimeOwnerInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), l8RuntimeOwnerContainmentBudget)
	defer cancel()
	selected.session, err = selected.coordinator.start(ctx, request)
	if err != nil {
		return l8RuntimeOwnerStartedChild{}, errL8RuntimeOwnerInvalid
	}
	return l8RuntimeOwnerStartedChild{Observation: selected.starter.observation, Release: selected.starter.release, Abort: func() error { _, err := selected.contain(); return err }}, nil
}

func (selected *jailerRecoveryRuntime) contain() (l8RuntimeOwnerAbsenceObservation, error) {
	selected.mu.Lock()
	defer selected.mu.Unlock()
	if selected.terminal {
		return selected.observation, nil
	}
	if !selected.attempted || selected.coordinator == nil {
		return l8RuntimeOwnerAbsenceObservation{}, errL8RuntimeOwnerInvalid
	}
	ctx, cancel := context.WithTimeout(context.Background(), l8RuntimeOwnerContainmentBudget)
	defer cancel()
	coordinator := selected.coordinator
	coordinator.mu.Lock()
	generation := coordinator.generation
	active := generation != nil && generation.state == strictJailerCoordinatorActive
	coordinator.mu.Unlock()
	var err error
	if active {
		err = coordinator.stop(ctx, selected.session)
	} else if generation != nil {
		err = coordinator.retryCleanup(ctx, selected.session)
	}
	if err != nil {
		return l8RuntimeOwnerAbsenceObservation{}, errL8RuntimeOwnerInvalid
	}
	coordinator.mu.Lock()
	pending := coordinator.generation != nil
	coordinator.mu.Unlock()
	if pending || selected.starter.close() != nil {
		return l8RuntimeOwnerAbsenceObservation{}, errL8RuntimeOwnerInvalid
	}
	selected.observation = l8RuntimeOwnerAbsenceObservation{Kind: l8RuntimeOwnerAbsenceKindWait, ObservedAt: time.Now()}
	selected.terminal = true
	return selected.observation, nil
}

func (owned *l8RuntimeOwnerLinuxRuntime) DuplicateNetworkNamespaceForStrictJailer() (*os.File, error) {
	owned.mu.Lock()
	defer owned.mu.Unlock()
	if owned.selected == nil || owned.namespaces[1] == nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	if _, err := l8RuntimeOwnerStatNamespaceFD(int(owned.namespaces[1].Fd())); err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	fd, err := unix.FcntlInt(owned.namespaces[1].Fd(), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		return nil, errL8RuntimeOwnerInvalid
	}
	return os.NewFile(uintptr(fd), "jailer-owner-network"), nil
}

func readJailerRecoverySelectedConfigFD(fd int) (jailerRecoverySupervisorConfig, bool, error) {
	identity, err := validateL8RuntimeOwnerSealedRegularFD(fd, l8RuntimeOwnerSupervisorConfigLimit)
	if err != nil || identity.Size <= 0 {
		return jailerRecoverySupervisorConfig{}, false, errL8RuntimeOwnerInvalid
	}
	payload := make([]byte, identity.Size)
	if n, err := unix.Pread(fd, payload, 0); err != nil || n != len(payload) {
		return jailerRecoverySupervisorConfig{}, false, errL8RuntimeOwnerInvalid
	}
	var marker struct {
		Version string `json:"version"`
	}
	if json.Unmarshal(payload, &marker) != nil {
		return jailerRecoverySupervisorConfig{}, false, errL8RuntimeOwnerInvalid
	}
	if marker.Version == "" {
		return jailerRecoverySupervisorConfig{}, false, nil
	}
	config, err := decodeJailerRecoverySupervisorConfig(payload)
	return config, true, err
}
