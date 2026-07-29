//go:build l5_firecracker_vsock_integration

package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

const (
	l5DistributionDirEnv       = "HAL_L5_DISTRIBUTION_DIR"
	l5FirecrackerExecutable    = "firecracker"
	l5FirecrackerVersion       = "Firecracker v1.15.1"
	l5FirecrackerManifestValue = "v1.15.1"

	l5BootTimeout      = 45 * time.Second
	l5OperationTimeout = 30 * time.Second
	l5CleanupTimeout   = 30 * time.Second
)

func TestL5PreparedLinuxFirecrackerVsockE2E(t *testing.T) {
	prerequisites := requireL5PreparedLinuxPrerequisites(t)
	harness := newL5PreparedLinuxHarness(t, prerequisites)
	t.Cleanup(harness.cleanup)

	mainTarget := harness.startWithAPIAcceptanceGate(t, "contract")
	assertL5PreparedGuestReadiness(t, mainTarget)
	harness.assertPrivateRuntimeState(t, mainTarget)
	assertL5PreparedGuestIdentityAndMounts(t, harness.driver, mainTarget)
	assertL5PreparedGuestExecAndCopy(t, harness.driver, mainTarget)
	assertL5PreparedEscapedGuestProcess(t, harness.driver, mainTarget)
	if pids := harness.tracker.activePIDs(); len(pids) != 1 {
		t.Fatalf("owned live Firecracker process count = %d, want 1 before escaped-process containment teardown", len(pids))
	}
	harness.deleteAndAssertContained(t, mainTarget)

	timeoutTarget := harness.start(t, "timeout")
	assertL5PreparedGuestReadiness(t, timeoutTarget)
	assertL5PreparedExecTimeout(t, harness.driver, timeoutTarget)
	harness.deleteAndAssertContained(t, timeoutTarget)

	cancelTarget := harness.start(t, "cancel")
	assertL5PreparedGuestReadiness(t, cancelTarget)
	assertL5PreparedExecCancellation(t, harness.driver, cancelTarget)
	harness.deleteAndAssertContained(t, cancelTarget)

	lossTarget := harness.start(t, "agent-loss")
	assertL5PreparedGuestReadiness(t, lossTarget)
	assertL5PreparedGuestAgentLossFailsClosed(t, harness.driver, lossTarget)
	harness.deleteAndAssertContained(t, lossTarget)

	harness.assertZeroOwnedRuntimeResources(t)
	assertL5PreparedMasterRootfsUnchanged(t, prerequisites)
}

type l5PreparedLinuxPrerequisites struct {
	firecrackerPath string
	distribution    localresolver.VerifiedDistribution
	rootfsPath      string
	rootfsDigest    string
}

func requireL5PreparedLinuxPrerequisites(t *testing.T) l5PreparedLinuxPrerequisites {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Fatalf("L5 Firecracker/vsock acceptance requires Linux; got %s", runtime.GOOS)
	}
	if runtime.GOARCH != "amd64" {
		t.Fatalf("L5 Firecracker/vsock acceptance requires x86_64; got %s", runtime.GOARCH)
	}
	kvm, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0)
	if err != nil {
		t.Fatal("L5 Firecracker/vsock acceptance requires writable KVM")
	}
	if err := kvm.Close(); err != nil {
		t.Fatal("L5 Firecracker/vsock acceptance could not close its KVM prerequisite")
	}

	firecrackerPath, err := exec.LookPath(l5FirecrackerExecutable)
	if err != nil {
		t.Fatal("L5 Firecracker/vsock acceptance requires the pinned Firecracker executable")
	}
	info, err := os.Stat(firecrackerPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		t.Fatal("L5 Firecracker/vsock acceptance requires an executable regular Firecracker binary")
	}
	versionCtx, versionCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer versionCancel()
	versionOutput, err := exec.CommandContext(versionCtx, firecrackerPath, "--version").CombinedOutput()
	if err != nil || strings.TrimSpace(string(versionOutput)) != l5FirecrackerVersion {
		t.Fatalf("L5 Firecracker version must be exactly %s", l5FirecrackerVersion)
	}

	distributionRoot := strings.TrimSpace(os.Getenv(l5DistributionDirEnv))
	if distributionRoot == "" {
		t.Fatalf("%s is required and must name the installed L5 distribution", l5DistributionDirEnv)
	}
	distribution, err := localresolver.VerifyDistributionBundle(localresolver.DistributionRequest{
		RootDir: distributionRoot,
	})
	if err != nil {
		t.Fatal("L5 installed distribution failed production verification")
	}
	if distribution.Manifest.Architecture != "x86_64" ||
		distribution.Manifest.Versions.Firecracker != l5FirecrackerManifestValue {
		t.Fatal("L5 installed distribution does not match the prepared host architecture and Firecracker lock")
	}

	kernelPath, kernelDigest := l5DistributionAsset(distribution.Descriptor, assets.AssetRoleKernel)
	rootfsPath, rootfsDigest := l5DistributionAsset(distribution.Descriptor, assets.AssetRoleRootfs)
	if kernelPath == "" || kernelDigest == "" || rootfsPath == "" || rootfsDigest == "" {
		t.Fatal("L5 installed distribution is missing locked kernel or rootfs launch assets")
	}
	return l5PreparedLinuxPrerequisites{
		firecrackerPath: firecrackerPath,
		distribution:    distribution,
		rootfsPath:      rootfsPath,
		rootfsDigest:    rootfsDigest,
	}
}

func l5DistributionAsset(descriptor assets.LaunchDescriptor, role assets.AssetRole) (string, string) {
	for _, asset := range descriptor.Assets {
		if asset.Role != role ||
			asset.Source.HostPath == nil ||
			asset.Lock.Digest.Algorithm != assets.DigestAlgorithmSHA256 {
			continue
		}
		return asset.Source.HostPath.Path, asset.Lock.Digest.Value
	}
	return "", ""
}

type l5PreparedLinuxHarness struct {
	t         *testing.T
	driver    *microvm.Driver
	tracker   *l5TrackingHostProcessRunner
	apiGate   *l5APIAcceptanceGate
	baseRoot  string
	stateRoot string

	mu      sync.Mutex
	targets map[string]sandboxruntime.Target
}

func newL5PreparedLinuxHarness(t *testing.T, prerequisites l5PreparedLinuxPrerequisites) *l5PreparedLinuxHarness {
	t.Helper()
	baseRoot, err := os.MkdirTemp("/tmp", "hal-l5-vsock-e2e-")
	if err != nil {
		t.Fatal("create private L5 acceptance root failed")
	}
	keepRoot := false
	defer func() {
		if !keepRoot {
			_ = os.RemoveAll(baseRoot)
		}
	}()
	if err := os.Chmod(baseRoot, 0o700); err != nil {
		t.Fatal("secure private L5 acceptance root failed")
	}
	stateRoot := filepath.Join(baseRoot, "state")
	assetRoot := filepath.Join(baseRoot, "assets")
	for _, directory := range []string{stateRoot, assetRoot} {
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal("create private L5 acceptance directory failed")
		}
	}
	scratchRootfs := filepath.Join(assetRoot, "rootfs.ext4")
	if err := copyL5PreparedRootfs(prerequisites.rootfsPath, scratchRootfs, prerequisites.rootfsDigest); err != nil {
		t.Fatal("create digest-identical L5 scratch rootfs failed")
	}

	descriptor := cloneL5LaunchDescriptor(prerequisites.distribution.Descriptor)
	if !replaceL5DescriptorRootfsPath(&descriptor, scratchRootfs) {
		t.Fatal("materialize L5 scratch rootfs launch descriptor failed")
	}
	config := microvm.DefaultConfig()
	config.HypervisorPath = prerequisites.firecrackerPath
	config.LaunchDescriptor = &descriptor
	config.CPUCount = 1
	config.MemoryMiB = 512
	config.GuestWorkDir = "/workspace"

	tracker := newL5TrackingHostProcessRunner()
	apiGate := newL5APIAcceptanceGate()
	driver, err := NewLiveDriver(LiveDriverOptions{
		Config:               config,
		BaseStateDir:         stateRoot,
		HostProcessRunner:    tracker,
		BootAcceptancePoller: apiGate,
		BootTimeout:          l5BootTimeout,
		BootPollInterval:     10 * time.Millisecond,
		GuestTimeout:         l5BootTimeout,
		GuestPollInterval:    10 * time.Millisecond,
		ProductionVsock:      true,
	})
	if err != nil {
		t.Fatal("construct production L5 Firecracker driver failed")
	}
	keepRoot = true
	return &l5PreparedLinuxHarness{
		t:         t,
		driver:    driver,
		tracker:   tracker,
		apiGate:   apiGate,
		baseRoot:  baseRoot,
		stateRoot: stateRoot,
		targets:   make(map[string]sandboxruntime.Target),
	}
}

func copyL5PreparedRootfs(sourcePath, destinationPath, expectedDigest string) error {
	sourceInfo, err := os.Lstat(sourcePath)
	if err != nil || sourceInfo.Mode()&os.ModeSymlink != 0 || !sourceInfo.Mode().IsRegular() {
		return errors.New("L5 master rootfs is unavailable")
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		return errors.New("L5 master rootfs is unreadable")
	}
	defer source.Close()
	openedInfo, err := source.Stat()
	if err != nil || !os.SameFile(sourceInfo, openedInfo) {
		return errors.New("L5 master rootfs identity changed")
	}
	destination, err := os.OpenFile(destinationPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return errors.New("L5 scratch rootfs is unavailable")
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(destination, hash), source)
	syncErr := destination.Sync()
	closeErr := destination.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("L5 scratch rootfs copy failed")
	}
	if hex.EncodeToString(hash.Sum(nil)) != expectedDigest {
		return errors.New("L5 scratch rootfs digest mismatch")
	}
	return nil
}

func cloneL5LaunchDescriptor(source assets.LaunchDescriptor) assets.LaunchDescriptor {
	cloned := assets.LaunchDescriptor{
		ID:     source.ID,
		Labels: append([]assets.SafeLabel(nil), source.Labels...),
		Assets: make([]assets.LaunchAsset, len(source.Assets)),
	}
	for i, asset := range source.Assets {
		cloned.Assets[i] = asset
		cloned.Assets[i].Labels = append([]assets.SafeLabel(nil), asset.Labels...)
		cloned.Assets[i].Resources = append([]assets.ResourceMetadata(nil), asset.Resources...)
		if asset.Source.HostPath != nil {
			hostPath := *asset.Source.HostPath
			cloned.Assets[i].Source.HostPath = &hostPath
		}
	}
	return cloned
}

func replaceL5DescriptorRootfsPath(descriptor *assets.LaunchDescriptor, scratchRootfs string) bool {
	if descriptor == nil {
		return false
	}
	for i := range descriptor.Assets {
		asset := &descriptor.Assets[i]
		if asset.Role != assets.AssetRoleRootfs || asset.Source.HostPath == nil {
			continue
		}
		asset.Source.HostPath.Path = scratchRootfs
		return true
	}
	return false
}

func (harness *l5PreparedLinuxHarness) startWithAPIAcceptanceGate(t *testing.T, suffix string) sandboxruntime.Target {
	t.Helper()
	created := harness.create(t, suffix)
	type startResult struct {
		target *sandboxruntime.Target
		err    error
	}
	result := make(chan startResult, 1)
	startCtx, startCancel := context.WithTimeout(context.Background(), l5BootTimeout)
	defer func() {
		startCancel()
		harness.apiGate.release()
	}()
	go func() {
		target, err := harness.driver.Start(startCtx, sandboxruntime.LifecycleRequest{Target: created})
		result <- startResult{target: target, err: err}
	}()

	select {
	case <-harness.apiGate.accepted:
	case started := <-result:
		harness.apiGate.release()
		if started.err != nil {
			t.Fatal("Firecracker failed before API acceptance")
		}
		t.Fatal("Firecracker start returned before the API-only acceptance gate")
	case <-time.After(l5BootTimeout):
		harness.apiGate.release()
		t.Fatal("Firecracker API socket was not accepted before the L5 timeout")
	}
	if created.Runtime.Metadata != nil && created.Runtime.Metadata.GuestReadiness != nil {
		t.Fatal("created target carried guest readiness before live protocol proof")
	}
	select {
	case <-result:
		t.Fatal("API socket acceptance alone returned a ready target")
	default:
	}
	paths := l5PathsForTarget(t, harness.stateRoot, created)
	assertL5PrivatePath(t, paths.StateDir, 0o700, true)
	assertL5PrivatePath(t, paths.APISocketPath, 0o600, false)

	harness.apiGate.release()
	select {
	case started := <-result:
		if started.err != nil || started.target == nil {
			t.Fatal("Firecracker failed to reach protocol-v1 vsock readiness")
		}
		harness.remember(*started.target)
		return *started.target
	case <-time.After(l5BootTimeout):
		t.Fatal("Firecracker did not reach protocol-v1 vsock readiness before timeout")
	}
	return sandboxruntime.Target{}
}

func (harness *l5PreparedLinuxHarness) start(t *testing.T, suffix string) sandboxruntime.Target {
	t.Helper()
	created := harness.create(t, suffix)
	ctx, cancel := context.WithTimeout(context.Background(), l5BootTimeout)
	defer cancel()
	target, err := harness.driver.Start(ctx, sandboxruntime.LifecycleRequest{Target: created})
	if err != nil || target == nil {
		t.Fatal("Firecracker failed to reach protocol-v1 vsock readiness")
	}
	harness.remember(*target)
	harness.assertPrivateRuntimeState(t, *target)
	return *target
}

func (harness *l5PreparedLinuxHarness) create(t *testing.T, suffix string) sandboxruntime.Target {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	target, err := harness.driver.Create(ctx, sandboxruntime.CreateRequest{
		Name: "l5-prepared-" + suffix,
	})
	if err != nil || target == nil {
		t.Fatal("create production L5 Firecracker target failed")
	}
	return *target
}

func (harness *l5PreparedLinuxHarness) remember(target sandboxruntime.Target) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	harness.targets[target.Runtime.RuntimeID] = target
}

func (harness *l5PreparedLinuxHarness) forget(target sandboxruntime.Target) {
	harness.mu.Lock()
	defer harness.mu.Unlock()
	delete(harness.targets, target.Runtime.RuntimeID)
}

func assertL5PreparedGuestReadiness(t *testing.T, target sandboxruntime.Target) {
	t.Helper()
	if target.Runtime.Metadata == nil || target.Runtime.Metadata.GuestReadiness == nil {
		t.Fatal("started target did not carry live guest readiness")
	}
	readiness := target.Runtime.Metadata.GuestReadiness
	labels := append([]string(nil), readiness.Labels...)
	sort.Strings(labels)
	if readiness.State != sandboxruntime.RuntimeGuestReadinessStateReady ||
		readiness.Transport != "vsock" ||
		!equalL5Strings(labels, []string{"probe_ok", "protocol_v1", "runtime_bound"}) {
		t.Fatal("started target did not carry exact protocol-v1 runtime-bound vsock readiness")
	}
}

func (harness *l5PreparedLinuxHarness) assertPrivateRuntimeState(t *testing.T, target sandboxruntime.Target) {
	t.Helper()
	paths := l5PathsForTarget(t, harness.stateRoot, target)
	assertL5PrivatePath(t, harness.baseRoot, 0o700, true)
	assertL5PrivatePath(t, harness.stateRoot, 0o700, true)
	assertL5PrivatePath(t, paths.StateDir, 0o700, true)
	for _, path := range []string{
		paths.APISocketPath,
		paths.VsockSocketPath,
		paths.ConfigPath,
		paths.LogPath,
		paths.MetricsPath,
	} {
		assertL5PrivatePath(t, path, 0o600, false)
	}
	if err := validatePrivateFirecrackerStateDir(paths.StateDir); err != nil {
		t.Fatal("Firecracker runtime state ownership is not private")
	}
	for _, socketPath := range []string{paths.APISocketPath, paths.VsockSocketPath} {
		info, err := os.Lstat(socketPath)
		if err != nil || validateVsockSocketOwnership(socketPath, info) != nil {
			t.Fatal("Firecracker runtime socket ownership is not private")
		}
	}
}

func assertL5PrivatePath(t *testing.T, path string, mode os.FileMode, directory bool) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != mode {
		t.Fatal("L5 runtime path is missing, aliased, or has non-private permissions")
	}
	if directory && !info.IsDir() {
		t.Fatal("L5 private runtime directory is not a directory")
	}
	if !directory && !info.Mode().IsRegular() && info.Mode()&os.ModeSocket == 0 {
		t.Fatal("L5 private runtime entry is neither a regular file nor a socket")
	}
}

func assertL5PreparedGuestIdentityAndMounts(t *testing.T, driver *microvm.Driver, target sandboxruntime.Target) {
	t.Helper()
	script := `set -eu
uid=$(id -u)
gid=$(id -g)
workspace_stat=$(stat -c '%u:%g:%a' /workspace)
root_mount=
workspace_mount=
while read -r device mountpoint filesystem options rest; do
	case "$mountpoint" in
	/) root_mount="$device:$filesystem:$options" ;;
	/workspace) workspace_mount="$device:$filesystem:$options" ;;
	esac
done </proc/mounts
printf 'uid=%s\n' "$uid"
printf 'gid=%s\n' "$gid"
printf 'workspace-stat=%s\n' "$workspace_stat"
printf 'root-mount=%s\n' "$root_mount"
printf 'workspace-mount=%s\n' "$workspace_mount"
printf 'workspace-write=ok\n' > /workspace/l5-write-probe
rm /workspace/l5-write-probe`
	stdout, stderr, result, err := l5GuestExec(context.Background(), driver, target, []string{"sh", "-c", script})
	if err != nil || result == nil || result.ExitCode != 0 || stderr != "" {
		t.Fatal("L5 guest identity and mount inspection failed")
	}
	values := l5KeyValueLines(stdout)
	if values["uid"] != "1000" ||
		values["gid"] != "1000" ||
		values["workspace-stat"] != "1000:1000:700" {
		t.Fatal("L5 guest agent or workspace does not use UID/GID 1000 and mode 0700")
	}
	rootFields := strings.SplitN(values["root-mount"], ":", 3)
	workspaceFields := strings.SplitN(values["workspace-mount"], ":", 3)
	if len(rootFields) != 3 || len(workspaceFields) != 3 ||
		rootFields[1] != "ext4" ||
		!l5MountOption(rootFields[2], "ro") ||
		workspaceFields[1] != "tmpfs" ||
		!l5MountOption(workspaceFields[2], "rw") ||
		rootFields[0] == workspaceFields[0] {
		t.Fatal("L5 immutable ext4 root and separate writable tmpfs workspace were not proven")
	}
}

func l5MountOption(options, expected string) bool {
	for _, option := range strings.Split(options, ",") {
		if option == expected {
			return true
		}
	}
	return false
}

func assertL5PreparedGuestExecAndCopy(t *testing.T, driver *microvm.Driver, target sandboxruntime.Target) {
	t.Helper()
	stdout, stderr, result, err := l5GuestExec(context.Background(), driver, target, []string{
		"sh", "-c", `printf 'l5-stdout'; printf 'l5-stderr' >&2; exit 23`,
	})
	if err != nil || result == nil || result.ExitCode != 23 ||
		stdout != "l5-stdout" || stderr != "l5-stderr" {
		t.Fatal("L5 guest exec did not preserve stdout, stderr, and non-zero exit status")
	}

	payload := append([]byte{0x00, 0x01, 0xfe, 0xff}, bytes.Repeat([]byte("l5-copy-integrity"), 257)...)
	hostRoot := t.TempDir()
	sourcePath := filepath.Join(hostRoot, "copy-in.bin")
	destinationPath := filepath.Join(hostRoot, "copy-out.bin")
	if err := os.WriteFile(sourcePath, payload, 0o600); err != nil {
		t.Fatal("write L5 host copy fixture failed")
	}
	if err := driver.CopyIn(context.Background(), sandboxruntime.CopyRequest{
		Target:          target,
		SourcePath:      sourcePath,
		DestinationPath: "/workspace/copy-integrity.bin",
	}); err != nil {
		t.Fatal("L5 production copy-in failed")
	}
	if err := driver.CopyOut(context.Background(), sandboxruntime.CopyRequest{
		Target:          target,
		SourcePath:      "/workspace/copy-integrity.bin",
		DestinationPath: destinationPath,
	}); err != nil {
		t.Fatal("L5 production copy-out failed")
	}
	copied, err := os.ReadFile(destinationPath)
	if err != nil || !bytes.Equal(copied, payload) ||
		sha256.Sum256(copied) != sha256.Sum256(payload) {
		t.Fatal("L5 copy-in/copy-out bytes or SHA-256 digest changed")
	}
}

func assertL5PreparedEscapedGuestProcess(t *testing.T, driver *microvm.Driver, target sandboxruntime.Target) {
	t.Helper()
	launch := `set -eu
setsid sh -c 'trap "" TERM INT HUP; while :; do sleep 1; done' </dev/null >/dev/null 2>&1 &
printf '%s\n' "$!" > /workspace/escaped.pid`
	_, stderr, result, err := l5GuestExec(context.Background(), driver, target, []string{"sh", "-c", launch})
	if err != nil || result == nil || result.ExitCode != 0 || stderr != "" {
		t.Fatal("L5 escaped guest process fixture did not start")
	}
	stdout, stderr, result, err := l5GuestExec(context.Background(), driver, target, []string{
		"sh", "-c", `set -eu; read -r escaped </workspace/escaped.pid; kill -0 "$escaped"; printf 'escaped-alive'`,
	})
	if err != nil || result == nil || result.ExitCode != 0 ||
		stdout != "escaped-alive" || stderr != "" {
		t.Fatal("L5 escaped guest process was not live before whole-VM teardown")
	}
}

func assertL5PreparedExecTimeout(t *testing.T, driver *microvm.Driver, target sandboxruntime.Target) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target:  target,
		Args:    []string{"sh", "-c", "sleep 30"},
		WorkDir: "/workspace",
	})
	if err == nil || result != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("L5 guest exec timeout did not preserve context deadline failure")
	}
	if time.Since(started) > 5*time.Second {
		t.Fatal("L5 guest exec timeout exceeded its bounded cleanup window")
	}
}

func assertL5PreparedExecCancellation(t *testing.T, driver *microvm.Driver, target sandboxruntime.Target) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	timer := time.AfterFunc(250*time.Millisecond, cancel)
	defer timer.Stop()
	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target:  target,
		Args:    []string{"sh", "-c", "sleep 30"},
		WorkDir: "/workspace",
	})
	if err == nil || result != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("L5 guest exec cancellation did not preserve explicit cancellation")
	}
}

func assertL5PreparedGuestAgentLossFailsClosed(t *testing.T, driver *microvm.Driver, target sandboxruntime.Target) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target:  target,
		Args:    []string{"sh", "-c", `kill -KILL "$PPID"; while :; do :; done`},
		WorkDir: "/workspace",
	})
	if err == nil {
		t.Fatal("L5 guest-agent loss was reported as a successful exec")
	}
	retryCtx, retryCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer retryCancel()
	result, retryErr := driver.Exec(retryCtx, sandboxruntime.ExecRequest{
		Target:  target,
		Args:    []string{"sh", "-c", "exit 0"},
		WorkDir: "/workspace",
	})
	if retryErr == nil || result != nil {
		t.Fatal("L5 exec did not fail closed after guest-agent loss")
	}
}

func l5GuestExec(
	ctx context.Context,
	driver *microvm.Driver,
	target sandboxruntime.Target,
	args []string,
) (string, string, *sandboxruntime.ExecResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, l5OperationTimeout)
	defer cancel()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	result, err := driver.Exec(ctx, sandboxruntime.ExecRequest{
		Target:  target,
		Args:    args,
		WorkDir: "/workspace",
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	return stdout.String(), stderr.String(), result, err
}

func l5KeyValueLines(output string) map[string]string {
	values := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = value
		}
	}
	return values
}

func (harness *l5PreparedLinuxHarness) deleteAndAssertContained(t *testing.T, target sandboxruntime.Target) {
	t.Helper()
	paths := l5PathsForTarget(t, harness.stateRoot, target)
	pids := harness.tracker.activePIDs()
	if len(pids) > 1 {
		t.Fatalf("owned live Firecracker process count = %d, want at most 1 before teardown", len(pids))
	}
	ctx, cancel := context.WithTimeout(context.Background(), l5CleanupTimeout)
	defer cancel()
	if err := harness.driver.Delete(ctx, sandboxruntime.LifecycleRequest{Target: target}); err != nil {
		t.Fatal("production Firecracker delete failed")
	}
	if err := harness.driver.Delete(ctx, sandboxruntime.LifecycleRequest{Target: target}); err != nil {
		t.Fatal("repeated production Firecracker delete was not idempotent")
	}
	harness.forget(target)
	if len(pids) == 1 {
		waitForL5Condition(t, l5CleanupTimeout, func() bool {
			return len(harness.tracker.activePIDs()) == 0 && l5ProcessAbsent(pids[0])
		}, "owned Firecracker process remained after teardown")
	} else if len(harness.tracker.activePIDs()) != 0 {
		t.Fatal("owned Firecracker process appeared during teardown")
	}
	for _, path := range []string{paths.APISocketPath, paths.VsockSocketPath, paths.StateDir} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("owned Firecracker socket or runtime state remained after teardown")
		}
	}
	for _, path := range []string{paths.APISocketPath, paths.VsockSocketPath} {
		reconnectCtx, reconnectCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		connection, reconnectErr := (&netDialerForL5{}).dial(reconnectCtx, path)
		reconnectCancel()
		if connection != nil {
			_ = connection.Close()
		}
		if reconnectErr == nil {
			t.Fatal("former Firecracker socket accepted a connection after teardown")
		}
	}
	if entries, err := os.ReadDir(harness.stateRoot); err != nil || len(entries) != 0 {
		t.Fatal("Firecracker base state is not empty after target teardown")
	}
	if count := l5OwnedMountCount(harness.baseRoot); count != 0 {
		t.Fatalf("owned host mount count after teardown = %d, want 0", count)
	}
}

// netDialerForL5 keeps the acceptance reconnect proof local without retaining
// the former socket path in any error or evidence value.
type netDialerForL5 struct{}

func (*netDialerForL5) dial(ctx context.Context, path string) (io.Closer, error) {
	dialer := &net.Dialer{}
	connection, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	return connection, nil
}

func l5PathsForTarget(t *testing.T, stateRoot string, target sandboxruntime.Target) firecracker.PathPlan {
	t.Helper()
	paths, err := firecracker.PlanPaths(firecracker.PathPlanRequest{
		RuntimeID:    target.Runtime.RuntimeID,
		BaseStateDir: stateRoot,
	})
	if err != nil {
		t.Fatal("derive L5 target-owned Firecracker paths failed")
	}
	return paths
}

func l5ProcessAbsent(pid int) bool {
	if pid <= 0 {
		return true
	}
	_, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	return os.IsNotExist(err)
}

func l5OwnedMountCount(root string) int {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return -1
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, root) {
			count++
		}
	}
	return count
}

func (harness *l5PreparedLinuxHarness) assertZeroOwnedRuntimeResources(t *testing.T) {
	t.Helper()
	if pids := harness.tracker.activePIDs(); len(pids) != 0 {
		t.Fatalf("owned Firecracker process count = %d, want 0", len(pids))
	}
	if entries, err := os.ReadDir(harness.stateRoot); err != nil || len(entries) != 0 {
		t.Fatal("owned Firecracker socket or state remains after final cleanup")
	}
	if count := l5OwnedMountCount(harness.baseRoot); count != 0 {
		t.Fatalf("owned host mount count = %d, want 0", count)
	}
}

func (harness *l5PreparedLinuxHarness) cleanup() {
	harness.mu.Lock()
	targets := make([]sandboxruntime.Target, 0, len(harness.targets))
	for _, target := range harness.targets {
		targets = append(targets, target)
	}
	harness.mu.Unlock()
	for _, target := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), l5CleanupTimeout)
		err := harness.driver.Delete(ctx, sandboxruntime.LifecycleRequest{Target: target})
		cancel()
		if err != nil {
			harness.t.Errorf("cleanup of owned Firecracker target failed")
		}
		harness.forget(target)
	}
	if pids := harness.tracker.activePIDs(); len(pids) != 0 {
		harness.t.Errorf("owned Firecracker processes remain after test cleanup: %d", len(pids))
		return
	}
	if err := os.RemoveAll(harness.baseRoot); err != nil {
		harness.t.Errorf("remove private L5 acceptance root failed")
	}
}

func assertL5PreparedMasterRootfsUnchanged(t *testing.T, prerequisites l5PreparedLinuxPrerequisites) {
	t.Helper()
	digest, err := digestL5File(prerequisites.rootfsPath)
	if err != nil || digest != prerequisites.rootfsDigest {
		t.Fatal("immutable L5 master rootfs changed during live acceptance")
	}
	if err := assetbuild.ValidateProvenanceAgainstManifest(
		prerequisites.distribution.Provenance,
		prerequisites.distribution.Manifest,
	); err != nil {
		t.Fatal("L5 provenance and distribution manifest lost correlation")
	}
}

func digestL5File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func waitForL5Condition(t *testing.T, timeout time.Duration, condition func() bool, failure string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal(failure)
}

func equalL5Strings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

type l5APIAcceptanceGate struct {
	delegate    APISocketBootAcceptancePoller
	accepted    chan struct{}
	released    chan struct{}
	once        sync.Once
	releaseOnce sync.Once
}

func newL5APIAcceptanceGate() *l5APIAcceptanceGate {
	return &l5APIAcceptanceGate{
		delegate: NewAPISocketBootAcceptancePoller(),
		accepted: make(chan struct{}),
		released: make(chan struct{}),
	}
}

func (gate *l5APIAcceptanceGate) PollBootAcceptance(
	ctx context.Context,
	request firecracker.BootAcceptanceRequest,
) (firecracker.BootAcceptanceResult, error) {
	result, err := gate.delegate.PollBootAcceptance(ctx, request)
	if err != nil || !result.ProcessAccepted || !result.APISocketAvailable {
		return result, err
	}
	first := false
	gate.once.Do(func() {
		first = true
		close(gate.accepted)
	})
	if first {
		select {
		case <-ctx.Done():
			return firecracker.BootAcceptanceResult{}, ctx.Err()
		case <-gate.released:
		}
	}
	return result, nil
}

func (gate *l5APIAcceptanceGate) release() {
	gate.releaseOnce.Do(func() {
		close(gate.released)
	})
}

type l5TrackingHostProcessRunner struct {
	delegate OSExecProcessRunner

	mu        sync.Mutex
	processes map[int]<-chan struct{}
}

func newL5TrackingHostProcessRunner() *l5TrackingHostProcessRunner {
	return &l5TrackingHostProcessRunner{
		delegate:  NewOSExecProcessRunner(),
		processes: make(map[int]<-chan struct{}),
	}
}

func (runner *l5TrackingHostProcessRunner) StartHostProcess(
	ctx context.Context,
	request firecracker.ProcessRunnerStartRequest,
) (HostProcess, error) {
	process, err := runner.delegate.StartHostProcess(ctx, request)
	if err != nil {
		return nil, err
	}
	identity, ok := process.(hostProcessIdentity)
	if !ok || identity.HostPID() <= 0 || identity.Done() == nil {
		_ = process.Kill(context.Background())
		return nil, errors.New("production Firecracker process identity is unavailable")
	}
	runner.mu.Lock()
	runner.processes[identity.HostPID()] = identity.Done()
	runner.mu.Unlock()
	return process, nil
}

func (runner *l5TrackingHostProcessRunner) activePIDs() []int {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	active := make([]int, 0, len(runner.processes))
	for pid, done := range runner.processes {
		select {
		case <-done:
			delete(runner.processes, pid)
		default:
			active = append(active, pid)
		}
	}
	sort.Ints(active)
	return active
}

var (
	_ BootAcceptancePoller = (*l5APIAcceptanceGate)(nil)
	_ HostProcessRunner    = (*l5TrackingHostProcessRunner)(nil)
)
