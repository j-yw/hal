//go:build linux

package firecrackerhost

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strconv"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/minimalcontrol"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/guestagent/session"
	"golang.org/x/sys/unix"
)

func (a *minimalPreexecAttempt) assembleConfig() error {
	invalid := sandboxruntime.ErrMinimalLaunchUnavailable
	claim, request, scope := a.owner.identity, a.owner.request, a.host.association.scope
	paths, err := firecracker.PlanPaths(firecracker.PathPlanRequest{RuntimeID: claim.RuntimeID, BaseStateDir: a.host.input.jailPathBase})
	if err != nil || !a.current() {
		return invalid
	}
	descriptor, err := a.session.LaunchDescriptor(a.networkIdentity)
	if err != nil {
		return invalid
	}
	network := &minimalL7ConfigExpectation{descriptor: descriptor, runtimeGeneration: claim.RuntimeGeneration, topologyGeneration: a.networkIdentity.TopologyGenerationID}
	nic, base, err := renderMinimalL7Config(a.host.input.baseBootArguments, network)
	_, static, mappingErr := minimalL7Mapping(network)
	public := a.seed.publicKey()
	if err != nil || mappingErr != nil || public == ([32]byte{}) || !a.current() {
		return invalid
	}
	n := a.networkIdentity
	fields := map[string]string{
		"sandboxId": claim.SandboxID, "executionId": claim.ExecutionID, "workerId": claim.WorkerID,
		"hostId": claim.HostID, "runtimeId": claim.RuntimeID, "runtimeGeneration": claim.RuntimeGeneration,
		"workerJobId": claim.WorkerJobID, "submissionId": claim.SubmissionID, "planId": claim.PlanID,
		"jobGeneration": claim.JobGeneration, "principalId": claim.PrincipalID, "runtimeDriver": "microvm",
		"admissionGrantId": request.AdmissionGrantID, "admissionRevision": strconv.FormatUint(request.AdmissionGrantRevision, 10),
		"templatePolicyId": scope.TemplatePolicyID, "workspacePolicyId": scope.WorkspacePolicyID,
		"networkPlanId": n.PlanID, "policySnapshotId": n.PolicySnapshotID, "proxySessionId": n.ProxySessionID,
		"proxyGenerationId": n.ProxyGenerationID, "topologyGenerationId": n.TopologyGenerationID, "ruleGenerationId": n.RuleGenerationID,
		"bootGeneration": a.publicGenerations[0], "imageGeneration": a.publicGenerations[1], "imageDigest": "sha256-" + a.owner.measured[1].SHA256,
	}
	identity := session.Identity{Channel: session.ChannelControl, GuestCID: session.GuestCID, GuestPort: session.ControlPort,
		RuntimeID: claim.RuntimeID, RuntimeGeneration: claim.RuntimeGeneration, BootGeneration: a.publicGenerations[0],
		ImageGeneration: a.publicGenerations[1], ControllerKeyGeneration: a.publicGenerations[2], GuestBootNonce: a.bootNonce}
	image, err := hex.DecodeString(a.owner.measured[1].SHA256)
	if err != nil || len(image) != 32 {
		return invalid
	}
	copy(identity.ImageSHA256[:], image)
	// The shared renderer is last: no boot fields are appended afterwards.
	boot, err := minimalcontrol.RenderBootCommandLine(base, identity, public[:], fields)
	if err != nil {
		return invalid
	}
	fc := strictJailerConfigFile{BootSource: firecracker.BootSourcePayload{KernelImagePath: "/boot/vmlinux", BootArgs: boot},
		Drives: []firecracker.RootDrivePayload{{DriveID: "rootfs", PathOnHost: "/images/rootfs.ext4", IsRootDevice: true}}, Entropy: json.RawMessage("{}")}
	fc.MachineConfig.VCPUCount, fc.MachineConfig.MemSizeMiB = a.host.input.vcpus, int(a.host.input.memoryMiB)
	fc.Vsock = &struct {
		GuestCID uint32 `json:"guest_cid"`
		UDSPath  string `json:"uds_path"`
	}{GuestCID: session.GuestCID, UDSPath: paths.VsockSocketPath}
	fc.NetworkInterfaces, err = json.Marshal([]minimalL7NetworkInterface{nic})
	if err != nil {
		return invalid
	}
	payload, err := json.Marshal(fc)
	if err != nil || len(payload) > maxStrictJailerConfigBytes || !a.current() {
		return invalid
	}
	file, sealErr := a.ops.seal(a.ctx, payload)
	captureErr := a.capture(&a.fcFile, file)
	if sealErr != nil || captureErr != nil || !a.current() {
		return invalid
	}
	asset, err := a.measureConfig(a.fcFile, payload)
	if err != nil {
		return invalid
	}
	a.config = minimalControlSupervisorConfig{jailerRecoverySupervisorConfig: jailerRecoverySupervisorConfig{
		Version: minimalControlSupervisorConfigVersion, DaemonUID: 0,
		Job: jailerRecoveryJob{SandboxID: claim.SandboxID, ExecutionID: claim.ExecutionID, WorkerID: claim.WorkerID, HostID: claim.HostID,
			RuntimeID: claim.RuntimeID, RuntimeGeneration: claim.RuntimeGeneration}, Policy: a.host.input.policy, Paths: paths,
		Kernel: a.owner.measured[0], Rootfs: a.owner.measured[1], Config: asset, EnablePCI: true,
		Roles: append(jailerRecoverySupervisorRoles(), "minimal-controller-key")},
		Control: minimalControlPublicConfig{Prelaunch: fields, ControllerPublicKey: base64.RawURLEncoding.EncodeToString(public[:]),
			ControllerKeyGeneration: a.publicGenerations[2], BootNonce: base64.RawURLEncoding.EncodeToString(a.bootNonce[:]),
			PreparationDeadlineUnixNano: a.owner.preparationDeadline.UnixNano(), LaunchGrantID: claim.LaunchGrantID,
			LaunchPolicyRevision: strconv.FormatUint(claim.LaunchPolicyRevision, 10), NetworkInterface: nic, StaticNetwork: static, Namespace: a.namespacePins}}
	payload, err = json.Marshal(a.config)
	if err != nil || !a.current() {
		return invalid
	}
	decoded, decodedPublic, err := decodeMinimalControlSupervisorConfig(payload)
	if err != nil || !reflect.DeepEqual(decoded, a.config) || !bytes.Equal(public[:], decodedPublic) {
		return invalid
	}
	a.configDigest = sha256.Sum256(payload)
	actual, err := readMinimalControlFirecrackerConfig(int(a.fcFile.Fd()), asset)
	if err != nil || validateMinimalControlFirecrackerConfig(actual, a.config, public[:]) != nil {
		return invalid
	}
	a.expectation, err = captureMinimalControlConfigExpectation(a.config, public[:], a.configDigest)
	if err != nil || a.validateCoordinatorInputs() != nil || !a.current() {
		return invalid
	}
	file, sealErr = a.ops.seal(a.ctx, payload)
	captureErr = a.capture(&a.configFile, file)
	if sealErr != nil || captureErr != nil || !a.current() {
		return invalid
	}
	_, err = a.measureConfig(a.configFile, payload)
	return err
}

func (a *minimalPreexecAttempt) measureConfig(file *os.File, expected []byte) (jailerRecoveryAsset, error) {
	if file == nil || !a.current() {
		return jailerRecoveryAsset{}, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	pin, err := validateL8RuntimeOwnerSealedRegularFD(int(file.Fd()), maxStrictJailerConfigBytes)
	digest := sha256.Sum256(expected)
	actual := minimalPreexecHash(a.ctx, file, int64(len(expected)), maxStrictJailerConfigBytes)
	if err != nil || pin.Size != int64(len(expected)) || actual != digest || !a.current() {
		return jailerRecoveryAsset{}, sandboxruntime.ErrMinimalLaunchUnavailable
	}
	return jailerRecoveryAsset{Kind: "config", Device: pin.Device, Inode: pin.Inode, Size: pin.Size, SHA256: hex.EncodeToString(digest[:])}, nil
}

func (a *minimalPreexecAttempt) validatePreparedFiles() error {
	invalid := sandboxruntime.ErrMinimalLaunchUnavailable
	if !a.current() || a.host.checkFiles(a.ctx, a.hostFiles) != nil || a.checkDirectory() != nil {
		return invalid
	}
	// Re-obtain the live handoff from the SAME Session after the final callback;
	// equality with an earlier descriptor alone does not establish currentness.
	descriptor, err := a.session.LaunchDescriptor(a.networkIdentity)
	if err != nil {
		return invalid
	}
	nic, static, err := minimalL7Mapping(&minimalL7ConfigExpectation{descriptor: descriptor,
		runtimeGeneration: a.owner.identity.RuntimeGeneration, topologyGeneration: a.networkIdentity.TopologyGenerationID})
	pins, namespaceErr := minimalPreexecNamespacePins(a.namespace)
	if err != nil || namespaceErr != nil || pins != a.namespacePins || nic != a.config.Control.NetworkInterface || static != a.config.Control.StaticNetwork {
		return invalid
	}
	for index, file := range a.owner.files {
		expected := a.owner.measured[index]
		pin, err := validateL8RuntimeOwnerSealedRegularFD(int(file.Fd()), []int64{128 << 20, 4 << 30}[index])
		if err != nil || pin.Size != expected.Size || validateL8RuntimeOwnerAssetFD(int(file.Fd()), l8RuntimeOwnerDescriptorIdentityV1{
			Kind: expected.Kind, Device: expected.Device, Inode: expected.Inode, Digest: expected.SHA256}) != nil || !a.current() {
			return invalid
		}
	}
	public := a.seed.publicKey()
	if public == ([32]byte{}) || a.validateSeedFile(public[:]) != nil || !a.current() {
		return invalid
	}
	payload, err := json.Marshal(a.config)
	if err != nil || sha256.Sum256(payload) != a.configDigest {
		return invalid
	}
	if _, err := a.measureConfig(a.configFile, payload); err != nil {
		return invalid
	}
	actualPayload, err := io.ReadAll(io.NewSectionReader(a.configFile, 0, int64(len(payload))+1))
	if err != nil || !bytes.Equal(actualPayload, payload) {
		return invalid
	}
	decoded, decodedPublic, err := decodeMinimalControlSupervisorConfig(actualPayload)
	if err != nil || !reflect.DeepEqual(decoded, a.config) || !bytes.Equal(decodedPublic, public[:]) {
		return invalid
	}
	actual, err := readMinimalControlFirecrackerConfig(int(a.fcFile.Fd()), a.config.Config)
	if err != nil || validateMinimalControlFirecrackerConfig(actual, a.config, public[:]) != nil ||
		validateMinimalControlRequestConfig(actual, &a.expectation, a.owner.identity.RuntimeID, a.config.Config.SHA256) != nil || a.validateCoordinatorInputs() != nil || !a.current() {
		return invalid
	}
	return nil
}

func (a *minimalPreexecAttempt) validateSeedFile(public []byte) error {
	borrowed, err := a.seed.borrowFile()
	if err != nil || borrowed == nil {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	// The unchanged consuming loader revalidates metadata and actual public-key
	// correspondence. Its temporary owned duplicate is never an inherited role.
	fd, err := unix.FcntlInt(borrowed.Fd(), unix.F_DUPFD_CLOEXEC, 10)
	if err != nil {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	file := os.NewFile(uintptr(fd), "minimal-preexec-seed-check")
	defer file.Close()
	key, err := loadMinimalControllerKey(fd, a.host.uid, public, unix.Pread, func(int) error { return file.Close() })
	clear(key)
	if err != nil {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	return nil
}

// Construct only the existing validator input, not another runtime owner or
// manager. Positional sources leave all retained descriptor offsets untouched.
func (a *minimalPreexecAttempt) validateCoordinatorInputs() error {
	c, p := a.config, a.config.Policy
	r := strictJailerCoordinatorRequest{runtimeID: c.Job.RuntimeID, jailPaths: c.Paths, enablePCI: c.EnablePCI,
		minimalControl: &a.expectation,
		cgroup:         &strictJailerCgroupResources{anchor: p.CgroupAnchor, cpuQuota: p.CPUQuota, cpuPeriod: p.CPUPeriod, memoryMax: p.MemoryMax, swapMax: p.SwapMax, pidsMax: p.PidsMax},
		inspection: strictJailerHostInspectionRequest{jailerPath: p.JailerPath, firecrackerPath: p.FirecrackerPath, trustedFilesystemAnchor: p.TrustedAnchor,
			runtimeUID: p.UID, runtimeGID: p.GID, chrootBaseDir: p.ChrootBase}}
	for _, pair := range []struct {
		text   string
		target *[32]byte
	}{{p.JailerSHA256, &r.inspection.expectedJailerSHA256}, {p.FirecrackerSHA256, &r.inspection.expectedFirecrackerSHA256}} {
		value, err := hex.DecodeString(pair.text)
		if err != nil || len(value) != 32 {
			return sandboxruntime.ErrMinimalLaunchUnavailable
		}
		copy(pair.target[:], value)
	}
	r.config = jailerStagingResourceInput{ID: "config", JailPath: c.Paths.ConfigPath, Source: io.NewSectionReader(a.fcFile, 0, c.Config.Size), SizeBytes: c.Config.Size, SHA256: c.Config.SHA256, Mode: 0o400}
	r.kernel = jailerStagingResourceInput{ID: "kernel", JailPath: "/boot/vmlinux", Source: io.NewSectionReader(a.owner.files[0], 0, c.Kernel.Size), SizeBytes: c.Kernel.Size, SHA256: c.Kernel.SHA256, Mode: 0o400}
	r.rootfs = jailerStagingResourceInput{ID: "rootfs", JailPath: "/images/rootfs.ext4", Source: io.NewSectionReader(a.owner.files[1], 0, c.Rootfs.Size), SizeBytes: c.Rootfs.Size, SHA256: c.Rootfs.SHA256, Mode: 0o600}
	empty := sha256.Sum256(nil)
	for _, item := range []struct{ id, path string }{{"log", c.Paths.LogPath}, {"metrics", c.Paths.MetricsPath}} {
		r.support = append(r.support, jailerStagingResourceInput{ID: item.id, JailPath: item.path, Source: bytes.NewReader(nil), SHA256: hex.EncodeToString(empty[:]), Mode: 0o600})
	}
	if validateStrictJailerCoordinatorConfig(r) != nil {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	_, err := strictJailerCoordinatorCgroupRequest(r)
	if err != nil {
		return sandboxruntime.ErrMinimalLaunchUnavailable
	}
	return nil
}
