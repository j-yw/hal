package firecrackerhost

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

var (
	errStrictJailerCoordinatorInvalid           = errors.New("strict Jailer coordinator request is invalid")
	errStrictJailerCoordinatorBusy              = errors.New("strict Jailer coordinator is busy")
	errStrictJailerCoordinatorFailed            = errors.New("strict Jailer coordinator operation failed")
	errStrictJailerCoordinatorCleanupIncomplete = errors.New("strict Jailer coordinator cleanup is incomplete")
)

const maxStrictJailerConfigBytes = 1 << 20

// strictJailerCoordinatorRequest deliberately has no host path plan, raw
// argv, or process-start request. Those values are derived only after the
// private inspection and config/resource correlation complete.
type strictJailerCoordinatorRequest struct {
	cgroup     *strictJailerCgroupResources
	runtimeID  string
	inspection strictJailerHostInspectionRequest
	jailPaths  firecracker.PathPlan
	kernel     jailerStagingResourceInput
	rootfs     jailerStagingResourceInput
	config     jailerStagingResourceInput
	support    []jailerStagingResourceInput
	enablePCI  bool
}

type strictJailerCoordinatorError struct {
	kind      error
	operation string
}

func (err *strictJailerCoordinatorError) Error() string {
	kind := safeStrictJailerCoordinatorErrorKind(nil)
	operation := ""
	if err != nil {
		kind = safeStrictJailerCoordinatorErrorKind(err.kind)
		operation = safeStrictJailerCoordinatorOperation(err.operation)
	}
	if operation == "" {
		return kind.Error()
	}
	return kind.Error() + ": " + operation
}

func (err *strictJailerCoordinatorError) Unwrap() error {
	if err == nil {
		return errStrictJailerCoordinatorFailed
	}
	return safeStrictJailerCoordinatorErrorKind(err.kind)
}

func newStrictJailerCoordinatorError(kind error, operation string) *strictJailerCoordinatorError {
	return &strictJailerCoordinatorError{kind: safeStrictJailerCoordinatorErrorKind(kind), operation: safeStrictJailerCoordinatorOperation(operation)}
}

func safeStrictJailerCoordinatorErrorKind(kind error) error {
	switch {
	case errors.Is(kind, errStrictJailerCoordinatorInvalid):
		return errStrictJailerCoordinatorInvalid
	case errors.Is(kind, errStrictJailerCoordinatorBusy):
		return errStrictJailerCoordinatorBusy
	case errors.Is(kind, errStrictJailerCoordinatorCleanupIncomplete):
		return errStrictJailerCoordinatorCleanupIncomplete
	default:
		return errStrictJailerCoordinatorFailed
	}
}

func safeStrictJailerCoordinatorOperation(operation string) string {
	switch strings.TrimSpace(operation) {
	case "config", "inspect", "filesystem", "stage", "verify", "plan", "start", "stop", "process_cleanup", "root_cleanup", "session":
		return strings.TrimSpace(operation)
	default:
		return ""
	}
}

type strictJailerCoordinatorLifecycle interface {
	start(context.Context, strictJailerLifecycleStartRequest) (strictJailerLifecycleProcess, error)
	stop(context.Context, strictJailerLifecycleProcess) error
	terminated(strictJailerLifecycleProcess) bool
	forgetTerminated(strictJailerLifecycleProcess) error
	retryUncertainStartCleanup(context.Context) error
}

type strictJailerCoordinatorDependencies struct {
	recovery      *jailerRecoveryAuthority
	identity      *strictJailerIdentityAuthority
	prepareCgroup func(context.Context, strictJailerCgroupRequest) (*strictJailerCgroupLease, error)
	inspect       func(strictJailerHostInspectionRequest) (strictJailerHostInspectionResult, error)
	newFilesystem func(jailerStagingAuthority) (jailerStagingFilesystem, error)
	stage         func(jailerStagingFilesystem, jailerStagingRequest) (jailerStagingResult, error)
	plan          func(strictJailerLaunchRequest) (strictJailerLaunchPlan, error)
	lifecycle     strictJailerCoordinatorLifecycle
}

type strictJailerCoordinatorState uint8

const (
	strictJailerCoordinatorActive strictJailerCoordinatorState = iota + 1
	strictJailerCoordinatorStartCleanupPending
	strictJailerCoordinatorStopCleanupPending
	strictJailerCoordinatorRootCleanupPending
)

type strictJailerCoordinatorGeneration struct {
	identity          *strictJailerIdentityLease
	cgroup            *strictJailerCgroupLease
	unresolvedStaging bool
	id                uint64
	state             strictJailerCoordinatorState
	staging           jailerStagingResult
	process           strictJailerLifecycleProcess
	hasProcess        bool
}

// strictJailerSession is an opaque ownership token for one coordinator
// generation. All fields remain private and its JSON representation is {}.
type strictJailerSession struct {
	coordinator *strictJailerCoordinator
	generation  uint64
}

// strictJailerCoordinator is package-private and not selected by any default
// runtime path. It serializes one active or cleanup-pending generation.
type strictJailerCoordinator struct {
	mu         sync.Mutex
	deps       strictJailerCoordinatorDependencies
	next       uint64
	generation *strictJailerCoordinatorGeneration
}

func newStrictJailerCoordinator(lifecycle *strictJailerLifecycle, identity *strictJailerIdentityAuthority, recovery *jailerRecoveryAuthority) *strictJailerCoordinator {
	return newStrictJailerCoordinatorWithDependencies(strictJailerCoordinatorDependencies{
		recovery:      recovery,
		identity:      identity,
		prepareCgroup: prepareStrictJailerCgroup,
		inspect:       inspectAndPinStrictJailerHost,
		newFilesystem: func(authority jailerStagingAuthority) (jailerStagingFilesystem, error) {
			return newLinuxJailerStagingFilesystem(authority)
		},
		stage:     stageStrictJailerResources,
		plan:      planStrictJailerLaunch,
		lifecycle: lifecycle,
	})
}

func newStrictJailerCoordinatorWithDependencies(deps strictJailerCoordinatorDependencies) *strictJailerCoordinator {
	return &strictJailerCoordinator{deps: deps}
}

func (coordinator *strictJailerCoordinator) start(ctx context.Context, request strictJailerCoordinatorRequest) (result strictJailerSession, resultErr error) {
	return coordinator.startWithMinimalLease(ctx, request, nil)
}

func (coordinator *strictJailerCoordinator) startWithMinimalLease(ctx context.Context, request strictJailerCoordinatorRequest, assets *localresolver.VerifiedL8MinimalLaunchLease) (result strictJailerSession, resultErr error) {
	if coordinator == nil {
		return strictJailerSession{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "session")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	ctx = nonNilContext(ctx)
	if ctx.Err() != nil {
		return strictJailerSession{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorFailed, "session")
	}
	if coordinator.generation != nil {
		return strictJailerSession{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorBusy, "session")
	}
	if err := validateStrictJailerCoordinatorConfig(request); err != nil {
		return strictJailerSession{}, err
	}
	cgroupRequest, cgroupErr := strictJailerCoordinatorCgroupRequest(request)
	if cgroupErr != nil || coordinator.deps.prepareCgroup == nil {
		return strictJailerSession{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
	}
	if coordinator.deps.identity == nil || coordinator.deps.inspect == nil || coordinator.deps.newFilesystem == nil || coordinator.deps.stage == nil ||
		coordinator.deps.plan == nil || interfaceValueIsNil(coordinator.deps.lifecycle) {
		return strictJailerSession{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "session")
	}
	owner := coordinator.deps.recovery
	if owner == nil || owner.current == nil || owner.busy == nil || owner.terminal == nil || owner.current(ctx, request.runtimeID, request.config.SHA256) != nil {
		return strictJailerSession{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "session")
	}

	identity, identityErr := coordinator.deps.identity.reserve(ctx, request.runtimeID, request.config.SHA256, request.inspection.runtimeUID, request.inspection.runtimeGID)
	if identity == nil {
		return strictJailerSession{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorFailed, "verify")
	}
	coordinator.next++
	generation := &strictJailerCoordinatorGeneration{id: coordinator.next, identity: identity, state: strictJailerCoordinatorRootCleanupPending}
	session := strictJailerSession{coordinator: coordinator, generation: generation.id}
	coordinator.generation = generation
	if identityErr != nil || identity.verify(ctx) != nil {
		return coordinator.failBeforeProcess(generation, session, "verify")
	}
	if owner.busy(ctx, identity) != nil {
		// No host allocation has happened. The owner update may be uncertain;
		// retain the exact busy lease, never infer idle from a failed checkpoint.
		return session, newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "session")
	}
	inspection, err := coordinator.deps.inspect(request.inspection)
	defer func() {
		if err := inspection.executables.close(); err != nil {
			resultErr = errors.Join(resultErr, newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "inspect"))
		}
	}()
	if err != nil {
		return coordinator.failBeforeProcess(generation, session, "inspect")
	}
	authority, hostPaths, err := strictJailerCoordinatorAuthority(request, inspection)
	if err != nil {
		return coordinator.failBeforeProcess(generation, session, "inspect")
	}
	if identity.verify(ctx) != nil {
		return coordinator.failBeforeProcess(generation, session, "verify")
	}
	cgroup, cgroupErr := coordinator.deps.prepareCgroup(ctx, cgroupRequest)
	generation.cgroup = cgroup
	if cgroup == nil {
		return coordinator.failBeforeProcess(generation, session, "verify")
	}
	if cgroupErr != nil || !cgroup.matches(request.runtimeID, request.config.SHA256) || identity.verify(ctx) != nil {
		return coordinator.failBeforeProcess(generation, session, "verify")
	}
	filesystem, err := coordinator.deps.newFilesystem(authority)
	if err != nil || interfaceValueIsNil(filesystem) {
		return coordinator.failBeforeProcess(generation, session, "filesystem")
	}
	stagingRequest := jailerStagingRequest{
		Authority: authority,
		Kernel:    request.kernel,
		Rootfs:    request.rootfs,
		Config:    request.config,
		Support:   append([]jailerStagingResourceInput(nil), request.support...),
	}
	var staging jailerStagingResult
	if assets == nil {
		staging, err = coordinator.deps.stage(filesystem, stagingRequest)
	} else {
		staging, err = stageStrictJailerMinimalAssets(ctx, assets, coordinator.deps.stage, filesystem, stagingRequest)
	}
	if err != nil {
		generation.staging = staging
		generation.unresolvedStaging = !staging.retainsOwnedRoot() && !staging.rootReleaseTerminal() && errors.Is(err, errJailerStagingCleanupIncomplete) && !jailerCgroupOnlyTerminalStagingClose(err, 0)
		if staging.retainsOwnedRoot() || generation.unresolvedStaging {
			return session, errors.Join(newStrictJailerCoordinatorError(errStrictJailerCoordinatorFailed, "stage"), newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "root_cleanup"))
		}
		result, cleanupErr := coordinator.failBeforeProcess(generation, session, "stage")
		if errors.Is(err, errJailerStagingCleanupIncomplete) {
			cleanupErr = errors.Join(cleanupErr, newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "root_cleanup"))
		}
		return result, cleanupErr
	}

	generation.staging = staging
	if ctx.Err() != nil {
		return coordinator.failBeforeProcess(generation, session, "stage")
	}
	if err := staging.verifyOwnedRoot(); err != nil {
		return coordinator.failBeforeProcess(generation, session, "verify")
	}
	launchPlan, err := coordinator.deps.plan(strictJailerLaunchRequest{
		RuntimeID:                authority.RuntimeID,
		JailerPath:               inspection.canonicalJailerPath,
		CanonicalFirecrackerPath: authority.CanonicalFirecrackerPath,
		UID:                      authority.UID,
		GID:                      authority.GID,
		ChrootBaseDir:            authority.ChrootBaseDir,
		HostPaths:                hostPaths,
		JailPaths:                request.jailPaths,
		Firecracker: firecracker.ProcessRunnerStartRequest{
			Executable: authority.CanonicalFirecrackerPath,
			Args:       strictFirecrackerPathArgs(hostPaths, request.enablePCI),
		},
	})
	if err != nil {
		return coordinator.failBeforeProcess(generation, session, "plan")
	}
	if assets != nil {
		if err := assets.ConfirmCurrent(ctx); err != nil {
			return coordinator.failBeforeProcess(generation, session, "verify")
		}
	}
	if cgroup.verifyForLaunch() != nil {
		return coordinator.failBeforeProcess(generation, session, "verify")
	}
	if ctx.Err() != nil {
		return coordinator.failBeforeProcess(generation, session, "start")
	}
	var process strictJailerLifecycleProcess
	err = identity.withLaunch(ctx, func() error {
		var startErr error
		process, startErr = coordinator.deps.lifecycle.start(nonNilContext(ctx), strictJailerLifecycleStartRequest{launchPlan: launchPlan, hostPaths: hostPaths, executables: inspection.executables, cgroup: cgroup, configSHA256: request.config.SHA256})
		return startErr
	})
	if err != nil {
		if strictJailerLifecycleStartCleanupUncertain(err) {
			generation.state = strictJailerCoordinatorStartCleanupPending
			coordinator.generation = generation
			return session, newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "process_cleanup")
		}
		return coordinator.failBeforeProcess(generation, session, "start")
	}
	generation.process = process
	generation.hasProcess = true
	generation.state = strictJailerCoordinatorActive
	coordinator.generation = generation
	return session, nil
}

func (coordinator *strictJailerCoordinator) failBeforeProcess(generation *strictJailerCoordinatorGeneration, session strictJailerSession, operation string) (strictJailerSession, error) {
	generation.state = strictJailerCoordinatorRootCleanupPending
	err := coordinator.releaseGenerationRoot(context.Background(), generation)
	if coordinator.generation == nil {
		session = strictJailerSession{}
	}
	return session, errors.Join(newStrictJailerCoordinatorError(errStrictJailerCoordinatorFailed, operation), err)
}

func (coordinator *strictJailerCoordinator) stop(ctx context.Context, session strictJailerSession) error {
	if coordinator == nil {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "session")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	generation, err := coordinator.sessionGeneration(session)
	if err != nil || generation.state != strictJailerCoordinatorActive {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "session")
	}
	stopErr := coordinator.deps.lifecycle.stop(nonNilContext(ctx), generation.process)
	if generation.cgroup.quiesce(ctx) != nil {
		generation.state = strictJailerCoordinatorStopCleanupPending
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "process_cleanup")
	}
	if !coordinator.deps.lifecycle.terminated(generation.process) {
		generation.state = strictJailerCoordinatorStopCleanupPending
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "process_cleanup")
	}
	generation.state = strictJailerCoordinatorRootCleanupPending
	releaseErr := coordinator.releaseGenerationRoot(ctx, generation)
	if stopErr != nil {
		return errors.Join(newStrictJailerCoordinatorError(errStrictJailerCoordinatorFailed, "stop"), releaseErr)
	}
	return releaseErr
}

func (coordinator *strictJailerCoordinator) retryCleanup(ctx context.Context, session strictJailerSession) error {
	if coordinator == nil {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "session")
	}
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	generation, err := coordinator.sessionGeneration(session)
	if err != nil {
		return err
	}
	switch generation.state {
	case strictJailerCoordinatorStartCleanupPending:
		if generation.cgroup.quiesce(ctx) != nil {
			return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "process_cleanup")
		}
		if err := coordinator.deps.lifecycle.retryUncertainStartCleanup(nonNilContext(ctx)); err != nil {
			return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "process_cleanup")
		}
		generation.state = strictJailerCoordinatorRootCleanupPending
	case strictJailerCoordinatorStopCleanupPending:
		stopErr := coordinator.deps.lifecycle.stop(nonNilContext(ctx), generation.process)
		if generation.cgroup.quiesce(ctx) != nil {
			return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "process_cleanup")
		}
		if !coordinator.deps.lifecycle.terminated(generation.process) {
			return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "process_cleanup")
		}
		generation.state = strictJailerCoordinatorRootCleanupPending
		if err := coordinator.releaseGenerationRoot(ctx, generation); err != nil {
			return err
		}
		if stopErr != nil {
			return newStrictJailerCoordinatorError(errStrictJailerCoordinatorFailed, "stop")
		}
		return nil
	case strictJailerCoordinatorRootCleanupPending:
	default:
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "session")
	}
	return coordinator.releaseGenerationRoot(ctx, generation)
}

func (coordinator *strictJailerCoordinator) sessionGeneration(session strictJailerSession) (*strictJailerCoordinatorGeneration, error) {
	if session.coordinator != coordinator || session.generation == 0 || coordinator.generation == nil || coordinator.generation.id != session.generation {
		return nil, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "session")
	}
	return coordinator.generation, nil
}

func (coordinator *strictJailerCoordinator) releaseGenerationRoot(ctx context.Context, generation *strictJailerCoordinatorGeneration) error {
	if (generation.cgroup != nil && generation.cgroup.quiesce(ctx) != nil) || generation.unresolvedStaging || generation.identity.verifyCleanup(ctx) != nil {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "root_cleanup")
	}
	var releaseErr error
	if generation.staging.lease != nil {
		releaseErr = generation.staging.releaseOwnedRoot()
	}
	if generation.staging.lease != nil && !generation.staging.rootReleaseTerminal() {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "root_cleanup")
	}
	if generation.cgroup != nil && generation.cgroup.release() != nil {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "root_cleanup")
	}
	if generation.hasProcess {
		if err := coordinator.deps.lifecycle.forgetTerminated(generation.process); err != nil {
			processErr := newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "process_cleanup")
			if releaseErr != nil {
				return errors.Join(
					newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "root_cleanup"),
					processErr,
				)
			}
			return processErr
		}
		generation.hasProcess = false
	}
	if coordinator.deps.recovery == nil || coordinator.deps.recovery.terminal == nil || coordinator.deps.recovery.terminal(ctx, generation.identity) != nil {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "root_cleanup")
	}
	if generation.identity.release(ctx) != nil {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "root_cleanup")
	}
	coordinator.generation = nil
	if releaseErr != nil {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorCleanupIncomplete, "root_cleanup")
	}
	return nil
}

type strictJailerConfigFile struct {
	MachineConfig struct {
		VCPUCount  int `json:"vcpu_count"`
		MemSizeMiB int `json:"mem_size_mib"`
	} `json:"machine-config"`
	BootSource firecracker.BootSourcePayload  `json:"boot-source"`
	Drives     []firecracker.RootDrivePayload `json:"drives"`
	Vsock      *struct {
		GuestCID uint32 `json:"guest_cid"`
		UDSPath  string `json:"uds_path"`
	} `json:"vsock,omitempty"`
	Entropy json.RawMessage `json:"entropy,omitempty"`
}

func validateStrictJailerCoordinatorConfig(request strictJailerCoordinatorRequest) error {
	paths, hasPaths, err := validatedCleanupPathPlan(request.jailPaths)
	if err != nil || !hasPaths || !cleanupPathPlansEqual(paths, request.jailPaths) ||
		!validStrictJailerRuntimeID(request.runtimeID) || strings.TrimSpace(request.runtimeID) != request.runtimeID {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
	}
	if request.config.JailPath != paths.ConfigPath || !validJailerStagingDigest(request.config.SHA256) ||
		interfaceValueIsNil(request.config.Source) || request.config.SizeBytes < 0 || request.config.SizeBytes > maxStrictJailerConfigBytes {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
	}
	rendered, err := readStrictJailerConfig(request.config)
	if err != nil {
		return err
	}
	if rendered.MachineConfig.VCPUCount <= 0 || rendered.MachineConfig.MemSizeMiB <= 0 ||
		rendered.BootSource.KernelImagePath != request.kernel.JailPath || len(rendered.Drives) != 1 ||
		rendered.Drives[0].DriveID != "rootfs" || !rendered.Drives[0].IsRootDevice || rendered.Drives[0].PathOnHost != request.rootfs.JailPath ||
		(rendered.Vsock != nil && (rendered.Vsock.GuestCID < 3 || rendered.Vsock.UDSPath != paths.VsockSocketPath)) ||
		!validStrictJailerEntropy(rendered.Entropy) ||
		request.enablePCI != (rendered.Vsock != nil) || request.kernel.Mode != 0o400 || request.rootfs.Mode != 0o600 || request.config.Mode != 0o400 {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
	}
	resources := make([]jailerStagingResourceInput, 0, 3+len(request.support))
	resources = append(resources, request.kernel, request.rootfs, request.config)
	resources = append(resources, request.support...)
	reservedExecutable := ""
	if filepathIsCleanAbsolute(request.inspection.firecrackerPath) && !cleanupFilesystemRoot(request.inspection.firecrackerPath) {
		reservedExecutable = "/" + filepath.Base(request.inspection.firecrackerPath)
	}
	seen := make(map[string]int, len(resources))
	for _, resource := range resources {
		jailPath, _, pathErr := validateJailerStagingPath(resource.JailPath)
		if pathErr != nil || jailerPathOverlapsEndpoint(jailPath, paths.APISocketPath) ||
			jailerPathOverlapsEndpoint(jailPath, paths.VsockSocketPath) || jailerPathOverlapsEndpoint(jailPath, reservedExecutable) ||
			jailPath == "/dev" || strings.HasPrefix(jailPath, "/dev/") {
			return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
		}
		seen[jailPath]++
		if seen[jailPath] != 1 {
			return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
		}
	}
	allowedSupport := map[string]os.FileMode{paths.LogPath: 0o600, paths.MetricsPath: 0o600}
	if rendered.BootSource.InitrdPath != nil {
		initrd := *rendered.BootSource.InitrdPath
		if initrd == "" || initrd == request.kernel.JailPath || initrd == request.rootfs.JailPath ||
			initrd == request.config.JailPath || initrd == paths.LogPath || initrd == paths.MetricsPath {
			return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
		}
		allowedSupport[initrd] = 0o400
	}
	if len(request.support) != len(allowedSupport) {
		return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
	}
	for _, resource := range request.support {
		mode, allowed := allowedSupport[resource.JailPath]
		if !allowed || resource.Mode != mode || seen[resource.JailPath] != 1 {
			return newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
		}
	}
	return nil
}

func jailerPathOverlapsEndpoint(value, endpoint string) bool {
	return endpoint != "" && (value == endpoint ||
		strings.HasPrefix(value, endpoint+"/") ||
		strings.HasPrefix(endpoint, value+"/"))
}

func validStrictJailerEntropy(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	var fields map[string]json.RawMessage
	return json.Unmarshal(raw, &fields) == nil && fields != nil && len(fields) == 0
}

func readStrictJailerConfig(resource jailerStagingResourceInput) (strictJailerConfigFile, error) {
	if _, err := resource.Source.Seek(0, io.SeekStart); err != nil {
		return strictJailerConfigFile{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorFailed, "config")
	}
	data, err := io.ReadAll(io.LimitReader(resource.Source, resource.SizeBytes+1))
	seekErr := error(nil)
	if _, resetErr := resource.Source.Seek(0, io.SeekStart); resetErr != nil {
		seekErr = resetErr
	}
	digest := sha256.Sum256(data)
	if err != nil || seekErr != nil || int64(len(data)) != resource.SizeBytes || hex.EncodeToString(digest[:]) != resource.SHA256 {
		return strictJailerConfigFile{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if strictJailerConfigHasNoncanonicalOrDuplicateFields(data) {
		return strictJailerConfigFile{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
	}
	decoder.DisallowUnknownFields()
	var rendered strictJailerConfigFile
	if err := decoder.Decode(&rendered); err != nil {
		return strictJailerConfigFile{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return strictJailerConfigFile{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
	}
	return rendered, nil
}

func strictJailerConfigHasNoncanonicalOrDuplicateFields(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var visit func(json.Token) bool
	visit = func(token json.Token) bool {
		delimiter, ok := token.(json.Delim)
		if !ok {
			return false
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, keyOK := keyToken.(string)
				if err != nil || !keyOK || !canonicalStrictJailerConfigField(key) {
					return true
				}
				if _, duplicate := seen[key]; duplicate {
					return true
				}
				seen[key] = struct{}{}
				value, err := decoder.Token()
				if err != nil || visit(value) {
					return true
				}
			}
			end, err := decoder.Token()
			return err != nil || end != json.Delim('}')
		case '[':
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil || visit(value) {
					return true
				}
			}
			end, err := decoder.Token()
			return err != nil || end != json.Delim(']')
		default:
			return true
		}
	}
	first, err := decoder.Token()
	return err != nil || visit(first)
}

func canonicalStrictJailerConfigField(field string) bool {
	switch field {
	case "machine-config", "boot-source", "drives", "vsock", "entropy",
		"vcpu_count", "mem_size_mib", "kernel_image_path", "initrd_path", "boot_args",
		"drive_id", "path_on_host", "is_root_device", "is_read_only", "guest_cid", "uds_path":
		return true
	default:
		return false
	}
}

func strictJailerCoordinatorAuthority(request strictJailerCoordinatorRequest, inspection strictJailerHostInspectionResult) (jailerStagingAuthority, firecracker.PathPlan, error) {
	if inspection.canonicalJailerPath == "" || inspection.canonicalFirecrackerPath == "" || inspection.runtimeUID == 0 || inspection.runtimeGID == 0 ||
		inspection.canonicalChrootBaseDir == "" || inspection.runtimeUID != request.inspection.runtimeUID || inspection.runtimeGID != request.inspection.runtimeGID ||
		inspection.canonicalJailerPath != request.inspection.jailerPath || inspection.canonicalFirecrackerPath != request.inspection.firecrackerPath ||
		inspection.canonicalChrootBaseDir != request.inspection.chrootBaseDir || !filepathIsCleanAbsolute(inspection.canonicalJailerPath) ||
		cleanupFilesystemRoot(inspection.canonicalJailerPath) || inspection.canonicalJailerPath == inspection.canonicalFirecrackerPath {
		return jailerStagingAuthority{}, firecracker.PathPlan{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorFailed, "inspect")
	}
	jailRoot := filepath.Join(inspection.canonicalChrootBaseDir, filepath.Base(inspection.canonicalFirecrackerPath), request.runtimeID, "root")
	authority := jailerStagingAuthority{
		RuntimeID: request.runtimeID, CanonicalFirecrackerPath: inspection.canonicalFirecrackerPath,
		ChrootBaseDir: inspection.canonicalChrootBaseDir, JailRootHostPath: jailRoot,
		UID: inspection.runtimeUID, GID: inspection.runtimeGID, DirectoryMode: 0o700,
	}
	if _, err := validateJailerStagingAuthority(authority); err != nil {
		return jailerStagingAuthority{}, firecracker.PathPlan{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorFailed, "inspect")
	}
	hostPaths, err := strictJailerHostPaths(jailRoot, request.jailPaths)
	if err != nil {
		return jailerStagingAuthority{}, firecracker.PathPlan{}, newStrictJailerCoordinatorError(errStrictJailerCoordinatorInvalid, "config")
	}
	return authority, hostPaths, nil
}
