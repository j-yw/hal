package firecrackerhost

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

// errStrictJailerLaunchInvalid is returned before process creation when a
// strict host launch cannot be bound to one Jailer, Firecracker executable,
// runtime identity, and separate host/jail path plans.
var errStrictJailerLaunchInvalid = errors.New("strict Firecracker Jailer launch is invalid")

// strictJailerLaunchError identifies a sanitized invalid input field. It does
// not retain path, argument, environment, or numeric identity values.
type strictJailerLaunchError struct {
	field string
}

func (err *strictJailerLaunchError) Error() string {
	if err == nil {
		return errStrictJailerLaunchInvalid.Error()
	}
	field := safeStrictJailerLaunchField(err.field)
	if field == "" {
		return errStrictJailerLaunchInvalid.Error()
	}
	return errStrictJailerLaunchInvalid.Error() + ": " + field
}

func (*strictJailerLaunchError) Unwrap() error {
	return errStrictJailerLaunchInvalid
}

// strictJailerLaunchRequest is a pure, pre-exec boundary. HostPaths describe
// lifecycle-owned files outside the chroot; JailPaths describe their staged
// names as seen by Firecracker inside the chroot. The caller must not submit
// this request until a later host stager has created and verified that mapping.
//
// The current sealed L7/L8 inherited-FD asset path is deliberately rejected:
// the Firecracker Jailer closes inherited descriptors before exec.
type strictJailerLaunchRequest struct {
	RuntimeID  string
	JailerPath string
	// CanonicalFirecrackerPath must be produced by the future host inspector
	// after resolving symlinks and validating every parent component. Keeping
	// this input private prevents configuration text from being treated as that
	// authority before the inspector exists.
	CanonicalFirecrackerPath string
	UID                      uint32
	GID                      uint32
	ChrootBaseDir            string
	HostPaths                firecracker.PathPlan
	JailPaths                firecracker.PathPlan
	Firecracker              firecracker.ProcessRunnerStartRequest
}

// strictJailerLaunchPlan keeps executable paths, argv, identities, and path
// authority private until an atomic lifecycle consumer exists. It must not be
// passed to ProcessLifecycleManager.StartProcess: that compatibility entrypoint
// derives host ownership from Firecracker argv, while this plan's argv is
// intentionally jail-visible.
type strictJailerLaunchPlan struct {
	process         firecracker.ProcessRunnerStartRequest
	runtimeID       string
	firecrackerPath string
	runtimeUID      uint32
	runtimeGID      uint32
	chrootBaseDir   string
	enablePCI       bool
	hostPaths       firecracker.PathPlan
	jailPaths       firecracker.PathPlan
}

type strictJailerLaunchAuthority struct {
	process    firecracker.ProcessRunnerStartRequest
	runtimeUID uint32
	hostPaths  firecracker.PathPlan
}

// processRequest returns a copy of the exact Jailer command. The result has no
// environment entries or inherited files and intentionally omits daemonizing
// flags so the existing supervisor can retain the exact launched process.
func (plan strictJailerLaunchPlan) processRequest() firecracker.ProcessRunnerStartRequest {
	return firecracker.ProcessRunnerStartRequest{
		Executable:     plan.process.Executable,
		Args:           append([]string(nil), plan.process.Args...),
		Environment:    []string{},
		InheritedFiles: []*os.File{},
	}
}

// hostPathPlan returns the private lifecycle path plan. It remains separate from
// the jail-visible argv so polling and cleanup never mistake a chroot path for
// a host-owned path.
func (plan strictJailerLaunchPlan) hostPathPlan() firecracker.PathPlan {
	return plan.hostPaths
}

// jailPathPlan returns the private Firecracker-visible path plan for the host
// stager. These paths are never serialized as launch evidence.
func (plan strictJailerLaunchPlan) jailPathPlan() firecracker.PathPlan {
	return plan.jailPaths
}

// validatedAuthority re-renders the exact command from private structured
// fields. Lifecycle code consumes this authority and never derives host
// identity, ownership, or paths from jail-visible argv. Raw argv parsing stays
// confined to the final namespace runner validation boundary.
func (plan strictJailerLaunchPlan) validatedAuthority() (strictJailerLaunchAuthority, error) {
	if !validStrictJailerRuntimeID(plan.runtimeID) || strings.TrimSpace(plan.runtimeID) != plan.runtimeID ||
		!filepathIsCleanAbsolute(plan.firecrackerPath) || cleanupFilesystemRoot(plan.firecrackerPath) ||
		plan.runtimeUID == 0 || plan.runtimeGID == 0 ||
		!filepathIsCleanAbsolute(plan.chrootBaseDir) || cleanupFilesystemRoot(plan.chrootBaseDir) {
		return strictJailerLaunchAuthority{}, errStrictJailerLaunchInvalid
	}
	jailerPath := strings.TrimSpace(plan.process.Executable)
	if jailerPath != plan.process.Executable || !filepathIsCleanAbsolute(jailerPath) ||
		cleanupFilesystemRoot(jailerPath) || jailerPath == plan.firecrackerPath ||
		len(plan.process.Environment) != 0 || len(plan.process.InheritedFiles) != 0 {
		return strictJailerLaunchAuthority{}, errStrictJailerLaunchInvalid
	}
	jailPaths, removeJailState, err := validatedCleanupPathPlan(plan.jailPaths)
	if err != nil || !removeJailState || !cleanupPathPlansEqual(jailPaths, plan.jailPaths) {
		return strictJailerLaunchAuthority{}, errStrictJailerLaunchInvalid
	}
	hostPaths, removeHostState, err := validatedCleanupPathPlan(plan.hostPaths)
	if err != nil || !removeHostState || !cleanupPathPlansEqual(hostPaths, plan.hostPaths) {
		return strictJailerLaunchAuthority{}, errStrictJailerLaunchInvalid
	}
	jailRoot := filepath.Join(plan.chrootBaseDir, filepath.Base(plan.firecrackerPath), plan.runtimeID, "root")
	wantHostPaths, err := strictJailerHostPaths(jailRoot, jailPaths)
	if err != nil || !cleanupPathPlansEqual(wantHostPaths, hostPaths) {
		return strictJailerLaunchAuthority{}, errStrictJailerLaunchInvalid
	}
	wantArgs := strictJailerArguments(
		plan.runtimeID, plan.firecrackerPath, plan.runtimeUID, plan.runtimeGID,
		plan.chrootBaseDir, jailPaths, plan.enablePCI,
	)
	if !equalJailerStrings(plan.process.Args, wantArgs) {
		return strictJailerLaunchAuthority{}, errStrictJailerLaunchInvalid
	}
	return strictJailerLaunchAuthority{
		process: firecracker.ProcessRunnerStartRequest{
			Executable: jailerPath, Args: append([]string(nil), wantArgs...),
			Environment: []string{}, InheritedFiles: []*os.File{},
		},
		runtimeUID: plan.runtimeUID,
		hostPaths:  hostPaths,
	}, nil
}

// planStrictJailerLaunch validates and builds the immutable Jailer command
// shape without touching the filesystem or starting a process. It is not live
// strict proof; production selection remains blocked until host staging,
// ownership inspection, launch, readiness, and cleanup are implemented and
// accepted on prepared Linux.
func planStrictJailerLaunch(request strictJailerLaunchRequest) (strictJailerLaunchPlan, error) {
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if !validStrictJailerRuntimeID(runtimeID) {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("runtimeId")
	}

	jailerPath := strings.TrimSpace(request.JailerPath)
	if !filepathIsCleanAbsolute(jailerPath) || cleanupFilesystemRoot(jailerPath) {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("jailerPath")
	}
	firecrackerPath := strings.TrimSpace(request.CanonicalFirecrackerPath)
	if !filepathIsCleanAbsolute(firecrackerPath) || cleanupFilesystemRoot(firecrackerPath) || firecrackerPath == jailerPath {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("firecrackerPath")
	}
	if request.UID == 0 {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("uid")
	}
	if request.GID == 0 {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("gid")
	}
	chrootBaseDir := strings.TrimSpace(request.ChrootBaseDir)
	if !filepathIsCleanAbsolute(chrootBaseDir) || cleanupFilesystemRoot(chrootBaseDir) {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("chrootBaseDir")
	}

	jailPaths, removeJailState, err := validatedCleanupPathPlan(request.JailPaths)
	if err != nil || !removeJailState {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("jailPaths")
	}
	jailRoot := filepath.Join(chrootBaseDir, filepath.Base(firecrackerPath), runtimeID, "root")
	wantHostPaths, err := strictJailerHostPaths(jailRoot, jailPaths)
	if err != nil {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("jailPaths")
	}
	hostPaths, removeHostState, err := validatedCleanupPathPlan(request.HostPaths)
	if err != nil || !removeHostState || !cleanupPathPlansEqual(hostPaths, wantHostPaths) {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("hostPaths")
	}

	if len(request.Firecracker.Environment) != 0 {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("environment")
	}
	if len(request.Firecracker.InheritedFiles) != 0 {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("inheritedFiles")
	}
	if strings.TrimSpace(request.Firecracker.Executable) != firecrackerPath {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("firecrackerPath")
	}

	enablePCI := len(request.Firecracker.Args) > 0 && request.Firecracker.Args[0] == "--enable-pci"
	if !equalJailerStrings(request.Firecracker.Args, strictFirecrackerPathArgs(hostPaths, enablePCI)) {
		return strictJailerLaunchPlan{}, newStrictJailerLaunchError("hostPaths")
	}

	jailerArgs := strictJailerArguments(runtimeID, firecrackerPath, request.UID, request.GID, chrootBaseDir, jailPaths, enablePCI)

	return strictJailerLaunchPlan{
		process: firecracker.ProcessRunnerStartRequest{
			Executable:     jailerPath,
			Args:           jailerArgs,
			Environment:    []string{},
			InheritedFiles: []*os.File{},
		},
		runtimeID: runtimeID, firecrackerPath: firecrackerPath,
		runtimeUID: request.UID, runtimeGID: request.GID,
		chrootBaseDir: chrootBaseDir, enablePCI: enablePCI,
		hostPaths: hostPaths, jailPaths: jailPaths,
	}, nil
}

func strictJailerArguments(
	runtimeID, firecrackerPath string,
	runtimeUID, runtimeGID uint32,
	chrootBaseDir string,
	jailPaths firecracker.PathPlan,
	enablePCI bool,
) []string {
	args := []string{
		"--id", runtimeID,
		"--exec-file", firecrackerPath,
		"--uid", strconv.FormatUint(uint64(runtimeUID), 10),
		"--gid", strconv.FormatUint(uint64(runtimeGID), 10),
		"--chroot-base-dir", chrootBaseDir,
		"--",
	}
	return append(args, strictFirecrackerPathArgs(jailPaths, enablePCI)...)
}

func newStrictJailerLaunchError(field string) *strictJailerLaunchError {
	return &strictJailerLaunchError{field: safeStrictJailerLaunchField(field)}
}

func safeStrictJailerLaunchField(field string) string {
	switch strings.TrimSpace(field) {
	case "runtimeId", "jailerPath", "firecrackerPath", "uid", "gid", "chrootBaseDir",
		"hostPaths", "jailPaths", "environment", "inheritedFiles":
		return strings.TrimSpace(field)
	default:
		return ""
	}
}

func validStrictJailerRuntimeID(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	first := value[0]
	if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || (first >= '0' && first <= '9')) {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-':
		default:
			return false
		}
	}
	return true
}

func strictFirecrackerPathArgs(paths firecracker.PathPlan, enablePCI bool) []string {
	args := make([]string, 0, 9)
	if enablePCI {
		args = append(args, "--enable-pci")
	}
	return append(args,
		"--api-sock", paths.APISocketPath,
		"--config-file", paths.ConfigPath,
		"--log-path", paths.LogPath,
		"--metrics-path", paths.MetricsPath,
	)
}

func strictJailerHostPaths(jailRoot string, jailPaths firecracker.PathPlan) (firecracker.PathPlan, error) {
	mapPath := func(jailPath string) (string, error) {
		jailPath = filepath.Clean(jailPath)
		if !filepath.IsAbs(jailPath) || cleanupFilesystemRoot(jailPath) {
			return "", errStrictJailerLaunchInvalid
		}
		relative := strings.TrimPrefix(jailPath, string(filepath.Separator))
		hostPath := filepath.Join(jailRoot, relative)
		if !pathWithin(jailRoot, hostPath) {
			return "", errStrictJailerLaunchInvalid
		}
		return hostPath, nil
	}

	stateDir, err := mapPath(jailPaths.StateDir)
	if err != nil {
		return firecracker.PathPlan{}, err
	}
	apiSocketPath, err := mapPath(jailPaths.APISocketPath)
	if err != nil {
		return firecracker.PathPlan{}, err
	}
	configPath, err := mapPath(jailPaths.ConfigPath)
	if err != nil {
		return firecracker.PathPlan{}, err
	}
	logPath, err := mapPath(jailPaths.LogPath)
	if err != nil {
		return firecracker.PathPlan{}, err
	}
	metricsPath, err := mapPath(jailPaths.MetricsPath)
	if err != nil {
		return firecracker.PathPlan{}, err
	}
	vsockSocketPath, err := mapPath(jailPaths.VsockSocketPath)
	if err != nil {
		return firecracker.PathPlan{}, err
	}
	return firecracker.PathPlan{
		StateDir: stateDir, APISocketPath: apiSocketPath, ConfigPath: configPath,
		LogPath: logPath, MetricsPath: metricsPath, VsockSocketPath: vsockSocketPath,
	}, nil
}

func pathWithin(parent, candidate string) bool {
	relative, err := filepath.Rel(parent, candidate)
	return err == nil && relative != "." && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func equalJailerStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
