package firecrackerhost

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/firecracker"
)

const strictJailerLaunchMode = "jailer"

// ErrStrictJailerLaunchInvalid is returned before process creation when a
// strict host launch cannot be bound to one Jailer, Firecracker executable,
// runtime identity, and separate host/jail path plans.
var ErrStrictJailerLaunchInvalid = errors.New("strict Firecracker Jailer launch is invalid")

// StrictJailerLaunchError identifies a sanitized invalid input field. It does
// not retain path, argument, environment, or numeric identity values.
type StrictJailerLaunchError struct {
	Field string
}

func (err *StrictJailerLaunchError) Error() string {
	if err == nil || strings.TrimSpace(err.Field) == "" {
		return ErrStrictJailerLaunchInvalid.Error()
	}
	return ErrStrictJailerLaunchInvalid.Error() + ": " + err.Field
}

func (*StrictJailerLaunchError) Unwrap() error {
	return ErrStrictJailerLaunchInvalid
}

// StrictJailerLaunchRequest is a pure, pre-exec boundary. HostPaths describe
// lifecycle-owned files outside the chroot; JailPaths describe their staged
// names as seen by Firecracker inside the chroot. The caller must not submit
// this request until a later host stager has created and verified that mapping.
//
// The current sealed L7/L8 inherited-FD asset path is deliberately rejected:
// the Firecracker Jailer closes inherited descriptors before exec.
type StrictJailerLaunchRequest struct {
	RuntimeID       string
	JailerPath      string
	FirecrackerPath string
	UID             uint32
	GID             uint32
	ChrootBaseDir   string
	HostPaths       firecracker.PathPlan
	JailPaths       firecracker.PathPlan
	Firecracker     firecracker.ProcessRunnerStartRequest
}

// StrictJailerLaunchPlan keeps executable paths and argv private while
// exposing only the safe launch mode and runtime identity in JSON.
type StrictJailerLaunchPlan struct {
	Mode      string `json:"mode"`
	RuntimeID string `json:"runtimeId"`

	process   firecracker.ProcessRunnerStartRequest
	hostPaths firecracker.PathPlan
	jailPaths firecracker.PathPlan
}

// ProcessRequest returns a copy of the exact Jailer command. The result has no
// environment entries or inherited files and intentionally omits daemonizing
// flags so the existing supervisor can retain the exact launched process.
func (plan StrictJailerLaunchPlan) ProcessRequest() firecracker.ProcessRunnerStartRequest {
	return firecracker.ProcessRunnerStartRequest{
		Executable:     plan.process.Executable,
		Args:           append([]string(nil), plan.process.Args...),
		Environment:    []string{},
		InheritedFiles: []*os.File{},
	}
}

// HostPaths returns the private lifecycle path plan. It remains separate from
// the jail-visible argv so polling and cleanup never mistake a chroot path for
// a host-owned path.
func (plan StrictJailerLaunchPlan) HostPaths() firecracker.PathPlan {
	return plan.hostPaths
}

// JailPaths returns the private Firecracker-visible path plan for the host
// stager. These paths are never serialized as launch evidence.
func (plan StrictJailerLaunchPlan) JailPaths() firecracker.PathPlan {
	return plan.jailPaths
}

// PlanStrictJailerLaunch validates and builds the immutable Jailer command
// shape without touching the filesystem or starting a process. It is not live
// strict proof; production selection remains blocked until host staging,
// ownership inspection, launch, readiness, and cleanup are implemented and
// accepted on prepared Linux.
func PlanStrictJailerLaunch(request StrictJailerLaunchRequest) (StrictJailerLaunchPlan, error) {
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if !validStrictJailerRuntimeID(runtimeID) {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("runtimeId")
	}

	jailerPath := strings.TrimSpace(request.JailerPath)
	if !filepathIsCleanAbsolute(jailerPath) {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("jailerPath")
	}
	firecrackerPath := strings.TrimSpace(request.FirecrackerPath)
	if !filepathIsCleanAbsolute(firecrackerPath) || firecrackerPath == jailerPath {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("firecrackerPath")
	}
	if request.UID == 0 {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("uid")
	}
	if request.GID == 0 {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("gid")
	}
	chrootBaseDir := strings.TrimSpace(request.ChrootBaseDir)
	if !filepathIsCleanAbsolute(chrootBaseDir) || cleanupFilesystemRoot(chrootBaseDir) {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("chrootBaseDir")
	}

	jailPaths, removeJailState, err := validatedCleanupPathPlan(request.JailPaths)
	if err != nil || !removeJailState {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("jailPaths")
	}
	jailRoot := filepath.Join(chrootBaseDir, filepath.Base(firecrackerPath), runtimeID, "root")
	wantHostPaths, err := strictJailerHostPaths(jailRoot, jailPaths)
	if err != nil {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("jailPaths")
	}
	hostPaths, removeHostState, err := validatedCleanupPathPlan(request.HostPaths)
	if err != nil || !removeHostState || !cleanupPathPlansEqual(hostPaths, wantHostPaths) {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("hostPaths")
	}

	if len(request.Firecracker.Environment) != 0 {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("environment")
	}
	if len(request.Firecracker.InheritedFiles) != 0 {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("inheritedFiles")
	}
	if strings.TrimSpace(request.Firecracker.Executable) != firecrackerPath {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("firecrackerPath")
	}

	enablePCI := len(request.Firecracker.Args) > 0 && request.Firecracker.Args[0] == "--enable-pci"
	if !equalJailerStrings(request.Firecracker.Args, strictFirecrackerPathArgs(hostPaths, enablePCI)) {
		return StrictJailerLaunchPlan{}, newStrictJailerLaunchError("hostPaths")
	}

	jailerArgs := []string{
		"--id", runtimeID,
		"--exec-file", firecrackerPath,
		"--uid", strconv.FormatUint(uint64(request.UID), 10),
		"--gid", strconv.FormatUint(uint64(request.GID), 10),
		"--chroot-base-dir", chrootBaseDir,
		"--",
	}
	jailerArgs = append(jailerArgs, strictFirecrackerPathArgs(jailPaths, enablePCI)...)

	return StrictJailerLaunchPlan{
		Mode:      strictJailerLaunchMode,
		RuntimeID: runtimeID,
		process: firecracker.ProcessRunnerStartRequest{
			Executable:     jailerPath,
			Args:           jailerArgs,
			Environment:    []string{},
			InheritedFiles: []*os.File{},
		},
		hostPaths: hostPaths,
		jailPaths: jailPaths,
	}, nil
}

func newStrictJailerLaunchError(field string) *StrictJailerLaunchError {
	return &StrictJailerLaunchError{Field: strings.TrimSpace(field)}
}

func validStrictJailerRuntimeID(value string) bool {
	if value == "" || len(value) > 64 {
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
			return "", ErrStrictJailerLaunchInvalid
		}
		relative := strings.TrimPrefix(jailPath, string(filepath.Separator))
		hostPath := filepath.Join(jailRoot, relative)
		if !pathWithin(jailRoot, hostPath) {
			return "", ErrStrictJailerLaunchInvalid
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
