package firecracker

import (
	"path/filepath"
	"strings"
	"unicode"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

const (
	// PathPlanningOperation is the sanitized operation label used for
	// Firecracker path planning errors.
	PathPlanningOperation = "firecracker_path_plan"

	maxPathPlanRuntimeIDBytes         = 64
	maxFirecrackerUnixSocketPathBytes = 107
)

// PathPlanRequest contains the inputs needed to derive per-runtime
// Firecracker state paths without touching the host filesystem.
type PathPlanRequest struct {
	RuntimeID    string `json:"runtimeId,omitempty"`
	BaseStateDir string `json:"-"`
}

// PlanPaths derives deterministic Firecracker state paths for one runtime
// target. The returned paths are for process-boundary use; validation errors
// are sanitized and refer only to stable path roles.
func PlanPaths(request PathPlanRequest) (PathPlan, error) {
	runtimeID := strings.TrimSpace(request.RuntimeID)
	if !validPathPlanRuntimeID(runtimeID) {
		return PathPlan{}, newPathPlanError("runtimeId", "runtime ID must be a safe identifier")
	}

	baseStateDir := strings.TrimSpace(request.BaseStateDir)
	if baseStateDir == "" {
		return PathPlan{}, newPathPlanError("baseStateDir", "base state directory is required")
	}
	if hasUnsafePathControl(baseStateDir) {
		return PathPlan{}, newPathPlanError("baseStateDir", "base state directory is invalid")
	}

	baseStateDir = filepath.Clean(baseStateDir)
	if !filepath.IsAbs(baseStateDir) {
		return PathPlan{}, newPathPlanError("baseStateDir", "base state directory must be absolute")
	}
	if isFilesystemRoot(baseStateDir) {
		return PathPlan{}, newPathPlanError("baseStateDir", "base state directory must not be the filesystem root")
	}

	stateDir := filepath.Join(baseStateDir, runtimeID)
	apiSocketPath := filepath.Join(stateDir, DefaultAPISocketPath)
	if !validFirecrackerAPISocketPath(apiSocketPath) {
		return PathPlan{}, newPathPlanError("apiSocketPath", "API socket path exceeds the Unix socket path limit")
	}
	return PathPlan{
		StateDir:      stateDir,
		APISocketPath: apiSocketPath,
		LogPath:       filepath.Join(stateDir, DefaultLogPath),
		MetricsPath:   filepath.Join(stateDir, DefaultMetricsPath),
		ConfigPath:    filepath.Join(stateDir, DefaultConfigPath),
	}, nil
}

// Firecracker runs only on Linux, where sockaddr_un.sun_path has 108 bytes.
// Pathname sockets must reserve one byte for the terminating NUL.
func validFirecrackerAPISocketPath(path string) bool {
	return len(path) <= maxFirecrackerUnixSocketPathBytes
}

func validPathPlanRuntimeID(value string) bool {
	if value == "" || value == "." || value == ".." || len(value) > maxPathPlanRuntimeIDBytes {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '-' || r == '.':
		default:
			return false
		}
	}
	return true
}

func hasUnsafePathControl(value string) bool {
	for _, r := range value {
		if r == 0 || unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func isFilesystemRoot(path string) bool {
	volumeName := filepath.VolumeName(path)
	withoutVolume := strings.TrimPrefix(path, volumeName)
	return withoutVolume == string(filepath.Separator)
}

func newPathPlanError(field, message string) *microvm.OperationError {
	err := microvm.NewInvalidConfigError(PathPlanningOperation, microvm.ErrInvalidConfig)
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}
