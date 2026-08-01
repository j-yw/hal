package firecracker

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

const liveBootRenderOperation = "firecracker_live_boot_render"

var errUnsafeLiveBootStateEntry = errors.New("unsafe live boot state entry")

// Log and metrics paths are intentionally omitted here because the validated
// start argv initializes them once through Firecracker's CLI flags.
type liveBootConfigFile struct {
	MachineConfig     MachineConfigPayload      `json:"machine-config"`
	BootSource        BootSourcePayload         `json:"boot-source"`
	Drives            []RootDrivePayload        `json:"drives"`
	NetworkInterfaces []networkInterfacePayload `json:"network-interfaces,omitempty"`
	Vsock             *vsockDevicePayload       `json:"vsock,omitempty"`
	Entropy           *entropyDevicePayload     `json:"entropy,omitempty"`
}

type vsockDevicePayload struct {
	GuestCID uint32 `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

type entropyDevicePayload struct{}

func renderLiveBootFiles(config BackendConfig) error {
	files, err := renderLiveBootFilesForStart(config)
	if len(files) > 0 {
		err = joinLiveBootRenderCleanup(err, closeProcessInheritedFiles(files))
		if config.VerifiedL7Assets != nil {
			err = joinLiveBootRenderCleanup(err, config.VerifiedL7Assets.Close())
		}
	}
	return err
}

func renderLiveBootFilesForStart(config BackendConfig) (files []*os.File, retErr error) {
	if config.LaunchDescriptor != nil {
		if _, err := firecrackerLaunchDescriptorAssets(config.LaunchDescriptor, liveBootRenderOperation); err != nil {
			return nil, err
		}
	}
	paths, err := validateLiveBootRenderPaths(config.Paths)
	if err != nil {
		return nil, err
	}
	config.Paths = paths
	var material *sealedL7LaunchMaterial
	prepared := false
	l7Lease := config.VerifiedL7Assets
	ownsL7Lease := config.NetworkMode == microvm.NetworkModeL7PolicyProxy && l7Lease != nil
	defer func() {
		if ownsL7Lease && !prepared {
			retErr = joinLiveBootRenderCleanup(retErr, l7Lease.Close())
		}
	}()
	if config.NetworkMode == microvm.NetworkModeL7PolicyProxy {
		if err := ensureLiveBootStateDir(paths.StateDir); err != nil {
			return nil, err
		}
		config, material, err = prepareVerifiedL7LaunchMaterial(config)
		if err != nil {
			return nil, err
		}
	}
	rendered, err := liveBootConfig(config)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(rendered)
	if err != nil {
		return nil, newLiveBootRenderFailure("config", "boot config encoding failed", err)
	}
	encoded = append(encoded, '\n')

	if err := ensureLiveBootStateDir(paths.StateDir); err != nil {
		return nil, err
	}
	if config.ProductionVsock {
		if err := renderProductionLiveBootFiles(paths, encoded); err != nil {
			return nil, err
		}
		if material == nil {
			return nil, nil
		}
		files, err := material.inheritedFiles()
		if err != nil {
			return nil, newLiveBootRenderFailure("launchDescriptor", "sealed L7 launch assets are unavailable", err)
		}
		prepared = true
		return files, nil
	}
	if err := writeLiveBootFile(paths.ConfigPath, encoded, "configPath", "boot config write failed"); err != nil {
		return nil, err
	}
	if err := writeLiveBootSupportFile(paths.LogPath, "logPath", "log file preparation failed"); err != nil {
		return nil, err
	}
	if err := writeLiveBootSupportFile(paths.MetricsPath, "metricsPath", "metrics file preparation failed"); err != nil {
		return nil, err
	}
	return nil, nil
}

func prepareVerifiedL7LaunchMaterial(config BackendConfig) (BackendConfig, *sealedL7LaunchMaterial, error) {
	if config.VerifiedL7Assets == nil || config.LaunchDescriptor == nil {
		return BackendConfig{}, nil, newLiveBootRenderConfigError("launchDescriptor", "verified L7 asset lease is required")
	}
	childFD, err := normalizedL7AssetChildFDStart(config.AssetChildFDStart)
	if err != nil {
		return BackendConfig{}, nil, err
	}
	material, err := newSealedL7LaunchMaterial(config.Paths.StateDir, childFD)
	if err != nil {
		return BackendConfig{}, nil, newLiveBootRenderFailure("launchDescriptor", "private L7 launch material preparation failed", err)
	}
	descriptor, profile, err := config.VerifiedL7Assets.PrepareLaunch(config.LaunchDescriptor, material)
	if err != nil {
		prepareErr := newLiveBootRenderL7PrepareError(err)
		prepareErr = joinLiveBootRenderCleanup(prepareErr, material.Close())
		return BackendConfig{}, nil, prepareErr
	}
	config.LaunchDescriptor = &descriptor
	config.VerifiedL7Profile = &profile
	return config, material, nil
}

func newLiveBootRenderL7PrepareError(cause error) error {
	err := microvm.NewInvalidConfigError(liveBootRenderOperation, sanitizedLiveBootL7PrepareCause{cause: cause})
	err.Field = "launchDescriptor"
	err.Message = "current verified L7 network image assets are required"
	return err
}

type sanitizedLiveBootL7PrepareCause struct {
	cause error
}

func (sanitizedLiveBootL7PrepareCause) Error() string {
	return microvm.ErrInvalidConfig.Error()
}

func (cause sanitizedLiveBootL7PrepareCause) Is(target error) bool {
	return target == microvm.ErrInvalidConfig || errors.Is(cause.cause, target)
}

func (cause sanitizedLiveBootL7PrepareCause) As(target any) bool {
	return errors.As(cause.cause, target)
}

func joinLiveBootRenderCleanup(primary, cleanupErr error) error {
	if cleanupErr == nil {
		return primary
	}
	uncertain := newLiveBootRenderFailure(
		"launchDescriptor",
		"sealed L7 launch asset cleanup was not confirmed",
		cleanupErr,
	)
	if primary == nil {
		return uncertain
	}
	return errors.Join(primary, uncertain)
}

func liveBootConfig(config BackendConfig) (liveBootConfigFile, error) {
	if config.ProductionVsock && strings.TrimSpace(config.Paths.VsockSocketPath) == "" {
		return liveBootConfigFile{}, newLiveBootRenderConfigError("vsockSocketPath", "vsock socket path is required")
	}
	machineConfig, err := RenderMachineConfigPayload(config)
	if err != nil {
		return liveBootConfigFile{}, liveBootRenderPayloadError(err)
	}
	networkInterfaces, staticNetwork, err := renderNetworkInterfaces(config)
	if err != nil {
		return liveBootConfigFile{}, err
	}
	config.StaticNetwork = staticNetwork
	bootSource, err := RenderBootSourcePayload(config)
	if err != nil {
		return liveBootConfigFile{}, liveBootRenderPayloadError(err)
	}
	rootDrive, err := RenderRootDrivePayload(config)
	if err != nil {
		return liveBootConfigFile{}, liveBootRenderPayloadError(err)
	}
	if config.ProductionVsock && hasDuplicateLiveBootPath(
		filepath.Clean(config.Paths.APISocketPath),
		filepath.Clean(config.Paths.VsockSocketPath),
		filepath.Clean(config.Paths.ConfigPath),
		filepath.Clean(config.Paths.LogPath),
		filepath.Clean(config.Paths.MetricsPath),
		filepath.Clean(rootDrive.PathOnHost),
	) {
		return liveBootConfigFile{}, newLiveBootRenderConfigError("paths", "runtime and root drive paths must be unique")
	}
	return liveBootConfigFile{
		MachineConfig:     machineConfig,
		BootSource:        bootSource,
		Drives:            []RootDrivePayload{rootDrive},
		NetworkInterfaces: networkInterfaces,
		Vsock:             renderVsockDevice(config),
		Entropy:           renderEntropyDevice(config),
	}, nil
}

func renderEntropyDevice(config BackendConfig) *entropyDevicePayload {
	if !config.ProductionVsock {
		return nil
	}
	return &entropyDevicePayload{}
}

func renderVsockDevice(config BackendConfig) *vsockDevicePayload {
	if !config.ProductionVsock {
		return nil
	}
	return &vsockDevicePayload{GuestCID: l5GuestCID, UDSPath: config.Paths.VsockSocketPath}
}

func validateLiveBootRenderPaths(paths PathPlan) (PathPlan, error) {
	stateDir, err := cleanAbsoluteLiveBootPath(paths.StateDir, "stateDir")
	if err != nil {
		return PathPlan{}, err
	}
	if isFilesystemRoot(stateDir) {
		return PathPlan{}, newLiveBootRenderConfigError("stateDir", "state directory is invalid")
	}

	apiSocketPath, err := cleanLiveBootStateFilePath(paths.APISocketPath, stateDir, "apiSocketPath")
	if err != nil {
		return PathPlan{}, err
	}
	if !validFirecrackerAPISocketPath(apiSocketPath) {
		return PathPlan{}, newLiveBootRenderConfigError("apiSocketPath", "API socket path exceeds the Unix socket path limit")
	}
	configPath, err := cleanLiveBootStateFilePath(paths.ConfigPath, stateDir, "configPath")
	if err != nil {
		return PathPlan{}, err
	}
	logPath, err := cleanLiveBootStateFilePath(paths.LogPath, stateDir, "logPath")
	if err != nil {
		return PathPlan{}, err
	}
	metricsPath, err := cleanLiveBootStateFilePath(paths.MetricsPath, stateDir, "metricsPath")
	if err != nil {
		return PathPlan{}, err
	}
	vsockSocketPath := ""
	if strings.TrimSpace(paths.VsockSocketPath) != "" {
		vsockSocketPath, err = cleanLiveBootStateFilePath(paths.VsockSocketPath, stateDir, "vsockSocketPath")
		if err != nil {
			return PathPlan{}, err
		}
		if !validFirecrackerAPISocketPath(vsockSocketPath) {
			return PathPlan{}, newLiveBootRenderConfigError("vsockSocketPath", "vsock socket path exceeds the Unix socket path limit")
		}
	}
	allPaths := []string{apiSocketPath, configPath, logPath, metricsPath}
	if vsockSocketPath != "" {
		allPaths = append(allPaths, vsockSocketPath)
	}
	if hasDuplicateLiveBootPath(allPaths...) {
		return PathPlan{}, newLiveBootRenderConfigError("paths", "support file paths must be unique")
	}

	return PathPlan{
		StateDir:        stateDir,
		APISocketPath:   apiSocketPath,
		ConfigPath:      configPath,
		LogPath:         logPath,
		MetricsPath:     metricsPath,
		VsockSocketPath: vsockSocketPath,
	}, nil
}

func cleanLiveBootStateFilePath(path, stateDir, field string) (string, error) {
	cleaned, err := cleanAbsoluteLiveBootPath(path, field)
	if err != nil {
		return "", err
	}
	if cleaned == stateDir {
		return "", newLiveBootRenderConfigError(field, "support file path must be inside the state directory")
	}
	rel, err := filepath.Rel(stateDir, cleaned)
	if err != nil || rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return "", newLiveBootRenderConfigError(field, "support file path must be inside the state directory")
	}
	if filepath.Dir(cleaned) != stateDir {
		return "", newLiveBootRenderConfigError(field, "support file path must be directly inside the state directory")
	}
	return cleaned, nil
}

func cleanAbsoluteLiveBootPath(path, field string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", newLiveBootRenderConfigError(field, "path is required")
	}
	if hasUnsafePathControl(path) {
		return "", newLiveBootRenderConfigError(field, "path is invalid")
	}
	cleaned := filepath.Clean(path)
	if !filepath.IsAbs(cleaned) {
		return "", newLiveBootRenderConfigError(field, "path must be absolute")
	}
	return cleaned, nil
}

func hasDuplicateLiveBootPath(paths ...string) bool {
	seen := make(map[string]bool, len(paths))
	for _, path := range paths {
		if seen[path] {
			return true
		}
		seen[path] = true
	}
	return false
}

func ensureLiveBootStateDir(path string) error {
	info, err := os.Lstat(path)
	switch {
	case err == nil:
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
			return newLiveBootRenderConfigError("stateDir", "state directory is invalid")
		}
		return nil
	case !os.IsNotExist(err):
		return newLiveBootRenderFailure("stateDir", "state directory inspection failed", err)
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return newLiveBootRenderFailure("stateDir", "state directory creation failed", err)
	}
	info, err = os.Lstat(path)
	if err != nil {
		return newLiveBootRenderFailure("stateDir", "state directory inspection failed", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return newLiveBootRenderConfigError("stateDir", "state directory is invalid")
	}
	return nil
}

func writeLiveBootFile(path string, data []byte, field, message string) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return newLiveBootRenderConfigError(field, "support file path is invalid")
	} else if err != nil && !os.IsNotExist(err) {
		return newLiveBootRenderFailure(field, message, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return newLiveBootRenderFailure(field, message, err)
	}
	return nil
}

func writeLiveBootSupportFile(path, field, message string) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return newLiveBootRenderConfigError(field, "support file path is invalid")
	} else if err != nil && !os.IsNotExist(err) {
		return newLiveBootRenderFailure(field, message, err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return newLiveBootRenderFailure(field, message, err)
	}
	if err := file.Close(); err != nil {
		return newLiveBootRenderFailure(field, message, err)
	}
	return nil
}

func liveBootRenderPayloadError(err error) error {
	field := "payloads"
	message := "boot payload rendering failed"

	var operationErr *microvm.OperationError
	if errors.As(err, &operationErr) {
		if strings.TrimSpace(operationErr.Field) != "" {
			field = operationErr.Field
		}
		if strings.TrimSpace(operationErr.Message) != "" {
			message = operationErr.Message
		}
	}
	return newLiveBootRenderConfigError(field, message)
}

func newLiveBootRenderConfigError(field, message string) *microvm.OperationError {
	err := microvm.NewInvalidConfigError(liveBootRenderOperation, microvm.ErrInvalidConfig)
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}

func newLiveBootRenderFailure(field, message string, cause error) *microvm.OperationError {
	err := microvm.NewBackendOperationFailedError(liveBootRenderOperation, sanitizedLiveBootRenderCause{
		detail: message,
		cause:  cause,
	})
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}

type sanitizedLiveBootRenderCause struct {
	detail string
	cause  error
}

func (err sanitizedLiveBootRenderCause) Error() string {
	if detail := strings.TrimSpace(err.detail); detail != "" {
		return detail
	}
	return "live boot file rendering failed"
}

func (err sanitizedLiveBootRenderCause) Is(target error) bool {
	return target != nil && errors.Is(err.cause, target)
}

func (err sanitizedLiveBootRenderCause) As(target any) bool {
	return errors.As(err.cause, target)
}
