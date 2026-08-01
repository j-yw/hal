package firecracker

import (
	"errors"
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

const (
	// ConfigOperation is the sanitized operation label used for Firecracker
	// configuration mapping errors.
	ConfigOperation = "firecracker_config"

	DefaultRuntimeID     = BackendID
	DefaultStateDir      = "firecracker"
	DefaultAPISocketPath = "firecracker.sock"
	DefaultLogPath       = "firecracker.log"
	DefaultMetricsPath   = "firecracker.metrics"
	DefaultConfigPath    = "firecracker-config.json"
	defaultVsockPath     = "guest.vsock"

	l5GuestCID           uint32 = 3
	l5ProductionBootArgs        = "console=ttyS0 reboot=k panic=1 nomodule devtmpfs.mount=0 ro root=/dev/vda rootfstype=ext4 rootwait init=/sbin/init"
)

// BackendConfig is the Firecracker-specific configuration contract derived
// from the backend-neutral microVM config before live backend behavior exists.
type BackendConfig struct {
	BackendID         string                              `json:"backendId,omitempty"`
	ExecutablePath    string                              `json:"executablePath,omitempty"`
	JailerPath        *string                             `json:"jailerPath,omitempty"`
	KernelImagePath   string                              `json:"kernelImagePath,omitempty"`
	RootfsPath        string                              `json:"rootfsPath,omitempty"`
	InitrdPath        *string                             `json:"initrdPath,omitempty"`
	LaunchDescriptor  *assets.LaunchDescriptor            `json:"-"`
	VerifiedL7Profile *localresolver.VerifiedL7Profile    `json:"-"`
	VerifiedL7Assets  *localresolver.VerifiedL7AssetLease `json:"-"`
	CPUCount          int                                 `json:"cpuCount,omitempty"`
	MemoryMiB         int                                 `json:"memoryMiB,omitempty"`
	GuestWorkDir      GuestWorkDirMetadata                `json:"guestWorkDir,omitempty"`
	RuntimeID         string                              `json:"runtimeId,omitempty"`
	Paths             PathPlan                            `json:"paths,omitempty"`
	ProductionVsock   bool                                `json:"productionVsock,omitempty"`
	NetworkMode       microvm.NetworkMode                 `json:"networkMode,omitempty"`
	NetworkInterfaces []NetworkInterfaceConfig            `json:"-"`
	StaticNetwork     *StaticNetworkBootConfig            `json:"-"`
}

// NetworkInterfaceConfig is private live input supplied by the L7 topology
// owner after it creates a TAP. Raw interface and MAC values are deliberately
// omitted from JSON and public runtime metadata.
type NetworkInterfaceConfig struct {
	InterfaceID    string `json:"-"`
	HostDeviceName string `json:"-"`
	GuestMAC       string `json:"-"`
}

// StaticNetworkBootConfig is private live input used only to render bounded
// guest boot parameters. Addresses and the proxy endpoint are never public
// Firecracker metadata.
type StaticNetworkBootConfig struct {
	GuestInterfaceName string `json:"-"`
	IPv4Address        string `json:"-"`
	IPv4Gateway        string `json:"-"`
	IPv6Address        string `json:"-"`
	IPv6Gateway        string `json:"-"`
	ProxyURL           string `json:"-"`
}

// GuestWorkDirMetadata carries the guest workdir contract without adding host
// filesystem metadata.
type GuestWorkDirMetadata struct {
	Path string `json:"path,omitempty"`
}

// PathPlan carries safe Firecracker path-planning inputs. Later path-planning
// work can replace these defaults with target-specific paths without changing
// payload consumers.
type PathPlan struct {
	StateDir        string `json:"stateDir,omitempty"`
	APISocketPath   string `json:"apiSocketPath,omitempty"`
	LogPath         string `json:"logPath,omitempty"`
	MetricsPath     string `json:"metricsPath,omitempty"`
	ConfigPath      string `json:"configPath,omitempty"`
	VsockSocketPath string `json:"vsockSocketPath,omitempty"`
}

// BackendConfigFromMicroVMConfig maps valid Phase 31 backend-neutral microVM
// configuration into the Firecracker backend contract without touching the
// host filesystem, opening sockets, or consulting live Firecracker binaries.
func BackendConfigFromMicroVMConfig(input microvm.Config) (BackendConfig, error) {
	config := microvm.ApplyDefaults(input)
	if err := validateBackendConfigInput(config); err != nil {
		return BackendConfig{}, err
	}

	kernelImagePath := strings.TrimSpace(config.KernelImagePath)
	rootfsPath := strings.TrimSpace(config.RootfsPath)
	initrdPath := optionalPath(config.InitrdPath)
	var launchDescriptor *assets.LaunchDescriptor
	if config.LaunchDescriptor != nil {
		launchAssets, err := firecrackerLaunchDescriptorAssets(config.LaunchDescriptor, ConfigOperation)
		if err != nil {
			return BackendConfig{}, err
		}
		kernelImagePath = launchAssets.kernelPath()
		rootfsPath = launchAssets.rootfsPath()
		initrdPath = launchAssets.initrdPath()
		descriptor := launchAssets.Descriptor
		launchDescriptor = &descriptor
	}

	return BackendConfig{
		BackendID:        BackendID,
		ExecutablePath:   strings.TrimSpace(config.HypervisorPath),
		JailerPath:       optionalPath(config.JailerPath),
		KernelImagePath:  kernelImagePath,
		RootfsPath:       rootfsPath,
		InitrdPath:       initrdPath,
		LaunchDescriptor: launchDescriptor,
		CPUCount:         config.CPUCount,
		MemoryMiB:        config.MemoryMiB,
		GuestWorkDir: GuestWorkDirMetadata{
			Path: strings.TrimSpace(config.GuestWorkDir),
		},
		RuntimeID: DefaultRuntimeID,
		Paths: PathPlan{
			StateDir:      DefaultStateDir,
			APISocketPath: DefaultAPISocketPath,
			LogPath:       DefaultLogPath,
			MetricsPath:   DefaultMetricsPath,
			ConfigPath:    DefaultConfigPath,
		},
		NetworkMode: config.NetworkMode,
	}, nil
}

func validateBackendConfigInput(config microvm.Config) error {
	if strings.TrimSpace(config.HypervisorPath) == "" {
		return newBackendConfigError("executablePath", "firecracker executable path is required")
	}
	if err := microvm.ValidateConfig(config); err != nil {
		return backendConfigErrorFromMicroVM(err)
	}
	return nil
}

func backendConfigErrorFromMicroVM(err error) error {
	field := "microvmConfig"
	message := "microVM config is invalid"

	var operationErr *microvm.OperationError
	if errors.As(err, &operationErr) {
		if strings.TrimSpace(operationErr.Field) != "" {
			field = operationErr.Field
		}
		if strings.TrimSpace(operationErr.Message) != "" {
			message = operationErr.Message
		}
	}
	return newBackendConfigError(field, message)
}

func newBackendConfigError(field, message string) *microvm.OperationError {
	err := microvm.NewInvalidConfigError(ConfigOperation, microvm.ErrInvalidConfig)
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}

func optionalPath(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}
