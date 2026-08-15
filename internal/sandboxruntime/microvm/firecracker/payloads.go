package firecracker

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

const (
	// PayloadRenderingOperation is the sanitized operation label used for
	// Firecracker payload rendering errors.
	PayloadRenderingOperation = "firecracker_payload"

	defaultRootDriveID = "rootfs"
)

// MachineConfigPayload is the JSON-compatible Firecracker machine-config
// request body derived from the validated backend configuration.
type MachineConfigPayload struct {
	VCPUCount  int `json:"vcpu_count"`
	MemSizeMiB int `json:"mem_size_mib"`
}

// BootSourcePayload is the JSON-compatible Firecracker boot-source request
// body. InitrdPath is omitted when the backend configuration has no initrd.
type BootSourcePayload struct {
	KernelImagePath string  `json:"kernel_image_path"`
	InitrdPath      *string `json:"initrd_path,omitempty"`
	BootArgs        string  `json:"boot_args,omitempty"`
}

// RootDrivePayload is the JSON-compatible Firecracker block-device request
// body for the root filesystem.
type RootDrivePayload struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

// RenderMachineConfigPayload derives the Firecracker machine-config payload
// without starting processes, opening sockets, or consulting live binaries.
func RenderMachineConfigPayload(config BackendConfig) (MachineConfigPayload, error) {
	if config.CPUCount <= 0 {
		return MachineConfigPayload{}, newPayloadRenderingError("cpuCount", "CPU count must be positive")
	}
	if config.MemoryMiB <= 0 {
		return MachineConfigPayload{}, newPayloadRenderingError("memoryMiB", "memory size must be positive")
	}
	return MachineConfigPayload{
		VCPUCount:  config.CPUCount,
		MemSizeMiB: config.MemoryMiB,
	}, nil
}

// RenderBootSourcePayload derives the Firecracker boot-source payload without
// touching host files or requiring a Firecracker binary.
func RenderBootSourcePayload(config BackendConfig) (BootSourcePayload, error) {
	bootArgs, err := productionBootArgs(config)
	if err != nil {
		return BootSourcePayload{}, err
	}
	if config.LaunchDescriptor != nil {
		launchAssets, err := firecrackerLaunchDescriptorAssets(config.LaunchDescriptor, PayloadRenderingOperation)
		if err != nil {
			return BootSourcePayload{}, err
		}
		return BootSourcePayload{
			KernelImagePath: launchAssets.kernelPath(),
			InitrdPath:      launchAssets.initrdPath(),
			BootArgs:        bootArgs,
		}, nil
	}
	kernelImagePath := strings.TrimSpace(config.KernelImagePath)
	if kernelImagePath == "" {
		return BootSourcePayload{}, newPayloadRenderingError("kernelImagePath", "kernel image path is required")
	}
	return BootSourcePayload{
		KernelImagePath: kernelImagePath,
		InitrdPath:      optionalPayloadPath(config.InitrdPath),
		BootArgs:        bootArgs,
	}, nil
}

func productionBootArgs(config BackendConfig) (string, error) {
	if !config.ProductionVsock {
		if mode := strings.TrimSpace(string(config.NetworkMode)); mode != "" && mode != string(microvm.NetworkModeNoLiveNetworking) {
			return "", newPayloadRenderingError("networkMode", "live networking requires production guest readiness")
		}
		return "", nil
	}
	_, staticNetwork, err := renderNetworkInterfaces(config)
	if err != nil {
		return "", err
	}
	if staticNetwork == nil {
		return l5ProductionBootArgs, nil
	}
	return l7ProductionBootArgs(*staticNetwork)
}

// RenderRootDrivePayload derives the Firecracker root block-device payload
// without checking or opening the root filesystem path.
func RenderRootDrivePayload(config BackendConfig) (RootDrivePayload, error) {
	if config.LaunchDescriptor != nil {
		launchAssets, err := firecrackerLaunchDescriptorAssets(config.LaunchDescriptor, PayloadRenderingOperation)
		if err != nil {
			return RootDrivePayload{}, err
		}
		return RootDrivePayload{
			DriveID:      defaultRootDriveID,
			PathOnHost:   launchAssets.rootfsPath(),
			IsRootDevice: true,
			IsReadOnly:   config.ProductionVsock,
		}, nil
	}
	rootfsPath := strings.TrimSpace(config.RootfsPath)
	if rootfsPath == "" {
		return RootDrivePayload{}, newPayloadRenderingError("rootfsPath", "rootfs path is required")
	}
	return RootDrivePayload{
		DriveID:      defaultRootDriveID,
		PathOnHost:   rootfsPath,
		IsRootDevice: true,
		IsReadOnly:   config.ProductionVsock,
	}, nil
}

func optionalPayloadPath(value *string) *string {
	if value == nil {
		return nil
	}
	return optionalPath(*value)
}

func newPayloadRenderingError(field, message string) *microvm.OperationError {
	err := microvm.NewInvalidConfigError(PayloadRenderingOperation, microvm.ErrInvalidConfig)
	err.Field = strings.TrimSpace(field)
	err.Message = strings.TrimSpace(message)
	return err
}
