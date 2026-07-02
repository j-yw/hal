package microvm

import "strings"

const configValidationOperation = "validate_config"

// ValidateConfig validates backend-neutral microVM configuration before any
// backend, host, or worker operation starts.
func ValidateConfig(config Config) error {
	if strings.TrimSpace(config.KernelImagePath) == "" {
		return newConfigValidationError("kernelImagePath", "kernel image path is required")
	}
	if strings.TrimSpace(config.RootfsPath) == "" {
		return newConfigValidationError("rootfsPath", "rootfs path is required")
	}
	if config.CPUCount <= 0 {
		return newConfigValidationError("cpuCount", "cpu count must be positive")
	}
	if config.MemoryMiB <= 0 {
		return newConfigValidationError("memoryMiB", "memory size must be positive")
	}
	if config.DiskSizeMiB <= 0 {
		return newConfigValidationError("diskSizeMiB", "disk size must be positive")
	}
	if strings.TrimSpace(config.GuestWorkDir) == "" {
		return newConfigValidationError("guestWorkDir", "guest workdir is required")
	}
	if !validNetworkMode(config.NetworkMode) {
		return newConfigValidationError("networkMode", "network mode is unsupported")
	}
	return nil
}

func validNetworkMode(mode NetworkMode) bool {
	return NetworkMode(strings.TrimSpace(string(mode))) == NetworkModeNoLiveNetworking
}

func newConfigValidationError(field, message string) *OperationError {
	err := NewInvalidConfigError(configValidationOperation, ErrInvalidConfig)
	err.Field = field
	err.Message = message
	return err
}
