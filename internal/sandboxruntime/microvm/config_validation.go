package microvm

import (
	"strings"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

const configValidationOperation = "validate_config"

// ValidateConfig validates backend-neutral microVM configuration before any
// backend, host, or worker operation starts.
func ValidateConfig(config Config) error {
	if config.LaunchDescriptor != nil {
		if err := validateLaunchDescriptorConfig(config.LaunchDescriptor); err != nil {
			return err
		}
	}
	if config.LaunchDescriptor == nil && strings.TrimSpace(config.KernelImagePath) == "" {
		return newConfigValidationError("kernelImagePath", "kernel image path is required")
	}
	if config.LaunchDescriptor == nil && strings.TrimSpace(config.RootfsPath) == "" {
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

func validateLaunchDescriptorConfig(descriptor *assets.LaunchDescriptor) error {
	if descriptor == nil {
		return nil
	}
	result := assets.ValidateAndNormalizeLaunchDescriptor(*descriptor)
	if result.Valid {
		return nil
	}
	return newLaunchDescriptorValidationError(result.Errors)
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

func newLaunchDescriptorValidationError(validationErrors []assets.ValidationError) *OperationError {
	field := "launchDescriptor"
	message := "launch asset descriptor is invalid"
	if len(validationErrors) > 0 {
		validationErr := validationErrors[0]
		if strings.TrimSpace(validationErr.Field) != "" {
			field += "." + launchDescriptorValidationField(validationErr.Field)
		}
		if validationErr.Code != "" {
			message += " (" + string(validationErr.Code) + ")"
		}
		if strings.TrimSpace(validationErr.Message) != "" {
			message += ": " + strings.TrimSpace(validationErr.Message)
		}
	}
	return newConfigValidationError(field, message)
}

func launchDescriptorValidationField(field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return ""
	}
	field = strings.NewReplacer("[", ".", "]", "").Replace(field)
	return strings.Trim(field, ".")
}
