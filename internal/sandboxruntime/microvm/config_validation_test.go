package microvm

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestValidateConfigAcceptsMinimalNoLiveNetworking(t *testing.T) {
	config := minimalValidConfig()

	if err := ValidateConfig(config); err != nil {
		t.Fatalf("ValidateConfig() error = %v, want nil", err)
	}
}

func TestValidateConfigDoesNotRequireLiveBackendState(t *testing.T) {
	config := minimalValidConfig()
	config.KernelImagePath = "/missing/hal/images/vmlinux"
	config.RootfsPath = "/missing/hal/images/rootfs.ext4"
	config.HypervisorPath = "/missing/bin/firecracker"
	config.JailerPath = "/missing/bin/firecracker-jailer"

	if err := ValidateConfig(config); err != nil {
		t.Fatalf("ValidateConfig() error = %v, want nil for path-only validation", err)
	}
}

func TestValidateConfigRejectsMissingKernelAndRootfs(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		field   string
		message string
	}{
		{
			name: "missing kernel",
			mutate: func(config *Config) {
				config.KernelImagePath = " \t "
			},
			field:   "kernelImagePath",
			message: "kernel image path is required",
		},
		{
			name: "missing rootfs",
			mutate: func(config *Config) {
				config.RootfsPath = ""
			},
			field:   "rootfsPath",
			message: "rootfs path is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := minimalValidConfig()
			tt.mutate(&config)

			err := ValidateConfig(config)
			assertInvalidConfigError(t, err, tt.field, tt.message)
		})
	}
}

func TestValidateConfigRejectsInvalidSizing(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		field   string
		message string
	}{
		{
			name: "zero cpu",
			mutate: func(config *Config) {
				config.CPUCount = 0
			},
			field:   "cpuCount",
			message: "cpu count must be positive",
		},
		{
			name: "negative memory",
			mutate: func(config *Config) {
				config.MemoryMiB = -1024
			},
			field:   "memoryMiB",
			message: "memory size must be positive",
		},
		{
			name: "zero disk",
			mutate: func(config *Config) {
				config.DiskSizeMiB = 0
			},
			field:   "diskSizeMiB",
			message: "disk size must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := minimalValidConfig()
			tt.mutate(&config)

			err := ValidateConfig(config)
			assertInvalidConfigError(t, err, tt.field, tt.message)
		})
	}
}

func TestValidateConfigRejectsUnsupportedNetworkMode(t *testing.T) {
	config := minimalValidConfig()
	config.NetworkMode = "tap"

	err := ValidateConfig(config)
	assertInvalidConfigError(t, err, "networkMode", "network mode is unsupported")
}

func TestValidateConfigErrorStringsAreSanitized(t *testing.T) {
	config := minimalValidConfig()
	config.NetworkMode = NetworkMode("tap token=ghp_secret endpoint=https://deploy.example.test:8443/api /Users/alice/private/tap")
	config.KernelImagePath = "/Users/alice/private/vmlinux"
	config.RootfsPath = "/var/folders/secret/rootfs.ext4"
	config.ImageLabel = "secret-template"

	err := ValidateConfig(config)
	assertInvalidConfigError(t, err, "networkMode", "network mode is unsupported")

	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(validation error) error: %v", marshalErr)
	}
	publicText := err.Error() + " " + string(encoded)
	for _, unsafe := range []string{
		"/Users/alice",
		"/var/folders",
		"rootfs.ext4",
		"ghp_secret",
		"deploy.example.test",
		"8443",
		"secret-template",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("validation error leaked unsafe fragment %q in %q", unsafe, publicText)
		}
	}
}

func minimalValidConfig() Config {
	return Config{
		KernelImagePath: "/opt/hal/images/vmlinux",
		RootfsPath:      "/opt/hal/images/rootfs.ext4",
		CPUCount:        2,
		MemoryMiB:       2048,
		DiskSizeMiB:     10240,
		GuestWorkDir:    "/workspace/project",
		NetworkMode:     NetworkModeNoLiveNetworking,
	}
}

func assertInvalidConfigError(t *testing.T, err error, field, message string) {
	t.Helper()
	if err == nil {
		t.Fatal("ValidateConfig() error = nil, want invalid config error")
	}
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("errors.Is(err, ErrInvalidConfig) = false for %v", err)
	}

	var opErr *OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T, want *OperationError", err)
	}
	if opErr.Code != ErrorCodeInvalidConfig {
		t.Fatalf("OperationError.Code = %q, want %q", opErr.Code, ErrorCodeInvalidConfig)
	}
	if opErr.Operation != "validate_config" {
		t.Fatalf("OperationError.Operation = %q, want validate_config", opErr.Operation)
	}
	if opErr.Field != field {
		t.Fatalf("OperationError.Field = %q, want %q", opErr.Field, field)
	}
	if !strings.Contains(opErr.Error(), message) {
		t.Fatalf("OperationError.Error() = %q, want message %q", opErr.Error(), message)
	}

	encoded, marshalErr := json.Marshal(opErr)
	if marshalErr != nil {
		t.Fatalf("Marshal(OperationError) error: %v", marshalErr)
	}
	if !strings.Contains(string(encoded), `"field":"`+field+`"`) {
		t.Fatalf("OperationError JSON = %s, want field %q", encoded, field)
	}
}
