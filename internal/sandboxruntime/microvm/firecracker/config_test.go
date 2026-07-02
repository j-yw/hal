package firecracker

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestBackendConfigFromMicroVMConfigMapsRequiredFields(t *testing.T) {
	input := validMicroVMConfig()
	input.HypervisorPath = " /usr/bin/firecracker "
	input.KernelImagePath = " /opt/hal/images/vmlinux "
	input.RootfsPath = " /opt/hal/images/rootfs.ext4 "
	input.CPUCount = 4
	input.MemoryMiB = 4096
	input.GuestWorkDir = " /workspace/project "

	config, err := BackendConfigFromMicroVMConfig(input)
	if err != nil {
		t.Fatalf("BackendConfigFromMicroVMConfig() error = %v, want nil", err)
	}

	if config.BackendID != BackendID {
		t.Fatalf("BackendID = %q, want %q", config.BackendID, BackendID)
	}
	if config.ExecutablePath != "/usr/bin/firecracker" {
		t.Fatalf("ExecutablePath = %q, want trimmed Firecracker executable path", config.ExecutablePath)
	}
	if config.KernelImagePath != "/opt/hal/images/vmlinux" {
		t.Fatalf("KernelImagePath = %q, want trimmed kernel image path", config.KernelImagePath)
	}
	if config.RootfsPath != "/opt/hal/images/rootfs.ext4" {
		t.Fatalf("RootfsPath = %q, want trimmed rootfs path", config.RootfsPath)
	}
	if config.CPUCount != 4 {
		t.Fatalf("CPUCount = %d, want explicit CPU count", config.CPUCount)
	}
	if config.MemoryMiB != 4096 {
		t.Fatalf("MemoryMiB = %d, want explicit memory size", config.MemoryMiB)
	}
	if config.GuestWorkDir.Path != "/workspace/project" {
		t.Fatalf("GuestWorkDir.Path = %q, want trimmed guest workdir", config.GuestWorkDir.Path)
	}
	if config.RuntimeID != DefaultRuntimeID {
		t.Fatalf("RuntimeID = %q, want %q", config.RuntimeID, DefaultRuntimeID)
	}
	if config.Paths.StateDir != DefaultStateDir {
		t.Fatalf("Paths.StateDir = %q, want %q", config.Paths.StateDir, DefaultStateDir)
	}
	if config.Paths.APISocketPath != DefaultAPISocketPath {
		t.Fatalf("Paths.APISocketPath = %q, want %q", config.Paths.APISocketPath, DefaultAPISocketPath)
	}
	if config.Paths.LogPath != DefaultLogPath {
		t.Fatalf("Paths.LogPath = %q, want %q", config.Paths.LogPath, DefaultLogPath)
	}
	if config.Paths.MetricsPath != DefaultMetricsPath {
		t.Fatalf("Paths.MetricsPath = %q, want %q", config.Paths.MetricsPath, DefaultMetricsPath)
	}
}

func TestBackendConfigFromMicroVMConfigAppliesCPUAndMemoryDefaults(t *testing.T) {
	input := validMicroVMConfig()
	input.CPUCount = 0
	input.MemoryMiB = 0

	config, err := BackendConfigFromMicroVMConfig(input)
	if err != nil {
		t.Fatalf("BackendConfigFromMicroVMConfig() error = %v, want nil", err)
	}

	if config.CPUCount != microvm.DefaultCPUCount {
		t.Fatalf("CPUCount = %d, want microVM default %d", config.CPUCount, microvm.DefaultCPUCount)
	}
	if config.MemoryMiB != microvm.DefaultMemoryMiB {
		t.Fatalf("MemoryMiB = %d, want microVM default %d", config.MemoryMiB, microvm.DefaultMemoryMiB)
	}
}

func TestBackendConfigFromMicroVMConfigPreservesOptionalInitrdAndJailer(t *testing.T) {
	withoutOptionals, err := BackendConfigFromMicroVMConfig(validMicroVMConfig())
	if err != nil {
		t.Fatalf("BackendConfigFromMicroVMConfig() error = %v, want nil", err)
	}
	if withoutOptionals.InitrdPath != nil {
		t.Fatalf("InitrdPath = %q, want nil when microVM initrd path is empty", *withoutOptionals.InitrdPath)
	}
	if withoutOptionals.JailerPath != nil {
		t.Fatalf("JailerPath = %q, want nil when microVM jailer path is empty", *withoutOptionals.JailerPath)
	}

	encoded, marshalErr := json.Marshal(withoutOptionals)
	if marshalErr != nil {
		t.Fatalf("Marshal(BackendConfig) error: %v", marshalErr)
	}
	payload := string(encoded)
	for _, omitted := range []string{`"initrdPath"`, `"jailerPath"`} {
		if strings.Contains(payload, omitted) {
			t.Fatalf("BackendConfig JSON with nil optionals = %s, want %s omitted", payload, omitted)
		}
	}

	input := validMicroVMConfig()
	input.InitrdPath = " /opt/hal/images/initrd.img "
	input.JailerPath = " /usr/bin/firecracker-jailer "

	withOptionals, err := BackendConfigFromMicroVMConfig(input)
	if err != nil {
		t.Fatalf("BackendConfigFromMicroVMConfig() error = %v, want nil", err)
	}
	if withOptionals.InitrdPath == nil || *withOptionals.InitrdPath != "/opt/hal/images/initrd.img" {
		t.Fatalf("InitrdPath = %#v, want trimmed optional initrd path", withOptionals.InitrdPath)
	}
	if withOptionals.JailerPath == nil || *withOptionals.JailerPath != "/usr/bin/firecracker-jailer" {
		t.Fatalf("JailerPath = %#v, want trimmed optional jailer path", withOptionals.JailerPath)
	}
}

func TestBackendConfigFromMicroVMConfigRejectsMissingRequiredInputsWithoutLeakingPaths(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(*microvm.Config)
	}{
		{
			name:  "missing executable",
			field: "executablePath",
			mutate: func(config *microvm.Config) {
				config.HypervisorPath = " \t "
			},
		},
		{
			name:  "missing kernel",
			field: "kernelImagePath",
			mutate: func(config *microvm.Config) {
				config.KernelImagePath = ""
			},
		},
		{
			name:  "missing rootfs",
			field: "rootfsPath",
			mutate: func(config *microvm.Config) {
				config.RootfsPath = ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validMicroVMConfig()
			input.HypervisorPath = "/Users/alice/private/bin/firecracker"
			input.KernelImagePath = "/Users/alice/private/images/vmlinux"
			input.RootfsPath = "/var/folders/secret/rootfs.ext4"
			input.InitrdPath = "/tmp/secret/initrd.img"
			tt.mutate(&input)

			_, err := BackendConfigFromMicroVMConfig(input)
			assertFirecrackerInvalidConfigError(t, err, tt.field)
			assertFirecrackerErrorDoesNotLeak(t, err,
				"/Users/alice",
				"/var/folders",
				"/tmp/secret",
				"rootfs.ext4",
				"initrd.img",
				"vmlinux",
			)
		})
	}
}

func TestBackendConfigFromMicroVMConfigRejectsInvalidCPUAndMemory(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(*microvm.Config)
	}{
		{
			name:  "negative cpu",
			field: "cpuCount",
			mutate: func(config *microvm.Config) {
				config.CPUCount = -1
			},
		},
		{
			name:  "negative memory",
			field: "memoryMiB",
			mutate: func(config *microvm.Config) {
				config.MemoryMiB = -512
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validMicroVMConfig()
			tt.mutate(&input)

			_, err := BackendConfigFromMicroVMConfig(input)
			assertFirecrackerInvalidConfigError(t, err, tt.field)
		})
	}
}

func validMicroVMConfig() microvm.Config {
	config := microvm.DefaultConfig()
	config.HypervisorPath = "/usr/bin/firecracker"
	config.KernelImagePath = "/opt/hal/images/vmlinux"
	config.RootfsPath = "/opt/hal/images/rootfs.ext4"
	config.GuestWorkDir = "/workspace/project"
	return config
}

func assertFirecrackerInvalidConfigError(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatal("BackendConfigFromMicroVMConfig() error = nil, want invalid config error")
	}
	if !errors.Is(err, microvm.ErrInvalidConfig) {
		t.Fatalf("errors.Is(err, microvm.ErrInvalidConfig) = false for %v", err)
	}
	var opErr *microvm.OperationError
	if !errors.As(err, &opErr) {
		t.Fatalf("error type = %T, want *microvm.OperationError", err)
	}
	if opErr.Code != microvm.ErrorCodeInvalidConfig {
		t.Fatalf("OperationError.Code = %q, want %q", opErr.Code, microvm.ErrorCodeInvalidConfig)
	}
	if opErr.Operation != ConfigOperation {
		t.Fatalf("OperationError.Operation = %q, want %q", opErr.Operation, ConfigOperation)
	}
	if opErr.Field != field {
		t.Fatalf("OperationError.Field = %q, want %q", opErr.Field, field)
	}
}

func assertFirecrackerErrorDoesNotLeak(t *testing.T, err error, unsafeFragments ...string) {
	t.Helper()
	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(error) error: %v", marshalErr)
	}
	publicText := err.Error() + " " + string(encoded)
	for _, unsafe := range unsafeFragments {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("public error text leaked unsafe fragment %q in %q", unsafe, publicText)
		}
	}
}
