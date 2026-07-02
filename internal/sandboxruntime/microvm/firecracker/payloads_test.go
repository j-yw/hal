package firecracker

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
)

func TestRenderMachineConfigPayloadReturnsExactJSON(t *testing.T) {
	config := validFirecrackerPayloadConfig(t)
	config.CPUCount = 4
	config.MemoryMiB = 4096

	payload, err := RenderMachineConfigPayload(config)
	if err != nil {
		t.Fatalf("RenderMachineConfigPayload() error = %v, want nil", err)
	}

	want := `{"vcpu_count":4,"mem_size_mib":4096}`
	if got := mustMarshalFirecrackerPayload(t, payload); got != want {
		t.Fatalf("machine payload JSON = %s, want %s", got, want)
	}
}

func TestRenderBootSourcePayloadOmitsOptionalInitrd(t *testing.T) {
	config := validFirecrackerPayloadConfig(t)

	withoutInitrd, err := RenderBootSourcePayload(config)
	if err != nil {
		t.Fatalf("RenderBootSourcePayload() error = %v, want nil", err)
	}

	withoutInitrdJSON := mustMarshalFirecrackerPayload(t, withoutInitrd)
	wantWithoutInitrd := `{"kernel_image_path":"/opt/hal/images/vmlinux"}`
	if withoutInitrdJSON != wantWithoutInitrd {
		t.Fatalf("boot payload JSON without initrd = %s, want %s", withoutInitrdJSON, wantWithoutInitrd)
	}
	if strings.Contains(withoutInitrdJSON, "initrd_path") {
		t.Fatalf("boot payload JSON without initrd = %s, want initrd_path omitted", withoutInitrdJSON)
	}

	emptyInitrd := " \t "
	config.InitrdPath = &emptyInitrd
	emptyInitrdPayload, err := RenderBootSourcePayload(config)
	if err != nil {
		t.Fatalf("RenderBootSourcePayload(empty initrd) error = %v, want nil", err)
	}
	if got := mustMarshalFirecrackerPayload(t, emptyInitrdPayload); got != wantWithoutInitrd {
		t.Fatalf("boot payload JSON with empty initrd = %s, want %s", got, wantWithoutInitrd)
	}

	initrdPath := " /opt/hal/images/initrd.img "
	config.InitrdPath = &initrdPath
	withInitrd, err := RenderBootSourcePayload(config)
	if err != nil {
		t.Fatalf("RenderBootSourcePayload(with initrd) error = %v, want nil", err)
	}

	wantWithInitrd := `{"kernel_image_path":"/opt/hal/images/vmlinux","initrd_path":"/opt/hal/images/initrd.img"}`
	if got := mustMarshalFirecrackerPayload(t, withInitrd); got != wantWithInitrd {
		t.Fatalf("boot payload JSON with initrd = %s, want %s", got, wantWithInitrd)
	}
}

func TestRenderRootDrivePayloadReturnsExactJSON(t *testing.T) {
	config := validFirecrackerPayloadConfig(t)

	payload, err := RenderRootDrivePayload(config)
	if err != nil {
		t.Fatalf("RenderRootDrivePayload() error = %v, want nil", err)
	}

	want := `{"drive_id":"rootfs","path_on_host":"/opt/hal/images/rootfs.ext4","is_root_device":true,"is_read_only":false}`
	if got := mustMarshalFirecrackerPayload(t, payload); got != want {
		t.Fatalf("root drive payload JSON = %s, want %s", got, want)
	}
}

func TestRenderPayloadsRejectInvalidConfigWithoutLeakingRawMetadata(t *testing.T) {
	tests := []struct {
		name   string
		field  string
		mutate func(*BackendConfig)
		render func(BackendConfig) error
	}{
		{
			name:  "invalid cpu",
			field: "cpuCount",
			mutate: func(config *BackendConfig) {
				config.CPUCount = 0
			},
			render: func(config BackendConfig) error {
				_, err := RenderMachineConfigPayload(config)
				return err
			},
		},
		{
			name:  "missing kernel",
			field: "kernelImagePath",
			mutate: func(config *BackendConfig) {
				config.KernelImagePath = " \t "
			},
			render: func(config BackendConfig) error {
				_, err := RenderBootSourcePayload(config)
				return err
			},
		},
		{
			name:  "missing rootfs",
			field: "rootfsPath",
			mutate: func(config *BackendConfig) {
				config.RootfsPath = " \t "
			},
			render: func(config BackendConfig) error {
				_, err := RenderRootDrivePayload(config)
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := BackendConfig{
				KernelImagePath: "/Users/alice/private/images/secret-vmlinux",
				RootfsPath:      "/var/folders/private/rootfs-secret.ext4",
				InitrdPath:      stringPtr(" /tmp/private/initrd-secret.img "),
				CPUCount:        2,
				MemoryMiB:       2048,
			}
			tt.mutate(&config)

			err := tt.render(config)
			assertFirecrackerPayloadRenderingError(t, err, tt.field)
			assertFirecrackerErrorDoesNotLeak(t, err,
				"/Users/alice",
				"/var/folders",
				"/tmp/private",
				"secret-vmlinux",
				"rootfs-secret.ext4",
				"initrd-secret.img",
			)
		})
	}
}

func validFirecrackerPayloadConfig(t *testing.T) BackendConfig {
	t.Helper()

	config, err := BackendConfigFromMicroVMConfig(validMicroVMConfig())
	if err != nil {
		t.Fatalf("BackendConfigFromMicroVMConfig() error = %v, want nil", err)
	}
	return config
}

func mustMarshalFirecrackerPayload(t *testing.T, payload any) string {
	t.Helper()

	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal(%T) error: %v", payload, err)
	}
	return string(encoded)
}

func assertFirecrackerPayloadRenderingError(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatal("payload render error = nil, want invalid config error")
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
	if opErr.Operation != PayloadRenderingOperation {
		t.Fatalf("OperationError.Operation = %q, want %q", opErr.Operation, PayloadRenderingOperation)
	}
	if opErr.Field != field {
		t.Fatalf("OperationError.Field = %q, want %q", opErr.Field, field)
	}
}

func stringPtr(value string) *string {
	return &value
}
