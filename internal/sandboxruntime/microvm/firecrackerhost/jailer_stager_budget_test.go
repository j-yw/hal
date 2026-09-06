package firecrackerhost

import (
	"bytes"
	"errors"
	"testing"
)

func TestStageStrictJailerResourcesRejectsOversizedResourcesBeforeRootCreation(t *testing.T) {
	tests := []struct {
		name string
		edit func(*jailerStagingRequest)
	}{
		{
			name: "kernel",
			edit: func(request *jailerStagingRequest) {
				request.Kernel.SizeBytes = maxJailerStagingResourceBytes + 1
			},
		},
		{
			name: "rootfs",
			edit: func(request *jailerStagingRequest) {
				request.Rootfs.SizeBytes = maxJailerStagingResourceBytes + 1
			},
		},
		{
			name: "config",
			edit: func(request *jailerStagingRequest) {
				request.Config.SizeBytes = maxStrictJailerConfigBytes + 1
			},
		},
		{
			name: "support",
			edit: func(request *jailerStagingRequest) {
				request.Support[0].SizeBytes = maxJailerStagingResourceBytes + 1
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := validJailerStagingRequest()
			tt.edit(&request)
			filesystem := newFakeJailerStagingFilesystem()

			_, err := stageStrictJailerResources(filesystem, request)
			if !errors.Is(err, errJailerStagingInvalid) {
				t.Fatalf("error = %v, want errJailerStagingInvalid", err)
			}
			if filesystem.createCalls != 0 {
				t.Fatalf("root create calls = %d, want resource budget validation before mutation", filesystem.createCalls)
			}
			assertJailerStagingErrorRedacted(t, err)
		})
	}
}

func TestStageStrictJailerResourcesRejectsAggregateBudgetBeforeRootCreation(t *testing.T) {
	request := validJailerStagingRequest()
	request.Kernel.SizeBytes = maxJailerStagingResourceBytes
	request.Rootfs.SizeBytes = maxJailerStagingResourceBytes
	request.Support[0].SizeBytes = maxJailerStagingResourceBytes
	request.Support = append(request.Support, jailerStagingResourceInput{
		ID:        "support-second",
		JailPath:  "/etc/hal/second",
		Source:    bytes.NewReader(nil),
		SizeBytes: maxJailerStagingResourceBytes,
		SHA256:    sha256Hex(nil),
		Mode:      0o400,
	})
	filesystem := newFakeJailerStagingFilesystem()

	_, err := stageStrictJailerResources(filesystem, request)
	if !errors.Is(err, errJailerStagingInvalid) {
		t.Fatalf("error = %v, want errJailerStagingInvalid", err)
	}
	if filesystem.createCalls != 0 {
		t.Fatalf("root create calls = %d, want aggregate budget validation before mutation", filesystem.createCalls)
	}
	assertJailerStagingErrorRedacted(t, err)
}

func TestValidateJailerStagingResourcesAcceptsExactByteBudgets(t *testing.T) {
	request := validJailerStagingRequest()
	request.Kernel.SizeBytes = maxJailerStagingResourceBytes
	request.Rootfs.SizeBytes = maxJailerStagingResourceBytes
	request.Config.SizeBytes = 0
	request.Support[0].SizeBytes = maxJailerStagingResourceBytes
	request.Support = append(request.Support, jailerStagingResourceInput{
		ID:        "support-second",
		JailPath:  "/etc/hal/second",
		Source:    bytes.NewReader(nil),
		SizeBytes: maxJailerStagingResourceBytes,
		SHA256:    sha256Hex(nil),
		Mode:      0o400,
	})

	resources, err := validateJailerStagingResources(request.Authority, request)
	if err != nil {
		t.Fatalf("validateJailerStagingResources() error = %v, want exact limits accepted", err)
	}
	if len(resources) != 5 {
		t.Fatalf("validated resources = %d, want 5", len(resources))
	}

	request = validJailerStagingRequest()
	request.Config.SizeBytes = maxStrictJailerConfigBytes
	if _, err := validateJailerStagingResources(request.Authority, request); err != nil {
		t.Fatalf("validateJailerStagingResources(config limit) error = %v, want nil", err)
	}
}
