package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

func TestBackendConfigFromMicroVMConfigUsesLaunchDescriptorAssetPaths(t *testing.T) {
	descriptor := validFirecrackerLaunchDescriptorForTest()
	input := validMicroVMConfig()
	input.KernelImagePath = "/legacy/images/vmlinux"
	input.RootfsPath = "/legacy/images/rootfs.ext4"
	input.InitrdPath = "/legacy/images/initrd.img"
	input.LaunchDescriptor = &descriptor

	config, err := BackendConfigFromMicroVMConfig(input)
	if err != nil {
		t.Fatalf("BackendConfigFromMicroVMConfig() error = %v, want nil", err)
	}

	if config.KernelImagePath != "/verified/assets/kernel-v1" {
		t.Fatalf("KernelImagePath = %q, want descriptor kernel path", config.KernelImagePath)
	}
	if config.RootfsPath != "/verified/assets/rootfs-v1.ext4" {
		t.Fatalf("RootfsPath = %q, want descriptor rootfs path", config.RootfsPath)
	}
	if config.InitrdPath == nil || *config.InitrdPath != "/verified/assets/initrd-v1.img" {
		t.Fatalf("InitrdPath = %#v, want descriptor initrd path", config.InitrdPath)
	}
	if config.LaunchDescriptor == nil {
		t.Fatal("LaunchDescriptor = nil, want normalized descriptor preserved for render validation")
	}

	bootSource, err := RenderBootSourcePayload(config)
	if err != nil {
		t.Fatalf("RenderBootSourcePayload() error = %v, want nil", err)
	}
	if bootSource.KernelImagePath != "/verified/assets/kernel-v1" {
		t.Fatalf("boot source kernel path = %q, want descriptor kernel path", bootSource.KernelImagePath)
	}
	if bootSource.InitrdPath == nil || *bootSource.InitrdPath != "/verified/assets/initrd-v1.img" {
		t.Fatalf("boot source initrd path = %#v, want descriptor initrd path", bootSource.InitrdPath)
	}

	rootDrive, err := RenderRootDrivePayload(config)
	if err != nil {
		t.Fatalf("RenderRootDrivePayload() error = %v, want nil", err)
	}
	if rootDrive.PathOnHost != "/verified/assets/rootfs-v1.ext4" {
		t.Fatalf("root drive path = %q, want descriptor rootfs path", rootDrive.PathOnHost)
	}
}

func TestRenderPayloadsKeepPathOnlyFallbackCompatible(t *testing.T) {
	config := validFirecrackerPayloadConfig(t)

	bootSource, err := RenderBootSourcePayload(config)
	if err != nil {
		t.Fatalf("RenderBootSourcePayload() error = %v, want nil", err)
	}
	if bootSource.KernelImagePath != "/opt/hal/images/vmlinux" {
		t.Fatalf("boot source kernel path = %q, want legacy kernel path", bootSource.KernelImagePath)
	}
	if bootSource.InitrdPath != nil {
		t.Fatalf("boot source initrd path = %#v, want nil legacy initrd", bootSource.InitrdPath)
	}

	rootDrive, err := RenderRootDrivePayload(config)
	if err != nil {
		t.Fatalf("RenderRootDrivePayload() error = %v, want nil", err)
	}
	if rootDrive.PathOnHost != "/opt/hal/images/rootfs.ext4" {
		t.Fatalf("root drive path = %q, want legacy rootfs path", rootDrive.PathOnHost)
	}
}

func TestRenderStartOperationPlanValidatesDescriptorBeforePlanning(t *testing.T) {
	descriptor := validFirecrackerLaunchDescriptorForTest()
	descriptor.Assets[0].Lock.Digest.Value = "token=ghp_secret"
	config := validFirecrackerOperationConfig(t)
	config.LaunchDescriptor = &descriptor

	_, err := RenderStartOperationPlan(config)

	assertFirecrackerOperationPlanError(t, err, "launchDescriptor.assets.0.lock.digest.value")
	assertFirecrackerErrorDoesNotLeak(t, err,
		"ghp_secret",
		"/verified/assets",
		"kernel-v1",
		"rootfs-v1.ext4",
		"initrd-v1.img",
	)
}

func TestRenderStartOperationPlanRejectsFirecrackerInconsistentDescriptor(t *testing.T) {
	descriptor := validFirecrackerLaunchDescriptorForTest()
	descriptor.Assets[0].Kind = assets.AssetKindRootfsImage
	config := validFirecrackerOperationConfig(t)
	config.LaunchDescriptor = &descriptor

	_, err := RenderStartOperationPlan(config)

	assertFirecrackerOperationPlanError(t, err, "launchDescriptor.assets.0.kind")
	assertFirecrackerErrorDoesNotLeak(t, err, "/verified/assets", "kernel-v1")
}

func TestDescriptorBackedOperationMetadataExposesOnlySafeAssetMetadata(t *testing.T) {
	descriptor := validFirecrackerLaunchDescriptorForTest()
	descriptor.Assets[0].Source.HostPath.Path = "/Users/alice/private/images/kernel-secret-v1"
	descriptor.Assets[1].Source.HostPath.Path = "/Users/alice/private/images/rootfs-secret-v1.ext4"
	descriptor.Assets[2].Source.HostPath.Path = "/Users/alice/private/images/initrd-secret-v1.img"

	input := validMicroVMConfig()
	input.KernelImagePath = "/legacy/images/vmlinux"
	input.RootfsPath = "/legacy/images/rootfs.ext4"
	input.InitrdPath = "/legacy/images/initrd.img"
	input.LaunchDescriptor = &descriptor

	backend := NewBackend(BackendOptions{
		BaseStateDir: firecrackerPathTestBase("descriptor-operation-state"),
	})
	target, err := backend.Create(context.Background(), microvm.BackendCreateRequest{
		Name:   "descriptor-dev",
		Config: input,
	})
	if err != nil {
		t.Fatalf("Create() error = %v, want nil", err)
	}
	controller, err := backend.Controller(context.Background(), microvm.ControllerRequest{
		Operation: microvm.OperationStart,
		Target:    *target,
	})
	if err != nil {
		t.Fatalf("Controller() error = %v, want nil", err)
	}
	started, err := controller.Start(context.Background(), microvm.ControllerLifecycleRequest{
		Operation: microvm.OperationStart,
		Config:    input,
		Target:    *target,
	})
	if err != nil {
		t.Fatalf("Start() error = %v, want nil", err)
	}

	if started.Runtime.Metadata == nil || started.Runtime.Metadata.OperationPlan == nil {
		t.Fatalf("operation metadata = %#v, want descriptor-backed operation plan", started.Runtime.Metadata)
	}
	payloads := started.Runtime.Metadata.OperationPlan.Payloads
	wantPayloads := descriptorRuntimePayloadsForTest()
	if !reflect.DeepEqual(payloads, wantPayloads) {
		t.Fatalf("runtime payloads = %#v, want %#v", payloads, wantPayloads)
	}
	if started.Runtime.Metadata.OperationPlan.ProcessDescriptor == nil {
		t.Fatal("process descriptor metadata = nil, want descriptor-backed process metadata")
	}
	if !reflect.DeepEqual(started.Runtime.Metadata.OperationPlan.ProcessDescriptor.Payloads, wantPayloads) {
		t.Fatalf("process descriptor payloads = %#v, want %#v", started.Runtime.Metadata.OperationPlan.ProcessDescriptor.Payloads, wantPayloads)
	}

	encoded, marshalErr := json.Marshal(started.Runtime.Metadata.OperationPlan)
	if marshalErr != nil {
		t.Fatalf("Marshal(operation metadata) error = %v", marshalErr)
	}
	publicText := string(encoded)
	for _, want := range []string{
		`"assetRole":"kernel"`,
		`"assetRole":"rootfs"`,
		`"assetRole":"initrd"`,
		`"id":"kernel-v1"`,
		`"id":"rootfs-v1"`,
		`"id":"initrd-v1"`,
		`"labels":["boot","stable"]`,
		`"algorithm":"sha256"`,
		strings.Repeat("a", 64),
		strings.Repeat("b", 64),
		strings.Repeat("c", 64),
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("operation metadata %s missing safe descriptor metadata %q", publicText, want)
		}
	}
	for _, unsafe := range []string{
		"/Users/alice",
		"private",
		"kernel-secret-v1",
		"rootfs-secret-v1.ext4",
		"initrd-secret-v1.img",
		"/legacy/images",
		"vmlinux",
		"rootfs.ext4",
		"initrd.img",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("operation metadata leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}

func TestDescriptorValidationErrorsAreSanitizedBeforeLiveBootRender(t *testing.T) {
	descriptor := validFirecrackerLaunchDescriptorForTest()
	descriptor.Assets[1].Source.HostPath.Path = " \t "
	config := validFirecrackerOperationConfig(t)
	config.LaunchDescriptor = &descriptor

	err := renderLiveBootFiles(config)

	assertFirecrackerLiveBootRenderError(t, err, "launchDescriptor.assets.1.source.hostPath.path")
	assertFirecrackerErrorDoesNotLeak(t, err, "/verified/assets", "rootfs-v1.ext4")
}

func validFirecrackerLaunchDescriptorForTest() assets.LaunchDescriptor {
	return assets.LaunchDescriptor{
		ID:     "phase41-firecracker-launch",
		Labels: []assets.SafeLabel{"phase41", "descriptor"},
		Assets: []assets.LaunchAsset{
			{
				ID:     "kernel-v1",
				Role:   assets.AssetRoleKernel,
				Kind:   assets.AssetKindKernelImage,
				Labels: []assets.SafeLabel{"boot", "stable"},
				Source: firecrackerDescriptorSourceForTest("/verified/assets/kernel-v1"),
				Lock:   firecrackerDescriptorLockForTest(strings.Repeat("a", 64)),
			},
			{
				ID:     "rootfs-v1",
				Role:   assets.AssetRoleRootfs,
				Kind:   assets.AssetKindRootfsImage,
				Labels: []assets.SafeLabel{"root", "stable"},
				Source: firecrackerDescriptorSourceForTest("/verified/assets/rootfs-v1.ext4"),
				Lock:   firecrackerDescriptorLockForTest(strings.Repeat("b", 64)),
			},
			{
				ID:     "initrd-v1",
				Role:   assets.AssetRoleInitrd,
				Kind:   assets.AssetKindInitrdImage,
				Labels: []assets.SafeLabel{"init", "stable"},
				Source: firecrackerDescriptorSourceForTest("/verified/assets/initrd-v1.img"),
				Lock:   firecrackerDescriptorLockForTest(strings.Repeat("c", 64)),
			},
		},
	}
}

func firecrackerDescriptorSourceForTest(path string) assets.AssetSource {
	return assets.AssetSource{
		Type: assets.SourceTypeLocalFile,
		HostPath: &assets.HostPathMetadata{
			Path: path,
			Role: assets.HostPathRoleResolvedLocalAsset,
		},
	}
}

func firecrackerDescriptorLockForTest(value string) assets.LockMetadata {
	return assets.LockMetadata{
		Digest: assets.DigestMetadata{
			Algorithm: assets.DigestAlgorithmSHA256,
			Value:     value,
		},
		SizeBytes:          4096,
		LockedAtUnixMillis: 1783015200000,
	}
}

func descriptorRuntimePayloadsForTest() []sandboxruntime.RuntimeOperationPayload {
	return []sandboxruntime.RuntimeOperationPayload{
		{Role: string(OperationPayloadRoleMachineConfig), APIPath: firecrackerMachineConfigAPIPath},
		{
			Role:    string(OperationPayloadRoleBootSource),
			APIPath: firecrackerBootSourceAPIPath,
			Assets: []sandboxruntime.RuntimeOperationPayloadAsset{
				{
					AssetRole: string(assets.AssetRoleKernel),
					ID:        "kernel-v1",
					Labels:    []string{"boot", "stable"},
					Digest: &sandboxruntime.RuntimeOperationPayloadDigest{
						Algorithm: string(assets.DigestAlgorithmSHA256),
						Value:     strings.Repeat("a", 64),
					},
				},
				{
					AssetRole: string(assets.AssetRoleInitrd),
					ID:        "initrd-v1",
					Labels:    []string{"init", "stable"},
					Digest: &sandboxruntime.RuntimeOperationPayloadDigest{
						Algorithm: string(assets.DigestAlgorithmSHA256),
						Value:     strings.Repeat("c", 64),
					},
				},
			},
		},
		{
			Role:    string(OperationPayloadRoleRootDrive),
			APIPath: firecrackerRootDriveAPIPath,
			Assets: []sandboxruntime.RuntimeOperationPayloadAsset{
				{
					AssetRole: string(assets.AssetRoleRootfs),
					ID:        "rootfs-v1",
					Labels:    []string{"root", "stable"},
					Digest: &sandboxruntime.RuntimeOperationPayloadDigest{
						Algorithm: string(assets.DigestAlgorithmSHA256),
						Value:     strings.Repeat("b", 64),
					},
				},
			},
		},
	}
}

func assertFirecrackerLiveBootRenderError(t *testing.T, err error, field string) {
	t.Helper()
	if err == nil {
		t.Fatal("live boot render error = nil, want invalid config error")
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
	if opErr.Operation != liveBootRenderOperation {
		t.Fatalf("OperationError.Operation = %q, want %q", opErr.Operation, liveBootRenderOperation)
	}
	if opErr.Field != field {
		t.Fatalf("OperationError.Field = %q, want %q", opErr.Field, field)
	}
}
