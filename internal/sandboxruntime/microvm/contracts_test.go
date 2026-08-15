package microvm

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

func TestConfigContractFieldsAndJSONNames(t *testing.T) {
	configType := reflect.TypeOf(Config{})

	assertConfigField(t, configType, "KernelImagePath", reflect.TypeOf(""), `json:"kernelImagePath,omitempty"`)
	assertConfigField(t, configType, "RootfsPath", reflect.TypeOf(""), `json:"rootfsPath,omitempty"`)
	assertConfigField(t, configType, "InitrdPath", reflect.TypeOf(""), `json:"initrdPath,omitempty"`)
	assertConfigField(t, configType, "JailerPath", reflect.TypeOf(""), `json:"jailerPath,omitempty"`)
	assertConfigField(t, configType, "HypervisorPath", reflect.TypeOf(""), `json:"hypervisorPath,omitempty"`)
	assertConfigField(t, configType, "LaunchDescriptor", reflect.TypeOf((*assets.LaunchDescriptor)(nil)), `json:"launchDescriptor,omitempty"`)
	assertConfigField(t, configType, "CPUCount", reflect.TypeOf(0), `json:"cpuCount,omitempty"`)
	assertConfigField(t, configType, "MemoryMiB", reflect.TypeOf(0), `json:"memoryMiB,omitempty"`)
	assertConfigField(t, configType, "DiskSizeMiB", reflect.TypeOf(0), `json:"diskSizeMiB,omitempty"`)
	assertConfigField(t, configType, "GuestWorkDir", reflect.TypeOf(""), `json:"guestWorkDir,omitempty"`)
	assertConfigField(t, configType, "NetworkMode", reflect.TypeOf(NetworkMode("")), `json:"networkMode,omitempty"`)
	assertConfigField(t, configType, "ImageLabel", reflect.TypeOf(""), `json:"imageLabel,omitempty"`)
	assertConfigField(t, configType, "ImageDigest", reflect.TypeOf(""), `json:"imageDigest,omitempty"`)
	assertConfigField(t, configType, "TemplateLabel", reflect.TypeOf(""), `json:"templateLabel,omitempty"`)
	assertConfigField(t, configType, "TemplateDigest", reflect.TypeOf(""), `json:"templateDigest,omitempty"`)

	optionsType := reflect.TypeOf(Options{})
	assertConfigField(t, optionsType, "Config", configType, `json:"config,omitempty"`)
}

func TestConfigJSONIncludesMicroVMRuntimeInputs(t *testing.T) {
	descriptor := validConfigLaunchDescriptorForTest()
	config := Config{
		KernelImagePath:  "/opt/hal/images/vmlinux",
		RootfsPath:       "/opt/hal/images/rootfs.ext4",
		InitrdPath:       "/opt/hal/images/initrd.img",
		JailerPath:       "/usr/bin/firecracker-jailer",
		HypervisorPath:   "/usr/bin/cloud-hypervisor",
		LaunchDescriptor: &descriptor,
		CPUCount:         4,
		MemoryMiB:        4096,
		DiskSizeMiB:      16384,
		GuestWorkDir:     "/workspace/project",
		NetworkMode:      NetworkModeNoLiveNetworking,
		ImageLabel:       "ubuntu-24.04",
		ImageDigest:      "sha256:abc123",
		TemplateLabel:    "hal-agent",
		TemplateDigest:   "sha256:def456",
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Marshal(Config) error: %v", err)
	}
	payload := string(encoded)
	for _, want := range []string{
		`"kernelImagePath":`,
		`"rootfsPath":`,
		`"initrdPath":`,
		`"jailerPath":`,
		`"hypervisorPath":`,
		`"launchDescriptor":`,
		`"assets":`,
		`"role":"kernel"`,
		`"role":"rootfs"`,
		`"digest":{"algorithm":"sha256","value":"`,
		`"cpuCount":4`,
		`"memoryMiB":4096`,
		`"diskSizeMiB":16384`,
		`"guestWorkDir":`,
		`"networkMode":"no_live_networking"`,
		`"imageLabel":"ubuntu-24.04"`,
		`"imageDigest":"sha256:abc123"`,
		`"templateLabel":"hal-agent"`,
		`"templateDigest":"sha256:def456"`,
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("Config JSON %s missing %s", payload, want)
		}
	}
}

func TestConfigJSONOmitsAbsentLaunchDescriptor(t *testing.T) {
	encoded, err := json.Marshal(minimalValidConfig())
	if err != nil {
		t.Fatalf("Marshal(Config) error: %v", err)
	}
	if strings.Contains(string(encoded), "launchDescriptor") {
		t.Fatalf("Config JSON = %s, want launchDescriptor omitted when absent", encoded)
	}
}

func TestDefaultConfigUsesNoLiveNetworking(t *testing.T) {
	defaultConfig := DefaultConfig()
	if DefaultNetworkMode != NetworkModeNoLiveNetworking {
		t.Fatalf("DefaultNetworkMode = %q, want %q", DefaultNetworkMode, NetworkModeNoLiveNetworking)
	}
	if defaultConfig.NetworkMode != NetworkModeNoLiveNetworking {
		t.Fatalf("DefaultConfig().NetworkMode = %q, want %q", defaultConfig.NetworkMode, NetworkModeNoLiveNetworking)
	}
	if defaultConfig.CPUCount <= 0 {
		t.Fatalf("DefaultConfig().CPUCount = %d, want positive default", defaultConfig.CPUCount)
	}
	if defaultConfig.MemoryMiB <= 0 {
		t.Fatalf("DefaultConfig().MemoryMiB = %d, want positive default", defaultConfig.MemoryMiB)
	}
	if defaultConfig.DiskSizeMiB <= 0 {
		t.Fatalf("DefaultConfig().DiskSizeMiB = %d, want positive default", defaultConfig.DiskSizeMiB)
	}
	if defaultConfig.GuestWorkDir != "/workspace" {
		t.Fatalf("DefaultConfig().GuestWorkDir = %q, want /workspace", defaultConfig.GuestWorkDir)
	}

	effective := Options{Config: Config{CPUCount: 6, NetworkMode: "tap"}}.EffectiveConfig()
	if effective.CPUCount != 6 {
		t.Fatalf("EffectiveConfig().CPUCount = %d, want explicit value", effective.CPUCount)
	}
	if effective.NetworkMode != "tap" {
		t.Fatalf("EffectiveConfig().NetworkMode = %q, want explicit value", effective.NetworkMode)
	}
	if effective.MemoryMiB != defaultConfig.MemoryMiB || effective.DiskSizeMiB != defaultConfig.DiskSizeMiB {
		t.Fatalf("EffectiveConfig() = %#v, want memory/disk defaults", effective)
	}
}

func TestApplyDefaultsPreservesLaunchDescriptorAndLegacyImageMetadata(t *testing.T) {
	descriptor := validConfigLaunchDescriptorForTest()
	config := Config{
		LaunchDescriptor: &descriptor,
		ImageLabel:       "ubuntu-24.04",
		ImageDigest:      "sha256:abc123",
		TemplateLabel:    "hal-agent",
		TemplateDigest:   "sha256:def456",
	}

	effective := ApplyDefaults(config)
	if effective.CPUCount != DefaultCPUCount {
		t.Fatalf("CPUCount = %d, want default %d", effective.CPUCount, DefaultCPUCount)
	}
	if effective.MemoryMiB != DefaultMemoryMiB {
		t.Fatalf("MemoryMiB = %d, want default %d", effective.MemoryMiB, DefaultMemoryMiB)
	}
	if effective.DiskSizeMiB != DefaultDiskSizeMiB {
		t.Fatalf("DiskSizeMiB = %d, want default %d", effective.DiskSizeMiB, DefaultDiskSizeMiB)
	}
	if effective.GuestWorkDir != DefaultGuestWorkDir {
		t.Fatalf("GuestWorkDir = %q, want %q", effective.GuestWorkDir, DefaultGuestWorkDir)
	}
	if effective.NetworkMode != DefaultNetworkMode {
		t.Fatalf("NetworkMode = %q, want %q", effective.NetworkMode, DefaultNetworkMode)
	}
	if !reflect.DeepEqual(effective.LaunchDescriptor, &descriptor) {
		t.Fatalf("LaunchDescriptor = %#v, want preserved descriptor", effective.LaunchDescriptor)
	}
	if effective.ImageLabel != "ubuntu-24.04" || effective.ImageDigest != "sha256:abc123" ||
		effective.TemplateLabel != "hal-agent" || effective.TemplateDigest != "sha256:def456" {
		t.Fatalf("legacy image/template metadata was not preserved: %#v", effective)
	}
}

func TestOperationErrorCodesAreStable(t *testing.T) {
	tests := []struct {
		name string
		got  ErrorCode
		want string
	}{
		{name: "unavailable capability", got: ErrorCodeUnavailableCapability, want: "unavailable_capability"},
		{name: "invalid config", got: ErrorCodeInvalidConfig, want: "invalid_config"},
		{name: "backend not configured", got: ErrorCodeBackendNotConfigured, want: "backend_not_configured"},
		{name: "backend operation failed", got: ErrorCodeBackendOperationFailed, want: "backend_operation_failed"},
		{name: "target required", got: ErrorCodeTargetRequired, want: "target_required"},
		{name: "target name required", got: ErrorCodeTargetNameRequired, want: "target_name_required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if string(tt.got) != tt.want {
				t.Fatalf("error code = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestOperationErrorStringAndJSONAreSanitized(t *testing.T) {
	cause := errors.New("firecracker-go-sdk failed kernel=/Users/alice/private/vmlinux rootfs=/var/folders/secret/rootfs.ext4 endpoint=https://deploy:raw-secret@example.test:8443/api token=ghp_secret password=hunter2 template=secret-template")
	err := NewOperationError(ErrorCodeInvalidConfig, "create", cause)

	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(%v, cause) = false, want true", err)
	}

	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(OperationError) error: %v", marshalErr)
	}
	publicText := err.Error() + " " + string(encoded)
	for _, unsafe := range []string{
		"/Users/alice",
		"/var/folders",
		"rootfs.ext4",
		"raw-secret",
		"ghp_secret",
		"hunter2",
		"secret-template",
		"example.test",
		"8443",
		"firecracker-go-sdk",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("public error text leaked unsafe fragment %q in %q", unsafe, publicText)
		}
	}
	for _, want := range []string{
		"invalid_config",
		"create",
		"[redacted-path]",
		"[redacted-endpoint]",
		"token=[redacted]",
		"password=[redacted]",
	} {
		if !strings.Contains(publicText, want) {
			t.Fatalf("public error text %q missing sanitized marker %q", publicText, want)
		}
	}
}

func TestOperationErrorSanitizesArbitraryAbsoluteHostPaths(t *testing.T) {
	cause := errors.New("missing kernel /srv/hal/images/vmlinux rootfs=/nix/store/abc123/rootfs.ext4 socket(/mnt/secrets/firecracker.sock)")
	err := NewOperationError(ErrorCodeUnavailableCapability, "detect_capability", cause)

	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(OperationError) error: %v", marshalErr)
	}
	publicText := err.Error() + " " + string(encoded)
	for _, unsafe := range []string{
		"/srv/hal",
		"/nix/store",
		"/mnt/secrets",
		"vmlinux",
		"rootfs.ext4",
		"firecracker.sock",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("public error text leaked unsafe fragment %q in %q", unsafe, publicText)
		}
	}
	if !strings.Contains(publicText, "[redacted-path]") {
		t.Fatalf("public error text %q missing redacted path marker", publicText)
	}
}

func TestOperationErrorConstructorsUseStableCodes(t *testing.T) {
	tests := []struct {
		name string
		err  *OperationError
		code ErrorCode
	}{
		{name: "unavailable capability", err: NewUnavailableCapabilityError("create", errors.New("kvm unavailable")), code: ErrorCodeUnavailableCapability},
		{name: "invalid config", err: NewInvalidConfigError("create", errors.New("bad config")), code: ErrorCodeInvalidConfig},
		{name: "backend not configured", err: NewBackendNotConfiguredError("inspect"), code: ErrorCodeBackendNotConfigured},
		{name: "backend operation failed", err: NewBackendOperationFailedError("exec", errors.New("backend failed")), code: ErrorCodeBackendOperationFailed},
		{name: "durability uncertain", err: NewOperationError(ErrorCodeDurabilityUncertain, "copy_in", ErrDurabilityUncertain), code: ErrorCodeDurabilityUncertain},
		{name: "target required", err: NewTargetRequiredError("start"), code: ErrorCodeTargetRequired},
		{name: "target name required", err: NewTargetNameRequiredError("create"), code: ErrorCodeTargetNameRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err == nil {
				t.Fatal("constructor returned nil")
			}
			if tt.err.Code != tt.code {
				t.Fatalf("OperationError.Code = %q, want %q", tt.err.Code, tt.code)
			}
			if strings.TrimSpace(tt.err.Error()) == "" {
				t.Fatal("OperationError.Error() returned empty string")
			}
		})
	}
}

func validConfigLaunchDescriptorForTest() assets.LaunchDescriptor {
	return assets.LaunchDescriptor{
		ID:     "phase41-launch",
		Labels: []assets.SafeLabel{"ubuntu-24.04"},
		Assets: []assets.LaunchAsset{
			{
				ID:   "kernel",
				Role: assets.AssetRoleKernel,
				Kind: assets.AssetKindKernelImage,
				Source: assets.AssetSource{
					Type: assets.SourceTypeLocalFile,
					HostPath: &assets.HostPathMetadata{
						Path: "/opt/hal/images/vmlinux",
						Role: assets.HostPathRoleResolvedLocalAsset,
					},
				},
				Lock: configTestLockMetadata(strings.Repeat("a", 64)),
			},
			{
				ID:   "rootfs",
				Role: assets.AssetRoleRootfs,
				Kind: assets.AssetKindRootfsImage,
				Source: assets.AssetSource{
					Type: assets.SourceTypeLocalFile,
					HostPath: &assets.HostPathMetadata{
						Path: "/opt/hal/images/rootfs.ext4",
						Role: assets.HostPathRoleResolvedLocalAsset,
					},
				},
				Lock: configTestLockMetadata(strings.Repeat("1", 64)),
			},
		},
	}
}

func configTestLockMetadata(value string) assets.LockMetadata {
	return assets.LockMetadata{
		Digest: assets.DigestMetadata{
			Algorithm: assets.DigestAlgorithmSHA256,
			Value:     value,
		},
		SizeBytes:          4096,
		LockedAtUnixMillis: 1783015200000,
	}
}

func assertConfigField(t *testing.T, typ reflect.Type, fieldName string, wantType reflect.Type, wantTag string) {
	t.Helper()
	field, ok := typ.FieldByName(fieldName)
	if !ok {
		t.Fatalf("%s field missing from %s", fieldName, typ.Name())
	}
	if field.Type != wantType {
		t.Fatalf("%s.%s type = %v, want %v", typ.Name(), fieldName, field.Type, wantType)
	}
	if got := string(field.Tag); got != wantTag {
		t.Fatalf("%s.%s tag = %q, want %q", typ.Name(), fieldName, got, wantTag)
	}
}
