package assets

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidateLaunchDescriptorAcceptsRequiredAndOptionalRoles(t *testing.T) {
	descriptor := validLaunchDescriptorForTest()
	descriptor.Assets = append(descriptor.Assets,
		LaunchAsset{
			ID:   "initrd",
			Role: AssetRoleInitrd,
			Kind: AssetKindInitrdImage,
			Source: AssetSource{
				Type: SourceTypeLocalFile,
				HostPath: &HostPathMetadata{
					Path: "/opt/hal/images/initrd.img",
					Role: HostPathRoleResolvedLocalAsset,
				},
			},
			Lock: testLock(DigestAlgorithmSHA384, strings.Repeat("b", 96)),
		},
		LaunchAsset{
			ID:     "guest-init-config",
			Role:   AssetRoleGuestInitConfig,
			Kind:   AssetKindGuestConfig,
			Source: AssetSource{Type: SourceTypeGenerated},
			Lock:   testLock(DigestAlgorithmSHA256, strings.Repeat("c", 64)),
			InitConfig: &InitConfigMetadata{
				Format:     "cloud-init",
				EntryPoint: "boot",
			},
		},
		LaunchAsset{
			ID:     "guest-agent-config",
			Role:   AssetRoleGuestAgentConfig,
			Kind:   AssetKindAgentConfig,
			Source: AssetSource{Type: SourceTypeEmbedded},
			Lock:   testLock(DigestAlgorithmSHA512, strings.Repeat("d", 128)),
			AgentConfig: &AgentConfigMetadata{
				Protocol: "guest-agent-v1",
				Features: []SafeLabel{
					"readiness",
					"copy-in",
				},
			},
		},
	)

	result := ValidateAndNormalizeLaunchDescriptor(descriptor)
	if !result.Valid {
		t.Fatalf("validation errors = %#v, want valid descriptor", result.Errors)
	}
	if result.Normalized == nil {
		t.Fatal("Normalized = nil, want normalized descriptor")
	}
	if len(result.Normalized.Assets) != 5 {
		t.Fatalf("normalized assets = %d, want 5", len(result.Normalized.Assets))
	}
	if result.Normalized.Assets[2].Role != AssetRoleInitrd {
		t.Fatalf("optional initrd role = %q", result.Normalized.Assets[2].Role)
	}
}

func TestValidateLaunchDescriptorRequiresKernelAndRootfsRoles(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*LaunchDescriptor)
		wantCode ValidationCode
		wantText string
	}{
		{
			name: "missing kernel",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets = descriptor.Assets[1:]
			},
			wantCode: ValidationMissingRequiredRole,
			wantText: "kernel asset is required",
		},
		{
			name: "missing rootfs",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets = descriptor.Assets[:1]
			},
			wantCode: ValidationMissingRequiredRole,
			wantText: "rootfs asset is required",
		},
		{
			name: "duplicate kernel",
			mutate: func(descriptor *LaunchDescriptor) {
				duplicate := descriptor.Assets[0]
				duplicate.ID = "kernel-copy"
				descriptor.Assets = append(descriptor.Assets, duplicate)
			},
			wantCode: ValidationDuplicateRequiredRole,
			wantText: "required asset role must be unique",
		},
		{
			name: "duplicate rootfs",
			mutate: func(descriptor *LaunchDescriptor) {
				duplicate := descriptor.Assets[1]
				duplicate.ID = "rootfs-copy"
				descriptor.Assets = append(descriptor.Assets, duplicate)
			},
			wantCode: ValidationDuplicateRequiredRole,
			wantText: "required asset role must be unique",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descriptor := validLaunchDescriptorForTest()
			tt.mutate(&descriptor)

			result := ValidateAndNormalizeLaunchDescriptor(descriptor)
			assertLaunchAssetInvalid(t, result, tt.wantCode, tt.wantText)
		})
	}
}

func TestValidateLaunchDescriptorRejectsUnsafeIDsAndLabels(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*LaunchDescriptor)
		wantCode ValidationCode
		wantText string
	}{
		{
			name: "unsafe descriptor id",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.ID = "https://secret.example.test/launch"
			},
			wantCode: ValidationUnsafeID,
			wantText: "descriptor id must be a safe identifier",
		},
		{
			name: "unsafe descriptor label",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Labels = []SafeLabel{"ubuntu", "token=ghp_secret"}
			},
			wantCode: ValidationUnsafeLabel,
			wantText: "descriptor label must be safe metadata",
		},
		{
			name: "unsafe asset id",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].ID = "../kernel"
			},
			wantCode: ValidationUnsafeID,
			wantText: "asset id must be a safe identifier",
		},
		{
			name: "unsafe asset label",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].Labels = []SafeLabel{"boot", "secret-kernel"}
			},
			wantCode: ValidationUnsafeLabel,
			wantText: "asset label must be safe metadata",
		},
		{
			name: "unsafe init config label",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].InitConfig = &InitConfigMetadata{Format: "cloud-init", Labels: []SafeLabel{"password"}}
			},
			wantCode: ValidationUnsafeLabel,
			wantText: "init config label must be safe metadata",
		},
		{
			name: "unsafe agent feature",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[1].AgentConfig = &AgentConfigMetadata{Features: []SafeLabel{"http://metadata.example.test"}}
			},
			wantCode: ValidationUnsafeLabel,
			wantText: "agent config feature must be safe metadata",
		},
		{
			name: "unsafe resource id",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[1].Resources = []ResourceMetadata{{ID: "rootfs/secret"}}
			},
			wantCode: ValidationUnsafeID,
			wantText: "resource id must be a safe identifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descriptor := validLaunchDescriptorForTest()
			tt.mutate(&descriptor)

			result := ValidateAndNormalizeLaunchDescriptor(descriptor)
			assertLaunchAssetInvalid(t, result, tt.wantCode, tt.wantText)
			assertLaunchAssetValidationNoUnsafeLeak(t, result)
		})
	}
}

func TestValidateLaunchDescriptorRejectsUnsupportedMetadata(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*LaunchDescriptor)
		wantCode ValidationCode
		wantText string
	}{
		{
			name: "unsupported role",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].Role = "firecracker_kernel"
			},
			wantCode: ValidationUnsupportedRole,
			wantText: "asset role is unsupported",
		},
		{
			name: "unsupported kind",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].Kind = "ami"
			},
			wantCode: ValidationUnsupportedKind,
			wantText: "asset kind is unsupported",
		},
		{
			name: "unsupported source type",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].Source.Type = "http"
			},
			wantCode: ValidationUnsupportedSourceType,
			wantText: "asset source type is unsupported",
		},
		{
			name: "unsupported host path role",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].Source.HostPath.Role = "firecracker_boot"
			},
			wantCode: ValidationUnsupportedHostPathRole,
			wantText: "asset host path role is unsupported",
		},
		{
			name: "negative lock size",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].Lock.SizeBytes = -1
			},
			wantCode: ValidationInvalidMetadata,
			wantText: "lock size must be non-negative",
		},
		{
			name: "negative resource size",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].Resources = []ResourceMetadata{{ID: "kernel-resource", SizeBytes: -1}}
			},
			wantCode: ValidationInvalidMetadata,
			wantText: "resource size must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descriptor := validLaunchDescriptorForTest()
			tt.mutate(&descriptor)

			result := ValidateAndNormalizeLaunchDescriptor(descriptor)
			assertLaunchAssetInvalid(t, result, tt.wantCode, tt.wantText)
		})
	}
}

func TestValidateLaunchDescriptorRejectsMalformedDigestLocks(t *testing.T) {
	tests := []struct {
		name     string
		mutate   func(*LaunchDescriptor)
		wantCode ValidationCode
		wantText string
	}{
		{
			name: "missing lock",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].Lock = LockMetadata{}
			},
			wantCode: ValidationMalformedDigestAlgorithm,
			wantText: "digest algorithm is required",
		},
		{
			name: "malformed algorithm",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].Lock.Digest.Algorithm = "sha-256"
			},
			wantCode: ValidationMalformedDigestAlgorithm,
			wantText: "digest algorithm is unsupported",
		},
		{
			name: "wrong sha256 length",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].Lock.Digest.Value = strings.Repeat("a", 63)
			},
			wantCode: ValidationMalformedDigestValue,
			wantText: "digest value length does not match algorithm",
		},
		{
			name: "non hex value",
			mutate: func(descriptor *LaunchDescriptor) {
				descriptor.Assets[0].Lock.Digest.Value = strings.Repeat("z", 64)
			},
			wantCode: ValidationMalformedDigestValue,
			wantText: "digest value must be lowercase hexadecimal",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			descriptor := validLaunchDescriptorForTest()
			tt.mutate(&descriptor)

			result := ValidateAndNormalizeLaunchDescriptor(descriptor)
			assertLaunchAssetInvalid(t, result, tt.wantCode, tt.wantText)
		})
	}
}

func TestValidateLaunchDescriptorNormalizesSafeEnumMetadata(t *testing.T) {
	descriptor := validLaunchDescriptorForTest()
	descriptor.Assets[0].Role = " Kernel "
	descriptor.Assets[0].Kind = " Kernel_Image "
	descriptor.Assets[0].Source.Type = " Local_File "
	descriptor.Assets[0].Source.HostPath.Role = " Resolved_Local_Asset "
	descriptor.Assets[0].Lock.Digest.Algorithm = " SHA256 "
	descriptor.Assets[0].Lock.Digest.Value = strings.ToUpper(strings.Repeat("a", 64))

	result := ValidateAndNormalizeLaunchDescriptor(descriptor)
	if !result.Valid {
		t.Fatalf("validation errors = %#v, want valid descriptor", result.Errors)
	}
	got := result.Normalized.Assets[0]
	if got.Role != AssetRoleKernel || got.Kind != AssetKindKernelImage || got.Source.Type != SourceTypeLocalFile {
		t.Fatalf("normalized role/kind/source = %#v", got)
	}
	if got.Source.HostPath == nil || got.Source.HostPath.Role != HostPathRoleResolvedLocalAsset {
		t.Fatalf("normalized host path = %#v", got.Source.HostPath)
	}
	if got.Lock.Digest.Algorithm != DigestAlgorithmSHA256 || got.Lock.Digest.Value != strings.Repeat("a", 64) {
		t.Fatalf("normalized digest = %#v", got.Lock.Digest)
	}
}

func TestValidateLaunchDescriptorPreservesNilVersusExplicitEmptyOptionals(t *testing.T) {
	nilDescriptor := validLaunchDescriptorForTest()
	nilResult := ValidateAndNormalizeLaunchDescriptor(nilDescriptor)
	if !nilResult.Valid {
		t.Fatalf("nil optionals validation errors = %#v", nilResult.Errors)
	}
	if nilResult.Normalized.Labels != nil {
		t.Fatalf("normalized descriptor labels = %#v, want nil", nilResult.Normalized.Labels)
	}
	if nilResult.Normalized.Assets[0].Labels != nil {
		t.Fatalf("normalized asset labels = %#v, want nil", nilResult.Normalized.Assets[0].Labels)
	}
	if nilResult.Normalized.Assets[0].Resources != nil {
		t.Fatalf("normalized resources = %#v, want nil", nilResult.Normalized.Assets[0].Resources)
	}
	if nilResult.Normalized.Assets[0].InitConfig != nil {
		t.Fatalf("normalized init config = %#v, want nil", nilResult.Normalized.Assets[0].InitConfig)
	}

	emptyDescriptor := validLaunchDescriptorForTest()
	emptyDescriptor.Labels = []SafeLabel{}
	emptyDescriptor.Assets[0].Labels = []SafeLabel{}
	emptyDescriptor.Assets[0].Resources = []ResourceMetadata{}
	emptyDescriptor.Assets[0].InitConfig = &InitConfigMetadata{Labels: []SafeLabel{}}
	emptyDescriptor.Assets[1].AgentConfig = &AgentConfigMetadata{Features: []SafeLabel{}}

	emptyResult := ValidateAndNormalizeLaunchDescriptor(emptyDescriptor)
	if !emptyResult.Valid {
		t.Fatalf("empty optionals validation errors = %#v, want valid descriptor", emptyResult.Errors)
	}
	if emptyResult.Normalized.Labels == nil {
		t.Fatal("normalized descriptor labels = nil, want explicit empty slice preserved")
	}
	if emptyResult.Normalized.Assets[0].Labels == nil {
		t.Fatal("normalized asset labels = nil, want explicit empty slice preserved")
	}
	if emptyResult.Normalized.Assets[0].Resources == nil {
		t.Fatal("normalized resources = nil, want explicit empty slice preserved")
	}
	if emptyResult.Normalized.Assets[0].InitConfig == nil || emptyResult.Normalized.Assets[0].InitConfig.Labels == nil {
		t.Fatalf("normalized init config = %#v, want explicit empty label slice preserved", emptyResult.Normalized.Assets[0].InitConfig)
	}
	if emptyResult.Normalized.Assets[1].AgentConfig == nil || emptyResult.Normalized.Assets[1].AgentConfig.Features == nil {
		t.Fatalf("normalized agent config = %#v, want explicit empty feature slice preserved", emptyResult.Normalized.Assets[1].AgentConfig)
	}
}

func validLaunchDescriptorForTest() LaunchDescriptor {
	return LaunchDescriptor{
		ID: "phase41-launch",
		Assets: []LaunchAsset{
			{
				ID:   "kernel",
				Role: AssetRoleKernel,
				Kind: AssetKindKernelImage,
				Source: AssetSource{
					Type: SourceTypeLocalFile,
					HostPath: &HostPathMetadata{
						Path: "/opt/hal/images/vmlinux",
						Role: HostPathRoleResolvedLocalAsset,
					},
				},
				Lock: testLock(DigestAlgorithmSHA256, strings.Repeat("a", 64)),
			},
			{
				ID:   "rootfs",
				Role: AssetRoleRootfs,
				Kind: AssetKindRootfsImage,
				Source: AssetSource{
					Type: SourceTypeLocalFile,
					HostPath: &HostPathMetadata{
						Path: "/opt/hal/images/rootfs.ext4",
						Role: HostPathRoleResolvedLocalAsset,
					},
				},
				Lock: testLock(DigestAlgorithmSHA256, strings.Repeat("1", 64)),
			},
		},
	}
}

func testLock(algorithm DigestAlgorithm, value string) LockMetadata {
	return LockMetadata{
		Digest: DigestMetadata{
			Algorithm: algorithm,
			Value:     value,
		},
		SizeBytes:          4096,
		LockedAtUnixMillis: 1783015200000,
	}
}

func assertLaunchAssetInvalid(t *testing.T, result ValidationResult, wantCode ValidationCode, wantMessage string) {
	t.Helper()

	if result.Valid {
		t.Fatalf("Valid = true, want invalid result")
	}
	if result.Normalized != nil {
		t.Fatalf("Normalized = %#v, want nil for invalid result", result.Normalized)
	}
	for _, validationErr := range result.Errors {
		if validationErr.Code == wantCode && validationErr.Message == wantMessage {
			return
		}
	}
	t.Fatalf("errors = %#v, want code=%q message=%q", result.Errors, wantCode, wantMessage)
}

func assertLaunchAssetValidationNoUnsafeLeak(t *testing.T, result ValidationResult) {
	t.Helper()

	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal(ValidationResult) error: %v", err)
	}
	publicText := string(encoded)
	for _, unsafe := range []string{
		"https://secret.example.test",
		"token=ghp_secret",
		"../kernel",
		"secret-kernel",
		"password",
		"http://metadata.example.test",
		"rootfs/secret",
	} {
		if strings.Contains(publicText, unsafe) {
			t.Fatalf("validation result leaked unsafe fragment %q in %s", unsafe, publicText)
		}
	}
}
