package localresolver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

const testLockedAtUnixMillis int64 = 1783015200000

func TestResolveLocalAssetsComputesStableSHA256DigestLocks(t *testing.T) {
	kernelPath := writeResolverTestFile(t, "vmlinux", "kernel-bytes")
	rootfsPath := writeResolverTestFile(t, "rootfs.ext4", "rootfs-bytes")
	initrdPath := writeResolverTestFile(t, "initrd.img", "initrd-bytes")
	initConfigPath := writeResolverTestFile(t, "guest-init.json", `{"users":[]}`)
	agentConfigPath := writeResolverTestFile(t, "guest-agent.json", `{"protocol":"v1"}`)

	request := ResolveRequest{
		ID:                 "phase41-launch",
		Labels:             []assets.SafeLabel{"phase41", "local"},
		LockedAtUnixMillis: testLockedAtUnixMillis,
		Assets: []AssetRequest{
			{
				ID:     "kernel",
				Role:   assets.AssetRoleKernel,
				Kind:   assets.AssetKindKernelImage,
				Path:   kernelPath,
				Labels: []assets.SafeLabel{"boot"},
			},
			{
				ID:   "rootfs",
				Role: assets.AssetRoleRootfs,
				Kind: assets.AssetKindRootfsImage,
				Path: rootfsPath,
				Resources: []assets.ResourceMetadata{
					{ID: "rootfs-ext4", Kind: "ext4"},
				},
			},
			{
				ID:   "initrd",
				Role: assets.AssetRoleInitrd,
				Kind: assets.AssetKindInitrdImage,
				Path: initrdPath,
			},
			{
				ID:   "guest-init-config",
				Role: assets.AssetRoleGuestInitConfig,
				Kind: assets.AssetKindGuestConfig,
				Path: initConfigPath,
				InitConfig: &assets.InitConfigMetadata{
					Format:     "json",
					EntryPoint: "init-v1",
				},
			},
			{
				ID:   "guest-agent-config",
				Role: assets.AssetRoleGuestAgentConfig,
				Kind: assets.AssetKindAgentConfig,
				Path: agentConfigPath,
				AgentConfig: &assets.AgentConfigMetadata{
					Protocol: "guest-agent-v1",
					Version:  "v1",
				},
			},
		},
	}

	descriptor, err := Resolve(request)
	if err != nil {
		t.Fatalf("Resolve() error = %v, want nil", err)
	}
	if err := assets.ValidateLaunchDescriptor(descriptor); err != nil {
		t.Fatalf("resolved descriptor failed US-001 validation: %v", err)
	}

	if descriptor.ID != request.ID {
		t.Fatalf("descriptor ID = %q, want %q", descriptor.ID, request.ID)
	}
	if !reflect.DeepEqual(descriptor.Labels, request.Labels) {
		t.Fatalf("descriptor labels = %#v, want %#v", descriptor.Labels, request.Labels)
	}
	if len(descriptor.Assets) != len(request.Assets) {
		t.Fatalf("resolved assets = %d, want %d", len(descriptor.Assets), len(request.Assets))
	}

	wantDigests := map[assets.SafeID]string{
		"kernel":             sha256Hex("kernel-bytes"),
		"rootfs":             sha256Hex("rootfs-bytes"),
		"initrd":             sha256Hex("initrd-bytes"),
		"guest-init-config":  sha256Hex(`{"users":[]}`),
		"guest-agent-config": sha256Hex(`{"protocol":"v1"}`),
	}
	wantSizes := map[assets.SafeID]int64{
		"kernel":             int64(len("kernel-bytes")),
		"rootfs":             int64(len("rootfs-bytes")),
		"initrd":             int64(len("initrd-bytes")),
		"guest-init-config":  int64(len(`{"users":[]}`)),
		"guest-agent-config": int64(len(`{"protocol":"v1"}`)),
	}

	for i, resolved := range descriptor.Assets {
		requested := request.Assets[i]
		if resolved.ID != requested.ID || resolved.Role != requested.Role || resolved.Kind != requested.Kind {
			t.Fatalf("asset[%d] metadata = %#v, want id=%q role=%q kind=%q", i, resolved, requested.ID, requested.Role, requested.Kind)
		}
		if resolved.Source.Type != assets.SourceTypeLocalFile {
			t.Fatalf("asset[%d] source type = %q, want local_file", i, resolved.Source.Type)
		}
		if resolved.Source.HostPath == nil {
			t.Fatalf("asset[%d] host path = nil, want resolved local host path", i)
		}
		if resolved.Source.HostPath.Path != requested.Path {
			t.Fatalf("asset[%d] host path = %q, want %q", i, resolved.Source.HostPath.Path, requested.Path)
		}
		if resolved.Source.HostPath.Role != assets.HostPathRoleResolvedLocalAsset {
			t.Fatalf("asset[%d] host path role = %q, want %q", i, resolved.Source.HostPath.Role, assets.HostPathRoleResolvedLocalAsset)
		}
		if resolved.Lock.Digest.Algorithm != assets.DigestAlgorithmSHA256 {
			t.Fatalf("asset[%d] digest algorithm = %q, want sha256", i, resolved.Lock.Digest.Algorithm)
		}
		if resolved.Lock.Digest.Value != wantDigests[resolved.ID] {
			t.Fatalf("asset[%d] digest = %q, want %q", i, resolved.Lock.Digest.Value, wantDigests[resolved.ID])
		}
		if resolved.Lock.SizeBytes != wantSizes[resolved.ID] {
			t.Fatalf("asset[%d] size = %d, want %d", i, resolved.Lock.SizeBytes, wantSizes[resolved.ID])
		}
		if resolved.Lock.LockedAtUnixMillis != testLockedAtUnixMillis {
			t.Fatalf("asset[%d] lockedAt = %d, want %d", i, resolved.Lock.LockedAtUnixMillis, testLockedAtUnixMillis)
		}
	}

	again, err := Resolve(request)
	if err != nil {
		t.Fatalf("second Resolve() error = %v, want nil", err)
	}
	if !reflect.DeepEqual(again, descriptor) {
		t.Fatalf("Resolve() output changed for identical input:\nfirst=%#v\nsecond=%#v", descriptor, again)
	}
}

func TestResolveLocalAssetsRejectsUnsafeAndUnavailablePaths(t *testing.T) {
	kernelPath := writeResolverTestFile(t, "vmlinux", "kernel-bytes")
	rootfsPath := writeResolverTestFile(t, "rootfs.ext4", "rootfs-bytes")
	linkPath := filepath.Join(t.TempDir(), "kernel-link")
	if err := makeResolverTestSymlink(kernelPath, linkPath); err != nil {
		t.Fatalf("Symlink(%q, %q) error: %v", kernelPath, linkPath, err)
	}

	tests := []struct {
		name      string
		path      string
		wantCode  ErrorCode
		wantField string
	}{
		{
			name:      "missing",
			path:      filepath.Join(t.TempDir(), "missing-kernel"),
			wantCode:  ErrorCodeFileUnavailable,
			wantField: "assets[0].path",
		},
		{
			name:      "non regular",
			path:      t.TempDir(),
			wantCode:  ErrorCodeUnsupportedFileType,
			wantField: "assets[0].path",
		},
		{
			name:      "symlink",
			path:      linkPath,
			wantCode:  ErrorCodeSymlinkRejected,
			wantField: "assets[0].path",
		},
		{
			name:      "relative",
			path:      "images/vmlinux",
			wantCode:  ErrorCodeUnsafePath,
			wantField: "assets[0].path",
		},
		{
			name:      "unclean",
			path:      filepath.Dir(kernelPath) + string(os.PathSeparator) + "images" + string(os.PathSeparator) + ".." + string(os.PathSeparator) + filepath.Base(kernelPath),
			wantCode:  ErrorCodeUnsafePath,
			wantField: "assets[0].path",
		},
		{
			name:      "control character",
			path:      filepath.Join(filepath.Dir(kernelPath), "kernel\nimage"),
			wantCode:  ErrorCodeUnsafePath,
			wantField: "assets[0].path",
		},
		{
			name:      "url like",
			path:      "https://assets.example.test/vmlinux",
			wantCode:  ErrorCodeUnsafePath,
			wantField: "assets[0].path",
		},
		{
			name:      "secret looking",
			path:      filepath.Join(filepath.Dir(kernelPath), "secret-token-vmlinux"),
			wantCode:  ErrorCodeUnsafePath,
			wantField: "assets[0].path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := validResolverRequest(kernelPath, rootfsPath)
			request.Assets[0].Path = tt.path

			_, err := Resolve(request)
			assertResolverError(t, err, tt.wantCode, tt.wantField)
			assertResolverErrorDoesNotLeak(t, err, tt.path, kernelPath, rootfsPath)
		})
	}
}

func TestResolveLocalAssetsPublicErrorsDoNotLeakRejectedInput(t *testing.T) {
	kernelPath := writeResolverTestFile(t, "vmlinux", "kernel-bytes")
	rootfsPath := writeResolverTestFile(t, "rootfs.ext4", "rootfs-bytes")

	tests := []struct {
		name string
		path string
	}{
		{name: "raw host path", path: filepath.Join(t.TempDir(), "missing-rootfs.ext4")},
		{name: "raw url", path: "https://deploy.example.test:8443/rootfs.ext4?token=ghp_secret"},
		{name: "token value", path: filepath.Join(filepath.Dir(rootfsPath), "ghp_secret_token_rootfs.ext4")},
		{name: "secret marker", path: filepath.Join(filepath.Dir(rootfsPath), "private-secret-rootfs.ext4")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := validResolverRequest(kernelPath, rootfsPath)
			request.Assets[1].Path = tt.path

			_, err := Resolve(request)
			if err == nil {
				t.Fatal("Resolve() error = nil, want rejection")
			}
			assertResolverErrorDoesNotLeak(t, err, tt.path, kernelPath, rootfsPath)
		})
	}
}

func validResolverRequest(kernelPath, rootfsPath string) ResolveRequest {
	return ResolveRequest{
		ID:                 "phase41-launch",
		LockedAtUnixMillis: testLockedAtUnixMillis,
		Assets: []AssetRequest{
			{
				ID:   "kernel",
				Role: assets.AssetRoleKernel,
				Kind: assets.AssetKindKernelImage,
				Path: kernelPath,
			},
			{
				ID:   "rootfs",
				Role: assets.AssetRoleRootfs,
				Kind: assets.AssetKindRootfsImage,
				Path: rootfsPath,
			},
		},
	}
}

func writeResolverTestFile(t *testing.T, name, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := writeResolverTestFileContents(path, contents); err != nil {
		t.Fatalf("write test file %q: %v", name, err)
	}
	return path
}

func writeResolverTestFileContents(path, contents string) error {
	return os.WriteFile(path, []byte(contents), 0o600)
}

func makeResolverTestSymlink(oldname, newname string) error {
	return os.Symlink(oldname, newname)
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func assertResolverError(t *testing.T, err error, wantCode ErrorCode, wantField string) {
	t.Helper()

	if err == nil {
		t.Fatal("Resolve() error = nil, want resolver error")
	}
	var resolverErr *Error
	if !errors.As(err, &resolverErr) {
		t.Fatalf("error type = %T, want *Error", err)
	}
	if resolverErr.Code != wantCode {
		t.Fatalf("Error.Code = %q, want %q for %v", resolverErr.Code, wantCode, err)
	}
	if resolverErr.Field != wantField {
		t.Fatalf("Error.Field = %q, want %q for %v", resolverErr.Field, wantField, err)
	}
}

func assertResolverErrorDoesNotLeak(t *testing.T, err error, unsafeValues ...string) {
	t.Helper()

	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil {
		t.Fatalf("Marshal(error) error: %v", marshalErr)
	}
	publicText := err.Error() + " " + string(encoded)
	for _, unsafe := range unsafeValues {
		if unsafe == "" {
			continue
		}
		for _, fragment := range unsafeFragments(unsafe) {
			if strings.Contains(publicText, fragment) {
				t.Fatalf("resolver error leaked unsafe fragment %q in %q", fragment, publicText)
			}
		}
	}
}

func unsafeFragments(value string) []string {
	fragments := []string{value}
	base := filepath.Base(value)
	if base != "." && base != string(filepath.Separator) {
		fragments = append(fragments, base)
	}
	for _, marker := range []string{
		"assets.example.test",
		"deploy.example.test",
		"8443",
		"ghp_secret",
		"secret-token",
		"private-secret",
		"missing-rootfs.ext4",
	} {
		if strings.Contains(value, marker) {
			fragments = append(fragments, marker)
		}
	}
	return fragments
}
