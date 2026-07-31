package firecracker

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
	assetbuild "github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/build"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets/localresolver"
)

func TestL7FirecrackerRendersExactlyOneValidatedNetworkInterface(t *testing.T) {
	config := validL7NetworkBackendConfig(t)
	rendered, err := liveBootConfig(config)
	if err != nil {
		t.Fatalf("liveBootConfig() error = %v", err)
	}
	encoded, err := json.Marshal(rendered)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	interfaces, ok := raw["network-interfaces"].([]any)
	if !ok || len(interfaces) != 1 {
		t.Fatalf("network-interfaces = %#v, want exactly one", raw["network-interfaces"])
	}
	got := interfaces[0].(map[string]any)
	if got["iface_id"] != "net1" || got["host_dev_name"] != "tap-l7abc" || got["guest_mac"] != "02:00:00:00:00:02" {
		t.Fatalf("network interface = %#v, want exact validated payload", got)
	}
	boot := raw["boot-source"].(map[string]any)
	args, _ := boot["boot_args"].(string)
	for _, token := range []string{
		"hal_l7_net_if=eth0",
		"hal_l7_ipv4=192.0.2.2/30",
		"hal_l7_ipv4_gateway=192.0.2.1",
		"hal_l7_ipv6=fd00:7::2/126",
		"hal_l7_ipv6_gateway=fd00:7::1",
		"hal_l7_proxy=http://192.0.2.1:18080",
	} {
		if !strings.Contains(args, token) {
			t.Fatalf("boot args missing %q", token)
		}
	}
}

func TestL7FirecrackerRejectsChangedVerifiedAssetsBeforeLiveBootRender(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, string)
	}{
		{
			name: "in-place mutation",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				contents, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				contents[0] ^= 0xff
				if err := os.WriteFile(path, contents, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "path replacement",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				contents, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				contents[0] ^= 0xff
				replacement := path + ".replacement"
				if err := os.WriteFile(replacement, contents, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, path); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := validL7NetworkBackendConfig(t)
			launchAssets, err := firecrackerLaunchDescriptorAssets(config.LaunchDescriptor, liveBootRenderOperation)
			if err != nil {
				t.Fatal(err)
			}
			tt.mutate(t, launchAssets.rootfsPath())

			stateDir := filepath.Join(t.TempDir(), "state")
			config.Paths = PathPlan{
				StateDir:        stateDir,
				APISocketPath:   filepath.Join(stateDir, "api.sock"),
				ConfigPath:      filepath.Join(stateDir, "config.json"),
				LogPath:         filepath.Join(stateDir, "firecracker.log"),
				MetricsPath:     filepath.Join(stateDir, "firecracker.metrics"),
				VsockSocketPath: filepath.Join(stateDir, "guest.vsock"),
			}
			err = renderLiveBootFiles(config)
			if err == nil || !errors.Is(err, microvm.ErrInvalidConfig) {
				t.Fatalf("renderLiveBootFiles() error = %v, want invalid config", err)
			}
			if _, statErr := os.Stat(config.Paths.ConfigPath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("config path stat error = %v, want not-exist", statErr)
			}
		})
	}
}

func TestL7FirecrackerNetworkConfigFailsClosedAndRedactsRawValues(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*BackendConfig)
	}{
		{name: "missing interface", mutate: func(config *BackendConfig) { config.NetworkInterfaces = nil }},
		{name: "multiple interfaces", mutate: func(config *BackendConfig) {
			config.NetworkInterfaces = append(config.NetworkInterfaces, config.NetworkInterfaces[0])
		}},
		{name: "missing boot config", mutate: func(config *BackendConfig) { config.StaticNetwork = nil }},
		{name: "unsafe tap", mutate: func(config *BackendConfig) { config.NetworkInterfaces[0].HostDeviceName = "tap secret /tmp/canary" }},
		{name: "nonlocal mac", mutate: func(config *BackendConfig) { config.NetworkInterfaces[0].GuestMAC = "00:00:00:00:00:02" }},
		{name: "gateway outside prefix", mutate: func(config *BackendConfig) { config.StaticNetwork.IPv4Gateway = "198.51.100.1" }},
		{name: "broad IPv4 prefix", mutate: func(config *BackendConfig) { config.StaticNetwork.IPv4Address = "192.0.2.2/0" }},
		{name: "broad IPv6 prefix", mutate: func(config *BackendConfig) { config.StaticNetwork.IPv6Address = "fd00:7::2/64" }},
		{name: "IPv6 prefix-base guest", mutate: func(config *BackendConfig) { config.StaticNetwork.IPv6Address = "fd00:7::/126" }},
		{name: "IPv6 prefix-base gateway", mutate: func(config *BackendConfig) { config.StaticNetwork.IPv6Gateway = "fd00:7::" }},
		{name: "IPv4 network address", mutate: func(config *BackendConfig) {
			config.StaticNetwork.IPv4Address = "192.0.2.0/30"
			config.StaticNetwork.IPv4Gateway = "192.0.2.1"
		}},
		{name: "IPv4 broadcast address", mutate: func(config *BackendConfig) {
			config.StaticNetwork.IPv4Address = "192.0.2.3/30"
			config.StaticNetwork.IPv4Gateway = "192.0.2.1"
		}},
		{name: "IPv4 network gateway", mutate: func(config *BackendConfig) { config.StaticNetwork.IPv4Gateway = "192.0.2.0" }},
		{name: "IPv4 broadcast gateway", mutate: func(config *BackendConfig) { config.StaticNetwork.IPv4Gateway = "192.0.2.3" }},
		{name: "private proxy", mutate: func(config *BackendConfig) { config.StaticNetwork.ProxyURL = "http://10.0.0.8:19443" }},
		{name: "raw path assets", mutate: func(config *BackendConfig) { config.LaunchDescriptor = nil }},
		{name: "exact synthetic relabel without verified bundle", mutate: func(config *BackendConfig) {
			encoded, err := json.Marshal(config.LaunchDescriptor)
			if err != nil {
				panic(err)
			}
			var synthetic assets.LaunchDescriptor
			if err := json.Unmarshal(encoded, &synthetic); err != nil {
				panic(err)
			}
			config.LaunchDescriptor = &synthetic
			forged := localresolver.VerifiedL7Profile{}
			config.VerifiedL7Profile = &forged
		}},
		{name: "generic descriptor", mutate: func(config *BackendConfig) {
			descriptor := validFirecrackerLaunchDescriptorForTest()
			config.LaunchDescriptor = &descriptor
		}},
		{name: "L5 descriptor", mutate: func(config *BackendConfig) {
			descriptor := validL7LaunchDescriptorForTest()
			descriptor.ID = "l5-image"
			descriptor.Labels = []assets.SafeLabel{"firecracker", "reproducible"}
			config.LaunchDescriptor = &descriptor
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := validL7NetworkBackendConfig(t)
			tt.mutate(&config)
			_, err := liveBootConfig(config)
			if err == nil || !errors.Is(err, microvm.ErrInvalidConfig) {
				t.Fatalf("liveBootConfig() error = %v, want invalid config", err)
			}
			encoded, marshalErr := json.Marshal(err)
			if marshalErr != nil {
				t.Fatalf("json.Marshal(error) error = %v", marshalErr)
			}
			public := err.Error() + " " + string(encoded)
			for _, forbidden := range []string{"192.0.2", "198.51.100", "10.0.0.8", "19443", "18080", "tap-l7abc", "/tmp/canary", "02:00:00:00:00:02"} {
				if strings.Contains(public, forbidden) {
					t.Fatalf("public error leaked %q in %q", forbidden, public)
				}
			}
		})
	}
}

func TestL7RawNetworkConfigIsOmittedAndNoNetworkOutputStaysUnchanged(t *testing.T) {
	config := validL7NetworkBackendConfig(t)
	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"192.0.2", "fd00:7", "18080", "tap-l7abc", "02:00:00:00:00:02", "boot_args"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("BackendConfig JSON leaked %q: %s", forbidden, encoded)
		}
	}

	noNetwork, err := liveBootConfig(BackendConfig{
		CPUCount: 1, MemoryMiB: 128, KernelImagePath: "/kernel", RootfsPath: "/rootfs",
	})
	if err != nil {
		t.Fatal(err)
	}
	noNetworkJSON, err := json.Marshal(noNetwork)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(noNetworkJSON), "network-interfaces") || strings.Contains(string(noNetworkJSON), "hal_l7_") {
		t.Fatalf("default Firecracker config gained networking: %s", noNetworkJSON)
	}
}

func validL7NetworkBackendConfig(t *testing.T) BackendConfig {
	t.Helper()
	verified := verifiedL7DistributionForTest(t)
	profile, ok := verified.L7Profile()
	if !ok {
		t.Fatal("verified L7 distribution did not produce an opaque profile")
	}
	descriptor := verified.Descriptor
	return BackendConfig{
		CPUCount:          1,
		MemoryMiB:         128,
		KernelImagePath:   "/kernel",
		RootfsPath:        "/rootfs",
		LaunchDescriptor:  &descriptor,
		VerifiedL7Profile: &profile,
		ProductionVsock:   true,
		Paths: PathPlan{
			StateDir: "/state", APISocketPath: "/state/api.sock", ConfigPath: "/state/config.json",
			LogPath: "/state/firecracker.log", MetricsPath: "/state/firecracker.metrics", VsockSocketPath: "/state/guest.vsock",
		},
		NetworkMode: microvm.NetworkModeL7PolicyProxy,
		NetworkInterfaces: []NetworkInterfaceConfig{{
			InterfaceID: "net1", HostDeviceName: "tap-l7abc", GuestMAC: "02:00:00:00:00:02",
		}},
		StaticNetwork: &StaticNetworkBootConfig{
			GuestInterfaceName: "eth0",
			IPv4Address:        "192.0.2.2/30",
			IPv4Gateway:        "192.0.2.1",
			IPv6Address:        "fd00:7::2/126",
			IPv6Gateway:        "fd00:7::1",
			ProxyURL:           "http://192.0.2.1:18080",
		},
	}
}

func verifiedL7DistributionForTest(t *testing.T) localresolver.VerifiedDistribution {
	t.Helper()
	root := t.TempDir()
	kernel := []byte("verified-l7-kernel")
	rootfs := []byte("verified-l7-rootfs")
	assetsMetadata := []assetbuild.DistributionAsset{
		{Key: "vmlinux", ID: "kernel", Kind: "kernel_image", SizeBytes: int64(len(kernel)), SHA256: sha256Text(kernel)},
		{Key: "rootfs.ext4", ID: "rootfs", Kind: "rootfs_image", SizeBytes: int64(len(rootfs)), SHA256: sha256Text(rootfs)},
	}
	commonVersions := assetbuild.Versions{
		Buildroot: "2026.05.1", Linux: "6.1.178", BusyBox: "1.38.0",
		E2fsprogs: "1.47.4", Go: "1.25.7", Firecracker: "v1.15.1",
	}
	agent := assetbuild.GuestAgent{Protocol: "guest-agent-v1", Features: []string{"copy_in", "copy_out", "exec", "readiness"}}
	network := &assetbuild.GuestNetwork{Mode: assetbuild.GuestNetworkModeStaticProxy, Features: []string{"ipv4", "ipv6", "proxy_bootstrap", "virtio_net"}}
	manifest := assetbuild.DistributionManifest{
		SchemaVersion: assetbuild.SchemaVersionV1, ImageProfile: assetbuild.ImageProfileL7Network,
		Architecture: "x86_64", Versions: commonVersions, GuestAgent: agent, GuestNetwork: network,
		Assets: assetsMetadata,
	}
	provenance := assetbuild.Provenance{
		SchemaVersion: assetbuild.SchemaVersionV1, ImageProfile: assetbuild.ImageProfileL7Network,
		SourceRevision: strings.Repeat("a", 40), SourceTree: "tree-" + strings.Repeat("b", 64),
		SourceDateEpoch: 1, BuildImageDigest: "sha256:" + strings.Repeat("c", 64),
		Architecture: "x86_64", Versions: commonVersions, GuestAgent: agent, GuestNetwork: network,
		Outputs: []assetbuild.Output{
			{Key: "vmlinux", ID: "kernel", Kind: "kernel_image", SizeBytes: int64(len(kernel)), SHA256: sha256Text(kernel)},
			{Key: "rootfs.ext4", ID: "rootfs", Kind: "rootfs_image", SizeBytes: int64(len(rootfs)), SHA256: sha256Text(rootfs)},
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	provenanceBytes, err := json.Marshal(provenance)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"distribution-manifest.json": append(manifestBytes, '\n'),
		"provenance.json":            append(provenanceBytes, '\n'),
		"rootfs.ext4":                rootfs,
		"vmlinux":                    kernel,
	}
	checksums := ""
	for _, name := range []string{"distribution-manifest.json", "provenance.json", "rootfs.ext4", "vmlinux"} {
		checksums += fmt.Sprintf("%s  %s\n", sha256Text(files[name]), name)
	}
	files["SHA256SUMS"] = []byte(checksums)
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	verified, err := localresolver.VerifyDistributionBundle(localresolver.DistributionRequest{RootDir: root, LockedAtUnixMillis: 1})
	if err != nil {
		t.Fatalf("VerifyDistributionBundle() error = %v", err)
	}
	return verified
}

func sha256Text(data []byte) string {
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum[:])
}

func validL7LaunchDescriptorForTest() assets.LaunchDescriptor {
	descriptor := validFirecrackerLaunchDescriptorForTest()
	descriptor.ID = "l7-network-image"
	descriptor.Labels = []assets.SafeLabel{"firecracker", "reproducible", "network-profile"}
	descriptor.Assets = descriptor.Assets[:2]
	descriptor.Assets[0].ID = "kernel"
	descriptor.Assets[1].ID = "rootfs"
	return descriptor
}
