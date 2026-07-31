package firecracker

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jywlabs/hal/internal/sandboxruntime/microvm"
	"github.com/jywlabs/hal/internal/sandboxruntime/microvm/assets"
)

func TestL7FirecrackerRendersExactlyOneValidatedNetworkInterface(t *testing.T) {
	config := validL7NetworkBackendConfig()
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
		{name: "IPv4 network address", mutate: func(config *BackendConfig) {
			config.StaticNetwork.IPv4Address = "192.0.2.0/30"
			config.StaticNetwork.IPv4Gateway = "192.0.2.1"
		}},
		{name: "IPv4 broadcast address", mutate: func(config *BackendConfig) {
			config.StaticNetwork.IPv4Address = "192.0.2.3/30"
			config.StaticNetwork.IPv4Gateway = "192.0.2.1"
		}},
		{name: "private proxy", mutate: func(config *BackendConfig) { config.StaticNetwork.ProxyURL = "http://10.0.0.8:19443" }},
		{name: "raw path assets", mutate: func(config *BackendConfig) { config.LaunchDescriptor = nil }},
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
			config := validL7NetworkBackendConfig()
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
	config := validL7NetworkBackendConfig()
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

func validL7NetworkBackendConfig() BackendConfig {
	descriptor := validL7LaunchDescriptorForTest()
	return BackendConfig{
		CPUCount:         1,
		MemoryMiB:        128,
		KernelImagePath:  "/kernel",
		RootfsPath:       "/rootfs",
		LaunchDescriptor: &descriptor,
		ProductionVsock:  true,
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

func validL7LaunchDescriptorForTest() assets.LaunchDescriptor {
	descriptor := validFirecrackerLaunchDescriptorForTest()
	descriptor.ID = "l7-network-image"
	descriptor.Labels = []assets.SafeLabel{"firecracker", "reproducible", "network-profile"}
	return descriptor
}
